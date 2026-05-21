#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

COMMENT_MARKER = '<!-- ghost-guard-scan -->'
CLAUDE_MODEL = 'claude-sonnet-4-6'
CLAUDE_MAX_TOKENS = 2048

RISK_LABELS = {
  'no_concerns'    => ['✅', 'No concerns identified'],
  'minor'          => ['🟡', 'Minor — low risk, review recommended'],
  'needs_scrutiny' => ['⚠️', 'Needs scrutiny before running tests'],
  'high'           => ['🚨', 'High — do not trigger tests without careful review'],
}.freeze

ANTHROPIC_API_KEY = ENV.fetch('ANTHROPIC_API_KEY')
GITHUB_TOKEN      = ENV.fetch('GITHUB_TOKEN')
PR_NUMBER         = ENV.fetch('PR_NUMBER')
REPO              = ENV.fetch('REPO') # owner/repo

def github_request(method, path, accept: 'application/vnd.github+json', body: nil)
  uri = URI("https://api.github.com#{path}")
  req = case method
        when :get   then Net::HTTP::Get.new(uri)
        when :post  then Net::HTTP::Post.new(uri)
        when :patch then Net::HTTP::Patch.new(uri)
        end
  req['Authorization'] = "Bearer #{GITHUB_TOKEN}"
  req['Accept']        = accept
  req['User-Agent']    = 'ghost-guard-scan'
  if body
    req['Content-Type'] = 'application/json'
    req.body = JSON.generate(body)
  end
  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  raise "GitHub API #{method.upcase} #{path} failed: #{res.code} #{res.body}" unless res.is_a?(Net::HTTPSuccess)

  res.body
end

def fetch_diff
  github_request(:get, "/repos/#{REPO}/pulls/#{PR_NUMBER}", accept: 'application/vnd.github.v3.diff')
end

def analyze_diff(diff)
  system_prompt = <<~PROMPT
    You are reviewing a unified diff from a fork PR against a Puppet module repository.

    Threat model: the diff will be executed during acceptance tests in a CI environment that holds
    secrets. Your job is to advise human reviewers whether running those tests is safe — specifically
    whether the diff contains code that could exfiltrate CI secrets during test execution.

    High-scrutiny files and their risk vectors:
    - spec/**                : RSpec hooks/helpers that read ENV and exfiltrate (e.g. HTTP POST out)
    - spec/spec_helper.rb    : runs before every test — ideal exfiltration point
    - Gemfile                : malicious/typosquatted gems that execute on bundle install / require
    - Rakefile               : code that runs on require; tasks invoked during test runs
    - .fixtures.yml          : module source URLs redirected to attacker-controlled repos
    - .github/**             : workflow steps that directly access secrets
    - CODEOWNERS             : removal of legitimate reviewers (lower weight)
    - metadata.json          : source URL changes (lower weight)

    Puppet-specific risk vectors — apply additional scrutiny to these:

    GEM VERSION BUMPS (Gemfile)
    A version bump to a gem version that does not yet exist on rubygems.org is a known
    supply-chain attack: the attacker publishes a malicious gem at that exact version and
    bundle install pulls it automatically. Flag as HIGH when:
    - A version is pinned with '=' to a version that looks very recent or implausible
      (e.g. jumping from 1.2.1 to 1.2.99 or to a future-dated pre-release)
    - A pessimistic constraint '~>' is widened in a way that could pull in an unpublished version
    Flag as needs_scrutiny when a version is bumped to a plausible but unverifiable new patch.

    PUPPET PROVIDERS (lib/puppet/provider/**)
    Providers execute as root during catalog application on managed nodes.
    Flag as HIGH any: outbound HTTP/socket calls, ENV secret reads, shell commands via
    Puppet::Util::Execution.execute, backticks, system(), or Open3.

    CUSTOM FACTS (lib/facter/** or facts.d/**)
    Custom facts run on every Puppet agent at every catalog request.
    Flag as HIGH any: outbound HTTP calls, reads of sensitive paths (/root/.ssh,
    /etc/passwd, credential files), or ENV access that is then transmitted.

    PUPPET MANIFESTS (manifests/**)
    Flag as needs_scrutiny: new exec { } resources, file { } resources writing to
    sensitive system paths, or package sources changed to non-standard URLs.
    Flag as HIGH: exec resources whose command reads ENV or makes network calls.

    HIERA DATA (data/**)
    Hiera values are injected directly into class parameters at catalog compile time.
    Flag as needs_scrutiny: new keys that look like credentials or tokens, base64-encoded
    blobs, or lookup() calls pointing to external data sources.

    BOLT TASKS AND PLANS (tasks/**, plans/**)
    Tasks and plans execute arbitrary code on remote nodes via Bolt.
    Flag as HIGH any outbound network calls, secret ENV reads, or file exfiltration.

    MODULE METADATA (metadata.json)
    Flag as HIGH: dependency source URLs changed from forge.puppet.com to any other domain.
    Flag as needs_scrutiny: version constraints widened significantly or new dependencies added.

    Assign exactly one risk level:
    - no_concerns    : no suspicious changes; routine updates
    - minor          : touches a high-scrutiny file but the change is clearly explainable
    - needs_scrutiny : ambiguous but potentially dangerous (e.g. new gem, exec resource, external fixture)
    - high           : clear indicators — secret access, network exfiltration, backdoor, source redirect,
                       or gem bumped to a plausibly non-existent version

    Reply with a single JSON object and nothing else:
    {
      "risk_level": "no_concerns" | "minor" | "needs_scrutiny" | "high",
      "summary": "one-line summary",
      "findings": [
        { "location": "path/to/file:LINE", "explanation": "what is suspicious and why" }
      ]
    }

    Only include findings for high-scrutiny files. If risk_level is no_concerns, findings may be [].
  PROMPT

  uri = URI('https://api.anthropic.com/v1/messages')
  req = Net::HTTP::Post.new(uri)
  req['x-api-key']         = ANTHROPIC_API_KEY
  req['anthropic-version'] = '2023-06-01'
  req['content-type']      = 'application/json'
  req.body = JSON.generate(
    model: CLAUDE_MODEL,
    max_tokens: CLAUDE_MAX_TOKENS,
    system: system_prompt,
    messages: [{ role: 'user', content: "Unified diff to review:\n\n#{diff}" }],
  )

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  raise "Claude API failed: #{res.code} #{res.body}" unless res.is_a?(Net::HTTPSuccess)

  text = JSON.parse(res.body).dig('content', 0, 'text').to_s.strip
  # Strip ```json fences if Claude wraps the output despite instructions.
  text = text.sub(/\A```(?:json)?\s*/, '').sub(/\s*```\z/, '')
  JSON.parse(text)
end

def render_comment(analysis)
  level = analysis['risk_level']
  emoji, label = RISK_LABELS.fetch(level, ['❓', "Unknown (#{level})"])
  summary = analysis['summary'].to_s.strip
  findings = Array(analysis['findings'])

  findings_section =
    if findings.empty?
      'No specific findings.'
    else
      findings.map { |f| "- `#{f['location']}` — #{f['explanation']}" }.join("\n")
    end

  <<~MD
    #{COMMENT_MARKER}
    ## Ghost Guard Advisory Scan

    **Risk:** #{emoji} #{label}

    **Summary:** #{summary}

    **Findings:**
    #{findings_section}

    ---
    > Advisory only — not a substitute for human review. This scan helps assess whether it is safe to trigger acceptance tests on this fork PR.
  MD
end

def find_or_update_comment(body)
  raw = github_request(:get, "/repos/#{REPO}/issues/#{PR_NUMBER}/comments?per_page=100")
  existing = JSON.parse(raw).find { |c| c['body'].to_s.include?(COMMENT_MARKER) }

  if existing
    github_request(:patch, "/repos/#{REPO}/issues/comments/#{existing['id']}", body: { body: body })
  else
    github_request(:post, "/repos/#{REPO}/issues/#{PR_NUMBER}/comments", body: { body: body })
  end
end

diff = fetch_diff
analysis = analyze_diff(diff)
find_or_update_comment(render_comment(analysis))
puts "Ghost Guard: posted #{analysis['risk_level']} verdict for PR ##{PR_NUMBER}"
