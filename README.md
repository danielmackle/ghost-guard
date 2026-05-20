# Ghost Guard

Advisory security scanner for fork PRs in Puppet module repositories, powered by Claude.

When a contributor forks your repo and opens a PR, Ghost Guard automatically analyses the diff for patterns that could exfiltrate CI secrets during acceptance test execution. It posts a structured advisory comment so reviewers can decide whether it is safe to trigger tests — without blocking anything automatically.

## How it works

1. A fork PR is opened or updated
2. The `pull_request_target` workflow fires (base repo context — fork code is never checked out)
3. `ghost_guard_scan.rb` fetches the unified diff via the GitHub API
4. The diff is sent to Claude (`claude-sonnet-4-6`) with a structured threat-model prompt
5. Claude returns a risk verdict and findings
6. The script posts (or updates) an advisory comment on the PR

## Risk levels

| Level | Meaning |
|---|---|
| ✅ No concerns | Routine changes, nothing suspicious |
| 🟡 Minor | Touches a high-scrutiny file but the change is clearly explainable |
| ⚠️ Needs scrutiny | Ambiguous — verify before running acceptance tests |
| 🚨 High | Clear exfiltration pattern, backdoor, or source redirect — do not trigger tests |

## High-scrutiny files

| File | Risk vector |
|---|---|
| `spec/**` | RSpec hooks that read `ENV` and exfiltrate values |
| `spec/spec_helper.rb` | Runs before every test — ideal exfiltration point |
| `Gemfile` | Malicious or typosquatted gems |
| `Rakefile` | Code that runs on `require` or during test tasks |
| `.fixtures.yml` | Module source URLs redirected to attacker-controlled repos |
| `.github/**` | Workflow steps that directly access secrets |
| `CODEOWNERS` | Removal of legitimate reviewers |
| `metadata.json` | Source URL changes |

## Setup

### 1. Add the workflow files to your repo

Copy `.github/workflows/claude.yml` and `.github/scripts/ghost_guard_scan.rb` into your Puppet module repository.

### 2. Add the API key secret

In your repo: **Settings → Secrets and variables → Actions → New repository secret**

- Name: `ANTHROPIC_API_KEY`
- Value: your Anthropic API key

That's it. Ghost Guard will run automatically on the next fork PR.

## Requirements

- Ruby (available on all GitHub-hosted runners)
- `ANTHROPIC_API_KEY` repo secret
- `GITHUB_TOKEN` (provided automatically by GitHub Actions)

## Advisory only

Ghost Guard never blocks a merge or prevents tests from running. A human reviewer reads the output and decides. The scan covers only what appears in the unified diff — it does not execute any fork code.
