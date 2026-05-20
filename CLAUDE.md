# Ghost Guard Skill Design

**Date:** 2026-05-20
**Status:** Approved

## Purpose

A Claude Code skill that scaffolds and manages a GitHub Actions workflow providing advisory security scanning of fork PRs in a Puppet module repository. The scan helps reviewers decide whether it is safe to trigger acceptance tests on a fork PR — specifically, whether the diff contains code that could exfiltrate CI secrets during test execution.

The scan is advisory only. It never blocks merges or test runs. A human reviewer reads the output and decides.

## Threat Model

**Attacker:** External fork contributor submitting a PR.

**Attack surface:** Code that runs during acceptance test execution and could leak CI secrets or credentials.

**Relevant files and their risks:**

| File | Risk vector |
|---|---|
| `spec/**` | RSpec hooks/helpers that read `ENV` vars and exfiltrate them (e.g., HTTP POST to external host) |
| `spec/spec_helper.rb` | Runs before every test — ideal exfiltration point |
| `Gemfile` | Malicious or typosquatted gem that executes on `bundle install` or `require` |
| `Rakefile` | Code that runs on `require`; tasks invoked during test runs |
| `.fixtures.yml` | Module source URLs redirected to attacker-controlled repos, pulled during `spec_prep` |
| `.github/**` | Workflow steps that directly access secrets |
| `CODEOWNERS` | Removal of legitimate reviewers (lower weight — does not affect test execution directly) |
| `metadata.json` | Source URL changes (lower weight — does not affect test execution directly) |

## Architecture

The skill writes two files and documents one required secret. It does not check out or execute any fork code.

```
.github/
  workflows/
    ghost-guard-scan.yml     # Trigger, permissions, env wiring
  scripts/
    ghost_guard_scan.rb      # Diff fetch -> Claude analysis -> PR comment
```

**Required secret:** `ANTHROPIC_API_KEY` — configured in repo Settings > Secrets and variables > Actions.

The skill file is the source of truth. Re-invoking the skill regenerates (overwrites) both files with the latest version.

## Workflow Design

**File:** `.github/workflows/ghost-guard-scan.yml`

**Trigger:** `pull_request_target` on `opened`, `synchronize`, `reopened`.

**Fork filter:** Job runs only when `github.event.pull_request.head.repo.fork == true`. Internal branch PRs skip the job entirely.

**Permissions:**
```yaml
permissions:
  pull-requests: write   # post and update PR comments
  contents: read         # read PR metadata via API
```

**Steps:**
1. Run `ruby .github/scripts/ghost_guard_scan.rb` — the script owns all API calls (diff fetch, Claude analysis, comment post/update)

No checkout step is present. The workflow passes these environment variables to the script: `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `PR_NUMBER`, `REPO` (owner/repo slug).

## Ruby Script Design

**File:** `.github/scripts/ghost_guard_scan.rb`

Three methods:

### `fetch_diff`
Uses `GITHUB_TOKEN` and `PR_NUMBER` to GET the unified diff from the GitHub API. Returns the raw diff string.

### `analyze_diff(diff)`
Builds a Claude API request using `claude-sonnet-4-6`, `max_tokens: 2048`.

**Prompt instructs Claude to:**
- Understand context: Puppet module repo, fork PR, threat model is secret leakage during acceptance test execution
- Reason about each changed high-scrutiny file using the risk vectors defined in the threat model above
- Assign a risk level (one of four values — see below)
- Produce structured output only: risk level, one-line summary, and findings as `file:line — explanation`

**Risk levels:**
- `no_concerns` — no suspicious changes, routine updates
- `minor` — touches a high-scrutiny file but change is clearly explainable (e.g., bump a gem version)
- `needs_scrutiny` — ambiguous but potentially dangerous (e.g., new gem added, modified CI step)
- `high` — clear indicators: secret access in CI, network exfiltration pattern, backdoor, source redirect

### `find_or_update_comment(body)`
Lists PR comments, finds one containing `<!-- ghost-guard-scan -->`. If found, PATCH to update. Otherwise POST a new comment.

## PR Comment Format

```
<!-- ghost-guard-scan -->
## Ghost Guard Advisory Scan

**Risk:** [emoji] [Label]

**Summary:** [one-line summary from Claude]

**Findings:**
- `file:line` — explanation
- `file:line` — explanation

---
> Advisory only — not a substitute for human review. This scan helps assess whether it is safe to trigger acceptance tests on this fork PR.
```

**Risk label mapping** (rendered in the `**Risk:**` line):
- `no_concerns` → `No concerns identified`
- `minor` → `Minor — low risk, review recommended`
- `needs_scrutiny` → `Needs scrutiny before running tests`
- `high` → `High — do not trigger tests without careful review`

When risk is `no_concerns` and Claude returns no findings, the Findings section is replaced with: `No specific findings.`

## Skill Structure

The skill (`ghost-guard.md`) lives in the Claude Code skills directory. When invoked it:

1. Announces what it will create
2. Writes `.github/workflows/ghost-guard-scan.yml`
3. Writes `.github/scripts/ghost_guard_scan.rb`
4. Reminds the user to add `ANTHROPIC_API_KEY` to repo secrets
5. Summarises what was created

The skill handles both first-time setup and updates (re-running overwrites existing files).

## Out of Scope

- Blocking PRs or test runs automatically
- Scanning non-fork PRs
- Checking out or executing any fork code
- Static pattern matching (analysis is entirely AI-driven)
- Any analysis beyond what appears in the unified diff
