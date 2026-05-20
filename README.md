# Ghost Guard

Advisory security scanner for fork PRs in Puppet module repositories, powered by Claude.

When a contributor forks your repo and opens a PR, Ghost Guard fetches the unified diff and asks Claude to assess whether it is safe to trigger acceptance tests. It posts a structured comment on the PR — a human reviewer reads it and decides. Nothing is blocked automatically.

## How it works

1. A fork PR is opened or pushed to in your repo
2. Your caller workflow fires on `pull_request_target` and calls this reusable workflow
3. `ghost_guard_scan.rb` fetches the unified diff from the GitHub API (no fork code is checked out)
4. The diff is sent to `claude-sonnet-4-6` with a structured threat-model prompt
5. Claude returns a risk verdict and findings as JSON
6. The script posts or updates an advisory comment on the PR

## Adding Ghost Guard to your repo

### 1. Add the caller workflow

Create `.github/workflows/ghost-guard.yml` in your Puppet module repo:

```yaml
name: Ghost Guard

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  ghost-guard:
    if: github.event.pull_request.head.repo.fork == true
    uses: danielmackle/ghost-guard/.github/workflows/claude.yml@main
    with:
      pr_number: ${{ github.event.pull_request.number }}
      repo: ${{ github.repository }}
    secrets:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

> **Important:** Use `pull_request_target`, not `pull_request`. Only `pull_request_target` has access to repo secrets for fork PRs. The `if:` condition ensures the scan only runs for PRs from forks — internal branch PRs are skipped.

### 2. Add the API key secret

In your repo: **Settings → Secrets and variables → Actions → New repository secret**

| Name | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |

`GITHUB_TOKEN` is provided automatically by GitHub Actions — no configuration needed.

That's it. Ghost Guard will run on the next fork PR.

## Risk levels

| Level | When |
|---|---|
| ✅ No concerns | No suspicious changes; routine updates |
| 🟡 Minor | Touches a high-scrutiny file but the change is clearly explainable |
| ⚠️ Needs scrutiny | Ambiguous — verify before triggering acceptance tests |
| 🚨 High | Clear indicators: secret access, network exfiltration, backdoor, source redirect |

## High-scrutiny files

| File | Risk vector |
|---|---|
| `spec/**` | RSpec hooks that read `ENV` and exfiltrate values |
| `spec/spec_helper.rb` | Runs before every test — the most common exfiltration point |
| `Gemfile` | Malicious or typosquatted gems that execute on `bundle install` or `require` |
| `Rakefile` | Code that runs on `require` or during test tasks |
| `.fixtures.yml` | Module source URLs redirected to attacker-controlled repos |
| `.github/**` | Workflow steps that directly access secrets |
| `CODEOWNERS` | Removal of legitimate reviewers |
| `metadata.json` | Source URL changes |

## Requirements

- Your repo must be on GitHub (public or private)
- `ANTHROPIC_API_KEY` secret added to your repo's Actions secrets
- GitHub-hosted runner (`ubuntu-latest`) — Ruby is pre-installed, no extra dependencies

## Security properties

- **Fork code is never checked out or executed.** The scan fetches only the unified diff text via the GitHub API.
- **`pull_request_target` runs in the base repo context**, so secrets are available and safe from fork code.
- **This repo must remain public** for cross-repo `workflow_call` to work without a personal access token.
- The scan is advisory only — it never blocks a merge or prevents tests from running.
