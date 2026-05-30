# Public Repository Privacy Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a daily GitHub Actions privacy audit for every public `subisle` repository, including forks, all branches, tags, and reachable history.

**Architecture:** A standalone Python script uses the GitHub API to list public repositories, mirror-clones each repository, scans historical paths, commit messages, and reachable blobs, then prints masked findings. A read-only GitHub Actions workflow runs the script every day and fails when findings are found.

**Tech Stack:** Python 3.11 standard library, Git CLI, GitHub REST API, GitHub Actions, `unittest`.

---

### Task 1: Add Scanner Tests

**Files:**
- Create: `tests/test_privacy_audit_public_repos.py`

- [ ] **Step 1: Write unit tests for masking, allowlist stripping, path rules, and content rules**

```python
def test_mask_value_keeps_context():
    value = audit.mask_value("maskable_value_abcdefghijklmnopqrstuvwxyz1234567890")
    assert value.startswith("mask")
    assert "*" in value

def test_allowed_github_url_is_stripped_before_matching():
    line = "homepage = https://github.com/subisle/demo"
    stripped = audit.strip_allowlisted_text(line)
    assert "github.com" not in stripped

def test_agent_path_is_review_finding():
    findings = audit.scan_path("AGENTS.md")
    assert findings[0].rule == "agent_instruction_path"

def test_secret_assignment_is_high_finding():
    findings = audit.scan_text("config.py", "TOKEN = 'abc1234567890abc1234567890'", "blob")
    assert any(item.rule == "secret_assignment" and item.severity == "high" for item in findings)
```

- [ ] **Step 2: Run tests and confirm they fail before implementation**

Run: `python3 -m unittest discover -s tests -v`
Expected: import or attribute failures before `scripts/privacy_audit_public_repos.py` exists.

### Task 2: Implement the Scanner

**Files:**
- Create: `scripts/privacy_audit_public_repos.py`

- [ ] **Step 1: Implement scanner data structures and rules**

```python
@dataclass(frozen=True)
class Finding:
    repo: str
    source: str
    path: str
    line: int
    rule: str
    severity: str
    snippet: str
```

- [ ] **Step 2: Implement GitHub API repository listing**

Run: `python3 scripts/privacy_audit_public_repos.py --owner subisle --limit 1 --dry-run`
Expected: prints the first public repository name without cloning or findings.

- [ ] **Step 3: Implement mirror clone and Git scanning**

Use `git clone --mirror` for each repository. Use `git log --all --name-only --pretty=format:` for historical paths, `git log --all --format=%H%x00%B%x00END_COMMIT%x00` for commit messages, and `git rev-list --objects --all` plus `git cat-file -p` for reachable blob contents.

- [ ] **Step 4: Implement masked Markdown reporting and non-zero exit on findings**

Run: `python3 scripts/privacy_audit_public_repos.py --owner subisle --limit 1`
Expected: prints a summary and exits `1` when findings exist, otherwise exits `0`.

### Task 3: Add Daily GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/privacy-audit.yml`

- [ ] **Step 1: Add workflow**

```yaml
name: Public repository privacy audit

on:
  workflow_dispatch:
  schedule:
    - cron: "17 2 * * *"

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python scripts/privacy_audit_public_repos.py --owner subisle
        env:
          GITHUB_TOKEN: ${{ secrets.PROFILE_README_TOKEN || github.token }}
```

- [ ] **Step 2: Verify workflow syntax is plain YAML and does not require write permissions**

Run: `sed -n '1,160p' .github/workflows/privacy-audit.yml`
Expected: workflow has only `contents: read`.

### Task 4: Verify and Commit

**Files:**
- Modify: repository git index only.

- [ ] **Step 1: Run unit tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all tests pass.

- [ ] **Step 2: Run Python syntax check**

Run: `python3 -m py_compile scripts/privacy_audit_public_repos.py tests/test_privacy_audit_public_repos.py`
Expected: exit code `0`.

- [ ] **Step 3: Run dry-run**

Run: `python3 scripts/privacy_audit_public_repos.py --owner subisle --limit 1 --dry-run`
Expected: lists one repository and exits `0`.

- [ ] **Step 4: Check diff for secrets**

Run: `git diff --check && git diff --stat`
Expected: no whitespace errors; only planned files changed.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/privacy-audit.yml scripts/privacy_audit_public_repos.py tests/test_privacy_audit_public_repos.py docs/superpowers/specs/2026-05-30-public-repo-privacy-audit-design.md docs/superpowers/plans/2026-05-30-public-repo-privacy-audit.md
git commit -m "🐳 chore: 添加公开仓库隐私巡检"
```
