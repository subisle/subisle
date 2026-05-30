# Public Repository Privacy Audit Design

## Outcome

Create a daily GitHub Actions audit that checks every public repository owned by `subisle`, including forks, all remote branches, tags, and reachable Git history. The audit reports likely private data or non-project artifacts in the workflow log and fails the run when findings exist. It does not modify audited repositories and does not create GitHub issues.

## Scope

The audit covers:

- Public repositories returned by the GitHub API for the authenticated `subisle` account.
- Forks and source repositories owned by the account.
- All refs fetched by `git clone --mirror`, including remote branches and tags.
- Historical paths, reachable blobs, and commit messages.

The audit intentionally does not scan private repositories, unrelated local directories, OS credential stores, browser profiles, or personal files outside the checked-out repositories.

## Detection Model

Findings are split into two severities:

- `high`: values that should not appear in public repositories, such as private keys, API tokens, session cookies, database URLs, `.env` files, credentials, phone numbers, emails, and sensitive data files.
- `review`: items that may be legitimate but should be checked, such as personal/contact labels, social-account fields, project-copy phrases, upstream/reference traces, and local agent or skill files.

The scanner reports only repository, ref/commit or object, file path, line number, rule name, severity, and a masked snippet. It must not print full matched secrets or personal values.

## Rule Groups

Path rules flag:

- Agent and assistant files: `AGENTS.md`, `CLAUDE.md`, `agent.md`, `.claude/`, `.codex/`, `.codebuddy/`, `.clinerules/`, `skill/`, `skills/`.
- Secret/config files: `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.npmrc`, `.pypirc`, cloud credential files.
- Data and local artifacts: `*.sqlite`, `*.db`, `*.csv`, `*.tsv`, `*.xlsx`, `*.xls`, `*.jsonl`, `*.har`, logs, backups, dumps, archives.

Content rules flag:

- Private key blocks, GitHub/OpenAI/Cloudflare style tokens, generic `token/secret/password/api_key` assignments.
- Database or cache connection strings.
- JWTs, cookies, sessions, webhooks, and authorization headers.
- Email addresses, mainland China mobile phone numbers, likely ID-card numbers.
- Address/contact lines, Chinese/English name labels, WeChat/QQ/Telegram/Discord/WhatsApp/LINE/social account labels.
- Reference-project phrases such as "forked from", "based on", "copied from", "upstream", "参考", "来自", "原项目".

Allowlist behavior:

- GitHub URLs and raw GitHub asset URLs are treated as public by default.
- Explicit public channels can be added to the allowlist later.
- Allowed snippets are removed before rule matching so they do not produce alerts.

## Workflow

`.github/workflows/privacy-audit.yml` runs daily and on manual dispatch. It uses read-only repository permissions and passes `GITHUB_TOKEN` to the script for API access.

The script:

1. Fetches public repositories for `subisle` with the GitHub API.
2. Mirror-clones each repository into a temporary directory.
3. Scans historical file paths.
4. Scans commit messages.
5. Scans all reachable blob contents once.
6. Prints a compact Markdown summary.
7. Exits with status `1` when findings exist.

## Verification

Local verification uses only standard Python and Git:

- `python3 -m unittest discover -s tests -v`
- `python3 -m py_compile scripts/privacy_audit_public_repos.py`
- `python3 scripts/privacy_audit_public_repos.py --owner subisle --limit 1 --dry-run`

Live verification can run with `GH_TOKEN` or `GITHUB_TOKEN` set. The output must not expose token values.
