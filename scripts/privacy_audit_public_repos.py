#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


OWNER_DEFAULT = "subisle"
REPO_API = "https://api.github.com/user/repos"
GITHUB_API_VERSION = "2022-11-28"
REPORT_LIMIT = 200
ALLOWLIST_URL_PREFIXES = (
    "https://github.com/",
    "https://www.github.com/",
    "https://raw.githubusercontent.com/",
    "https://gist.github.com/",
    "https://t.me/",
    "https://telegram.me/",
    "https://discord.gg/",
    "https://discord.com/invite/",
)
BINARY_EXTENSIONS = {
    ".7z",
    ".bin",
    ".bz2",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".otf",
    ".pdf",
    ".png",
    ".so",
    ".tar",
    ".tgz",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}
GENERATED_CONTENT_PATHS: list[re.Pattern[str]] = [
    re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|Cargo\.lock|go\.sum)$", re.I),
    re.compile(r"(^|/)tsconfig.*\.tsbuildinfo$", re.I),
]

PATH_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("agent_instruction_path", "review", re.compile(r"(^|/)(AGENTS\.md|CLAUDE\.md|agent\.md)$", re.I)),
    ("agent_folder_path", "review", re.compile(r"(^|/)(\.claude|\.codex|\.codebuddy|\.clinerules)(/|$)", re.I)),
    ("skill_folder_path", "review", re.compile(r"(^|/)(skill|skills)(/|$)", re.I)),
    ("env_file_path", "high", re.compile(r"(^|/)\.env($|\.(local|prod|production|dev|development|test|staging)$)", re.I)),
    ("env_template_path", "review", re.compile(r"(^|/)\.env\.(example|sample|template)$", re.I)),
    ("credential_file_path", "high", re.compile(r"(^|/).*\.(pem|key|p12|pfx|kdbx|asc)$", re.I)),
    ("data_file_path", "review", re.compile(r"(^|/).*\.(db|sqlite|sqlite3|csv|tsv|xlsx|xls|jsonl|har|log|bak|backup|dump|sql|zip|tar|gz|tgz|bz2|7z)$", re.I)),
]

TEXT_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("private_key_block", "high", re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----")),
    ("github_token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai_style_key", "high", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("aws_access_key_id", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer_token", "high", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}\b")),
    ("jwt_token", "high", re.compile(r"(?<![A-Za-z0-9_-])eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}(?![A-Za-z0-9_-])")),
    ("database_url", "high", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp|amqps|sqlite|sqlserver|mssql)://\S+")),
    (
        "secret_assignment",
        "high",
        re.compile(
            r"(?ix)"
            r"\b(?:api[_-]?key|access[_-]?key|secret|token|private[_-]?key|password|passwd|auth|session|cookie|client[_-]?secret|webhook)\b"
            r"\s*[:=]\s*"
            r"(?:"
            r"(?P<quote>['\"])(?P<quoted>[^'\"]{8,})(?P=quote)"
            r"|(?P<bare>[A-Za-z0-9_./+=-]{16,})"
            r")"
        ),
    ),
    ("email_address", "high", re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w.+-])")),
    ("phone_number", "high", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("id_card_number", "high", re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("contact_label", "review", re.compile(r"(?i)(?:^|[\s\"'])(?:real[_ -]+name|full[_ -]+name|contact[_ -]+name|legal[_ -]+name|mobile|phone|email|wechat|weixin|qq|telegram|discord|whatsapp|line|twitter|instagram|facebook|bilibili|xiaohongshu|真实姓名|姓名|联系人|手机号|电话|邮箱|地址|住址|微信|微博|小红书)\s*[:：=]\s*[^\s,;；，]{2,64}")),
    ("reference_project", "review", re.compile(r"(?i)\b(?:forked from|copied from|derived from|reference project|mirror of)\b|\bbased on\s+(?:https?://|github\.com|[\w.-]+/[\w.-]+|the original project|项目|repo|repository)\b|\bupstream\s+(?:repo|repository|project|github|https?://)\b|参考项目|原项目|复制自|来自\s+\S+/\S+")),
]


@dataclasses.dataclass(frozen=True)
class Finding:
    repo: str
    source: str
    path: str
    line: int
    rule: str
    severity: str
    snippet: str


def github_token() -> str:
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "PROFILE_README_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    raise SystemExit("missing GITHUB_TOKEN, GH_TOKEN, or PROFILE_README_TOKEN")


def request_json(url: str, token: str) -> object:
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "subisle-public-repo-privacy-audit",
        },
    )
    with urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_public_repos(owner: str, token: str, limit: int | None = None) -> list[dict]:
    repos: list[dict] = []
    page = 1
    while True:
        url = REPO_API + "?" + urlencode(
            {
                "affiliation": "owner",
                "direction": "desc",
                "page": page,
                "per_page": 100,
                "sort": "pushed",
                "visibility": "public",
            }
        )
        batch = request_json(url, token)
        if not isinstance(batch, list):
            raise SystemExit("unexpected GitHub repository response")
        for repo in batch:
            if not isinstance(repo, dict):
                continue
            if repo.get("owner", {}).get("login") != owner:
                continue
            repos.append(repo)
            if limit is not None and len(repos) >= limit:
                return repos
        if len(batch) < 100:
            break
        page += 1
    return repos


def run_git(args: list[str], cwd: Path | None = None, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        input=input_text,
        capture_output=True,
    )


def mask_value(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return value[:1] + "*" * max(1, len(value) - 1)
    return value[:keep] + "*" * max(6, len(value) - (keep * 2)) + value[-keep:]


def redact_match(text: str, match: re.Match[str]) -> str:
    start, end = match.span()
    preview = text[:start] + "<redacted>" + text[end:]
    preview = re.sub(r"\s+", " ", preview).strip()
    return preview[:220]


def strip_allowlisted_text(text: str) -> str:
    cleaned = text
    for prefix in ALLOWLIST_URL_PREFIXES:
        cleaned = cleaned.replace(prefix, "__ALLOWLISTED_URL__")
    cleaned = re.sub(r"https?://(?:www\.)?github\.com/[^\s)>\]\"']+", "__ALLOWLISTED_URL__", cleaned, flags=re.I)
    cleaned = re.sub(r"https?://(?:raw\.githubusercontent\.com|githubusercontent\.com)/[^\s)>\]\"']+", "__ALLOWLISTED_URL__", cleaned, flags=re.I)
    cleaned = re.sub(r"[\w.+-]+@users\.noreply\.github\.com", "__ALLOWLISTED_EMAIL__", cleaned, flags=re.I)
    return cleaned


def scan_path(repo: str, path: str, source: str) -> list[Finding]:
    normalized = path.replace("\\", "/")
    findings: list[Finding] = []
    for rule, severity, pattern in PATH_RULES:
        if pattern.search(normalized):
            findings.append(
                Finding(
                    repo=repo,
                    source=source,
                    path=normalized,
                    line=1,
                    rule=rule,
                    severity=severity,
                    snippet=mask_value(normalized),
                )
            )
    return findings


def scan_text(repo: str, path: str, text: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    stripped = strip_allowlisted_text(text)
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        for rule, severity, pattern in TEXT_RULES:
            match = pattern.search(line)
            if match:
                if should_ignore_match(rule, match):
                    continue
                findings.append(
                    Finding(
                        repo=repo,
                        source=source,
                        path=path,
                        line=lineno,
                        rule=rule,
                        severity=severity,
                        snippet=redact_match(line, match),
                    )
                )
    return findings


def scan_text_with_rules(
    repo: str,
    path: str,
    text: str,
    source: str,
    rule_names: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    stripped = strip_allowlisted_text(text)
    selected_rules = [rule for rule in TEXT_RULES if rule[0] in rule_names]
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        for rule, severity, pattern in selected_rules:
            match = pattern.search(line)
            if match:
                if should_ignore_match(rule, match):
                    continue
                findings.append(
                    Finding(
                        repo=repo,
                        source=source,
                        path=path,
                        line=lineno,
                        rule=rule,
                        severity=severity,
                        snippet=redact_match(line, match),
                    )
                )
    return findings


def should_ignore_match(rule: str, match: re.Match[str]) -> bool:
    if rule != "secret_assignment":
        return False
    groups = match.groupdict()
    value = groups.get("quoted") or groups.get("bare") or ""
    normalized = value.strip().strip("'\"").lower()
    if normalized in {"your_password", "password", "changeme", "change_me", "example", "placeholder"}:
        return True
    if set(normalized) <= {"x"}:
        return True
    if groups.get("bare"):
        if "process.env" in normalized or "os.environ" in normalized or "import.meta.env" in normalized:
            return True
        if re.fullmatch(r"[a-z_][a-z0-9_.]*", normalized):
            return True
        if len(normalized) < 24:
            return True
        if not re.search(r"\d", normalized) and len(normalized) < 32:
            return True
    return False


def should_scan_blob(path: str, payload: bytes) -> bool:
    normalized = path.replace("\\", "/")
    for pattern in GENERATED_CONTENT_PATHS:
        if pattern.search(normalized):
            return False
    suffix = Path(path).suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return False
    if b"\x00" in payload[:4096]:
        return False
    return True


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, int, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.repo, finding.source, finding.path, finding.line, finding.rule, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def scan_historical_paths(repo: str, repo_dir: Path) -> list[Finding]:
    proc = run_git(["log", "--all", "--name-only", "--pretty=format:"], cwd=repo_dir)
    paths = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_path(repo, path, "history-path"))
    return findings


def scan_commit_metadata(repo: str, repo_dir: Path) -> list[Finding]:
    proc = run_git(["log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%s%x00%b%x00ENDCOMMIT"], cwd=repo_dir)
    findings: list[Finding] = []
    for record in proc.stdout.split("ENDCOMMIT"):
        record = record.strip("\n\x00")
        if not record:
            continue
        parts = record.split("\x00")
        if len(parts) < 7:
            continue
        commit, author_name, author_email, committer_name, committer_email, subject, body = parts[:7]
        blob = "\n".join(
            [
                f"commit: {commit}",
                f"author: {author_name} <{author_email}>",
                f"committer: {committer_name} <{committer_email}>",
                f"subject: {subject}",
                body,
            ]
        )
        findings.extend(
            scan_text_with_rules(
                repo,
                f"<commit:{commit[:12]}>",
                blob,
                "commit-metadata",
                {
                    "private_key_block",
                    "github_token",
                    "openai_style_key",
                    "aws_access_key_id",
                    "bearer_token",
                    "jwt_token",
                    "database_url",
                    "secret_assignment",
                    "email_address",
                    "phone_number",
                    "id_card_number",
                    "reference_project",
                },
            )
        )
    return findings


def scan_blob_contents(repo: str, repo_dir: Path) -> list[Finding]:
    rev_list = run_git(["rev-list", "--objects", "--all"], cwd=repo_dir)
    objects: dict[str, str] = {}
    for line in rev_list.stdout.splitlines():
        if not line.strip():
            continue
        sha, _, path = line.partition(" ")
        if path:
            objects.setdefault(sha, path)
    if not objects:
        return []

    # Shelling out once per object would be too slow; Git's batch protocol
    # streams each reachable object in one process.
    batch = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=str(repo_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert batch.stdin is not None
    assert batch.stdout is not None
    findings: list[Finding] = []
    for sha, path in objects.items():
        batch.stdin.write(f"{sha}\n".encode("ascii"))
        batch.stdin.flush()
        header_bytes = batch.stdout.readline()
        header = header_bytes.decode("ascii", errors="replace")
        if not header:
            break
        header = header.rstrip("\n")
        if header.endswith(" missing"):
            continue
        sha, obj_type, size_text = header.split(" ", 2)
        size = int(size_text)
        payload = batch.stdout.read(size)
        batch.stdout.read(1)
        if obj_type != "blob":
            continue
        path = objects.get(sha, f"<blob:{sha[:12]}>")
        if not should_scan_blob(path, payload):
            continue
        text = payload.decode("utf-8", errors="ignore")
        findings.extend(scan_text(repo, path, text, f"blob:{sha[:12]}"))

    batch.stdin.close()
    rc = batch.wait()
    if rc != 0:
        raise subprocess.CalledProcessError(rc, ["git", "cat-file", "--batch"])
    return findings


def scan_repository(repo: dict, workdir: Path) -> list[Finding]:
    full_name = repo["full_name"]
    clone_url = repo["clone_url"]
    target = workdir / full_name.replace("/", "__")
    run_git(["clone", "--mirror", "--quiet", clone_url, str(target)])
    findings: list[Finding] = []
    findings.extend(scan_historical_paths(full_name, target))
    findings.extend(scan_commit_metadata(full_name, target))
    findings.extend(scan_blob_contents(full_name, target))
    return dedupe_findings(findings)


def render_report(findings: list[Finding], scanned: list[str]) -> str:
    severity_order = {"high": 0, "review": 1}
    findings = sorted(
        findings,
        key=lambda item: (
            severity_order.get(item.severity, 9),
            item.repo,
            item.rule,
            item.path,
            item.line,
        ),
    )
    by_rule: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    for finding in findings:
        by_rule[finding.rule] += 1
        by_severity[finding.severity] += 1

    lines = [
        "# Public repository privacy audit",
        "",
        f"- Repositories scanned: `{len(scanned)}`",
        f"- Findings: `{len(findings)}`",
        f"- High: `{by_severity.get('high', 0)}`",
        f"- Review: `{by_severity.get('review', 0)}`",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.extend(["## Findings by rule", ""])
    for rule, count in sorted(by_rule.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- `{rule}`: `{count}`")
    lines.extend(["", f"## Findings (first {min(REPORT_LIMIT, len(findings))})", ""])
    for finding in findings[:REPORT_LIMIT]:
        lines.append(
            f"- `{finding.repo}` `{finding.source}` `{finding.path}:{finding.line}` "
            f"`{finding.rule}` `{finding.severity}` — {finding.snippet}"
        )
    omitted = len(findings) - REPORT_LIMIT
    if omitted > 0:
        lines.append(f"- `{omitted}` additional findings omitted from log output.")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit public repositories for leaked private data.")
    parser.add_argument("--owner", default=OWNER_DEFAULT, help="GitHub owner to audit")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of repositories to inspect")
    parser.add_argument("--dry-run", action="store_true", help="List repositories without cloning or scanning")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    token = github_token()
    repos = fetch_public_repos(args.owner, token, args.limit)

    if args.dry_run:
        for index, repo in enumerate(repos, start=1):
            print(f"{index}. {repo['full_name']} ({repo['html_url']})")
        return 0

    scanned: list[str] = []
    all_findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="privacy-audit-") as tmp:
        workdir = Path(tmp)
        for repo in repos:
            print(f"Scanning {repo['full_name']} ...", file=sys.stderr)
            scanned.append(repo["full_name"])
            all_findings.extend(scan_repository(repo, workdir))

    all_findings = dedupe_findings(all_findings)
    report = render_report(all_findings, scanned)
    print(report)
    if all_findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
