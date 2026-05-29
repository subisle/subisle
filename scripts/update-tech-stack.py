#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
OWNER = "subisle"
TECH_START = "<!-- TECH_STACK:START -->"
TECH_END = "<!-- TECH_STACK:END -->"
PROJECTS_START = "<!-- PUBLIC_PROJECTS:START -->"
PROJECTS_END = "<!-- PUBLIC_PROJECTS:END -->"

EXCLUDED_LANGUAGES = {
    "BibTeX Style",
    "Makefile",
    "MDX",
    "PowerShell",
    "Batchfile",
    "TeX",
}

LANGUAGE_ALIASES = {
    "Dockerfile": "Docker",
}

LANGUAGE_META = {
    "Astro": {"logo": "astro", "color": "FF5D01"},
    "CSS": {"logo": "css3", "color": "1572B6"},
    "Docker": {"logo": "docker", "color": "2496ED"},
    "Go": {"logo": "go", "color": "00ADD8"},
    "HTML": {"logo": "html5", "color": "E34F26"},
    "JavaScript": {"logo": "javascript", "color": "F7DF1E", "logoColor": "black"},
    "Kotlin": {"logo": "kotlin", "color": "7F52FF"},
    "Python": {"logo": "python", "color": "3776AB"},
    "Rust": {"logo": "rust", "color": "000000"},
    "Shell": {"logo": "gnu-bash", "color": "89E051"},
    "TypeScript": {"logo": "typescript", "color": "3178C6"},
    "Vue": {"logo": "vuedotjs", "color": "4FC08D"},
}

PRIMARY_LANGUAGE_ORDER = [
    "Python",
    "TypeScript",
    "JavaScript",
    "Go",
    "Kotlin",
    "Vue",
    "Astro",
    "Rust",
    "HTML",
    "CSS",
    "Shell",
    "Docker",
]


def github_token() -> str:
    for key in ("PROFILE_README_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    raise SystemExit("missing PROFILE_README_TOKEN, GITHUB_TOKEN, or GH_TOKEN")


def request_json(url: str, token: str) -> object:
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "subisle-profile-readme-updater",
        },
    )
    with urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_repo_languages(repo: dict, token: str) -> dict[str, int]:
    data = request_json(repo["languages_url"], token)
    if not isinstance(data, dict):
        return {}
    return {str(name): int(bytes_count) for name, bytes_count in data.items()}


def fetch_all_repos(token: str) -> list[dict]:
    repos: list[dict] = []
    page = 1
    while True:
        url = (
            "https://api.github.com/user/repos?"
            + urlencode(
                {
                    "affiliation": "owner",
                    "direction": "desc",
                    "page": page,
                    "per_page": 100,
                    "sort": "pushed",
                }
            )
        )
        batch = request_json(url, token)
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return repos


def collect_language_bytes(repos: list[dict], token: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for repo in repos:
        for language, bytes_count in fetch_repo_languages(repo, token).items():
            language = LANGUAGE_ALIASES.get(language, language)
            if not language or language in EXCLUDED_LANGUAGES:
                continue
            counts[language] += bytes_count
    return counts


def badge_for_language(language: str) -> str:
    meta = LANGUAGE_META.get(language)
    label = language.replace(" ", "%20")
    if meta is None:
        return (
            f'<img alt="{language}" '
            f'src="https://img.shields.io/badge/-{label}-555555?style=flat-square" />'
        )
    params = [f"style=flat-square", f"logo={meta['logo']}", f"color={meta['color']}"]
    if "logoColor" in meta:
        params.append(f"logoColor={meta['logoColor']}")
    query = "&".join(params)
    return (
        f'<img alt="{language}" '
        f'src="https://img.shields.io/badge/-{label}-{meta["color"]}?{query}" />'
    )


def render_badges(languages: Iterable[str]) -> str:
    badges = [badge_for_language(language) for language in languages]
    return "<p align=\"center\">\n  " + " ".join(badges) + "\n</p>"


def parse_languages(counts: Counter[str]) -> list[str]:
    ordered: list[str] = []
    for language in PRIMARY_LANGUAGE_ORDER:
        if language in counts:
            ordered.append(language)

    extras = sorted(
        (language for language in counts if language not in ordered),
        key=lambda language: (-counts[language], language.lower()),
    )
    ordered.extend(extras)
    return ordered


def render_projects(repos: list[dict]) -> str:
    public_repos = [
        repo
        for repo in repos
        if not repo.get("private")
        and not repo.get("fork")
        and repo.get("name") != OWNER
        and repo.get("html_url")
    ]
    public_repos.sort(key=lambda repo: repo.get("pushed_at") or "", reverse=True)
    rows = []
    for repo in public_repos[:4]:
        name = repo["name"]
        url = repo["html_url"]
        language = repo.get("language")
        description = (repo.get("description") or "").strip()
        if not description and "docs" in name.lower():
            description = "文档与资料整理"
        parts = []
        if description:
            parts.append(description)
        if language:
            parts.append(f"`{language}`")
        if not parts:
            parts.append("近期公开项目")
        rows.append(f"- [{name}]({url}) — " + " · ".join(parts))
    if not rows:
        rows.append("- 暂无公开项目")
    return "\n".join(rows)


def replace_block(text: str, start: str, end: str, replacement: str) -> str:
    start_index = text.find(start)
    end_index = text.find(end)
    if start_index == -1 or end_index == -1 or end_index < start_index:
        raise SystemExit(f"missing markers: {start} / {end}")
    start_line_end = text.find("\n", start_index)
    end_line_start = text.rfind("\n", 0, end_index)
    if start_line_end == -1 or end_line_start == -1 or end_line_start < start_line_end:
        raise SystemExit(f"invalid marker layout: {start} / {end}")
    return text[: start_line_end + 1] + replacement + text[end_line_start:]


def main() -> int:
    token = github_token()
    repos = fetch_all_repos(token)

    tech_counts = collect_language_bytes(repos, token)
    tech_section = render_badges(parse_languages(tech_counts))
    projects_section = render_projects(repos)

    readme = README.read_text(encoding="utf-8")
    readme = replace_block(readme, TECH_START, TECH_END, tech_section)
    readme = replace_block(readme, PROJECTS_START, PROJECTS_END, projects_section)
    README.write_text(readme, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
