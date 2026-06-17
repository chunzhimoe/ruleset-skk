#!/usr/bin/env python3
"""Sync aggregated Clash rules from Sukka's ruleset server."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SUKKA_BASE = "https://ruleset.skk.moe/Clash"
BLACKMATRIX_BASE = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash"
)

STREAM_NAMES = (
    "stream",
    "stream_biliintl",
    "stream_eu",
    "stream_hk",
    "stream_jp",
    "stream_kr",
    "stream_tw",
    "stream_us",
)

CLASSICAL_PREFIXES = {
    "AND",
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-SUFFIX",
    "DOMAIN-WILDCARD",
    "DST-PORT",
    "GEOIP",
    "GEOSITE",
    "IN-PORT",
    "IN-TYPE",
    "IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "NETWORK",
    "NOT",
    "OR",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "RULE-SET",
    "SRC-IP-CIDR",
    "SRC-PORT",
    "USER-AGENT",
    "URL-REGEX",
}

OPENAI_MARKERS = (
    "openai",
    "chatgpt",
    "oaistatic",
    "oaiusercontent",
    "sora.com",
    "chat.com",
    "ai.com",
)
CLAUDE_MARKERS = ("anthropic", "claude")
GROK_MARKERS = ("grok", "x.ai")

# Grok: hand-maintained only (no Sukka / blackmatrix7 sync).
GROK_STATIC_RULES: tuple[str, ...] = (
    "DOMAIN-SUFFIX,grok.com",
    "DOMAIN-SUFFIX,cdn.grok.com",
    "DOMAIN-SUFFIX,x.ai",
    "DOMAIN-SUFFIX,cdn.cookielaw.org",
    "DOMAIN,js.stripe.com",
    "DOMAIN-SUFFIX,static.cloudflareinsights.com",
)


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    behavior: str = "classical"
    output_behavior: str | None = None
    allow_empty: bool = False


@dataclass
class ParsedSource:
    source: Source
    comments: list[str]
    rules: list[str]
    last_updated: str | None
    sha256: str


@dataclass(frozen=True)
class OutputSpec:
    name: str
    behavior: str
    sources: tuple[Source, ...]
    rule_filter: tuple[str, ...] = ()
    source_filters: tuple[tuple[str, tuple[str, ...]], ...] = ()
    source_excludes: tuple[tuple[str, tuple[str, ...]], ...] = ()


def sukka(kind: str, name: str, behavior: str = "classical") -> Source:
    return Source(f"sukka:{kind}/{name}.txt", f"{SUKKA_BASE}/{kind}/{name}.txt", behavior)


def sukka_domain_as_classical(name: str) -> Source:
    return Source(
        f"sukka:domainset/{name}.txt",
        f"{SUKKA_BASE}/domainset/{name}.txt",
        "domain",
        "classical",
    )


def blackmatrix(service: str, file_name: str) -> Source:
    return Source(
        f"blackmatrix7:{service}",
        f"{BLACKMATRIX_BASE}/{service}/{file_name}.list",
        "classical",
    )


OPENAI_SOURCE = blackmatrix("OpenAI", "OpenAI")
CLAUDE_SOURCE = blackmatrix("Claude", "Claude")
SUKKA_AI_SOURCE = sukka("non_ip", "ai")


OUTPUTS: tuple[OutputSpec, ...] = (
    OutputSpec(
        "reject",
        "domain",
        (
            sukka("domainset", "reject", "domain"),
            sukka("domainset", "reject_extra", "domain"),
            sukka("domainset", "reject_phishing", "domain"),
            Source(
                "sukka:domainset/reject_sukka.txt",
                f"{SUKKA_BASE}/domainset/reject_sukka.txt",
                "domain",
                None,
                True,
            ),
        ),
    ),
    OutputSpec(
        "apple",
        "classical",
        (
            sukka("non_ip", "apple_services"),
            sukka("non_ip", "apple_cn"),
            sukka_domain_as_classical("apple_cdn"),
            sukka("non_ip", "apple_intelligence"),
            sukka("ip", "apple_services"),
        ),
    ),
    OutputSpec(
        "microsoft",
        "classical",
        (
            sukka("non_ip", "microsoft"),
            sukka("non_ip", "microsoft_cdn"),
        ),
    ),
    OutputSpec("telegram", "classical", (sukka("non_ip", "telegram"),)),
    OutputSpec(
        "telegramcidr",
        "classical",
        (
            sukka("ip", "telegram"),
            sukka("ip", "telegram_asn"),
        ),
    ),
    OutputSpec(
        "streaming",
        "classical",
        tuple(sukka("non_ip", name) for name in STREAM_NAMES),
    ),
    OutputSpec(
        "streamingip",
        "classical",
        tuple(sukka("ip", name) for name in STREAM_NAMES),
    ),
    OutputSpec("global", "classical", (sukka("non_ip", "global"),)),
    OutputSpec("domestic", "classical", (sukka("non_ip", "domestic"),)),
    OutputSpec("direct", "classical", (sukka("non_ip", "direct"),)),
    OutputSpec("lan", "classical", (sukka("non_ip", "lan"),)),
    OutputSpec("lancidr", "classical", (sukka("ip", "lan"),)),
    OutputSpec(
        "ai",
        "classical",
        (SUKKA_AI_SOURCE, OPENAI_SOURCE, CLAUDE_SOURCE),
        source_excludes=((SUKKA_AI_SOURCE.url, GROK_MARKERS),),
    ),
    OutputSpec(
        "openai",
        "classical",
        (OPENAI_SOURCE, SUKKA_AI_SOURCE),
        OPENAI_MARKERS,
    ),
    OutputSpec(
        "claude",
        "classical",
        (CLAUDE_SOURCE, SUKKA_AI_SOURCE),
        CLAUDE_MARKERS,
    ),
)

PROVIDER_ORDER = (
    "lan",
    "lancidr",
    "reject",
    "openai",
    "claude",
    "grok",
    "telegram",
    "telegramcidr",
    "streaming",
    "streamingip",
    "apple",
    "microsoft",
    "global",
    "domestic",
    "direct",
)

RULE_LINES = (
    "  - RULE-SET,lan,DIRECT",
    "  - RULE-SET,lancidr,DIRECT",
    "  - RULE-SET,reject,\U0001f6d1 \u5e7f\u544a\u62e6\u622a",
    "  - RULE-SET,openai,\U0001f9f2 OpenAI",
    "  - RULE-SET,claude,\U0001f9e9 Claude",
    "  - RULE-SET,grok,\U0001f916 Grok",
    "  - RULE-SET,telegram,\U0001f4f2 \u7535\u62a5\u4fe1\u606f",
    "  - RULE-SET,telegramcidr,\U0001f4f2 \u7535\u62a5\u4fe1\u606f",
    "  - RULE-SET,streaming,\U0001f3ac \u6d41\u5a92\u4f53",
    "  - RULE-SET,streamingip,\U0001f3ac \u6d41\u5a92\u4f53",
    "  - RULE-SET,apple,\U0001f34e \u82f9\u679c\u670d\u52a1",
    "  - RULE-SET,microsoft,\u24c2\ufe0f \u5fae\u8f6f\u670d\u52a1",
    "  - RULE-SET,global,\U0001f680 \u8282\u70b9\u9009\u62e9",
    "  - RULE-SET,domestic,\U0001f3af \u56fd\u5185\u76f4\u8fde",
    "  - RULE-SET,direct,\U0001f3af \u56fd\u5185\u76f4\u8fde",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="ruleset",
        help="Directory for generated rule files.",
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Directory for generated Clash config snippets.",
    )
    parser.add_argument(
        "--github-repository",
        default=os.environ.get("GITHUB_REPOSITORY") or discover_github_repository(),
        help="GitHub repository in owner/name form for raw URLs.",
    )
    parser.add_argument(
        "--branch",
        default=(
            os.environ.get("GITHUB_REF_NAME")
            or os.environ.get("DEFAULT_BRANCH")
            or discover_git_branch()
            or "main"
        ),
        help="Branch name for raw.githubusercontent.com URLs.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Download and validate sources without writing files.",
    )
    parser.add_argument(
        "--skip-config",
        action="store_true",
        help="Do not generate the Clash config snippet.",
    )
    return parser.parse_args()


def discover_github_repository() -> str | None:
    remote = run_git("config", "--get", "remote.origin.url")
    if not remote:
        return None

    patterns = (
        r"github\.com[:/](?P<repo>[^/]+/[^/.]+)(?:\.git)?$",
        r"https://github\.com/(?P<repo>[^/]+/[^/.]+)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.search(pattern, remote)
        if match:
            return match.group("repo")
    return None


def discover_git_branch() -> str | None:
    return run_git("branch", "--show-current")


def run_git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ("git", *args),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    value = result.stdout.strip()
    return value or None


def fetch_text(source: Source, timeout: int, attempts: int = 3) -> str:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = Request(
                source.url,
                headers={
                    "User-Agent": "clashrule-sync/1.0 (+https://github.com/)",
                    "Accept": "text/plain,*/*",
                },
            )
            with urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", response.getcode())
                if status != 200:
                    raise RuntimeError(f"unexpected HTTP status {status}")
                raw = response.read()
            text = raw.decode("utf-8-sig")
            if not text.strip():
                raise RuntimeError("empty response")
            return normalize_newlines(text)
        except (HTTPError, URLError, TimeoutError, RuntimeError, UnicodeError) as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(attempt)
    raise RuntimeError(f"failed to fetch {source.url}: {last_error}") from last_error


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def parse_source(source: Source, text: str) -> ParsedSource:
    comments: list[str] = []
    rules: list[str] = []
    last_updated: str | None = None

    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if is_eof_marker(line):
            continue
        if line.startswith("#"):
            comments.append(line)
            last_updated = last_updated or parse_last_updated(line)
            continue
        validate_rule_line(source, line, line_number)
        rules.append(convert_rule(source, line))

    if not rules and not is_allowed_empty_source(source, comments):
        raise RuntimeError(f"{source.url} contains no rules")

    return ParsedSource(
        source=source,
        comments=comments,
        rules=rules,
        last_updated=last_updated,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def parse_last_updated(line: str) -> str | None:
    match = re.search(r"Last Updated:\s*(\S+)", line, re.IGNORECASE)
    return match.group(1) if match else None


def is_eof_marker(line: str) -> bool:
    normalized = line.strip("# ").lower()
    return normalized == "eof"


def validate_rule_line(source: Source, line: str, line_number: int) -> None:
    if "\t" in line or line != line.strip():
        raise RuntimeError(f"{source.url}:{line_number}: invalid surrounding whitespace")

    if source.behavior == "domain":
        if any(char.isspace() for char in line):
            raise RuntimeError(f"{source.url}:{line_number}: domain rule contains whitespace")
        if "," in line:
            raise RuntimeError(f"{source.url}:{line_number}: domainset rule must not use commas")
        return

    prefix = line.split(",", 1)[0].upper()
    if prefix not in CLASSICAL_PREFIXES:
        raise RuntimeError(f"{source.url}:{line_number}: unsupported rule prefix {prefix!r}")

    if prefix in {"IP-CIDR", "IP-CIDR6"}:
        parts = line.split(",")
        if len(parts) < 2:
            raise RuntimeError(f"{source.url}:{line_number}: missing CIDR value")
        if "/" not in parts[1]:
            raise RuntimeError(f"{source.url}:{line_number}: invalid CIDR value {parts[1]!r}")


def convert_rule(source: Source, line: str) -> str:
    if source.behavior == "domain" and source.output_behavior == "classical":
        if line.startswith("+."):
            return f"DOMAIN-SUFFIX,{line[2:]}"
        if line.startswith("."):
            return f"DOMAIN-SUFFIX,{line[1:]}"
        return f"DOMAIN,{line}"
    return line


def is_allowed_empty_source(source: Source, comments: list[str]) -> bool:
    if not source.allow_empty and not source.output_behavior:
        return False
    comment_text = "\n".join(comments).lower()
    return "deprecated" in comment_text or "merged with" in comment_text


def dedupe_rules(parsed_sources: Iterable[ParsedSource], markers: tuple[str, ...]) -> list[tuple[ParsedSource, list[str]]]:
    return dedupe_rules_with_source_filters(parsed_sources, markers, {}, {})


def dedupe_rules_with_source_filters(
    parsed_sources: Iterable[ParsedSource],
    markers: tuple[str, ...],
    source_filters: dict[str, tuple[str, ...]],
    source_excludes: dict[str, tuple[str, ...]] | None = None,
) -> list[tuple[ParsedSource, list[str]]]:
    seen: set[str] = set()
    sections: list[tuple[ParsedSource, list[str]]] = []
    excludes = source_excludes or {}

    for parsed in parsed_sources:
        source_rules: list[str] = []
        effective_markers = source_filters.get(parsed.source.url, markers)
        exclude_markers = excludes.get(parsed.source.url, ())
        for rule in parsed.rules:
            if exclude_markers and matches_any_marker(rule, exclude_markers):
                continue
            if effective_markers and not matches_any_marker(rule, effective_markers):
                continue
            if rule in seen:
                continue
            seen.add(rule)
            source_rules.append(rule)
        if source_rules:
            sections.append((parsed, source_rules))
    return sections


def matches_any_marker(rule: str, markers: tuple[str, ...]) -> bool:
    rule_lower = rule.lower()
    return any(marker in rule_lower for marker in markers)


def render_static_grok() -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        "#########################################",
        "# Clash ruleset: grok",
        "# Generated by scripts/sync_sukka_rules.py",
        f"# Generated at: {now}",
        "# Behavior: classical",
        "#",
        "# Sources: static (hand-maintained; not synced from Sukka or blackmatrix7)",
        "#########################################",
        "",
        "# ---- Static Grok / xAI ----",
    ]
    lines.extend(GROK_STATIC_RULES)
    lines.extend(("", "################## EOF ##################", ""))
    return "\n".join(lines)


def render_output(spec: OutputSpec, sections: list[tuple[ParsedSource, list[str]]]) -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    source_last_updated = max(
        (parsed.last_updated for parsed, _rules in sections if parsed.last_updated),
        default="unknown",
    )
    lines = [
        "#########################################",
        f"# Aggregated Clash ruleset: {spec.name}",
        "# Generated by scripts/sync_sukka_rules.py",
        f"# Generated at: {now}",
        f"# Source last updated: {source_last_updated}",
        f"# Behavior: {spec.behavior}",
        "#",
        "# Sources:",
    ]

    for parsed, _rules in sections:
        lines.append(f"# - {parsed.source.url}")

    lines.append("#########################################")

    for parsed, rules in sections:
        lines.extend(
            (
                "",
                f"# ---- Source: {parsed.source.name} ----",
            )
        )
        lines.extend(parsed.comments)
        lines.extend(rules)

    lines.extend(("", "################## EOF ##################", ""))
    return "\n".join(lines)


def normalized_for_compare(text: str) -> str:
    lines = normalize_newlines(text).split("\n")
    return "\n".join(line for line in lines if not line.startswith("# Generated at:"))


def write_if_changed(path: Path, content: str) -> bool:
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if normalized_for_compare(existing) == normalized_for_compare(content):
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        file.write(content)
    return True


def render_metadata(outputs: dict[str, str], parsed_by_url: dict[str, ParsedSource]) -> str:
    payload = {
        "generator": "scripts/sync_sukka_rules.py",
        "outputs": outputs,
        "sources": {
            url: {
                "name": parsed.source.name,
                "sha256": parsed.sha256,
                "last_updated": parsed.last_updated,
            }
            for url, parsed in sorted(parsed_by_url.items())
        },
    }
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def render_config(repository: str | None, branch: str, output_specs: dict[str, OutputSpec]) -> str:
    repo = repository or "OWNER/REPO"
    raw_base = f"https://raw.githubusercontent.com/{repo}/{branch}/ruleset"
    lines = [
        "# Generated Clash rule-provider snippet.",
        "# Copy the provider entries and RULE-SET lines into your main Clash config.",
        "# Keep unrelated providers, proxy groups, and custom rules from your own config.",
        "# The old cn-media provider is intentionally omitted because Sukka has no stream_cn.txt.",
        "",
        "rule-providers:",
    ]

    for name in PROVIDER_ORDER:
        if name == "grok":
            behavior = "classical"
        else:
            behavior = output_specs[name].behavior
        lines.extend(
            (
                f"  {name}:",
                "    type: http",
                f"    behavior: {behavior}",
                "    format: text",
                "    interval: 43200",
                f"    url: {raw_base}/{name}.txt",
                f"    path: ./ruleset/{name}.txt",
            )
        )

    lines.extend(("", "rules:"))
    lines.extend(RULE_LINES)
    lines.append("")
    return "\n".join(lines)


def collect_sources(outputs: Iterable[OutputSpec]) -> dict[str, Source]:
    sources: dict[str, Source] = {}
    for spec in outputs:
        for source in spec.sources:
            existing = sources.get(source.url)
            if existing is None:
                sources[source.url] = source
            elif existing.behavior != source.behavior:
                sources[source.url] = Source(
                    source.name,
                    source.url,
                    "classical",
                    source.output_behavior or existing.output_behavior,
                    source.allow_empty or existing.allow_empty,
                )
    return sources


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    config_dir = Path(args.config_dir)
    output_specs = {spec.name: spec for spec in OUTPUTS}

    parsed_by_url: dict[str, ParsedSource] = {}
    for source in collect_sources(OUTPUTS).values():
        print(f"Fetching {source.url}", file=sys.stderr)
        text = fetch_text(source, timeout=args.timeout)
        parsed_by_url[source.url] = parse_source(source, text)

    generated_outputs: dict[str, str] = {}
    changed: list[Path] = []

    for spec in OUTPUTS:
        parsed_sources = [parsed_by_url[source.url] for source in spec.sources]
        source_filters = dict(spec.source_filters)
        source_excludes = dict(spec.source_excludes)
        sections = dedupe_rules_with_source_filters(
            parsed_sources,
            spec.rule_filter,
            source_filters,
            source_excludes,
        )
        if not sections:
            raise RuntimeError(f"{spec.name}: no rules after filtering")
        content = render_output(spec, sections)
        relative_path = f"ruleset/{spec.name}.txt"
        generated_outputs[spec.name] = relative_path
        if not args.check:
            path = output_dir / f"{spec.name}.txt"
            if write_if_changed(path, content):
                changed.append(path)

    grok_content = render_static_grok()
    generated_outputs["grok"] = "ruleset/grok.txt"
    if not args.check:
        grok_path = output_dir / "grok.txt"
        if write_if_changed(grok_path, grok_content):
            changed.append(grok_path)

    metadata = render_metadata(generated_outputs, parsed_by_url)
    if not args.check:
        metadata_path = output_dir / "sync-metadata.json"
        if write_if_changed(metadata_path, metadata):
            changed.append(metadata_path)

    if not args.check and not args.skip_config:
        config = render_config(args.github_repository, args.branch, output_specs)
        config_path = config_dir / "clash-rule-providers.yaml"
        if write_if_changed(config_path, config):
            changed.append(config_path)

    if args.check:
        print(f"Validated {len(parsed_by_url)} sources and {len(OUTPUTS)} outputs.")
    elif changed:
        print("Updated files:")
        for path in changed:
            print(f"  {path}")
    else:
        print("All generated files are already up to date.")

    if not args.github_repository:
        print(
            "Warning: GitHub repository could not be inferred; config uses OWNER/REPO placeholder.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
