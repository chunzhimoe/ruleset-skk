#!/usr/bin/env python3
"""Regenerate grok.txt only via sync script static path."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sync_sukka_rules import render_static_grok, write_if_changed  # noqa: E402

def main() -> int:
    content = render_static_grok()
    path = ROOT / "ruleset" / "grok.txt"
    changed = write_if_changed(path, content)
    print("updated" if changed else "unchanged", path)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())