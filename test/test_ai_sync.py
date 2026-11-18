"""Check that AI source data is published with compatible Clash rules."""

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sync_sukka_rules as sync


class AISyncTest(unittest.TestCase):
    def test_complete_ai_rules_are_published_alongside_existing_providers(self):
        domains = ("DOMAIN-SUFFIX,chatgpt.com", "DOMAIN-SUFFIX,grok.com")
        ai_ips = (
            "IP-CIDR,192.0.2.8/32,no-resolve",
            "IP-CIDR6,2001:db8::/48,no-resolve",
        )
        apple_ai = ("DOMAIN,apple-relay.apple.com",)

        def fixture(source, timeout):
            rules = {
                "/Clash/non_ip/ai.txt": domains,
                "/Clash/ip/ai.txt": ai_ips,
                "/Clash/non_ip/apple_intelligence.txt": apple_ai,
                "/OpenAI/OpenAI.list": ("DOMAIN-SUFFIX,openai.com",),
                "/Claude/Claude.list": ("DOMAIN-SUFFIX,claude.ai",),
            }
            for suffix, text in rules.items():
                if source.url.endswith(suffix):
                    return "\n".join(text) + "\n"
            if source.behavior == "domain":
                return "+.example.test\n"
            return "DOMAIN,example.test\n"

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            argv = [
                "sync_sukka_rules.py",
                "--output-dir", str(path / "ruleset"),
                "--config-dir", str(path / "config"),
                "--github-repository", "example/rules",
                "--branch", "main",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(sync, "fetch_text", fixture),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(sync.main(), 0)

            def rules_in(name):
                text = (path / "ruleset" / f"{name}.txt").read_text(encoding="utf-8")
                return tuple(line for line in text.splitlines() if line and not line.startswith("#"))

            self.assertEqual(rules_in("ai_non_ip"), domains)
            self.assertEqual(rules_in("ai_ip"), ai_ips)
            self.assertEqual(rules_in("apple_intelligence_non_ip"), apple_ai)
            self.assertNotIn(domains[1], rules_in("ai"))
            self.assertIn(domains[1], rules_in("grok"))

            snippet = (path / "config/clash-rule-providers.yaml").read_text(encoding="utf-8")
            metadata = json.loads((path / "ruleset/sync-metadata.json").read_text(encoding="utf-8"))
            for name in ("ai_non_ip", "ai_ip", "apple_intelligence_non_ip"):
                self.assertIn(f"/main/ruleset/{name}.txt", snippet)
                self.assertIn(f"RULE-SET,{name},", snippet)
                self.assertEqual(metadata["outputs"][name], f"ruleset/{name}.txt")
            self.assertLess(snippet.index("RULE-SET,grok,"), snippet.index("RULE-SET,ai_non_ip,"))
            self.assertLess(snippet.index("RULE-SET,apple_intelligence_non_ip,"), snippet.index("RULE-SET,apple,"))
            self.assertLess(snippet.index("RULE-SET,direct,"), snippet.index("RULE-SET,ai_ip,"))


if __name__ == "__main__":
    unittest.main()
