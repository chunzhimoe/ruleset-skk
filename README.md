# Clash Rule Sync

This repository syncs aggregated Clash rule-provider files from Sukka's ruleset
server and a few AI service rule lists.

## Usage

Run a validation-only check:

```sh
python3 scripts/sync_sukka_rules.py --check
```

Generate rule files and the Clash rule-provider snippet:

```sh
python3 scripts/sync_sukka_rules.py --github-repository chunzhimoe/ruleset-skk --branch main
```

Generated files are written to `ruleset/*.txt`. The generated Clash snippet is
written to `config/clash-rule-providers.yaml`; copy the relevant provider entries
and `RULE-SET` lines into your main Clash configuration. The old `cn-media`
provider is intentionally omitted because Sukka's current Clash rules do not
include `stream_cn.txt`.

The GitHub Actions workflow runs daily and commits only when generated content
changes.

## AI rules

The sync publishes the three rule sets listed under AI in the
[Sukka documentation](https://github.com/SukkaW/Surge#ai):

| Provider | Published rules |
| --- | --- |
| `ai_non_ip` | All Sukka AI domain rules, including Gemini, Perplexity and Grok |
| `apple_intelligence_non_ip` | Sukka's Apple Intelligence domains |
| `ai_ip` | Sukka's AI IP rules, including ChatGPT Voice |

The existing `openai`, `claude`, and `grok` rules keep their precedence.
The generated snippet uses the existing `🧲 OpenAI` group for the three new
providers. Put these entries before broader catch-all rules in your own
configuration, and keep `ai_ip` after domain rules. The old aggregate
`ruleset/ai.txt` keeps its original exclusions for compatibility.

The mirrored lists retain Sukka's attribution and AGPL-3.0 notices in their
source headers. See [Sukka's source](https://github.com/SukkaW/Surge) and the
[included AGPL-3.0 license](licenses/Sukka-AGPL-3.0.txt).

### Optional CT UK routing in Clash Party

Import either file as a local override. Enable one UFI override per
subscription to choose its USB connection.

| Override | USB interface |
| --- | --- |
| [`clash-party-ct-uk.js`](config/clash-party-ct-uk.js) | `feth50` |
| [`clash-party-ufi2.js`](config/clash-party-ufi2.js) | `feth52` |

Both use identical rules for the AI providers, Claude and Antigravity processes
and domains, the Google Search hosts `google.com` and `www.google.com`, and the
exact `na.gateway.spring.citi.com` hostname. Each uses DNS-over-HTTPS on its
chosen USB interface for the matched domains. Missing Sukka providers refresh
from the official server every 12 hours. Existing provider URLs are preserved.

HTTPS routing uses hostnames, so URLs on the same host use the same route.
Other hostnames follow the subscription unless an AI or process rule matches.
Both overrides reject matched external UDP for AI and Search to avoid falling
through to the primary network. WebRTC features that require UDP can be
unavailable.

If the subscription has a `wifi-call-uk` provider and rule, the override routes
that rule through a separate direct outbound on the same USB interface.
This outbound allows UDP for Wi-Fi Calling, and the matched domains use the
same interface for DNS-over-HTTPS.

After editing the shared routing logic in `clash-party-ct-uk.js`, rebuild the
standalone override with `node scripts/build_clash_ufi2.js`.
