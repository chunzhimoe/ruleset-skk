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

Import [`clash-party-ct-uk.js`](config/clash-party-ct-uk.js) as a subscription
override. It adds the three Sukka providers where missing and tells Mihomo to
refresh them from the official server every 12 hours. It keeps existing
provider URLs and routes TCP matched by the AI rules and the Claude desktop
app through `feth50`. Claude and the matched AI domains use DNS-over-HTTPS
through the same interface. Adjust the interface name if yours differs.

The override rejects matched UDP outside the Claude app's loopback connections
to avoid DNS and WebRTC traffic falling through to the primary network. WebRTC
features that require UDP can be unavailable with this override.

The override also has an exact CT UK route and DNS policy for the locally
requested `na.gateway.spring.citi.com` host. Other `citi.com` hosts keep the
subscription's rules.
