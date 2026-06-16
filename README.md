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
