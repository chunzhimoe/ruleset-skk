# Claude Code 分流扩展

两份 UFI 覆写原先覆盖 Claude 的核心域名、进程和已有订阅规则。本次补齐用户给出的 CDN、认证、内容、监控、第三方和 KYC 域名，并用 `anthropic.com` 后缀覆盖其 API、CDN、MCP、Console 和 Workbench 子域名。

- `config/clash-party-ct-uk.js` 提供共享规则，`config/clash-party-ufi2.js` 由生成脚本同步。域名和 `datadog`、`sentry`、`sift` 关键词的 DoH 绑定当前选中的 UFI。
- 增加 Anthropic IPv4 网段和 ASN 兜底。IP 和 ASN 规则使用 `no-resolve`。两条 UFI 只提供公网 IPv4，指定 IPv6 网段匹配时拒绝连接，避免经过 Mac 主网卡。
- UDP 目的端口 123 使用独立的 UFI NTP 出口。这个规则先于 AI UDP 拒绝规则。现有 Wi-Fi Calling 保持原来的 UDP 出口。
- EasyTier 认证入口沿用本机凭据和来源网段限制，并复用扩展的 TCP 分流。仓库的 `easyTierRelay` 默认关闭。

## 实测

- `node test/check_ct_uk_override.js`、`node scripts/build_clash_ufi2.js --check`、`python3 -m unittest discover -s test` 和 `git diff --check` 通过。
- Mac 的 Mihomo 1.19.24 通过当前配置和第二台最小配置的 `-t` 预检。首次使用既有代理测试时，回环地址受原有局域网访问规则限制。临时认证回环入口验证完成后已撤除。
- Mac 运行日志确认 `api.anthropic.com`、`api.datadoghq.com` 和 `maps.googleapis.com` 经第一台 UFI 出站，分别得到 HTTP 404、307 和 302。IPv4 字面地址命中指定网段，IPv6 字面地址命中 REJECT。Cloudflare NTP 经 `CT-UK · USB 4G · NTP` 返回应答。
- 已热重载并保存本机的两份覆写。第一台保持启用，系统默认路由保留在 `en0`，原有 EasyTier 入口仍在监听。
- 第二台的独立测试命中 Anthropic 域名和 Datadog 关键词的 `CT-UK · UFI 2` 出口。直接绑定 `feth52` 访问 `1.1.1.1:443` 超时，第二台的 DoH 和应用端到端连通性仍未通过。
