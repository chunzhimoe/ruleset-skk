# CT UK USB 直连与 UDP 分流

Clash Party 曾加载 WireGuard 出口。日志显示赴 UFI 网关的 UDP 握手遇到
`network is unreachable`，之后匹配的 Claude 和 ChatGPT DNS 查询超时。故障后
检查时 `feth50` 没有 IPv4。重新连接现有 RNDIS 会话后，网卡重新获得
`10.42.0.94` 和网关 `10.42.0.1`。网卡最初失去地址的原因尚无证据。

`config/clash-party-ct-uk.js` 恢复绑定 `feth50` 的 IPv4 直连。
Claude.app 及其辅助进程按可执行文件路径匹配，回环连接保留直连。
Claude 域名、已有 AI 规则和指定的 ChatGPT App 域名通过 USB 查询
DNS-over-HTTPS。匹配这些规则的 UDP 由显式规则拒绝，避免未验证的
macOS UDP 绑定或后续规则将流量引到主网络。覆盖范围取决于 Mihomo TUN
接管和进程识别。需要 UDP 的 WebRTC 功能可能不可用。

UFI 上的 `wg-quick@ufi-ai` 已停止并取消开机启动，原 WireGuard 配置留作回退。
Clash Party 已热加载 USB 直连覆写。普通 DNS 上游和 Mac 的默认网卡没有修改。

- `node --check config/clash-party-ct-uk.js`、`node test/check_ct_uk_override.js`、
  `git diff --check` 通过。
- 用 Clash Party 自带的 Mihomo v1.19.24 对合并后的当前订阅执行
  `mihomo -t`，通过。
- 使用隔离的 Mihomo 实例，以 `curl` 确认公网出口为英国 4G
  `31.94.32.69`，以 `dig` 确认绑定 `feth50` 的 DoH 能解析 Claude 域名。
  来自模拟 Claude.app 路径的 SOCKS UDP 请求命中
  `ProcessPathRegex` 与 `NETWORK,UDP` 的组合规则并被拒绝。
- 在热加载后的实际代理上用 `curl` 测试，Apple 和 ChatGPT 返回 HTTP 200。
  Claude 的 HTTPS 命中 USB 出口，收到带 `cf-mitigated: challenge` 的
  HTTP 403。桌面应用会话未验证。
  `route -n get default` 显示默认路由为 `en0`，UFI 网关仍经 `feth50`。
- RNDIS 进程当前运行，但其 launchd 引用的可执行文件已缺失。
  Mac 重启后 USB 自动启动尚不能验收。恢复原驱动文件需要本机管理员权限。

代码归档在 `codex/sync-skk-ai`。实际提交和推送状态以 Git 记录为准。
