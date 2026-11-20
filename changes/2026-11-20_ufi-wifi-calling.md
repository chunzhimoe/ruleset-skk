# 英国 Wi-Fi Calling 的 UFI 直连

两份覆写沿用当前订阅的 `wifi-call-uk` provider 和规则顺序。命中时使用
独立的 IPv4 直连出口，允许 UDP，DNS 绑定同一 UFI。第一台使用 `feth50`，
第二台使用 `feth52`。香港、美国的 Wi-Fi Calling 规则及 AI 和搜索的
UDP 拦截保持原样。

- 变更前，以两份独立的 Mihomo v1.19.24 配置访问 USB 私网的 UDP 回包服务。
  两张卡分别收到对应设备的回包。指定不存在的网卡时，Mihomo 报
  `interface not found`，测试未收到回包。
- `node scripts/build_clash_ufi2.js --check`、两份覆写的 `node --check`、
  `node test/check_ct_uk_override.js`、`python3 -m unittest discover -s test`
  和 `git diff --check` 通过。两份覆写分别与现用订阅合并，均通过 `mihomo -t`。
- Clash Party 的现有两份脚本已更新，继续保持关闭。订阅、覆写登记表及
  运行配置的 SHA-256 一致。运营商注册及实际通话留待手动验收。
