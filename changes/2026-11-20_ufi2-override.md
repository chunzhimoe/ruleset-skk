# 第二台 UFI 覆写

现有 CT UK 覆写绑定第一台的 `feth50`。本次新增独立的 `clash-party-ufi2.js`，绑定
`feth52`，沿用 AI 分流、DNS-over-HTTPS 和外部 UDP 拒绝规则。第二台还匹配
Antigravity.app、`agy`、Antigravity 专用域名及 Google 搜索的 `google.com`
和 `www.google.com`。HTTPS 同一主机名内的不同路径共用一条规则。

`scripts/build_clash_ufi2.js` 从第一台的脚本生成可独立导入的第二台覆写。
新增记录已写入 Clash Party 本地配置，`global: false`，所有订阅都未关联。
当前界面的列表由应用缓存，重新打开 Clash Party 后从磁盘重新读取。
现用订阅、运行配置和第一台覆写文件的 SHA-256 在登记前后都一致。

- `node scripts/build_clash_ufi2.js --check`、`node --check config/clash-party-ufi2.js`、
  `node test/check_ct_uk_override.js` 和 `git diff --check` 通过。
- 使用内置 Mihomo 对现用订阅和新覆写的合并结果执行 `mihomo -t`，通过。
- 用独立的 Mihomo 实例测试，Google 搜索、Antigravity 首页和 ChatGPT 均命中
  第二台且返回 HTTP 200。实测出口是英国 `31.94.4.67`，Antigravity 的 DNS
  查询返回 A 记录，Gmail 在测试实例命中默认拒绝规则。
- Antigravity 登录及实际模型请求未测试，正式订阅中的第二台覆写保持关闭。
