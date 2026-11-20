# 统一两台 UFI 的分流规则

Google 搜索的精确域名和 Antigravity 的应用及域名规则原先只在生成第二台
覆写时加入。两份覆写现在使用同一组规则、DNS 策略和 UDP 拦截，分别
生成 `feth50` 和 `feth52` 的出口。现有 AI 规则、Claude 进程规则和
订阅中的普通 Google 规则仍保留。

本机两份脚本已替换，均保持关闭。替换前后比对了订阅、覆写登记表和
Mihomo 当前运行配置的 SHA-256，结果一致。

- `node scripts/build_clash_ufi2.js --check`、两份脚本的 `node --check`、
  `node test/check_ct_uk_override.js`、`python3 -m unittest discover -s test`
  和 `git diff --check` 通过。测试在归一化出口名和网卡后比对完整输出。
- 两份覆写分别与当前订阅合并，通过 Mihomo `-t` 预检。
- 两个独立测试实例均让 Google 搜索、Antigravity 首页、ChatGPT 返回
  HTTP 200，Antigravity 的绑定 DNS 查询均成功。两台英国出口分别为
  `31.94.24.216` 和 `31.94.4.66`。测试未启用正式覆写。
