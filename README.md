# ipx.al 风险库

[ipx.al](https://ipx.al) 风险库的公开数据与构建脚本。

- `build-risk.py`：从 DShield、blocklist.de、CINS、IPsum、FireHOL、Spamhaus DROP、Tor、Feodo、ET compromised、StopForumSpam 等公开名单聚合去重
- `.github/workflows/risk.yml`：每 6 小时自动构建，结果强推到 `data` 分支（只保留最新一份）
- `data` 分支：`sources.csv`（人可读）、`risk.bin`（线上查询用）、`risk.json`（来源与条数）

命中只代表这个 IP 近期出现在名单里，不等于当前使用者有问题。误报请提 issue，附上 IP 和依据。
