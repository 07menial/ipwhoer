# ipx.al 风险库

[ipx.al](https://ipx.al) 风险库的公开数据与构建脚本。

- `build-risk.py`：从 DShield、blocklist.de、CINS、IPsum、FireHOL、Spamhaus DROP、Tor、Feodo、ET compromised、StopForumSpam 等公开名单聚合去重
- `.github/workflows/risk.yml`：每 6 小时自动构建，结果强推到 `data` 分支（只保留最新一份）
- `data` 分支：`sources.csv`（人可读）、`risk.bin`（线上查询用）、`risk.json`（来源与条数）

命中只代表这个 IP 近期出现在名单里，不等于当前使用者有问题。误报请提 issue，附上 IP 和依据。

## ipx 机房段库（build-dc.py）
每 6 小时随风险库一起重建，只发布结论区间（`dc.csv` 人可读）。来源：AWS / Google Cloud / Oracle / Cloudflare 官方段，DigitalOcean / Linode / Vultr geofeed，RIPE RIS riswhois 路由表，`hosting-asns.txt`（人工整理），PeeringDB 主类型为 Content 的网络（排除 `not-hosting.txt`）。误判请提 issue，或直接 PR 修改这两个名单。

## ipx 地理层（build-geofeed.py）
每天重建一次。收集网络运营商自己声明的 RFC 8805 geofeed：DigitalOcean / Linode / Vultr / Google Cloud / Starlink 官方 feed，加上 RIPE、APNIC、AFRINIC、LACNIC whois 里 inetnum 挂的 `geofeed:`。whois 来的条目只接受落在引用它的 inetnum 范围内的（RFC 9632）。ARIN 没有公开批量库，暂缺。

## ipx VPN 出口库（build-vpn.py）
每 6 小时重建。只收 VPN 服务商自己公开的服务器地址（Mullvad、NordVPN、Private Internet Access 的官方 API，IVPN、Surfshark 的官方主机名），以及苹果公开的 iCloud 专用代理出口表。不转载第三方 VPN 名单。
