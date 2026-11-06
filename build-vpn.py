#!/usr/bin/env python3
"""ipx VPN / 中继出口库：只收各家自己公开的服务器地址，不抓第三方黑名单。

VPN（类别 1）：Mullvad、NordVPN、Private Internet Access 的官方服务器 API；
              IVPN、Surfshark 的官方服务器主机名（解析成 IP）。
中继（类别 2）：iCloud 专用代理（Private Relay）官方出口表 egress-ip-ranges.csv。
               它是苹果给 Safari 用户的隐私中继，不是传统 VPN，报告里单独标注。

输出 OUT/：
  vpn.bin   IPv4，每条 12 字节小端：start u32, end u32, meta u32（类别 << 16 | 服务商下标）
  vpn6.bin  IPv6，每条 20 字节：start 高 64 位（hi, lo）, end 高 64 位, meta
  vpn.json  服务商名、各家条数、构建时间
"""
import bisect, concurrent.futures as cf, csv, datetime as dt, io, ipaddress, json, os, socket, struct, sys, urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
UA = {'User-Agent': 'ipx.al-data (+https://github.com/yehyakin/ipx-al-data)'}


def get(url, timeout=120):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def resolve(host):
    try:
        return host, sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
    except OSError:
        return host, []


def mullvad():
    out = []
    for r in json.loads(get('https://api.mullvad.net/www/relays/all/')):
        out += [x for x in (r.get('ipv4_addr_in'), r.get('ipv6_addr_in')) if x]
    return out


def nord():
    u = 'https://api.nordvpn.com/v1/servers?limit=20000&fields%5Bservers.station%5D=1&fields%5Bservers.ipv6_station%5D=1'
    return [x for s in json.loads(get(u, 180)) for x in (s.get('station'), s.get('ipv6_station')) if x]


def pia():
    j = json.loads(get('https://serverlist.piaservers.net/vpninfo/servers/v6').decode().split('\n', 1)[0])
    return [s['ip'] for r in j['regions'] for grp in r['servers'].values() for s in grp if s.get('ip')]


def ivpn():
    hosts = set()
    for s in json.loads(get('https://api.ivpn.net/v4/servers/stats'))['servers']:
        hosts.add(s['gateway'])
        hosts.update((s.get('hostnames') or {}).values())
    with cf.ThreadPoolExecutor(32) as ex:
        return [ip for _, ips in ex.map(resolve, hosts) for ip in ips]


def surfshark():
    hosts = {c['connectionName'] for c in json.loads(get('https://api.surfshark.com/v4/server/clusters/generic')) if c.get('connectionName')}
    with cf.ThreadPoolExecutor(32) as ex:
        return [ip for _, ips in ex.map(resolve, hosts) for ip in ips]


def airvpn():
    # AirVPN 公开状态接口：每台服务器的入口 IP（v4/v6 各 4 个）
    s = json.loads(get('https://airvpn.org/api/status/'))['servers']
    return [v for x in s for k, v in x.items() if k.startswith(('ip_v4_in', 'ip_v6_in')) and v]


def windscribe():
    # Windscribe 客户端用的公开服务器列表：每个节点 ip / ip2 / ip3
    d = json.loads(get('https://assets.windscribe.com/serverlist/openvpn/1/1'))['data']
    return [n[k] for loc in d for n in loc.get('nodes') or [] for k in ('ip', 'ip2', 'ip3') if n.get(k)]


def ovpn():
    j = json.loads(get('https://www.ovpn.com/v2/api/client/entry'))
    return [x['ip'] for d in j['datacenters'] for x in d.get('servers', []) if x.get('ip')]


def privado():
    return [x['ip'] for x in json.loads(get('https://privadovpn.com/apps/servers_export.json'))['servers'] if x.get('ip')]


def resolve_all(hosts):
    with cf.ThreadPoolExecutor(32) as ex:
        return [ip for _, ips in ex.map(resolve, hosts) for ip in ips]


def ipvanish():
    # 官方 OpenVPN 配置包里的 remote 主机名
    import re, zipfile
    z = zipfile.ZipFile(io.BytesIO(get('https://configs.ipvanish.com/configs/configs.zip', 180)))
    hosts = set()
    for n in z.namelist():
        m = re.search(rb'^remote\s+(\S+)', z.read(n), re.M) if n.endswith('.ovpn') else None
        if m: hosts.add(m.group(1).decode())
    return resolve_all(hosts)


def vypr():
    import re
    t = get('https://support.vyprvpn.com/hc/en-us/articles/360037728912-What-are-the-VyprVPN-server-addresses-').decode('utf-8', 'replace')
    return resolve_all(set(re.findall(r'[a-z0-9-]+\.vyprvpn\.com', t)) - {'www.vyprvpn.com', 'support.vyprvpn.com'})


def tor_relays():
    # Tor 官方 Onionoo：所有在线中继的 OR 地址（含非出口）。只展示，不计分
    j = json.loads(get('https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses', 180))
    out = []
    for r in j['relays']:
        for a in r.get('or_addresses', []):
            h = a.rsplit(':', 1)[0].strip('[]')
            out.append(h)
    return out


def zscaler():
    # Zscaler 官方公布的云节点出口段（企业安全代理）。只展示，不计分
    import re
    t = get('https://config.zscaler.com/api/zscaler.net/cenr/json').decode()
    return re.findall(r'"range"\s*:\s*"([0-9a-fA-F:./]+)"', t)


SCAN_NAMES = {'binaryedge.ninja': 'BinaryEdge', 'stretchoid.com': 'Stretchoid', 'censys.io': 'Censys', 'onyphe.net': 'Onyphe',
              'rapid7.com': 'Rapid7', 'shodan.io': 'Shodan', 'kudelskisecurity.com': 'Kudelski Security', 'riskiq.com': 'RiskIQ',
              'criminalip.com': 'Criminal IP', 'driftnet.io': 'Driftnet', 'shadowserver.org': 'Shadowserver', 'colostate.edu': 'CSU 网络测量'}


def scanners():
    # stamparm/maltrail（MIT）整理的已知互联网扫描器 IP，按注释里的域名归到扫描机构。只展示，不计分
    # 只用 mass_scanner.txt（单个 IP）。mass_scanner_cidr.txt 是把每个 IP 扩到所在 /24（BinaryEdge 还有 /18–/22）的派生表，
    # 扫描器租用的 DigitalOcean 等云段会被整段标成扫描器：2026-11-06 Atlas 复核时 28 个 DO 上的探针被标成 BinaryEdge。
    import re
    by = {}
    for f in ('mass_scanner.txt',):
        for l in get(GH + 'stamparm/maltrail/master/data/' + f).decode('utf-8', 'replace').splitlines():
            if not l.strip() or l.startswith('#'): continue
            ip, _, c = l.partition('#')
            m = re.search(r'([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})\b', c.strip().lower())
            d = '.'.join(m.group(1).split('.')[-2:]) if m else ''
            by.setdefault(SCAN_NAMES.get(d, d), []).append(ip.strip())
    out, other = {}, []
    for k, v in by.items():
        (out.__setitem__(k, v) if k and len(v) >= 20 else other.extend(v))
    out['其他扫描器'] = other
    return out


GH = 'https://raw.githubusercontent.com/'


def lines(url):
    return [l.split(',')[0].strip() for l in get(url, 180).decode('utf-8', 'replace').splitlines() if l.strip() and not l.startswith('#')]


def proton():
    # tn3w/ProtonVPN-IPs（Apache-2.0）：Proton 官方 API 公布的出口 + 入口 IP，每日更新
    b = GH + 'tn3w/ProtonVPN-IPs/master/'
    return lines(b + 'protonvpn_ips.txt') + lines(b + 'protonvpn_entry_ips.txt')


def windscribe_exit():
    # tn3w/Windscribe-IPs（Apache-2.0）：Windscribe 出口 IP（官方列表只有入口）
    return lines(GH + 'tn3w/Windscribe-IPs/master/windscribe_ips.txt')


def tunnelbear():
    # tn3w/TunnelBear-IPs（Apache-2.0）
    return lines(GH + 'tn3w/TunnelBear-IPs/master/tunnelbear_ips.txt')


# 爬虫：各家官方公布的抓取段，经 rezmoss/cloud-provider-ip-addresses（CC0）汇总。只展示，不计分
BOTS = [('googlebot', 'Googlebot'), ('bingbot', 'Bingbot'), ('gptbot', 'OpenAI 爬虫'), ('claudebot', 'Anthropic 爬虫'),
        ('applebot', 'Applebot'), ('perplexitybot', 'Perplexity 爬虫'), ('duckduckbot', 'DuckDuckBot'),
        ('amazonbot', 'Amazonbot'), ('commoncrawl', 'Common Crawl')]


def bot(key):
    return lambda: lines(GH + f'rezmoss/cloud-provider-ip-addresses/main/{key}/{key}_ips.txt')


def icloud():
    raw = get('https://mask-api.icloud.com/egress-ip-ranges.csv', 300).decode('utf-8', 'replace')
    return [line.split(',', 1)[0] for line in raw.splitlines() if line and not line.startswith('#')]


SOURCES = [('Mullvad', 1, mullvad), ('NordVPN', 1, nord), ('Private Internet Access', 1, pia),
           ('IVPN', 1, ivpn), ('Surfshark', 1, surfshark), ('AirVPN', 1, airvpn), ('Windscribe', 1, windscribe),
           ('OVPN', 1, ovpn), ('PrivadoVPN', 1, privado), ('VyprVPN', 1, vypr),  # IPVanish 配置包对 CI 的 UA 返回错误，不绕过
           ('ProtonVPN', 1, proton), ('Windscribe', 1, windscribe_exit), ('TunnelBear', 1, tunnelbear),
           ('iCloud Private Relay', 2, icloud)] + [(name, 3, bot(k)) for k, name in BOTS] + [('Tor 中继', 4, tor_relays), ('Zscaler', 5, zscaler), ('__scanners__', 6, scanners)]


def main():
    os.makedirs(OUT, exist_ok=True)
    provs, counts, items = [], {}, {4: [], 6: []}
    prev = os.path.join(OUT, 'vpn.json')
    srcs = []
    for name, cat, fn in SOURCES:
        if not name.startswith('__'):
            srcs.append((name, cat, fn)); continue
        try:
            srcs += [(k, cat, (lambda v=v: v)) for k, v in fn().items()]
        except Exception as e:
            print(name, 'failed:', e); counts[name.strip('_')] = f'error: {type(e).__name__}'
    for name, cat, fn in srcs:
        try:
            lst = fn()
        except Exception as e:
            print(name, 'failed:', e); counts[name] = f'error: {type(e).__name__}'; continue
        if name in provs:
            pi = provs.index(name); n = counts[name] if isinstance(counts.get(name), int) else 0
        else:
            pi = len(provs); provs.append(name); n = 0
        for x in lst:
            try:
                nw = ipaddress.ip_network(x.strip(), strict=False)
            except ValueError:
                continue
            if not nw.is_global:
                continue
            if nw.version == 4:
                items[4].append((int(nw.network_address), int(nw.broadcast_address), nw.prefixlen, cat << 16 | pi))
            else:
                # vpn6.bin 只存高 64 位。Tor 中继、扫描器名单是单个主机地址，而 Linode、DigitalOcean 等是多台机器共用一个 /64，
                # 存成 /64 会把邻居也标上（2026-11-06 Atlas 复核：119 个 v6 Tor 命中里 96 个并不是中继本身）。这两类只展示，v6 只收 ≤/64 的段
                if cat in (4, 6) and nw.prefixlen > 64:
                    continue
                items[6].append((int(nw.network_address) >> 64, int(nw.broadcast_address) >> 64, min(nw.prefixlen, 64), cat << 16 | pi))
            n += 1
        counts[name] = n
        print(name, n, flush=True)
    if not any(isinstance(v, int) and v for v in counts.values()):
        sys.exit('all sources failed')
    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 1,
            'providers': provs, 'categories': {1: 'VPN', 2: '隐私中继', 3: '爬虫', 4: 'Tor 中继', 5: '企业代理', 6: '扫描器'}, 'counts': counts}
    for ver, name in ((4, 'vpn.bin'), (6, 'vpn6.bin')):
        it = sorted(items[ver], key=lambda x: (x[2], 0 if x[3] >> 16 >= 3 else 1))  # 同长度时只展示类（爬虫/Tor 中继/企业代理）优先级最低
        bounds = sorted({x[0] for x in it} | {x[1] + 1 for x in it})
        owner = [None] * len(bounds)
        for x in it:
            for k in range(bisect.bisect_left(bounds, x[0]), bisect.bisect_left(bounds, x[1] + 1)):
                owner[k] = x[3]
        rows = []
        for k in range(len(bounds) - 1):
            if owner[k] is None:
                continue
            s, e = bounds[k], bounds[k + 1] - 1
            if rows and rows[-1][1] + 1 == s and rows[-1][2] == owner[k]:
                rows[-1][1] = e
            else:
                rows.append([s, e, owner[k]])
        buf = bytearray()
        for s, e, m in rows:
            buf += struct.pack('<III', s, e, m) if ver == 4 else struct.pack('<IIIII', s >> 32, s & 0xffffffff, e >> 32, e & 0xffffffff, m)
        open(os.path.join(OUT, name), 'wb').write(buf)
        meta[f'v{ver}'] = len(rows)
    json.dump(meta, open(prev, 'w'), ensure_ascii=False)
    print(json.dumps(meta, ensure_ascii=False))


if __name__ == '__main__':
    main()
