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


def icloud():
    raw = get('https://mask-api.icloud.com/egress-ip-ranges.csv', 300).decode('utf-8', 'replace')
    return [line.split(',', 1)[0] for line in raw.splitlines() if line and not line.startswith('#')]


SOURCES = [('Mullvad', 1, mullvad), ('NordVPN', 1, nord), ('Private Internet Access', 1, pia),
           ('IVPN', 1, ivpn), ('Surfshark', 1, surfshark), ('AirVPN', 1, airvpn), ('Windscribe', 1, windscribe),
           ('iCloud Private Relay', 2, icloud)]


def main():
    os.makedirs(OUT, exist_ok=True)
    provs, counts, items = [], {}, {4: [], 6: []}
    prev = os.path.join(OUT, 'vpn.json')
    for name, cat, fn in SOURCES:
        try:
            lst = fn()
        except Exception as e:
            print(name, 'failed:', e); counts[name] = f'error: {type(e).__name__}'; continue
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
                items[6].append((int(nw.network_address) >> 64, int(nw.broadcast_address) >> 64, min(nw.prefixlen, 64), cat << 16 | pi))
            n += 1
        counts[name] = n
        print(name, n, flush=True)
    if not any(isinstance(v, int) and v for v in counts.values()):
        sys.exit('all sources failed')
    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 1,
            'providers': provs, 'categories': {1: 'VPN', 2: '隐私中继'}, 'counts': counts}
    for ver, name in ((4, 'vpn.bin'), (6, 'vpn6.bin')):
        it = sorted(items[ver], key=lambda x: x[2])
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
