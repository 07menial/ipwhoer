#!/usr/bin/env python3
"""ipx 自有机房段库（IPv4，第一版）。每天由 GitHub Actions 重建，只输出结论区间。

来源（全部公开）：
  云厂商官方段：AWS ip-ranges.json、Google Cloud cloud.json、Oracle Cloud、Cloudflare ips-v4、
               DigitalOcean / Linode(Akamai) / Vultr 的 RFC 8805 geofeed
  路由：RIPE RIS riswhois（前缀 → 起源 ASN，至少 10 个对等体看到才算）
  机房 ASN：hosting-asns.txt（人工整理，与 ipx.al 的 HOSTING_ASNS 同步）
           + PeeringDB 主类型为 Content 的网络（排除 not-hosting.txt）

输出 OUT/：
  dc.bin   每条 16 字节小端：start u32, end u32, asn u32, meta u32
           meta = 来源 << 16 | 厂商下标；来源 1=云厂商官方段 2=人工机房 ASN 3=PeeringDB Content
           区间互不重叠，按 start 排序；更具体的前缀覆盖更宽的前缀，官方段覆盖路由推断
  dc.json  厂商名、来源说明、条数、构建时间
  dc.csv   人可读：start,end,asn,source,provider
"""
import csv, gzip, io, ipaddress, json, os, struct, sys, urllib.request, datetime as dt

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
HERE = os.path.dirname(os.path.abspath(__file__))
UA = {'User-Agent': 'ipx.al-data (+https://github.com/yehyakin/ipx-al-data)'}
MIN_PEERS = 10


def get(url, timeout=120):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def v4(cidr):
    try:
        n = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    if n.version != 4 or not n.is_global:
        return None
    return int(n.network_address), int(n.broadcast_address), n.prefixlen


def cloud():
    out = []  # (cidr, provider)
    j = json.loads(get('https://ip-ranges.amazonaws.com/ip-ranges.json'))
    out += [(p['ip_prefix'], 'AWS') for p in j['prefixes'] if p.get('service') in ('EC2', 'AMAZON')]
    j = json.loads(get('https://www.gstatic.com/ipranges/cloud.json'))
    out += [(p['ipv4Prefix'], 'Google Cloud') for p in j['prefixes'] if 'ipv4Prefix' in p]
    j = json.loads(get('https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'))
    out += [(c['cidr'], 'Oracle Cloud') for r in j['regions'] for c in r['cidrs']]
    out += [(l, 'Cloudflare') for l in get('https://www.cloudflare.com/ips-v4').decode().split()]
    for url, name in [('https://digitalocean.com/geo/google.csv', 'DigitalOcean'),
                      ('https://geoip.linode.com/', 'Linode'),
                      ('https://geofeed.constant.com/?text', 'Vultr')]:
        for line in get(url).decode('utf-8', 'replace').splitlines():
            if line and not line.startswith('#'):
                out.append((line.split(',')[0], name))
    return out


def asn_file(name):
    p = os.path.join(HERE, name)
    if not os.path.exists(p):
        return {}
    d = {}
    for line in open(p, encoding='utf-8'):
        line = line.split('#', 1)
        a = line[0].strip()
        if a.isdigit():
            d[int(a)] = (line[1].strip() if len(line) > 1 else '')
    return d


def main():
    os.makedirs(OUT, exist_ok=True)
    provs, pidx = [''], {'': 0}

    def P(name):
        if name not in pidx:
            pidx[name] = len(provs); provs.append(name)
        return pidx[name]

    manual = asn_file('hosting-asns.txt')
    deny = asn_file('not-hosting.txt')
    pdb = json.loads(get('https://www.peeringdb.com/api/net?fields=asn,name,info_type', 180))['data']
    pdb_name = {x['asn']: x['name'] for x in pdb}
    content = {x['asn'] for x in pdb if x.get('info_type') == 'Content'} - set(deny) - set(manual)

    items = []  # (start, end, plen, rank, asn, src, prov)
    # 路由：riswhois
    raw = gzip.decompress(get('https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz', 300)).decode('utf-8', 'replace')
    for line in raw.splitlines():
        if not line or line[0] in '%#':
            continue
        p = line.split('\t')
        if len(p) < 3 or not p[0].isdigit() or int(p[2]) < MIN_PEERS:
            continue
        r = v4(p[1])
        if not r:
            continue
        a = int(p[0])
        if a in manual:
            items.append((*r, 1, a, 2, P(manual[a] or pdb_name.get(a, f'AS{a}'))))
        elif a in content:
            items.append((*r, 1, a, 3, P(pdb_name.get(a, f'AS{a}'))))
    n_route = len(items)
    # 云厂商官方段（优先级最高）
    for cidr, name in cloud():
        r = v4(cidr)
        if r:
            items.append((*r, 2, 0, 1, P(name)))
    n_cloud = len(items) - n_route

    # 拍平：更具体（前缀更长）优先，同长度官方段优先
    items.sort(key=lambda x: (x[2], x[3]))  # 先放宽的、低优先级的，后面的覆盖
    bounds = sorted({x[0] for x in items} | {x[1] + 1 for x in items})
    # 区间着色：按优先级从低到高写入，用分段数组
    import bisect
    owner = [None] * len(bounds)
    for it in items:
        i, j = bisect.bisect_left(bounds, it[0]), bisect.bisect_left(bounds, it[1] + 1)
        for k in range(i, j):
            owner[k] = it
    rows = []
    for k in range(len(bounds) - 1):
        it = owner[k]
        if not it:
            continue
        s, e = bounds[k], bounds[k + 1] - 1
        asn = it[4]  # 官方段不带 ASN（Worker 用报告里的起源 ASN）
        meta = it[5] << 16 | it[6]
        if rows and rows[-1][1] + 1 == s and rows[-1][2] == asn and rows[-1][3] == meta:
            rows[-1][1] = e
        else:
            rows.append([s, e, asn, meta])

    buf = bytearray()
    for s, e, a, m in rows:
        buf += struct.pack('<IIII', s, e, a, m)
    open(os.path.join(OUT, 'dc.bin'), 'wb').write(buf)
    SRC = {1: '云厂商官方段', 2: '人工整理机房 ASN', 3: 'PeeringDB Content'}
    with open(os.path.join(OUT, 'dc.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['start', 'end', 'asn', 'source', 'provider'])
        for s, e, a, m in rows:
            w.writerow([str(ipaddress.IPv4Address(s)), str(ipaddress.IPv4Address(e)), a or '', SRC[m >> 16], provs[m & 0xffff]])
    addrs = sum(e - s + 1 for s, e, _, _ in rows)
    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 1,
            'ranges': len(rows), 'addresses': addrs, 'providers': provs,
            'sources': SRC, 'counts': {'route_prefixes': n_route, 'cloud_prefixes': n_cloud,
                                        'manual_asns': len(manual), 'pdb_content_asns': len(content)}}
    json.dump(meta, open(os.path.join(OUT, 'dc.json'), 'w'), ensure_ascii=False)
    print(json.dumps({k: v for k, v in meta.items() if k != 'providers'}, ensure_ascii=False), 'providers', len(provs))


if __name__ == '__main__':
    main()
