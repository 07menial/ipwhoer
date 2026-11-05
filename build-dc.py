#!/usr/bin/env python3
"""ipx 自有机房段库（IPv4，第一版）。每天由 GitHub Actions 重建，只输出结论区间。

来源（全部公开）：
  云厂商官方段：AWS ip-ranges.json、Google Cloud cloud.json、Oracle Cloud、Cloudflare ips-v4/v6、Fastly public-ip-list、
               DigitalOcean / Linode(Akamai) / Vultr 的 RFC 8805 geofeed
  路由：RIPE RIS riswhois（前缀 → 起源 ASN，至少 10 个对等体看到才算）
  机房 ASN：hosting-asns.txt（人工整理，与 ipx.al 的 HOSTING_ASNS 同步）
           + PeeringDB 主类型为 Content 的网络（排除 not-hosting.txt）

输出 OUT/：
  dc6.bin  IPv6，每条 24 字节小端：start 高 64 位（hi u32, lo u32）, end 高 64 位, asn u32, meta u32
  dc.bin   每条 16 字节小端：start u32, end u32, asn u32, meta u32
           meta = 来源 << 16 | 厂商下标；来源 1=云厂商官方段 2=人工机房 ASN 3=PeeringDB Content
           区间互不重叠，按 start 排序；更具体的前缀覆盖更宽的前缀，官方段覆盖路由推断
  dc.json  厂商名、来源说明、条数、构建时间
  dc.csv   人可读：start,end,asn,source,provider
"""
import csv, gzip, io, ipaddress, json, os, re, struct, sys, urllib.request, datetime as dt

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
HERE = os.path.dirname(os.path.abspath(__file__))
UA = {'User-Agent': 'ipx.al-data (+https://github.com/yehyakin/ipx-al-data)'}
MIN_PEERS = 10


def get(url, timeout=120):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def net(cidr, ver):
    """IPv4 返回完整 32 位区间；IPv6 只取高 64 位（/64 以下的更细前缀并入所在 /64）。"""
    try:
        n = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    if n.version != ver or not n.is_global:
        return None
    if ver == 4:
        return int(n.network_address), int(n.broadcast_address), n.prefixlen
    return int(n.network_address) >> 64, int(n.broadcast_address) >> 64, min(n.prefixlen, 64)


def azure():
    # 微软每周发布 ServiceTags_Public_YYYYMMDD.json（下载路径固定，文件名带日期）；先读下载页，失败再按日期往回试 21 天
    base = 'https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/'
    urls = []
    try:
        urls += re.findall(r'https://download\.microsoft\.com/[^"\']*ServiceTags_Public_\d{8}\.json',
                           get('https://www.microsoft.com/en-us/download/details.aspx?id=56519', 60).decode('utf-8', 'replace'))
    except Exception:
        pass
    today = dt.date.today()
    urls += [base + f'ServiceTags_Public_{(today - dt.timedelta(days=i)):%Y%m%d}.json' for i in range(21)]
    for u in urls:
        try:
            j = json.loads(get(u, 120))
        except Exception:
            continue
        return [p for v in j['values'] if v['name'] == 'AzureCloud' for p in v['properties']['addressPrefixes']]
    raise RuntimeError('Azure ServiceTags not found')


def cloud():
    out = []  # (cidr, provider)
    j = json.loads(get('https://ip-ranges.amazonaws.com/ip-ranges.json'))
    out += [(p['ip_prefix'], 'AWS') for p in j['prefixes'] if p.get('service') in ('EC2', 'AMAZON')]
    out += [(p['ipv6_prefix'], 'AWS') for p in j.get('ipv6_prefixes', []) if p.get('service') in ('EC2', 'AMAZON')]
    j = json.loads(get('https://www.gstatic.com/ipranges/cloud.json'))
    out += [(p.get('ipv4Prefix') or p.get('ipv6Prefix'), 'Google Cloud') for p in j['prefixes'] if p.get('ipv4Prefix') or p.get('ipv6Prefix')]
    j = json.loads(get('https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'))
    out += [(c['cidr'], 'Oracle Cloud') for r in j['regions'] for c in r['cidrs']]
    out += [(c, 'Fastly') for k in ('addresses', 'ipv6_addresses') for c in json.loads(get('https://api.fastly.com/public-ip-list')).get(k, [])]
    try:
        out += [(c, 'Azure') for c in azure()]
    except Exception as e:
        print('Azure failed:', e)
    out += [(l, 'Cloudflare') for v in ('v4', 'v6') for l in get(f'https://www.cloudflare.com/ips-{v}').decode().split()]
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


def flatten(items):
    """更具体（前缀更长）优先，同长度官方段优先；返回互不重叠的 [start, end, asn, meta]。"""
    import bisect
    items.sort(key=lambda x: (x[2], x[3]))  # 先写宽的、低优先级的，后写的覆盖
    bounds = sorted({x[0] for x in items} | {x[1] + 1 for x in items})
    owner = [None] * len(bounds)
    for it in items:
        for k in range(bisect.bisect_left(bounds, it[0]), bisect.bisect_left(bounds, it[1] + 1)):
            owner[k] = it
    rows = []
    for k in range(len(bounds) - 1):
        it = owner[k]
        if not it:
            continue
        s, e, asn, meta = bounds[k], bounds[k + 1] - 1, it[4], it[5] << 16 | it[6]  # 官方段 asn=0，Worker 用报告里的起源 ASN
        if rows and rows[-1][1] + 1 == s and rows[-1][2] == asn and rows[-1][3] == meta:
            rows[-1][1] = e
        else:
            rows.append([s, e, asn, meta])
    return rows


def main():
    os.makedirs(OUT, exist_ok=True)
    provs, pidx = [''], {'': 0}

    def P(name):
        if name not in pidx:
            pidx[name] = len(provs); provs.append(name)
        return pidx[name]

    manual = asn_file('hosting-asns.txt')
    deny = asn_file('not-hosting.txt')
    cache = os.path.join(OUT, 'peeringdb-net.json')  # 上一次的副本（data 分支恢复），PeeringDB 匿名限流时退回
    try:
        pdb = json.loads(get('https://www.peeringdb.com/api/net?fields=asn,name,info_type', 180))['data']
        json.dump(pdb, open(cache, 'w'), ensure_ascii=False)
    except Exception as e:
        print('PeeringDB 获取失败，用上次副本：', e)
        pdb = json.load(open(cache))
    pdb_name = {x['asn']: x['name'] for x in pdb}
    content = {x['asn'] for x in pdb if x.get('info_type') == 'Content'} - set(deny) - set(manual)
    clouds = cloud()
    SRC = {1: '云厂商官方段', 2: '人工整理机房 ASN', 3: 'PeeringDB Content'}
    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 2,
            'sources': SRC, 'providers': provs}

    for ver in (4, 6):
        items = []  # (start, end, plen, rank, asn, src, prov)
        raw = gzip.decompress(get(f'https://www.ris.ripe.net/dumps/riswhoisdump.IPv{ver}.gz', 300)).decode('utf-8', 'replace')
        for line in raw.splitlines():
            if not line or line[0] in '%#':
                continue
            p = line.split('\t')
            if len(p) < 3 or not p[0].isdigit() or int(p[2]) < MIN_PEERS:
                continue
            r = net(p[1], ver)
            if not r:
                continue
            a = int(p[0])
            if a in manual:
                items.append((*r, 1, a, 2, P(manual[a] or pdb_name.get(a, f'AS{a}'))))
            elif a in content:
                items.append((*r, 1, a, 3, P(pdb_name.get(a, f'AS{a}'))))
        n_route = len(items)
        for cidr, name in clouds:
            r = net(cidr, ver)
            if r:
                items.append((*r, 2, 0, 1, P(name)))
        rows = flatten(items)
        buf = bytearray()
        if ver == 4:
            for s_, e, a, m in rows:
                buf += struct.pack('<IIII', s_, e, a, m)
            fmt = lambda x: str(ipaddress.IPv4Address(x))
        else:  # 24 字节：start 高 64 位（hi u32, lo u32）、end 高 64 位、asn、meta
            for s_, e, a, m in rows:
                buf += struct.pack('<IIIIII', s_ >> 32, s_ & 0xffffffff, e >> 32, e & 0xffffffff, a, m)
            fmt = lambda x: str(ipaddress.IPv6Address(x << 64))
        name = 'dc' if ver == 4 else 'dc6'
        open(os.path.join(OUT, name + '.bin'), 'wb').write(buf)
        with open(os.path.join(OUT, name + '.csv'), 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(['start', 'end', 'asn', 'source', 'provider'])
            for s_, e, a, m in rows:
                w.writerow([fmt(s_), fmt(e) if ver == 4 else str(ipaddress.IPv6Address((e << 64) | (2 ** 64 - 1))), a or '', SRC[m >> 16], provs[m & 0xffff]])
        stats = {'ranges': len(rows), 'route_prefixes': n_route, 'cloud_prefixes': len(items) - n_route}
        stats['addresses' if ver == 4 else 'slash64s'] = sum(e - s_ + 1 for s_, e, _, _ in rows)
        if ver == 4:
            meta.update({'ranges': stats['ranges'], 'addresses': stats['addresses']})  # v1 字段保持兼容
        meta['v%d' % ver] = stats
    meta['counts'] = {'manual_asns': len(manual), 'pdb_content_asns': len(content)}
    meta['hosting_asns'] = sorted(manual)  # ipx.al Worker 每小时读这份名单作为 HOSTING_ASNS（唯一来源）
    json.dump(meta, open(os.path.join(OUT, 'dc.json'), 'w'), ensure_ascii=False)
    print(json.dumps({k: v for k, v in meta.items() if k != 'providers'}, ensure_ascii=False), 'providers', len(provs))


if __name__ == '__main__':
    main()
