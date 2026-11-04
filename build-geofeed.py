#!/usr/bin/env python3
"""ipx 自有地理层（第一版）：收集网络运营商自己声明的 RFC 8805 geofeed。

0. 几家云厂商和 Starlink 直接公布的 geofeed（见 DIRECT）。
1. 从 RIPE、APNIC、AFRINIC、LACNIC 的公开 whois 库里找 inetnum / inet6num 上的
   `geofeed:` 属性或 `remarks: Geofeed <url>`（RFC 9632）。
   ARIN 没有公开批量库：discover-arin.py 逐块查 RDAP，结果在 arin 分支的 arin.tsv，这里读进来。
2. 抓取每个 geofeed 文件，只接受落在「引用它的那条 inetnum」范围内的条目（RFC 9632 的授权规则），
   防止有人在自己的文件里声明别人的地址。
3. 更具体的前缀覆盖更宽的前缀，输出区间表。

输出 OUT/：
  gf.bin    IPv4，每条 12 字节小端：start u32, end u32, loc u32（gf.json locations 的下标）
  gf6.bin   IPv6，每条 20 字节小端：start 高 64 位（hi, lo）, end 高 64 位（hi, lo）, loc u32
  gf.json   locations（"国家|地区|城市"）、条数、构建时间、各来源统计
  geofeed-urls.csv  人可读：url, 引用它的 inetnum 数, 接受条目数, 状态
"""
import bisect, concurrent.futures as cf, csv, datetime as dt, gzip, io, ipaddress, json, os, re, struct, sys, urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
UA = {'User-Agent': 'ipx.al-data geofeed collector (+https://github.com/yehyakin/ipx-al-data)'}
DBS = [
    'https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz',
    'https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz',
    'https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz',
    'https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz',
    'https://ftp.afrinic.net/pub/dbase/afrinic.db.gz',
    'https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz',
]
# 大厂直接公布、不挂在 RIPE/APNIC whois 上的 geofeed（官方地址，整份信任）
DIRECT = [
    'https://digitalocean.com/geo/google.csv',
    'https://geoip.linode.com/',
    'https://geofeed.constant.com/?text',
    'https://www.gstatic.com/ipranges/cloud_geofeed',
    'https://geoip.starlinkisp.net/feed.csv',
]
ARIN_TSV = 'https://raw.githubusercontent.com/yehyakin/ipx-al-data/arin/arin.tsv'
URL_RE = re.compile(r'https://\S+', re.I)
MAX_FEED = 30 * 1024 * 1024


def nets_of(key, val):
    """inetnum 'a - b' 或 inet6num CIDR → [ip_network]"""
    try:
        if key == 'inetnum':
            a, b = [x.strip() for x in val.split('-', 1)]
            return list(ipaddress.summarize_address_range(ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)))
        return [ipaddress.ip_network(val.strip(), strict=False)]
    except ValueError:
        return []


def scan(url, refs, stats):
    """流式读 whois 库，记录 geofeed url → 引用它的网段"""
    n = 0
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=600) as r:
        f = io.TextIOWrapper(gzip.GzipFile(fileobj=r), encoding='latin-1')
        key = val = None; feed = None
        for line in f:
            if not line.strip():
                if key and feed:
                    for nw in nets_of(key, val):
                        refs.setdefault(feed, []).append(nw)
                    n += 1
                key = val = feed = None
                continue
            if line[0] in ' \t+':
                continue
            k, _, v = line.partition(':')
            k = k.strip().lower(); v = v.strip()
            if k in ('inetnum', 'inet6num') and key is None:
                key, val = k, v
            elif k == 'geofeed' or (k == 'remarks' and v.lower().startswith('geofeed')):
                m = URL_RE.search(v)
                if m:
                    feed = m.group(0).rstrip('.,;')
        if key and feed:
            for nw in nets_of(key, val):
                refs.setdefault(feed, []).append(nw)
            n += 1
    stats[url.rsplit('/', 1)[-1]] = n


def fetch(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
            body = r.read(MAX_FEED + 1)
        if len(body) > MAX_FEED:
            return url, None, 'too-large'
        return url, body.decode('utf-8', 'replace'), 'ok'
    except Exception as e:
        return url, None, type(e).__name__


def main():
    os.makedirs(OUT, exist_ok=True)
    refs, stats = {}, {}
    for u in DBS:
        try:
            scan(u, refs, stats)
        except Exception as e:
            stats[u.rsplit('/', 1)[-1]] = f'error: {e}'
        print('scanned', u, stats.get(u.rsplit('/', 1)[-1]), 'urls', len(refs), flush=True)

    try:
        raw = urllib.request.urlopen(urllib.request.Request(ARIN_TSV, headers=UA), timeout=120).read().decode()
        n = 0
        for l in raw.splitlines():
            p = l.split('\t')
            if len(p) != 5 or l.startswith('#') or not p[4]:
                continue
            try:
                a, b = ipaddress.ip_address(p[2]), ipaddress.ip_address(p[3])
                nws = list(ipaddress.summarize_address_range(a, b))
            except ValueError:
                continue
            for u in p[4].split():
                refs.setdefault(u, []).extend(nws)
            n += 1
        stats['arin-rdap'] = n
    except Exception as e:
        stats['arin-rdap'] = f'error: {e}'
    print('arin', stats['arin-rdap'], 'urls', len(refs), flush=True)

    for u in DIRECT:
        refs.setdefault(u, []).extend([ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')])
    stats['direct'] = len(DIRECT)
    locs, lidx = [], {}
    items = {4: [], 6: []}  # (start, end, plen, loc)
    report = []
    with cf.ThreadPoolExecutor(48) as ex:
        for url, body, st in ex.map(fetch, list(refs)):
            ok = 0
            if body:
                par = {4: [], 6: []}
                for pa in ipaddress.collapse_addresses([x for x in refs[url] if x.version == 4]):
                    par[4].append((int(pa.network_address), int(pa.broadcast_address)))
                for pa in ipaddress.collapse_addresses([x for x in refs[url] if x.version == 6]):
                    par[6].append((int(pa.network_address), int(pa.broadcast_address)))
                starts = {v: [a for a, _ in par[v]] for v in par}

                def inside(nw):
                    L = par[nw.version]; i = bisect.bisect_right(starts[nw.version], int(nw.network_address)) - 1
                    return i >= 0 and L[i][0] <= int(nw.network_address) and int(nw.broadcast_address) <= L[i][1]
                for line in body.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    p = [x.strip() for x in line.split(',')]
                    try:
                        nw = ipaddress.ip_network(p[0], strict=False)
                    except ValueError:
                        continue
                    cc = (p[1] if len(p) > 1 else '').upper()
                    if not re.fullmatch(r'[A-Z]{2}', cc) or not nw.is_global:
                        continue
                    if not inside(nw):
                        continue  # 不在引用它的 inetnum 内：不授权
                    region = p[2] if len(p) > 2 else ''
                    city = p[3] if len(p) > 3 else ''
                    key = f'{cc}|{region}|{city}'
                    if key not in lidx:
                        lidx[key] = len(locs); locs.append(key)
                    if nw.version == 4:
                        items[4].append((int(nw.network_address), int(nw.broadcast_address), nw.prefixlen, lidx[key]))
                    else:
                        items[6].append((int(nw.network_address) >> 64, int(nw.broadcast_address) >> 64, min(nw.prefixlen, 64), lidx[key]))
                    ok += 1
            report.append((url, len(refs[url]), ok, st))

    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 1,
            'locations': locs, 'whois': stats, 'feeds': len(refs),
            'feeds_ok': sum(1 for r in report if r[3] == 'ok'), 'feeds_with_entries': sum(1 for r in report if r[2])}
    for ver, name, fmt in ((4, 'gf.bin', '<III'), (6, 'gf6.bin', '<IIIII')):
        it = items[ver]
        it.sort(key=lambda x: x[2])  # 宽的先写，具体的覆盖
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
        for s, e, l in rows:
            buf += struct.pack(fmt, s, e, l) if ver == 4 else struct.pack(fmt, s >> 32, s & 0xffffffff, e >> 32, e & 0xffffffff, l)
        open(os.path.join(OUT, name), 'wb').write(buf)
        meta[f'v{ver}'] = {'entries': len(it), 'ranges': len(rows)}
    with open(os.path.join(OUT, 'geofeed-urls.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['url', 'inetnums', 'accepted', 'status'])
        w.writerows(sorted(report))
    json.dump(meta, open(os.path.join(OUT, 'gf.json'), 'w'), ensure_ascii=False)
    print(json.dumps({k: v for k, v in meta.items() if k != 'locations'}, ensure_ascii=False), 'locations', len(locs))


if __name__ == '__main__':
    main()
