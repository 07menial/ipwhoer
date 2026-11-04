#!/usr/bin/env python3
"""ARIN 区 geofeed 发现：ARIN 没有公开批量 whois 库，只能逐块问 RDAP。

1. 读 ARIN 公开的 delegated-arin-extended-latest，列出所有已分配/指派的 IPv4、IPv6 块。
2. 对每个块调用 rdap.arin.net，读 NetRange 的 remarks 里的 `Geofeed: https://...`（RFC 9632）。
3. 结果写 arin.tsv：查询块、查询日期、NetRange 起止、geofeed 地址（空格分隔，可为空）。
   build-geofeed.py 用 NetRange 起止做授权范围，只接受落在里面的条目。

全量约 9 万块，按每秒约 6 次需要 4 小时以上，所以按时间预算分批：先查从没查过的块，
再按日期从旧到新复查（超过 30 天的）。上次的 arin.tsv 作为进度，下次接着跑。
只拿到直接分配那一层的 geofeed；下游客户（reassignment）自己挂的 geofeed 不在里面。
"""
import concurrent.futures as cf, datetime as dt, ipaddress, json, os, re, sys, threading, time, urllib.error, urllib.request

PREV = sys.argv[1] if len(sys.argv) > 1 else 'arin.tsv'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'arin.tsv'
BUDGET = int(os.environ.get('BUDGET', '18000'))
THREADS = int(os.environ.get('THREADS', '8'))
UA = {'User-Agent': 'ipx.al-data geofeed collector (+https://github.com/yehyakin/ipx-al-data)', 'Accept': 'application/rdap+json'}
URL_RE = re.compile(r'https://\S+', re.I)
TODAY = dt.date.today().toordinal()


def blocks():
    raw = urllib.request.urlopen(urllib.request.Request('https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest', headers=UA), timeout=120).read().decode()
    out = []
    for l in raw.splitlines():
        p = l.split('|')
        if len(p) < 7 or p[0] != 'arin' or p[2] not in ('ipv4', 'ipv6') or p[6] not in ('allocated', 'assigned'):
            continue
        if p[2] == 'ipv4':
            a = ipaddress.IPv4Address(p[3]); n = int(p[4])
            out += [str(nw) for nw in ipaddress.summarize_address_range(a, a + n - 1)]
        else:
            out.append(f'{p[3]}/{p[4]}')
    return out


stat = {'ok': 0, '404': 0, '429': 0, 'err': 0}
lock = threading.Lock()


def query(b):
    for i in range(4):
        try:
            d = json.load(urllib.request.urlopen(urllib.request.Request('https://rdap.arin.net/registry/ip/' + b, headers=UA), timeout=30))
            feeds = []
            for r in d.get('remarks', []):
                for x in r.get('description', []):
                    if x.lower().lstrip().startswith('geofeed'):
                        m = URL_RE.search(x)
                        if m:
                            feeds.append(m.group(0).rstrip('.,;'))
            with lock: stat['ok'] += 1
            return b, [b, str(TODAY), d.get('startAddress', ''), d.get('endAddress', ''), ' '.join(feeds)]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                with lock: stat['404'] += 1
                return b, [b, str(TODAY), '', '', '']
            with lock: stat['429' if e.code == 429 else 'err'] += 1
            time.sleep(5 * (i + 1) if e.code == 429 else 2)
        except Exception:
            with lock: stat['err'] += 1
            time.sleep(2)
    return b, None


def main():
    rows = {}
    if os.path.exists(PREV):
        for l in open(PREV, encoding='utf-8'):
            p = l.rstrip('\n').split('\t')
            if len(p) == 5 and not p[0].startswith('#'):
                rows[p[0]] = p
    bl = blocks()
    live = set(bl)
    rows = {k: v for k, v in rows.items() if k in live}
    todo = [b for b in bl if b not in rows]
    todo += sorted((b for b in rows if TODAY - int(rows[b][1]) > 30), key=lambda b: int(rows[b][1]))
    print('blocks', len(bl), 'known', len(rows), 'todo', len(todo), flush=True)
    t0 = time.time(); n = 0
    with cf.ThreadPoolExecutor(THREADS) as ex:
        it = iter(todo); pending = set()
        while True:
            while len(pending) < THREADS * 2 and time.time() - t0 < BUDGET:
                b = next(it, None)
                if b is None: break
                pending.add(ex.submit(query, b))
            if not pending: break
            done, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
            for f in done:
                b, r = f.result(); n += 1
                if r: rows[b] = r
            if n and n % 2000 < len(done):
                print(n, round(n / (time.time() - t0), 1), '/s', stat, flush=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('# block\tqueried(ordinal)\tnet_start\tnet_end\tgeofeeds\n')
        for b in bl:
            if b in rows: f.write('\t'.join(rows[b]) + '\n')
    feeds = {u for r in rows.values() for u in r[4].split()}
    print(json.dumps({'queried_now': n, 'known': len(rows), 'of': len(bl), 'with_geofeed': sum(1 for r in rows.values() if r[4]), 'feed_urls': len(feeds), **stat}))


if __name__ == '__main__':
    main()
