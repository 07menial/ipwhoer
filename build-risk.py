#!/usr/bin/env python3
"""ipx.al 风险库构建：聚合公开威胁情报 → 不重叠的 IPv4 区间表。

输出（写到 OUT 目录，默认 ./risk-data）：
  risk.bin   每条 16 字节小端：start u32, end u32, mask u32, first u32（首次出现，距 2026-01-01 的天数）
  risk.json  元数据：来源列表（bit、名称、类别、链接、条数）、构建时间、区间数
  state.json.gz  首次出现时间状态（下次构建读取，保持 first 不变）
  sources.csv    可读版本（start,end,sources,first_seen）
只用公开、允许再分发的数据；不含任何站点访客查询记录。
"""
import csv, datetime as dt, gzip, io, ipaddress, json, os, re, struct, sys, urllib.request, zipfile

OUT = sys.argv[1] if len(sys.argv) > 1 else 'risk-data'
UA = 'ipx.al risk builder (+https://ipx.al/risk)'
EPOCH = dt.date(2026, 1, 1)
TODAY = dt.datetime.now(dt.timezone.utc).date()

# bit, id, 名称, 类别, 链接, 拉取地址, 解析器
SOURCES = [
    (0, 'dshield', 'SANS DShield 攻击源', '扫描/攻击', 'https://isc.sans.edu/', 'https://isc.sans.edu/api/sources/attacks/5000?json', 'dshield'),
    (1, 'blocklistde', 'blocklist.de', '爆破/攻击', 'https://www.blocklist.de/', 'https://lists.blocklist.de/lists/all.txt', 'lines'),
    (2, 'cins', 'CINS Army', '扫描/攻击', 'https://cinsscore.com/', 'https://cinsscore.com/list/ci-badguys.txt', 'lines'),
    (3, 'ipsum', 'IPsum（≥3 个名单）', '综合', 'https://github.com/stamparm/ipsum', 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', 'ipsum'),
    (4, 'firehol1', 'FireHOL Level 1', '综合', 'https://iplists.firehol.org/', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'lines'),
    (5, 'spamhausdrop', 'Spamhaus DROP', '劫持/恶意网段', 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/', 'https://www.spamhaus.org/drop/drop_v4.json', 'drop'),
    (6, 'tor', 'Tor 出口节点', '匿名网络', 'https://check.torproject.org/', 'https://check.torproject.org/torbulkexitlist', 'lines'),
    (7, 'feodo', 'abuse.ch Feodo 僵尸网络 C2', '僵尸网络', 'https://feodotracker.abuse.ch/', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'lines'),
    (8, 'etcompromised', 'Emerging Threats 已失陷主机', '失陷主机', 'https://rules.emergingthreats.net/', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'lines'),
    (9, 'sfs', 'StopForumSpam（30 天）', '垃圾注册', 'https://www.stopforumspam.com/', 'https://www.stopforumspam.com/downloads/listed_ip_30.zip', 'sfszip'),
]


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def rng(tok):
    tok = tok.strip()
    try:
        if '/' in tok:
            n = ipaddress.ip_network(tok, strict=False)
            if n.version != 4 or not n.is_global or int(n.broadcast_address) >= 0xE0000000: return None  # 去掉 FireHOL 里的保留/私网/组播段
            return int(n.network_address), int(n.broadcast_address)
        a = ipaddress.ip_address(tok)
        if a.version != 4: return None
        return int(a), int(a)
    except ValueError:
        return None


def parse(kind, raw):
    out = []
    if kind == 'lines':
        for l in raw.decode(errors='replace').splitlines():
            l = l.split('#')[0].split(';')[0].strip()
            if l and (r := rng(l.split()[0])): out.append(r)
    elif kind == 'ipsum':
        for l in raw.decode().splitlines():
            if l.startswith('#'): continue
            p = l.split()
            if len(p) == 2 and int(p[1]) >= 3 and (r := rng(p[0])): out.append(r)
    elif kind == 'dshield':
        for x in json.loads(raw):
            ip = '.'.join(str(int(o)) for o in str(x.get('ip', '')).split('.')) if x.get('ip') else ''
            if ip and (r := rng(ip)): out.append(r)
    elif kind == 'drop':
        for l in raw.decode().splitlines():
            try: j = json.loads(l)
            except ValueError: continue
            if 'cidr' in j and (r := rng(j['cidr'])): out.append(r)
    elif kind == 'sfszip':
        z = zipfile.ZipFile(io.BytesIO(raw))
        for name in z.namelist():
            for l in z.read(name).decode(errors='replace').splitlines():
                tok = l.split(',')[0].strip().strip('"')
                if tok and (r := rng(tok)): out.append(r)
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    state = {}
    sp = os.path.join(OUT, 'state.json.gz')
    if os.path.exists(sp):
        state = json.loads(gzip.decompress(open(sp, 'rb').read()))
    events = []  # (pos, +bit / -bit)
    meta = []
    for bit, sid, name, cat, link, url, kind in SOURCES:
        try:
            rs = parse(kind, get(url))
            err = None
        except Exception as e:
            rs, err = [], str(e)[:120]
        # 来源失败时沿用上次条目（state 里保存的区间），避免数据突然消失
        if not rs and sid in state.get('_last', {}):
            rs = [tuple(x) for x in state['_last'][sid]]
            err = (err or 'empty') + '（沿用上次数据）'
        for s, e in rs:
            events.append((s, 0, bit)); events.append((e + 1, 1, bit))
        state.setdefault('_last', {})[sid] = rs
        meta.append({'bit': bit, 'id': sid, 'name': name, 'cat': cat, 'link': link, 'count': len(rs), 'error': err})
        print(f'{sid:14} {len(rs):7}', err or '', file=sys.stderr)
    events.sort()
    cnt = [0] * 32
    rows = []
    prev, i = None, 0
    while i < len(events):
        pos = events[i][0]
        if prev is not None and pos > prev:
            mask = sum(1 << b for b in range(32) if cnt[b] > 0)
            if mask:
                if rows and rows[-1][1] == prev - 1 and rows[-1][2] == mask:
                    rows[-1][1] = pos - 1
                else:
                    rows.append([prev, pos - 1, mask])
        while i < len(events) and events[i][0] == pos:
            _, typ, b = events[i]
            cnt[b] += 1 if typ == 0 else -1
            i += 1
        prev = pos
    fs = state.get('first', {})
    today = (TODAY - EPOCH).days
    newfs = {}
    buf = bytearray()
    for s, e, m in rows:
        k = f'{s}-{e}'
        f = fs.get(k, today)
        newfs[k] = f
        buf += struct.pack('<IIII', s, e, m, f)
    state['first'] = newfs
    open(os.path.join(OUT, 'risk.bin'), 'wb').write(buf)
    open(sp, 'wb').write(gzip.compress(json.dumps(state, separators=(',', ':')).encode()))
    json.dump({'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'epoch': EPOCH.isoformat(),
               'ranges': len(rows), 'ips': sum(e - s + 1 for s, e, _ in rows), 'sources': meta},
              open(os.path.join(OUT, 'risk.json'), 'w'), ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, 'sources.csv'), 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['start', 'end', 'sources', 'first_seen'])
        ids = {b: sid for b, sid, *_ in SOURCES}
        for s, e, m in rows:
            w.writerow([str(ipaddress.ip_address(s)), str(ipaddress.ip_address(e)),
                        '|'.join(ids[b] for b in range(32) if m >> b & 1), (EPOCH + dt.timedelta(days=newfs[f'{s}-{e}'])).isoformat()])
    print('ranges', len(rows), 'bytes', len(buf), file=sys.stderr)


if __name__ == '__main__':
    main()
