#!/usr/bin/env python3
"""ipx RIR 登记日期层：五大 RIR 官方 delegated-extended 统计文件（公开数据）。

每条记录的日期是 RIR 最后一次登记变更的日子，不一定是首次分配；报告里写「记录于」。
只收 allocated / assigned。

输出 OUT/：
  rir.bin   IPv4，每条 12 字节小端：start u32, end u32, date u32（YYYYMMDD）
  rir6.bin  IPv6，每条 20 字节：start 高 64 位（hi, lo）, end 高 64 位, date
  rir.json  构建时间、各 RIR 条数
"""
import datetime as dt, ipaddress, json, os, struct, sys, urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
URLS = {
    'arin': 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ripencc': 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
    'apnic': 'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
    'lacnic': 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
    'afrinic': 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
}
UA = {'User-Agent': 'ipx.al-data (+https://github.com/yehyakin/ipx-al-data)'}


def main():
    os.makedirs(OUT, exist_ok=True)
    v4, v6, counts = [], [], {}
    for rir, url in URLS.items():
        try:
            t = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180).read().decode('utf-8', 'replace')
        except Exception as e:
            counts[rir] = 'error: ' + type(e).__name__; print(rir, e, file=sys.stderr); continue
        n = 0
        for l in t.splitlines():
            p = l.split('|')
            if len(p) < 7 or p[6] not in ('allocated', 'assigned') or not (p[5].isdigit() and len(p[5]) == 8) or p[5] < '19800101':
                continue
            d = int(p[5])
            try:
                if p[2] == 'ipv4':
                    s = int(ipaddress.IPv4Address(p[3])); v4.append((s, s + int(p[4]) - 1, d)); n += 1
                elif p[2] == 'ipv6' and int(p[4]) <= 64:
                    net = ipaddress.IPv6Network(f'{p[3]}/{p[4]}')
                    v6.append((int(net.network_address) >> 64, int(net.broadcast_address) >> 64, d)); n += 1
            except ValueError:
                continue
        counts[rir] = n
        print(rir, n, file=sys.stderr)
    if sum(c for c in counts.values() if isinstance(c, int)) < 100000:
        sys.exit('too few records, keep previous layer')
    def flat(rows):  # 按起点排序，重叠时保留先出现的（各 RIR 互不重叠，防御而已）
        out = []
        for s, e, d in sorted(rows):
            if out and s <= out[-1][1]:
                continue
            out.append((s, e, d))
        return out
    v4, v6 = flat(v4), flat(v6)
    M = 0xffffffff
    open(os.path.join(OUT, 'rir.bin'), 'wb').write(b''.join(struct.pack('<III', s, e, d) for s, e, d in v4))
    open(os.path.join(OUT, 'rir6.bin'), 'wb').write(b''.join(struct.pack('<IIIII', s >> 32, s & M, e >> 32, e & M, d) for s, e, d in v6))
    json.dump({'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'v4': len(v4), 'v6': len(v6), 'counts': counts,
               'note': 'date = RIR 最后一次登记变更日，不一定是首次分配'}, open(os.path.join(OUT, 'rir.json'), 'w'), ensure_ascii=False, indent=1)


if __name__ == '__main__':
    main()
