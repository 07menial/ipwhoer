#!/usr/bin/env python3
"""ipx RIR 登记日期层：五大 RIR 官方 delegated-extended 统计文件（公开数据）。

每条记录的日期是 RIR 最后一次登记变更的日子，不一定是首次分配；报告里写「记录于」。
只收 allocated / assigned。

v2（2026-11-06）起每条带 delegated 统计里的国家（拿到这块分配的 LIR 所在国，不一定是网段登记的使用国）。
国家用两个字母的 ASCII 码拼成 u32：(ord(a) << 8) | ord(b)，没有国家写 0。

输出 OUT/（小端，16 字节文件头 ffffffff, 2, 每条字节数, 0；v1 没有文件头，第一条的 start 不可能是 ffffffff）：
  rir.bin   IPv4，每条 16 字节：start u32, end u32, date u32（YYYYMMDD）, cc u32
  rir6.bin  IPv6，每条 24 字节：start 高 64 位（hi, lo）, end 高 64 位（hi, lo）, date, cc
  rir.json  构建时间、各 RIR 条数、format
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
            d = int(p[5]); c = p[1].upper()
            ccv = (ord(c[0]) << 8) | ord(c[1]) if len(c) == 2 and c.isalpha() and c.isascii() and c != 'ZZ' else 0
            try:
                if p[2] == 'ipv4':
                    s = int(ipaddress.IPv4Address(p[3])); v4.append((s, s + int(p[4]) - 1, d, ccv)); n += 1
                elif p[2] == 'ipv6' and int(p[4]) <= 64:
                    net = ipaddress.IPv6Network(f'{p[3]}/{p[4]}')
                    v6.append((int(net.network_address) >> 64, int(net.broadcast_address) >> 64, d, ccv)); n += 1
            except ValueError:
                continue
        counts[rir] = n
        print(rir, n, file=sys.stderr)
    if sum(c for c in counts.values() if isinstance(c, int)) < 100000:
        sys.exit('too few records, keep previous layer')
    def flat(rows):  # 按起点排序，重叠时保留先出现的（各 RIR 互不重叠，防御而已）
        out = []
        for r in sorted(rows):
            if out and r[0] <= out[-1][1]:
                continue
            out.append(r)
        return out
    v4, v6 = flat(v4), flat(v6)
    M = 0xffffffff
    open(os.path.join(OUT, 'rir.bin'), 'wb').write(struct.pack('<IIII', M, 2, 16, 0) + b''.join(struct.pack('<IIII', s, e, d, c) for s, e, d, c in v4))
    open(os.path.join(OUT, 'rir6.bin'), 'wb').write(struct.pack('<IIII', M, 2, 24, 0) + b''.join(struct.pack('<IIIIII', s >> 32, s & M, e >> 32, e & M, d, c) for s, e, d, c in v6))
    json.dump({'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'v4': len(v4), 'v6': len(v6), 'counts': counts, 'format': 2,
               'note': 'date = RIR 最后一次登记变更日，不一定是首次分配；cc = delegated 统计的国家（LIR 所在国）'}, open(os.path.join(OUT, 'rir.json'), 'w'), ensure_ascii=False, indent=1)


if __name__ == '__main__':
    main()
