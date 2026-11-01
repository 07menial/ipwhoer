#!/usr/bin/env python3
"""国内 IP 库：把 ip2region（Apache-2.0, github.com/lionsoul2014/ip2region）的源数据切成小块，
供 ipx.al Worker 按需读取。输出 out/geo/{v4,v6}/idx.json 与 <n>.bin。

块格式（小端）：u32 count | count×start | count×end | count×u16 区域下标 | 区域字符串（\n 分隔，UTF-8）
v4 的 start/end 为 u32；v6 为 16 字节大端整数。区域串：国家|省|市|运营商|国家代码（"0" 记为空）。
"""
import ipaddress, json, os, struct, sys, urllib.request, datetime

SRC = 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv{}_source.txt'
CHUNK = {4: 4000, 6: 2000}
OUT = sys.argv[1] if len(sys.argv) > 1 else 'out/geo'


def rows(ver):
    path = os.environ.get(f'GEO_SRC_V{ver}')
    data = open(path, encoding='utf-8').read() if path else urllib.request.urlopen(SRC.format(ver), timeout=120).read().decode('utf-8')
    for line in data.splitlines():
        p = line.strip().split('|')
        if len(p) < 7:
            continue
        a, b = int(ipaddress.ip_address(p[0])), int(ipaddress.ip_address(p[1]))
        reg = '|'.join('' if x == '0' else x for x in p[2:7])
        if reg.startswith('Reserved'):
            continue
        yield a, b, reg


def build(ver):
    rs = sorted(rows(ver))
    d = os.path.join(OUT, f'v{ver}')
    os.makedirs(d, exist_ok=True)
    firsts = []
    for ci in range(0, len(rs), CHUNK[ver]):
        ch = rs[ci:ci + CHUNK[ver]]
        regs, ridx = [], {}
        for _, _, r in ch:
            if r not in ridx:
                ridx[r] = len(regs); regs.append(r)
        if ver == 4:
            body = struct.pack('<I', len(ch)) + b''.join(struct.pack('<I', a) for a, _, _ in ch) + b''.join(struct.pack('<I', b) for _, b, _ in ch)
            firsts.append(ch[0][0])
        else:
            body = struct.pack('<I', len(ch)) + b''.join(a.to_bytes(16, 'big') for a, _, _ in ch) + b''.join(b.to_bytes(16, 'big') for _, b, _ in ch)
            firsts.append(format(ch[0][0], '032x'))
        body += b''.join(struct.pack('<H', ridx[r]) for _, _, r in ch) + '\n'.join(regs).encode('utf-8')
        open(os.path.join(d, f'{len(firsts) - 1}.bin'), 'wb').write(body)
    json.dump({'src': 'ip2region', 'built': datetime.date.today().isoformat(), 'ranges': len(rs), 'first': firsts},
              open(os.path.join(d, 'idx.json'), 'w'), separators=(',', ':'))
    print(f'v{ver}: {len(rs)} ranges, {len(firsts)} chunks')


if __name__ == '__main__':
    build(4); build(6)
