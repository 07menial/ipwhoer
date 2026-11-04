#!/usr/bin/env python3
"""发布前的数据质量把关（每次 risk.yml 构建后运行，离线，不调用任何外部 API）。
用法：check-data.py <新数据目录> <上一版目录> <样本 tsv>
每一层（机房段库 dc、地理层 gf、VPN 出口库 vpn）分别检查：
  1. 条数不能比上一版少 20% 以上（来源抓取失败、半截文件）；
  2. 用 RIPE Atlas 独立标注样本（eval/atlas.tsv：ip、探针主人自报类型、国家）算命中率 / 误报率，低于门槛就判失败。
失败的层：把上一版文件放回新数据目录（继续用旧数据），原因写入 check.txt，workflow 据此开 issue。
"""
import sys, os, struct, bisect, json, ipaddress, shutil
NEW, PREV, SAMPLES = sys.argv[1:4]
FILES = {'dc': ['dc.bin', 'dc6.bin', 'dc.json', 'dc.csv'], 'gf': ['gf.bin', 'gf6.bin', 'gf.json', 'geofeed-urls.csv'], 'vpn': ['vpn.bin', 'vpn6.bin', 'vpn.json']}
SZ = {'dc.bin': 16, 'gf.bin': 12, 'vpn.bin': 12}

def rows(d, f):
    p = os.path.join(d, f)
    if not os.path.exists(p): return None
    b = open(p, 'rb').read(); n = SZ[f]
    return [struct.unpack_from('<' + 'I' * (n // 4), b, i) for i in range(0, len(b) - len(b) % n, n)]

def finder(T):
    S = [r[0] for r in T]
    def f(ip):
        i = bisect.bisect_right(S, ip) - 1
        return T[i] if i >= 0 and T[i][1] >= ip else None
    return f

samples = []
for l in open(SAMPLES):
    p = l.rstrip('\n').split('\t')
    if len(p) >= 3: samples.append((int(ipaddress.IPv4Address(p[0])), p[1], p[2]))
by = lambda t: [s for s in samples if s[1] == t]
msgs, notes = [], []

def check(layer, binf, quality):
    new, old = rows(NEW, binf), rows(PREV, binf)
    why = []
    if not new: why.append('文件缺失或为空')
    elif old and len(new) < 0.8 * len(old): why.append(f'条数从 {len(old)} 掉到 {len(new)}')
    if new and not why: why += quality(new)
    if why:
        if old:
            for f in FILES[layer]:
                src = os.path.join(PREV, f)
                if os.path.exists(src): shutil.copy(src, os.path.join(NEW, f))
            msgs.append(f'{layer}：' + '；'.join(why) + '，已保留上一版')
        else:
            msgs.append(f'{layer}：' + '；'.join(why) + '（没有上一版可回退）')
    notes.append(f'{layer} {len(new or [])} 条（上一版 {len(old or [])}）')

def q_dc(T):
    f = finder(T); h, i = by('hosting'), by('isp')
    hit = sum(1 for s in h if f(s[0])) / max(1, len(h)); fp = sum(1 for s in i if f(s[0])) / max(1, len(i))
    notes.append(f'dc 机房样本命中 {hit:.0%}，家宽样本误报 {fp:.1%}')
    out = []
    if h and hit < 0.25: out.append(f'机房样本命中率 {hit:.0%} < 25%')
    if i and fp > 0.06: out.append(f'家宽样本误报 {fp:.1%} > 6%')
    return out

def q_gf(T):
    f = finder(T)
    try: locs = json.load(open(os.path.join(NEW, 'gf.json')))['locations']
    except Exception: return ['gf.json 读不到 locations']
    cov = agree = 0
    for ip, t, cc in samples:
        r = f(ip)
        if r:
            cov += 1; agree += locs[r[2]].split('|')[0] == cc
    notes.append(f'gf 覆盖 {cov}/{len(samples)}，国家一致 {agree}/{cov}')
    if cov >= 20 and agree / cov < 0.95: return [f'国家一致率 {agree}/{cov} < 95%']
    return []

def q_vpn(T):
    f = finder(T); n = sum(1 for s in samples if f(s[0]))
    notes.append(f'vpn 在非 VPN 样本上命中 {n}')
    return [f'在 {n} 个非 VPN 样本上命中（> 3）'] if n > 3 else []

check('dc', 'dc.bin', q_dc); check('gf', 'gf.bin', q_gf); check('vpn', 'vpn.bin', q_vpn)
print('\n'.join(notes))
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check.txt'), 'w').write('\n'.join(msgs))
if msgs: print('BLOCKED:', '\n'.join(msgs))
