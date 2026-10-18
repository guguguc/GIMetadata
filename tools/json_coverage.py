#!/usr/bin/env python3
"""json_coverage.py —— 对照目标 version.json 统计自动化覆盖率。

只做**验证/回归**，不参与生成。用于回答“脚本现在能正确填多少”。

用法:
    python3 tools/json_coverage.py \
        --draft version/7.0/version.draft.json \
        --target version/7.0/version.json \
        --base version.json

输出:
    · tables: slot/op/key 完全一致 + 解码后的表值一致
    · fieldDecode / structOffsets: 逐字段
    · keyFormulas: 逐公式在 i=0..N 上语义等价
    · stringDecrypt / addresses
    · 按 docs/UPDATE.md §5.9 的 202 口径估算总覆盖率
"""
import argparse
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_version import load_json_with_comments  # noqa: E402
from sig import PE  # noqa: E402

M32 = 0xFFFFFFFF


def norm_spec(v):
    op, k = str(v).split(':', 1)
    op = {'sub': '-', 'add': '+', 'xor': '^'}.get(op, op)
    return op, int(k, 0)


def cname(s):
    return ''.join(w[:1].upper() + w[1:] for w in re.split(r'[_\s]+', s) if w)


def eval_formula(f, i):
    e = f['cpp'].strip()
    if e.startswith('return '):
        e = e[7:]
    e = e.rstrip(';').strip()
    for c in ('(uint32_t)', '(uint64_t)', '(int32_t)', '(int64_t)'):
        e = e.replace(c, '')
    params = {k: v for k, v in f.items() if k not in ('sig', 'cpp')}
    ns = {}
    for k, v in params.items():
        ns['k' + cname(k)] = int(str(v), 0)
    for tok in set(re.findall(r'\bk[A-Za-z0-9_]+\b', e)):
        if tok in ns:
            continue
        cands = [(len(cname(k)), k) for k in params if tok.lower().endswith(cname(k).lower())]
        if cands:
            k = max(cands)[1]
            ns[tok] = int(str(params[k]), 0)
    m = re.search(r'\(\s*\w+\s+(\w+)\s*\)', f.get('sig', ''))
    ns[m.group(1) if m else 'i'] = i
    return eval(e, {'__builtins__': {}}, ns) & M32


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--draft', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--exe', default=None)
    ap.add_argument('--samples', type=int, default=200)
    a = ap.parse_args()
    D = load_json_with_comments(a.draft)
    T = load_json_with_comments(a.target)
    B = load_json_with_comments(a.base)
    exe = a.exe
    if not exe:
        root = os.path.dirname(os.path.abspath(a.target))
        exe = os.path.join(root, 'gi.exe')

    # tables
    pe = PE(exe) if os.path.exists(exe) else None
    mhy = int(str(T.get('addresses', {}).get('mhyTableVA', '0')), 0)

    def tval(tb):
        if not pe or not mhy:
            return None
        raw = struct.unpack_from('<I', pe.D, pe.va2off(mhy + int(str(tb['slot']), 0)))[0]
        k = int(str(tb['key']), 0)
        return {'^': raw ^ k, '-': (raw - k) & M32, '+': (raw + k) & M32}[tb['op']]

    t_exact = t_val = 0
    t_diff = []
    for n, tb in T.get('tables', {}).items():
        db = D.get('tables', {}).get(n)
        if not db:
            t_diff.append(n)
            continue
        if (str(db['slot']).lower(), db['op'], str(db['key']).lower()) == \
           (str(tb['slot']).lower(), tb['op'], str(tb['key']).lower()):
            t_exact += 1
        if tval(db) is not None and tval(db) == tval(tb):
            t_val += 1
        else:
            t_diff.append(n)

    # fieldDecode
    fd_ok = fd_tot = 0
    fd_miss = []
    for st, fs in T.get('fieldDecode', {}).items():
        for nm, v in fs.items():
            fd_tot += 1
            av = D.get('fieldDecode', {}).get(st, {}).get(nm)
            if av is not None and norm_spec(av) == norm_spec(v):
                fd_ok += 1
            else:
                fd_miss.append('%s.%s' % (st, nm))

    # structOffsets
    so_ok = so_tot = 0
    so_miss = []
    for st, fs in T.get('structOffsets', {}).items():
        for nm, v in fs.items():
            so_tot += 1
            if D.get('structOffsets', {}).get(st, {}).get(nm) == v:
                so_ok += 1
            else:
                so_miss.append('%s.%s' % (st, nm))

    # keyFormulas
    kf_ok = kf_tot = 0
    kf_const_ok = kf_const_tot = 0
    kf_miss = []
    for name, tf in T.get('keyFormulas', {}).items():
        kf_tot += 1
        tf_consts = sum(1 for k in tf if k not in ('sig', 'cpp'))
        kf_const_tot += tf_consts
        af = D.get('keyFormulas', {}).get(name)
        if af and all(eval_formula(af, i) == eval_formula(tf, i) for i in range(a.samples)):
            kf_ok += 1
            kf_const_ok += tf_consts
        else:
            kf_miss.append(name)

    # stringDecrypt / addresses
    def flat(fam):
        return T.get(fam, {}) if isinstance(T.get(fam), dict) else {}

    sd_ok = sd_tot = 0
    sd_miss = []
    for k, v in flat('stringDecrypt').items():
        sd_tot += 1
        if str(D.get('stringDecrypt', {}).get(k)).lower() == str(v).lower():
            sd_ok += 1
        else:
            sd_miss.append(k)
    ad_ok = ad_tot = 0
    ad_miss = []
    for k, v in flat('addresses').items():
        ad_tot += 1
        if str(D.get('addresses', {}).get(k)).lower() == str(v).lower():
            ad_ok += 1
        else:
            ad_miss.append(k)

    # 202 口径：addresses 4 + stringDecrypt 5 + tables 102 + keyFormulas 43 + fieldDecode 42 + counts 6
    # counts 这里只统计三个 *Formula 的 key/op 字段
    ncount = cok = 0
    for fam in ('genericClassRangeCountFormula', 'genericInstsCountFormula', 'typesCountFormula'):
        tf = T.get(fam) or {}
        df = D.get(fam) or {}
        for k in ('op', 'key'):
            if k in tf:
                ncount += 1
                cok += (str(df.get(k)).lower() == str(tf.get(k)).lower())
    # 202 口径：addresses 4 + stringDecrypt 5 + tables 102 + keyFormulas 43 + fieldDecode 42 + counts 6
    # keyFormulas 按目标公式的实常数个数加权，不再无条件 +43。
    kf_weight = int(round(43.0 * kf_const_ok / kf_const_tot)) if kf_const_tot else 0
    total = min(ad_ok, 4) + min(sd_ok, 5) + (t_val * 3) + kf_weight + min(fd_ok, 42) + cok
    print('== JSON coverage (draft vs target) ==')
    print('tables exact slot/op/key : %d / %d' % (t_exact, len(T.get('tables', {}))))
    print('tables decoded value     : %d / %d   (%d / 102 常量)' % (t_val, len(T.get('tables', {})), t_val * 3))
    print('fieldDecode              : %d / %d' % (fd_ok, fd_tot))
    print('structOffsets            : %d / %d' % (so_ok, so_tot))
    print('keyFormulas              : %d / %d  (%d / %d 常数, 计 %d/43)' %
          (kf_ok, kf_tot, kf_const_ok, kf_const_tot, kf_weight))
    print('stringDecrypt            : %d / %d' % (sd_ok, sd_tot))
    print('addresses                : %d / %d' % (ad_ok, ad_tot))
    print('count formulas (op/key)  : %d / %d' % (cok, ncount))
    print('202 estimate             : %d / 202 (%.1f%%)' % (total, 100.0 * total / 202))
    if fd_miss:
        print('fieldDecode missing      :', ', '.join(fd_miss))
    if kf_miss:
        print('keyFormulas missing      :', ', '.join(kf_miss))
    if t_diff:
        print('tables value diff        :', ', '.join(t_diff))
    if sd_miss:
        print('stringDecrypt diff       :', ', '.join(sd_miss))
    if ad_miss:
        print('addresses diff           :', ', '.join(ad_miss))


if __name__ == '__main__':
    main()
