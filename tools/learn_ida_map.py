#!/usr/bin/env python3
"""从「已完成的 version.json + 该版本的 IDA 导出」学习通用映射。

学到的不是 slot/key（每版都变），而是：
    函数名 -> 该函数内 MHY 读取的**顺序** -> 表名

换版本时只要函数还叫同一个名字、读取顺序不变，update.py 就能按位置
把新的 slot/op/key 填进 version.json，不需要旧版本的 slot。

用法：
    python3 tools/learn_ida_map.py version/7.0/version.json /tmp/opencode/ida70.json \
        --exe version/7.0/gi.exe -o tools/ida_table_map.json
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig as S
from gen_version import load_json_with_comments


def table_value(pe, mhy, t):
    slot = int(str(t['slot']), 0)
    raw = int.from_bytes(pe.D[pe.va2off(mhy + slot):pe.va2off(mhy + slot) + 4], 'little')
    key = int(str(t['key']), 0)
    if t['op'] == '^':
        return raw ^ key
    if t['op'] == '-':
        return (raw - key) & 0xFFFFFFFF
    return (raw + key) & 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('version_json')
    ap.add_argument('ida_json')
    ap.add_argument('--exe', default=None)
    ap.add_argument('--mhy', default=None)
    ap.add_argument('-o', '--out', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_table_map.json'))
    args = ap.parse_args()

    J = load_json_with_comments(args.version_json)
    E = json.load(open(args.ida_json, encoding='utf-8'))
    mhy = int(args.mhy or E.get('mhy') or J['addresses']['mhyTableVA'], 0)

    exe = args.exe
    if not exe:
        d = os.path.dirname(os.path.abspath(args.version_json))
        if os.path.exists(os.path.join(d, 'gi.exe')):
            exe = os.path.join(d, 'gi.exe')
        else:
            ver = str(J.get('version', '')).split()[0]
            exe = os.path.join(os.path.dirname(d), ver, 'gi.exe')
    pe = S.PE(exe)

    # 值 -> 名字。表值相同（如 propertiesOffset 与 genericClassRangeOffset 都是 0）
    # 时用函数名消歧；仍不唯一就留空，交给人工。
    byval = collections.defaultdict(list)
    for name, t in J['tables'].items():
        byval[table_value(pe, mhy, t)].append(name)
    for name, v in J.get('registrationFields', {}).items():
        if isinstance(v, str) and v.lower().startswith('0x'):
            byval[int(v, 0)].append('registrationFields.' + name)

    funcs = collections.defaultdict(list)
    for t in E['tables']:
        for f in t.get('funcs', []):
            funcs[f].append(t)

    out = {}
    for f, ts in sorted(funcs.items()):
        # 同一个 (slot,op,key) 可能在函数里出现多次（不同指令/调用点），按首次 seq 去重
        seen = set()
        uniq = []
        for t in sorted(ts, key=lambda x: x.get('seq', 0)):
            k = (t['slot'], t['op'], t['key'])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(t)

        order = []
        for t in uniq:
            val = int(str(t['value']), 0)
            names = byval.get(val, [])
            if len(names) > 1 and 'Properties' in f and 'propertiesOffset' in names:
                names = ['propertiesOffset']
            order.append(names[0] if len(names) == 1 else None)
        out[f] = order

    doc = {
        '_comment': '函数内 MHY 读取顺序 -> 表名。slot/key 每版都变，函数名和读取顺序相对稳定。'
                    '由 learn_ida_map.py 从已完成版本学习；换版本后可用 update.py 按位置填新 slot/op/key。',
        '_learned_from': args.version_json,
        'funcs': out,
    }
    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print('wrote', args.out)
    labeled = sum(1 for v in out.values() for x in v if x)
    total = sum(len(v) for v in out.values())
    print('functions: %d, reads: %d, labeled: %d, unknown: %d' % (len(out), total, labeled, total - labeled))
    for f, o in out.items():
        print('  %-48s %s' % (f, ', '.join(x or '(?)' for x in o)))


if __name__ == '__main__':
    main()
