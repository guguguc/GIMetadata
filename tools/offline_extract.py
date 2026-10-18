#!/usr/bin/env python3
"""离线从 IDA 反编译文本补表（不启动 IDA）。

用途：ida_export.py 的正则曾经只认 `_DWORD`，漏掉 `int` 形式的表读取。
本脚本用同样的规则（类型下划线可选、32 位类型）重扫 decomp/*.c，
把 `g_MHY_Table + slot` 的读取合并回 ida.json，并标出可直接命名的表。

用法：
  python3 tools/offline_extract.py version/7.0
"""
import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig as S

RE_TABLE = re.compile(
    r'\*\(_?(\w+) \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)(?:LL|L)?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
OK_W = {'DWORD', 'int', 'unsigned', '__int32', 'u32', 'uint32_t', 'LODWORD'}
OK_OP = {'^', '-', '+'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--ida', default=None, help='默认 <root>/ida.json')
    ap.add_argument('--decomp', default=None, help='默认 <root>/ida/decomp')
    ap.add_argument('--table-funcs', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'table_funcs.json'))
    ap.add_argument('--ida-map', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_table_map.json'),
                    help='上一版学到的函数->读取顺序->表名')
    ap.add_argument('--out-extra', default=None, help='默认 <root>/ida/tables_extra.json')
    args = ap.parse_args()

    root = args.root if os.path.isabs(args.root) else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), args.root)
    ida_path = args.ida or os.path.join(root, 'ida.json')
    decomp = args.decomp or os.path.join(root, 'ida', 'decomp')
    extra_path = args.out_extra or os.path.join(root, 'ida', 'tables_extra.json')

    D = json.load(open(ida_path, encoding='utf-8'))
    mhy = int(str(D.get('mhy') or '0'), 0)
    exe = os.path.join(root, 'gi.exe')
    pe = S.PE(exe)

    def raw(slot):
        off = pe.va2off(mhy + slot)
        return int.from_bytes(pe.D[off:off + 4], 'little')

    def value(slot, op, key):
        v = raw(slot)
        return (v ^ key) if op == '^' else ((v - key) & 0xFFFFFFFF) if op == '-' else ((v + key) & 0xFFFFFFFF)

    tables = {tuple([int(str(t['slot']), 0), t['op'], int(str(t['key']), 0)]): t for t in D.get('tables', [])}
    added = []
    for f in sorted(glob.glob(os.path.join(decomp, '*.c'))):
        base = os.path.basename(f)[:-2]
        m = re.match(r'(.+)_([0-9A-Fa-f]{6,})$', base)
        if not m:
            continue
        fname, fea = m.group(1), int(m.group(2), 16)
        text = open(f, encoding='utf-8').read()
        for mm in RE_TABLE.finditer(text):
            w, g, slot, op, key = mm.group(1), mm.group(2), mm.group(3), mm.group(4), mm.group(5)
            if w not in OK_W or g != 'g_MHY_Table' or op not in OK_OP:
                continue
            slot = int(slot, 0); key = int(key, 0)
            k = (slot, op, key)
            if k in tables:
                fn = tables[k].setdefault('funcs', [])
                if fname not in fn:
                    fn.append(fname)
                tables[k]['n_funcs'] = len(fn)
            else:
                ent = {'slot': '0x%X' % slot, 'op': op, 'key': '0x%X' % key,
                       'base': 'g_MHY_Table', 'value': '0x%X' % value(slot, op, key),
                       'n_funcs': 1, 'funcs': [fname], 'func_eas': ['0x%X' % fea],
                       'seq': mm.start(), 'source': 'offline:' + base}
                tables[k] = ent
                added.append(ent)

    D['tables'] = list(tables.values())
    D.setdefault('_offline', {})['added'] = len(added)
    D['_offline']['decomp'] = os.path.relpath(decomp, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    json.dump(D, open(ida_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    # 通用标注：从上一版（7.1）学到的函数->读取顺序->表名
    # 不写死任何 7.0 表名；只按同一函数内的 seq 位置对齐。
    from collections import defaultdict
    mp = {}
    try:
        mp = json.load(open(args.ida_map, encoding='utf-8')).get('funcs', {})
    except Exception:
        pass
    tf = {}
    try:
        tf = json.load(open(args.table_funcs, encoding='utf-8'))
    except Exception:
        pass

    func_tables = defaultdict(list)
    for k, t in tables.items():
        fns = t.get('funcs', [])
        if not fns:
            continue
        # 只用主函数（funcs[0]）建立读取顺序；一张表同时出现在多个函数里时，
        # 其他函数只是“也读了这张表”，不能拿它们的顺序来对齐。
        fn = fns[0]
        func_tables[fn].append((t.get('seq', 0), t))

    labeled = {}
    # 1) 上一版 map 里有这个函数：按读取顺序对齐（map 允许 None）
    for fn, names in mp.items():
        if fn not in func_tables:
            continue
        ents = sorted(func_tables[fn], key=lambda x: x[0])
        for (seq, t), nm in zip(ents, names):
            if nm:
                labeled[nm] = t
    # 2) 7.1 的 IDA 里没有的函数（例如 SetupEventsLocked）：用语义表函数兜底
    for fn, names in tf.items():
        if fn.startswith('_') or fn in mp or fn not in func_tables:
            continue
        ents = sorted(func_tables[fn], key=lambda x: x[0])
        if len(ents) == len(names):
            for (seq, t), nm in zip(ents, names):
                labeled[nm] = t
    # 保留已有的人工/派生表项（例如从 IDA 反编译里手工确认的 nested/default blob）
    try:
        old_extra = json.load(open(extra_path, encoding='utf-8')) if os.path.exists(extra_path) else {}
    except Exception:
        old_extra = {}
    old_extra.update(labeled)
    json.dump(old_extra, open(extra_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    print('added %d tables; total %d; labeled %d' % (len(added), len(tables), len(labeled)))
    for e in added:
        print('  + slot 0x%-4X %s 0x%-10X -> 0x%X  (%s)' % (int(e['slot'], 16), e['op'], int(e['key'], 16), int(e['value'], 16), ','.join(e['funcs'])))
    print('labeled:', sorted(labeled))


if __name__ == '__main__':
    main()
