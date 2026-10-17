#!/usr/bin/env python3
"""ida_apply.py —— 把 IDA 导出的常量（`ida_export.py` 的产物）**配对**到表名。

思路：
  `ida_export.py` 给出 (slot, op, key, value, funcs)
  `table_funcs.json` 给出 (函数 -> 该函数读哪些表)
  两者相交 -> 候选；再用已自动检测到的值（relocate ④/⑧）和计数公式消歧。

用法：
    python3 tools/ida_apply.py /tmp/ida_export.json \
        --detected /tmp/detected.json --out /tmp/tables.json

  `--detected` 形如 {"fieldsOffset": "0x8D07B4", ...}（relocate 输出里摘出来即可）
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(p):
    return json.load(open(p, encoding='utf-8'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('export')
    ap.add_argument('--funcs', default=os.path.join(HERE, 'table_funcs.json'))
    ap.add_argument('--detected', default=None)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    exp = load(a.export)
    fmap = load(a.funcs)
    detected = {}
    if a.detected and os.path.exists(a.detected):
        detected = {k: int(v, 0) if isinstance(v, str) else int(v)
                    for k, v in load(a.detected).items()}

    tables = exp.get('tables', [])
    print('IDA 导出：%d 个 (slot,op,key)，MHY 全局 = %s' % (len(tables), exp.get('mhy_global')))

    # ---- 1) 按「函数 -> 表」建候选 ----
    by_table = {}
    for t in tables:
        for fn in t.get('funcs', []):
            for name in fmap.get(fn, []):
                by_table.setdefault(name, []).append(t)

    # ---- 2) 消歧 ----
    result, unresolved = {}, {}
    for name, cands in sorted(by_table.items()):
        # 2a) 已知值（④/⑧ 检测到） -> 直接按 value 匹配
        if name in detected:
            hit = [c for c in cands if c.get('value') and int(c['value'], 16) == detected[name]]
            if len(hit) == 1:
                result[name] = hit[0]
                continue
        # 2b) 只有一个候选 -> 直接用
        uniq = {(c['slot'], c['op'], c['key']): c for c in cands}
        if len(uniq) == 1:
            result[name] = list(uniq.values())[0]
        else:
            unresolved[name] = list(uniq.values())

    print('\n=== 已确定 %d 张表 ===' % len(result))
    for name, t in sorted(result.items()):
        print('  %-42s slot %-6s %s %-12s -> %-10s (函数 %s)'
              % (name, t['slot'], t['op'], t['key'], t.get('value'),
                 ','.join(t.get('funcs', [])[:2])))

    if unresolved:
        print('\n=== 需要消歧 %d 张（同一函数读了多张表）===' % len(unresolved))
        for name, cands in sorted(unresolved.items()):
            print('  %s:' % name)
            for c in cands[:6]:
                print('     slot %-6s %s %-12s value=%-10s  (%s)'
                      % (c['slot'], c['op'], c['key'], c.get('value'),
                         ','.join(c.get('funcs', [])[:2])))

    frag = {'tables': {k: {'slot': v['slot'], 'op': v['op'], 'key': v['key']}
                       for k, v in result.items()}}
    if a.out:
        json.dump(frag, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('\n已写 %s' % a.out)
    print('\n可直接填 version.json 的片段（%d 项）:' % len(result))
    print(json.dumps(frag, ensure_ascii=False, indent=1)[:1200])


if __name__ == '__main__':
    sys.exit(main())
