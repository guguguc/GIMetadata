#!/usr/bin/env python3
"""
ida_fielddecode.py —— 把 `fieldDecode`（42 个常数）从 IDA 导出里**自动回填**。

原理
----
`version.json` 里每个字段的值就是 `op:key`（如 `xor:0x4D8127F2`）。
而 `ida_export.py` 的 `fieldDecode` 每条是 `(width, disp, op, key, funcs...)`。

  ① 旧版本：用已知的 `(op, key)` 在旧导出里反查 -> 得到该字段的 `(width, disp)`
     （实测 7.1：42 个里 16 个能唯一匹配；其余需要导出正则放宽）
  ② 新版本：找 **同一 `(width, disp, op)`** 且**函数上下文相同**的条目 -> 取它的 `key`
  ③ 若同位置多条且 key 不一致 -> 报歧义，不猜

用法
----
    python3 tools/ida_fielddecode.py \
        --old /tmp/ida71.json --new /tmp/ida70.json \
        --version-json version.json --out /tmp/fielddecode70.json
"""
import argparse
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

OPMAP = {'sub': '-', 'xor': '^', 'add': '+', '-': '-', '^': '^', '+': '+'}


def parse_val(v):
    op, k = v.split(':', 1)
    return OPMAP.get(op, op), int(k, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True, help='旧版本 ida_export.py 的 JSON（知道真值）')
    ap.add_argument('--new', required=True, help='新版本 ida_export.py 的 JSON')
    ap.add_argument('--version-json', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    from gen_version import load_json_with_comments as L
    J = L(a.version_json)
    old = json.load(open(a.old, encoding='utf-8')).get('fieldDecode', [])
    new = json.load(open(a.new, encoding='utf-8')).get('fieldDecode', [])
    print('旧导出 %d 条字段；新导出 %d 条' % (len(old), len(new)))

    result = {}
    miss = amb = 0
    for st, fs in J.get('fieldDecode', {}).items():
        for name, val in fs.items():
            op, key = parse_val(val)
            m = [r for r in old if r['op'] == op and int(r['key'], 0) == key]
            if not m:
                print('  %-24s.%-22s ✗ 旧导出里找不到（op=%s key=0x%X）'
                      % (st, name, op, key))
                miss += 1
                continue
            sigs = {(r['width'], r['disp']) for r in m}
            if len(sigs) != 1:
                print('  %-24s.%-22s ✗ 旧导出同 key 多位置 %s' % (st, name, sorted(sigs)))
                amb += 1
                continue
            w, disp = sigs.pop()
            oldfuncs = set()
            for r in m:
                oldfuncs.update(r.get('funcs') or [])

            cand = [r for r in new if r['op'] == op and r['width'] == w and r['disp'] == disp]
            withfn = [r for r in cand if set(r.get('funcs') or []) & oldfuncs]
            pick = withfn or cand
            if not pick:
                print('  %-24s.%-22s ✗ 新导出没有 (%s,+%s,%s)' % (st, name, w, disp, op))
                miss += 1
                continue
            keys = Counter(int(r['key'], 0) for r in pick)
            if len(keys) != 1:
                print('  %-24s.%-22s ⚠ 新导出同位置 key 不一致: %s'
                      % (st, name, [hex(k) for k in keys]))
                amb += 1
                continue
            k = next(iter(keys))
            result.setdefault(st, {})[name] = '%s:0x%X' % (op, k)
            print('  %-24s.%-22s ✓ %s:0x%X  (width=%s disp=%s)'
                  % (st, name, op, k, w, disp))

    total = sum(len(v) for v in J.get('fieldDecode', {}).values())
    got = sum(len(v) for v in result.values())
    print('\n自动恢复 %d / %d 个字段（找不到 %d，歧义 %d）' % (got, total, miss, amb))
    if a.out:
        json.dump(result, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('已写 %s' % a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
