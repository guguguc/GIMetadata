#!/usr/bin/env python3
"""ida_check.py —— 把 `ida_export.py` 的产物与 `version.json` **真值**对照。

用途：在 7.1 上跑（我们知道全部真值），衡量导出的**召回率 / 误报率**，
从而判断这套 IDA 方案到底能覆盖多少。

用法：
    python3 tools/ida_check.py /tmp/ida71.json [--version-json version.json] [--root version/7.1]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from gen_version import load_json_with_comments as L  # noqa: E402


def K(x):
    return int(x, 0) if isinstance(x, str) else int(x)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('export')
    ap.add_argument('--version-json', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--root', default=os.path.join(ROOT, 'version/7.1'))
    a = ap.parse_args()

    from relocate import PE
    pe = PE(os.path.join(a.root, 'gi.exe'))
    import re
    J = L(a.version_json)
    # MHY：从 addresses 读（比再搜魔数省事）
    mhy = None
    for k, v in J.get('addresses', {}).items():
        if 'mhy' in k.lower():
            mhy = K(v)
    if mhy is None:
        print('✗ version.json 里没有 mhyTableVA')
        return 1
    M32 = (1 << 32) - 1

    truth = {}
    for name, cfg in J['tables'].items():
        if 'slot' not in cfg or cfg.get('stride', 0) == 0:
            continue
        slot, op, key = int(cfg['slot'], 0), cfg['op'], K(cfg['key'])
        raw = pe.u32(mhy + slot)
        val = ((raw - key) & M32) if op == '-' else (((raw ^ key) & M32) if op == '^' else (raw + key) & M32)
        truth[name] = (slot, op, key, val)

    exp = json.load(open(a.export, encoding='utf-8'))
    rows = exp.get('tables', [])
    print('导出 %d 个 (slot,op,key)；真值 %d 张表' % (len(rows), len(truth)))

    by_val = {}
    for r in rows:
        if r.get('value'):
            by_val.setdefault(int(r['value'], 16), []).append(r)

    matched, missing = {}, []
    for name, (slot, op, key, val) in sorted(truth.items()):
        hits = by_val.get(val, [])
        if not hits:
            missing.append(name)
            continue
        # 同一 value 可能被多张表共用（比如 fDV/pDV 的 value 相同）-> 只记一次
        matched[name] = hits[0]

    used_vals = {int(r['value'], 16) for r in matched.values() if r.get('value')}
    false_pos = [r for r in rows if r.get('value') and int(r['value'], 16) not in used_vals]

    print('\n=== 召回：%d / %d 张表在导出里 ===' % (len(matched), len(truth)))
    for name in sorted(matched):
        r = matched[name]
        ok = (int(r['slot'], 16) == truth[name][0] and r['op'] == truth[name][1]
              and int(r['key'], 16) == truth[name][2])
        print('  %-42s value=%-10s slot=%-6s %s %-12s  %s  (函数 %s)'
              % (name, r.get('value'), r['slot'], r['op'], r['key'],
                 '✅' if ok else '✗', ','.join(r.get('funcs', [])[:2])))

    if missing:
        print('\n=== 没导出（%d 张，说明该读取点没被正则抓到 / 在未命名函数里）===' % len(missing))
        print('  ' + ', '.join(missing))

    print('\n=== 误报候选（value 不对应任何已知表）：%d 个 ===' % len(false_pos))
    for r in false_pos[:15]:
        print('  slot %-6s %s %-12s value=%-10s  (%s)'
              % (r['slot'], r['op'], r['key'], r.get('value'), ','.join(r.get('funcs', [])[:2])))

    print('\n召回率 %.1f%%，误报 %d 个' % (100.0 * len(matched) / max(len(truth), 1), len(false_pos)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
