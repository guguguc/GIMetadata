#!/usr/bin/env python3
"""ida_dumpfuncs.py —— 只反编译**指定的函数**并导出伪代码（快）。

用法（IDA 无头）:
    idat64 -A -S"tools/ida_dumpfuncs.py <hits.json> <out_dir>" <db>
"""
import json
import os
import re
import sys

import ida_hexrays
import ida_funcs
import idautils

HITS = sys.argv[1] if len(sys.argv) > 1 else '/tmp/h.json'
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else '/tmp/opencode/fns'
# 只关心"读多张表"的函数
WANT = sys.argv[3].split(',') if len(sys.argv) > 3 and sys.argv[3] else None


def main():
    if not ida_hexrays.init_hexrays_plugin():
        print('✗ Hex-Rays 不可用')
        return
    hits = {}
    try:
        for nm, va in json.load(open(HITS))['hits'].items():
            hits[nm] = int(va, 16) if isinstance(va, str) else int(va)
    except Exception as e:
        print('读 hits 失败:', e)
        return
    os.makedirs(OUTDIR, exist_ok=True)
    for nm, va in sorted(hits.items()):
        if WANT and not any(w in nm for w in WANT):
            continue
        try:
            cf = ida_hexrays.decompile(va)
        except Exception as e:
            print('  %-38s ✗ %s' % (nm, e))
            continue
        if cf is None:
            continue
        text = str(cf)
        p = os.path.join(OUTDIR, nm + '.c')
        open(p, 'w').write(text)
        # 统计 MHY 槽位读取 + 它们在文本里的位置（这就是 seq 的来源）
        reads = []
        for m in re.finditer(r'\*\(_DWORD \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)\)', text):
            reads.append((m.start(), m.group(2)))
        print('  %-38s 0x%-9X %6d 字节, MHY读取 %d 条: %s'
              % (nm, va, len(text), len(reads), [r[1] for r in reads]))
    print('\n已写 %s' % OUTDIR)


if __name__ == '__main__':
    main()
    try:
        import idaapi
        if getattr(idaapi.cvar, 'batch', False):
            idaapi.qexit(0)
    except Exception:
        pass
