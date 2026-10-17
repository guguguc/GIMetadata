#!/usr/bin/env python3
"""ida_export.py —— 在 **IDA 里**运行，把「版本常量」自动导出成 JSON。

为什么必须进 IDA：
  · Hex-Rays 已经把混淆摊开成 `global + *(MHY+SLOT) OP KEY + STRIDE*i`
    —— 这正是我们一直在**手工抄**的表达式；
  · IDA 有真实的**函数边界**（7.0 的 `.pdata` 被混淆，外部 capstone 拿不到）；
  · IDA 有 **xref**，能确定哪个全局变量是 MHY。

在 IDA 里运行：File → Script file…   （IDAPython）
输出：/tmp/ida_export.json  + 控制台摘要

导出三类：
  1) tables      : `*(_DWORD *)(GLOBAL + SLOT) OP KEY`   （GLOBAL 是 qword_ 全局）
  2) fieldDecode : `*(_DWORD/WORD/BYTE *)(LOCAL + K) OP KEY`（LOCAL 是 a1/v5 等）
  3) formulas    : 含 `*` / `^` / `>>` 的内联 key(i) 表达式（原文，供人工确认）
"""
import json
import re

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_segment
import idautils

OUT = '/tmp/ida_export.json'

RE_TABLE = re.compile(
    r'\*\(_DWORD \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)')
RE_FIELD = re.compile(
    r'\*\(_(\w+) \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)')
# 公式的形态每版可能变（乘法/移位/xor 的组合），所以**只做粗筛**：
# 含「6 位以上大常数 + >>」的片段就抓下来，原文交给人工确认。
RE_FORMULA = re.compile(r'[^;{}\n]*\d{6,}[^;{}\n]{0,240}?>>[^;{}\n]{0,80}')


def K(s):
    return int(s, 0)


def find_mhy():
    """在只读数据段里搜魔数 b'MHY\\0' -> VA"""
    for seg in idautils.Segments():
        s = ida_segment.getseg(seg)
        if s is None:
            continue
        size = s.end_ea - s.start_ea
        if size <= 0 or size > 64 * 1024 * 1024:
            continue
        data = ida_bytes.get_bytes(s.start_ea, size)
        if not data:
            continue
        j = data.find(b'MHY\x00')
        if j >= 0:
            return s.start_ea + j
    return None


def main():
    if not ida_hexrays.init_hexrays_plugin():
        print('✗ Hex-Rays 不可用（需要 IDA 的 decompiler）')
        return

    mhy = find_mhy()
    print('MHY 表 = %s' % (hex(mhy) if mhy else '未找到'))

    tables = {}        # (global, slot, op, key) -> [func...]
    fields = {}        # (width, local, disp, op, key) -> [func...]
    formulas = []
    nfunc = 0

    for ea in idautils.Functions():
        try:
            cf = ida_hexrays.decompile(ea)
        except Exception:
            continue
        if cf is None:
            continue
        nfunc += 1
        text = str(cf)
        name = ida_funcs.get_func_name(ea) if hasattr(ida_funcs, 'get_func_name') else hex(ea)

        for m in RE_TABLE.finditer(text):
            g, slot, op, key = m.group(1), K(m.group(2)), m.group(3), K(m.group(4))
            if slot > 0x400:            # 表槽位不会这么大
                continue
            if key < 0x100:             # 太小的常数多半不是 key
                continue
            tables.setdefault((g, slot, op, key), []).append(name)

        for m in RE_FIELD.finditer(text):
            w, loc, disp, op, key = m.group(1), m.group(2), K(m.group(3)), m.group(4), K(m.group(5))
            if disp > 0x60 or key < 0x10:
                continue
            if loc.startswith('qword_'):    # 那是全局，归 tables
                continue
            fields.setdefault((w, loc, disp, op, key), []).append(name)

        for m in RE_FORMULA.finditer(text):
            formulas.append({'func': name, 'text': m.group(0)})

    # ---- 找出哪个全局是 MHY：按「被当作槽位表的次数」排序 ----
    byglob = {}
    for (g, slot, op, key), fns in tables.items():
        byglob.setdefault(g, []).append((slot, op, key, fns))
    ranked = sorted(byglob.items(), key=lambda kv: -len(kv[1]))

    print('\n函数 %d 个；候选全局 %d 个' % (nfunc, len(ranked)))
    for g, rows in ranked[:3]:
        print('  %-24s %d 个 (slot,op,key)' % (g, len(rows)))
    mhy_name = ranked[0][0] if ranked else None

    # ---- 解析 MHY 槽位 -> 值（如果找到了 MHY 表地址）----
    out_tables = []
    if mhy_name:
        for (g, slot, op, key), fns in sorted(tables.items()):
            if g != mhy_name:
                continue
            val = None
            if mhy is not None:
                raw = ida_bytes.get_dword(mhy + slot)
                if op == '-':
                    val = (raw - key) & 0xFFFFFFFF
                elif op == '+':
                    val = (raw + key) & 0xFFFFFFFF
                else:
                    val = (raw ^ key) & 0xFFFFFFFF
            out_tables.append({'slot': '0x%X' % slot, 'op': op, 'key': '0x%X' % key,
                               'value': ('0x%X' % val) if val is not None else None,
                               'n_funcs': len(fns), 'funcs': fns[:4]})

    out_fields = []
    for (w, loc, disp, op, key), fns in sorted(fields.items(), key=lambda kv: (kv[0][2], kv[0][0])):
        out_fields.append({'width': w, 'base': loc, 'disp': '0x%X' % disp,
                           'op': op, 'key': '0x%X' % key,
                           'n_funcs': len(fns), 'funcs': fns[:4]})

    res = {'mhy': (hex(mhy) if mhy else None), 'mhy_global': mhy_name,
           'tables': out_tables, 'fieldDecode': out_fields, 'formulas': formulas[:400]}
    with open(OUT, 'w') as f:
        json.dump(res, f, ensure_ascii=False, indent=1)

    print('\n=== tables: %d 个 (slot,op,key)，用全局 %s ===' % (len(out_tables), mhy_name))
    for t in out_tables[:60]:
        print('  slot 0x%-4s %s 0x%-10s -> %-10s  (%d 函数)'
              % (t['slot'][2:], t['op'], t['key'][2:], t['value'], t['n_funcs']))
    print('\n=== fieldDecode: %d 个候选 ===' % len(out_fields))
    for t in out_fields[:40]:
        print('  %-6s %-8s +0x%-3s %s 0x%-10s  (%d 函数)'
              % (t['width'], t['base'], t['disp'][2:], t['op'], t['key'][2:], t['n_funcs']))
    print('\n=== formulas: %d 条（原文，供人工确认）===' % len(formulas))
    for f in formulas[:8]:
        print('  [%s] %s' % (f['func'], f['text'][:100]))
    print('\n已写 %s' % OUT)


if __name__ == '__main__':
    main()
