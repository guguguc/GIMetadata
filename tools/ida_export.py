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

IDA_HEADLESS = any(a in sys.argv for a in ('-A', '--headless'))

import sys

# 无头模式：idat64 -A -S"ida_export.py <out.json> [hits.json]" <target>
OUT = sys.argv[1] if len(sys.argv) > 1 else '/tmp/ida_export.json'
HITS_JSON = sys.argv[2] if len(sys.argv) > 2 else '/tmp/h.json'
FAST = '--fast' in sys.argv      # 只反编译 sig 定位到的函数（秒级）；否则全量（小时级）
# 额外指定函数（未命名函数里的读取点，例如 7.1 的 typeDefs 在 0x1404B1588）
EXTRA = [int(a, 16) for a in sys.argv[2:] if a.startswith('0x') or a.startswith('0X')]

HITS = {}                      # ea -> name


def load_hits(path=HITS_JSON):
    """把 sig.py scan 的结果读进来：{地址: 名字}。

    IDA 自己不知道我们起的 `GIMeta_*` 名字（它只有 `sub_xxx`），
    所以必须用「地址」当桥：sig 命中表是 (name -> VA)，反过来就是 (VA -> name)。
    """
    global HITS
    try:
        import json as _j
        d = _j.load(open(path))
        for name, va in d.get('hits', {}).items():
            val = int(va, 16) if isinstance(va, str) else int(va)
            HITS[val] = name
        print('已加载 sig 命中表 %s（%d 条）' % (path, len(HITS)))
    except Exception as e:
        print('⚠ 没读到 sig 命中表（%s）：%s' % (path, e))
        print('   -> 先用 sig.py scan --json /tmp/h.json 生成；否则只能输出 sub_xxx')

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

    load_hits()
    mhy = find_mhy()
    print('MHY 表 = %s' % (hex(mhy) if mhy else '未找到'))

    tables = {}        # (global, slot, op, key) -> [func...]
    tbl_meta = {}      # (global, slot, op, key) -> {strides, callees, lhs}
    fields = {}        # (width, local, disp, op, key) -> [func...]
    formulas = []
    nfunc = 0
    if FAST and (HITS or EXTRA):
        targets = sorted(set(HITS.keys()) | set(EXTRA))
        print('FAST 模式：只反编译 %d 个函数（sig %d + 额外指定 %d；全量有几十万个）'
              % (len(targets), len(HITS), len(EXTRA)))
        print('   额外函数: %s' % [hex(x) for x in EXTRA])
    else:
        targets = list(idautils.Functions())
        print('全量模式：%d 个函数（会很慢；建议加 --fast）' % len(targets))

    for _k, ea in enumerate(targets):
        if _k and _k % 200 == 0:
            print('  ... %d/%d' % (_k, len(targets)))
        try:
            cf = ida_hexrays.decompile(ea)
        except Exception:
            continue
        if cf is None:
            continue
        nfunc += 1
        text = str(cf)
        f = ida_funcs.get_func(ea)
        fstart = f.start_ea if f else ea
        name = HITS.get(fstart) or ida_funcs.get_func_name(ea) or hex(ea)

        for m in RE_TABLE.finditer(text):
            g, slot, op, key = m.group(1), K(m.group(2)), m.group(3), K(m.group(4))
            if slot > 0x400:            # 表槽位不会这么大
                continue
            if key < 0x100:             # 太小的常数多半不是 key
                continue
            # ★ 取 LHS 变量（同一个赋值语句里），再找它被怎么用
            ls = text.rfind('\n', 0, m.start()) + 1
            pre = text[ls:m.start()]
            lm = re.search(r'(\w+)\s*=\s*[^=]*$', pre)
            lhs = lm.group(1) if lm else None
            strides, callees = set(), set()
            if lhs:
                for sm in re.finditer(r'\b' + re.escape(lhs) + r'\b\s*\+\s*(\d+)\s*\*', text):
                    strides.add(int(sm.group(1)))
                for cm in re.finditer(r'(\w+)\s*\([^);]*\b' + re.escape(lhs) + r'\b[^);]*\)', text):
                    if cm.group(1) not in ('if', 'while', 'for', 'switch', 'sizeof', 'return'):
                        callees.add(cm.group(1))
            ent = (name, hex(fstart))
            tables.setdefault((g, slot, op, key), []).append(ent)
            tbl_meta.setdefault((g, slot, op, key), {'strides': set(), 'callees': set(), 'lhs': set()})
            tbl_meta[(g, slot, op, key)]['strides'] |= strides
            tbl_meta[(g, slot, op, key)]['callees'] |= callees
            if lhs:
                tbl_meta[(g, slot, op, key)]['lhs'].add(lhs)

        for m in RE_FIELD.finditer(text):
            w, loc, disp, op, key = m.group(1), m.group(2), K(m.group(3)), m.group(4), K(m.group(5))
            if disp > 0x60 or key < 0x10:
                continue
            if loc.startswith('qword_'):    # 那是全局，归 tables
                continue
            fields.setdefault((w, loc, disp, op, key), []).append((name, hex(fstart)))

        for m in RE_FORMULA.finditer(text):
            formulas.append({'func': name, 'func_ea': hex(fstart), 'text': m.group(0)})

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
                               'n_funcs': len(fns),
                               'funcs': [n for n, _ in fns[:4]],
                               'func_eas': [e for _, e in fns[:4]],
                               'strides': sorted(tbl_meta.get((g, slot, op, key), {}).get('strides', [])),
                               'callees': sorted(tbl_meta.get((g, slot, op, key), {}).get('callees', []))[:6]})

    out_fields = []
    for (w, loc, disp, op, key), fns in sorted(fields.items(), key=lambda kv: (kv[0][2], kv[0][0])):
        out_fields.append({'width': w, 'base': loc, 'disp': '0x%X' % disp,
                           'op': op, 'key': '0x%X' % key,
                           'n_funcs': len(fns),
                           'funcs': [n for n, _ in fns[:4]],
                           'func_eas': [e for _, e in fns[:4]]})

    # ---- 守卫：MHY 地址/全局是否可信（解码值必须落在合理范围）----
    plausible = [t for t in out_tables
                 if t['value'] and 0x1000 <= int(t['value'], 16) < 0x8000000]
    if mhy is not None and len(out_tables) and len(plausible) < max(3, len(out_tables) // 3):
        print('⚠⚠ MHY 地址或全局可能认错了：%d 个值里只有 %d 个落在合理范围'
              % (len(out_tables), len(plausible)))
        print('   请人工确认 MHY（或直接把 mhy 传进来）；否则下面的 value 全是垃圾 ✗')
    elif len(out_tables):
        print('MHY 可信度：%d/%d 个值落在合理范围 ✓' % (len(plausible), len(out_tables)))

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
    # 无头（idat64 -A）时自动退出；GUI 里跑则保持打开
    try:
        import idaapi
        if getattr(idaapi.cvar, 'batch', False) or IDA_HEADLESS:
            idaapi.qexit(0)
    except Exception:
        pass
