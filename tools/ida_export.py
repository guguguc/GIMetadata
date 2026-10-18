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
import os
import re
import sys

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_segment
import idautils

IDA_HEADLESS = any(a in sys.argv for a in ('-A', '--headless'))

# 无头模式：idat64 -A -S"ida_export.py <out.json> [hits.json]" <target>
OUT = sys.argv[1] if len(sys.argv) > 1 else '/tmp/ida_export.json'
HITS_JSON = sys.argv[2] if len(sys.argv) > 2 else '/tmp/h.json'
FAST = '--fast' in sys.argv      # 只反编译 sig 定位到的函数（秒级）；否则全量（小时级）
# 额外指定函数（未命名函数里的读取点，例如 7.1 的 typeDefs 在 0x1404B1588）
EXTRA = [int(a, 16) for a in sys.argv[2:] if a.startswith('0x') or a.startswith('0X')]
# 可选：把每个函数的 Hex-Rays 文本落盘（用于定位 a1 等 base）
TEXT_DIR = os.environ.get('GI_TEXT') or None

HITS = {}                      # ea -> name
# MHY 也可能以参数形式传入（a1/v5/...），不一定是全局名。
# 只有「已知读 MHY 的表函数」才接受这些别名，避免把别的 base 误当 MHY。
MHY_ALIASES = set()   # a1/a2/v5 都是运行时上下文/local，不是 MHY；只认 g_MHY_Table
TABLE_FUNCS = set()
try:
    _tf = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'table_funcs.json')))
    TABLE_FUNCS = {k for k in _tf if not k.startswith('_')}
except Exception:
    pass


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

# 支持**嵌套基址** + LL/L 后缀（7.0 的 de​compiler 会把表读取写成
# `*(_DWORD *)(*(_QWORD *)(x + 152) + 28) ^ key`，旧正则只认单层 \(\w+ \+ disp\) ✗）。
RE_TABLE = re.compile(
    r'\*\(_?(\w+) \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)(?:LL|L)?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
# 允许**嵌套基址**（如 `*(int *)(*(_QWORD *)(TypeInfoByIndex + 152) + 28)`）和 LL/L 后缀。
# 用**贪婪** `.+` 才能取到最外层：`*(_QWORD *)(x + 152) + 28) ^ key` -> base=..., disp=28 ✓
RE_FIELD = re.compile(
    r'\*\(_?(\w+) \*\)\((.{1,200}) \+ (0x[0-9A-Fa-f]+|\d+)(?:LL|L)?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
# 公式的形态每版可能变（乘法/移位/xor 的组合），所以**只做粗筛**：
# 含「6 位以上大常数 + >>」的片段就抓下来，原文交给人工确认。
# 只做粗筛：含 6 位以上大常数，并且同一行里出现 * 或 >>（key(i) 公式一定满足其一）。
# methodKey/eventKey **没有移位**，所以不能强制要求 >>（这是之前漏掉它们的原因 ✗）。
# 局部变量数据流：`v10 = qword_xxx;` 之后 `*(v10 + slot)` 也能归到 MHY 全局
RE_ASSIGN = re.compile(r'^\s*(\w+)\s*=\s*(.+?);\s*$')
RE_GLOBAL = re.compile(r'^(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?$')


def _is_global_name(n):
    return bool(re.match(r'^(?:qword_|dword_|word_|byte_|unk_|off_|p_|s_|g_)', n)) or n in (
        'MHY_Table', 'p_MHY_Table', 's_MHYTable')


# 数组索引形态：`*(_DWORD *)(v33 + 8 * v32)` / `... + 4)`（7.0 大量使用）
RE_FIELD_IDX = re.compile(
    r'\*\(_?(\w+) \*\)\((\w+) \+ (\d+) \* (\w+)(?: \+ (0x[0-9A-Fa-f]+|\d+))?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')

RE_FORMULA = re.compile(r'[^;{}\n]*(?:0x[0-9A-Fa-f]{6,}|\d{6,})[^;{}\n]{0,300}')


def _dedup_formulas(rows):
    """同一函数里**原文完全相同**的行只留一条（保留 func/ea）。

    为什么要去重：`formulas` 原来硬截断 400 行，把排在后面的函数（SetupParameters、
    RuntimeInit 的一部分）切掉了 -> paramKey / imageKey 直接丢 ✗。
    去重后行数大幅下降，就不需要截断了 ✓。
    """
    seen = set()
    out = []
    for r in rows:
        key = (r.get('func'), r.get('text'))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


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
    # 强制覆盖“自动恢复必须看”的函数（名字 -> EA；EA 来自 sig.py scan）
    try:
        wanted_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_wanted.txt')
        if os.path.exists(wanted_path):
            for line in open(wanted_path, encoding='utf-8'):
                nm = line.strip()
                if nm and not nm.startswith('#') and nm in HITS:
                    EXTRA.append(HITS[nm])
    except Exception:
        pass
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

    try:
        import ida_auto
        _ok = ida_auto.auto_is_ok()
    except Exception:
        _ok = None
    if _ok is False:
        print('  ⚠ 自动分析尚未完成（auto_is_ok=False）——结果可能不完整', flush=True)
    _max = int(os.environ.get('IDA_MAX_FUNC', '0x20000'), 0)
    _prog_path = OUT + '.progress'
    try:
        _prog = open(_prog_path, 'w', encoding='utf-8')
    except Exception:
        _prog = None

    for _k, ea in enumerate(targets):
        _fn = ida_funcs.get_func(ea)
        _sz = (_fn.end_ea - _fn.start_ea) if _fn else 0
        if _sz and _sz > _max:
            print('  ⏭ 跳过超大函数 %s 0x%X size=0x%X (>0x%X)'
                  % (ida_funcs.get_func_name(ea), ea, _sz, _max), flush=True)
            continue
        print('  → %s 0x%X size=0x%X' % (ida_funcs.get_func_name(ea), ea, _sz), flush=True)
        if _prog:
            _prog.write('BEGIN %s 0x%X size=0x%X\n' % (ida_funcs.get_func_name(ea), ea, _sz)); _prog.flush()
        try:
            cf = ida_hexrays.decompile(ea)
        except Exception as _e:
            print('  ✗ 反编译异常 %s 0x%X: %s' % (ida_funcs.get_func_name(ea), ea, _e), flush=True)
            continue
        if cf is None:
            print('  ✗ 反编译返回 None %s 0x%X' % (ida_funcs.get_func_name(ea), ea), flush=True)
            if _prog:
                _prog.write('NONE %s 0x%X\n' % (ida_funcs.get_func_name(ea), ea)); _prog.flush()
            continue
        nfunc += 1
        text = str(cf)
        if _prog:
            _prog.write('OK %s 0x%X chars=%d\n' % (ida_funcs.get_func_name(ea), ea, len(text))); _prog.flush()
        f = ida_funcs.get_func(ea)
        fstart = f.start_ea if f else ea
        name = HITS.get(fstart) or ida_funcs.get_func_name(ea) or hex(ea)

        # 全量时把反编译文本也存下来；即使之后 IDA 崩了，已处理函数也已落盘
        if TEXT_DIR:
            try:
                os.makedirs(TEXT_DIR, exist_ok=True)
                tfn = os.path.join(TEXT_DIR, '%s_%X.c' % (name, fstart))
                with open(tfn, 'w', encoding='utf-8') as _tf:
                    _tf.write(text)
            except Exception as _te:
                print('  ⚠ 保存反编译文本失败 %s: %s' % (name, _te), flush=True)

        # ---- 局部变量数据流（7.0 大量读取形如 v10 = qword_xxx; *(v10 + slot)）----
        _lines = text.splitlines(keepends=True)
        _starts = []
        _pos = 0
        for _ln in _lines:
            _starts.append(_pos); _pos += len(_ln)

        def _line_idx(p):
            lo, hi = 0, len(_starts)
            while lo < hi:
                mid = (lo + hi) // 2
                if _starts[mid] <= p:
                    lo = mid + 1
                else:
                    hi = mid
            return max(0, lo - 1)

        _assigns = []      # (line, local, src_or_None, offset)
        for _i, _ln in enumerate(_lines):
            _am = RE_ASSIGN.match(_ln)
            if not _am:
                continue
            _lv, _rhs = _am.group(1), _am.group(2).strip()
            _gm = RE_GLOBAL.match(_rhs)
            if _gm:
                _src = _gm.group(1)
                _off = K(_gm.group(2)) if _gm.group(2) else 0
                # 全局、MHY 参数别名（a1/a2/v5...）、局部到局部别名、aN 都保留
                if (_is_global_name(_src) or _src in MHY_ALIASES
                        or re.fullmatch(r'v\d+', _src)):
                    _assigns.append((_i, _lv, _src, _off))
                elif re.fullmatch(r'v\d+', _lv):
                    _assigns.append((_i, _lv, None, 0))
            elif re.fullmatch(r'v\d+', _lv):
                _assigns.append((_i, _lv, None, 0))    # 被别的东西覆盖 -> 失效

        _loc = {}
        _ai = 0
        for m in RE_TABLE.finditer(text):
            _L = _line_idx(m.start())
            while _ai < len(_assigns) and _assigns[_ai][0] <= _L:
                _, _lv, _src, _off = _assigns[_ai]
                _loc[_lv] = (_src, _off) if _src else None
                _ai += 1

            _w, _base, _slot, _op, _key = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            # 表值都是 32 位；Hex-Rays 可能写成 DWORD / int / unsigned int / __int32 ...
            if _w not in ('DWORD', 'int', 'unsigned', '__int32', 'u32', 'uint32_t', 'LODWORD'):
                continue
            _g = re.match(r'[A-Za-z_]\w*', _base)
            _bid = _g.group(0) if _g else _base
            g, slot, op, key = _bid, K(_slot), _op, K(_key)
            if re.fullmatch(r'v\d+', _bid):
                # 局部变量：解析到全局 / MHY 参数别名（a1/v5/...）；支持别名链
                if _bid not in _loc or _loc[_bid] is None:
                    continue
                g, _off = _loc[_bid]
                slot += _off
                _seen = {_bid}
                while g in _loc and _loc[g] is not None and g not in _seen:
                    _seen.add(g)
                    g2, off2 = _loc[g]
                    slot += off2
                    g = g2
                if not (_is_global_name(g) or g in MHY_ALIASES):
                    continue
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
            tbl_meta.setdefault((g, slot, op, key), {'strides': set(), 'callees': set(),
                                                     'lhs': set(), 'seq': m.start()})
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

        for m in RE_FIELD_IDX.finditer(text):
            w, base, stride, idx, disp, op, key = (m.group(1), m.group(2), int(m.group(3)),
                                                   m.group(4), K(m.group(5)) if m.group(5) else 0,
                                                   m.group(6), K(m.group(7)))
            if disp > 0x60 or key < 0x10:
                continue
            # stride 进 base，便于后续按结构体步长归属
            fields.setdefault((w, '%s+%d*%s' % (base, stride, idx), disp, op, key), []).append(
                (name, hex(fstart)))

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
                # 5 个 setup 函数把 MHY 指针当 a1 传入（SetupMethods/Events/
                # IterNested/BuildMethodName/RegisterTables）；这些表以前被过滤掉。
                if g not in MHY_ALIASES:
                    continue
                if not any(n in TABLE_FUNCS for n, _ in fns):
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
                               'base': g,
                               'value': ('0x%X' % val) if val is not None else None,
                               'n_funcs': len(fns),
                               'funcs': [n for n, _ in fns[:4]],
                               'func_eas': [e for _, e in fns[:4]],
                               'seq': tbl_meta.get((g, slot, op, key), {}).get('seq', 0),
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
           'tables': out_tables, 'fieldDecode': out_fields, 'formulas': _dedup_formulas(formulas)}
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
