#!/usr/bin/env python3
"""把 MCP `export_funcs` 的 JSON 转成离线工具链格式。

输入（MCP export_funcs）:
  version/<ver>/ida.export.json
    {"functions":[{"addr":"0x...","name":"sub_...","prototype":"...",
                   "size":"0x...", "asm":"...", "code":"..."}]}

输出:
  version/<ver>/ida/decomp/<expected_name>_<ADDR>.c
  version/<ver>/funcs_wanted.json
  version/<ver>/ida.json                 # 只有空骨架；随后交给 offline_extract.py 填 tables

注意：
  · 只转换 export_funcs 已经导出的函数，不在这里枚举 IDA 函数；
  · 反编译文本里的 MHY 全局会被统一改名为 `g_MHY_Table`，这样
    offline_extract.py / fielddecode_auto.py 能复用 7.0/7.1 的规则；
  · 原始 MCP 导出仍保留在 ida.export.json，改名只发生在 decomp 副本里。

用法:
  python3 tools/mcp_export_to_ida.py version/6.7.0 \
      --export version/6.7.0/ida.export.json
"""
import argparse
import glob
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load_json_comments(path):
    """version.json 允许 // 注释；复用 gen_version 的 loader。"""
    sys.path.insert(0, HERE)
    from gen_version import load_json_with_comments
    return load_json_with_comments(path)


def pe_sections(exe):
    D = open(exe, 'rb').read()
    pe = struct.unpack_from('<I', D, 0x3C)[0]
    nsec = struct.unpack_from('<H', D, pe + 6)[0]
    opt = struct.unpack_from('<H', D, pe + 0x14)[0]
    imgbase = struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]
    so = pe + 0x18 + opt
    out = []
    for i in range(nsec):
        e = so + i * 40
        name = D[e:e + 8].rstrip(b'\0').decode(errors='replace')
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', D, e + 8)
        out.append((name, imgbase + vaddr, vsize, roff, rsize))
    return D, out


def va2off(sections, va):
    for _, sva, vsz, roff, rsz in sections:
        if sva <= va < sva + max(vsz, rsz):
            return roff + (va - sva)
    raise ValueError('VA not in PE sections: 0x%X' % va)


def read_ptr(D, sections, va):
    off = va2off(sections, va)
    return struct.unpack_from('<Q', D, off)[0]


def find_mhy_global(code, mhy, exe):
    """在反编译文本里找 MHY 全局。

    注意：样本的 pointer 本身可能是运行时初始化的（文件里不是 MHY VA），
    所以不能只靠“读出值 == mhy”。这里优先按“被当作槽位表的次数”打分：
    `qword_xxx + small_slot) op large_key` 出现最多的那个就是 MHY。
    """
    D, sections = pe_sections(exe)
    score = {}
    pat = re.compile(
        r'\((qword_[0-9A-Fa-f]+) \+ (0x[0-9A-Fa-f]+|\d+)\)'
        r'\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)')
    for m in pat.finditer(code):
        try:
            slot = int(m.group(2), 0)
            key = int(m.group(4), 0)
        except ValueError:
            continue
        if slot > 0x400 or key < 0x100:
            continue
        score[m.group(1)] = score.get(m.group(1), 0) + 1
    if score:
        return max(score, key=score.get)
    # 兜底：值可以直接等于 MHY 的 pointer global
    names = []
    for m in re.finditer(r'\b(qword_[0-9A-Fa-f]+)\b', code):
        n = m.group(1)
        if n not in names:
            names.append(n)
    for n in names:
        try:
            va = int(n.split('_', 1)[1], 16)
            if read_ptr(D, sections, va) == mhy:
                return n
        except Exception:
            continue
    return None


# 与 ida_export.py 相同的表/字段正则（只保留离线需要的部分）
RE_TABLE = re.compile(
    r'\*\(_?(\w+) \*\)\((\w+) \+ (0x[0-9A-Fa-f]+|\d+)(?:LL|L)?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
RE_FIELD = re.compile(
    r'\*\(_?(\w+) \*\)\((.{1,200}) \+ (0x[0-9A-Fa-f]+|\d+)(?:LL|L)?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
RE_FIELD_IDX = re.compile(
    r'\*\(_?(\w+) \*\)\((\w+) \+ (\d+) \* (\w+)(?: \+ (0x[0-9A-Fa-f]+|\d+))?\)\s*([-+^])\s*(0x[0-9A-Fa-f]+|\d+)(?:LL|L)?')
RE_ASSIGN = re.compile(r'^\s*(\w+)\s*=\s*(.+?);\s*$')
RE_GLOBAL = re.compile(r'^(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?$')
RE_FORMULA = re.compile(r'[^;{}\n]*(?:0x[0-9A-Fa-f]{6,}|\d{6,})[^;{}\n]{0,300}')


def parse_int(s):
    return int(str(s), 0)


def table_value(D, sections, mhy, slot, op, key):
    off = va2off(sections, mhy + slot)
    raw = struct.unpack_from('<I', D, off)[0]
    if op == '-':
        return (raw - key) & 0xFFFFFFFF
    if op == '+':
        return (raw + key) & 0xFFFFFFFF
    return (raw ^ key) & 0xFFFFFFFF


def extract_tables(code, func_name, func_ea, mhy, D, sections, mhy_global='g_MHY_Table'):
    """从一段 Hex-Rays 文本抽取 MHY 表读取，含局部变量别名数据流。"""
    tables = {}
    lines = code.splitlines(keepends=True)
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln)

    def line_idx(p):
        lo, hi = 0, len(starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if starts[mid] <= p:
                lo = mid + 1
            else:
                hi = mid
        return max(0, lo - 1)

    assigns = []
    for i, ln in enumerate(lines):
        am = RE_ASSIGN.match(ln)
        if not am:
            continue
        lv, rhs = am.group(1), am.group(2).strip()
        gm = RE_GLOBAL.match(rhs)
        if gm:
            src = gm.group(1)
            off = parse_int(gm.group(2)) if gm.group(2) else 0
            if (re.match(r'^(?:qword_|dword_|word_|byte_|unk_|off_|p_|s_|g_)', src)
                    or re.fullmatch(r'v\d+', src)):
                assigns.append((i, lv, src, off))
        elif re.fullmatch(r'v\d+', lv):
            assigns.append((i, lv, None, 0))

    loc = {}
    ai = 0
    for m in RE_TABLE.finditer(code):
        li = line_idx(m.start())
        while ai < len(assigns) and assigns[ai][0] <= li:
            _, lv, src, off = assigns[ai]
            loc[lv] = (src, off) if src else None
            ai += 1
        w, base, slot, op, key = (m.group(1), m.group(2), parse_int(m.group(3)),
                                  m.group(4), parse_int(m.group(5)))
        if w not in ('DWORD', 'int', 'unsigned', '__int32', 'u32', 'uint32_t', 'LODWORD'):
            continue
        g = base
        if g in loc:
            if loc[g] is None:
                continue
            g, off = loc[g]
            slot += off
            seen = {base}
            while g in loc and loc[g] is not None and g not in seen:
                seen.add(g)
                g2, off2 = loc[g]
                slot += off2
                g = g2
        if g != mhy_global:
            continue
        if slot > 0x400 or key < 0x100:
            continue
        k = (slot, op, key)
        e = tables.setdefault(k, {'slot': '0x%X' % slot, 'op': op, 'key': '0x%X' % key,
                                  'base': mhy_global,
                                  'value': '0x%X' % table_value(D, sections, mhy, slot, op, key),
                                  'n_funcs': 0, 'funcs': [], 'func_eas': [],
                                  'seq': m.start(), 'strides': [], 'callees': []})
        if func_name not in e['funcs']:
            e['funcs'].append(func_name)
            e['func_eas'].append(hex(func_ea))
            e['n_funcs'] = len(e['funcs'])
        e['seq'] = min(e['seq'], m.start())
    return tables


def extract_fields(code, func_name, func_ea):
    fields = {}
    for m in RE_FIELD.finditer(code):
        w, loc, disp, op, key = (m.group(1), m.group(2), parse_int(m.group(3)),
                                 m.group(4), parse_int(m.group(5)))
        if disp > 0x60 or key < 0x10 or loc.startswith(('qword_', 'g_')):
            continue
        k = (w, loc, disp, op, key)
        e = fields.setdefault(k, {'width': w, 'base': loc, 'disp': '0x%X' % disp,
                                  'op': op, 'key': '0x%X' % key,
                                  'funcs': [], 'func_eas': []})
        if func_name not in e['funcs']:
            e['funcs'].append(func_name)
            e['func_eas'].append(hex(func_ea))
    for m in RE_FIELD_IDX.finditer(code):
        w, base, stride, idx = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        disp = parse_int(m.group(5)) if m.group(5) else 0
        op, key = m.group(6), parse_int(m.group(7))
        if disp > 0x60 or key < 0x10:
            continue
        loc = '%s+%d*%s' % (base, stride, idx)
        k = (w, loc, disp, op, key)
        e = fields.setdefault(k, {'width': w, 'base': loc, 'disp': '0x%X' % disp,
                                  'op': op, 'key': '0x%X' % key,
                                  'funcs': [], 'func_eas': []})
        if func_name not in e['funcs']:
            e['funcs'].append(func_name)
            e['func_eas'].append(hex(func_ea))
    return fields


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root', help='version/<ver> 目录')
    ap.add_argument('--export', default=None, help='默认 <root>/ida.export.json')
    ap.add_argument('--mhy', default=None, help='默认读 <root>/version.draft.json 或 version.json')
    ap.add_argument('--mhy-global', default=None, help='例如 qword_145370498；默认自动找')
    ap.add_argument('--no-offline', action='store_true', help='只写 decomp/funcs_wanted，不跑 offline_extract')
    ap.add_argument('--no-clean', action='store_true', help='保留 decomp 目录里的旧 .c 文件')
    a = ap.parse_args()

    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, a.root)
    exp = a.export or os.path.join(root, 'ida.export.json')
    if not os.path.exists(exp):
        sys.exit('missing MCP export: %s' % exp)
    data = json.load(open(exp, encoding='utf-8'))
    funcs = data.get('functions') or []
    if not funcs:
        sys.exit('MCP export has no functions')

    # MHY VA：优先命令行，其次 draft，其次 version.json
    mhy = a.mhy
    if not mhy:
        for name in ('version.draft.json', 'version.json'):
            p = os.path.join(root, name)
            if not os.path.exists(p):
                continue
            try:
                d = load_json_comments(p)
                mhy = (d.get('addresses') or {}).get('mhyTableVA')
                if mhy:
                    break
            except Exception:
                pass
    if not mhy:
        sys.exit('cannot determine MHY VA; pass --mhy 0x...')
    mhy = int(str(mhy), 0)

    # 找 MHY 全局名：所有函数的 code 合并判断
    all_code = '\n'.join(str(f.get('code') or '') for f in funcs)
    mg = a.mhy_global or find_mhy_global(all_code, mhy, os.path.join(root, 'gi.exe'))
    if not mg:
        sys.exit('cannot find MHY global in MCP code; pass --mhy-global qword_...')
    print('MHY = 0x%X, global = %s' % (mhy, mg))

    decdir = os.path.join(root, 'ida', 'decomp')
    os.makedirs(decdir, exist_ok=True)
    if not a.no_clean:
        old = glob.glob(os.path.join(decdir, '*.c'))
        for p in old:
            os.remove(p)
        if old:
            print('cleaned %d old decomp files' % len(old))
    D, sections = pe_sections(os.path.join(root, 'gi.exe'))

    fw = []
    used = set()
    seen_code = {}
    all_tables = {}
    all_fields = {}
    formula_rows = []
    for f in funcs:
        addr = int(str(f.get('addr', '0x0')), 0)
        size = int(str(f.get('size', '0x0')), 0)
        expected = f.get('name_expected') or f.get('name') or ('sub_%X' % addr)
        code = str(f.get('code') or '')
        if not code or f.get('error'):
            print('  skip %s @ 0x%X: %s' % (expected, addr, f.get('error') or 'empty code'))
            continue
        # 只改反编译副本，原始 export 保持不变
        code = re.sub(r'\b' + re.escape(mg) + r'\b', 'g_MHY_Table', code)
        # MCP 的 code 带 /*0x...*/ 行尾注释；去掉后再做数据流正则匹配
        parse_code = re.sub(r'/\*.*?\*/', '', code)
        # 命中落在函数内部时，多个名字可能导出同一段反编译文本；只保留第一个。
        ch = hashlib.sha1(parse_code.encode('utf-8', 'ignore')).hexdigest()
        if ch in seen_code:
            print('  skip duplicate %s @ 0x%X (same code as %s)' % (expected, addr, seen_code[ch]))
            continue
        seen_code[ch] = expected
        # 让 decomp 的函数名和 7.0 的命名习惯一致（只改第一处定义）
        sub_name = f.get('name') or ('sub_%X' % addr)
        code = code.replace(sub_name, expected, 1)
        # 避免极端情况下文件名冲突
        base = '%s_%X' % (expected, addr)
        while base in used:
            base += '_x'
        used.add(base)
        with open(os.path.join(decdir, base + '.c'), 'w', encoding='utf-8') as out:
            out.write(code)
        fw.append({
            'name': expected,
            'start': addr,
            'end': addr + size,
            'size': size,
            'thunk': False,
            'jmp_target': None,
            'callees': [],
        })

        # tables：支持 `v = g_MHY_Table; *(v + slot) op key` 的局部别名
        for k, e in extract_tables(parse_code, expected, addr, mhy, D, sections).items():
            if k in all_tables:
                old = all_tables[k]
                for fn, ea in zip(e['funcs'], e['func_eas']):
                    if fn not in old['funcs']:
                        old['funcs'].append(fn)
                        old['func_eas'].append(ea)
                old['n_funcs'] = len(old['funcs'])
                old['seq'] = min(old.get('seq', 1 << 60), e.get('seq', 1 << 60))
            else:
                all_tables[k] = e

        # fieldDecode 的初筛；fielddecode_auto.py 还会做语义验证
        for k, e in extract_fields(parse_code, expected, addr).items():
            if k in all_fields:
                old = all_fields[k]
                for fn, ea in zip(e['funcs'], e['func_eas']):
                    if fn not in old['funcs']:
                        old['funcs'].append(fn)
                        old['func_eas'].append(ea)
            else:
                all_fields[k] = e

        # formulas 原文：与大常数同一行且含 * 或 >> 的片段
        for m in RE_FORMULA.finditer(parse_code):
            txt = m.group(0).strip()
            if ('*' in txt or '>>' in txt) and len(txt) < 500:
                formula_rows.append({'func': expected, 'func_ea': hex(addr), 'text': txt})

    with open(os.path.join(root, 'funcs_wanted.json'), 'w', encoding='utf-8') as out:
        json.dump({'funcs': fw}, out, ensure_ascii=False, indent=1)
        out.write('\n')
    print('wrote %d decomp files -> %s' % (len(fw), decdir))
    print('wrote %s' % os.path.join(root, 'funcs_wanted.json'))

    # 去重 formulas
    seen_f = set()
    formulas = []
    for r in formula_rows:
        k = (r['func'], r['text'])
        if k in seen_f:
            continue
        seen_f.add(k)
        formulas.append(r)

    ida_path = os.path.join(root, 'ida.json')
    out_ida = {
        'mhy': '0x%X' % mhy,
        'mhy_global': 'g_MHY_Table',
        'tables': [all_tables[k] for k in sorted(all_tables)],
        'fieldDecode': [all_fields[k] for k in sorted(all_fields)],
        'formulas': formulas,
        '_mcp_export': os.path.relpath(exp, ROOT),
    }
    with open(ida_path, 'w', encoding='utf-8') as out:
        json.dump(out_ida, out, ensure_ascii=False, indent=1)
        out.write('\n')
    print('wrote %s: %d tables, %d fieldDecode, %d formulas'
          % (ida_path, len(out_ida['tables']), len(out_ida['fieldDecode']), len(formulas)))

    if not a.no_offline:
        import subprocess
        cmd = [sys.executable, os.path.join(HERE, 'offline_extract.py'), root]
        print('run:', ' '.join(cmd))
        subprocess.check_call(cmd)


if __name__ == '__main__':
    main()
