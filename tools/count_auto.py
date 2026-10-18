#!/usr/bin/env python3
"""count_auto.py —— 从目标 RuntimeInit 反编译里恢复 T0/T1 计数公式。

只使用：
  · 上一版 version.json 中三个 *CountFormula 的字段偏移/格式（作为角色提示）
  · 目标 decomp/GIMeta_RuntimeInit*.c
  · 目标 gi.exe（只在字段发生移动时，用二进制立即数规范化 sub/add 表示）

输出：
  version/<ver>/ida/count.auto.json
  {
    "genericClassRangeCountFormula": {...},
    "genericInstsCountFormula": {...},
    "typesCountFormula": {...}
  }

不读取目标 version.json。
"""
import argparse
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_version import load_json_with_comments  # noqa: E402

M32 = 0xFFFFFFFF


def lit_int(s):
    return int(str(s), 0) & M32


def op_norm(s):
    return {'xor': '^', 'add': '+', 'sub': '-'}.get(s, s)


def semantics(op, key):
    """把 (op,key) 归一成对 raw 的等价函数签名：+k / -k。"""
    op, key = op_norm(op), lit_int(key)
    if op == '^':
        return ('^', key)
    if op == '+':
        return ('+', key)
    if op == '-':
        return ('-', key)
    return (op, key)


def same_formula(a, b, field_key):
    if not a or not b:
        return False
    fa = lit_int(a.get(field_key, '0'))
    fb = lit_int(b.get(field_key, '0'))
    return fa == fb and semantics(a.get('op'), a.get('key')) == semantics(b.get('op'), b.get('key'))


def read_formulas(root):
    texts = []
    for dirpath, _, names in os.walk(os.path.join(root, 'ida', 'decomp')):
        for n in names:
            if 'RuntimeInit' in n and n.endswith('.c'):
                texts.append(open(os.path.join(dirpath, n), encoding='utf-8', errors='ignore').read())
    text = '\n'.join(texts)
    # *(int *)(ptr + 0x54) OP key    /    *(unsigned int *)(ptr + 84) OP 0x...
    pat = re.compile(
        r'\*\(\s*(?:unsigned int|int|_DWORD)\s*\*\)\s*\(\s*'
        r'(?P<ptr>[A-Za-z_]\w*)\s*\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*'
        r'(?P<op>[\^+\-])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)')
    out = []
    seen = set()
    for m in pat.finditer(text):
        ptr = m.group('ptr')
        if not (ptr.startswith('qword_') or ptr == 'g_Il2CppType_Base'):
            continue
        off = int(m.group('off'), 0)
        op = op_norm(m.group('op'))
        key = lit_int(m.group('key'))
        k = (ptr, off, op, key)
        if k in seen:
            continue
        seen.add(k)
        out.append({'ptr': ptr, 'off': off, 'op': op, 'key': key})
    return out


def immediate_count(exe, key):
    if not exe or not os.path.exists(exe):
        return 0
    data = open(exe, 'rb').read()
    return data.count(struct.pack('<I', key & M32))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--exe', default=None)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, 'version', a.root)
    if not os.path.isdir(root):
        root = a.root
    base = load_json_with_comments(a.base)
    exe = a.exe or os.path.join(root, 'gi.exe')
    forms = read_formulas(root)
    out = {}

    def base_field(kind, name):
        d = base.get(name) or {}
        f = d.get(kind)
        return int(str(f), 0) if f is not None else None

    def find(ptr, off):
        for f in forms:
            if f['ptr'] == ptr and f['off'] == off:
                return f
        return None

    # typesCount：字段通常稳定在 T1+0x54，用它同时确定 T1 指针。
    bt = base_field('table1Field', 'typesCountFormula')
    t1 = None
    tf = None
    if bt is not None:
        hits = [f for f in forms if f['off'] == bt]
        if hits:
            t1 = hits[0]['ptr']
            tf = find(t1, bt)

    # genericClassRange：字段通常在 T0+0x80，用它确定 T0 指针。
    bg = base_field('table0Field', 'genericClassRangeCountFormula')
    t0 = None
    gf = None
    if bg is not None:
        hits = [f for f in forms if f['off'] == bg]
        if hits:
            t0 = hits[0]['ptr']
            gf = find(t0, bg)

    # genericInsts：同一 T1 指针上，字段变化时选离 types 字段最近的那个计数读取。
    bi = base_field('table1Field', 'genericInstsCountFormula')
    inf = None
    if t1 and bt is not None:
        others = [f for f in forms if f['ptr'] == t1 and f['off'] != bt]
        lower = [f for f in others if f['off'] < bt]
        upper = [f for f in others if f['off'] > bt]
        pool = ([max(lower, key=lambda f: f['off'])] if lower else
                ([min(upper, key=lambda f: f['off'])] if upper else []))
        if pool:
            inf = pool[0]

    def emit(name, f, field_key):
        if not f:
            return
        off, op, key = f['off'], f['op'], f['key']
        old = base.get(name) or {}
        # 字段没动且语义没变：保留旧 JSON 的数值/字符串写法，避免无意义 diff。
        if (old.get(field_key) is not None and lit_int(old[field_key]) == off
                and semantics(old.get('op'), old.get('key')) == semantics(op, key)):
            return
        # 字段移动时，反编译有时把 add imm32 写成 sub (2^32-imm)。
        # 优先用目标 exe 里真实出现的立即数形式。
        if f['off'] != lit_int(old.get(field_key, '0')) if old.get(field_key) is not None else False:
            if op == '-':
                alt = (-key) & M32
                if immediate_count(exe, alt) and not immediate_count(exe, key):
                    op, key = '+', alt
            elif op == '+':
                alt = (-key) & M32
                if immediate_count(exe, alt) and not immediate_count(exe, key):
                    op, key = '-', alt
        out[name] = {field_key: '0x%X' % off, 'op': op, 'key': '0x%X' % key}

    emit('genericClassRangeCountFormula', gf, 'table0Field')
    emit('genericInstsCountFormula', inf, 'table1Field')
    emit('typesCountFormula', tf, 'table1Field')

    outp = a.out or os.path.join(root, 'ida', 'count.auto.json')
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(out, open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('forms:', len(forms), 'T1:', t1, 'T0:', t0)
    print('已写', outp)
    for k, v in out.items():
        print(' ', k, v)


if __name__ == '__main__':
    main()
