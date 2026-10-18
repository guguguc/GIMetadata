#!/usr/bin/env python3
"""
formula_auto.py —— 自动恢复某个版本的 keyFormulas（不依赖旧版本模板）。

为什么需要它：
  · 7.0 的公式形状和 7.1 不同（32 位 XOR -> 64 位哈希），模板迁移失效 ✗
  · 但每个公式都能用**结构自证**验证：解出的 nameIndex 解密后必须是可打印名字

输入：
  --export   ida_export.py 的 JSON（含 formulas / tables）
  --exe      目标 exe（读 MHY 表）
  --dat      global-metadata.dat
  --strings  已验证的字符串密钥 JSON（stringkeys70_verified.json 格式）
  --funcs    formula 名 -> 函数名（默认用内置映射）

输出：
  每个公式的最佳候选 + 得分（可打印名字比例），写入 --out
"""
import argparse
import json
import os
import re
import struct
import sys

H = 0x210
M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF

NAME_OFF = {
    'methodKey': [0], 'fieldKey': [0, 4, 8], 'propertyKey': [0], 'eventKey': [0, 4],
    'paramKey': [0, 4, 8], 'imageKey': [0x20, 8], 'genericParamKey': [0, 8],
    'containerKey': None,      # 不是字符串字段，跳过
}

STRIDES = {
    'methodKey': 26, 'fieldKey': 8, 'propertyKey': 0xA, 'eventKey': 0xE,
    'paramKey': 8, 'imageKey': 0x28, 'containerKey': 0x10, 'genericParamKey': 14,
}

DEFAULT_FUNCS = {
    'methodKey': 'GIMeta_GetMethodNameFromIndex',
    'fieldKey': 'GIMeta_SetupFieldsLocked',
    'propertyKey': 'GIMeta_SetupPropertiesLocked',
    'eventKey': 'GIMeta_SetupEventsLocked',
    'paramKey': 'GIMeta_SetupParameters',
    'imageKey': 'GIMeta_RuntimeInit',
    'containerKey': 'GIMeta_GetGenericParameterInfo',
    'genericParamKey': 'GIMeta_BuildMethodName',
}

NUM = re.compile(r'0x[0-9A-Fa-f]+|\b\d+\b')
IDENT = re.compile(r'\b[A-Za-z_]\w*\b')
CASTS = re.compile(r'\(\s*(?:(?:unsigned|signed|const)\s+)*(?:__int(?:8|16|32|64)|_?(?:QWORD|DWORD|WORD|BYTE)|int|char|short|long|float|double|void|size_t|u?int(?:8|16|32|64)_t)\s*\**\s*\)')


def clean_expr(t, var='i'):
    """把反编译表达式变成只含 var/常量/运算符的 Python 表达式；不行就返回 None。"""
    t = re.sub(r'^\s*\w+\s*=\s*', '', t.strip())   # 去掉 LHS
    t = CASTS.sub('', t)
    # 数字后缀：0x...LL / ...uLL / ...i64（必须用「前一个字符是数字」而不是 \b）
    t = re.sub(r'(?<=[0-9A-Fa-f])(?:[uU]?(?:LL|ll))\b', '', t)
    t = re.sub(r'(?<=[0-9A-Fa-f])(?:i64|I64)\b', '', t)
    t = t.replace('__ROL8__', 'ROL8').replace('__ROR8__', 'ROR8')
    t = re.sub(r'\b(unsigned|signed|const)\b', '', t)
    t = t.replace('&&', ' and ').replace('||', ' or ')
    # 只允许一个变量名（把循环变量统一成 var）
    ids = [x for x in IDENT.findall(t) if x not in ('ROL8', 'ROR8')]
    if not ids:
        return None
    if len(set(ids)) != 1:
        return None
    src = ids[0]
    t = re.sub(r'\b%s\b' % re.escape(src), var, t)
    if not re.fullmatch(r'[\s0-9a-fA-FxX+\-*/%^&|<>~()i]+', t):
        return None
    # 括号平衡：反编译常把表达式拆在多行，起始行可能被截掉
    while t.count(')') > t.count('('):
        t = t[:t.rfind(')')] + t[t.rfind(')')+1:]
    while t.count('(') > t.count(')'):
        t = t[:t.rfind('(')] + t[t.rfind('(')+1:]
    # 语法检查
    try:
        compile(t, '<expr>', 'eval')
    except Exception:
        return None
    return t


def eval_expr(expr, i, rol8=lambda v, n: ((v << n) | (v >> (64 - n))) & M64,
              ror8=lambda v, n: ((v >> n) | (v << (64 - n))) & M64):
    try:
        return eval(expr, {'__builtins__': {}}, {'i': i, 'ROL8': rol8, 'ROR8': ror8}) & M32
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--export', required=True)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--dat', required=True)
    ap.add_argument('--strings', required=True)
    ap.add_argument('--funcs', default=None)
    ap.add_argument('--tables-json', default=None, help='读取已定位表值的 version JSON（可选）')
    ap.add_argument('--out', default=None)
    ap.add_argument('--samples', type=int, default=300)
    a = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sig import PE

    pe = PE(a.exe)
    data = open(a.dat, 'rb').read()
    keys = json.load(open(a.strings))
    sd = keys['stringDecrypt']
    KA = int(sd['keyMulA'], 0); KB = int(sd['keyMulB'], 0)
    KS = int(sd['keySeed'], 0); KP = int(sd['keyStep'], 0)
    STR = int(sd['stringLiteralDataOffset'], 0)
    funcs = DEFAULT_FUNCS if not a.funcs else json.load(open(a.funcs))

    ex = json.load(open(a.export))
    formulas = ex['formulas']

    # 候选表偏移：把所有 (slot,op,key) 用 MHY 解码
    mhy_va = int(ex['mhy'], 16)
    def u32va(va):
        o = pe.va2off(va)
        return struct.unpack_from('<I', pe.D, o)[0] if o is not None else None
    table_offsets = set()
    for t in ex['tables']:
        slot = int(t['slot'], 0); op = t['op']; key = int(t['key'], 0)
        v = u32va(mhy_va + slot)
        if v is None:
            continue
        v = {'^': v ^ key, '-': (v - key) & M32, '+': (v + key) & M32}.get(op)
        if v is not None and 0 < v < len(data) - H:
            table_offsets.add(v)
    # 从公式行里解析 `qword_MHY + slot` / `*(int*)(qword_MHY + slot) ^ key`
    MG = ex.get('mhy_global') or ''
    if MG:
        for f in formulas:
            t = f.get('text', '')
            for m in re.finditer(re.escape(MG) + r'\s*\+\s*(0x[0-9A-Fa-f]+|\d+)', t):
                slot = int(m.group(1), 0)
                tail = t[m.end():m.end() + 80]
                om = re.match(r'\s*\)?\s*([\^+\-])\s*(0x[0-9A-Fa-f]+|\d+)', tail)
                if not om:
                    continue
                key = int(om.group(2), 0)
                v = u32va(mhy_va + slot)
                if v is None:
                    continue
                d = {'^': v ^ key, '-': (v - key) & M32, '+': (v + key) & M32}[om.group(1)]
                if 0 < d < len(data) - H:
                    table_offsets.add(d)
    # 已定位的表值（例如 update.py 的 draft）也可以作为候选偏移
    if a.tables_json and os.path.exists(a.tables_json):
        from gen_version import load_json_with_comments
        TJ = load_json_with_comments(a.tables_json)
        mhy_va2 = int(str(TJ.get('addresses', {}).get('mhyTableVA', '0')), 0)
        for nm, tb in TJ.get('tables', {}).items():
            try:
                v = u32va(mhy_va2 + int(str(tb['slot']), 0))
                if v is None: continue
                k = int(str(tb['key']), 0)
                v = {'^': v ^ k, '-': (v - k) & M32, '+': (v + k) & M32}[tb['op']]
                if 0 < v < len(data) - H:
                    table_offsets.add(v)
            except Exception:
                pass
    print('候选表偏移: %d 个' % len(table_offsets))

    def decrypt(off, ln):
        if ln <= 0 or ln > 64 or off < 0:
            return b''
        if H + STR + off + ((ln + 7) // 8) * 8 > len(data):
            return b''
        key = (KA ^ ((KB * off + KS) & M64)) & M64
        out = bytearray()
        for k in range((ln + 7) // 8):
            p = H + STR + off + 8 * k
            out += (int.from_bytes(data[p:p + 8], 'little') ^ key).to_bytes(8, 'little')
            key = (key + KP) & M64
        return bytes(out[:ln])

    def printable(b):
        return len(b) > 0 and all(0x20 <= c < 0x7f for c in b)

    result = {}
    for name, fn in funcs.items():
        if name == 'containerKey':
            print('%-16s (跳过：container 的 key 不用于字符串名)' % name)
            continue
        lines = [f['text'] for f in formulas if f['func'] == fn]
        cands = []
        for i in range(len(lines)):
            # 只取赋值右边；去掉行首的续行运算符（^ / * / +）
            t = re.sub(r'^\s*\w+\s*=\s*', '', lines[i].strip())
            t = re.sub(r'^\s*[\^*+]+\s*', '', t)
            for j in range(i, min(i + 12, len(lines))):
                if j > i:
                    t += ' ' + lines[j].strip()
                if not ('*' in t or '>>' in t or '^' in t):
                    continue
                e = clean_expr(t)
                if e:
                    cands.append((t.strip(), e))
        # 同一段表达式会随拼接长度产生多个前缀；保留最长的（常数最全）
        seen = set(); uniq = []
        for raw, expr in sorted(cands, key=lambda x: (len(x[1]), len(x[0])), reverse=True):
            if expr in seen:
                continue
            seen.add(expr); uniq.append((raw, expr))
        cands = uniq
        if not cands:
            print('%-16s ✗ 函数里没有可解析的表达式' % name)
            continue
        best = None
        for raw, expr in cands:
            # 解码常数候选：表达式里的常数 + 0
            cs = {int(x, 0) for x in NUM.findall(raw)} | {0}
            cs = {x & M32 for x in cs}
            stride = STRIDES.get(name, 14)
            for T in table_offsets:
                for C in cs:
                    for fo in NAME_OFF.get(name, [0]):
                        for mode in (0, 1, 2, 3, 4):
                            ok = tot = 0
                            for p in range(min(a.samples, (len(data) - H - T) // stride + 1)):
                                base = H + T + stride * p + fo
                                rv = int.from_bytes(data[base:base + 4], 'little')
                                k = eval_expr(expr, p)
                                if k is None:
                                    continue
                                v = (((rv ^ C) - k) if mode == 0 else
                                     ((rv ^ k) - C) if mode == 1 else
                                     (rv ^ k ^ C) if mode == 2 else
                                     ((rv - C) ^ k) if mode == 3 else
                                     (rv ^ k)) & M32
                                off = v & 0xFFFFFF; ln = v >> 24
                                if 0 < off < 8_000_000 and 1 <= ln <= 48:
                                    tot += 1
                                    if printable(decrypt(off, ln)):
                                        ok += 1
                            if tot >= 40 and ok / tot >= 0.80 and (best is None or ok / tot > best[0]):
                                best = (ok / tot, ok, tot, T, C, fo, mode, raw, expr)
        if best:
            rate, ok, tot, T, C, fo, mode, raw, expr = best
            print('%-16s %.1f%% (%d/%d) 表=0x%X C=0x%X off=%d mode=%d' % (name, rate * 100, ok, tot, T, C, fo, mode))
            print('    %s' % raw[:200])
            result[name] = {'score': rate, 'table': '0x%X' % T, 'C': '0x%X' % C,
                            'nameOff': fo, 'mode': mode, 'expr': raw.strip()}
        else:
            print('%-16s ✗ 没有候选通过' % name)

    if a.out:
        json.dump(result, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('\n已写 %s' % a.out)


if __name__ == '__main__':
    sys.exit(main())
