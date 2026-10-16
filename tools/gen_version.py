#!/usr/bin/env python3
"""
version.json -> src/version.hpp

换版本时改 version.json，然后 make（Makefile 会自动跑这个脚本）。
本脚本不做任何推断，只把 JSON 里的数字/运算原样翻译成 C++ constexpr。
"""
import json, re, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JSON_PATH = os.path.join(ROOT, 'version.json')
OUT_PATH  = os.path.join(ROOT, 'src', 'version.hpp')

def load_json_with_comments(path):
    """剥掉 // 行注释（要识别字符串状态，注释里可能出现引号）"""
    src = open(path, encoding='utf-8').read()
    out = []
    for line in src.split('\n'):
        res = []
        in_str = False
        esc = False
        i = 0
        while i < len(line):
            ch = line[i]
            if in_str:
                res.append(ch)
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                    res.append(ch)
                elif ch == '/' and i + 1 < len(line) and line[i+1] == '/':
                    break
                else:
                    res.append(ch)
            i += 1
        out.append(''.join(res))
    return json.loads('\n'.join(out))

def num(v):
    """转成 C++ 字面量（十进制/十六进制原样，负数原样）"""
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    s = str(v)
    return s if s.startswith('-') else s

def cname(s):
    return ''.join(w[:1].upper() + w[1:] for w in re.split(r'[_\s]+', s) if w)

def opchar(op):
    return {'sub': '-', 'xor': '^', 'add': '+'}[op]

def split_op(spec):
    op, _, key = spec.partition(':')
    return opchar(op.strip()), num(key.strip())

def main():
    J = load_json_with_comments(JSON_PATH)
    L = []
    w = L.append
    w('// ============================================================================')
    w('//  自动生成 —— 不要手改！')
    w('//  来源: version.json   （用 tools/gen_version.py 生成，make 会自动调用）')
    w('//  版本: %s' % J.get('version', '?'))
    w('// ============================================================================')
    w('#pragma once')
    w('#include <cstdint>')
    w('#include <cstddef>')
    w('')
    w('namespace ver {')
    w('')
    w('struct OpKey { char op; uint64_t key; };')
    w('struct Table {')
    w('    uint32_t slot; char op; uint64_t key;')
    w('    uint32_t stride; bool startup;')
    w('    const char* role;  // "offset" | "count_div"')
    w('    int32_t countBias; // count_div 时额外加的偏置（如 -2）')
    w('};')
    w('')

    # ---- 地址 ----
    w('// ---------------- 全局地址 ----------------')
    for k, v in J.get('addresses', {}).items():
        ty = 'uint32_t' if isinstance(v, int) else 'uint64_t'
        w('inline constexpr %s k%s = %s;' % (ty, cname(k), num(v)))
    w('')

    # ---- 字符串解密 ----
    w('// ---------------- 字符串解密 ----------------')
    for k, v in J.get('stringDecrypt', {}).items():
        ty = 'uint64_t' if str(v).startswith('0x') and len(str(v)) > 10 else 'uint32_t'
        w('inline constexpr %s k%s = %s%s;' % (ty, cname(k), num(v), 'ull' if ty == 'uint64_t' and str(v).startswith('0x') else 'u'))
    w('')

    # ---- 表 ----
    w('// ---------------- 元数据表 ----------------')
    for name, d in J.get('tables', {}).items():
        w('inline constexpr Table k%s = { %s, \'%s\', %s, %s, %s, "%s", %s };' % (
            cname(name), num(d['slot']), d['op'], num(d['key']), num(d['stride']),
            'true' if d.get('side') == 'startup' else 'false',
            d.get('role', 'offset'), num(d.get('countBias', 0))))
    w('')

    # ---- 实测计数 ----
    w('// ---------------- 实测计数（表里没有）----------------')
    for k, v in J.get('measuredCounts', {}).items():
        w('inline constexpr uint32_t k%s = %s;' % (cname(k), num(v)))
    for k, d in sorted(J.items()):
        if not k.endswith('Formula') or not isinstance(d, dict): continue
        fld = d.get('table1Field', d.get('table0Field'))
        if fld is None: continue
        w('inline constexpr Table k%s = { %s, \'%s\', %s, 0, false, "count_raw", 0 };  // %s' % (
            cname(k), num(fld), d['op'], num(d['key']),
            'T1' if 'table1Field' in d else 'T0'))
    w('')

    # ---- 注册表字段偏移 ----
    w('// ---------------- T0/T1 字段偏移 ----------------')
    for k, v in J.get('registrationFields', {}).items():
        w('inline constexpr uint32_t k%s = %s;' % (cname(k), num(v)))
    w('')

    # ---- 逐索引 key 参数 ----
    w('// ---------------- 逐索引 key 公式参数 ----------------')
    for kf, params in J.get('keyFormulas', {}).items():
        for pk, pv in params.items():
            ty = 'uint64_t' if str(pv).startswith('0x') and len(str(pv)) > 10 else ('int64_t' if str(pv).startswith('-') else 'uint64_t')
            w('inline constexpr %s k%s%s = %s%s;' % (
                ty, cname(kf), cname(pk), num(pv),
                'ull' if ty == 'uint64_t' and str(pv).startswith('0x') and len(str(pv)) > 10 else ''))
    w('')

    # ---- 字段解码 ----
    w('// ---------------- 字段解码（每个字段一组 op/key）----------------')
    for st, fields in J.get('fieldDecode', {}).items():
        for fname, spec in fields.items():
            op, key = split_op(spec)
            w("inline constexpr OpKey k%s%s = { '%s', %s };  // %s" % (
                cname(st), cname(fname), op, key, spec))
    w('')

    # ---- 结构体尺寸 ----
    w('// ---------------- 结构体尺寸 ----------------')
    for k, v in J.get('structSizes', {}).items():
        w('inline constexpr size_t kSize_%s = %s;' % (k, num(v)))
    w('')

    # ---- 自检（verify.py 也检查这些）----
    w('// ---------------- 锚点自检值（verify.py 会独立验证）----------------')
    w('inline constexpr uint32_t kAnchor_FieldDefaultValues = 0x3D00478;')
    w('inline constexpr uint32_t kAnchor_Blob               = 0x00F1754C;')
    w('inline constexpr uint32_t kAnchor_ParameterDefaultValues = 0x37274C0;')
    w('')
    w('} // namespace ver')
    w('')

    txt = '\n'.join(L)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    old = open(OUT_PATH, encoding='utf-8').read() if os.path.exists(OUT_PATH) else None
    if old != txt:
        open(OUT_PATH, 'w', encoding='utf-8').write(txt)
        print("生成 %s (%d 行)" % (os.path.relpath(OUT_PATH, ROOT), txt.count('\n')))
    else:
        print("%s 无变化" % os.path.relpath(OUT_PATH, ROOT))

if __name__ == '__main__':
    main()
