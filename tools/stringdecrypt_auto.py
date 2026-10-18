#!/usr/bin/env python3
"""从目标版本的 GIMeta_DecryptString 反编译文本恢复 stringDecrypt 参数。

支持三种已见形状：
  7.0: (B * off - C) ^ A
  7.1: A * ((B * off) ^ C)
  6.7: ((A * ((B * off) ^ D)) + E) ^ F

不读目标 version.json；--base 只用于补齐无法从表达式推断的 entryXor/keySeed。
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
M64 = (1 << 64) - 1

RE_67 = re.compile(
    r'\(\s*(?P<A>0x[0-9A-Fa-f]+|[0-9]+)\s*\*\s*'
    r'\(\(\s*(?P<B>0x[0-9A-Fa-f]+|[0-9]+)\s*\*\s*\w+\s*\)\s*\^\s*'
    r'(?P<C>0x[0-9A-Fa-f]+|[0-9]+)\)\s*\+\s*'
    r'(?P<D>0x[0-9A-Fa-f]+|[0-9]+)\)\s*\^\s*'
    r'(?P<E>0x[0-9A-Fa-f]+|[0-9]+)')
RE_71 = re.compile(
    r'(?P<A>0x[0-9A-Fa-f]+|[0-9]+)\s*\*\s*'
    r'\(\(\s*(?P<B>0x[0-9A-Fa-f]+|[0-9]+)\s*\*\s*\w+\s*\)\s*\^\s*'
    r'(?P<C>0x[0-9A-Fa-f]+|[0-9]+)\)')
RE_70 = re.compile(
    r'\(\s*(?P<B>0x[0-9A-Fa-f]+|[0-9]+)\s*\*\s*\w+\s*-\s*'
    r'(?P<C>0x[0-9A-Fa-f]+|[0-9]+)\)\s*\^\s*'
    r'(?P<A>0x[0-9A-Fa-f]+|[0-9]+)')


def n(v):
    return int(str(v), 0) & M64


def hexs(v):
    return '0x%X' % (v & M64)


def load_base(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        sys.path.insert(0, HERE)
        from gen_version import load_json_with_comments
        return load_json_with_comments(path).get('stringDecrypt', {})
    except Exception:
        return {}


def find_formula(text):
    # 只看字符串解密专用的 offset/长度区域，避免命中前面的 hash 公式。
    # 注意前面还有 & 0xFFFFFFFFFFFFFFFC 之类的掩码，不能直接 find('& 0xFFFFFF')。
    om = re.search(r'&\s*0xFFFFFF\s*;', text)
    if om:
        head = text[om.start():om.start() + 2000]
    else:
        head = text

    for pat, shape in ((RE_67, '6.7'), (RE_71, '7.1'), (RE_70, '7.0')):
        m = pat.search(head)
        if m:
            return m, shape
    return None, None


def find_step(text, lhs):
    # 优先找 "vX += key" / "vX += key * n"
    pat = re.compile(r'\b' + re.escape(lhs) + r'\s*\+=\s*(0x[0-9A-Fa-f]+|[0-9]+)')
    m = pat.search(text)
    if m:
        return n(m.group(1))
    # 有时编译器写成 step * vN
    pat = re.compile(r'\b' + re.escape(lhs) + r'\s*\+=\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*\*')
    m = pat.search(text)
    return n(m.group(1)) if m else None


def find_entry_xor(root):
    """从 RuntimeInit 的 image 名解密调用推断 entryXor。

    7.1 形如 `... ^ key ^ 0x772FA51E`（两个 xor）；
    7.0 形如 `(raw ^ 0x1BD33CC0) - key`（只有一个 xor，entryXor=0）。
    """
    files = glob.glob(os.path.join(root, 'ida', 'decomp', 'GIMeta_RuntimeInit_*.c'))
    for f in files:
        text = open(f, encoding='utf-8', errors='ignore').read()
        text = re.sub(r'/\*.*?\*/', '', text)
        for line in text.splitlines():
            if '40 *' not in line:
                continue
            if 'DecryptString' not in line and 'sub_14050F280' not in line:
                continue
            if line.count('^') >= 2:
                xs = re.findall(r'\^\s*(0x[0-9A-Fa-f]+|[0-9]+)', line)
                if xs:
                    return hexs(n(xs[-1]))
    return '0x0'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--base', default=None)
    ap.add_argument('--decomp', default=None)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, 'version', a.root)
    if not os.path.isdir(root):
        root = a.root
    dec = a.decomp or os.path.join(root, 'ida', 'decomp')
    out = a.out or os.path.join(root, 'ida', 'stringdecrypt.auto.json')

    files = glob.glob(os.path.join(dec, 'GIMeta_DecryptString_*.c'))
    if not files:
        sys.exit('no GIMeta_DecryptString decomp in %s' % dec)
    text = open(files[0], encoding='utf-8', errors='ignore').read()
    # 去掉 C 整数字面量后缀和行尾注释，表达式正则只关心数值。
    text = re.sub(r'/\*.*?\*/', '', text)
    text = re.sub(r'(?<=[0-9A-Fa-f])(?:u?LL|ULL)\b', '', text)
    m, shape = find_formula(text)
    if not m:
        sys.exit('stringDecrypt formula not recognized')

    d = m.groupdict()
    A, B, C = n(d['A']), n(d['B']), n(d['C'])
    base = load_base(a.base)
    step = find_step(text, 'v115') or find_step(text, 'v112')
    if step is None:
        sys.exit('stringDecrypt keyStep not recognized')

    # 公式左侧的变量名从匹配前的文本里取（v115/v112）
    line_start = text.rfind('\n', 0, m.start()) + 1
    lhs_m = re.search(r'(\w+)\s*=\s*$', text[line_start:m.start()])
    lhs = lhs_m.group(1) if lhs_m else 'v115'
    step = find_step(text, lhs) or step

    outd = {
        'keyMulA': hexs(A),
        'keyMulB': hexs(B),
        'keyStep': hexs(step),
        'offsetMask': '0xFFFFFF',
        'lengthShift': 24,
        'entryXor': find_entry_xor(root),
        '_source': os.path.relpath(files[0], ROOT),
        '_shape': shape,
    }
    if shape == '6.7':
        outd.update({
            'keyOffsetXor': hexs(C),
            'keyAdd': hexs(n(d['D'])),
            'keyFinalXor': hexs(n(d['E'])),
        })
    elif shape == '7.1':
        outd['keySeed'] = hexs(C)
    else:
        # 7.0 反编译写成 (B*off - C) ^ A，version.json 用 seed=C 的补码。
        outd['keySeed'] = hexs((-C) & M64)

    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(outd, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('wrote', out, 'shape', shape, 'step', hexs(step))


if __name__ == '__main__':
    main()
