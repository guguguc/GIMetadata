#!/usr/bin/env python3
"""cmp_funcs.py —— 用 capstone 比对两个版本的**同名函数**，检验
「函数内槽位读取顺序」是否跨版本稳定（这是 ida_apply --order 的前提）。

用法:
    python3 tools/cmp_funcs.py --old version/7.1 --new version/7.0 \
        --sigs-old /tmp/h71.json --sigs-new /tmp/h70.json
"""
import argparse
import json
import os
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import port  # noqa: E402


def slot_reads(pe, md, va, size=0x9000):
    o = pe.va2off(va)
    out = []
    if o is None:
        return out
    for k, ins in enumerate(md.disasm(pe.D[o:o + size], va)):
        ops = ins.operands
        if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            m = ops[1].mem
            if m.base not in (0, X86_REG_RIP) and m.index == 0 and 0 <= m.disp < 0x300:
                out.append((k, ins.address, m.disp))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--sigs-old', required=True)
    ap.add_argument('--sigs-new', required=True)
    ap.add_argument('--size', type=lambda x: int(x, 0), default=0x9000)
    a = ap.parse_args()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    old = port.PE(os.path.join(ROOT, a.old, 'gi.exe'))
    new = port.PE(os.path.join(ROOT, a.new, 'gi.exe'))
    ho = port.parse_sig_json(a.sigs_old)
    hn = port.parse_sig_json(a.sigs_new)
    common = sorted(set(ho) & set(hn))
    print('共同定位的函数: %d' % len(common))
    print('%-40s %-8s %-8s %-8s %-10s %s'
          % ('函数', '7.1指令', '7.0指令', '相似度', '槽位读取', '顺序一致?'))
    ok = bad = 0
    for fn in common:
        oi = port.disasm_fn(old, md, ho[fn], a.size)
        ni = port.disasm_fn(new, md, hn[fn], a.size)
        if not oi or not ni:
            continue
        pairs, ratio = port.align_fn(oi, ni)
        m = {x: y for x, y in pairs}
        ro = slot_reads(old, md, ho[fn], a.size)
        rn = slot_reads(new, md, hn[fn], a.size)
        mapped = [m[k] for k, _, _ in ro if k in m]
        mono = all(y > x for x, y in zip(mapped, mapped[1:])) and len(mapped) > 1
        ok += mono
        bad += (not mono)
        print('%-40s %-8d %-8d %-8.3f %-10s %s'
              % (fn, len(oi), len(ni), ratio, '%d/%d' % (len(ro), len(rn)),
                 '✅ 单调' if mono else '✗ 逆序'))
    print('\n顺序保持: %d 个函数 ✓ ；不保持: %d 个 ✗' % (ok, bad))
    return 0


if __name__ == '__main__':
    sys.exit(main())
