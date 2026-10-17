#!/usr/bin/env python3
"""order_apply.py —— **不用 IDA**：用「7.1 的读取点地址 + 指令对齐」推出 7.0 的 (slot,op,key)。

步骤
----
  ① 从 docs/PROVENANCE.md 取每张表在 7.1 的**读取指令地址**（实测证据）
  ② 找到它所在的 sig 函数（起点 ≤ VA < 起点+窗口）
  ③ 指令级对齐 7.1 <-> 7.0（port.align_fn）
  ④ 映射到 7.0 的同一位置，在 ±3 条指令内找 `[base+disp]`（slot）和 imm（key）
"""
import argparse
import os
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RIP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import port  # noqa: E402


def load_provenance(path):
    """| table | slot | op key | 0xVA → **func** ... |"""
    rows = {}
    rx = re.compile(r'^\| (\w+) \| `0x([0-9A-Fa-f]+)` \| `(\w+)` `0x([0-9A-Fa-f]+)` \| (.*?) \|')
    for line in open(path, encoding='utf-8'):
        m = rx.match(line)
        if not m:
            continue
        name, slot, op, key, ev = m.groups()
        vas = [int(x, 16) for x in re.findall(r'`0x([0-9A-Fa-f]+)`', ev)]
        if vas:
            rows[name] = (int(slot, 16), op, int(key, 16), vas)
    return rows


def pick_fn(va, hits, window=0x9000):
    cand = [(v, n) for n, v in hits.items() if v <= va < v + window]
    return max(cand) if cand else (None, None)


def read_near(md, ins_list, idx):
    """按**指令形态**取 (slot,key)，不瞎猜：

      形态 B: mov reg,imm   ; add/sub/xor reg,[base+slot]
              -> slot 在 idx 的 mem，key 在 idx-1 的 imm
      形态 A: mov reg,[base+slot] ; add/sub/xor reg,rXX
              -> slot 在 idx-1 的 mem，key 未知（在别的寄存器）→ 失败

    另外要求 **7.0 的助记符与 7.1 相同**（形态没变）。
    """
    if idx is None or idx >= len(ins_list):
        return None, None
    ins = ins_list[idx]
    mem = imm_prev = None
    for o in ins.operands:
        if o.type == X86_OP_MEM:
            mm = o.mem
            if mm.base not in (0, X86_REG_RIP) and mm.index == 0 and 0 <= mm.disp < 0x300:
                mem = mm.disp
    if mem is not None and idx > 0:
        prev = ins_list[idx - 1]
        for o in prev.operands:
            if o.type == X86_OP_IMM and (o.imm & 0xFFFFFFFF) >= 0x100:
                imm_prev = o.imm & 0xFFFFFFFF
    return mem, imm_prev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', default='version/7.1')
    ap.add_argument('--new', default='version/7.0')
    ap.add_argument('--sigs-old', default='/tmp/opencode/h71.json')
    ap.add_argument('--sigs-new', default='/tmp/opencode/h70_new.json')
    ap.add_argument('--prov', default=os.path.join(ROOT, 'docs/PROVENANCE.md'))
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    old = port.PE(os.path.join(ROOT, a.old, 'gi.exe'))
    new = port.PE(os.path.join(ROOT, a.new, 'gi.exe'))
    ho = port.parse_sig_json(a.sigs_old)
    hn = port.parse_sig_json(a.sigs_new)
    prov = load_provenance(a.prov)
    print('PROVENANCE 表: %d 张' % len(prov))

    out = {}
    # 已知的 7.0 真值（④/⑦ 实测），用于验收
    KNOWN = {'fieldDefaultValuesOffset': (0x0C, 'xor', 0x720EB389),
             'methodPointerIndexOffset': (0x130, 'add', 0xA3B3FC56),
             'methodSlotTableOffset': (0x1F8, 'xor', 0x5A7DB1D1),
             'attributesInfoOffset': (0x80, 'xor', 0x69D6A445),
             'typeDefinitionsOffset': (0x1A0, 'xor', 0x4CE7B502),
             'fieldAndParameterDefaultValueDataOffset': (0x1B0, 'xor', 0x26AB5EF8)}
    # 7.0 的读取指令形态：op 的助记符映射回 version.json 的 op 写法
    OPMAP = {'sub': '-', 'add': '+', 'xor': '^'}

    ok = bad = miss = 0
    print('\n%-42s %-10s %-14s %s' % ('表', '7.0 slot', '7.0 op:key', '判定'))
    for name, (slot71, op71, key71, vas) in sorted(prov.items()):
        got = None
        for va in vas:
            sva, fn = pick_fn(va, ho)
            if not sva or fn not in hn:
                continue
            oi = port.disasm_fn(old, md, sva, 0x9000)
            ni = port.disasm_fn(new, md, hn[fn], 0x9000)
            idx = next((i for i, x in enumerate(oi) if x.address == va), None)
            if idx is None:
                continue
            pairs, ratio = port.align_fn(oi, ni)
            m = dict(pairs)
            if idx not in m:
                continue
            j = m[idx]
            # 注意：**op 会变**（xor->add），所以不能比助记符；只看"槽位+紧邻 key"的形态
            slot, key = read_near(md, ni, j)
            if slot is None or key is None:
                continue
            got = (slot, OPMAP.get(oi[idx].mnemonic, oi[idx].mnemonic), key, fn)
            break
        if got is None:
            miss += 1
            print('%-42s %-10s %-14s ✗ 没推出来' % (name, '-', '-'))
            continue
        exp = KNOWN.get(name)
        tag = '（7.0 真值未知）'
        if exp:
            good = (got[0] == exp[0] and got[2] == exp[2])
            ok += good; bad += (not good)
            tag = '✅ 与 ④/⑦ 一致' if good else '✗ 应为 slot 0x%X %s 0x%X' % (exp[0], exp[1], exp[2])
        out[name] = {'slot': '0x%X' % got[0], 'op': got[1], 'key': '0x%X' % got[2], 'func': got[3]}
        print('%-42s 0x%-8X %-14s %s' % (name, got[0], '%s 0x%X' % (got[1], got[2]), tag))

    print('\n已知 6 张里: ✅ %d / ✗ %d ；未推出 %d 张' % (ok, bad, miss))
    if a.out:
        import json
        json.dump({'tables': out}, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('已写 %s' % a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
