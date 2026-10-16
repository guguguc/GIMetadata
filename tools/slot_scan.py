#!/usr/bin/env python3
"""
MHY 槽位扫描器 —— 自动找出「MHY[slot] OP key => 元数据偏移」的全部组合。

原 6.7 dumper 只能在 init 函数里抄到 27 组；本脚本全 .text 扫描，能拿到 3000+ 组，
再用已知表（fieldDefaultValues / 常量值 blob / 各结构表）自检，避免抄错。

关键点（踩过的坑，别改回去）：
  * capstone 必须 md.skipdata = True，否则遇到非法字节就停止反汇编（只覆盖前几 KB）
  * VA->文件偏移必须按 PE 段表逐段映射，不能拿 .rdata 的线性关系外推到 .text
    （.text 起点 VA 0x140001000 对应文件 0x400，外推会差 0x400）
  * MHY 表本体 VA = 0x1427D4BD0（.rdata，开头 "MHY\0"）

用法:
    python3 slot_scan.py <gi.exe> [global-metadata.dat]
输出:
    1) 已知锚点自检（fieldDefaultValues 必须复现 0x3D00478）
    2) 所有解出「像元数据偏移」的组合
    3) 若给了 .dat，则把每个候选当 12 字节数组做结构合法性测试
"""
import struct, sys, json, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG

MHY_VA = 0x1427D4BD0
NSLOT = 0x300
M32 = (1 << 32) - 1
# 本样本已归档的锚点
ANCHORS = {0x3D00478: "fieldDefaultValues", 0xF1754C: "常量值 blob",
           0x37274C0: "parameterDefaultValues", 0x2439204: "methods"}


def load_sections(D):
    pe = struct.unpack_from('<I', D, 0x3C)[0]
    nsec = struct.unpack_from('<H', D, pe + 6)[0]
    opt = struct.unpack_from('<H', D, pe + 0x14)[0]
    so = pe + 0x18 + opt
    imgbase = struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]
    secs = []
    for i in range(nsec):
        e = so + i * 40
        nm = D[e:e + 8].rstrip(b'\0').decode(errors='replace')
        vsz, vaddr, rsz, roff = struct.unpack_from('<IIII', D, e + 8)
        secs.append((nm, imgbase + vaddr, vsz, roff, rsz))
    return secs


def va2off(secs, va):
    for nm, sva, vsz, roff, rsz in secs:
        if sva <= va < sva + max(vsz, rsz):
            return roff + (va - sva)
    raise ValueError("VA 不在任何段: 0x%X" % va)


def scan_text(D, secs):
    """返回 [(slot, op, key, 出现次数, 首个VA)]"""
    tname, tva, tvsz, toff, trsz = secs[0]
    text = D[toff:toff + trsz]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True                       # ★ 必须
    last_load, records, idx = {}, [], 0
    for insn in md.disasm(text, tva):
        idx += 1
        if insn.id == 0:                     # skipdata 占位
            last_load.clear()
            continue
        try:
            ops = insn.operands
        except Exception:
            last_load.clear()
            continue
        m = insn.mnemonic
        if m in ('mov', 'movsxd', 'movsx', 'movzx') and len(ops) == 2 \
           and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if mem.index == 0 and 0 <= mem.disp < NSLOT and mem.base != 0:
                last_load[ops[0].reg] = (mem.disp, idx)
            else:
                last_load.pop(ops[0].reg, None)
            continue
        if m in ('xor', 'sub', 'add', 'imul', 'or', 'and') and len(ops) == 2 \
           and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            r = ops[0].reg
            if r in last_load and idx - last_load[r][1] <= 8:
                records.append((last_load[r][0], m, ops[1].imm & M32, insn.address))
            last_load.pop(r, None)
            continue
        if ops and ops[0].type == X86_OP_REG:
            last_load.pop(ops[0].reg, None)
    uniq = {}
    for d, op, imm, va in records:
        uniq.setdefault((d, op, imm), []).append(va)
    return [(d, op, imm, len(v), v[0]) for (d, op, imm), v in uniq.items()]


def main():
    exe = sys.argv[1]
    dat = sys.argv[2] if len(sys.argv) > 2 else None
    D = open(exe, 'rb').read()
    secs = load_sections(D)
    svals = {o: struct.unpack_from('<I', D, va2off(secs, MHY_VA + o))[0]
             for o in range(0, NSLOT, 4)}

    print("=== 自检 ===")
    for slot, op, key, tgt, name in (
            (0x13C, '^', 0x593DE464, 0x3D00478, 'fieldDefaultValues'),
            (0x0A0, '^', 0x3F525210, 0xF1754C, '常量值 blob'),
            (0x104, '^', 0x094C42AB, 0x37274C0, 'parameterDefaultValues')):
        v = svals[slot]
        got = (v ^ key) if op == '^' else (v - key) & M32
        print("  MHY[0x%03X] %s 0x%08X = 0x%X  期望 0x%X  %s"
              % (slot, op, key, got, tgt, 'OK' if got == tgt else '**不符**'))

    print("\n扫描 .text ...")
    rows = scan_text(D, secs)
    print("唯一 (slot,op,key) 组合: %d" % len(rows))

    cand = []
    for d, op, imm, n, va in rows:
        if d == 0:
            continue
        v = svals.get(d)
        if v is None:
            continue
        val = (v ^ imm) if op == 'xor' else ((v - imm) & M32) if op == 'sub' else (v + imm) & M32
        cand.append((val, d, op, imm, n, va))

    if dat:
        raw = open(dat, 'rb').read()
        HDR = 0x210
        LIM = len(raw) - HDR
        print("\n=== 落在元数据范围内的候选 ===")
        out = []
        for val, d, op, imm, n, va in cand:
            if not (0x1000 <= val < LIM - 12):
                continue
            off = HDR + val
            # 12 字节数组：+0 < 683574（类型索引）且 +4 严格递增（fieldDefaultValues 风格）
            ok = 0
            prev = -1
            while off + 12 * ok + 12 <= len(raw):
                a, c, dd = struct.unpack_from('<iii', raw, off + 12 * ok)
                if 0 <= a < 683574 and 0 <= c < 0x7FFFFFFF and (ok == 0 or c > prev):
                    prev = c
                    ok += 1
                else:
                    break
            if ok >= 20:
                out.append((ok, val, d, op, imm, n, va))
        out.sort(reverse=True)
        for ok, val, d, op, imm, n, va in out:
            tag = ANCHORS.get(val, '')
            print("  12B 连续 %-6d 值 0x%-9X slot 0x%03X %s 0x%08X (%d次) %s"
                  % (ok, val, d, op, imm, n, tag))
    else:
        for val, d, op, imm, n, va in sorted(cand, key=lambda x: -x[0])[:60]:
            print("  0x%-9X slot 0x%03X %s 0x%08X (%d次) VA 0x%X"
                  % (val, d, op, imm, n, va))


if __name__ == '__main__':
    main()
