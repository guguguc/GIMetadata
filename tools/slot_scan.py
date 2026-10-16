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


# 寄存器族：32/64/8 位同名寄存器归一（eax/rax/ax/al → 'a'）
_GP = {}
for _names, _f in ((('rax','eax','ax','al','ah'),'a'), (('rbx','ebx','bx','bl','bh'),'b'),
                   (('rcx','ecx','cx','cl','ch'),'c'), (('rdx','edx','dx','dl','dh'),'d'),
                   (('rsi','esi','si','sil'),'si'), (('rdi','edi','di','dil'),'di'),
                   (('rbp','ebp','bp','bpl'),'bp'), (('rsp','esp','sp','spl'),'sp')):
    for _n in _names: _GP[_n] = _f
for _k in range(8, 16): _GP['r%d' % _k] = 'r%d' % _k
_GP.update({'r8d':'r8','r8w':'r8','r8b':'r8','r9d':'r9','r9w':'r9','r9b':'r9',
            'r10d':'r10','r10w':'r10','r10b':'r10','r11d':'r11','r11w':'r11','r11b':'r11',
            'r12d':'r12','r12w':'r12','r12b':'r12','r13d':'r13','r13w':'r13','r13b':'r13',
            'r14d':'r14','r14w':'r14','r14b':'r14','r15d':'r15','r15w':'r15','r15b':'r15'})


def scan_text(D, secs):
    """返回 [(slot, op, key, 出现次数, 首个VA)]

    匹配**三种**形态：
      A) mov reg,[mhy+slot]   ...  op reg,imm            槽位在前
      B) mov reg,imm          ...  op reg,[mhy+slot]     密钥在前 ← v1 漏掉
      C) mov reg,[mhy+slot] / mov reg2,imm / op reg,reg2 寄存器对寄存器 ← v2 漏掉
    寄存器按族归一（eax/rax 视为同一），窗口 8 条指令。
    """
    tname, tva, tvsz, toff, trsz = secs[0]
    text = D[toff:toff + trsz]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    last_load, last_imm, records, idx = {}, {}, [], 0
    OPS = ('xor', 'sub', 'add', 'imul', 'or', 'and')
    for insn in md.disasm(text, tva):
        idx += 1
        if insn.id == 0:
            last_load.clear(); last_imm.clear(); continue
        try:
            ops = insn.operands
        except Exception:
            last_load.clear(); last_imm.clear(); continue
        m = insn.mnemonic
        def fam(r): return _GP.get(md.reg_name(r), md.reg_name(r))

        # call/ret 会破坏调用者保存寄存器 → 清掉它们的追踪，避免跨调用误判
        if m in ('call', 'ret', 'retn', 'jmp', 'syscall', 'int3'):
            for _c in ('a', 'c', 'd', 'si', 'di', 'r8', 'r9', 'r10', 'r11'):
                last_load.pop(_c, None); last_imm.pop(_c, None)
            continue

        # A) mov reg, [base+disp]
        if m in ('mov', 'movsxd', 'movsx', 'movzx') and len(ops) == 2 \
           and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if mem.index == 0 and 0 <= mem.disp < NSLOT and mem.base != 0:
                last_load[fam(ops[0].reg)] = (mem.disp, idx)
            else:
                last_load.pop(fam(ops[0].reg), None)
            last_imm.pop(fam(ops[0].reg), None)
            continue

        # B) mov reg, imm   （把密钥装进寄存器）
        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            last_imm[fam(ops[0].reg)] = (ops[1].imm & M32, idx)
            last_load.pop(fam(ops[0].reg), None)
            continue

        # D) op reg, imm      （槽位已在 reg 里）
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            k = fam(ops[0].reg)
            if k in last_load:
                records.append((last_load[k][0], m, ops[1].imm & M32, insn.address))
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        # C) op reg, [base+disp]   （密钥已在 reg 里）★ v1 漏掉的形态
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            k = fam(ops[0].reg)
            mem = ops[1].mem
            if k in last_imm and mem.index == 0 and 0 <= mem.disp < NSLOT and mem.base != 0:
                records.append((mem.disp, m, last_imm[k][0], insn.address))
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        # E) op reg, reg   （槽位在一个寄存器、密钥在另一个寄存器）★ v2 漏掉的形态
        #    实测：mov ecx,[rcx+0x5c] / mov edx,0xe93d6d0d / add ecx,edx
        #    只失效**目的**寄存器；密钥寄存器常被后续多个槽位复用
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            kd, ks = fam(ops[0].reg), fam(ops[1].reg)
            ldd, immd = last_load.get(kd), last_imm.get(kd)
            lds, imms = last_load.get(ks), last_imm.get(ks)
            if ldd and imms:
                records.append((ldd[0], m, imms[0], insn.address))
            elif lds and immd:
                records.append((lds[0], m, immd[0], insn.address))
            last_load.pop(kd, None); last_imm.pop(kd, None)
            continue

        if ops and ops[0].type == X86_OP_REG:
            k = fam(ops[0].reg)
            last_load.pop(k, None); last_imm.pop(k, None)

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
    # 写缓存，供 tools/relocate.py 复用（省几分钟重扫）
    try:
        cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'slots_cache.json')
        json.dump({'svals': {str(k): v for k, v in svals.items()},
                   'uniq': [[d, op, imm, n, va] for d, op, imm, n, va in rows]},
                  open(cache_path, 'w'))
        print("缓存已写 %s" % cache_path)
    except Exception as e:
        print("写缓存失败:", e)

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
