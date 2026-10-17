#!/usr/bin/env python3
"""
MHY 槽位扫描器 —— 自动找出「MHY[slot] OP key => 元数据偏移」的全部组合。

原 6.7 dumper 只能在 init 函数里抄到 27 组；本脚本全 .text 扫描，能拿到 3000+ 组，
再用已知表（fieldDefaultValues / 常量值 blob / 各结构表）自检，避免抄错。

关键点（踩过的坑，别改回去）：
  * capstone 必须 md.skipdata = True，否则遇到非法字节就停止反汇编（只覆盖前几 KB）
  * VA->文件偏移必须按 PE 段表逐段映射，不能拿 .rdata 的线性关系外推到 .text
    （.text 起点 VA 0x140001000 对应文件 0x400，外推会差 0x400）
  * MHY 表本体：用 b"MHY\0" 魔数**自动发现**（换版本地址会变，脚本自带发现）
    7.1 = 0x1427D4BD0（.rdata，开头 "MHY\0"）

用法:
    python3 slot_scan.py <gi.exe> [global-metadata.dat] [--out CACHE]
输出:
    1) MHY 地址 + 已知锚点自检（7.1 的常数；换版本必然不符，属正常）
    2) 所有解出「像元数据偏移」的组合
    3) 若给了 .dat，则把每个候选当 12 字节数组做结构合法性测试
"""
import struct, sys, json, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG, X86_REG_RIP

MHY_VA_71 = 0x1427D4BD0
NSLOT = 0x300
M32 = (1 << 32) - 1
# 本样本已归档的锚点
ANCHORS = {0x3D00478: "fieldDefaultValues", 0xF1754C: "常量值 blob",
           0x37274C0: "parameterDefaultValues", 0x2439204: "methods"}


def find_mhy(D, secs):
    """按 b"MHY\\0" 魔数找 MHY 表的 VA（换版本自动适配）"""
    for nm, va, vsz, off, rsz in secs:
        if nm.upper() not in (".RDATA", ".DATA", "_RDATA"): continue
        blob = D[off:off + rsz]
        i = 0
        while True:
            j = blob.find(b'MHY\x00', i)
            if j < 0: break
            return va + j
            i = j + 1
    return None


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


def scan_text(D, secs, va0=None, size=None, maxdisp=NSLOT):
    """返回 [(slot, op, key, 出现次数, 首个VA)]

    匹配**三种**形态：
      A) mov reg,[mhy+slot]   ...  op reg,imm            槽位在前
      B) mov reg,imm          ...  op reg,[mhy+slot]     密钥在前 ← v1 漏掉
      C) mov reg,[mhy+slot] / mov reg2,imm / op reg,reg2 寄存器对寄存器 ← v2 漏掉
    寄存器按族归一（eax/rax 视为同一），窗口 8 条指令。
    """
    if va0 is None:
        tname, tva, tvsz, toff, trsz = secs[0]
        text = D[toff:toff + trsz]
    else:
        # 只扫指定函数区域（--func）：结构体字段读取点就在这些函数里
        tva = va0
        off0 = va2off(secs, va0)
        if off0 is None:
            return []
        text = D[off0:off0 + (size or 0x4000)]
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
            if mem.index == 0 and 0 <= mem.disp < maxdisp and mem.base != 0:
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
            if k in last_imm and mem.index == 0 and 0 <= mem.disp < maxdisp and mem.base != 0:
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

        # C2) op reg, [rip+const]  （槽位在 reg 里，密钥在**数据段常量池**）★ v3 漏掉的形态
        #    实测：typeDef+0x18(parentIndex)/+0x24(nameIndex)/+0x28(flags) 的密钥
        #          既不在 .text 立即数里，也不在寄存器里，而是 rip 相对的数据段常量
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG \
           and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP:
            k = fam(ops[0].reg)
            if k in last_load:
                tgt = insn.address + insn.size + ops[1].mem.disp
                o = va2off(secs, tgt)
                if o is not None and 0 <= o + 4 <= len(D):
                    keyv = struct.unpack_from('<I', D, o)[0]
                    records.append((last_load[k][0], m, keyv, insn.address))
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        if ops and ops[0].type == X86_OP_REG:
            k = fam(ops[0].reg)
            last_load.pop(k, None); last_imm.pop(k, None)

    uniq = {}
    for d, op, imm, va in records:
        uniq.setdefault((d, op, imm), []).append(va)
    return [(d, op, imm, len(v), v[0]) for (d, op, imm), v in uniq.items()]



# 结构体字段偏移 -> 字段名（镜像 src/il2cpp_image.hpp 的 struct；**布局跨版本稳定**，
# 变的只有解码密钥，所以这张表可以长期复用）
STRUCT_LAYOUT = {
    'typeDef': (0x46, {
        0x00: 'namespaceIndex', 0x08: 'propertyStart', 0x0C: 'methodStart',
        0x18: 'parentIndex', 0x1C: 'fieldStart', 0x20: 'unknown20',
        0x24: 'nameIndex', 0x28: 'flags', 0x30: 'method_count',
        0x34: 'eventStart', 0x36: 'nestedTypesStart', 0x38: 'field_count',
        0x3C: 'interfacesStart', 0x3E: 'genericContainerIndex',
        0x40: 'interfaces_count', 0x43: 'property_count',
        0x44: 'event_count', 0x45: 'nestedTypesCount',
    }),
}


def cmd_struct(D, secs, name, funcs):
    """扫描给定函数，解出「结构体字段的 (位移, op, 密钥)」并与 version.json 自检。"""
    if name not in STRUCT_LAYOUT:
        print('✗ 未知结构体 %r；可用: %s' % (name, ', '.join(STRUCT_LAYOUT)))
        return 1
    size, layout = STRUCT_LAYOUT[name]
    print('=== 扫描结构体 %s（%d 字节，%d 个已知字段）于 %d 个函数 ==='
          % (name, size, len(layout), len(funcs)))
    got = {}
    for va in funcs:
        for disp, op, key, cnt, first in scan_text(D, secs, va0=va, size=0x6000, maxdisp=size):
            got.setdefault(disp, []).append((op, key, cnt, first))
    uniq = 0
    for disp in sorted(layout):
        seen = sorted({(op, key) for op, key, _, _ in got.get(disp, [])})
        if len(seen) == 1:
            uniq += 1
            mark = '\u2705 \u552f\u4e00  '
        elif seen:
            mark = '  %d \u5019' % len(seen)
        else:
            mark = '  \u2014'
        print('  +0x%02X  %-22s %s: %s'
              % (disp, layout[disp], mark,
                 ', '.join('%s 0x%X' % t for t in seen[:3]) or '(没扫到)'))
    print('\n  \u552f\u4e00\u786e\u5b9a %d/%d \u4e2a\u5b57\u6bb5\uff08\u5176\u4f59\u9700\u8981\u5224\u5b9a\uff1a\u5019\u9009\u91cc\u9009\uff0c\u6216\u626b\u66f4\u591a\u51fd\u6570\uff09' % (uniq, len(layout)))
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gen_version import load_json_with_comments as L
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        J = L(os.path.join(root, 'version.json'))
        fd = J['fieldDecode'][name]
        print('\n=== 与 version.json 的 fieldDecode.%s 自检 ===' % name)
        ok = miss = 0
        for disp, fld in sorted(layout.items()):
            spec = fd.get(fld)
            if not spec:
                continue
            op, _, key = spec.partition(':')
            key = int(key.strip(), 0)
            cands = {(o, k) for o, k, _, _ in got.get(disp, [])}
            # 编译器会把「减 K」折成「加 -K 的补码」，位宽按**字段宽度**截断（8/16/32）
            alt = {(op, key)}
            for w in (8, 16, 32):
                m = (1 << w) - 1
                # 注意是 (-key) & m，不是 key + 2^w（后者 & m 后会绕回自身）
                if op == 'sub':
                    alt.add(('add', (-key) & m))
                elif op == 'add':
                    alt.add(('sub', (-key) & m))
            if cands & alt:
                ok += 1
                print('  \u2705 %-22s +0x%02X  %s' % (fld, disp, spec))
            else:
                miss += 1
                print('  \u2717 %-22s +0x%02X  期望 %s，本轮没扫到' % (fld, disp, spec))
        print('  覆盖: %d/%d' % (ok, ok + miss))
    except Exception as e:
        print('（自检跳过: %s）' % e)
    return 0


def main():
    argv = sys.argv[1:]
    out_path = None
    if '--out' in argv:
        i = argv.index('--out'); out_path = argv[i + 1]; del argv[i:i + 2]
    funcs = []
    while '--func' in argv:
        i = argv.index('--func'); funcs.append(int(argv[i + 1], 16)); del argv[i:i + 2]
    struct_name = None
    if '--struct' in argv:
        i = argv.index('--struct'); struct_name = argv[i + 1]; del argv[i:i + 2]
    hits_path = None
    if '--hits' in argv:
        i = argv.index('--hits'); hits_path = argv[i + 1]; del argv[i:i + 2]
    exe = argv[0]
    dat = argv[1] if len(argv) > 1 and not argv[1].startswith('-') else None
    D = open(exe, 'rb').read()
    secs = load_sections(D)
    if struct_name:
        if hits_path:
            # 函数地址来自 sig.py scan 的产物 -> **跨版本自动**，不用手抄地址
            import json as _j
            H = _j.load(open(hits_path))
            hv = H['hits'] if isinstance(H, dict) and 'hits' in H else H
            names = sorted(hv)
            funcs = [hv[n] for n in names]
            print('从 %s 取到 %d 个函数地址（sig.py scan 产物，跨版本自动）'
                  % (os.path.basename(hits_path), len(funcs)))
            print('  ' + ', '.join('%s@0x%X' % (n, hv[n]) for n in names[:6])
                  + (' ...' if len(names) > 6 else ''))
        if not funcs:
            print('\u2717 需要 --hits <sig scan 的 json> 或 --func <VA>')
            return 1
        return cmd_struct(D, secs, struct_name, funcs)
    MHY_VA = find_mhy(D, secs)
    if MHY_VA is None:
        print("✗ 未找到 b'MHY\\0' 魔数 —— 这不像 Genshin 的 gi.exe？")
        return 1
    print("MHY 表 VA = 0x%X%s" % (MHY_VA, "" if MHY_VA != MHY_VA_71 else "  (与 7.1 相同)"))
    svals = {o: struct.unpack_from('<I', D, va2off(secs, MHY_VA + o))[0]
             for o in range(0, NSLOT, 4)}

    print("\n=== 自检（7.1 的常数；换版本必然不符，属正常）===")
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
        cache_path = out_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'slots_cache.json')
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
