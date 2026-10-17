#!/usr/bin/env python3
"""为 version.json 的每一条偏移生成「溯源」报告。

**不看 slots_cache.json** —— 直接扫 gi.exe，找每个 (位移, op, 密钥) 真正被读的指令，
再映射到 `tools/sigs.json` 里的函数名。输出 docs/PROVENANCE.md。

用法:
    python3 tools/provenance.py version/7.1/gi.exe [--out docs/PROVENANCE.md]
"""
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG, X86_REG_RIP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

OPNAMES = {'sub': '-', 'add': '+', 'xor': '^'}
OPS = ('xor', 'sub', 'add')

_GP = {}
for _names, _f in ((('rax', 'eax', 'ax', 'al', 'ah'), 'a'), (('rbx', 'ebx', 'bx', 'bl', 'bh'), 'b'),
                   (('rcx', 'ecx', 'cx', 'cl', 'ch'), 'c'), (('rdx', 'edx', 'dx', 'dl', 'dh'), 'd'),
                   (('rsi', 'esi', 'si', 'sil'), 'si'), (('rdi', 'edi', 'di', 'dil'), 'di'),
                   (('rbp', 'ebp', 'bp', 'bpl'), 'bp'), (('rsp', 'esp', 'sp', 'spl'), 'sp')):
    for _n in _names:
        _GP[_n] = _f
_GP.update({'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
            'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'})


def get_imagebase(D):
    pe = struct.unpack_from('<I', D, 0x3C)[0]
    return struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]


def load_sections(D):
    pe = struct.unpack_from('<I', D, 0x3C)[0]
    nsec = struct.unpack_from('<H', D, pe + 6)[0]
    opt = struct.unpack_from('<H', D, pe + 0x14)[0]
    so = pe + 0x18 + opt
    imgbase = struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]
    out = []
    for i in range(nsec):
        e = so + i * 40
        nm = D[e:e + 8].rstrip(b'\0').decode(errors='replace')
        vsz, vaddr, rsz, roff = struct.unpack_from('<IIII', D, e + 8)
        out.append((nm, imgbase + vaddr, vsz, roff, rsz))
    return out


def va2off(secs, va):
    for nm, sva, vsz, roff, rsz in secs:
        if sva <= va < sva + max(vsz, rsz):
            return roff + (va - sva)
    return None


def scan(D, secs, targets, maxdisp=0x400):
    """扫 .text，只记录 targets 里的 (disp,op,imm)。

    四种形态与 slot_scan 一致（这里是**独立实现**，只为溯源取证）：
      A) mov reg,[base+disp] ... op reg,imm
      B) mov reg,imm        ... op reg,[base+disp]
      C) mov reg,[base+disp] ... op reg,reg2
      D) op reg,[rip+const]（密钥在数据段）
    返回值: {(disp,op,imm): [VA, ...]}  （每个最多 4 个）
    """
    tname, tva, tvsz, toff, trsz = secs[0]
    text = D[toff:toff + trsz]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    last_load, last_imm = {}, {}
    hits = {}

    def rec(disp, op, imm, va):
        k = (disp, op, imm & 0xFFFFFFFF)
        if k in targets:
            lst = hits.setdefault(k, [])
            if len(lst) < 4:
                lst.append(va)

    for insn in md.disasm(text, tva):
        if insn.id == 0:
            last_load.clear(); last_imm.clear(); continue
        try:
            ops = insn.operands
        except Exception:
            last_load.clear(); last_imm.clear(); continue
        m = insn.mnemonic

        def fam(r):
            return _GP.get(md.reg_name(r), md.reg_name(r))

        if m in ('call', 'ret', 'retn', 'jmp', 'syscall', 'int3'):
            for c in ('a', 'c', 'd', 'si', 'di', 'r8', 'r9', 'r10', 'r11'):
                last_load.pop(c, None); last_imm.pop(c, None)
            continue

        # A) mov reg,[base+disp]
        if m in ('mov', 'movsxd', 'movsx', 'movzx') and len(ops) == 2 \
           and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if mem.base != X86_REG_RIP and mem.index == 0 and 0 <= mem.disp < maxdisp and mem.base != 0:
                last_load[fam(ops[0].reg)] = (mem.disp, insn.address)
            else:
                last_load.pop(fam(ops[0].reg), None)
            last_imm.pop(fam(ops[0].reg), None)
            continue

        # B) mov reg,imm
        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            last_imm[fam(ops[0].reg)] = (ops[1].imm & 0xFFFFFFFF, insn.address)
            last_load.pop(fam(ops[0].reg), None)
            continue

        # D) op reg,imm
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            k = fam(ops[0].reg)
            if k in last_load:
                rec(last_load[k][0], m, ops[1].imm, insn.address)
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        # C) op reg,[base+disp]
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            k = fam(ops[0].reg)
            mem = ops[1].mem
            if k in last_imm and mem.index == 0 and 0 <= mem.disp < maxdisp and mem.base not in (0, X86_REG_RIP):
                rec(mem.disp, m, last_imm[k][0], insn.address)
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        # E) op reg,reg
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            kd, ks = fam(ops[0].reg), fam(ops[1].reg)
            ldd, immd = last_load.get(kd), last_imm.get(kd)
            lds, imms = last_load.get(ks), last_imm.get(ks)
            if ldd and imms:
                rec(ldd[0], m, imms[0], insn.address)
            elif lds and immd:
                rec(lds[0], m, immd[0], insn.address)
            last_load.pop(kd, None); last_imm.pop(kd, None)
            continue

        # F) op reg,[rip+const]（数据段常量池）
        if m in OPS and len(ops) == 2 and ops[0].type == X86_OP_REG \
           and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP:
            k = fam(ops[0].reg)
            if k in last_load:
                tgt = insn.address + insn.size + ops[1].mem.disp
                o = va2off(secs, tgt)
                if o is not None and 0 <= o + 4 <= len(D):
                    rec(last_load[k][0], m, struct.unpack_from('<I', D, o)[0], insn.address)
            last_load.pop(k, None); last_imm.pop(k, None)
            continue

        if ops and ops[0].type == X86_OP_REG:
            k = fam(ops[0].reg)
            last_load.pop(k, None); last_imm.pop(k, None)

    return hits


# 结构体字段偏移（镜像 src/il2cpp_image.hpp 的 struct 定义；布局跨版本稳定）
FIELD_LAYOUT = {
    'typeDef': {0x00: 'namespaceIndex', 0x08: 'propertyStart', 0x0C: 'methodStart',
                0x18: 'parentIndex', 0x1C: 'fieldStart', 0x20: 'unknown20',
                0x24: 'nameIndex', 0x28: 'flags', 0x30: 'method_count',
                0x34: 'eventStart', 0x36: 'nestedTypesStart', 0x38: 'field_count',
                0x3C: 'interfacesStart', 0x3E: 'genericContainerIndex',
                0x40: 'interfaces_count', 0x43: 'property_count',
                0x44: 'event_count', 0x45: 'nestedTypesCount'},
    'method': {0x00: 'nameIndex', 0x04: 'parameterStart', 0x08: 'returnType',
               0x0C: 'declaringType', 0x10: 'iflags', 0x16: 'flags', 0x18: 'parameterCount'},
    'field': {0x00: 'typeIndex', 0x04: 'nameIndex'},
    'property': {0x00: 'nameIndex', 0x06: 'get', 0x08: 'set'},
    'event': {0x00: 'typeIndex', 0x04: 'nameIndex', 0x08: 'add', 0x0A: 'remove', 0x0C: 'raise'},
    'parameter': {0x00: 'typeIndex', 0x04: 'nameIndex'},
    'genericContainer': {0x04: 'parameterStart', 0x08: 'argc'},
    'genericParameter': {0x00: 'nameIndex'},
}


def load_pdata(D, secs):
    """解析 .pdata 的 RUNTIME_FUNCTION 表 -> [(start_va, end_va)]

    这是 x64 的**权威函数边界**（编译器生成的异常展开表），
    比"用签名起点当边界"可靠得多。
    """
    imgbase = get_imagebase(D)
    out = []
    for nm, sva, vsz, roff, rsz in secs:
        if nm != '.pdata':
            continue
        for i in range(rsz // 12):
            b, e, _u = struct.unpack_from('<III', D, roff + i * 12)
            if b == 0 or e <= b:
                continue
            out.append((imgbase + b, imgbase + e))
    out.sort()
    return out


def load_sigs():
    p = os.path.join(HERE, 'sigs.json')
    if not os.path.exists(p):
        return []
    d = json.load(open(p))
    out = []
    for e in (d if isinstance(d, list) else d.get('sigs', [])):
        va = e.get('va') or e.get('address') or e.get('start')
        nm = e.get('name') or e.get('func')
        if va and nm:
            out.append((int(va, 0) if isinstance(va, str) else int(va), nm))
    return sorted(out)


_SIGS = []
SIG_WINDOW = 0x3000     # 证据地址距签名起点超过这个距离就不敢认（实测真归属都在 0xF00 内）


def func_of(va, sigs=None):
    """VA -> (函数描述, 是否敢认)。

    名字来自 `sigs.json` 的函数起点；窗口 = min(下一个签名起点, 起点+0x3000)。
    ⚠️ 这个二进制**没有可用的 .pdata**（被保护/混淆：区间大小出现 0xFFFBC308，
       同一地址落进 5 个区间）—— 所以只能用签名起点 + 距离窗口做保守归属。
    不敢认时返回 (None, False)，报告里只给指令地址（仍然可核对）。
    """
    global _SIGS
    if sigs is not None:
        _SIGS = sorted(sigs)
    prev = None
    nxt = None
    for s, nm in _SIGS:
        if s <= va:
            prev = (s, nm)
        else:
            nxt = s
            break
    if prev is None:
        return None, False
    s, nm = prev
    off = va - s
    if off > SIG_WINDOW:
        return None, False
    if nxt is not None and va >= min(nxt, s + SIG_WINDOW):
        return None, False
    return ('%s+0x%X' % (nm, off)) if off else nm, True


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith('--')]
    exe = argv[0] if argv else os.path.join(ROOT, 'version/7.1/gi.exe')
    out_path = os.path.join(ROOT, 'docs/PROVENANCE.md')
    if '--out' in sys.argv:
        out_path = sys.argv[sys.argv.index('--out') + 1]
    hits_in = sys.argv[sys.argv.index('--hits-in') + 1] if '--hits-in' in sys.argv else None
    hits_out = sys.argv[sys.argv.index('--hits-out') + 1] if '--hits-out' in sys.argv else None

    D = open(exe, 'rb').read()
    secs = load_sections(D)
    J = json.load(open(os.path.join(ROOT, 'version.json'))) if False else None
    # version.json 含注释 -> 用项目里的宽松加载器
    sys.path.insert(0, HERE)
    from gen_version import load_json_with_comments as L
    J = L(os.path.join(ROOT, 'version.json'))

    sigs = load_sigs()
    global _SIGS
    _SIGS = sorted(sigs)
    print("签名函数起点: %d 个（证据归属窗口 ±0x%X）" % (len(_SIGS), SIG_WINDOW))

    # ---- 目标集合 ----
    tables = {}      # (disp,op,imm) -> 标签
    M32 = (1 << 32) - 1
    for k, cfg in J.get('tables', {}).items():
        if 'slot' not in cfg or cfg.get('stride', 0) == 0:
            continue
        disp = int(cfg['slot'], 0)
        op = {'-': 'sub', '+': 'add', '^': 'xor'}[cfg['op']]
        imm = int(str(cfg['key']), 0) & M32
        tables[(disp, op, imm)] = k
        # 补码形式（编译器可能用 add -K）
        if op in ('sub', 'add'):
            tables.setdefault((disp, 'add' if op == 'sub' else 'sub', (-imm) & M32), k)

    fields = {}
    for st, d in J.get('fieldDecode', {}).items():
        layout = FIELD_LAYOUT.get(st, {})
        for fname, spec in d.items():
            op, _, key = spec.partition(':')
            key = int(key.strip(), 0) & M32
            off = None
            for o, n in layout.items():
                if n == fname or (fname == 'nameIndexBase' and n == 'nameIndex'):
                    off = o
                    break
            if off is None:
                continue
            fields[(off, op.strip(), key)] = '%s+0x%02X %s' % (st, off, fname)
            if op.strip() in ('sub', 'add'):
                other = 'add' if op.strip() == 'sub' else 'sub'
                fields[(off, other, (-key) & M32)] = '%s+0x%02X %s' % (st, off, fname)

    targets = dict(tables)
    targets.update(fields)

    if hits_in and os.path.exists(hits_in):
        raw = json.load(open(hits_in))
        hits = {}
        for k, vs in raw.items():
            d_, o_, i_ = k.split(',')
            hits[(int(d_), o_, int(i_))] = vs
        print("复用扫描结果: %s" % hits_in)
    else:
        print("扫描 .text（目标 %d 个三元组）..." % len(targets))
        hits = scan(D, secs, targets)
        if hits_out:
            json.dump({('%d,%s,%d' % k): v for k, v in hits.items()}, open(hits_out, 'w'))

    # ---- 输出 ----
    lines = []
    lines.append("# 逐条溯源 —— `version.json` 的每个常量从哪来\n")
    lines.append("> **本文件由 `tools/provenance.py` 生成**（直接扫 `gi.exe`，**不读** `slots_cache.json`）。\n")
    lines.append("> 「证据」列 = 真正执行 `*(默认对象+位移) op 密钥` 的指令地址；")
    lines.append("> 函数名来自 `tools/sigs.json`（%d 条结构签名，`GIMeta_*`/`MetaStr_*`）。\n" % len(sigs))
    lines.append("> 生成命令：`python3 tools/provenance.py version/7.1/gi.exe`\n")
    lines.append("> ⚠️ 未命中的条目**不是错**：它们通常由**结构自证 / 语义锚 / 反解**得到，")
    lines.append("> 而不是从这条指令形态读出来的（见 `UPDATE.md` §5.7）。\n")

    def row(k, disp, op, key, extra):
        h = hits.get((disp, op, key), [])
        if h:
            ev = []
            for va in h[:2]:
                nm, exact = func_of(va, sigs)
                ev.append("`0x%X` → **%s**" % (va, nm) if nm else "`0x%X`" % va)
            evs = " ✓ ".join(ev)
            selfv = "代码读取点"
        else:
            evs = "—"
            selfv = extra
        return "| %s | `0x%03X` | `%s` `0x%X` | %s | %s |" % (k, disp, op, key, evs, selfv)

    lines.append("\n## 一、表常量（`tables`，34 项）\n")
    lines.append("| 表 | 槽位 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |")
    lines.append("|---|---|---|---|---|")
    struct_self = {
        'fieldDefaultValuesOffset': '结构自证（12B，+0 严格递增，+8 全为合法 Il2CppType 索引）',
        'fieldAndParameterDefaultValueDataOffset': '常量签名反推（AttributeTargets 落位）',
        'typeDefinitionsCount': '公式 `(raw-key)/70-2` + verify 类型数',
        'methodsCount': '公式 `(raw^key)/26`',
        'genericTypeArgOffset': '本版本值为 0（代码里已不读）',
    }
    seen_tbl = set()
    for k, cfg in J.get('tables', {}).items():
        if 'slot' not in cfg or cfg.get('stride', 0) == 0:
            continue
        if k in seen_tbl:
            continue
        seen_tbl.add(k)
        disp = int(cfg['slot'], 0)
        op = {'-': 'sub', '+': 'add', '^': 'xor'}[cfg['op']]
        imm = int(str(cfg['key']), 0) & M32
        alt = (disp, {'sub': 'add', 'add': 'sub'}.get(op, op), (-imm) & M32)
        sites = list(hits.get((disp, op, imm), []))
        enc = '' if sites else ''
        if alt != (disp, op, imm):
            alt_sites = hits.get(alt, [])
            if alt_sites:
                sites = alt_sites
                enc = '（代码里用 `%s 0x%X` 补码形式）' % (alt[1], alt[2])
        if sites:
            ev = []
            for va in sites[:2]:
                nm, _ = func_of(va, sigs)
                ev.append("`0x%X` → **%s**" % (va, nm) if nm else "`0x%X`" % va)
            evs = " ✓ ".join(ev)
            why = '代码读取点' + enc
        else:
            evs = '—'
            why = struct_self.get(k, '未在本版本代码里找到该形态 → 靠结构自证/反解/该表未使用')
        lines.append("| %s | `0x%03X` | `%s` `0x%X` | %s | %s |" % (k, disp, op, imm, evs, why))

    lines.append("\n## 二、结构体字段（`fieldDecode`，8 个结构体）\n")
    for st in ('typeDef', 'method', 'field', 'property', 'event', 'parameter',
               'genericContainer', 'genericParameter'):
        d = J.get('fieldDecode', {}).get(st)
        if not d:
            continue
        lines.append("\n### `%s`\n" % st)
        lines.append("| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |")
        lines.append("|---|---|---|---|---|")
        for fname, spec in d.items():
            op, _, key = spec.partition(':')
            key = int(key.strip(), 0) & M32
            off = None
            layout = FIELD_LAYOUT.get(st, {})
            for o, n in layout.items():
                if n == fname or (fname == 'nameIndexBase' and n == 'nameIndex'):
                    off = o
                    break
            if off is None:
                continue
            DERIVED = {'parentIndex', 'genericContainerIndex'}
            if st == 'typeDef' and fname in DERIVED:
                extra = '**反解**（代码里没有这个立即数，见 §5.7.4）'
            elif st == 'typeDef':
                extra = '未命中：可能用了别的读取形态/位宽（需 IDA 复核）'
            else:
                extra = '未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定）'
            opn = op.strip()
            sites = list(hits.get((off, opn, key), []))
            enc = ''
            if not sites and opn in ('sub', 'add'):
                alt = (off, 'add' if opn == 'sub' else 'sub', (-key) & M32)
                alt_sites = hits.get(alt, [])
                if alt_sites:
                    sites = alt_sites
                    enc = '（代码里用 `%s 0x%X` 补码）' % (alt[1], alt[2])
            if sites:
                ev = []
                for va in sites[:2]:
                    nm, _ = func_of(va, sigs)
                    ev.append("`0x%X` → **%s**" % (va, nm) if nm else "`0x%X`" % va)
                evs = ' ✓ '.join(ev)
                why = '代码读取点' + enc
            else:
                evs = '—'
                why = extra
            lines.append("| %s.%s | `0x%02X` | `%s` `0x%X` | %s | %s |"
                         % (st, fname, off, opn, key, evs, why))

    lines.append("\n## 三、非「指令立即数」类常量\n")
    lines.append("| 类别 | 怎么来的 | 自证 |")
    lines.append("|---|---|---|")
    lines.append("| `keyFormulas.*` | 反编译 `xxxKey(i)` 的函数体（乘/加/移位/xor），**人工抄** | 名字可打印 / `typeIndex` 100% 合法 |")
    lines.append("| `structSizes.*` | il2cpp 原始 C 结构体定义 + 反编译步长 | `count = raw/stride` 与实测一致 |")
    lines.append("| `*CountFormula` | 找**消费者**（`RuntimeInit` 的循环定界/数组分配） | 算出的计数 == 实测 |")
    lines.append("| `addresses.MHY` | 搜 `.rdata` 魔数 `\"MHY\\0\"` | 表头魔数 |")
    lines.append("| `addresses.T0/T1` | 反编译 `GIMeta_RuntimeInit` 的全局赋值 | `*(T1+0x48)` type 字节 100% 合法 |")
    lines.append("| `stringDecrypt.*` | 文章算法 + `gi_string_decrypt.py` | 程序集名 75/75 |")
    lines.append("| `registrationFields.*` | 反编译 `*(T0+K)`/`*(T1+K)` 的用法 | 见 `UPDATE.md` §3.3 |")

    hit_cnt = sum(1 for (d, o, i) in targets if (d, o, i) in hits)
    lines.append("\n---\n")
    lines.append("**统计**：目标三元组 %d 个，在代码里找到读取点 **%d** 个，"
                 "其余 %d 个靠结构自证/公式/反解（属正常）。\n"
                 % (len(targets), hit_cnt, len(targets) - hit_cnt))

    open(out_path, 'w').write("\n".join(lines))
    print("→ %s" % out_path)
    print("目标 %d，命中 %d" % (len(targets), hit_cnt))
    return 0


if __name__ == '__main__':
    sys.exit(main())
