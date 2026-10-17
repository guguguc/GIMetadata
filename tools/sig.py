#!/usr/bin/env python3
"""
sig.py —— 结构签名工具（生成 + 扫描）

为什么不用「前 N 条指令 + 通配 imm」：
  寄存器分配 / 寻址形式 / 指令选择 / 序言 / 内联 都会变，那是最脆的锚。
本工具的做法：
  ① **跳过序言**（前 2~3 条指令是最易变的），从函数中部取 N 条
  ② 每代指令编成两种 token：
       loose : 只留 mnemonic + 操作数"种类"（寄存器位置全用 R 通配）      ← 跨版本稳，用于找候选
       strict: 额外保留**小立即数/小偏移**（< 0x1000，通常是语义常量）    ← 用于确认
       bytes : 原始字节，imm/disp/rel 位置一律 ??                        ← 快筛（可选）
  ③ 扫描时先按 loose 滑窗，再在命中处核对 strict；报告命中地址与置信度
  ④ 真正的判据仍然是语义锚点（见 tools/relocate.py / verify.py）—— 签名只负责"给候选"

用法:
    python3 tools/sig.py gen  version/7.1/gi.exe --names tools/sig_names.txt -o tools/sigs.json
    python3 tools/sig.py scan version/7.1/gi.exe --sigs tools/sigs.json
    python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json --loose-only

sig_names.txt 格式（每行）:  <十六进制VA>  <名字>   # VA 是**当前版本**的
"""
import os, re, sys, json, struct, argparse
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

M32 = (1 << 32) - 1
HERE = os.path.dirname(os.path.abspath(__file__))
SMALL = 0x1000          # |值| < SMALL 的小立即数/偏移 → strict 保留


# ---------------------------------------------------------------- PE
class PE:
    def __init__(self, path):
        D = self.D = open(path, 'rb').read()
        pe = struct.unpack_from('<I', D, 0x3C)[0]
        n = struct.unpack_from('<H', D, pe + 6)[0]
        opt = struct.unpack_from('<H', D, pe + 0x14)[0]
        so = pe + 0x18 + opt
        self.img = struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]
        self.sec = []
        for i in range(n):
            e = so + i * 40
            nm = D[e:e + 8].rstrip(b'\0').decode(errors='replace')
            vsz, va, rsz, roff = struct.unpack_from('<IIII', D, e + 8)
            self.sec.append((nm, self.img + va, vsz, roff, min(vsz, rsz)))
        self.text = None
        for nm, sva, vsz, roff, sz in self.sec:
            if nm == '.text':
                self.text = (sva, D[roff:roff + sz]); break

    def va2off(self, va):
        for nm, sva, vsz, roff, sz in self.sec:
            if sva <= va < sva + sz:
                return roff + (va - sva)
        return None


# ---------------------------------------------------------------- token
def toks_of(insn, strict):
    out = []
    for op in insn.operands:
        if op.type == X86_OP_REG:
            out.append('R')
        elif op.type == X86_OP_IMM:
            v = op.imm
            if strict and -SMALL <= v <= SMALL:
                out.append('i%s' % ('-' if v < 0 else '') + hex(abs(v))[2:])
            else:
                out.append('I')
        elif op.type == X86_OP_MEM:
            m = op.mem
            s = 'M'
            if strict and -SMALL <= m.disp <= SMALL:
                s += 'd%s' % ('-' if m.disp < 0 else '') + hex(abs(m.disp))[2:]
            else:
                s += 'd'
            if m.index:
                s += '*' if m.scale > 1 else '+'
            out.append(s)
        else:
            out.append('X')
    return insn.mnemonic + '|' + ','.join(out)


def mask_bytes(insn):
    """精确掩码：用 capstone 的 encoding 只通配 imm/disp 字节，其余固定。
    固定前缀尽量长 → 字节搜索又快又准（不再"全 .text 反汇编"）。"""
    n = insn.size
    pat = bytearray(insn.bytes)
    mask = bytearray(b'\xff' * n)
    try:
        enc = insn.encoding
        if enc.imm_size:
            for i in range(enc.imm_offset, min(n, enc.imm_offset + enc.imm_size)): mask[i] = 0
        if enc.disp_size:
            for i in range(enc.disp_offset, min(n, enc.disp_offset + enc.disp_size)): mask[i] = 0
    except Exception:
        if any(o.type == X86_OP_IMM for o in insn.operands) or \
           any(o.type == X86_OP_MEM and (o.mem.disp != 0 or o.mem.index != 0) for o in insn.operands):
            for i in range(max(1, n - 4), n): mask[i] = 0
    return pat.hex(), mask.hex()


def _interesting(t):
    """有信息量：含内存操作数 / 立即数 / call"""
    return ('M' in t) or ('I' in t) or t.startswith('call') or t.startswith('cmp')


def gen_sig(md, pe, va, name, ninstr=8, skip=0, next_=0):
    """跳过序言 + 跳过无信息量指令，再从**函数中部**取 ninstr 条"""
    off = pe.va2off(va)
    if off is None: return None
    insns = []
    for insn in md.disasm(pe.D[off:off + 1024], va):
        insns.append(insn)
        if len(insns) >= ninstr + next_ + 40: break
    if len(insns) < 4: return None
    insns_all = insns
    i = 0
    # 1) 跳序言
    while i < len(insns):
        m = insns[i].mnemonic
        ops = insns[i].operands
        is_pro = m in ('push', 'nop', 'endbr64') or \
                 (m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG) or \
                 (m in ('sub', 'add') and len(ops) == 2 and ops[1].type == X86_OP_IMM and abs(ops[1].imm) <= 0x400)
        if not is_pro: break
        i += 1
    # 2) 跳到第一个"有信息量"的指令
    while i < len(insns) and not _interesting(toks_of(insns[i], False)):
        i += 1
    if i >= len(insns): return None
    skip_bytes = sum(x.size for x in insns[:i])
    insns = insns[i:i + ninstr]
    if len(insns) < 4: return None
    loose = [toks_of(x, False) for x in insns]
    strict = [toks_of(x, True) for x in insns]
    bl = [mask_bytes(x) for x in insns]
    # 扩展参考：紧接其后的更多指令。**只用于并列时定夺**，搜索仍用上面 ninstr 条模式
    ext_loose = ext_strict = []
    if next_:
        tail = insns_all[i:i + ninstr + next_]
        if len(tail) > ninstr:
            more = tail[ninstr:]
            ext_loose = [toks_of(x, False) for x in more]
            ext_strict = [toks_of(x, True) for x in more]
    return {'name': name, 'va': '0x%X' % va, 'skip': i, 'skip_bytes': skip_bytes, 'n': len(insns),
            'loose': loose, 'strict': strict,
            'ext_loose': ext_loose, 'ext_strict': ext_strict,
            'bytes': [b[0] for b in bl], 'mask': [b[1] for b in bl],
            'pat': ''.join(b[0] for b in bl), 'pmask': ''.join(b[1] for b in bl),
            'distinct': len(set(loose)),
            'size': sum(x.size for x in insns)}


def load_names(path):
    out = []
    for line in open(path, encoding='utf-8'):
        line = line.split('#')[0].strip()
        if not line: continue
        p = line.split()
        if len(p) >= 2:
            out.append((int(p[0], 16), p[1]))
    return out


def cmd_gen(a):
    pe = PE(a.exe)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    sigs = []
    for va, name in load_names(a.names):
        # 跳板/对齐填充不能生成签名 —— 它不含函数体信息，只会匹配到别的跳板上
        # （实测 GIMeta_GetTypeInfoByIndex 就是 `jmp`+int3 跳到混淆区）
        if _is_stub(pe, md, va):
            tgt = ''
            ins = _first_insns(pe, md, va, 1)
            if ins and ins[0].mnemonic == 'jmp':
                tgt = ' (jmp %s)' % ins[0].op_str
            print("  SKIP %s (0x%X) 是跳板/填充，不是函数体%s" % (name, va, tgt))
            continue
        s = gen_sig(md, pe, va, name, a.ninstr, a.skip, a.next)
        if s:
            sigs.append(s)
            if s['distinct'] < 4: print("  ⚠ 弱签名(区分度低): %s" % name)
        else: print("  SKIP %s (0x%X) 反汇编不足" % (name, va))
    json.dump(sigs, open(a.out, 'w'), indent=1)
    print("生成 %d 条签名 -> %s" % (len(sigs), a.out))


def _longest_fixed(pb, pm):
    best = (0, 0); cur = 0
    for i, m in enumerate(pm):
        if m == 0xFF:
            cur += 1
            if cur > best[1]: best = (i - cur + 1, cur)
        else: cur = 0
    return best


def _first_insns(pe, md, va, n=3):
    off = pe.va2off(va)
    if off is None: return []
    return list(md.disasm(pe.D[off:off + 32], va))[:n]


def _is_stub(pe, md, va):
    """PLT / IAT 跳板或对齐填充 —— 不是函数体。
    踩过的坑：GIMeta_GetTypeInfoByIndex 在 7.0 上命中过 `jmp 0x146980b30` + int3 填充的跳板。"""
    ins = _first_insns(pe, md, va, 2)
    if not ins: return True
    m0 = ins[0].mnemonic
    if m0 in ('int3', 'nop', 'nopw', 'nopl', 'ud2'): return True
    if m0 == 'jmp' and len(ins) > 1 and ins[1].mnemonic in ('int3', 'nop', 'nopw', 'nopl'):
        return True
    return False


def _plausible_start(pe, va):
    """真函数起点的**前一个字节**通常是填充(int3/nop)或上一条函数的 ret"""
    off = pe.va2off(va)
    if off is None or off <= 0: return False
    return pe.D[off - 1] in (0xCC, 0x90, 0xC3)


def _call_targets(pe, md, va, maxbytes=32768):
    """函数体里所有 `call rel32` 的目标（调用图锚定的原料）。

    注意：**不能**在第一个 ret 处停 —— 大函数（如 RuntimeInit）有多个返回点，
    早停会漏掉后面几十个 call（实测：早停只能得到 59 个候选）。"""
    off = pe.va2off(va)
    if off is None: return []
    out = []
    for ins in md.disasm(pe.D[off:off + maxbytes], va):
        if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            try: out.append(int(ins.op_str, 16))
            except ValueError: pass
    return out


def _ptr_targets(pe, md, va, maxbytes=32768):
    """函数体里 `lea/mov reg,[rip+X]` 指向 .text 的目标（函数指针 / 跳板 / 局部跳转）"""
    off = pe.va2off(va)
    if off is None: return []
    tva, tbytes = pe.text
    out = []
    for ins in md.disasm(pe.D[off:off + maxbytes], va):
        if ins.mnemonic not in ('lea', 'mov'): continue
        op = ins.op_str
        if 'rip +' not in op: continue
        try:
            tgt = ins.address + ins.size + int(op.split('rip + ')[1].split(']')[0], 16)
        except ValueError:
            continue
        if tva <= tgt < tva + len(tbytes) and tgt % 4 == 0:
            out.append(tgt)
    return out


def _score_at(pe, md, va, sg):
    """在 va（当作函数头）处按 sg 的 loose/strict token 序列打分，返回 (loose, strict)"""
    off = pe.va2off(va)
    if off is None: return None
    insns = []
    for ins in md.disasm(pe.D[off:off + 160], va):
        insns.append(ins)
        if len(insns) >= sg['skip'] + sg['n'] + len(sg.get('ext_loose') or ()): break
    if len(insns) < sg['skip'] + sg['n']: return None
    seg = insns[sg['skip']:sg['skip'] + sg['n']]
    lo = [toks_of(x, False) for x in seg]
    st = [toks_of(x, True) for x in seg]
    return (sum(1 for i in range(sg['n']) if lo[i] == sg['loose'][i]),
            sum(1 for i in range(sg['n']) if st[i] == sg['strict'][i]),
            lo, st)


def _enum_func_starts(pe, tva, tbytes, limit=None):
    """字节级枚举 .text 里所有"像函数头"的位置：前一个字节是填充(int3/nop)或 ret。
    不需要反汇编，比全量 disasm 快两个数量级。"""
    out = []
    lo = tva + 1
    for k in range(1, len(tbytes)):
        if tbytes[k - 1] in (0xCC, 0x90, 0xC3):
            out.append(tva + k)
            if limit and len(out) >= limit:
                break
    return out


def deep_rescue(pe, md, sigs, unmatched, tva, tbytes, verbose=True):
    """--deep：穷举整个 .text 的函数头，对**未定下来的签名**逐个打分。

    解决"调用图到不了"的盲区：那 6 个函数既不在已定位函数的 call/指针可达集里，
    就只能全量枚举。此模式慢（分钟级），但只在收尾救援时用。"""
    if not unmatched:
        return {}
    starts = _enum_func_starts(pe, tva, tbytes)
    if verbose:
        print("\n  深度救援：枚举到 %d 个函数头（.text %.1f MB）" % (len(starts), len(tbytes) / 1e6))
    best = {}
    for sg in unmatched:
        b0 = None
        for st in starts:
            if _is_stub(pe, md, st):
                continue
            r = _score_at(pe, md, st, sg)
            if not r or r[0] < 4:
                continue
            if b0 is None or (r[0], r[1]) > (b0[0], b0[1]):
                b0 = (r[0], r[1], st)
        if b0:
            best[sg['name']] = b0
            if verbose:
                print("      %-40s 最优 %d/%d (严格 %d) @0x%X" % (sg['name'], b0[0], sg['n'], b0[1], b0[2]))
        else:
            if verbose:
                print("      %-40s -- 没有任何函数头能到 4/8" % sg['name'])
    return best


def _vtable_ptrs(pe, limit=None):
    """`.rdata` 等只读段里所有指向 .text 的 8 字节指针（函数指针表 / vtable）。
    这些是"经表间接调用"的函数的所在位置 —— 调用图扫不到的盲区。"""
    import numpy as np
    tva, tbytes = pe.text
    out = set()
    for nm, va, vsz, off, rsz in pe.sec:
        if nm == '.text':
            continue
        n = (rsz // 8) * 8
        if n < 8:
            continue
        # numpy 向量化：纯 Python 逐 8 字节 unpack_from 要循环几千万次，慢两个数量级
        arr = np.frombuffer(pe.D, dtype='<u8', count=n // 8, offset=off)
        m = (arr >= tva) & (arr < tva + len(tbytes))
        for v in arr[m]:
            if int(v) % 8 == 0:
                out.add(int(v))
        if limit and len(out) >= limit:
            break
    return sorted(out)


MAX_CANDS = 64      # 候选爆炸 -> 签名太弱（固定子串不唯一），直接判不可用


def cmd_scan(a):
    """字节模式优先：先按最长固定子串 bytes.find 找候选，只在候选处反汇编核对。秒级。

    判定规则（宁可"不可判"也不给错地址）：
      1. 候选数 > MAX_CANDS        -> 签名太弱，\u26a0 不可用
      2. 命中点是 int3/jmp 填充     -> PLT 跳板，跳过
      3. 回退到函数头后前一字节不像填充 -> \u26a0 不可判
      4. 最高分**并列** > 1         -> \u26a0 歧义（不给地址）
      5. 两条签名落到同一地址       -> \u26a0 撞址（多半有一条是错的）
    """
    import binascii, time
    t0 = time.time()
    sigs = json.load(open(a.sigs))
    pe = PE(a.exe)
    tva, tbytes = pe.text
    print("扫描 .text（%.1f MB，字节模式优先）…" % (len(tbytes) / 1e6))
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    hit = miss = amb = 0
    where = {}
    pending = []      # 歧义项（末尾按「同组相对次序」定夺）
    unmatched = []    # 没定下来的签名（--fuzzy 救援用）
    fuzzy_names = {}   # 模糊命中的名字（标记用）
    for sg in sigs:
        pb = binascii.unhexlify(sg['pat']); pm = binascii.unhexlify(sg['pmask'])
        fo, fl = _longest_fixed(pb, pm)
        if fl < 3:
            print("  %-42s \u26a0 固定子串太短(%d)" % (sg['name'], fl)); miss += 1; continue
        origin = int(sg['va'], 16)
        same_build = (tva <= origin < tva + len(tbytes))   # 扫的就是它自己那个版本？
        needle = pb[fo:fo + fl]
        cands = []; pos = 0; truncated = False
        if same_build:
            cands.append(origin)      # 同版本：记录的原地址就是标准答案，放最前优先核验
        while True:
            k = tbytes.find(needle, pos)
            if k < 0: break
            pos = k + 1
            base = k - fo
            if base < 0 or base + len(pb) > len(tbytes): continue
            if any(pm[i] and tbytes[base + i] != pb[i] for i in range(len(pb))): continue
            cands.append(tva + base)
            if len(cands) > MAX_CANDS: truncated = True; break
        if truncated:
            if not same_build:
                print("  %-42s \u26a0 候选 >%d（固定子串不唯一，签名太弱）" % (sg['name'], MAX_CANDS))
                amb += 1; continue
            print("  %-42s \u26a0 候选 >%d（签名弱），但同版本自测只看记录的原地址" % (sg['name'], MAX_CANDS))
        cands = list(dict.fromkeys(cands))      # 去重：origin 可能被插了两次
        scored = []
        for va in cands:
            if _is_stub(pe, md, va): continue
            off = pe.va2off(va); insns = []
            for ins in md.disasm(pe.D[off:off + 128], va):
                insns.append(ins)
                if len(insns) >= sg['n']: break
            if len(insns) < sg['n']: continue
            lo = [toks_of(x, False) for x in insns]; st = [toks_of(x, True) for x in insns]
            # 扩展参考打分（只用紧接其后的 token，不改变 8 条搜索模式的判据）
            xs = 0
            if sg.get('ext_loose'):
                more = []
                for ins in md.disasm(pe.D[off:off + 128], va):
                    more.append(ins)
                    if len(more) >= sg['n'] + len(sg['ext_loose']): break
                if len(more) >= sg['n']:
                    tail = more[sg['n']:]
                    tl = [toks_of(x, False) for x in tail]
                    ts = [toks_of(x, True) for x in tail]
                    xs = (sum(1 for i in range(len(tl)) if ts[i] == sg['ext_strict'][i]) * 2
                          + sum(1 for i in range(len(tl)) if tl[i] == sg['ext_loose'][i]))
            scored.append((va, sum(1 for i in range(sg['n']) if st[i] == sg['strict'][i]),
                           sum(1 for i in range(sg['n']) if lo[i] == sg['loose'][i]), xs))
        if not scored:
            miss += 1; unmatched.append(sg)
            print("  %-42s \u2717 未命中" % sg['name']); continue
        scored.sort(key=lambda x: (-x[1], -x[2], -x[3]))
        # 只接受**反汇编 token 真的对上**的候选：loose 必须全中（或接近全中）。
        # 教训：字节模式可能碰巧对上，但 token 一条不匹配（loose 0/8）—— 那是假命中。
        keep = [t for t in scored if t[2] == sg['n']]
        near = [t for t in scored if t[2] >= (sg['n'] * 3 + 2) // 4]
        if not keep:
            if not near:
                miss += 1; unmatched.append(sg)
                print("  %-42s \u2717 未命中（最佳 loose %d/%d，字节巧合而已）"
                      % (sg['name'], scored[0][2], sg['n']))
            else:
                amb += 1
                print("  %-42s \u26a0 部分匹配：loose %d/%d @0x%X（需人工确认）"
                      % (sg['name'], near[0][2], sg['n'], near[0][0] - sg.get('skip_bytes', 0)))
            continue
        scored = keep + [t for t in scored if t not in keep]
        top = (scored[0][1], scored[0][2], scored[0][3])
        tied = [t for t in scored if (t[1], t[2], t[3]) == top]
        fstart = scored[0][0] - sg.get('skip_bytes', 0)
        if len(tied) > 1:
            pick = [t for t in tied if t[0] - sg.get('skip_bytes', 0) == origin]
            if same_build and len(pick) == 1:
                # 同一版本自测：并列里正好有记录的原地址 -> 用它定夺（仍标注，不静默）
                hit += 1
                ns_, nl = pick[0][1], pick[0][2]
                tag = "严格全中" if ns_ == sg['n'] else "loose %d/%d" % (nl, sg['n'])
                print("  %-42s %-12s 函数起点 0x%-10X =原地址 \u2713（%d 个并列，按原地址定夺）"
                      % (sg['name'], tag, origin, len(tied)))
                where.setdefault(origin, []).append(sg['name'])
                continue
            pending.append((sg, sorted(t[0] - sg.get('skip_bytes', 0) for t in tied)))
            continue
        hit += 1
        va, ns_, nl, _xs = scored[0]
        same = (fstart == origin)
        tag = "严格全中" if ns_ == sg['n'] else "loose %d/%d" % (nl, sg['n'])
        flag = "" if len(scored) == 1 else "  (次优 %d/%d 扩展%d @0x%X)" % (
            scored[1][1], scored[1][2], scored[1][3], scored[1][0] - sg.get('skip_bytes', 0))
        # 起点存疑：前一字节不是填充 —— 通常是 skip_bytes 把"函数头"算到了指令中间。
        # **仍给出地址**（大概率对），但明确标注让人复核；同版本自测时原地址本身就是答案，不标。
        shaky = (not same) and (fstart % 16 != 0 or not _plausible_start(pe, fstart))
        if shaky:
            flag += "  \u26a0 起点存疑(未对齐/前字节非填充)"
        print("  %-42s %-12s 函数起点 0x%-10X %s%s" % (
            sg['name'], tag, fstart, "=原地址 ✓" if same else "(原 0x%X)" % origin, flag))
        where.setdefault(fstart, []).append(sg['name'])
    # ---- 歧义项：同组的（候选集合完全相同）按相对次序定夺 ----
    # 例：TypePredicateB/C/D 三个函数内容完全相同 -> 候选集合一样，
    #     但它们在 .text 里的**先后次序**跨版本保留，按记录次序一一对应。
    from collections import defaultdict
    groups = defaultdict(list)
    for sg, addrs in pending:
        groups[tuple(addrs)].append((sg, addrs))
    resolved = {}
    for addrs, items in groups.items():
        items.sort(key=lambda it: int(it[0]['va'], 16))
        if len(items) == len(addrs):
            for (sg, _), addr in zip(items, addrs):
                resolved[sg['name']] = addr
    for sg, addrs in pending:
        if sg['name'] in resolved:
            addr = resolved[sg['name']]
            hit += 1
            print("  %-42s %-12s 函数起点 0x%-10X (原 0x%X)  \u26a0 %d 个并列(同组，按相对次序定夺)"
                  % (sg['name'], "严格全中" if sg['n'] else "", addr, int(sg['va'], 16), len(addrs)))
            where.setdefault(addr, []).append(sg['name'])
        else:
            amb += 1
            print("  %-42s \u26a0 歧义：%d 个并列最高分 %s" % (
                sg['name'], len(addrs), ", ".join("0x%X" % x for x in addrs[:4])))
    # ---- 模糊救援（--fuzzy）：用**已定位函数的 call 目标**当候选，对未定下来的签名做 token 打分 ----
    # 依据：这些函数在新版本里**字节模式完全变了**，但它们的**调用者**是已定位的 ->
    #       从调用图取候选，比"全 .text 模糊搜"快几个数量级，且不会落到垃圾代码里。
    if getattr(a, 'fuzzy', False) and unmatched and where:
      # 迭代两轮：第 2 轮用第 1 轮新找到的函数当新锚 -> 等价于 2 跳调用图
      for rnd in (1, 2):
        if not unmatched: break
        cands = set()
        for f in list(where):
            cands.update(_call_targets(pe, md, f))
            cands.update(_ptr_targets(pe, md, f))
        if getattr(a, 'vtable', False):
            # 全量函数指针表（vtable/派发表）当候选源。
            # 实测：它**救不回**任何未命中签名（75118 个候选 vs 调用图的 722 个，结果同为 48/54），
            # 但它是「搜索空间已穷尽」的证据，所以做成 --vtable 可选（+12s），不进默认路径。
            cands.update(_vtable_ptrs(pe))
        cands = sorted(c for c in cands
                       if tva <= c < tva + len(tbytes) and c % 4 == 0 and not _is_stub(pe, md, c))
        print("\n  模糊救援 第%d轮：调用图候选 %d 个（锚点 %d 个已定位函数）" % (rnd, len(cands), len(where)))
        still = []
        # 每个候选**只反汇编一次**，token 序列缓存下来供全部未命中签名比对
        # （否则 7.5 万候选 × 6 签名 = 45 万次重复反汇编，慢一个数量级）
        need = max((sg['skip'] + sg['n'] for sg in unmatched), default=0)
        tokcache = {}
        for c in cands:
            off = pe.va2off(c)
            if off is None: continue
            ins = []
            for x in md.disasm(pe.D[off:off + 24 + need * 8], c):
                ins.append(x)
                if len(ins) >= need: break
            tokcache[c] = (ins, [toks_of(x, False) for x in ins],
                           [toks_of(x, True) for x in ins])
        for sg in unmatched:
            sc = []
            for c, (ins, lo_all, st_all) in tokcache.items():
                k, n2 = sg['skip'], sg['n']
                if len(lo_all) < k + n2: continue
                lo, st = lo_all[k:k + n2], st_all[k:k + n2]
                s_lo = sum(1 for i in range(n2) if lo[i] == sg['loose'][i])
                if s_lo <= 0: continue
                s_st = sum(1 for i in range(n2) if st[i] == sg['strict'][i])
                sc.append((s_lo, s_st, c))
            if not sc:
                print("      %-40s -- 调用图里没有候选能对上 token" % sg['name']); still.append(sg); continue
            sc.sort(reverse=True)
            b0 = sc[0]
            margin = b0[0] - sc[1][0] if len(sc) > 1 else b0[0]
            if b0[0] >= 5 and margin >= 2:
                hit += 1; miss -= 1
                print("      %-40s 模糊命中 %d/%d (严格 %d) 0x%X  次优 %d"
                      % (sg['name'], b0[0], sg['n'], b0[1], b0[2],
                         sc[1][0] if len(sc) > 1 else 0))
                where.setdefault(b0[2], []).append(sg['name']); fuzzy_names[sg['name']] = b0[1]
            else:
                print("      %-40s -- 最优 %d/%d @0x%X（低于门槛 5 或与次优太近，不采信）"
                      % (sg['name'], b0[0], sg['n'], b0[2])); still.append(sg)
        unmatched = still

    if getattr(a, 'deep', False) and unmatched:
        best = deep_rescue(pe, md, sigs, unmatched, tva, tbytes)
        still = []
        for sg in unmatched:
            b0 = best.get(sg['name'])
            if b0 and b0[0] >= 6:
                hit += 1; miss -= 1
                print("      -> 采信 %s @0x%X (%d/%d, 严格 %d)" % (sg['name'], b0[2], b0[0], sg['n'], b0[1]))
                where.setdefault(b0[2], []).append(sg['name']); fuzzy_names[sg['name']] = b0[1]
            else:
                still.append(sg)
        unmatched = still

    # ---- 置信度分档（回答「命中的是不是对的」）----
    #   loose 8/8  = 8 条指令的 **指令形状**（助记符+操作数种类）全对
    #   strict    = 其中「助记符+操作数种类+小立即数」也全对的条数
    #   loose token 不看立即数，所以「常量改了但结构没改」仍然 loose 8/8 —— 这是我们要的
    conf = {'严格 8/8': 0, '严格 6-7/8': 0, '严格 <6/8': 0}
    ref = {sg2['name']: int(sg2['va'], 16) for sg2 in sigs}
    addr_of = {}
    for va, names in where.items():
        for nm in names: addr_of[nm] = va
    for nm, va in addr_of.items():
        if nm in fuzzy_names:
            fuzzy_names[nm] = None      # 稍后统一算
    for nm, va in addr_of.items():
        st = None
        for sg2 in sigs:
            if sg2['name'] == nm:
                r = _score_at(pe, md, va, sg2); st = r[1] if r else None
        if st is None: continue
        conf['严格 8/8' if st >= 8 else ('严格 6-7/8' if st >= 6 else '严格 <6/8')] += 1
    print("\n  置信度：严格 8/8 = %d 个, 严格 6-7/8 = %d 个, 严格 <6/8 = %d 个"
          % (conf['严格 8/8'], conf['严格 6-7/8'], conf['严格 <6/8']))
    # 相对次序：把命中按新地址排序，与 sigs.json 记录的次序比，反转的对数
    pairs = inv = 0
    items = sorted(((v, ref[n], n) for n, v in addr_of.items() if n in ref))
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            pairs += 1
            if (items[i][0] - items[j][0]) * (items[i][1] - items[j][1]) < 0: inv += 1
    print("  相对次序校验：%d 对中 %d 对反转（反转会让人工复核，但不等于错）" % (pairs, inv))

    for va, names in where.items():
        if len(names) > 1:
            print("  \u26a0 0x%X 被 %d 条签名同时认领: %s  —— 多半有一条是错的"
                  % (va, len(names), ", ".join(names)))
    if getattr(a, 'json', None):
        json.dump({'hits': addr_of,
                   'ref': {sg2['name']: sg2['va'] for sg2 in sigs},
                   'stats': {'hit': hit, 'undecidable': amb, 'miss': miss}},
                  open(a.json, 'w'), indent=1)
        print("命中表已写 %s" % a.json)
    print("\n命中 %d / %d（不可判 %d，未命中 %d），耗时 %.1fs" % (hit, len(sigs), amb, miss, time.time() - t0))
    return 0 if miss == 0 else 1


BUILTIN = {
    0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x27D4EB2F165667C9,
    0x9E3779B97F4A7C15, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9,
    0x1555555555555555, 0x3333333333333333,
    0x0F0F0F0F0F0F0F0F, 0x1010101010101010,
    0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00,
    0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0,
    # SWAR 字节掩码（编译器做字节并行运算用）—— 跨版本不变，必须排除
    0x0101010101010101, 0xC000000000000000, 0xBFFFFFFFFFFFFFFE, 0x8000000000000001,
    0xFFFFFFFF00000000, 0x00000000FFFFFFFF, 0x8080808080808080, 0x7F7F7F7F7F7F7F7F,
}


def extract(pe, md, va, maxbytes=0x2000):
    """返回 [(值, 指令地址)]，只含 **非内置** 的 64 位立即数（按出现顺序）"""
    off = pe.va2off(va)
    if off is None:
        return None
    out = []
    shifts = []
    tva, tbytes = pe.text
    lo, hi = tva, tva + len(tbytes)
    for ins in md.disasm(pe.D[off:off + maxbytes], va):
        for op in ins.operands:
            if op.type != X86_OP_IMM:
                continue
            v = op.imm & 0xFFFFFFFFFFFFFFFF
            # 只有 movabs 才是「真 64 位立即数」；其余是移位量/栈大小/跳转目标 -> 噪声
            if ins.mnemonic != 'movabs':
                if ins.mnemonic in ('rol', 'ror', 'shl', 'shr', 'sar') and 0 < v < 64:
                    shifts.append((int(v), ins.address, ins.mnemonic))
                continue
            if v in BUILTIN or v in (0, 1):
                continue
            if lo <= v < hi:            # 其实是代码/数据地址，不是密钥
                continue
            out.append((v, ins.address, ins.mnemonic))
    out.sort(key=lambda x: x[1])
    return out, shifts



def label_string_consts(consts):
    """按**结构模式**标注字符串解密的 4 个 64 位密钥（不含 32 位的 entryXor）。

    模式（7.0/7.1 实测完全一致，因此可用于任意版本）：
      · 紧跟在 `rol 23 / shr 33 / shr 29 / shr 32` 那个 xorshift 块之后的
        **3 个连续 movabs**  = (keyMulB, keySeed, keyMulA)
      · 稍后出现的**同一个值重复 3 次**的 movabs = keyStep（每 8 字节递增一次）
    这样标注依赖的是**算法结构**而不是某版本的观测值。
    """
    from collections import Counter
    cnt = Counter(v for v, _, _ in consts)
    # 重复 3 次的那个 = keyStep
    step = None
    for v, c in cnt.items():
        if c >= 3:
            step = v
            break
    # 排除内置后，按地址最靠前的 3 个连续 movabs = (keyMulB, keySeed, keyMulA)
    # （7.0/7.1 实测：它们就是解密核心，紧跟在 xorshift 块之后）
    trio = None
    for i in range(len(consts) - 2):
        a1, a2, a3 = consts[i], consts[i + 1], consts[i + 2]
        if a2[1] - a1[1] < 0x40 and a3[1] - a2[1] < 0x40:
            trio = [a1[0], a2[0], a3[0]]
            break
    out = {}
    if trio:
        out['keyMulB'], out['keySeed'], out['keyMulA'] = trio
    if step is not None:
        out['keyStep'] = step
    return out



WIN = 4096          # verify: 函数体取多少字节


def body(pe, md, va, nbytes=WIN):
    off = pe.va2off(va)
    if off is None:
        return []
    return list(md.disasm(pe.D[off:off + nbytes], va))


def rip_targets(pe, md, va):
    """函数体里所有 rip 相对内存操作数解出来的 VA"""
    out = []
    for ins in body(pe, md, va):
        for op in ins.operands:
            if op.type != X86_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 or m.index != 0:
                continue
            # capstone: rip 相对时 base == X86_REG_RIP，我们直接用 disp 还原
            base_name = ins.reg_name(m.base) if m.base else ''
            if base_name == 'rip':
                out.append(ins.address + ins.size + m.disp)
    return out


def read_cstr(pe, va, maxn=200):
    off = pe.va2off(va)
    if off is None:
        return None
    blob = pe.D[off:off + maxn]
    i = blob.find(b'\0')
    if i <= 0:
        return None
    s = blob[:i]
    if len(s) < 4 or not all(32 <= b < 127 or b in (9, 10, 13) for b in s):
        return None
    try:
        return s.decode('ascii')
    except UnicodeDecodeError:
        return None


def strings_of(pe, md, va):
    """函数引用到的可打印字符串集合"""
    out = set()
    for t in rip_targets(pe, md, va):
        # 字符串在 .rdata 里；多试几个偏移（有时偏移 8/16 才是串头）
        for delta in (0, 8, 16, -8, 24):
            s = read_cstr(pe, t + delta)
            if s and len(s) >= 6:
                out.add(s)
    return out


def imms_of(pe, md, va):
    out = set()
    for ins in body(pe, md, va):
        for op in ins.operands:
            if op.type == 2:      # IMM
                v = op.imm
                if 2 <= abs(v) <= 0x7FFFFF:
                    out.add(v)
    return out


def callees_of(pe, md, va, nbytes=1024):
    out = set()
    for ins in body(pe, md, va, nbytes):
        if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            try:
                out.add(int(ins.op_str, 16))
            except ValueError:
                pass
    return out


def _seq(pe, md, va, n=60, strict=False):
    """取函数前 n 条的「助记符序列」和「完整 token 序列」"""
    off = pe.va2off(va)
    if off is None:
        return [], []
    ins = []
    for x in md.disasm(pe.D[off:off + 8 * n + 64], va):
        ins.append(x)
        if len(ins) >= n:
            break
    m = [x.mnemonic for x in ins]
    t = [toks_of(x, strict) for x in ins]
    return m, t


def similarity(pe_r, md, rva, pe_n, md2, nva, n=60):
    """两版函数的指令序列相似度（助记符 / 完整 token），独立于签名的第三方证据"""
    from difflib import SequenceMatcher
    mr, tr = _seq(pe_r, md, rva, n)
    mn, tn = _seq(pe_n, md2, nva, n)
    if not mr or not mn:
        return 0.0, 0.0
    return (SequenceMatcher(None, mr, mn).ratio(),
            SequenceMatcher(None, tr, tn).ratio())



def cmd_consts(a):
    # 参数由 main() 的子命令解析器提供（exe/--func/--bytes/--json/--role）

    pe = PE(a.exe)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    va = int(a.func, 16)
    got = extract(pe, md, va, a.bytes)
    if got is None:
        print('VA 0x%X 不在文件映射内' % va)
        return 1
    consts, shifts = got
    print('=== 函数 0x%X 的 64 位常量（movabs，排除内置 xxHash/位技巧常数与地址）===' % va)
    for v, at, m in consts:
        print('  0x%016X  @0x%-10X %s' % (v, at, m))
    print('共 %d 个' % len(consts))
    print('\n=== 循环移位/移位量（算法的一部分，跨版本通常不变）===')
    print('  ' + '  '.join('%s %d @0x%X' % (m, v, at) for v, at, m in shifts))
    if consts:
        print('\n=== 按结构模式自动标注 ===')
        lab = label_string_consts(consts)
        if not lab:
            print('  (模式不匹配 —— 可能是别的函数，或该版本的编译器换了写法)')
        for k, v in lab.items():
            print('  %-10s = 0x%016X' % (k, v))
        if a.role:
            print('\n=== 可直接写入 version.json 的片段 ===')
            import json as _j
            print(_j.dumps({'stringDecrypt_' + k: '0x%X' % v for k, v in lab.items()},
                           ensure_ascii=False, indent=2))
    if a.json:
        import json
        json.dump({'consts': [{'value': '0x%X' % v, 'va': '0x%X' % at} for v, at, _ in consts],
                   'shifts': [{'amount': v, 'va': '0x%X' % at, 'op': m} for v, at, m in shifts]},
                  open(a.json, 'w'), indent=1)
        print('已写 %s' % a.json)
    return 0



def cmd_verify(a):
    # 参数由 main() 的子命令解析器提供（--ref/--new/--hits/--show）

    d = json.load(open(a.hits))
    hits, ref = d['hits'], {k: int(v, 16) for k, v in d['ref'].items()}
    pe_r, pe_n = PE(a.ref), PE(a.new)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    rows = []
    for nm in sorted(hits):
        rva, nva = ref.get(nm), hits[nm]
        if rva is None:
            continue
        sr, sn = strings_of(pe_r, md, rva), strings_of(pe_n, md, nva)
        ir, inn = imms_of(pe_r, md, rva), imms_of(pe_n, md, nva)
        cr, cn = len(callees_of(pe_r, md, rva)), len(callees_of(pe_n, md, nva))
        common_s = sr & sn
        only_r = sr - sn
        # 判据：有共同字符串 -> 强证据；只有共同立即数 -> 中等；都没有 -> 弱
        if common_s and not only_r:
            verdict = '✅ 字符串完全一致(%d 条)' % len(common_s)
        elif common_s:
            verdict = '🟡 字符串有重合 %d/%d（少了 %d 条）' % (len(common_s), len(sr), len(only_r))
        elif ir & inn:
            verdict = '🟡 无字符串，但共同立即数 %d 个' % len(ir & inn)
        else:
            verdict = '⚠ 无字符串也无共同立即数（弱证据）'
        sm, st = similarity(pe_r, md, rva, pe_n, md, nva)
        rows.append((nm, rva, nva, len(sr), len(common_s), len(only_r),
                     len(ir & inn), cr, cn, verdict, sorted(common_s)[:2], sm, st))

    print("=== 反汇编级验证：%d 个命中 ===" % len(rows))
    print("%-40s %-9s %-9s %-13s %-8s %-13s %s"
          % ("函数", "7.1", "7.0", "共同字符串", "共同立即数", "指令序列相似", "判定"))
    for nm, rva, nva, ns, nc, no, ni, ccm, cn2, v, cs, sm, st in rows:
        print("%-40s 0x%-7X 0x%-7X %-13s %-8d %5.0f%%/%3.0f%%  %s"
              % (nm, rva, nva, "%d/%d" % (nc, ns), ni, sm * 100, st * 100, v))

    strong = sum(1 for r in rows if r[9].startswith('✅'))
    hi = sum(1 for r in rows if r[12] >= 0.60)
    print("指令序列相似度 >=60%%(助记符)的: %d / %d 个" % (hi, len(rows)))
    lo_list = [(r[0], r[11], r[12]) for r in rows if r[12] < 0.50]
    if lo_list:
        print("相似度 <50%% 的(需重点复核):")
        for nm, sm, st in sorted(lo_list, key=lambda x: x[1]):
            print("   %-40s 助记符 %.0f%%  token %.0f%%" % (nm, sm * 100, st * 100))
    mid = sum(1 for r in rows if r[9].startswith('🟡'))
    weak = sum(1 for r in rows if r[9].startswith('⚠'))
    print("\n汇总: 强证据 %d, 中等 %d, 弱 %d / 共 %d" % (strong, mid, weak, len(rows)))

    for nm, rva, nva, ns, nc, no, ni, ccm, cn2, v, cs, sm, st in rows[:a.show]:
        print("\n---- %s  7.1@0x%X  vs  7.0@0x%X ----" % (nm, rva, nva))
        lr = [(i.mnemonic, i.op_str) for i in body(pe_r, md, rva)][:14]
        ln = [(i.mnemonic, i.op_str) for i in body(pe_n, md, nva)][:14]
        for i in range(max(len(lr), len(ln))):
            x = "%-30s" % (' '.join(lr[i]) if i < len(lr) else '')
            y = "%-30s" % (' '.join(ln[i]) if i < len(ln) else '')
            print("   %-30s | %s" % (x, y))
    return 0




def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('gen');  g.add_argument('exe'); g.add_argument('--names', default=os.path.join(HERE, 'sig_names.txt'))
    g.add_argument('-o', '--out', default=os.path.join(HERE, 'sigs.json'))
    g.add_argument('--ninstr', type=int, default=8); g.add_argument('--skip', type=int, default=2)
    g.add_argument('--next', type=int, default=10, help='额外存的参考 token 条数（仅并列时定夺用）')
    g.set_defaults(fn=cmd_gen)
    s = sub.add_parser('scan'); s.add_argument('exe'); s.add_argument('--sigs', default=os.path.join(HERE, 'sigs.json'))
    s.add_argument('--fuzzy', action='store_true', help='未命中的签名走「调用图 + token 打分」救援')
    s.add_argument('--json', default=None, help='把命中表 name -> 新地址 写成 JSON（给 sig_verify.py 用）')
    s.add_argument('--deep', action='store_true', help='深度救援：穷举整个 .text 的函数头（分钟级，收尾用）')
    s.add_argument('--vtable', action='store_true', help='把 .rdata 里全部函数指针(vtable)当候选源（+12s，用于证明搜索空间已穷尽）')
    s.add_argument('--loose-only', action='store_true'); s.set_defaults(fn=cmd_scan)

    c = sub.add_parser('consts', help='从 sig 定位的函数里通用抽取 64 位常量（如字符串解密密钥）')
    c.add_argument('exe'); c.add_argument('--func', required=True, help='函数起始 VA（来自 scan）')
    c.add_argument('--bytes', type=lambda x: int(x, 0), default=0x2000)
    c.add_argument('--role', default=None); c.add_argument('--json', default=None)
    c.set_defaults(fn=cmd_consts)

    v = sub.add_parser('verify', help='反汇编级验证 scan 的命中对不对')
    v.add_argument('--ref', required=True); v.add_argument('--new', required=True)
    v.add_argument('--hits', required=True); v.add_argument('--show', type=int, default=0)
    v.set_defaults(fn=cmd_verify)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == '__main__':
    main()
