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


def gen_sig(md, pe, va, name, ninstr=8, skip=0):
    """跳过序言 + 跳过无信息量指令，再从**函数中部**取 ninstr 条"""
    off = pe.va2off(va)
    if off is None: return None
    insns = []
    for insn in md.disasm(pe.D[off:off + 512], va):
        insns.append(insn)
        if len(insns) >= ninstr + 40: break
    if len(insns) < 4: return None
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
    return {'name': name, 'va': '0x%X' % va, 'skip': i, 'skip_bytes': skip_bytes, 'n': len(insns),
            'loose': loose, 'strict': strict,
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
        s = gen_sig(md, pe, va, name, a.ninstr, a.skip)
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


def cmd_scan(a):
    """字节模式优先：先按最长固定子串 bytes.find 找候选，只在候选处反汇编核对。秒级。"""
    import binascii, time
    t0 = time.time()
    sigs = json.load(open(a.sigs))
    pe = PE(a.exe)
    tva, tbytes = pe.text
    print("扫描 .text（%.1f MB，字节模式优先）…" % (len(tbytes) / 1e6))
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    hit = miss = 0
    for sg in sigs:
        pb = binascii.unhexlify(sg['pat']); pm = binascii.unhexlify(sg['pmask'])
        fo, fl = _longest_fixed(pb, pm)
        if fl < 3:
            print("  %-42s \u26a0 固定子串太短(%d)" % (sg['name'], fl)); miss += 1; continue
        needle = pb[fo:fo + fl]
        cands = []; pos = 0; total = 0
        while True:
            k = tbytes.find(needle, pos)
            if k < 0: break
            pos = k + 1; total += 1
            base = k - fo
            if base < 0 or base + len(pb) > len(tbytes): continue
            ok = True
            for i in range(len(pb)):
                if pm[i] and tbytes[base + i] != pb[i]: ok = False; break
            if ok: cands.append(tva + base)
            if len(cands) > 200: break
        good = []
        for va in cands:
            off = pe.va2off(va); insns = []
            for ins in md.disasm(pe.D[off:off + 128], va):
                insns.append(ins)
                if len(insns) >= sg['n']: break
            if len(insns) < sg['n']: continue
            lo = [toks_of(x, False) for x in insns]; st = [toks_of(x, True) for x in insns]
            good.append((va, sum(1 for i in range(sg['n']) if st[i] == sg['strict'][i]),
                         sum(1 for i in range(sg['n']) if lo[i] == sg['loose'][i])))
        if good:
            good.sort(key=lambda x: (-x[1], -x[2])); hit += 1
            va, ns_, nl = good[0]
            fstart = va - sg.get('skip_bytes', 0)
            same = (fstart == int(sg['va'], 16))
            print("  %-42s %-12s 函数起点 0x%-10X %s%s" % (sg['name'], "严格全中" if ns_ == sg['n'] else "loose %d/%d" % (nl, sg['n']),
                  fstart, "=原地址 ✓" if same else "(原 0x%X)" % int(sg['va'], 16),
                  "" if len(good) == 1 else "  (+%d 候选)" % (len(good) - 1)))
        else:
            miss += 1; print("  %-42s \u2717 未命中" % sg['name'])
    print("\n命中 %d / %d，耗时 %.1fs" % (hit, len(sigs), time.time() - t0))
    return 0 if miss == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('gen');  g.add_argument('exe'); g.add_argument('--names', default=os.path.join(HERE, 'sig_names.txt'))
    g.add_argument('-o', '--out', default=os.path.join(HERE, 'sigs.json'))
    g.add_argument('--ninstr', type=int, default=8); g.add_argument('--skip', type=int, default=2)
    g.set_defaults(fn=cmd_gen)
    s = sub.add_parser('scan'); s.add_argument('exe'); s.add_argument('--sigs', default=os.path.join(HERE, 'sigs.json'))
    s.add_argument('--loose-only', action='store_true'); s.set_defaults(fn=cmd_scan)
    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == '__main__':
    main()
