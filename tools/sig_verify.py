#!/usr/bin/env python3
"""sig 命中的**反汇编级**验证器 —— 回答「命中的到底对不对」。

token 分数只能说明「指令形状像」，本工具找**语义证据**：

  1) **字符串常量**：函数体里 `lea/mov reg,[rip+X]` 引用的字符串
     （比如 SetupTypeLocked 引用的 "generic types cannot have explicit layout"）
     新旧版本若引用**同一批字符串**，几乎不可能是不同函数。
  2) **立即数指纹**：窗口内出现的小立即数（>=2 的）集合
  3) **调用图指纹**：这个函数调用了哪些函数（`call rel32` 目标集合）
     —— SetupMethodsLocked / SetupPropertiesLocked 这类"家族函数"会互相靠近，
        它们的被调集合应当高度重合。

用法:
    python3 tools/sig.py scan <新版本.exe> --sigs tools/sigs.json --fuzzy --json hits.json
    python3 tools/sig_verify.py --ref version/7.1/gi.exe --new version/7.0/gi.exe --hits hits.json
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64          # noqa: E402
from capstone.x86 import X86_OP_MEM                        # noqa: E402
from sig import PE                                        # noqa: E402

WIN = 4096          # 函数体取多少字节


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', required=True, help='签名来源版本的 gi.exe')
    ap.add_argument('--new', required=True, help='被扫描版本的 gi.exe')
    ap.add_argument('--hits', required=True, help='sig.py scan --json 产出的命中表')
    ap.add_argument('--show', type=int, default=0, help='额外打印前 N 个函数的两版反汇编对照')
    a = ap.parse_args()

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
        rows.append((nm, rva, nva, len(sr), len(common_s), len(only_r),
                     len(ir & inn), cr, cn, verdict, sorted(common_s)[:2]))

    print("=== 反汇编级验证：%d 个命中 ===" % len(rows))
    print("%-40s %-9s %-9s %-14s %-8s %s" % ("函数", "7.1", "7.0", "共同字符串", "共同立即数", "1KB 内 call 数 7.1/7.0"))
    for nm, rva, nva, ns, nc, no, ni, ccm, cn2, v, cs in rows:
        print("%-40s 0x%-7X 0x%-7X %-14s %-8d %d/%-6d %s"
              % (nm, rva, nva, "%d/%d" % (nc, ns), ni, ccm, cr, v))

    strong = sum(1 for r in rows if r[9].startswith('✅'))
    mid = sum(1 for r in rows if r[9].startswith('🟡'))
    weak = sum(1 for r in rows if r[9].startswith('⚠'))
    print("\n汇总: 强证据 %d, 中等 %d, 弱 %d / 共 %d" % (strong, mid, weak, len(rows)))

    for nm, rva, nva, ns, nc, no, ni, ccm, cn2, v, cs in rows[:a.show]:
        print("\n---- %s  7.1@0x%X  vs  7.0@0x%X ----" % (nm, rva, nva))
        lr = [(i.mnemonic, i.op_str) for i in body(pe_r, md, rva)][:14]
        ln = [(i.mnemonic, i.op_str) for i in body(pe_n, md, nva)][:14]
        for i in range(max(len(lr), len(ln))):
            x = "%-30s" % (' '.join(lr[i]) if i < len(lr) else '')
            y = "%-30s" % (' '.join(ln[i]) if i < len(ln) else '')
            print("   %-30s | %s" % (x, y))
    return 0


if __name__ == '__main__':
    sys.exit(main())