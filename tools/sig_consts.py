#!/usr/bin/env python3
"""从 sig 定位到的函数里**通用地**抽取 64 位常量。

动机：slot_scan 抽的是「MHY 槽位 + 密钥」三元组；这里抽的是**函数体内的立即数常量**
      （比如字符串解密的 5 个密钥），用于**跨版本**自动迁移。

关键点（实测得出，非硬编码）：
  * 版本相关的密钥会以 `movabs reg, imm64` 形式出现在函数体内；
  * 但同一函数里还有一批**编译器/库的内置常数**（xxHash64 素数、位技巧掩码），
    它们**跨版本完全相同** —— 必须排除，否则会把它们当成版本密钥。
  * 排除依据是一组**结构化、可识别的固定常数**（不是某版本的观测值），
    所以对任意版本都成立。

用法:
    python3 tools/sig_consts.py <gi.exe> --func <VA> [--bytes 0x2000] [--show]
    # VA 由 tools/sig.py scan 得到，例如 GIMeta_DecryptString
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import CS_ARCH_X86, CS_MODE_64, Cs          # noqa: E402
from capstone.x86 import X86_OP_IMM                       # noqa: E402

from sig import PE                                        # noqa: E402

# 编译器/库的内置常数：xxHash64 素数 + 位技巧掩码。跨版本不变，必须排除。
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exe')
    ap.add_argument('--func', required=True, help='函数起始 VA（来自 sig.py scan）')
    ap.add_argument('--bytes', type=lambda x: int(x, 0), default=0x2000)
    ap.add_argument('--json', default=None)
    ap.add_argument('--role', default=None, help='函数角色标记（如 stringdecrypt），用于输出可粘贴片段')
    a = ap.parse_args()

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


if __name__ == '__main__':
    sys.exit(main())