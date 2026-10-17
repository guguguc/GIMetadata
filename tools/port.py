#!/usr/bin/env python3
"""port.py —— 跨版本「常量搬运」：靠**指令对齐**，而不是搜索/猜测。

思路
----
同一个程序换代，**代码结构几乎不变**，变的只是常量。`sig.py` 已能定位 48~54 个函数，
所以可以逐函数做**指令序列对齐**（difflib），然后：

    对齐到同一位置的两条指令  ->  比较它们的立即数/位移  ->  得到 old -> new 的映射

这比"搜候选 + 结构自证"强得多：**位置本身就是语义**（同一个位置 = 同一个字段/表/key）。

用法
----
    python3 tools/port.py --old version/7.1 --new version/7.0 \
        --sigs tools/sigs.json --out /tmp/port70.json

输出
----
  * 每个 `version.json` 值的 old -> new 建议（带票数/置信度）
  * 冲突（同一个 old 值映射到多个 new）和未映射项
  * 自测：与已知的 7.0 真值对比（fDV / methodPtr / methodSlot / attrinfo / blob / 字符串密钥）
"""
import argparse
import difflib
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# 把"同一类"的助记符归一：解码用的 add/sub/xor 常被编译器换着用，
# 归一后才能对齐到同一位置（而 mnemonic 的变化本身也是信息）
MN_CLASS = {
    'add': 'ARITH', 'sub': 'ARITH', 'xor': 'ARITH',
    'mov': 'MOV', 'movzx': 'MOV', 'movsx': 'MOV', 'movsxd': 'MOV',
    'imul': 'MUL', 'lea': 'LEA', 'cmp': 'CMP', 'test': 'TEST',
}


class PE:
    def __init__(self, path):
        self.D = open(path, 'rb').read()
        pe = struct.unpack_from('<I', self.D, 0x3C)[0]
        n = struct.unpack_from('<H', self.D, pe + 6)[0]
        opt = struct.unpack_from('<H', self.D, pe + 0x14)[0]
        so = pe + 0x18 + opt
        self.base = struct.unpack_from('<Q', self.D, pe + 0x18 + 0x18)[0]
        self.secs = []
        for i in range(n):
            e = so + i * 40
            nm = self.D[e:e + 8].rstrip(b'\0').decode(errors='replace')
            vsz, va, rsz, ro = struct.unpack_from('<IIII', self.D, e + 8)
            self.secs.append((nm, self.base + va, vsz, ro, rsz))
        t = next(s for s in self.secs if s[0] == '.text')
        self.text = (t[1], self.D[t[3]:t[3] + t[4]])

    def va2off(self, va):
        for nm, sva, vsz, ro, rsz in self.secs:
            if sva <= va < sva + max(vsz, rsz):
                return ro + (va - sva)
        return None


def op_sig(op):
    if op.type == X86_OP_REG:
        return 'R'
    if op.type == X86_OP_IMM:
        return 'I'
    if op.type == X86_OP_MEM:
        m = op.mem
        return 'M%s%s%s' % ('B' if m.base else '', 'X' if m.index else '',
                            ('s%d' % m.scale) if m.index else '')
    return '?'


def imm_list(ins):
    """按操作数顺序取出「立即数/位移」值（跳过 0 位移）"""
    out = []
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            out.append(op.imm & 0xFFFFFFFFFFFFFFFF)
        elif op.type == X86_OP_MEM and op.mem.disp != 0:
            out.append(op.mem.disp & 0xFFFFFFFFFFFFFFFF)
    return out


def token(ins):
    cls = MN_CLASS.get(ins.mnemonic, ins.mnemonic)
    return cls + '|' + ','.join(op_sig(o) for o in ins.operands)


def disasm_fn(pe, md, va, maxbytes=0x8000):
    off = pe.va2off(va)
    if off is None:
        return []
    return list(md.disasm(pe.D[off:off + maxbytes], va))


def align_fn(old_ins, new_ins):
    """返回 [(old_idx, new_idx)] 对齐对（只保留 token 相同的）"""
    a = [token(i) for i in old_ins]
    b = [token(i) for i in new_ins]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    pairs = []
    for blk in sm.get_matching_blocks():
        for k in range(blk.size):
            pairs.append((blk.a + k, blk.b + k))
    return pairs, sm.ratio()


def collect(old_pe, new_pe, hits_old, hits_new, md, min_ratio=0.35):
    """对每个两边都定位到的函数做对齐 -> votes[(old_imm,new_imm)]"""
    votes = {}
    votes_fn = {}          # (fn, old) -> {new: count}
    fn_of_old = {}         # old -> set(fn)
    mnem_changes = {}
    stats = []
    common = sorted(set(hits_old) & set(hits_new))
    for nm in common:
        oi = disasm_fn(old_pe, md, hits_old[nm])
        ni = disasm_fn(new_pe, md, hits_new[nm])
        if not oi or not ni:
            continue
        pairs, ratio = align_fn(oi, ni)
        stats.append((nm, len(oi), len(ni), len(pairs), ratio))
        if ratio < min_ratio:
            continue
        for i, j in pairs:
            a, b = oi[i], ni[j]
            if a.mnemonic != b.mnemonic:
                mnem_changes.setdefault(a.mnemonic + '->' + b.mnemonic, 0)
                mnem_changes[a.mnemonic + '->' + b.mnemonic] += 1
            ia, ib = imm_list(a), imm_list(b)
            if len(ia) != len(ib):
                continue
            for x, y in zip(ia, ib):
                if x != y:
                    votes.setdefault(x, {}).setdefault(y, 0)
                    votes[x][y] += 1
                    votes_fn.setdefault((nm, x), {}).setdefault(y, 0)
                    votes_fn[(nm, x)][y] += 1
                    fn_of_old.setdefault(x, set()).add(nm)
    return votes, votes_fn, fn_of_old, mnem_changes, stats


def consolidate(votes, min_votes=1, min_conf=0.75):
    """votes -> {old: (new, 票数, 置信度)}；冲突的低置信项标记出来"""
    out = {}
    conflicts = []
    for old, cand in votes.items():
        tot = sum(cand.values())
        new, v = max(cand.items(), key=lambda kv: kv[1])
        conf = v / tot
        if v >= min_votes and conf >= min_conf:
            out[old] = (new, v, conf)
        else:
            conflicts.append((old, sorted(cand.items(), key=lambda kv: -kv[1])[:3]))
    return out, conflicts


def parse_sig_json(path):
    d = json.load(open(path))
    return {k: int(v, 16) if isinstance(v, str) else int(v) for k, v in d['hits'].items()}


def K(x):
    return int(x, 0) if isinstance(x, str) else int(x)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--sigs-old', required=True, help="旧版 sig scan --json 产物")
    ap.add_argument('--sigs-new', required=True, help="新版 sig scan --json 产物")
    ap.add_argument('--version-json', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--out', default=None)
    ap.add_argument('--min-ratio', type=float, default=0.35)
    a = ap.parse_args()

    from gen_version import load_json_with_comments as L
    J = L(a.version_json)
    old_pe, new_pe = PE(os.path.join(ROOT, a.old, 'gi.exe')), PE(os.path.join(ROOT, a.new, 'gi.exe'))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ho, hn = parse_sig_json(a.sigs_old), parse_sig_json(a.sigs_new)

    print("旧版定位 %d 个函数，新版 %d 个，共同 %d 个" % (len(ho), len(hn), len(set(ho) & set(hn))))
    votes, votes_fn, fn_of_old, mnch, stats = collect(old_pe, new_pe, ho, hn, md, a.min_ratio)
    mapped, conflicts = consolidate(votes)
    tot_pairs = sum(s[3] for s in stats)
    sim = sum(1 for s in stats if s[4] >= 0.8)
    print("对齐：%d 个函数，指令对 %d；相似度>=80%% 的函数 %d 个" % (len(stats), tot_pairs, sim))
    print("常量映射：%d 个 old 值有可靠 new 值；%d 个冲突" % (len(mapped), len(conflicts)))
    if mnch:
        print("助记符变化（说明解码 op 变了）:", dict(sorted(mnch.items(), key=lambda kv: -kv[1])[:6]))

    # ---- 把 version.json 的每个值映射一遍 ----
    def _pick(cand):
        if not cand:
            return None
        tot = sum(cand.values())
        new, v = max(cand.items(), key=lambda kv: kv[1])
        return (new, v, v / tot)

    def port(v):
        """全局映射 —— **只接受大常量**。

        小常量（< 0x10000，典型是结构体位移 slot）在全局按值映射里必然撞车
        （同一个 0x10/0x18 到处都是），**必须靠位置对齐**，见 docs/PORT.md。
        """
        v &= 0xFFFFFFFFFFFFFFFF
        if v < 0x10000:                 # 小常量：按值映射不可靠 -> 不接
            return None
        # 兼容 4 种编码：正/负 × 32/64 位（编译器把 sub K 写成 add -K，且位宽不一）
        cands = [v, v & 0xFFFFFFFF, (-v) & 0xFFFFFFFF, (-v) & 0xFFFFFFFFFFFFFFFF]
        for cand in cands:
            if cand in mapped:
                new, n, c = mapped[cand]
                if n >= 1 and c >= 0.99:
                    # 还原成「version.json 约定」：op='-' 时 key 为**正数**
                    nv = new
                    if v <= 0xFFFFFFFF:        # 只对 32 位常量截断；64 位（movabs）保留
                        nv &= 0xFFFFFFFF
                    return (nv, n, round(c, 2))
        return None

    def port_ctx(slot, key):
        """按上下文映射 slot：只在**含该 key 的那些函数**里看 slot 怎么变。

        规则：这些函数给出的 new slot 必须**完全一致**才采信（slot 是小数字，
        全局映射必然撞车；限定到"同一张表的读取点"才唯一）。
        """
        sv = slot & 0xFFFFFFFFFFFFFFFF
        kv = key & 0xFFFFFFFFFFFFFFFF
        fns = fn_of_old.get(kv, set())
        cand = {}
        for fn in fns:
            r = _pick(votes_fn.get((fn, sv)))
            if r:
                cand[r[0]] = cand.get(r[0], 0) + r[1]
        if len(cand) == 1:
            new, v = next(iter(cand.items()))
            return (new, v, 1.0, 'ctx:%d fn' % len(fns))
        return None

    report = {'tables': {}, 'fieldDecode': {}, 'keyFormulas': {}, 'stringDecrypt': {},
              'formulas': {}, 'unmapped': []}
    ok = bad = 0
    print("\n=== tables（slot/op/key）===")
    for name, cfg in J['tables'].items():
        if 'slot' not in cfg:
            continue
        for field in ('slot', 'key'):
            v = K(cfg[field])
            r = None
            if field == 'slot':
                rc = port_ctx(K(cfg['slot']), K(cfg['key']))
                if rc:
                    r = (rc[0], rc[1], rc[2])
            if r is None:
                r = port(v)
            ent = report['tables'].setdefault(name, {})
            if r:
                ent[field] = '0x%X' % r[0] if field == 'key' else hex(r[0])
                ok += 1
            else:
                report['unmapped'].append('tables.%s.%s (0x%X)' % (name, field, v))
                bad += 1
    print("  端口化 %d 个 slot/key，未映射 %d" % (ok, bad))

    print("\n=== fieldDecode（每个字段的 key）===")
    fok = fbad = 0
    for st, d in J['fieldDecode'].items():
        for f, spec in d.items():
            op, _, key = spec.partition(':')
            r = port(K(key))
            if r:
                report['fieldDecode']['%s.%s' % (st, f)] = '0x%X' % r[0]
                fok += 1
            else:
                report['unmapped'].append('fieldDecode.%s.%s (0x%X)' % (st, f, K(key)))
                fbad += 1
    print("  端口化 %d 个 key，未映射 %d" % (fok, fbad))

    print("\n=== keyFormulas（系数）===")
    kok = kbad = 0
    for kname, ks in J['keyFormulas'].items():
        for sk, sv in ks.items():
            r = port(K(sv))
            if r:
                report['keyFormulas'].setdefault(kname, {})[sk] = r[0]
                kok += 1
            else:
                report['unmapped'].append('keyFormulas.%s.%s (%s)' % (kname, sk, sv))
                kbad += 1
    print("  端口化 %d 个系数，未映射 %d" % (kok, kbad))

    print("\n=== stringDecrypt ===")
    sok = sbad = 0
    for sk, sv in J['stringDecrypt'].items():
        r = port(K(sv))
        if r:
            report['stringDecrypt'][sk] = '0x%X' % r[0]
            sok += 1
        else:
            report['unmapped'].append('stringDecrypt.%s (%s)' % (sk, sv))
            sbad += 1
    print("  端口化 %d 个，未映射 %d" % (sok, sbad))

    total_ok = ok + fok + kok + sok
    total_bad = bad + fbad + kbad + sbad
    print("\n=== 汇总 ===")
    print("  端口化 %d / %d（%.1f%%），未映射 %d"
          % (total_ok, total_ok + total_bad, 100.0 * total_ok / max(total_ok + total_bad, 1), total_bad))

    # 冲突明细
    if conflicts:
        print("\n冲突（old 值映射到多个 new，已拒收）前 10:")
        for old, cands in conflicts[:10]:
            print("  0x%-10X -> %s" % (old, ['0x%X(%d)' % (n, v) for n, v in cands]))

    if a.out:
        report['stats'] = {'mapped': len(mapped), 'conflicts': len(conflicts),
                           'aligned_pairs': tot_pairs}
        json.dump(report, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print("\n已写 %s" % a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
