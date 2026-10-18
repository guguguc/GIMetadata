#!/usr/bin/env python3
"""
semantic_ab.py —— 自动裁决 version.json 里的「语义 A/B」。

IDA 给出候选字段/常数，但下面三件事靠反编译变量名会选反；这里用数据自证：
  1. method flags / iflags 谁在 +18 / +22（access 分布）
  2. property getter / setter 谁在 +4 / +6 / +8（get_/set_ 方法名）
  3. T0+0x48 / T0+0x88 谁是方法体数组（合法 RVA 唯一性）

用法:
    python3 tools/semantic_ab.py version/7.0
    python3 tools/semantic_ab.py version/7.1
"""
import os, sys, struct, argparse
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from sig import PE
from gen_version import load_json_with_comments

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1


def load_version(root):
    jp = os.path.join(root, 'version.json')
    if not os.path.exists(jp):
        jp = os.path.join(ROOT, 'version.json')       # 7.1 用根 JSON
    return load_json_with_comments(jp), jp


def key_any(f, i):
    """兼容两种公式形状：7.0 (C/D/inner/outer) 与 7.1 (A/xor/add)。"""
    if 'C' in f:
        x = (int(str(f['C']), 0) * i + int(str(f['D']), 0)) & M64
        x = (f['innerMul'] * (x >> f['shift1'])) & M64
        x >>= f['shift2']
        x = (f['outerMul'] * x) & M64
        return (x & M32) ^ int(str(f.get('xor', '0')), 0)
    if 'A' in f and 'add' in f:
        return (((int(str(f['A']), 0) * i) ^ int(str(f.get('xor', '0')), 0)) + int(str(f['add']), 0)) & M32
    if 'A' in f:
        return (((int(str(f['A']), 0) * ((int(str(f.get('B', 0)), 0) * i) >> f.get('shift', 0))) & M64)
                ^ int(str(f.get('xor', '0')), 0)) & M32
    return 0


def derive(raw, spec, key):
    op, _, k = spec.partition(':')
    k = int(k, 0)
    if op == 'xor': return (key ^ raw ^ k) & M32
    if op == 'sub': return (key ^ ((raw - k) & M32)) & M32
    if op == 'add': return (key ^ ((raw + k) & M32)) & M32
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    a = ap.parse_args()
    root = a.root.rstrip('/')
    J, jp = load_version(root)
    exe = PE(os.path.join(root, 'gi.exe'))
    d = open(os.path.join(root, 'gi', 'Managed', 'Metadata', 'global-metadata.dat'), 'rb').read()[0x210:]
    AD = J['addresses']
    MHY = int(str(AD['mhyTableVA']), 0)

    def u16(o): return int.from_bytes(d[o:o+2], 'little')
    def u32(o): return int.from_bytes(d[o:o+4], 'little')

    def tval(name):
        t = J['tables'][name]
        v = struct.unpack_from('<I', exe.D, exe.va2off(MHY + int(t['slot'], 0)))[0]
        k = int(str(t['key']), 0)
        return (v ^ k) if t['op'] == '^' else ((v-k) & M32) if t['op'] == '-' else ((v+k) & M32)

    def tcount(name):
        t = J['tables'][name]
        return tval(name) // t.get('stride', 1)

    methods = tval('methodsOffset'); nm = tval('methodsCount') // 26
    tds = tval('typeDefinitionsOffset'); ntd = tval('typeDefinitionsCount') // 70
    print('== %s (%s) methods=0x%X n=%d typeDefs=%d' % (root, jp, methods, nm, ntd))

    # ---------------- 1) method flags / iflags ----------------
    so = J['structOffsets']['Il2CppMethodDefinition']
    fspec = J['fieldDecode']['method']['flags']
    ispec = J['fieldDecode']['method']['iflags']
    kfs = {'method': J['keyFormulas']['methodKey']}
    if 'methodParamKey' in J['keyFormulas']:
        kfs['methodParam'] = J['keyFormulas']['methodParamKey']
    N = min(nm, 50000)
    best_flags = []
    for kname, kf in kfs.items():
        for fo, io, swap in ((so['flags'], so['iflags'], False),
                             (so['iflags'], so['flags'], True)):
            spec = ispec if swap else fspec
            cnt = Counter(); st = ab = vi = pi = 0
            for m in range(N):
                b = methods + 26*m
                key = key_any(kf, m)
                fl = derive(u16(b + fo), spec, key) & 0xFFFF
                cnt[fl & 7] += 1
                st += (fl >> 4) & 1; vi += (fl >> 6) & 1; ab += (fl >> 10) & 1; pi += (fl >> 13) & 1
            score = -sum(((cnt[x]/N - t)**2) for x, t in
                         ((6, .58), (1, .25), (3, .13), (4, .037))) \
                    - (st/N-.215)**2 - (vi/N-.295)**2 - (ab/N-.03)**2 - (pi/N-.0036)**2
            print('  flags off=%2d key=%-11s swap=%-5s 6/1/3/4=%d/%d/%d/%d static=%.1f%% virtual=%.1f%% abstract=%.1f%% score=%.4f'
                  % (fo, kname, swap, cnt[6], cnt[1], cnt[3], cnt[4], 100*st/N, 100*vi/N, 100*ab/N, score))
            best_flags.append((score, fo, kname, swap))

    # ---------------- 2) property get / set ----------------
    props = tval('propertiesOffset')
    # 字符串
    sd = J['stringDecrypt']; KA=int(str(sd['keyMulA']),0); KB=int(str(sd['keyMulB']),0)
    KS=int(str(sd['keySeed']),0); KP=int(str(sd['keyStep']),0)
    STR = tval('stringLiteralDataOffset')
    cpp = J.get('decodeExpr', {}).get('decStringKey', {}).get('cpp', '')
    modeA = ('+ kKeySeed' in cpp or '+ (uint64_t)kKeySeed' in cpp)
    def ds(idx):
        off, ln = idx & 0xFFFFFF, idx >> 24
        if ln <= 0 or ln > 64: return ''
        k = ((KB*off + KS) & M64) ^ KA if modeA else (KA * ((KB*off) ^ KS)) & M64
        out = bytearray()
        for i in range((ln+7)//8):
            out += (int.from_bytes(d[STR+off+8*i:STR+off+8*i+8], 'little') ^ k).to_bytes(8, 'little')
            k = (k + KP) & M64
        return bytes(out[:ln]).decode(errors='replace')
    kmf = J['keyFormulas']['methodKey']
    name_spec = J['fieldDecode']['method']['nameIndex']
    def mname(m):
        raw = u32(methods + 26*m)
        entry = dec_spec(raw, name_spec)
        return ds((entry ^ key_any(kmf, m)) & M32)

    so_td = J['structOffsets']['Il2CppTypeDefinition']
    ms_spec = J['fieldDecode']['typeDef']['methodStart']; mc_spec = J['fieldDecode']['typeDef']['method_count']
    ps_spec = J['fieldDecode']['typeDef']['propertyStart']; pc_spec = J['fieldDecode']['typeDef']['property_count']
    ms_off, mc_off = so_td['methodStart'], so_td['method_count']
    ps_off, pc_off = so_td['propertyStart'], so_td['property_count']

    def dec_spec(raw, spec):
        op, _, k = spec.partition(':'); k = int(k, 0)
        if op == 'xor': return (raw ^ k) & M32
        if op == 'sub': return (raw - k) & M32
        if op == 'add': return (raw + k) & M32
        return raw
    get_spec = J['fieldDecode']['property']['get']; set_spec = J['fieldDecode']['property']['set']
    key_pf = J['keyFormulas']['propertyKey']

    def variants(raw, spec, key):
        k = int(str(spec.split(':')[1]), 0)
        return {
            'xor-sub': ((raw ^ k) - key) & 0xFFFF,
            'xor-key': (key ^ raw ^ k) & 0xFFFF,
            'subxor':  (((raw - k) & M32) ^ key) & 0xFFFF,
            'subadd':  ((raw - key) + k) & 0xFFFF,
            'sub':     (raw - key) & 0xFFFF,
        }

    gscore = Counter(); sscore = Counter(); samples = 0
    for t in range(min(ntd, 20000)):
        b = tds + 70*t
        ms = dec_spec(u32(b+ms_off), ms_spec)
        mc = dec_spec(u16(b+mc_off), mc_spec) & 0xFFFF
        ps = dec_spec(u32(b+ps_off), ps_spec)
        pc = dec_spec(d[b+pc_off], pc_spec) & 0xFF
        if mc == 0 or mc > 4096 or pc == 0 or pc > 64: continue
        for i in range(ps, ps+pc):
            if i >= 1_000_000: continue
            key = key_any(key_pf, i)
            r4 = u16(props + 10*i + 4); r6 = u16(props + 10*i + 6); r8 = u16(props + 10*i + 8)
            for off, raw in ((4, r4), (6, r6), (8, r8)):
                for tag, g in variants(raw, get_spec, key).items():
                    if 0 <= g < mc and mname(ms+g).startswith('get_'):
                        gscore[(off, tag)] += 1
                for tag, s in variants(raw, set_spec, key).items():
                    if 0 <= s < mc and mname(ms+s).startswith('set_'):
                        sscore[(off, tag)] += 1
            samples += 1
    print('  property samples=%d' % samples)
    print('  get  top:', gscore.most_common(5))
    print('  set  top:', sscore.most_common(5))

    # ---------------- 3) T0 method body array ----------------
    T0 = int(str(AD['table0VA']), 0)
    best_t0 = []
    for off in (0x48, 0x88):
        arr = struct.unpack_from('<Q', exe.D, exe.va2off(T0 + off))[0]
        ok = 0; vals = []
        for m in range(min(nm, 50000)):
            p = struct.unpack_from('<Q', exe.D, exe.va2off(arr + 8*m))[0]
            if p <= 1: continue
            for nm_, sva, vsz, roff, sz in exe.sec:
                if sva <= p < sva + sz:
                    if nm_ in ('.text', 'il2cpp'):
                        ok += 1; vals.append(p)
                    break
        print('  T0+0x%02X array=0x%X valid=%d/%d distinct=%d' % (off, arr, ok, min(nm,50000), len(set(vals))))
        best_t0.append((len(set(vals)), off))
    print('== 推荐 ==')
    if best_flags:
        b = max(best_flags)
        print('  flags: off=%d key=%s swap=%s' % (b[1], b[2], b[3]))
    if gscore: print('  property get: off=%d formula=%s (%d)' % (*gscore.most_common(1)[0][0], gscore.most_common(1)[0][1]))
    if sscore: print('  property set: off=%d formula=%s (%d)' % (*sscore.most_common(1)[0][0], sscore.most_common(1)[0][1]))
    if best_t0: print('  T0 method bodies: 0x%02X' % max(best_t0)[1])


if __name__ == '__main__':
    main()
