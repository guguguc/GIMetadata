#!/usr/bin/env python3
"""
relocate.py v2 —— 换版本时自动重定位 version.json 的**表**常量。

设计（见 docs/UPDATE.md §8）：三层锚，各司其职，不给字节签名当判据
  ① 引导：魔数 "MHY\\0"（最稳，跨大版本也活）
  ② 指令证据：slot_scan 的 (slot, op, key) 候选       ← 常量只存在于指令里
  ③ 结构自证：数据侧不变量（12B 严格递增 / 70B flags 只有 ~106 种 /
              AttributeTargets 的 [Flags] 值签名 …）  ← 判真伪，不看"像不像"
最终由 verify.py 的 28 项兜底。

**快**：所有数据侧探测都用 numpy 向量化（v1 用 Python 循环 2.7 亿次，几十分钟；
v2 是秒级）。

用法:
    python3 tools/relocate.py version/7.1            # 自测：应能复原现有 version.json
    python3 tools/relocate.py version/7.2 --scan     # 无缓存时自动跑 slot_scan
"""
import os, re, sys, json, struct, argparse, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_version import load_json_with_comments

M32 = (1 << 32) - 1
HERE = os.path.dirname(os.path.abspath(__file__))
ROOTDIR = os.path.dirname(HERE)
ATTR_TARGETS = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32767]


# ------------------------------------------------------------------ PE
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
            self.sec.append((nm, self.img + va, vsz, roff, min(vsz, rsz), rsz))

    def va2off(self, va):
        for nm, sva, vsz, roff, sz, _ in self.sec:
            if sva <= va < sva + sz:
                return roff + (va - sva)
        return None
    def off2va(self, off):
        for nm, sva, vsz, roff, sz, _ in self.sec:
            if roff <= off < roff + sz:
                return sva + (off - roff)
        return None
    def u32(self, va):
        return struct.unpack_from('<I', self.D, self.va2off(va))[0]
    def find(self, pat, secs=None):
        out = []
        for nm, sva, vsz, roff, sz, _ in self.sec:
            if secs and nm not in secs:
                continue
            i = 0
            while True:
                j = self.D.find(pat, roff + i, roff + sz)
                if j < 0: break
                out.append(self.off2va(j)); i = j - roff + 1
        return out


# ------------------------------------------------------------------ numpy 数据侧
class Data:
    """global-metadata.dat 的向量化视图"""
    def __init__(self, raw, hdr=0x210):
        import numpy as np
        self.np = np
        self.raw = raw
        self.hdr = hdr
        self.ub = np.frombuffer(raw, dtype=np.uint8)
        self.u32 = np.frombuffer(raw, dtype='<u4', count=len(raw) // 4).astype(np.int64)

    def f32(self, off, stride, n, field=0):
        """返回 off 起、stride 步长、n 项、第 field 字节处的 int32 数组（向量化）"""
        np = self.np
        base = off + field
        idx = base + np.arange(n, dtype=np.int64) * stride
        if idx.size and idx[-1] + 4 > len(self.ub):
            return None
        b = self.ub
        return (b[idx].astype(np.int64)
                | (b[idx + 1].astype(np.int64) << 8)
                | (b[idx + 2].astype(np.int64) << 16)
                | (b[idx + 3].astype(np.int64) << 24))

    def f32s(self, off, stride, n, field=0):
        v = self.f32(off, stride, n, field)
        if v is None: return None
        return self.np.where(v >= (1 << 31), v - (1 << 32), v)

    def u8(self, off, stride, n, field=0):
        np = self.np
        idx = off + field + np.arange(n, dtype=np.int64) * stride
        if idx.size and idx[-1] >= len(self.ub): return None
        return self.ub[idx].astype(np.int64)

    def u16(self, off, stride, n, field=0):
        np = self.np
        idx = off + field + np.arange(n, dtype=np.int64) * stride
        if idx.size and idx[-1] + 2 > len(self.ub): return None
        return (self.ub[idx].astype(np.int64) | (self.ub[idx + 1].astype(np.int64) << 8))


# ------------------------------------------------------------------ 探测器
def probe_fdv(d, off, typeCount, maxn=80000):
    v0 = d.f32(off, 12, maxn, 0)
    if v0 is None: return None
    inc = int((d.np.diff(v0) > 0).sum())
    # 找一个"连续严格递增前缀"
    good = d.np.diff(v0) > 0
    run = 0
    for g in good:
        if not g: break
        run += 1
    if run < 5000: return None
    v8 = d.f32(off, 12, run, 8)
    v4 = d.f32s(off, 12, run, 4)
    if v8 is None or v4 is None: return None
    if int(v8.max()) < typeCount:
        return ('fieldDefaultValuesOffset', run, "12B, +0 严格递增 %d 项, +8 全为合法 Il2CppType 索引" % run)
    if int((v4 == -1).sum()) > 0:
        return ('parameterDefaultValuesOffset', run, "12B, +0 严格递增 %d 项, +4 含 -1 哨兵" % run)
    return None


def probe_methods(d, off):
    pc = d.u8(off, 26, 733500, 0x18)
    if pc is None: return None
    # 严格 tail 会有垃圾，只看前 500000 项的 distinct
    import numpy as np
    seg = pc[:500000]
    n_dis = int(np.unique(seg).size)
    if 8 <= n_dis <= 80:
        return ('methodsOffset', 500000, "26B stride, +0x18(parameterCount) 只有 %d 种取值" % n_dis)
    return None


def probe_typedefs(d, off):
    fl = d.f32(off, 70, 88902, 0x28)
    if fl is None: return None
    import numpy as np
    n_dis = int(np.unique(fl).size)
    if 40 <= n_dis <= 400:
        return ('typeDefinitionsOffset', 88902, "70B stride, +0x28(flags) 只有 %d 种取值" % n_dis)
    return None


def probe_attributes_info(d, off):
    v = d.f32(off, 8, 1200, 4)
    if v is None: return None
    import numpy as np
    inc = int((np.diff(v) > 0).sum())
    if inc < 900: return None
    if inc < 1199: return None                      # 必须严格升序（无重复）
    hb = set(d.ub[off + 7 + d.np.arange(1200) * 8].tolist())
    if not (4 <= len(hb) <= 64): return None
    # 真正长度
    n = 1200
    while off + 8 * n + 8 <= len(d.raw):
        a = struct.unpack_from('<i', d.raw, off + 8 * n + 4)[0]
        b = struct.unpack_from('<i', d.raw, off + 8 * (n - 1) + 4)[0]
        if a <= b: break
        n += 1
    if n > 8000: return None                        # 本表只有千级（超大的不是它）
    return ('attributesInfoOffset', n, "8B, +4 严格升序 %d 项, 高字节 %d 种（token 形态）" % (n, len(hb)))


def find_blob(d, sig_pos, fdv_off, fdv_n, cands):
    """blob 基址：让 `sig_pos` 落在某个 fieldDefaultValues 的 dataIndex 上"""
    idxs = set()
    for i in range(min(fdv_n, 80000)):
        idxs.add(struct.unpack_from('<i', d.raw, fdv_off + 12 * i + 4)[0])
    out = []
    for val, slot, op, key in cands:
        base = d.hdr + val
        if sig_pos - base in idxs:
            out.append((val, slot, op, key))
    return out


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--slots', default=None)
    ap.add_argument('--scan', action='store_true', help='无缓存时自动跑 slot_scan.py')
    ap.add_argument('--typeCount', type=int, default=683574)
    args = ap.parse_args()

    root = args.root if os.path.isabs(args.root) else os.path.join(ROOTDIR, args.root)
    exe = os.path.join(root, 'gi.exe')
    gm = os.path.join(root, 'gi/Managed/Metadata/global-metadata.dat')
    t0 = time.time()

    pe = PE(exe)
    print("== ① 引导锚（魔数，最稳）==")
    mhy = pe.find(b'MHY\x00', secs={'.rdata', '_RDATA', '.data'})
    print("   'MHY\\0' ->", [hex(x) for x in mhy] or "✗ 未命中")
    if not mhy: return 1
    MHY = mhy[0]
    slot = lambda o: pe.u32(MHY + o)

    if not os.path.exists(gm):
        print("   (缺 global-metadata.dat，只能给 MHY 地址)"); return 0
    raw = open(gm, 'rb').read()
    d = Data(raw)
    print("   global-metadata.dat %.1f MB" % (len(raw) / 1e6))

    print("\n== ② 指令证据（slot_scan 的 (slot,op,key) 候选）==")
    cands = []
    cache = args.slots
    if cache is None:
        for p in (os.path.join(HERE, 'slots_cache.json'), '/tmp/opencode/slots_cache.json'):
            if os.path.exists(p): cache = p; break
    if cache is None and args.scan:
        print("   无缓存 → 跑 slot_scan.py（几分钟）…")
        subprocess.run([sys.executable, os.path.join(HERE, 'slot_scan.py'), exe, gm], check=False)
        cache = os.path.join(HERE, 'slots_cache.json')
    if cache and os.path.exists(cache):
        c = json.load(open(cache))
        sv = {int(k): v for k, v in c['svals'].items()}
        for dd, op, imm, n, va in c['uniq']:
            if dd not in sv: continue
            v = sv[dd]
            val = (v ^ imm) & M32 if op == 'xor' else ((v - imm) & M32 if op == 'sub' else (v + imm) & M32)
            cands.append((val, dd, op, imm))
        print("   缓存 %s：%d 个候选" % (os.path.relpath(cache, ROOTDIR), len(cands)))
    else:
        print("   ⚠ 无候选缓存（--scan 可自动生成）")
    vals = sorted({v for v, *_ in cands})

    print("\n== ③ 常量值 blob（AttributeTargets 的 [Flags] 值签名，无需任何锚）==")
    sig = b''.join(struct.pack('<i', v) for v in ATTR_TARGETS)
    hits = []
    i = 0
    while True:
        j = raw.find(sig, i)
        if j < 0: break
        hits.append(j); i = j + 1
    print("   签名命中:", [hex(h) for h in hits])

    print("\n== ④ 数据侧结构自证（numpy 向量化）==")
    found = {}
    probes = [lambda o: probe_fdv(d, o, args.typeCount),
              lambda o: probe_methods(d, o),
              lambda o: probe_typedefs(d, o),
              lambda o: probe_attributes_info(d, o)]
    t1 = time.time()
    for val in vals:
        if not (0x1000 <= val < len(raw) - 0x210): continue
        for pr in probes:
            r = pr(d.hdr + val)
            if r:
                name, n, why = r
                if name not in found or n > found[name][3]:
                    found[name] = (val, n, why, n)
    for k, (val, n, why, _) in sorted(found.items()):
        print("   %-28s = 0x%-9X (%d 项)  ← %s" % (k, val, n, why))
    if 'fieldDefaultValuesOffset' in found:
        fv, fn = found['fieldDefaultValuesOffset'][0], found['fieldDefaultValuesOffset'][1]
        for h in hits:
            b = find_blob(d, h, d.hdr + fv, fn, cands)
            for val, s, op, key in b[:2]:
                print("   %-28s = 0x%-9X  ← 让 AttributeTargets 签名落在某条 dataIndex 上 (slot 0x%X %s 0x%X)"
                      % ('blob(fieldAndParameterDefaultValueData)', val, s, op, key))
    print("   （探测耗时 %.1fs）" % (time.time() - t1))

    print("\n== ⑤ 与现有 version.json 对照（自测：应全部一致）==")
    vj = os.path.join(ROOTDIR, 'version.json')
    if os.path.exists(vj):
        J = load_json_with_comments(vj)
        ok = bad = 0
        for k, cfg in J.get('tables', {}).items():
            if 'slot' not in cfg: continue
            s = int(cfg['slot'], 0); op = cfg['op']; key = int(cfg['key'], 0)
            v = slot(s)
            val = (v ^ key) & M32 if op == '^' else ((v - key) & M32 if op == '-' else (v + key) & M32)
            det = found.get(k)
            mark = ''
            if det is not None:
                mark = ' ✅ 探测值一致' if det[0] == val else ' ⚠ 探测=%X' % det[0]
                ok += 1 if det[0] == val else 0
                bad += 0 if det[0] == val else 1
            print("   %-42s slot 0x%03X %s 0x%-10X -> 0x%-9X%s" % (k, s, op, key, val, mark))
        print("\n   可被结构探测交叉验证的表：一致 %d, 不一致 %d" % (ok, bad))
    print("\n总耗时 %.1fs" % (time.time() - t0))
    return 0


if __name__ == '__main__':
    sys.exit(main())
