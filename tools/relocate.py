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


def probe_methods_DISABLED(d, off):
    pc = d.u8(off, 26, 733500, 0x18)
    if pc is None: return None
    # 严格 tail 会有垃圾，只看前 500000 项的 distinct
    import numpy as np
    seg = pc[:500000]
    n_dis = int(np.unique(seg).size)
    if 8 <= n_dis <= 80:
        return ('methodsOffset', 500000, "26B stride, +0x18(parameterCount) 只有 %d 种取值" % n_dis)
    return None


def probe_typedefs_DISABLED(d, off, n=88902):
    """70B 步长，+0x28(flags) 的**不同取值数**只有 ~106（实测；"递增"是错误的判据）"""
    fl = d.f32(off, 70, n, 0x28)
    if fl is None: return None
    import numpy as np
    nd = int(np.unique(fl).size)
    if 40 <= nd <= 400:
        return ('typeDefinitionsOffset', n, "70B stride, +0x28(flags) 只有 %d 种取值" % nd)
    return None


def probe_attributes_info_DISABLED(d, off):
    """实测：+0(start) 严格递增 1114/1114；+4(token) **不**递增。所以判据用 +0。"""
    v = d.f32(off, 8, 1200, 0)
    if v is None: return None
    import numpy as np
    if int((np.diff(v) > 0).sum()) < 1199: return None
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


def probe_field_offsets_DISABLED(d, off):
    """fieldOffset 表：4B；高 3 位只有两种（0x00000000=实例 / 0xC0000000=static）→ 指纹极强。"""
    import numpy as np
    n = 440172
    v = d.f32(off, 4, n, 0)
    if v is None: return None
    hi = v & 0xE0000000
    u, cnt = np.unique(hi, return_counts=True)
    # 实测：{0x60000000:429110, 0xC0000000:9277, 0:1785} → 种类 ≤4 且某个占绝大多数
    if u.size > 4 or cnt.max() < n * 0.8: return None
    return ('fieldOffset', n, "4B, 高3位只有 %d 种（%s），最大值域占 %d%%"
            % (u.size, "/".join(hex(x) for x in u.tolist()), 100 * cnt.max() // n))


def probe_interfaces_DISABLED(d, off, typeCount=683574):
    """interfaces 表：6B 步长，+0 是合法 Il2CppType 索引。"""
    import numpy as np
    n = 30000
    v = d.f32(off, 6, n, 0)
    if v is None: return None
    if int((v < typeCount).sum()) < n * 0.98: return None
    return ('interfacesTable', n, "6B stride, +0 全为合法 Il2CppType 索引")


def probe_method_slot_table_DISABLED(d, off, methodsCount=733442):
    """methodSlotTable：6B 步长 {methodIndex(int32), slot(uint16)}，由代码**二分查找** →
    必然满足：+0 严格递增 且 +4 == 索引（slot 就是行号）。指纹极强。"""
    import numpy as np
    n = 20000
    a = d.f32(off, 6, n, 0)
    b = d.u16(off, 6, n, 4)
    if a is None or b is None: return None
    if int((np.diff(a) > 0).sum()) < n - 2: return None
    if int(a.max()) >= methodsCount: return None
    if not np.array_equal(b, np.arange(n)): return None
    return ('methodSlotTableOffset', n, "6B, +0 严格递增且 <methodsCount, +4 == 索引（slot==行号）")


def probe_method_pointer_index(d, off, ptrCount=79765):
    """methodPointerIndex：4B，值只有 -1（无实现）或 < 泛型方法指针数组长度。"""
    import numpy as np
    n = 200000
    v = d.f32s(off, 4, n, 0)
    if v is None: return None
    if int(v.min()) < -1: return None
    if int(v.max()) >= ptrCount: return None
    nm1 = int((v == -1).sum())
    if nm1 < n * 0.005: return None           # 实测有 8548/200000 个 -1
    return ('methodPointerIndexOffset', n, "4B, 值域 [-1, %d), -1 占 %.1f%%" % (ptrCount, 100.0 * nm1 / n))


# ============================================================================
#  「引导阶梯」第二级：用**旧 version.json 当提示** + **字符串解码当二次证据**
#  思路：这些表的内容是逐索引混淆的，没有干净指纹；但只要"解码出来的名字可打印"，
#       就能把候选钉死 —— 不独特 ⇒ 不会误报。
# ============================================================================
def make_str_decoder(raw, str_data_off, keys):
    """keys = (entryXor, mulA, mulB, seed, step)"""
    ex, ma, mb, sd, st = keys
    def dec(name_index):
        name_index &= M32
        off = name_index & 0xFFFFFF
        ln = name_index >> 24
        base = str_data_off + off
        if ln == 0 or base + ln + 8 > len(raw): return None
        k = (ma * ((mb * off) ^ sd)) & ((1 << 64) - 1)
        out = bytearray()
        for j in range((ln + 7) // 8):
            c = struct.unpack_from('<Q', raw, base + 8 * j)[0]
            out += struct.pack('<Q', c ^ ((k + j * st) & ((1 << 64) - 1)))
        try: return out[:ln].decode('ascii')
        except Exception: return None
    return dec


def probe_typedefs_verified(d, off, hint):
    """typeDefinitions：70B + flags 种类 40~400（弱指纹）→ **必须再通过名字可打印**（二次证据）。
    hint: dict(str_data_off=..., str_keys=..., type_name_key=...) —— 来自旧 version.json"""
    if not hint or not hint.get('dec'): return None
    fl = d.f32(off, 70, 88902, 0x28)
    if fl is None: return None
    import numpy as np
    nd = int(np.unique(fl).size)
    if not (40 <= nd <= 400): return None
    dec = hint['dec']; tk = hint['type_name_key']
    ok = 0; n = 200
    for i in range(0, 88902, max(1, 88902 // n)):
        raw = struct.unpack_from('<I', d.raw, off + 70 * i + 0x24)[0]
        nm = dec((raw - tk) & M32)
        if nm and nm and all(32 <= ord(c) < 127 for c in nm): ok += 1
    if ok < n * 0.95: return None
    return ('typeDefinitionsOffset', 88902, "70B, flags %d 种, 且 %d/%d 个 nameIndex 解出可打印名字" % (nd, ok, n))


# ============================================================================
#  阶梯 ④⑤：用 typeDefinitions（已检测）+ 旧 JSON 的字段键，解出各表的**预期长度**，
#  再用「长度 + 结构」约束去钉候选。下面先用指纹最强的 nestedTypes 落地。
# ============================================================================
def ladder_expected_lengths(hint, d, td_off, td_count):
    """解码 typeDefs 的各字段（用旧 JSON 的键）→ 各表的预期总长度 / nested 区间"""
    import numpy as np
    H = hint['keys']          # {'td_nested_start':6631,'td_nested_count':0xBA, ...}
    ub = d.ub
    def f32(field, off, stride, n):
        idx = off + field + np.arange(n, dtype=np.int64) * stride
        b = d.ub
        v = b[idx].astype(np.int64)
        for k in range(1, 4): v |= b[idx + k].astype(np.int64) << (8 * k)
        return np.where(v >= (1 << 31), v - (1 << 32), v)
    def u16(field):
        idx = td_off + field + np.arange(td_count, dtype=np.int64) * 70
        return (d.ub[idx].astype(np.int64) | (d.ub[idx + 1].astype(np.int64) << 8))
    def u8(field):
        return d.ub[td_off + field + np.arange(td_count, dtype=np.int64) * 70].astype(np.int64)

    def dec(v, op, key, mask):
        # version.json 里的 op 是 sub/xor/add 全词（也兼容 -/^/+ 简写）
        if op in ('-', 'sub'): return (v - key) & mask
        if op in ('^', 'xor'): return (v ^ key) & mask
        if op in ('+', 'add'): return (v + key) & mask   # +N 型必须按位宽截断（8/16 位）
        raise ValueError('未知 op: %r' % (op,))
    out = {}
    fc = dec(u16(0x38), *H['td_field_count'], 0xFFFF)
    out['fieldsLen'] = int(fc.sum())
    mc = dec(u16(0x30), *H['td_method_count'], 0xFFFF)
    out['methodsLen'] = int(mc.sum())
    pc = dec(u8(0x43), *H['td_property_count'], 0xFF)
    out['propertiesLen'] = int(pc.sum())
    ec = dec(u8(0x44), *H['td_event_count'], 0xFF)
    out['eventsLen'] = int(ec.sum())
    ns = dec(u16(0x36), *H['td_nested_start'], 0xFFFF)
    ns = np.where(ns >= 0x8000, ns - 0x10000, ns)
    nc = dec(u8(0x45), *H['td_nested_count'], 0xFF)
    seg = [(int(a), int(b)) for a, b in zip(ns, nc) if b]
    out['nestedSegs'] = seg
    out['nestedLen'] = int(sum(b for _, b in seg))
    ic = dec(u8(0x40), *H['td_interfaces_count'], 0xFF)
    out['interfacesLen'] = int(ic.sum())
    return out


def probe_pdv(d, off, typeCount, maxn=80000):
    """parameterDefaultValues：12B {parameterIndex@+0, dataIndex@+4, typeIndex@+8}。
    与 fieldDefaultValues 结构同构，但用 **+4 的 -1 哨兵**区分（fDV 没有）。
    **完全不依赖任何版本常量**（typeCount 只当上界，不参与判据）。"""
    v0 = d.f32(off, 12, maxn, 0)
    if v0 is None: return None
    good = d.np.diff(v0) > 0
    run = 0
    for g in good:
        if not g: break
        run += 1
    if run < 5000: return None
    v4 = d.f32s(off, 12, run, 4)
    v8 = d.f32(off, 12, run, 8)
    if v4 is None or v8 is None: return None
    if int((v4 == -1).sum()) == 0: return None            # fDV 没有 -1，pDV 有
    if int((v8 < typeCount).mean()) < 0.98: return None
    return ('parameterDefaultValuesOffset', run,
            "12B, +0 严格递增 %d 项, +4 含 -1 哨兵, +8 全为合法 Il2CppType 索引" % run)


def probe_attrinfo(d, off, maxn=40000):
    """attributesInfo：8B {start@+0, token@+4}。三个**互相独立**的条件：
       1) +0 严格递增
       2) +4 的**高字节**有界（实测 1..0x54）
       3) +4 的**低 24 位单调不减**（token 重映射后仍保序）
    ⚠️ 只用条件 1+2 会**误报**（实测 7.0 上 0x260A7F8 假命中 12513 项，真值只有 ~1000）。
    加上条件 3 后判据足够强，且完全不依赖任何旧版本常量。"""
    v0 = d.f32(off, 8, maxn, 0)
    if v0 is None: return None
    good = d.np.diff(v0) > 0
    run = 0
    for g in good:
        if not g: break
        run += 1
    if run < 200: return None
    v4 = d.f32(off, 8, run, 4)
    if v4 is None: return None
    hi = (v4 >> 24) & 0xFF
    if int(hi.min()) < 1 or int(hi.max()) > 0x60: return None
    lo = v4 & 0xFFFFFF
    if int(d.np.diff(lo).min()) < 0: return None          # 条件 3：低 24 位单调不减
    if run > 20000: return None                            # 真实表只有千级，12513 那种是误报
    return ('attributesInfoOffset', run,
            "8B, +0 严格递增 %d 项, +4 高字节 ∈[1,0x%X] 且低 24 位单调" % (run, int(hi.max())))


def probe_typedefs_hintfree(d, off, maxn=6000):
    """typeDefinitions（70 字节）的 hint-free 初筛。

    ⚠️ **目前不生效**：它直接读 +0x08/+0x0C/+0x1C/+0x28 的**原始字节**，
    但这些字段是**逐字段混淆**的（`raw op key`），原始值是随机的 ——
    所以"累计索引单调""flags 只有几十种"都不成立，实测一律返回 None。

    要让它真正 hint-free，得先做**字段密钥反查**：对每个字段偏移枚举
    slot_scan 候选里的 (op,key)，挑出"解出值单调/落在字符串块内且可打印"的那个
    —— 与 ⑦「值 -> 唯一 slot」同源，只是方向相反（字段密钥 -> 偏移）。
    保留在此作为占位与思路记录。"""
    STRIDE = 70
    if off + STRIDE * 200 > len(d.raw): return None
    n = min(maxn, (len(d.raw) - off) // STRIDE)
    if n < 200: return None
    a8 = d.f32(off, STRIDE, n, 0x08)
    ac = d.f32(off, STRIDE, n, 0x0C)
    a1c = d.f32(off, STRIDE, n, 0x1C)
    if a8 is None or ac is None or a1c is None: return None
    for v in (a8, ac, a1c):
        if int(v.min()) < 0: return None
        # 累计索引：允许相等（无该表的类型），但不允许大幅回退
        if int(d.np.diff(v).min()) < -1000: return None
    # 三个字段都不该超过总表长度的合理上界（几十万）
    if max(int(a8.max()), int(ac.max()), int(a1c.max())) > 4_000_000: return None
    f28 = d.f32(off, STRIDE, n, 0x28)
    if f28 is None: return None
    kinds = len(set(f28[:400].tolist()))
    if kinds > 200: return None                          # flags 只有几十种
    return ('typeDefinitionsOffset', n,
            "70B, +0x08/+0x0C/+0x1C 累计索引单调, +0x28 flags %d 种" % kinds)


def probe_nestedtypes_verified(d, off, hint, exp):
    """4B 表：typeDefs 的 nested 区间必须**恰好铺满** [0, N)，且条目全为合法 typeDef 索引。
    两个独立条件 —— 指纹很强。（长度 N 由 typeDefs 解出，不用猜）"""
    import numpy as np
    if not exp or 'nestedLen' not in exp: return None
    N = exp['nestedLen']; tdc = hint['typeDefCount']
    if N <= 0 or off + 4 * N > len(d.raw): return None
    idx = off + np.arange(N, dtype=np.int64) * 4
    b = d.ub
    v = b[idx].astype(np.int64) | (b[idx + 1].astype(np.int64) << 8) | \
        (b[idx + 2].astype(np.int64) << 16) | (b[idx + 3].astype(np.int64) << 24)
    if int((v < tdc).sum()) < N * 0.999: return None
    # 每个 typeDef 只能嵌套在一个父类型里 → N 个条目必须**两两不同**（杀误报的关键）
    if len(set(v.tolist())) != N: return None
    # 平铺：区间的并集必须恰好是 [0, N)
    segs = sorted(exp['nestedSegs'])
    if segs[0][0] != 0: return None
    cur = 0
    for a, c in segs:
        if a != cur: return None
        cur = a + c
    if cur != N: return None
    return ('nestedTypesTable', N, "4B, typeDefs 区间恰好铺满 [0,%d), 条目全为合法 typeDef 索引且两两不同" % N)


def probe_interfaces_table(d, off, hint, exp):
    """6B 表：+0 是 Il2CppType 索引（-1 = null），+4 是 int16。
    长度 = typeDefs 解出的 interfaces 条目总数（区间有重叠，不能用 max）。
    判据：窗口内 +0 **全部**落在 {-1} ∪ [0, typesCount) —— 实测真表 100%，很强。"""
    import numpy as np
    if not exp or not exp.get('interfacesLen'): return None
    N = exp['interfacesLen']
    tc = hint.get('typesCount', 683574)
    if N <= 0 or off + 6 * N > len(d.raw): return None
    idx = off + np.arange(N, dtype=np.int64) * 6
    b = d.ub
    a = (b[idx].astype(np.int64) | (b[idx + 1].astype(np.int64) << 8)
         | (b[idx + 2].astype(np.int64) << 16) | (b[idx + 3].astype(np.int64) << 24))
    a = np.where(a >= (1 << 31), a - (1 << 32), a)          # int32
    ok = float(((a == -1) | ((a >= 0) & (a < tc))).mean())
    big = int((a > 10000).sum())
    if ok < 0.999 or big < 5000: return None
    return ('interfacesTable', N,
            "6B, +0 全为合法 Il2CppType 索引(-1=null) 比例 %.5f, 含 %d 个大索引" % (ok, big))


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
        # ---- 缓存自检（踩过的坑）----
        # 缓存里存的是 MHY 各槽位的原始值；若生成时 MHY 定位错了，这些值会退化成 0/1，
        # 于是所有候选值都算错、探测**静默地啥也找不到**（不是报错，只是结果为空）。
        deg = sum(1 for v in sv.values() if v <= 1)
        if sv and deg > len(sv) * 0.5:
            print("   \u26a0\u26a0 缓存可疑：%d/%d 个槽位值 <=1 —— 生成时 MHY 定位错了？"
                  % (deg, len(sv)))
            print("      请重扫：python3 tools/slot_scan.py <gi.exe> <global-metadata.dat> --out %s" % cache)
            return 1
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

    # ---- 读旧 version.json 当「提示」（阶梯用；任何一步都要过二次证据才接受）----
    hint = {}
    vj0 = os.path.join(ROOTDIR, 'version.json')
    if os.path.exists(vj0):
        try:
            J0 = load_json_with_comments(vj0)
            globals()['J0'] = J0
            sd = J0['tables']['stringLiteralDataOffset']
            sdo = (slot(int(sd['slot'], 0)) + int(sd['key'], 0)) & M32 if sd['op'] == '+' else 0
            sk = J0['stringDecrypt']
            def K(x): return int(x, 0) if isinstance(x, str) else int(x)
            dec = make_str_decoder(raw, d.hdr + sdo,
                                   (K(sk['entryXor']), K(sk['keyMulA']), K(sk['keyMulB']), K(sk['keySeed']), K(sk['keyStep'])))
            # 把 typeDefs 各字段的解码键也放进提示（阶梯 ④ 要用）
            fd = J0['fieldDecode']['typeDef']
            def opk(name):
                op, _, key = fd[name].partition(':')
                return (op.strip(), K(key.strip()))
            hint = {'dec': dec,
                    'type_name_key': K(fd['nameIndex'].split(':')[1]),
                    'keys': {'td_field_start': opk('fieldStart'),
                             'td_field_count': opk('field_count'),
                             'td_method_count': opk('method_count'),
                             'td_property_count': opk('property_count'),
                             'td_event_count': opk('event_count'),
                             'td_nested_start': opk('nestedTypesStart'),
                             'td_nested_count': opk('nestedTypesCount'),
                             'td_interfaces_count': opk('interfaces_count')},
                    'typeDefCount': 0,
                    'typesCount': args.typeCount}
            print("   提示(旧 version.json): 字符串数据块 0x%X, typeNameKey=%d" % (sdo, hint['type_name_key']))
        except Exception as e:
            print("   提示读取失败:", e)

    print("\n== ④ 数据侧结构自证（numpy 向量化）==")
    found = {}
    # ⚠️ 只保留**自测能推出已知正确值**的探测器（宁可漏报，不可误报）：
    #    fieldDefaultValues / methodPointerIndex / blob
    # 其余探测器判据不够独特，会在**其他表**上误命中（实测过）：
    #    typeDefinitions  : 有别的偏移也满足「+0x28 只有 40~400 种取值」
    #    attributesInfo   : fDV 表的尾巴也满足「8B + +0 严格递增」
    #    fieldOffset      : methodPointerIndex 表也满足「高 3 位种类少」
    #    methodSlotTable  : 需要「+4 == 行号」之外的二次证据才不与别的表混淆
    #    methods          : +0x18 有 256 种（逐方法 key 打散）→ 无可用指纹
    #  要启用它们，得先加**二次证据**（字符串解码 / 跨表一致性），见 §12 末
    probes = [lambda o: probe_fdv(d, o, args.typeCount),
              lambda o: probe_pdv(d, o, args.typeCount),
              lambda o: probe_attrinfo(d, o),
              lambda o: probe_method_pointer_index(d, o),
              # 阶梯第二级：弱指纹 + 二次证据（名字可打印）→ 可安全启用（依赖 hint）
              lambda o: probe_typedefs_verified(d, o, hint),
              # **无 hint 兜底**：字符串解码密钥每版都变，这个探针只用结构 → 换版本仍能初筛
              lambda o: probe_typedefs_hintfree(d, o)]
    t1 = time.time()
    for val in vals:
        if not (0x1000 <= val < len(raw) - 0x210): continue
        for pr in probes:
            r = pr(d.hdr + val)
            if r:
                name, n, why = r
                if name not in found or n > found[name][3]:
                    found[name] = (val, n, why, n)
    VERIFIED = {'fieldDefaultValuesOffset', 'blob(fieldAndParameterDefaultValueData)',
                'methodsOffset', 'typeDefinitionsOffset', 'nestedTypesTable',
                'interfacesTable', 'fieldOffset'}

    # ---- 阶梯 ④⑤：typeDefinitions（已检测）→ 各表预期长度/区间 → 钉住更多表 ----
    # 必须在打印之前跑，否则结果来不及显示
    exp = None
    if 'typeDefinitionsOffset' in found and hint.get('keys'):
        td_off = d.hdr + found['typeDefinitionsOffset'][0]
        try:
            td = J0['tables']['typeDefinitionsCount']
            v = slot(int(td['slot'], 0))
            key = int(td['key'], 0)
            if td['op'] in ('^', 'xor'): tdc = ((v ^ key) & M32) // 70 - 2
            else: tdc = ((v - key) & M32) // 70 - 2
        except Exception:
            tdc = 88902
        hint['typeDefCount'] = tdc
        exp = ladder_expected_lengths(hint, d, td_off, tdc)
        # 每个「长度约束」探针：候选值必须让该表**完整落在文件内**且结构自证
        ladder_multi = {}
        for val in vals:
            if not (0x1000 <= val < len(raw) - 0x210): continue
            for name, r in (('nestedTypesTable', probe_nestedtypes_verified(d, d.hdr + val, hint, exp)),
                            ('interfacesTable', probe_interfaces_table(d, d.hdr + val, hint, exp))):
                # 注：fieldOffset 表**不是**按 fieldStart 索引，而是按 typeDef+0x20(unknown20) + k，
                #     且实测"类型内偏移非递减"只有 57% —— 判据不足，暂不启用（宁可漏报）
                if not r: continue
                ladder_multi.setdefault(name, []).append(val)
                if name not in found:
                    found[name] = (val, r[1], r[2], r[1])
        for name, ms in ladder_multi.items():
            if len(ms) > 1:
                print("   ⚠ %s 有 %d 个候选同时通过（可能是误报）: %s"
                      % (name, len(ms), [hex(x) for x in ms]))

    for k, (val, n, why, _) in sorted(found.items()):
        tag = '已验收' if k in VERIFIED else '未验收(仅参考)'
        print("   %-28s = 0x%-9X (%d 项) [%s] ← %s" % (k, val, n, tag, why))
    if exp:
        print("   阶梯④ 由 typeDefs 解出预期长度: fields=%d methods=%d properties=%d events=%d nested=%d interfaces=%d"
              % (exp['fieldsLen'], exp['methodsLen'], exp['propertiesLen'], exp['eventsLen'], exp['nestedLen'], exp['interfacesLen']))

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

    print("\n== ⑥ 旧 JSON slot 提示：逐表重新解值（检验「slot 跨版本稳定」假设）==")
    if os.path.exists(vj):
        J = load_json_with_comments(vj)
        byslot = {}
        for val, s, op, key in cands:
            byslot.setdefault(s, []).append((val, op, key))
        uniq_n = multi = none_n = 0
        details = []
        for k, cfg in J.get('tables', {}).items():
            if 'slot' not in cfg: continue
            s = int(cfg['slot'], 0)
            lst = byslot.get(s, [])
            ok_c = [(v, op, key) for v, op, key in lst if 0x1000 <= v < len(raw) - 0x210]
            if not lst:
                ver, none_n = '✗ 该 slot 无候选（需重扫 slot_scan）', none_n + 1
            elif not ok_c:
                ver, none_n = '✗ 无落入元数据范围的候选', none_n + 1
            elif len(ok_c) == 1:
                ver, uniq_n = '✅ 唯一', uniq_n + 1
            else:
                ver, multi = '⚠ %d 个候选，需结构/人工判定' % len(ok_c), multi + 1
            if not ver.startswith('✅'):
                details.append("   %-38s slot 0x%-4X %s" % (k, s, ver))
        for line in details:
            print(line)
        print("   合计: slot 唯一确定 %d 张, 多候选 %d 张, 无候选 %d 张" % (uniq_n, multi, none_n))
        print("   （前提：slot 跨版本稳定 —— 尚未用第二个样本验证；见 docs/UPDATE.md §8.6）")

    print("\n== ⑦ 反查 slot：结构自证得到的值 → 唯一 (slot,op,key)（换版本可全自动）==")
    byval = {}
    for val, s, op, key in cands:
        byval.setdefault(val, []).append((s, op, key))
    auto = 0
    for k in sorted(found):
        v0 = found[k][0]
        hits = byval.get(v0, [])
        if len(hits) == 1:
            s, op, key = hits[0]
            print("   %-28s 0x%-9X -> slot 0x%-4X %-4s 0x%X   ✅ 唯一" % (k, v0, s, op, key))
            auto += 1
        else:
            print("   %-28s 0x%-9X -> %d 个候选 ⚠（需人工/二次证据）" % (k, v0, len(hits)))
    if auto:
        print("   ★ 这 %d 张表换版本可全自动：结构自证出值 → 反查唯一 (slot,op,key)，不需要旧 JSON" % auto)

    print("\n总耗时 %.1fs" % (time.time() - t0))
    return 0


if __name__ == '__main__':
    sys.exit(main())
