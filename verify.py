#!/usr/bin/env python3
"""
版本更新后的验收脚本（换 gi.exe / *.dat 后跑这个）

用法:
    python3 verify.py                          # 默认校验 version/7.1 与 out/dump.cs
    python3 verify.py <game_root> [dump.cs]    # 校验别的样本，例如 version/7.1
    python3 verify.py <exe> <global.dat> <startup.dat>

输出每项 PASS/FAIL，并在末尾给出总结。
任何 FAIL 都意味着还不要用这份 dump —— 本项目的历史 bug 全是「不崩、只静默产出垃圾」。
"""
import struct, sys, os, re

M32 = (1 << 32) - 1
M64 = (1 << 64) - 1

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(HERE, 'version', '7.1')
if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
    ROOT = sys.argv[1]
    EXE  = os.path.join(ROOT, 'gi.exe')
    GM   = os.path.join(ROOT, 'gi/Managed/Metadata/global-metadata.dat')
    SM   = os.path.join(ROOT, 'gi/Managed/Metadata/startup-metadata.dat')
    DUMP = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, 'out', 'dump.cs')
else:
    EXE  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DEFAULT_ROOT, 'gi.exe')
    GM   = sys.argv[2] if len(sys.argv) > 2 else os.path.join(DEFAULT_ROOT, 'gi/Managed/Metadata/global-metadata.dat')
    SM   = sys.argv[3] if len(sys.argv) > 3 else os.path.join(DEFAULT_ROOT, 'gi/Managed/Metadata/startup-metadata.dat')
    DUMP = os.path.join(HERE, 'out', 'dump.cs')

D   = open(EXE, 'rb').read()
raw = open(GM,  'rb').read()
sm  = open(SM,  'rb').read()

RESULTS = []
def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s %-44s %s" % ("PASS" if ok else "FAIL", name, detail))

# ---------- PE 段表（VA <-> 文件偏移必须逐段换算）----------
pe = struct.unpack_from('<I', D, 0x3C)[0]
nsec = struct.unpack_from('<H', D, pe + 6)[0]
opt  = struct.unpack_from('<H', D, pe + 0x14)[0]
so   = pe + 0x18 + opt
img  = struct.unpack_from('<Q', D, pe + 0x18 + 0x18)[0]
SEC  = []
for i in range(nsec):
    e = so + i * 40
    nm = D[e:e+8].rstrip(b'\0').decode(errors='replace')
    vsz, va, rsz, roff = struct.unpack_from('<IIII', D, e + 8)
    SEC.append((nm, img + va, roff, min(vsz, rsz)))

def va2off(v):
    for nm, va, roff, sz in SEC:
        if va <= v < va + sz:
            return roff + (v - va)
    return None

# ---------- 三个全局表（地址变了要改这里）----------
MHY_VA = 0x1427D4BD0      # "MHY\0"
T0_VA  = 0x1422DE370
T1_VA  = 0x142870A88

def need(name, va):
    o = va2off(va)
    if o is None:
        check(name, False, "VA 0x%X 不在任何段（地址变了？）" % va)
    return o

mhy_o = need("MHY 表地址可解析", MHY_VA)
if mhy_o is None:
    print("\nMHY 表地址失效，后续检查无法进行。"); sys.exit(1)
slot = lambda off: struct.unpack_from('<I', D, mhy_o + off)[0]

# 表头魔数
check("MHY 表以 'MHY\\0' 开头", D[mhy_o:mhy_o+4] == b'MHY\x00', D[mhy_o:mhy_o+4])

# ---------- §3 槽位自检（这三条必须成立，否则扫描/密钥抄错了）----------
FIELDDEF = (slot(0x13C) ^ 0x593DE464) & M32
BLOB     = (slot(0x0A0) ^ 0x3F525210) & M32
PDV      = (slot(0x104) ^ 0x094C42AB) & M32
check("MHY[0x13C]^0x593DE464 落在元数据内", 0x1000 < FIELDDEF < len(raw), "0x%X" % FIELDDEF)
check("MHY[0x0A0]^0x3F525210 落在元数据内", 0x1000 < BLOB < len(raw), "0x%X" % BLOB)
check("MHY[0x104]^0x094C42AB 落在元数据内", 0x1000 < PDV < len(raw), "0x%X" % PDV)

# ---------- 字符串解密（75 个程序集名）----------
SDO = (slot(0x184) + 0xBF9D4735) & M32
def getstr(idx):
    if idx == -1: return ""
    off = idx & 0xFFFFFF; ln = idx >> 24
    base = 0x210 + SDO + off
    if ln == 0 or base + ln + 8 > len(raw): return ""
    key = (0x5C2B4E660E2D0544 * ((0x694418957C890198 * off) ^ 0x55A357D81EF0E48B)) & M64
    out = bytearray()
    for k in range((ln + 7) // 8):
        c = struct.unpack_from('<Q', raw, base + 8 * k)[0]
        out += struct.pack('<Q', c ^ ((key + k * 0x6B0B40C349AE61E5) & M64))
    return bytes(out[:ln]).decode('utf-8', 'replace')

IMGC = (slot(0x02C) - 0x2465B023) & M32
IMGO = (slot(0x20C) - 0x0ECB27F5) & M32
nimg = IMGC // 40
check("imagesCount == 75", nimg == 75, "得到 %d" % nimg)
# 程序集名（ImageIndexKey）
def imgkey(i):
    return (1368137530 * ((667674736 * (((13029 * i) ^ 0x43E2DEB7)) + 0xCB287082F0) >> 8) + 1505552983) & M32
okname = 0
for i in range(min(nimg, 200)):
    e = struct.unpack_from('<I', sm, IMGO + 40 * i + 32)[0]
    nm = getstr((imgkey(i) ^ e ^ 0x772FA51E) & M32)
    if re.match(r'^[A-Za-z0-9_.\-]+\.dll$', nm): okname += 1
check("程序集名解码 (%d/%d)" % (okname, min(nimg, 200)), okname == min(nimg, 200), "应为 100%")

# ---------- 结构计数 ----------
TDCNT = ((slot(0x0E0) - 0x1D064F83) & M32) // 70 - 2
TD    = 0x210 + ((slot(0xB4) - 0x13B75461) & M32)
MCNT  = ((slot(0x188) ^ 0x1B58E334) & M32) // 26
MB    = 0x210 + ((slot(0x16C) - 0x1CCA7654) & M32)
check("typeDefinitionsCount == 88902", TDCNT == 88902, "得到 %d" % TDCNT)
check("methodsCount == 733442", MCNT == 733442, "得到 %d" % MCNT)

# ---------- typeDef 名字里的 `N（泛型锚点）----------
def tname(t):
    return getstr(((struct.unpack_from('<I', raw, TD + 70 * t + 0x24)[0] - 72511848) & M32))
gen = {}
for t in range(TDCNT):
    n = tname(t)
    if '`' in n:
        try: gen[t] = int(n.split('`')[1])
        except Exception: pass
check("泛型类型数 > 500", len(gen) > 500, "%d 个（含 `N 的类型）" % len(gen))

# ---------- parentIndex 锚点：枚举->Enum，结构体->ValueType ----------
# 需要 dump.cs 提供「哪些是枚举/结构体」
def dump_kinds():
    kinds = {}
    cur = None
    with open(DUMP, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if '// TypeDefIndex:' in line and cur is None:
                pass
            m = re.search(r'// TypeDefIndex: (\d+)', line)
            if m and ('enum ' in line or 'struct ' in line or 'class ' in line or 'interface ' in line):
                i = int(m.group(1))
                if re.search(r'\benum\b', line): kinds[i] = 'enum'
                elif re.search(r'\bstruct\b', line): kinds[i] = 'struct'
                elif re.search(r'\binterface\b', line): kinds[i] = 'iface'
                else: kinds[i] = 'class'
    return kinds

if os.path.exists(DUMP):
    kinds = dump_kinds()
    # Il2CppType 数组
    t1o = va2off(T1_VA)
    typesVA = struct.unpack_from('<Q', D, t1o + 0x48)[0]
    to = va2off(typesVA)
    def parent_klass(t):
        p = (struct.unpack_from('<I', raw, TD + 70 * t + 0x18)[0] - 0x3D74901F) & M32
        if p == M32 or p >= 683574: return None
        b = to + 16 * p
        if D[b+10] not in (0x11, 0x12): return None
        return struct.unpack_from('<I', D, b)[0]
    enums = [t for t, k in kinds.items() if k == 'enum' and t < TDCNT]
    structs = [t for t, k in kinds.items() if k == 'struct' and t < TDCNT]
    okE = sum(1 for t in enums if parent_klass(t) == 204)      # System.Enum
    okV = sum(1 for t in structs if parent_klass(t) == 405)    # System.ValueType
    check("parentIndex: 枚举->System.Enum", enums and okE >= 0.98*len(enums), "%d/%d" % (okE, len(enums)))
    check("parentIndex: 结构体->System.ValueType", structs and okV >= 0.98*len(structs), "%d/%d" % (okV, len(structs)))

    # ---------- genericContainerIndex 锚点：argc == 名字里的 N ----------
    GC = 0x210 + ((slot(0x28) ^ 0x774A3BA6) & M32)
    def ckey(c):
        return ((1714760523 * (((1015151837 * (((10661 * c + 1371718001) & M64) ^ 0x146D2C3D)) & M64) ^ 0x5D7F95E0)) & M64) >> 19
    def gci(t):
        r = struct.unpack_from('<H', raw, TD + 70 * t + 0x3E)[0]
        return -1 if r == 26229 else ((r - 26230) & 0xFFFF) - (0x10000 if ((r - 26230) & 0xFFFF) >= 0x8000 else 0)
    okc = 0
    for t, N in gen.items():
        c = gci(t)
        if c >= 0:
            argc = (struct.unpack_from('<I', raw, GC + 16 * c + 8)[0] - ckey(c) - 1053517166) & M32
            if argc == N: okc += 1
    # 小于 N 的例外应只来自嵌套在泛型类里的闭包类型
    check("genericContainerIndex: argc==名字N", okc >= 0.95 * len(gen), "%d/%d" % (okc, len(gen)))

    # ---------- nestedTypes 表：起点互不重叠、恰好铺满 ----------
    NT = 0x210 + ((slot(0x05C) - 381850355) & M32)
    segs = []
    total = 0
    for t in range(TDCNT):
        r = struct.unpack_from('<H', raw, TD + 70 * t + 0x36)[0]
        c = raw[TD + 70 * t + 0x45] ^ 0xBA
        if c:
            s = (r + 6631) & 0xFFFF
            s = s - 0x10000 if s >= 0x8000 else s
            segs.append((s, c)); total += c
    starts = sorted(s for s, _ in segs)
    check("nestedTypes 起点互不重叠", len(set(starts)) == len(starts), "%d 个父" % len(segs))
    endmax = max(s + c for s, c in segs) if segs else 0
    check("nestedTypes 恰好铺满 [0,%d)" % total,
          starts and starts[0] == 0 and endmax == total and sum(c for _, c in segs) == total,
          "总 %d 项, 最大末位 %d" % (total, endmax))

    # ---------- fieldDefaultValues 严格递增 ----------
    n = 0; prev = -1
    while 0x210 + FIELDDEF + 12 * (n + 1) <= len(raw):
        v = struct.unpack_from('<i', raw, 0x210 + FIELDDEF + 12 * n)[0]
        if v <= prev or v < 0: break
        prev = v; n += 1
    check("fieldDefaultValues fieldIndex 严格递增", n > 10000, "连续 %d 项" % n)

    # ---------- parameterDefaultValues 严格递增 ----------
    n = 0; prev = -1
    while 0x210 + PDV + 12 * (n + 1) <= len(raw):
        v = struct.unpack_from('<i', raw, 0x210 + PDV + 12 * n)[0]
        if v <= prev or v < 0: break
        prev = v; n += 1
    check("parameterDefaultValues 严格递增", n > 1000, "连续 %d 项" % n)

    # ---------- dump.cs 统计 ----------
    tot = dict(types=0, base=0, nested=0, generic=0, methods=0, fields=0, props=0,
               propacc=0, events=0, eventacc=0, fieldconst=0, paramdef=0, garbage=0, qmark=0)
    reField = re.compile(r'^\t[^\t].*; // 0x[0-9A-Fa-f]+$')
    reProp  = re.compile(r'\{ (get;|set;|get; set;) \}')
    with open(DUMP, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.rstrip('\n')
            if '\ufffd' in s: tot['garbage'] += 1
            if '// TypeDefIndex:' in s:
                tot['types'] += 1
                d = s.split('//')[0]
                if re.search(r'[A-Za-z0-9_>]:\s*[A-Za-z_]', d): tot['base'] += 1
                head = d.split(':')[0].split()
                if head and '.' in head[-1]: tot['nested'] += 1
                if re.search(r'<[A-Za-z_][A-Za-z0-9_, ]*>\s*$', d.split(':')[0]): tot['generic'] += 1
                continue
            if '// RVA:' in s: continue
            if s.lstrip('\t').startswith('['): continue
            if reProp.search(s):
                tot['props'] += 1
                if re.search(r'// Getter: [A-Za-z_]|// Setter: [A-Za-z_]', s): tot['propacc'] += 1
                continue
            if re.search(r'\bevent \S', s) and '{' in s:
                tot['events'] += 1
                if re.search(r'// Add: [A-Za-z_]|// Remove: [A-Za-z_]', s): tot['eventacc'] += 1
                continue
            if reField.match(s):
                tot['fields'] += 1
                if ' = ' in s: tot['fieldconst'] += 1
                continue
            if '(' in s and ')' in s:
                tot['methods'] += 1
                if '?' in s: tot['qmark'] += 1
                if re.search(r'[(,]\s*[\w\.\<\>\[\]\?]+ \w+ = ', s): tot['paramdef'] += 1
    print()
    check("dump.cs 类型数 == typeDefinitionsCount", tot['types'] == TDCNT, "%d" % tot['types'])
    check("带基类 > 0（parentIndex 生效）", tot['base'] > 1000, "%d" % tot['base'])
    check("嵌套前缀 > 0", tot['nested'] > 1000, "%d" % tot['nested'])
    check("带泛型参数 > 0", tot['generic'] > 100, "%d" % tot['generic'])
    check("属性带访问器名 >= 99%", tot['props'] and tot['propacc'] >= 0.99*tot['props'], "%d/%d" % (tot['propacc'], tot['props']))
    check("事件 628 且都有访问器名", tot['events'] == 628 and tot['eventacc'] == 628, "%d/%d" % (tot['eventacc'], tot['events']))
    check("参数默认值 > 0（未接线会 0）", tot['paramdef'] > 1000, "%d" % tot['paramdef'])
    check("字段常量值 > 0", tot['fieldconst'] > 1000, "%d" % tot['fieldconst'])
    check("乱码行(U+FFFD) < 200", tot['garbage'] < 200, "%d" % tot['garbage'])
    check("签名 '?' 占比 < 8%", tot['methods'] and tot['qmark'] < 0.08*tot['methods'], "%d/%d" % (tot['qmark'], tot['methods']))

    # ---------- 方法 RVA 去重（诱饵表检测）----------
    rvas = {}
    with open(DUMP, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if '// RVA: ' in line and 'Offset:' in line:
                m = re.match(r'// RVA: 0x([0-9A-Fa-f]+) Offset: 0x([0-9A-Fa-f]+) VA: 0x([0-9A-Fa-f]+)', line.strip())
                if m:
                    va = 0x140000000 + int(m.group(1), 16)
                    rvas[va] = rvas.get(va, 0) + 1
    if rvas:
        n = sum(rvas.values())
        check("方法 RVA 去重率 > 90%", len(rvas) >= 0.9*n, "%d 不同 / %d 条" % (len(rvas), n))
        top = max(rvas.values())
        check("单一 RVA 共用 < 1000 次（诱饵表会到几十万）", top < 1000, "最多 %d 次" % top)
else:
    print("\n(未找到 dump.cs，跳过输出侧检查)")

print("\n" + "=" * 60)
bad = [n for n, ok, _ in RESULTS if not ok]
print("总计 %d 项，FAIL %d 项" % (len(RESULTS), len(bad)))
if bad:
    print("失败项：")
    for n in bad: print("   -", n)
    sys.exit(1)
print("全部通过。")
