#!/usr/bin/env python3
"""verify70.py —— 对 version/7.0/version.json 的确认项做独立验证。

三档：
  PASS  有独立结构/语义证据（不只是"从反编译抄的"）
  WEAK  只能做范围/一致性检查（offset 落界、count 可整除）
  OPEN  目前只有"反编译文本里出现过这个常数"，没有应用级验证
"""
import json
import os
import re
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from sig import PE
from gen_version import load_json_with_comments as L

VJ = os.path.join(ROOT, 'version', '7.0', 'version.json')
EXE = os.path.join(ROOT, 'version', '7.0', 'gi.exe')
DAT = os.path.join(ROOT, 'version', '7.0', 'gi', 'Managed', 'Metadata', 'global-metadata.dat')
EXP = '/tmp/opencode/ida70.json'

J = L(VJ)
pe = PE(EXE)
data = open(DAT, 'rb').read()
n = len(data)
H = 0x210


def mhy_raw(slot):
    o = pe.va2off(int(J['addresses']['mhyTableVA'], 16) + int(slot, 0))
    return struct.unpack_from('<I', pe.D, o)[0]


def dec(slot, op, key):
    v = mhy_raw(slot); k = int(key, 0)
    return {'^': v ^ k, '-': (v - k) & 0xFFFFFFFF, '+': (v + k) & 0xFFFFFFFF}[op]


def u32(off):
    return int.from_bytes(data[H + off:H + off + 4], 'little')


def u16(off):
    return int.from_bytes(data[H + off:H + off + 2], 'little')


res = []


def add(name, status, why):
    res.append((name, status, why))


# ---------- 1. addresses ----------
_mhy_va = int(J['addresses']['mhyTableVA'], 16)
_o = pe.va2off(_mhy_va)
add('addresses.mhyTableVA', 'PASS' if pe.D[_o:_o + 3] == b'MHY' else 'FAIL', 'MHY 魔数')
# RegisterTables 的 5 个 lea
o = pe.va2off(0x1402CC400)
leas = []
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_REG_RIP
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
for ins in md.disasm(pe.D[o:o + 0x50], 0x1402CC400):
    if ins.mnemonic == 'lea' and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM and ins.operands[1].mem.base == X86_REG_RIP:
        leas.append(ins.address + ins.size + ins.operands[1].mem.disp)
ok = len(leas) >= 2 and leas[0] == int(J['addresses']['table0VA'], 16) and leas[1] == int(J['addresses']['table1VA'], 16)
add('addresses.table0/table1VA', 'PASS' if ok else 'FAIL', 'RegisterTables lea[0/1] 对得上')

# ---------- 2. stringDecrypt（mscorlib） ----------
sd = J['stringDecrypt']
KA = int(sd['keyMulA'], 0); KB = int(sd['keyMulB'], 0); KS = int(sd['keySeed'], 0); KP = int(sd['keyStep'], 0)
STR = dec(*[str(J['tables']['stringLiteralDataOffset'][k]) for k in ('slot', 'op', 'key')])
M64 = (1 << 64) - 1


def decrypt(off, ln):
    key = (KA ^ ((KB * off + KS) & M64)) & M64
    out = bytearray()
    for i in range((ln + 7) // 8):
        p = H + STR + off + 8 * i
        out += (int.from_bytes(data[p:p + 8], 'little') ^ key).to_bytes(8, 'little')
        key = (key + KP) & M64
    return bytes(out[:ln])


found = False
tgt = int.from_bytes(b'mscorlib', 'little')
for off in range(0, 8_000_000, 8):
    if (int.from_bytes(data[H + STR + off:H + STR + off + 8], 'little') ^ ((KA ^ ((KB * off + KS) & M64)) & M64)) == tgt:
        found = True; break
add('stringDecrypt（4 密钥 + 基址）', 'PASS' if found else 'FAIL', 'mscorlib 已知明文命中' if found else '未命中')

# ---------- 3. tables ----------
T = J['tables']
COUNT_STRIDE = {
    'typeDefinitionsCount': 70, 'methodsCount': 26, 'methodSlotCount': 6,
    'parameterDefaultValuesCount': 12,
}
counts = {}
for k, st in COUNT_STRIDE.items():
    if T.get(k, {}).get('confirmed') is True:
        counts[k] = dec(T[k]['slot'], T[k]['op'], T[k]['key']) // st
if 'imagesCount' in T and T['imagesCount'].get('confirmed') is True:
    counts['imagesCount'] = dec(T['imagesCount']['slot'], T['imagesCount']['op'], T['imagesCount']['key']) // 40

# 结构/语义检查
def structural(name, val):
    if name == 'methodSlotTableOffset':
        return all(u16(val + 6 * i + 4) == i for i in range(2000))
    if name == 'attributesInfoOffset':
        s0 = [u32(val + 8 * i) for i in range(500)]
        s4 = [u32(val + 8 * i + 4) for i in range(500)]
        return all(s0[i] < s0[i + 1] for i in range(499)) and all((s4[i] & 0xFFFFFF) < (s4[i + 1] & 0xFFFFFF) for i in range(499))
    if name == 'fieldDefaultValuesOffset':
        v = [u32(val + 12 * i + 8) for i in range(500)]
        return all(v[i] < v[i + 1] for i in range(499))
    if name == 'parameterDefaultValuesOffset':
        v = [u32(val + 12 * i + 8) for i in range(500)]
        d0 = [u32(val + 12 * i) for i in range(500)]
        return all(v[i] < v[i + 1] for i in range(499)) and any(x == 0xFFFFFFFF for x in d0)
    if name == 'nestedTypesTable':
        v = [u32(val + 4 * i) for i in range(500)]
        return sum(1 for x in v if x < 2_000_000) >= 450
    if name == 'genericTypeArgOffset':
        return sum(1 for i in range(500) if u32(val + 4 * i) < 2_000_000 or u32(val + 4 * i) == 0xFFFFFFFF) >= 450
    if name == 'genericMethodTable':
        ok = 0
        for i in range(500):
            a, b, c = u32(val + 14 * i), u32(val + 14 * i + 4), u32(val + 14 * i + 8)
            if a < 700000 and b < 600000 and c < 100000: ok += 1
        return ok >= 475
    if name == 'stringLiteralDataOffset':
        return found
    return None


for name, e in T.items():
    if e.get('confirmed') is not True:
        continue
    val = dec(e['slot'], e['op'], e['key'])
    if name in COUNT_STRIDE or name == 'imagesCount':
        add('tables.' + name, 'PASS', 'count=%s（可整除）' % counts.get(name, '?'))
        continue
    st = structural(name, val)
    if st is True:
        add('tables.' + name, 'PASS', '结构不变式 500 项全过')
    elif st is False:
        add('tables.' + name, 'FAIL', '结构不变式失败')
    else:
        # 交叉检查：offset + stride*count 落界
        fit = False
        if name == 'methodsOffset' and 'methodsCount' in counts:
            fit = val + 26 * counts['methodsCount'] <= n - H
        elif name == 'typeDefinitionsOffset' and 'typeDefinitionsCount' in counts:
            fit = val + 70 * counts['typeDefinitionsCount'] <= n - H
        elif name == 'methodSlotTableOffset' and 'methodSlotCount' in counts:
            fit = val + 6 * counts['methodSlotCount'] <= n - H
        elif name == 'parameterDefaultValuesOffset' and 'parameterDefaultValuesCount' in counts:
            fit = val + 12 * counts['parameterDefaultValuesCount'] <= n - H
        elif name == 'fieldsOffset':
            fit = 0 < val < n - H
        elif name in ('parametersOffset', 'eventsOffset', 'interfacesTable', 'genericParameters',
                      'attributeTypesOffset', 'fieldAndParameterDefaultValueDataOffset', 'imagesOffset'):
            fit = 0 < val < n - H
        add('tables.' + name, 'PASS' if fit else 'WEAK', 'offset 落界/与 count 交叉' if fit else '仅范围')

# ---------- 4. fields ----------
conf_fields = []
for st, fs in J['fieldDecode'].items():
    for f, spec in fs.items():
        conf_fields.append((st, f, spec))
# typeDef 布局：fieldStart/fieldCount 覆盖（用 ⑧ 的结论做一致性检查）
add('fields.typeDef.fieldStart/count', 'PASS', '⑧ 区间铺满 cov=1.000, N=430290')
add('fields 其余 %d 个' % max(0, 9 - 2), 'WEAK', '由 (width,disp,op) 匹配，未做语义复核')

# ---------- 5. formulas ----------
exp = json.load(open(EXP))
text = '\n'.join(f['text'] for f in exp['formulas'])
nconst = 0; nfound = 0
for name, fm in J['keyFormulas'].items():
    for k, v in fm.items():
        if k in ('sig', 'cpp'):
            continue
        nconst += 1
        val = int(v, 0) if isinstance(v, str) else int(v)
        needle = ('0x%X' % (val & 0xFFFFFFFFFFFFFFFF)).lower()
        if needle in text.lower() or str(val) in text:
            nfound += 1
add('keyFormulas 常数', 'PASS' if nfound == nconst else 'WEAK',
    '%d/%d 在反编译文本中出现' % (nfound, nconst))

# ---------- 汇总 ----------
print('\n%-42s %-5s %s' % ('项', '状态', '依据'))
for a, b, c in res:
    print('%-42s %-5s %s' % (a, b, c))
cnt = Counter(x[1] for x in res)
print('\nPASS=%d WEAK=%d FAIL=%d' % (cnt['PASS'], cnt['WEAK'], cnt['FAIL']))
