#!/usr/bin/env python3
"""table_roles.py —— 按“表角色”从 IDA 候选里选目标表。

不依赖目标 version.json；只用：
  · 上一版 version.json（角色/stride/side）
  · 目标 ida.json 的候选表（value/funcs/strides/callees）
  · 目标 global-metadata.dat（结构自证）

用法:
    python3 tools/table_roles.py version/7.0 \
        --draft version/7.0/version.draft.json \
        --ida version/7.0/ida.json --base version.json
"""
import argparse
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_version import load_json_with_comments  # noqa: E402

H = 0x210
ALLOWED_STRIDES = {4, 6, 8, 10, 12, 14, 16, 26, 40}


def enrich_table_strides(root, tables):
    """从反编译数据流补全候选表的 stride/divisor 证据。

    旧 ida.json 只有 slot/op/key/value/funcs。这里同时记录：
      · muls：`lhs + 8 * i` / `26 * i` 这类索引步长；
      · divs：`... / 0x28` / `... >> 3` 这类计数/字节数证据。
    两者分开，避免把 count 表的 `/14` 误当成 14 字节 offset 表。
    """
    import glob as _glob
    texts = []
    for f in _glob.glob(os.path.join(root, 'ida', 'decomp', '*.c')):
        try:
            texts.append(open(f, encoding='utf-8', errors='ignore').read().splitlines())
        except Exception:
            pass
    if not texts:
        return
    for t in tables:
        try:
            slot = int(str(t.get('slot', '0')), 0)
        except Exception:
            continue
        if slot <= 0:
            continue
        pat = re.compile(r'g_MHY_Table\s*\+\s*(0x%X|%d)\b' % (slot, slot))
        muls, divs = set(), set()
        for lines in texts:
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                # 先看当前行和紧邻两行（很多表达式跨行）。
                win = '\n'.join(lines[max(0, i - 1):i + 3])
                for m in re.finditer(r'(?<![\w.])(\d+)\s*(?:LL|ll|L)?\s*\*\s*', win):
                    n = int(m.group(1))
                    if n in ALLOWED_STRIDES:
                        muls.add(n)
                for m in re.finditer(r'/\s*(0x[0-9A-Fa-f]+|\d+)', win):
                    n = int(m.group(1), 0)
                    if n in ALLOWED_STRIDES:
                        divs.add(n)
                for m in re.finditer(r'>>\s*(\d+)', win):
                    n = 1 << int(m.group(1))
                    if n in ALLOWED_STRIDES:
                        divs.add(n)
                # 再做局部变量数据流：`vX = MHY[slot] ...` 后 12 行内的 vX 用法。
                lm = re.match(r'\s*(\w+)\s*=', line)
                if not lm:
                    continue
                lhs = lm.group(1)
                for j in range(i + 1, min(i + 13, len(lines))):
                    ln = lines[j]
                    if lhs not in ln:
                        continue
                    for m in re.finditer(re.escape(lhs) + r'\s*\+\s*(\d+)\s*(?:LL|ll|L)?\s*\*', ln):
                        n = int(m.group(1))
                        if n in ALLOWED_STRIDES:
                            muls.add(n)
                    for m in re.finditer(r'(\d+)\s*(?:LL|ll|L)?\s*\*\s*' + re.escape(lhs) + r'\b', ln):
                        n = int(m.group(1))
                        if n in ALLOWED_STRIDES:
                            muls.add(n)
                    for m in re.finditer(r'/\s*(0x[0-9A-Fa-f]+|\d+)', ln):
                        n = int(m.group(1), 0)
                        if n in ALLOWED_STRIDES:
                            divs.add(n)
        if muls:
            t['muls'] = sorted(set(t.get('muls') or []) | muls)
            t['strides'] = sorted(set(t.get('strides') or []) | muls)
        if divs:
            t['divs'] = sorted(set(t.get('divs') or []) | divs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--draft', required=True)
    ap.add_argument('--ida', default=None)
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, 'version', a.root)
    if not os.path.isdir(root):
        root = a.root
    D = load_json_with_comments(a.draft)
    base = load_json_with_comments(a.base)
    ida = json.load(open(a.ida or os.path.join(root, 'ida.json'), encoding='utf-8'))
    dat = open(os.path.join(root, 'gi', 'Managed', 'Metadata', 'global-metadata.dat'), 'rb').read()
    cand = []
    for t in ida.get('tables', []):
        try:
            v = int(str(t.get('value', '0')), 0)
        except Exception:
            continue
        if 0 < v < len(dat) - H:
            cand.append((t, v))

    # 0) 先判断旧读序是否已经明显违反 typeDefs -> methodSlot 的硬约束。
    # 只有违反时才启用新的语义规则和 stride 证据；7.0/7.1 保持原有算法。
    def _table_val(name):
        try:
            tb = D['tables'][name]
            import sig as _S
            pe_ = _S.PE(os.path.join(root, 'gi.exe'))
            mhy_ = int(str(D.get('addresses', {}).get('mhyTableVA', '0')), 0)
            raw = struct.unpack_from('<I', pe_.D, pe_.va2off(mhy_ + int(str(tb['slot']), 0)))[0]
            k = int(str(tb['key']), 0)
            return {'^': raw ^ k, '-': (raw - k) & 0xFFFFFFFF,
                    '+': (raw + k) & 0xFFFFFFFF}[tb['op']]
        except Exception:
            return None

    semantic_needed = False
    try:
        td0 = _table_val('typeDefinitionsOffset')
        tdc0 = _table_val('typeDefinitionsCount')
        msot0 = _table_val('methodSlotTableOffset')
        if td0 is not None and tdc0 is not None and msot0 is not None:
            end0 = td0 + (tdc0 // 70) * 70
            # 7.0 的 methodSlot 在 typeDefs 之前，这是已验证布局，不要触发语义重算。
            # 6.7 冷启动时旧读序会落到 typeDefs 之后很远的位置，才是真正异常。
            if msot0 < end0:
                semantic_needed = False
            else:
                semantic_needed = not (end0 <= msot0 <= end0 + 0x1000)
        else:
            semantic_needed = True
    except Exception:
        semantic_needed = True

    if semantic_needed:
        enrich_table_strides(root, ida.get('tables', []))

    def apply(name, t):
        if name not in D.get('tables', {}):
            return
        e = dict(D['tables'][name])
        e['slot'] = t['slot']
        e['op'] = t['op']
        e['key'] = t['key']
        D['tables'][name] = e

    # 1) fieldsOffset：字段表，8 字节，SetupFieldsLocked/GetFieldName
    for t, v in cand:
        if 8 in (t.get('strides') or []) and any(
                'SetupFieldsLocked' in f or 'GetFieldName' in f for f in (t.get('funcs') or [])):
            apply('fieldsOffset', t)
            break

    # 2) fieldOffset：同一函数里的 4 字节偏移表，值明显小于 fieldsOffset
    fsv = None
    try:
        fsv = int(str(D['tables']['fieldsOffset'].get('slot')), 0)
    except Exception:
        pass
    fo = [(t, v) for t, v in cand if any('SetupFieldsLocked' in f for f in (t.get('funcs') or []))]
    fo = [(t, v) for t, v in fo if v < 0x1000000]
    if fo:
        # 取最小的非零值（字段偏移表在 metadata 前部）
        t, v = min(fo, key=lambda x: x[1])
        apply('fieldOffset', t)

    # 3) methodSpecs：12 字节
    for t, v in cand:
        if 12 in (t.get('strides') or []):
            apply('methodSpecs', t)
            break

    # 4) attributeTypesOffset：SetupTypeInfoLocked 里的 4 字节表，调用 bsearch
    for t, v in cand:
        if any('SetupTypeInfoLocked' in f for f in (t.get('funcs') or [])) and \
           any('bsearch' in str(x) for x in (t.get('callees') or [])):
            apply('attributeTypesOffset', t)
            break

    # 5) attributesInfoOffset：8 字节结构，start/token 单调
    def attr_score(off):
        try:
            starts = [int.from_bytes(dat[H + off + 8 * i:H + off + 8 * i + 4], 'little') for i in range(500)]
            toks = [int.from_bytes(dat[H + off + 8 * i + 4:H + off + 8 * i + 8], 'little') & 0xFFFFFF for i in range(500)]
        except Exception:
            return 0
        s1 = sum(1 for x, y in zip(starts, starts[1:]) if y > x) / 499
        s2 = sum(1 for x, y in zip(toks, toks[1:]) if y > x) / 499
        return s1 + s2
    best = None
    for t, v in cand:
        if any('SetupTypeInfoLocked' in f for f in (t.get('funcs') or [])):
            sc = attr_score(v)
            if best is None or sc > best[0]:
                best = (sc, t)
    if best and best[0] > 1.5:
        apply('attributesInfoOffset', best[1])

    # 6) genericTypeArgOffset：RuntimeInit 里 14 字节步长的 startup 表
    for t, v in cand:
        if any('RuntimeInit' in f for f in (t.get('funcs') or [])) and 14 in (t.get('strides') or []):
            apply('genericTypeArgOffset', t)
            break

    # 7) genericClassRangeOffset：RuntimeInit 里值为 0 的 startup 表
    for t in ida.get('tables', []):
        try:
            v = int(str(t.get('value', '1')), 0)
        except Exception:
            continue
        if v == 0 and any('RuntimeInit' in f for f in (t.get('funcs') or [])):
            apply('genericClassRangeOffset', t)
            break

    # 8) genericMethodTable / Count：两者之和 == methodPointerIndexOffset
    mp = None
    try:
        import sig as S
        mhy = int(str(D['addresses']['mhyTableVA']), 0)
        pe = S.PE(os.path.join(root, 'gi.exe'))
        tb = D['tables']['methodPointerIndexOffset']
        raw = struct.unpack_from('<I', pe.D, pe.va2off(mhy + int(str(tb['slot']), 0)))[0]
        k = int(str(tb['key']), 0)
        mp = {'^': raw ^ k, '-': (raw - k) & 0xFFFFFFFF, '+': (raw + k) & 0xFFFFFFFF}[tb['op']]
    except Exception:
        pass
    if mp:
        rc = [(t, v) for t, v in cand if any('RuntimeInit' in f for f in (t.get('funcs') or [])) and v]
        pair = None
        for i in range(len(rc)):
            for j in range(i + 1, len(rc)):
                if rc[i][1] + rc[j][1] == mp:
                    pair = (rc[i], rc[j])
                    break
            if pair:
                break
        if pair:
            a1, a2 = sorted(pair, key=lambda x: x[1])
            apply('genericMethodTable', a1[0])
            apply('genericMethodTableCount', a2[0])

    # 8.1) nestedTypesTable：用 typeDef 的 nestedTypesStart/Count 反查 4 字节表
    try:
        fdd = json.load(open(os.path.join(root, 'ida', 'fielddecode.auto.json'), encoding='utf-8'))
        fd = fdd.get('fieldDecode', {}).get('typeDef', {})
        def dec_spec(raw, spec):
            op, _, k = spec.partition(':'); k = int(k, 0)
            op = {'sub': '-', 'add': '+', 'xor': '^'}.get(op, op)
            return {'^': raw ^ k, '-': (raw - k) & 0xFFFFFFFF, '+': (raw + k) & 0xFFFFFFFF}[op]
        td = None
        try:
            import sig as S
            mhy = int(str(D['addresses']['mhyTableVA']), 0)
            pe = S.PE(os.path.join(root, 'gi.exe'))
            tb = D['tables']['typeDefinitionsOffset']
            raw = struct.unpack_from('<I', pe.D, pe.va2off(mhy + int(str(tb['slot']), 0)))[0]
            td = {'^': raw ^ int(str(tb['key']), 0),
                  '-': (raw - int(str(tb['key']), 0)) & 0xFFFFFFFF,
                  '+': (raw + int(str(tb['key']), 0)) & 0xFFFFFFFF}[tb['op']]
        except Exception:
            pass
        if td and 'nestedTypesStart' in fd and 'nestedTypesCount' in fd:
            type_count = 0
            try:
                type_count = int(len(dat) / 70)  # 仅用于上界
            except Exception:
                type_count = 1 << 20
            samples = []
            total = 0
            for i in range(min(20000, (len(dat) - H - td) // 70)):
                p = H + td + 70 * i
                st = dec_spec(int.from_bytes(dat[p + 52:p + 54], 'little'), fd['nestedTypesStart']) & 0xFFFF
                ct = dec_spec(dat[p + 65], fd['nestedTypesCount']) & 0xFF
                if ct:
                    samples.append((st, ct))
                    total = max(total, st + ct)
            if samples:
                fs = None
                try:
                    fs = int(str(D['tables']['fieldsOffset'].get('slot')), 0)
                except Exception:
                    pass
                lo = max(0, (fs or 0x3e00000) - 0x400000)
                hi = min(len(dat) - H - total * 4, (fs or 0x3e00000) + 0x400000)
                best = None
                for o in range(lo, hi, 4):
                    if o < 0:
                        continue
                    ok = 0
                    for st, ct in samples[:40]:
                        if all(int.from_bytes(dat[H + o + 4 * (st + j):H + o + 4 * (st + j) + 4], 'little') < (1 << 20)
                               for j in range(min(ct, 8))):
                            ok += 1
                    if ok >= len(samples[:40]) * 0.95:
                        best = o
                        break
                if best is not None:
                    # 反查 slot/op/key：直接构造 Table 值，slot 用 RuntimeInit 里的候选
                    # 这里只改 value，slot/op/key 从候选里找同值的；没有就保留原 slot。
                    hit = None
                    for t, v in cand:
                        if v == best:
                            hit = t; break
                    if hit:
                        apply('nestedTypesTable', hit)
    except Exception:
        pass

    # 8.2) addresses.table0/table1：RegisterTables 里的两个 &unk_
    try:
        import glob as _glob
        for p in _glob.glob(os.path.join(root, 'ida', 'decomp', 'GIMeta_RegisterTables_*.c')):
            tx = open(p, encoding='utf-8', errors='ignore').read()
            vals = re.findall(r'&(?:unk|off)_([0-9A-Fa-f]+)', tx)
            if len(vals) >= 2:
                D.setdefault('addresses', {})['table0VA'] = '0x' + vals[0]
                D.setdefault('addresses', {})['table1VA'] = '0x' + vals[1]
            if 'codeRegistration' not in tx.lower():
                D.setdefault('addresses', {})['codeRegistrationVA'] = '0x0'
            break
    except Exception:
        pass

    # 8.3) stringDecrypt.entryXor：旧常数若在 DecryptString 里消失，说明公式已变（7.0 = xor:0）
    try:
        import glob as _glob
        old_xor = str(base.get('stringDecrypt', {}).get('entryXor', ''))
        if old_xor:
            found = False
            for p in _glob.glob(os.path.join(root, 'ida', 'decomp', 'GIMeta_DecryptString_*.c')):
                tx = open(p, encoding='utf-8', errors='ignore').read().lower()
                if old_xor.lower().replace('0x', '') in tx:
                    found = True
                    break
            if not found:
                D.setdefault('stringDecrypt', {})['entryXor'] = '0x0'
    except Exception:
        pass

    # 8.4) 结构/语义优先的 7.1 布局角色（候选来自目标自身读取点）
    # 只在目标确实出现“stride=4 的 fieldOffset”或“base=qword 的 genericClassRange”
    # 时启用，避免把旧版本已有的人工结果覆盖掉。
    tabs = ida.get('tables', [])

    def tf(t):
        try:
            return int(str(t.get('value', '0')), 0)
        except Exception:
            return None

    def hasf(t, name):
        return name in (t.get('funcs') or [])

    def callees(t):
        return [str(x) for x in (t.get('callees') or []) if str(x).startswith('sub_')]

    adv_setup = any(hasf(t, 'GIMeta_SetupTypeInfoLocked') and 4 in (t.get('strides') or [])
                    for t in tabs)
    adv_runtime = any(hasf(t, 'GIMeta_RuntimeInit') and 0 < (tf(t) or 0) < 0x100000
                      and str(t.get('base', '')).startswith('qword')
                      and not t.get('strides') and not callees(t)
                      for t in tabs)

    if adv_setup:
        # fieldOffset / methodSlotTableOffset：stride 分别是 4 / 6
        for nm, stride in (('fieldOffset', 4), ('methodSlotTableOffset', 6)):
            xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
                  and stride in (t.get('strides') or [])]
            if len(xs) == 1:
                apply(nm, xs[0])

        setup = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
                 and tf(t) is not None and not t.get('strides')]
        # attributesInfoOffset / Count：同一 bsearch 调用的两个候选，值一大一小
        pair = None
        groups = {}
        for t in setup:
            for c in callees(t):
                groups.setdefault(c, []).append(t)
        for c, xs in groups.items():
            vals = [tf(t) for t in xs]
            if len(xs) >= 2 and max(vals) != min(vals) and max(vals) > 0x100000:
                pair = (max(xs, key=lambda t: tf(t)), min(xs, key=lambda t: tf(t)))
                break
        if pair:
            apply('attributesInfoOffset', pair[0])
            apply('attributesInfoCount', pair[1])
            # methodSlotCount：剩余的“小计数”候选
            rest = [t for t in setup if t not in pair and 0 < (tf(t) or 0) < 0x100000]
            if len(rest) == 1:
                apply('methodSlotCount', rest[0])
            # attributeTypesOffset：剩余无 base、无 callee 的候选里值最大的一个
            rest = [t for t in setup if t not in pair and not t.get('base') and not callees(t)
                    and (tf(t) or 0) > 0x100000]
            if rest:
                apply('attributeTypesOffset', max(rest, key=lambda t: tf(t)))
        # interfacesTable：SetupTypeInfoLocked 读到的最大表偏移
        xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked') and tf(t)
              and not t.get('strides')]
        if xs:
            apply('interfacesTable', max(xs, key=lambda t: tf(t)))

        # methodSpecs：RuntimeInit / SetupTypeInfoLocked 读到的 12 字节表
        xs = [t for t in tabs if 12 in (t.get('strides') or [])
              and (hasf(t, 'GIMeta_RuntimeInit') or hasf(t, 'GIMeta_SetupTypeInfoLocked'))]
        if xs:
            apply('methodSpecs', max(xs, key=lambda t: tf(t) or 0))

        # 默认值 blob：同时被 field/parameter 两个读取函数使用
        xs = [t for t in tabs if hasf(t, 'GIMeta_GetFieldDefaultValue')
              and hasf(t, 'GIMeta_GetDefaultParameterValueObject')]
        if len(xs) == 1:
            apply('fieldAndParameterDefaultValueDataOffset', xs[0])

        # parameterDefaultValuesOffset：同一函数里较大的偏移（另一个是小计数）
        xs = [t for t in tabs if hasf(t, 'GIMeta_GetDefaultParameterValueObject') and tf(t)]
        if xs:
            apply('parameterDefaultValuesOffset', max(xs, key=lambda t: tf(t)))

    if adv_runtime:
        # genericClassRangeOffset：qword base、无 stride/callee 的小偏移
        xs = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit')
              and str(t.get('base', '')).startswith('qword') and not t.get('strides')
              and not callees(t) and 0 < (tf(t) or 0) < 0x100000]
        if len(xs) == 1:
            apply('genericClassRangeOffset', xs[0])
            # 该版本 genericTypeArgOffset 读到的地址为 0
            zeros = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit') and tf(t) == 0]
            if zeros:
                apply('genericTypeArgOffset', zeros[0])

        # genericMethodTable：14/16 字节步长的最大表
        xs = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit')
              and any(st in (t.get('strides') or []) for st in (14, 16))
              and (tf(t) or 0) > 0x100000]
        if xs:
            apply('genericMethodTable', max(xs, key=lambda t: tf(t)))

        # genericMethodTableCount：无 base、带分配器 callee 的候选
        xs = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit')
              and not t.get('base') and callees(t) and tf(t)]
        if xs:
            apply('genericMethodTableCount', max(xs, key=lambda t: tf(t)))

        # imagesOffset：用 startup-metadata.dat 的程序集名做结构自证
        try:
            import re as _re
            import struct as _struct
            import sig as _S
            from json_coverage import eval_formula as _evalf
            startup_p = os.path.join(root, 'gi', 'Managed', 'Metadata', 'startup-metadata.dat')
            if os.path.exists(startup_p):
                sm = open(startup_p, 'rb').read()
                pe = _S.PE(os.path.join(root, 'gi.exe'))
                mhy = int(str(D.get('addresses', {}).get('mhyTableVA', '0')), 0)
                def tval(name):
                    tb = D['tables'][name]
                    raw = _struct.unpack_from('<I', pe.D, pe.va2off(mhy + int(str(tb['slot']), 0)))[0]
                    k = int(str(tb['key']), 0)
                    return {'^': raw ^ k, '-': (raw - k) & 0xFFFFFFFF,
                            '+': (raw + k) & 0xFFFFFFFF}[tb['op']]
                sd = D.get('stringDecrypt', {})
                kf = {}
                kfp = os.path.join(root, 'ida', 'keyformulas.auto.json')
                if os.path.exists(kfp):
                    kf = json.load(open(kfp, encoding='utf-8'))
                if 'imageKey' in kf and sd:
                    A = int(str(sd['keyMulA']), 0); B = int(str(sd['keyMulB']), 0)
                    S = int(str(sd['keySeed']), 0); P = int(str(sd['keyStep']), 0)
                    ex = int(str(sd.get('entryXor', '0')), 0)
                    STR = tval('stringLiteralDataOffset')
                    nameoff = int(D['structOffsets']['Il2CppImageDefinition']['nameIndex'])
                    nimg = max(1, min(20, int(D['tables']['imagesCount'] and 20)))
                    def dec(v):
                        off = v & 0xFFFFFF; ln = (v >> 24) & 0xFF
                        if ln == 0 or off + STR + 16 > len(dat):
                            return b''
                        first = None
                        for mode in (0, 1):
                            key = ((A ^ ((B * off + S) & ((1 << 64) - 1))) if mode == 0
                                   else (A * ((B * off) ^ S)) & ((1 << 64) - 1))
                            o = bytearray()
                            for q in range((ln + 7) // 8):
                                p = H + STR + off + 8 * q
                                o += (int.from_bytes(dat[p:p + 8], 'little') ^ key).to_bytes(8, 'little')
                                key = (key + P) & ((1 << 64) - 1)
                            b = bytes(o[:ln])
                            if first is None:
                                first = b
                            if all(0x20 <= c < 0x7F for c in b):
                                return b
                        return first or b''
                    best = None
                    for t in tabs:
                        v = tf(t)
                        if not hasf(t, 'GIMeta_RuntimeInit') or not v or v + 40 * nimg > len(sm):
                            continue
                        ok = 0
                        for i in range(nimg):
                            raw = _struct.unpack_from('<I', sm, v + 40 * i + nameoff)[0]
                            k = _evalf(kf['imageKey'], i)
                            nm = dec((raw ^ k ^ ex) & 0xFFFFFFFF)
                            if _re.match(rb'^[A-Za-z0-9_.\-]+\.dll$', nm):
                                ok += 1
                        if best is None or ok > best[0]:
                            best = (ok, t)
                    if best and best[0] >= max(1, nimg // 2):
                        apply('imagesOffset', best[1])
        except Exception:
            pass

    # 8.5) 内容/结构语义优先：只用目标 decomp + metadata + 已恢复的布局做判定。
    #     这些规则在旧读序规则之后执行，语义证据充分时覆盖旧结果。
    def table_val(name):
        try:
            tb = D['tables'][name]
            import sig as _S
            pe_ = _S.PE(os.path.join(root, 'gi.exe'))
            mhy_ = int(str(D.get('addresses', {}).get('mhyTableVA', '0')), 0)
            raw = struct.unpack_from('<I', pe_.D, pe_.va2off(mhy_ + int(str(tb['slot']), 0)))[0]
            k = int(str(tb['key']), 0)
            return {'^': raw ^ k, '-': (raw - k) & 0xFFFFFFFF,
                    '+': (raw + k) & 0xFFFFFFFF}[tb['op']]
        except Exception:
            return None

    def one(cands_):
        seen = []
        for t in cands_:
            if t not in seen:
                seen.append(t)
        return seen

    # 语义开关在进入旧规则前已经算好（semantic_needed）。
    old_tables = json.loads(json.dumps(D.get('tables', {})))
    assigned_sem = set()

    # typeDefs 末尾之后的第一个 SetupTypeInfo 表就是 methodSlotTableOffset。
    try:
        td = table_val('typeDefinitionsOffset')
        tdc = table_val('typeDefinitionsCount')
        if td is not None and tdc is not None:
            end = td + (tdc // 70) * 70
            xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
                  and (tf(t) or 0) >= end and (tf(t) or 0) <= end + 0x1000]
            if len(xs) == 1:
                apply('methodSlotTableOffset', xs[0]); assigned_sem.add('methodSlotTableOffset')
            # 6 字节的“小计数”与紧邻 typeDefs 末尾的 offset 配对。
            xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
                  and 6 in (t.get('divs') or []) and 0 < (tf(t) or 0) < 0x100000]
            xs = [t for t in xs if t.get('slot') != D.get('tables', {}).get('methodSlotTableOffset', {}).get('slot')]
            if xs:
                apply('methodSlotCount', min(xs, key=lambda t: tf(t) or 0))
                assigned_sem.add('methodSlotCount')
    except Exception:
        pass

    # fieldOffset：4 字节、值为普通字段偏移（0x10/0x18/...），而不是旧版的静态标志表。
    xs = [t for t in tabs if hasf(t, 'GIMeta_SetupFieldsLocked')
          and 4 in (t.get('muls') or []) and 0 < (tf(t) or 0) < 0x1000000]
    if xs:
        def small_int_score(t):
            v = tf(t) or 0
            try:
                import sig as _S
                pe_ = _S.PE(os.path.join(root, 'gi.exe'))
                vals = [struct.unpack_from('<I', pe_.D, pe_.va2off(int(str(D.get('addresses', {}).get('mhyTableVA', '0')), 0) + int(str(t['slot']), 0)))[0] for _ in range(1)]
                # 取表本身前 64 项；这里必须用解码后的 value，而不是 slot 原值。
                off = v
                vals = [struct.unpack_from('<I', dat, H + off + 4 * i)[0] for i in range(min(64, max(1, (len(dat) - H - off) // 4)))]
                return sum(1 for x in vals if 0 < x < 0x10000) / max(1, len(vals))
            except Exception:
                return 0.0
        t = max(xs, key=small_int_score)
        if small_int_score(t) >= 0.5:
            apply('fieldOffset', t); assigned_sem.add('fieldOffset')

    # methodSpecs：12 字节，且读取函数是 SetupTypeInfo/RuntimeInit。
    xs = [t for t in tabs if 12 in (t.get('muls') or [])
          and (hasf(t, 'GIMeta_SetupTypeInfoLocked') or hasf(t, 'GIMeta_RuntimeInit'))]
    xs = one(xs)
    if len(xs) == 1:
        apply('methodSpecs', xs[0]); assigned_sem.add('methodSpecs')

    # genericContainers/genericParameters：16/14 字节步长。
    xs = one([t for t in tabs if 16 in (t.get('muls') or [])
              and (hasf(t, 'GIMeta_GetGenericParameterInfo')
                   or hasf(t, 'GIMeta_GetGenericMethodParamInfo')
                   or hasf(t, 'GIMeta_SetupNestedLocked'))])
    pure = [x for x in xs if (x.get('muls') or []) == [16]]
    chosen = pure if len(pure) == 1 else (xs if len(xs) == 1 else [])
    if len(chosen) == 1:
        apply('genericContainers', chosen[0]); assigned_sem.add('genericContainers')
    xs = one([t for t in tabs if 14 in (t.get('muls') or [])
              and (hasf(t, 'GIMeta_GetGenericParameterInfo')
                   or hasf(t, 'GIMeta_TypeInfoDispatcher')
                   or hasf(t, 'GIMeta_SetupNestedLocked'))])
    if len(xs) == 1:
        apply('genericParameters', xs[0]); assigned_sem.add('genericParameters')

    # genericMethodTable / Count：RuntimeInit 中两张相邻表，和等于 methodSpecs
    # 或 methodPointerIndexOffset（不同版本落点不同）。
    rc = one([t for t in tabs if hasf(t, 'GIMeta_RuntimeInit') and (tf(t) or 0) > 0])
    anchors = set()
    for nm in ('methodSpecs', 'methodPointerIndexOffset'):
        v = table_val(nm)
        if v:
            anchors.add(v)
    pair = None
    for i in range(len(rc)):
        for j in range(i + 1, len(rc)):
            if (tf(rc[i]) or 0) + (tf(rc[j]) or 0) in anchors:
                pair = (rc[i], rc[j]); break
        if pair:
            break
    if pair:
        a1, a2 = sorted(pair, key=lambda t: t.get('seq', 0))
        apply('genericMethodTable', a1)
        apply('genericMethodTableCount', a2)
        assigned_sem.update(('genericMethodTable', 'genericMethodTableCount'))

    # genericTypeArgOffset / genericClassRangeOffset：startup 表，4/8 字节步长。
    # typeArg 是较小的 4 字节表；classRange 是剩下的 8 字节表。
    xs = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit') and 4 in (t.get('muls') or [])
          and (tf(t) or 0) > 0x10000]
    if xs:
        t = min(xs, key=lambda x: tf(x) or 0)
        apply('genericTypeArgOffset', t); assigned_sem.add('genericTypeArgOffset')
    try:
        typearg_v = table_val('genericTypeArgOffset')
    except Exception:
        typearg_v = None
    xs = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit') and 8 in (t.get('muls') or [])
          and (tf(t) or 0) > 0x100000 and (tf(t) or 0) != (typearg_v or 0)]
    if xs:
        # 优先只带 8 的表，避免 8/12/14 混合的表把 methodSpecs 抢走。
        pure = [t for t in xs if (t.get('muls') or []) == [8]]
        t = min(pure or xs, key=lambda x: tf(x) or 0)
        apply('genericClassRangeOffset', t); assigned_sem.add('genericClassRangeOffset')

    # interfacesTable：SetupTypeInfo 里 6 字节、只做乘法索引的表。
    xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
          and 6 in (t.get('muls') or []) and 6 not in (t.get('divs') or [])
          and 0 < (tf(t) or 0) < 0x100000]
    if len(xs) == 1:
        apply('interfacesTable', xs[0]); assigned_sem.add('interfacesTable')

    # parameterDefaultValuesOffset：默认参数表，排除字段/参数共用的 blob。
    blob_slot = D.get('tables', {}).get('fieldAndParameterDefaultValueDataOffset', {}).get('slot')
    xs = [t for t in tabs if (t.get('funcs') or [None])[0] == 'GIMeta_GetDefaultParameterValueObject'
          and (tf(t) or 0) > 0x100000 and t.get('slot') != blob_slot]
    if xs:
        apply('parameterDefaultValuesOffset', max(xs, key=lambda t: tf(t) or 0))
        assigned_sem.add('parameterDefaultValuesOffset')

    # 默认值 blob：同时被字段/参数默认值读取函数使用。
    xs = one([t for t in tabs if hasf(t, 'GIMeta_GetFieldDefaultValue')
              and hasf(t, 'GIMeta_GetDefaultParameterValueObject')])
    if len(xs) == 1:
        apply('fieldAndParameterDefaultValueDataOffset', xs[0])
        assigned_sem.add('fieldAndParameterDefaultValueDataOffset')

    # attributesInfoCount：8 字节表的小计数候选（排除 methodSlotCount）。
    xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
          and 8 in (t.get('divs') or []) and 0 < (tf(t) or 0) < 0x100000
          and D.get('tables', {}).get('methodSlotCount', {}).get('slot') != t.get('slot')]
    if xs:
        x = min(xs, key=lambda t: tf(t) or 0)
        apply('attributesInfoCount', x); assigned_sem.add('attributesInfoCount')

    # attributeTypesOffset：4 字节、较大的类型索引表。
    xs = [t for t in tabs if hasf(t, 'GIMeta_SetupTypeInfoLocked')
          and 4 in (t.get('muls') or []) and (tf(t) or 0) > 0x100000
          and D.get('tables', {}).get('methodSlotTableOffset', {}).get('slot') != t.get('slot')
          and D.get('tables', {}).get('fieldOffset', {}).get('slot') != t.get('slot')]
    if xs:
        ai = table_val('attributesInfoOffset')
        below = [t for t in xs if ai is None or (tf(t) or 0) < ai]
        x = min(below or xs, key=lambda t: tf(t) or 0)
        apply('attributeTypesOffset', x); assigned_sem.add('attributeTypesOffset')

    if not semantic_needed:
        D['tables'] = old_tables

    # imagesOffset 的独立结构证据：startup 表值为 0，且 RuntimeInit 用 40 字节步长索引。
    # 7.0/7.1 的零值候选没有 40 字节步长，不会被这条规则碰到。
    zero40 = [t for t in tabs if hasf(t, 'GIMeta_RuntimeInit')
              and tf(t) == 0 and 40 in (t.get('muls') or [])]
    if len(zero40) == 1:
        apply('imagesOffset', zero40[0])

    # 同 slot 的旧角色只有在语义规则明确重算时才换 op/key。
    # 这能保住 7.0/7.1 已验证的同 slot key，同时不阻断 6.7 的跨 slot 布局变化。
    if semantic_needed:
        for _name, _ent in list(D.get('tables', {}).items()):
            _b = base.get('tables', {}).get(_name)
            if not _b or _name in assigned_sem:
                continue
            if str(_ent.get('slot', '')).lower() == str(_b.get('slot', '')).lower() and \
               (_ent.get('op') != _b.get('op') or str(_ent.get('key', '')).lower() != str(_b.get('key', '')).lower()):
                _ent = dict(_ent)
                _ent['op'] = _b.get('op')
                _ent['key'] = _b.get('key')
                D['tables'][_name] = _ent

    # 只有语义规则没有判定 attributesInfoCount 时，才保留旧基线的兼容值。
    if (not semantic_needed or 'attributesInfoCount' not in assigned_sem) \
            and 'attributesInfoCount' in D.get('tables', {}) and 'attributesInfoCount' in base.get('tables', {}):
        D['tables']['attributesInfoCount'] = dict(base['tables']['attributesInfoCount'])


    if a.apply:
        json.dump(D, open(a.draft, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print('已写', a.draft)
    for n in ('fieldsOffset', 'fieldOffset', 'methodSpecs', 'attributeTypesOffset',
              'attributesInfoOffset', 'genericTypeArgOffset', 'genericClassRangeOffset',
              'genericMethodTable', 'genericMethodTableCount'):
        print('%-26s %s' % (n, D.get('tables', {}).get(n)))


if __name__ == '__main__':
    main()
