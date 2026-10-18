#!/usr/bin/env python3
"""fielddecode_auto.py —— 用目标版本数据自证 fieldDecode / structOffsets。

只使用：
  · 上一版 version.json（字段名、宽度、字段语义）
  · 目标 ida_export.py 的 fieldDecode 候选（disp/width/op/key/funcs）
  · 目标 global-metadata.dat + MHY 表
  · 目标 keyFormulas（可选，用于方法/属性名验证）

不读取目标 version.json。

输出：
  version/<ver>/ida/fielddecode.auto.json
  {
    "fieldDecode": {...},
    "structOffsets": {...},
    "evidence": {...}
  }

当前重点：typeDef 的 18 个字段 + method/property/event/field/parameter/generic/image
的确定性字段。无法自证的字段不写入，交给 update.py 保留旧值并报告。
"""
import argparse
import json
import os
import re
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_version import load_json_with_comments  # noqa: E402

H = 0x210
M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
OPS = {'xor': '^', 'add': '+', 'sub': '-', '^': '^', '+': '+', '-': '-'}

WIDTH = {'BYTE': (1, 0xFF), 'WORD': (2, 0xFFFF), '_int16': (2, 0xFFFF),
         'DWORD': (4, M32), 'int': (4, M32), 'QWORD': (8, M64)}


def norm_op(op):
    return OPS.get(str(op).lower(), op)


def read_int(buf, off, width):
    if off < 0 or off + width > len(buf):
        return 0
    return int.from_bytes(buf[off:off + width], 'little')


def apply(raw, op, key, mask):
    op = norm_op(op)
    v = raw & mask
    if op == '^':
        return (v ^ key) & mask
    if op == '-':
        return (v - key) & mask
    if op == '+':
        return (v + key) & mask
    return v



def decomp_texts(root):
    d = {}
    import glob
    for p in glob.glob(os.path.join(root, 'ida', 'decomp', '*.c')):
        fn = os.path.basename(p)[:-2]
        d[fn] = open(p, encoding='utf-8', errors='ignore').read()
    return d


def find_key_near(text, off_re, key_re, window=500):
    """在 offset 表达式附近找 op/key；返回 (disp, op, key) 或 None。"""
    m = re.search(off_re, text)
    if not m:
        return None
    disp = int(m.group(1), 0)
    tail = text[m.end():m.end() + window]
    km = re.search(key_re, tail)
    if not km:
        return None
    op = km.group(1)
    key = int(km.group(2), 0)
    return disp, norm_op(op), key


def extra_candidates(root):
    """从反编译文本抽取 ida_export.py 正则漏掉的 (disp,width,op,key)。

    这里只写“语义角色 -> 反编译形状”，偏移/常数全部从文本捕获。
    """
    T = decomp_texts(root)
    out = []

    def add(fn, struct, field, regex, width, disp_fixed=None):
        for name, tx in T.items():
            if not name.startswith(fn):
                continue
            for m in re.finditer(regex, tx):
                try:
                    disp = int(str(m.groupdict().get('disp') or disp_fixed), 0)
                    key = int(m.group('key'), 0)
                except Exception:
                    continue
                out.append({'disp': disp, 'width': width, 'op': norm_op(m.groupdict().get('op') or '-'),
                            'key': key, 'funcs': [fn], 'struct': struct, 'field': field})

    # typeDef
    add('GIMeta_SetupPropertiesLocked', 'typeDef', 'propertyStart',
        r'v(?P<v>\d+) = \*\(_DWORD \*\)\([^\n;]+ \+ (?P<disp>\d+)LL\);[\s\S]{0,400}?v(?P=v) - (?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD')
    add('GIMeta_SetupFieldsLocked', 'typeDef', 'fieldStart',
        r'v(?P<v>\d+) = \*\(_DWORD \*\)\([^\n;]+ \+ (?P<disp>\d+)\);[\s\S]{0,300}?v(?P=v) - (?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD')
    add('GIMeta_SetupFieldsLocked', 'typeDef', 'field_count',
        r'\*\(_WORD \*\)\([^\n;]+ \+ (?P<disp>\d+)LL\)\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'WORD')
    add('GIMeta_SetupEventsLocked', 'typeDef', 'eventStart',
        r'\*\(_WORD \*\)\([^\n;]+ \+ (?P<disp>\d+)LL\)\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'WORD')
    add('GIMeta_SetupEventsLocked', 'typeDef', 'event_count',
        r'\*\(_BYTE \*\)\([^\n;]+ \+ (?P<disp>\d+)LL?\)\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'BYTE')
    # property
    add('GIMeta_SetupPropertiesLocked', 'property', 'nameIndex',
        r'\*\(_DWORD \*\)\([^\n;]+ \+ 10LL \* [^)]+\)\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD', disp_fixed=0)
    add('GIMeta_SetupPropertiesLocked', 'property', 'get',
        r'\+ 10LL \* [^)]+ \+ (?P<disp>\d+)\) - [^+\n;]+ (?P<op>\+)\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'WORD')
    # property get/set 在 SetupPropertiesLocked 的 +8/+4，直接在 data 验证
    # event
    add('GIMeta_SetupEventsLocked', 'event', 'typeIndex',
        r'\*\(_DWORD \*\)v\d+\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD', disp_fixed=0)
    # parameter
    add('GIMeta_SetupParameters', 'parameter', 'typeIndex',
        r'\*\(_DWORD \*\)\([^\n;]+ \+ 8 \* [^)]+\)\s*\^\s*\w+\s*(?P<op>\^)\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD', disp_fixed=0)
    # generic container parameterStart
    add('GIMeta_BuildMethodName', 'genericContainer', 'parameterStart',
        r'v\d+ = \(unsigned int\)\(v\d+ (?P<op>-)\s*(?P<key>0x[0-9A-Fa-f]+|\d+)\)', 'DWORD', disp_fixed=12)
    # image name: v122[40 * ... + 8] ^ key
    add('GIMeta_RuntimeInit', 'image', 'nameIndexXor',
        r'\[40 \* [^\]]+ \+ (?P<disp>\d+)\]\s*(?P<op>[-+^])\s*(?P<key>0x[0-9A-Fa-f]+|\d+)', 'DWORD')
    return out


class Ctx:
    def __init__(self, root, base, draft, kf):
        self.root = root
        self.base = base
        self.draft = draft
        self.dat = open(os.path.join(root, 'gi', 'Managed', 'Metadata', 'global-metadata.dat'), 'rb').read()
        self.ida = json.load(open(os.path.join(root, 'ida.json'), encoding='utf-8'))
        self.cands = []
        for r in self.ida.get('fieldDecode', []):
            w = r.get('width')
            if w not in WIDTH:
                continue
            try:
                disp = int(str(r['disp']), 0)
                key = int(str(r['key']), 0)
            except Exception:
                continue
            if not (0 <= disp < 0x100):
                continue
            self.cands.append({'disp': disp, 'width': w, 'op': norm_op(r['op']),
                               'key': key, 'funcs': r.get('funcs', [])})
        # 去重
        seen = set(); uniq = []
        for c in self.cands:
            k = (c['disp'], c['width'], c['op'], c['key'])
            if k in seen:
                continue
            seen.add(k); uniq.append(c)
        # 反编译里 ida_export.py 漏掉的候选
        for c in extra_candidates(root):
            k = (c['disp'], c['width'], c['op'], c['key'])
            if k in seen:
                # 合并 funcs
                for old in self.cands:
                    if (old['disp'], old['width'], old['op'], old['key']) == k:
                        for f in c['funcs']:
                            if f not in old['funcs']:
                                old['funcs'].append(f)
                        if 'struct' in c:
                            old['struct'] = c['struct']
                            old['field'] = c['field']
                        break
                continue
            seen.add(k); uniq.append(c)
        self.cands = uniq
        self.kf = kf
        self.kf_expr = {}
        vp = os.path.join(root, 'ida', 'keyformulas.values.json')
        if os.path.exists(vp):
            try:
                self.kf_expr = json.load(open(vp, encoding='utf-8')).get('formulas', {})
            except Exception:
                self.kf_expr = {}
        # 字符串解密：优先用 stringkeys.json，否则用 draft
        sd = {}
        p = os.path.join(root, 'ida', 'stringkeys.json')
        if os.path.exists(p):
            try:
                sd = json.load(open(p, encoding='utf-8')).get('stringDecrypt', {})
            except Exception:
                sd = {}
        if not sd:
            sd = draft.get('stringDecrypt', {})
        self.sd = sd
        self.KA = int(str(sd.get('keyMulA', '0')), 0)
        self.KB = int(str(sd.get('keyMulB', '0')), 0)
        self.KS = int(str(sd.get('keySeed', '0')), 0)
        self.KP = int(str(sd.get('keyStep', '0')), 0)
        self.STR = self.table_value('stringLiteralDataOffset') if draft else 0

    def table_value(self, name):
        try:
            tb = self.draft['tables'][name]
            t = tb
            exe = os.path.join(self.root, 'gi.exe')
            # 复用 draft 里的 mhy 地址
            from sig import PE
            mhy = int(str(self.draft['addresses']['mhyTableVA']), 0)
            pe = PE(exe)
            raw = struct.unpack_from('<I', pe.D, pe.va2off(mhy + int(str(t['slot']), 0)))[0]
            op = norm_op(t['op']); key = int(str(t['key']), 0)
            return apply(raw, op, key, M32)
        except Exception:
            return 0

    def decrypt(self, v):
        off = v & 0xFFFFFF
        ln = (v >> 24) & 0xFF
        if ln <= 0 or ln > 64 or off < 0:
            return b''
        if H + self.STR + off + ((ln + 7) // 8) * 8 > len(self.dat):
            return b''
        first = None
        # 7.0: A ^ (B*off + seed) / 7.1: A * (B*off ^ seed)
        for mode in (0, 1):
            key = ((self.KA ^ ((self.KB * off + self.KS) & M64)) if mode == 0
                   else (self.KA * ((self.KB * off) ^ self.KS)) & M64)
            out = bytearray()
            for k in range((ln + 7) // 8):
                p = H + self.STR + off + 8 * k
                out += (int.from_bytes(self.dat[p:p + 8], 'little') ^ key).to_bytes(8, 'little')
                key = (key + self.KP) & M64
            b = bytes(out[:ln])
            if first is None:
                first = b
            if self.printable(b):
                return b
        return first or b''

    def printable(self, b):
        return len(b) > 0 and all(0x20 <= c < 0x7F for c in b)

    def array(self, cand, table_off, stride, n, field=0, signed=False):
        w, mask = WIDTH[cand['width']]
        out = []
        for i in range(n):
            p = H + table_off + stride * i + field + cand['disp']
            raw = read_int(self.dat, p, w)
            v = apply(raw, cand['op'], cand['key'], mask)
            if signed and w == 2 and v >= 0x8000:
                v -= 0x10000
            elif signed and w == 4 and v >= 0x80000000:
                v -= 0x100000000
            out.append(v)
        return out

    def key(self, name, i):
        f = (self.kf or {}).get(name)
        if not f:
            e = (self.kf_expr.get(name) or {}).get('expr')
            if not e:
                return None
            try:
                e = e.replace('LL', '').replace('uLL', '').replace('ull', '')
                e = e.replace('__int64', '').replace('(unsigned int)', '').replace('(unsigned __int64)', '')
                e = e.replace('__ROL8__', 'ROL8').replace('__ROR8__', 'ROR8')
                ns = {'i': i, 'ROL8': lambda v, n: ((v << n) | (v >> (64 - n))) & M64,
                      'ROR8': lambda v, n: ((v >> n) | (v << (64 - n))) & M64}
                return eval(e, {'__builtins__': {}}, ns) & M32
            except Exception:
                return None
        try:
            # 只支持本脚本生成的 c0/c1... 常量形式
            ns = {'i': i}
            for k, v in f.items():
                if k.startswith('c') and k[1:].isdigit():
                    ns['k' + k[:1].upper() + k[1:]] = int(str(v), 0)
            cpp = f.get('cpp', '')
            e = cpp.strip()
            if e.startswith('return '):
                e = e[7:]
            e = e.rstrip(';')
            if e.startswith('(') and e.endswith(')'):
                e = e[1:-1]
            e = e.replace('(uint32_t)', '').replace('(uint64_t)', '')
            return eval(e, {'__builtins__': {}}, ns) & M32
        except Exception:
            return None


def score_strings(ctx, arr):
    n = min(len(arr), 400)
    ok = empty = dot = 0
    for v in arr[:n]:
        b = ctx.decrypt(v)
        if not b:
            empty += 1
            continue
        if ctx.printable(b):
            ok += 1
            if b'.' in b:
                dot += 1
    return ok / max(n, 1), empty / max(n, 1), dot / max(n, 1)


def pair_score(S, C, n):
    good = tot = gap = 0
    for i in range(min(n - 1, len(S) - 1)):
        s, c, s2 = S[i], C[i], S[i + 1]
        if c == 0:
            continue
        # 4 字节无符号 -1 表示“没有”
        if s == 0xFFFFFFFF or s2 == 0xFFFFFFFF:
            continue
        if s > 0x7FFFFFFF or s2 > 0x7FFFFFFF:
            continue
        tot += 1
        if s2 >= s and s2 - s >= c:
            good += 1
            gap += s2 - s - c
    return (good / tot if tot else 0), (gap / good if good else 999), tot



def calibrate_count(ctx, td, start_cand, n):
    """用 start 的相邻 gap 反推 count 字段的 (disp,width,op,key)。"""
    S = ctx.array(start_cand, td, 70, n)
    gaps = []
    for i in range(n - 1):
        a, b = S[i], S[i + 1]
        if a in (0xFFFFFFFF, 0xFFFF) or b in (0xFFFFFFFF, 0xFFFF):
            continue
        if a > 0x7FFFFFFF or b > 0x7FFFFFFF:
            continue
        if b < a:
            continue
        gaps.append((i, b - a))
    if len(gaps) < 20:
        return None
    best = None
    for o in range(0, 72):
        for w, mask in ((1, 0xFF), (2, 0xFFFF)):
            raws = {}
            for i, g in gaps:
                p = H + td + 70 * i + o
                raws[i] = read_int(ctx.dat, p, w)
            for op in ('+', '-', '^'):
                ks = []
                for i, g in gaps:
                    r = raws[i]
                    if op == '+':
                        ks.append((g - r) & mask)
                    elif op == '-':
                        ks.append((r - g) & mask)
                    else:
                        ks.append((g ^ r) & mask)
                if not ks:
                    continue
                from collections import Counter
                key, cnt = Counter(ks).most_common(1)[0]
                sc = cnt / len(gaps)
                if sc >= 0.95 and key not in (0xFFFF, 0xFF):
                    # 排除平凡的 0/1 常数
                    if best is None or sc > best[0]:
                        best = (sc, o, w, op, key, len(gaps))
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--draft', default=None)
    ap.add_argument('--keyformulas', default=None)
    ap.add_argument('--out', default=None)
    ap.add_argument('--samples', type=int, default=4000)
    a = ap.parse_args()
    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, 'version', a.root)
    if not os.path.isdir(root):
        root = a.root
    base = load_json_with_comments(a.base)
    draft_path = a.draft or os.path.join(root, 'version.draft.json')
    draft = load_json_with_comments(draft_path) if os.path.exists(draft_path) else base
    kf = {}
    kp = a.keyformulas or os.path.join(root, 'ida', 'keyformulas.auto.json')
    if os.path.exists(kp):
        try:
            kf = json.load(open(kp, encoding='utf-8'))
        except Exception:
            kf = {}
    ctx = Ctx(root, base, draft, kf)

    # 目标表
    td = ctx.table_value('typeDefinitionsOffset')
    td_count = ctx.table_value('typeDefinitionsCount') // 70
    methods = ctx.table_value('methodsOffset')
    methods_count = ctx.table_value('methodsCount') // 26
    fields_off = None
    # fieldsOffset 目前自动化可能错；优先从 IDA candidate 里找 stride 8 且函数语义是字段表
    for c in ctx.ida.get('tables', []):
        try:
            v = int(str(c.get('value', '0')), 0)
        except Exception:
            continue
        fns = c.get('funcs') or []
        if (0 < v < len(ctx.dat) - H and 8 in (c.get('strides') or [])
                and any('SetupFieldsLocked' in f or 'GetFieldName' in f for f in fns)):
            fields_off = v
            break
    if fields_off is None:
        fields_off = ctx.table_value('fieldsOffset')
    events = ctx.table_value('eventsOffset')
    params = ctx.table_value('parametersOffset')
    nested = ctx.table_value('nestedTypesTable')
    interfaces = ctx.table_value('interfacesTable')
    gcont = ctx.table_value('genericContainers')
    gparam = ctx.table_value('genericParameters')
    images = ctx.table_value('imagesOffset')
    print('tables: td=0x%X n=%d methods=0x%X n=%d fields=0x%X events=0x%X nested=0x%X iface=0x%X' %
          (td, td_count, methods, methods_count, fields_off or 0, events, nested, interfaces))

    n = min(a.samples, td_count)
    # 计算候选数组
    cands = []
    for c in ctx.cands:
        if c['disp'] > 72:
            continue
        arr = ctx.array(c, td, 70, n)
        cands.append((c, arr))
        # 7.1 的导出正则有时把 2/4 字节字段读成 QWORD；
        # 对小 key 的 QWORD 追加 32/16 位视图，供 pair/字符串验证使用。
        if c['width'] == 'QWORD':
            for w in ('DWORD',):
                cc = dict(c); cc['width'] = w
                cands.append((cc, ctx.array(cc, td, 70, n)))
            if (c['key'] & 0xFFFFFFFF) <= 0xFFFF:
                cc = dict(c); cc['width'] = 'WORD'
                cands.append((cc, ctx.array(cc, td, 70, n)))
    print('typeDef candidates:', len(cands))

    # 字符串候选
    str_info = []
    for c, arr in cands:
        if c['width'] not in ('DWORD',):
            continue
        pr, er, dr = score_strings(ctx, arr)
        if pr > 0.90:
            str_info.append((c, pr, er, dr, arr))
    str_info.sort(key=lambda x: x[1] * (1 - x[2]), reverse=True)
    name_c = str_info[0] if str_info else None
    ns_c = None
    for x in str_info[1:]:
        if x[2] > (name_c[2] if name_c else 0):
            ns_c = x
            break
    print('string candidates:', [(x[0]['disp'], round(x[1], 2), round(x[2], 2)) for x in str_info[:6]])

    # 计数/起始候选
    starts = []
    counts = []
    for c, arr in cands:
        if (name_c and c is name_c[0]) or (ns_c and c is ns_c[0]):
            continue
        vals = [v for v in arr if not (v == 0xFFFFFFFF or v == 0xFFFF)]
        mx = max(vals) if vals else 0
        uniq = len(set(vals))
        if c['width'] in ('BYTE', 'WORD', '_int16') and mx < 0x8000 and uniq > 2:
            counts.append((c, arr))
        if c['width'] in ('WORD', '_int16', 'DWORD') and mx < 0x1000000 and uniq > 2:
            starts.append((c, arr))

    # 配对
    pairs = []
    for sc, sa in starts:
        for cc, ca in counts:
            if sc['disp'] == cc['disp']:
                continue
            sc_, gap, tot = pair_score(sa, ca, n)
            if tot >= 20 and sc_ > 0.80:
                pairs.append({'start': sc, 'count': cc, 's': sa, 'c': ca, 'score': sc_, 'gap': gap})
    pairs.sort(key=lambda x: (x['score'], -x['gap']), reverse=True)
    print('pairs:', [(p['start']['disp'], p['count']['disp'], round(p['score'], 3), round(p['gap'], 2)) for p in pairs[:12]])

    def valid_method(p):
        # 方法表：start/count 范围内的名字可打印
        ok = tot = 0
        for i in range(min(n, 400)):
            s, c = p['s'][i], p['c'][i]
            if c == 0 or s + c > methods_count:
                continue
            for j in (s, s + c - 1):
                k = ctx.key('methodKey', j)
                if k is None:
                    return 0
                nm = ctx.decrypt(ctx._raw_method(j) ^ k) if hasattr(ctx, '_raw_method') else b''
                # 直接从表读
                raw = read_int(ctx.dat, H + methods + 26 * j, 4)
                nm = ctx.decrypt(raw ^ k)
                tot += 1
                ok += ctx.printable(nm)
        return ok / tot if tot else 0

    def cand_at(disp, op, fn):
        for c in ctx.cands:
            if c['disp'] == disp and c['op'] == op and any(fn in f for f in c['funcs']):
                return c
        return None
    ftype = cand_at(0, '-', 'SetupFieldsLocked')
    etype = cand_at(0, '-', 'SetupEventsLocked')
    ptype = cand_at(0, '^', 'SetupParameters')

    def valid_entry(p, off, stride, skip, kind, limit):
        ok = tot = 0
        for i in range(min(n, 400)):
            s, c = p['s'][i], p['c'][i]
            if c == 0 or s >= limit:
                continue
            s = min(s, limit - 1)
            raw = read_int(ctx.dat, H + off + stride * s, 4)
            if kind == 'field' and ftype:
                k = ctx.key('fieldKey', s)
                v = ((raw - ftype['key']) & M32) ^ (k or 0)
            elif kind == 'event' and etype:
                k = ctx.key('eventKey', s)
                v = ((raw - etype['key']) & M32) ^ (k or 0)
            elif kind == 'param' and ptype:
                k = ctx.key('paramKey', s)
                v = (raw ^ ptype['key'] ^ (k or 0)) & M32
            elif kind == 'iface':
                v = raw
                limit = 1 << 21
                tot += 1; ok += (v < limit); continue
            else:
                v = raw
            tot += 1
            ok += (v == 0xFFFFFFFF or v < limit)
        return ok / tot if tot else 0

    # 给每对打分：方法/字段/事件/nested/interfaces/参数
    for p in pairs:
        p['method'] = valid_method(p)
        p['field'] = valid_entry(p, fields_off, 8, 0, 'field', 1 << 21) if fields_off else 0
        p['event'] = valid_entry(p, events, 14, 0, 'event', 1 << 21) if events else 0
        p['nested'] = valid_entry(p, nested, 4, 0, 'nested', td_count) if nested else 0
        p['iface'] = valid_entry(p, interfaces, 4, 0, 'iface', 1 << 21) if interfaces else 0
        p['param'] = valid_entry(p, params, 8, 0, 'param', 1 << 21) if params else 0

    assigned = {}
    # 配对只用于打印证据；具体字段由下面的语义/校准器写入，避免错位覆盖。
    print('pair evidence:', {p['start']['disp']: round(max(p['method'], p['field'], p['event'], p['iface'], p['param']), 2) for p in pairs[:8]})

    out = {'fieldDecode': {}, 'structOffsets': {}, 'evidence': {}}
    fd = out['fieldDecode']
    so = out['structOffsets']

    def put(struct, field, c):
        if struct not in fd:
            fd[struct] = {}
        fd[struct][field] = '%s:0x%X' % ({'^': 'xor', '+': 'add', '-': 'sub'}[c['op']], c['key'])
        if struct == 'typeDef':
            so.setdefault('Il2CppTypeDefinition', {})[field] = c['disp']

    if name_c:
        put('typeDef', 'nameIndex', name_c[0])
    if ns_c:
        put('typeDef', 'namespaceIndex', ns_c[0])
    family_name = {'method': ('methodStart', 'method_count'), 'field': ('fieldStart', 'field_count'),
                   'event': ('eventStart', 'event_count'), 'nested': ('nestedTypesStart', 'nestedTypesCount'),
                   'iface': ('interfacesStart', 'interfaces_count'), 'param': ('propertyStart', 'property_count')}
    for fam, (sn, cn) in family_name.items():
        if fam in assigned:
            p = assigned[fam]
            put('typeDef', sn, p['start'])
            put('typeDef', cn, p['count'])
    # 剩余的单个字段：parentIndex / genericContainerIndex / flags / unknown20
    used_disp = set()
    for c, _ in cands:
        for st in fd.values():
            pass
    for fam, p in assigned.items():
        used_disp.add(p['start']['disp']); used_disp.add(p['count']['disp'])
    if name_c: used_disp.add(name_c[0]['disp'])
    if ns_c: used_disp.add(ns_c[0]['disp'])

    # genericContainerIndex：2 字节，值多为 0xFFFF 或小于容器数
    gc_count = 0
    raw_gc = ctx.table_value('genericContainers')
    if raw_gc:
        # 容器数未知，用 typeDef 最大值估计
        gc_count = 1 << 20
    best = None
    for c, arr in cands:
        if c['disp'] in used_disp or c['width'] not in ('WORD', '_int16'):
            continue
        sent = sum(1 for v in arr[:400] if v in (0xFFFF, 0xFFFE))
        small = sum(1 for v in arr[:400] if v < gc_count)
        sc = (sent + small) / max(len(arr[:400]), 1)
        if best is None or sc > best[0]:
            best = (sc, c, arr)
    if best and best[0] > 0.9:
        put('typeDef', 'genericContainerIndex', best[1])

    # parentIndex：4 字节，-1 或 < typeDef count
    best = None
    for c, arr in cands:
        if c['disp'] in used_disp or c['width'] != 'DWORD':
            continue
        sent = sum(1 for v in arr[:400] if v >= 0xFFFFFFF0 or v < td_count)
        sc = sent / max(len(arr[:400]), 1)
        if best is None or sc > best[0]:
            best = (sc, c, arr)

    # 简单结构：直接按目标函数里的 disp/width/顺序映射
    def add_from_funcs(struct, funcs, names, widths, offsets=None):
        got = []
        for c in ctx.cands:
            if any(f in c['funcs'] for f in funcs):
                got.append(c)
        # 去重并按 disp 排序
        seen = set(); uniq = []
        for c in sorted(got, key=lambda x: (x['disp'], x['width'])):
            k = (c['disp'], c['width'], c['op'], c['key'])
            if k in seen:
                continue
            seen.add(k); uniq.append(c)
        # 按名称宽度匹配
        used = set()
        for nm in names:
            w = widths.get(nm)
            for c in uniq:
                if id(c) in used or (w and c['width'] != w):
                    continue
                # 若给了偏移，只接受该偏移
                if offsets and nm in offsets and c['disp'] != offsets[nm]:
                    continue
                put(struct, nm, c)
                used.add(id(c))
                break

    # method：按目标函数里的 disp/宽度确定角色
    m_cands = []
    for c in ctx.cands:
        if any(f in c['funcs'] for f in ('GIMeta_SetupMethodsLocked', 'GIMeta_SetupParameters')):
            m_cands.append(c)
    m_cands = sorted({(c['disp'], c['width'], c['op'], c['key']): c for c in m_cands}.values(),
                     key=lambda c: (c['disp'], c['width']))
    # parameterStart：SetupParameters 的 +8 DWORD（+0 是参数 typeIndex）
    for c in m_cands:
        if ('GIMeta_SetupParameters' in c['funcs'] and c['width'] == 'DWORD'
                and c['disp'] == 8):
            put('method', 'parameterStart', c); break
    # genericContainerIndex：SetupMethodsLocked 里第一个 WORD
    words = [c for c in m_cands if 'GIMeta_SetupMethodsLocked' in c['funcs'] and c['width'] == 'WORD']
    if words:
        put('method', 'genericContainerIndex', words[0])
        if len(words) >= 2:
            put('method', 'iflags', words[1])
        if len(words) >= 3:
            # +22 有两个候选：用 access 分布选 method.flags
            best = None
            for c in words[2:]:
                arr = ctx.array(c, methods, 26, min(n, 4000))
                from collections import Counter
                cnt = Counter(v & 7 for v in arr)
                tot = max(len(arr), 1)
                exp = {6: .58, 1: .25, 3: .13, 4: .037}
                sc = -sum((cnt[k] / tot - v) ** 2 for k, v in exp.items())
                if best is None or sc > best[0]:
                    best = (sc, c)
            if best:
                put('method', 'flags', best[1])
    for c in m_cands:
        if 'GIMeta_SetupMethodsLocked' in c['funcs'] and c['width'] == 'BYTE':
            put('method', 'parameterCount', c); break
    add_from_funcs('field', ['GIMeta_SetupFieldsLocked', 'GIMeta_GetFieldName'],
                   ['typeIndex', 'nameIndexBase'], {'typeIndex': 'DWORD', 'nameIndexBase': 'DWORD'})
    add_from_funcs('event', ['GIMeta_SetupEventsLocked'],
                   ['typeIndex', 'nameIndex', 'add', 'remove', 'raise'],
                   {'typeIndex': 'DWORD', 'nameIndex': 'DWORD', 'add': 'WORD', 'remove': 'WORD', 'raise': 'WORD'})
    add_from_funcs('parameter', ['GIMeta_SetupParameters'],
                   ['typeIndex', 'nameIndexXor'], {'typeIndex': 'DWORD', 'nameIndexXor': 'DWORD'})
    add_from_funcs('property', ['GIMeta_SetupPropertiesLocked'],
                   ['nameIndex', 'set'], {'nameIndex': 'DWORD', 'set': 'WORD'})
    add_from_funcs('genericContainer', ['GIMeta_GetGenericMethodParamInfo', 'GIMeta_SetupNestedLocked'],
                   ['argc'], {'argc': 'DWORD'})
    add_from_funcs('genericParameter', ['GIMeta_GetGenericParameterInfo'],
                   ['nameIndex'], {'nameIndex': 'QWORD'})
    add_from_funcs('image', ['GIMeta_RuntimeInit'], ['nameIndexXor'],
                   {'nameIndexXor': 'DWORD'})

    # 用 start 候选的函数上下文给配对命名（通用：不依赖版本偏移）
    for _p in pairs:
        _f = ' '.join(_p['start'].get('funcs') or [])
        if 'GetMethodName' in _f or 'SetupMethods' in _f:
            put('typeDef', 'methodStart', _p['start'])
            put('typeDef', 'method_count', _p['count'])
        elif 'SetupFields' in _f:
            put('typeDef', 'fieldStart', _p['start'])
            put('typeDef', 'field_count', _p['count'])
        elif 'SetupProperties' in _f:
            put('typeDef', 'propertyStart', _p['start'])
            put('typeDef', 'property_count', _p['count'])
        elif 'SetupEvents' in _f:
            put('typeDef', 'eventStart', _p['start'])
            put('typeDef', 'event_count', _p['count'])
        elif 'Nested' in _f or 'IterNested' in _f:
            put('typeDef', 'nestedTypesStart', _p['start'])
            put('typeDef', 'nestedTypesCount', _p['count'])

    # 反编译直接语义候选（优先于通用配对）
    for c in ctx.cands:
        if 'struct' in c and 'field' in c:
            put(c['struct'], c['field'], c)

    # typeDef 直接语义拾取：只按“函数 + 位宽 + 操作符”选候选，不写死偏移。
    def pick_fn(fn, width=None, op=None):
        hits = []
        for c in ctx.cands:
            if fn and not any(fn in f for f in c['funcs']):
                continue
            if width and c['width'] != width:
                continue
            if op and c['op'] != op:
                continue
            hits.append(c)
        uniq = {(c['disp'], c['width'], c['op'], c['key']): c for c in hits}
        if len(uniq) == 1:
            return next(iter(uniq.values()))
        # 同一 (disp,key) 的重复候选：值完全一致时视为唯一
        if len({(c['disp'], c['op'], c['key']) for c in hits}) == 1:
            return hits[0]
        return None

    def put_if(struct, field, c):
        if c:
            put(struct, field, c)

    put_if('typeDef', 'namespaceIndex',
           pick_fn('GIMeta_IterNestedTypes', 'DWORD', '^') or
           pick_fn('GIMeta_FindTypeByName2', 'DWORD', '^'))
    put_if('typeDef', 'methodStart',
           pick_fn('GIMeta_GetMethodNameFromIndex', 'DWORD', '-'))
    put_if('typeDef', 'genericContainerIndex',
           pick_fn('GIMeta_SetupNestedLocked', '_int16', '^') or
           pick_fn('GIMeta_SetupNestedLocked', 'WORD', '^'))
    if name_c:
        put('typeDef', 'nameIndex', name_c[0])

    # unknown20：RuntimeInit 的 32 位减法候选，用类型表数据分布自证。
    # 该字段值域应几乎全部落在 {-1} ∪ [0, 2M]。
    if 'unknown20' not in fd.get('typeDef', {}):
        best = None
        for c in ctx.cands:
            if c['width'] != 'DWORD' or c['op'] != '-' or c['disp'] >= 70:
                continue
            if not any('RuntimeInit' in f for f in c['funcs']):
                continue
            arr = ctx.array(c, td, 70, min(n, 2000))
            if not arr:
                continue
            good = 0
            for v in arr:
                sv = v - 0x100000000 if v >= 0x80000000 else v
                if sv == -1 or 0 <= sv <= 2_000_000:
                    good += 1
            sc = good / len(arr)
            if best is None or sc > best[0]:
                best = (sc, c)
        if best and best[0] >= 0.95:
            put('typeDef', 'unknown20', best[1])
            out['evidence']['unknown20'] = {'score': round(best[0], 4),
                                            'disp': best[1]['disp'],
                                            'key': '0x%X' % best[1]['key']}

    # 用 start 的 gap 反推 method_count。
    ms = pick_fn('GIMeta_GetMethodNameFromIndex', 'DWORD', '-')
    if ms:
        cal = calibrate_count(ctx, td, ms, min(n, 4000))
        if cal:
            sc, o, w, op, key, tot = cal
            c = {'disp': o, 'width': 'BYTE' if w == 1 else 'WORD', 'op': op, 'key': key, 'funcs': []}
            put('typeDef', 'method_count', c)
            out['evidence']['method_count'] = {'score': sc, 'disp': o, 'width': w,
                                                'op': op, 'key': '0x%X' % key, 'n': tot}

    # ---- structOffsets：直接结构的布局 ----
    so = out['structOffsets']
    def setso(struct, field, off):
        so.setdefault(struct, {})[field] = off

    # property / image / genericContainer / event
    for c in ctx.cands:
        if c.get('struct') == 'property':
            setso('Il2CppPropertyDefinition', c['field'], c['disp'])
        if c.get('struct') == 'image':
            setso('Il2CppImageDefinition', c['field'], c['disp'])
        if c.get('struct') == 'genericContainer':
            setso('Il2CppGenericContainer', c['field'], c['disp'])
        if c.get('struct') == 'event':
            setso('Il2CppEventDefinition', c['field'], c['disp'])
    # image nameIndex 在 structOffsets 里叫 nameIndex
    img = so.get('Il2CppImageDefinition', {})
    if 'nameIndexXor' in img:
        img['nameIndex'] = img.pop('nameIndexXor')
    # ---- parentIndex / flags：从 typeDef 数据分布自证，不读目标 version.json ----
    # 这两个字段没有出现在当前 decomp 读取点里，但数据形态很强：
    #   parentIndex: raw - key 后绝大多数是 {-1} ∪ [0, typesCount)
    #   flags:       TYPE_ATTRIBUTE 位掩码，重复值远少于普通索引字段
    tdo = so.get('Il2CppTypeDefinition', {})
    known_off = set(tdo.values())
    free4 = [o for o in range(0, 68, 4) if o not in known_off]
    stats = {}
    npar = min(td_count, 20000)
    for off in free4:
        raws = [read_int(ctx.dat, H + td + 70 * i + off, 4) for i in range(npar)]
        if not raws:
            continue
        M, mcount = __import__('collections').Counter(raws).most_common(1)[0]
        mfreq = mcount / len(raws)
        pkey = (M - 1) & M32
        pvals = [(r - pkey) & M32 for r in raws]
        pgood = sum(1 for v in pvals if v == M32 or v < td_count) / len(pvals)
        pneg = sum(1 for v in pvals if v == M32) / len(pvals)
        fbest = None
        for fop in ('^', '-'):
            fkey = ((M ^ 0x100001) if fop == '^' else ((M - 0x100001) & M32))
            fvals = [((r ^ fkey) if fop == '^' else ((r - fkey) & M32)) for r in raws]
            fgood = sum(1 for v in fvals if v <= 0x200000) / len(fvals)
            cand = (fgood, -max(fvals), -len(set(fvals)), fop, fkey, max(fvals))
            if fbest is None or cand > fbest:
                fbest = cand
        stats[off] = {'M': M, 'freq': mfreq, 'pkey': pkey,
                      'pgood': pgood, 'pneg': pneg,
                      'pdistinct': len(set(pvals)), 'flags': fbest}

    # flags：位掩码字段的 distinct 极小，且 0x100001 是最常见的可见性/初始化组合。
    fslot = None
    for off, st in stats.items():
        fgood, negmax, negdistinct, fop, fkey, fmax = st['flags']
        fdistinct = -negdistinct
        if fgood >= 0.98 and st['freq'] >= 0.02:
            cand = (fdistinct, -fgood, -fmax, off)
            if fslot is None or cand < fslot[0]:
                fslot = (cand, off, fop, fkey)
    if fslot:
        _, off, fop, fkey = fslot
        fd.setdefault('typeDef', {})['flags'] = \
            '%s:0x%X' % ({'^': 'xor', '-': 'sub'}[fop], fkey)
        tdo['flags'] = off
        out['evidence']['flags'] = {'disp': off,
                                     'op': {'^': 'xor', '-': 'sub'}[fop],
                                     'key': '0x%X' % fkey}

    # parentIndex：优先选择存在 -1 哨兵的自由槽；否则选择高置信、低重复度的槽。
    pcands = []
    for off, st in stats.items():
        if fslot and off == fslot[1]:
            continue
        pcands.append((off, st))
    pool = []
    for off, st in pcands:
        if st['pdistinct'] >= 0.15 * npar:
            continue
        sc = st['pgood'] * st['freq']
        pool.append((sc, off, st))
    parent = max(pool, key=lambda x: x[0]) if pool else None
    if parent:
        # 父索引通常有 -1 哨兵；若某个带 -1 的槽分数接近最高分，则优先它。
        best_sc = parent[0]
        neg = [(sc, off, st) for sc, off, st in pool
               if 0.005 < st['pneg'] < 0.5 and sc >= best_sc * 0.40]
        if neg:
            parent = max(neg, key=lambda x: x[0])
    if parent:
        _, off, st = parent
        fd.setdefault('typeDef', {})['parentIndex'] = 'sub:0x%X' % st['pkey']
        tdo['parentIndex'] = off
        out['evidence']['parentIndex'] = {'disp': off, 'key': '0x%X' % st['pkey'],
                                          'score': round(parent[0], 4)}

    # field/parameter default value 三列置换：用单调列 + 合法 typeIndex 列判定
    def probe_defaults(table_name, kind):
        off = ctx.table_value(table_name)
        if not off:
            return
        n2 = 3000
        cols = {k: [read_int(ctx.dat, H + off + 12 * i + k, 4) for i in range(n2)] for k in (0, 4, 8)}
        def mono(v):
            return sum(1 for a, b in zip(v, v[1:]) if b >= a) / max(len(v) - 1, 1)
        def uniform4(v):
            return sum(1 for a, b in zip(v, v[1:]) if b - a == 4) / max(len(v) - 1, 1)
        def neg1(v):
            return sum(1 for x in v if x == 0xFFFFFFFF) / max(len(v), 1)
        struct = 'Il2CppFieldDefaultValue' if kind == 'field' else 'Il2CppParameterDefaultValue'
        if kind == 'field':
            # dataIndex 是 +4 均匀递增列；fieldIndex 是另一个非均匀递增列；余下是 typeIndex
            data_col = max((0, 4, 8), key=lambda k: uniform4(cols[k]))
            field_col = max({0, 4, 8} - {data_col}, key=lambda k: mono(cols[k]) * (1 - uniform4(cols[k])))
            type_col = ({0, 4, 8} - {data_col, field_col}).pop()
            setso(struct, 'dataIndex', data_col)
            setso(struct, 'fieldIndex', field_col)
            setso(struct, 'typeIndex', type_col)
        else:
            # parameterIndex 递增；dataIndex 带 -1；余下是 typeIndex
            param_col = max((0, 4, 8), key=lambda k: mono(cols[k]))
            data_col = max({0, 4, 8} - {param_col}, key=lambda k: neg1(cols[k]))
            type_col = ({0, 4, 8} - {param_col, data_col}).pop()
            setso(struct, 'parameterIndex', param_col)
            setso(struct, 'dataIndex', data_col)
            setso(struct, 'typeIndex', type_col)
    probe_defaults('fieldDefaultValuesOffset', 'field')
    probe_defaults('parameterDefaultValuesOffset', 'parameter')

    # 一些固定语义：xor:0 的字段
    for st, nm in (('method', 'nameIndex'), ('method', 'declaringType'),
                   ('field', 'nameIndexXor')):
        fd.setdefault(st, {})[nm] = 'xor:0x0'
    fd.setdefault('parameter', {})['nameIndexBase'] = 'sub:0x0'

    # 7.0 method/property 的布局：从候选 disp 推断（不写死 slot）
    for c in ctx.cands:
        if 'GIMeta_SetupMethodsLocked' in c['funcs'] and c['width'] == 'WORD':
            pass

    # ---- 从目标 decomp 解析事件/属性/参数的字段语义（通用，不写死版本常数）----
    import glob as _glob, re as _re
    def _read(prefix):
        for fp in _glob.glob(os.path.join(root, 'ida', 'decomp', prefix + '*.c')):
            return open(fp, encoding='utf-8', errors='ignore').read()
        return ''
    def _word_ops(text, allowed):
        out = []
        for line in text.splitlines():
            if '136' in line:
                continue
            m = _re.search(r'\*\(_WORD \*\)\([^)]*\+ (\d+)(?:LL)?\)', line)
            if not m or int(m.group(1)) not in allowed:
                continue
            vals = _re.findall(r'([\^+\-])\s*(0x[0-9A-Fa-f]+|\d+)', line[m.end():])
            vals = [v for v in vals if int(v[1], 0) > 1]
            if not vals:
                continue
            op, key = vals[0]
            out.append((op, int(key, 0)))
        return out
    ev = _word_ops(_read('GIMeta_SetupEventsLocked'), {8, 10, 12})
    if len(ev) >= 3:
        for nm, (op, key) in zip(('add', 'remove', 'raise'), ev[:3]):
            out.setdefault('fieldDecode', {}).setdefault('event', {})[nm] = {
                '^': 'xor', '+': 'add', '-': 'sub'}[op] + ':0x%X' % key
    pr = _word_ops(_read('GIMeta_SetupPropertiesLocked'), {4, 6, 8})
    if len(pr) >= 2:
        for nm, (op, key) in zip(('get', 'set'), pr[:2]):
            out.setdefault('fieldDecode', {}).setdefault('property', {})[nm] = {
                '^': 'xor', '+': 'add', '-': 'sub'}[op] + ':0x%X' % key
    ptxt = _read('GIMeta_SetupParameters')
    m = _re.search(r'\+ 4\)\s*-\s*(0x[0-9A-Fa-f]+|\d+)\)?\s*\^\s*(0x[0-9A-Fa-f]+|\d+)', ptxt)
    if m:
        out.setdefault('fieldDecode', {}).setdefault('parameter', {})['nameIndexBase'] = 'sub:0x%X' % int(m.group(1), 0)
        out.setdefault('fieldDecode', {}).setdefault('parameter', {})['nameIndexXor'] = 'xor:0x%X' % int(m.group(2), 0)

    # ---- 从目标 decomp 语义规则提取字段密钥 ----
    # 这里不写版本号、不写具体 key、不写字段偏移：规则只描述“哪个读取形状代表哪个角色”。
    _alltxt = ''.join(open(fp, encoding='utf-8', errors='ignore').read()
                       for fp in _glob.glob(os.path.join(root, 'ida', 'decomp', '*.c')))
    _K = r'(?P<key>0x[0-9A-Fa-f]+|\d+)'
    _OP = r'(?P<op>[\^+\-])'

    def _set_fd(st, nm, op, key):
        out.setdefault('fieldDecode', {}).setdefault(st, {})[nm] = \
            '%s:0x%X' % ({'^': 'xor', '+': 'add', '-': 'sub'}.get(op, op), key)

    def _accesses(text, type_re, limit=70):
        """抽取 *(_TYPE *)(expr + off) op key；expr 可嵌套，off 取最外层最后一个 +N。"""
        pat = (r'\*\(\s*(?:' + type_re + r')\s*\*\)\s*\([^\n;]*'
               r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
        out2 = []
        for m in _re.finditer(pat, text):
            try:
                off = int(m.group('off'), 0)
                key = int(m.group('key'), 0)
            except Exception:
                continue
            if off < limit and key > 1:
                out2.append((off, m.group('op'), key, m.group(0)))
        return out2

    def _first(text, pat, fixed_op=None, limit=70):
        for m in _re.finditer(pat, text):
            d = m.groupdict()
            try:
                off = int(d.get('off') or 0, 0)
                key = int(d['key'], 0)
            except Exception:
                continue
            if off < limit and key > 1:
                return off, (d.get('op') or fixed_op), key
        return None

    def _last(text, pat, fixed_op=None, limit=70):
        got = None
        for m in _re.finditer(pat, text):
            d = m.groupdict()
            try:
                off = int(d.get('off') or 0, 0)
                key = int(d['key'], 0)
            except Exception:
                continue
            if off < limit and key > 1:
                got = (off, (d.get('op') or fixed_op), key)
        return got

    # event / property：取简单事件/属性记录上的 WORD 访问，按源码出现顺序命名。
    # 用“行内 cast + 后续相邻数值运算”解析，兼容 7.0 的 `- v26 + 9297` 形式。
    def _record_accesses(text, limit=32):
        rows = []
        head = _re.compile(r'\*\(\s*(?:_WORD|unsigned __int16)\s*\*\)\s*\([^\n;]*?\+\s*(\d+)(?:LL)?\s*\)')
        for line in text.splitlines():
            m = head.search(line)
            if not m:
                continue
            off = int(m.group(1), 0)
            if off >= limit:
                continue
            vals = _re.findall(r'([\^+\-])\s*(0x[0-9A-Fa-f]+|\d+)', line[m.end():])
            vals = [v for v in vals if int(v[1], 0) > 1]
            if vals:
                op, key = vals[0]
                rows.append((off, op, int(key, 0)))
        # 同一偏移只保留第一次出现（例如 7.0 的 get 同时有比较行和取值行）
        seen = set(); uniq = []
        for off, op, key in rows:
            if off in seen:
                continue
            seen.add(off); uniq.append((off, op, key))
        return uniq

    ev = _record_accesses(_read('GIMeta_SetupEventsLocked'))
    for nm, (_, op, key) in zip(('add', 'remove', 'raise'), ev):
        _set_fd('event', nm, op, key)
    pr = _record_accesses(_read('GIMeta_SetupPropertiesLocked'))
    for nm, (_, op, key) in zip(('get', 'set'), pr):
        _set_fd('property', nm, op, key)

    # parameter.nameIndex：形如 (*(u32*)(...+N) - BASE) ^ XOR；偏移由文本捕获。
    ptxt = _read('GIMeta_SetupParameters')
    pm = _re.search(r'\*\(\s*_DWORD\s*\*\)\s*\([^\n;]*\+\s*\d+(?:LL)?\s*\)\s*-\s*'
                    r'(?P<base>0x[0-9A-Fa-f]+|\d+)\)?\s*\^\s*(?P<xor>0x[0-9A-Fa-f]+|\d+)', ptxt)
    if pm:
        _set_fd('parameter', 'nameIndexBase', '-', int(pm.group('base'), 0))
        _set_fd('parameter', 'nameIndexXor', '^', int(pm.group('xor'), 0))

    # typeDef.namespaceIndex：类型名/命名空间访问里对 typeDef+0 的减法。
    for fn in ('GIMeta_IterNestedTypes', 'GIMeta_Helper_5158B0',
               'GIMeta_FindTypeByName2', 'GIMeta_TypePredicate'):
        tx = _read(fn)
        m = _re.search(r'\*\(\s*_DWORD\s*\*\)\s*\(\s*\w+\s*\)\s*-\s*' + _K, tx)
        if not m:
            m = _re.search(r'\*\*\(\s*_DWORD\s*\*\*\s*\)\s*\([^)]*\)\s*-\s*' + _K, tx)
        if m:
            _set_fd('typeDef', 'namespaceIndex', '-', int(m.group('key'), 0))
            break

    # typeDef 读取形状：函数语义 + 位宽 + 操作符，偏移全部从文本捕获。
    # unknown20：SetupTypeInfoLocked 里的 32 位 ^ 读取（排除 WORD 的 interfacesStart）。
    for off, op, key, line in _accesses(_read('GIMeta_SetupTypeInfoLocked'), r'_DWORD|int', 70):
        if op == '^' and key > 0x10000 and '*(_QWORD *)' in line:
            _set_fd('typeDef', 'unknown20', op, key)
            break
    # genericContainerIndex：SetupNestedLocked 里 16 位的减法读取。
    for m in _re.finditer(r'\*\(\s*(?:_WORD|_int16|__int16)\s*\*\)\s*\([\s\S]{0,500}'
                          r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*-\s*' + _K,
                          _read('GIMeta_SetupNestedLocked')):
        off, key = int(m.group('off'), 0), int(m.group('key'), 0)
        if off < 70 and key > 1:
            _set_fd('typeDef', 'genericContainerIndex', '-', key)
            break
    # interfacesStart：SetupTypeInfoLocked 里的 16 位 ^ 读取。
    hit = _first(_read('GIMeta_SetupTypeInfoLocked'),
                 r'\*\(\s*(?:unsigned __int16|_WORD)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'interfacesStart', hit[1], hit[2])
    # field_count：SetupFieldsLocked 里的 16 位读取（fieldStart 是 32 位）。
    hit = _first(_read('GIMeta_SetupFieldsLocked'),
                 r'\*\(\s*(?:unsigned __int16|_WORD)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'field_count', hit[1], hit[2])
    # property_count：SetupPropertiesLocked 里的 8 位读取。
    hit = _first(_read('GIMeta_SetupPropertiesLocked'),
                 r'\*\(\s*(?:unsigned __int8|_BYTE)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'property_count', hit[1], hit[2])
    # interfaces_count：SetupNestedLocked 里的 8 位读取。
    hit = _first(_read('GIMeta_SetupNestedLocked'),
                 r'\*\(\s*(?:unsigned __int8|_BYTE)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'interfaces_count', hit[1], hit[2])
    # nestedTypesStart / nestedTypesCount：IterNestedTypes 的 16/8 位读取。
    hit = _first(_read('GIMeta_IterNestedTypes'),
                 r'\*\(\s*(?:unsigned __int16|_WORD|__int16)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'nestedTypesStart', hit[1], hit[2])
    hit = _first(_read('GIMeta_IterNestedTypes'),
                 r'\*\(\s*(?:unsigned __int8|_BYTE)\s*\*\)\s*\([^\n;]*'
                 r'\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*' + _OP + r'\s*' + _K)
    if hit:
        _set_fd('typeDef', 'nestedTypesCount', hit[1], hit[2])
    # eventStart / eventCount：SetupEventsLocked 里对 typeDef 的 16/8 位读取。
    for nm, tre in (('eventStart', r'_WORD|unsigned __int16'), ('event_count', r'_BYTE|unsigned __int8')):
        for off, op, key, line in _accesses(_read('GIMeta_SetupEventsLocked'), tre, 70):
            if '_QWORD *' in line:
                _set_fd('typeDef', nm, op, key)
                break
    # method_count：RuntimeInit 里对 WORD 的 != KEY（count=0 的哨兵）。
    for m in _re.finditer(r'\*\(\s*_WORD\s*\*\)\s*\([^\n;]*\+\s*(?P<off>\d+)(?:LL)?\s*\)\s*!=\s*' + _K,
                          _read('GIMeta_RuntimeInit')):
        off, key = int(m.group('off'), 0), int(m.group('key'), 0)
        if off < 70 and key > 1:
            _set_fd('typeDef', 'method_count', '-', key)
            break

    # method.nameIndex：GetMethodNameFromIndex 中 26 字节方法表 +0 的读取。
    tx = _read('GIMeta_GetMethodNameFromIndex')
    m = _re.search(r'\*\(\s*_DWORD\s*\*\)\s*\(\s*\w+\s*\+\s*[A-Za-z_]\w*\s*\)\s*-\s*' + _K, tx)
    if m:
        _set_fd('method', 'nameIndex', '-', int(m.group('key'), 0))
    # method.returnType / declaringType：26 字节表 +N 的 XOR 读取。
    for st, nm, prefix in (('method', 'returnType', 'GIMeta_GetMethodDeclClass'),
                           ('method', 'declaringType', 'GIMeta_GetMethodInfoFromIndex')):
        tx = _read(prefix)
        m = _re.search(r'26\s*(?:LL)?\s*\*\s*[^;\n]{0,120}?\+\s*(?P<off>\d+)\s*\)'
                       r'([\s\S]{0,500})', tx)
        if m:
            ks = _re.findall(r'\^\s*(0x[0-9A-Fa-f]+|\d+)', m.group(2))
            # 26 字节表达式里先出现逐索引 key，再出现字段解码 key；取第二个。
            if len(ks) >= 2:
                _set_fd(st, nm, '^', int(ks[1], 0))
    # method.flags / iflags：SetupMethodsLocked 中写入方法结构的两条 WORD 读取。
    mwords = []
    for line in _read('GIMeta_SetupMethodsLocked').splitlines():
        if '=' not in line:
            continue
        lhs, rhs = line.split('=', 1)
        if '_WORD' not in lhs and 'WORD *' not in lhs:
            continue
        vals = _accesses(rhs, r'_WORD|unsigned __int16', 32)
        if vals:
            mwords.append(vals[0])
    for nm, row in zip(('flags', 'iflags'), mwords):
        _set_fd('method', nm, row[1], row[2])
    # method.parameterStart：SetupParameters 里偏移最小、且在全量 decomp 中出现最多的 DWORD 减法。
    pc = []
    for off, op, key, line in _accesses(_read('GIMeta_SetupParameters'), r'_DWORD|int', 26):
        if op == '-':
            pc.append((_alltxt.count(str(key)), off, key))
    if pc:
        pc.sort(reverse=True)
        _set_fd('method', 'parameterStart', '-', pc[0][2])
    # field.nameIndexXor：字段名解密链上的最后一个数值 XOR。
    fkeys = []
    for line in _read('GIMeta_GetFieldName').splitlines() + _read('GIMeta_SetupFieldsLocked').splitlines():
        if 'sub_14050F280' not in line and 'sub_14050' not in line:
            continue
        ks = _re.findall(r'\^\s*(0x[0-9A-Fa-f]+|\d+)', line)
        if ks:
            fkeys.append(int(ks[-1], 0))
    if fkeys:
        _set_fd('field', 'nameIndexXor', '^', max(set(fkeys), key=fkeys.count))
    # genericContainer.parameterStart：GetGenericMethodParamInfo/BuildMethodName 的 DWORD XOR。
    gc = []
    for off, op, key, line in _accesses(_read('GIMeta_GetGenericMethodParamInfo') + _read('GIMeta_BuildMethodName'),
                                        r'_DWORD|int', 16):
        if op == '^':
            gc.append((_alltxt.count(str(key)), off, key))
    if gc:
        gc.sort(reverse=True)
        _set_fd('genericContainer', 'parameterStart', '^', gc[0][2])
    # genericContainer.argc：同一组函数里 +8 的 DWORD 减法读取。
    ga = []
    for off, op, key, line in _accesses(_read('GIMeta_GetGenericMethodParamInfo') + _read('GIMeta_BuildMethodName'),
                                        r'_DWORD|int', 16):
        if op == '-':
            ga.append((_alltxt.count(str(key)), off, key))
    if ga:
        ga.sort(reverse=True)
        _set_fd('genericContainer', 'argc', '-', ga[0][2])

    # nestedTypesStart 缺失时，用 nestedTypesCount 的相邻 gap 自证（不写死偏移）。
    if 'nestedTypesStart' not in fd.get('typeDef', {}):
        nspec = fd.get('typeDef', {}).get('nestedTypesCount')
        if nspec:
            nop, _, nkey = nspec.partition(':')
            nop = {'sub': '-', 'add': '+', 'xor': '^'}.get(nop, nop)
            nkey = int(nkey, 0)
            ncand = None
            for c in ctx.cands:
                if c['width'] == 'BYTE' and c['op'] == nop and c['key'] == nkey:
                    if any('IterNestedTypes' in f or 'GetMethodInfo' in f for f in c['funcs']):
                        ncand = c
                        break
            if ncand:
                C = ctx.array(ncand, td, 70, min(n, 4000))
                best = None
                for o in range(0, 72):
                    raws = [read_int(ctx.dat, H + td + 70 * i + o, 2) for i in range(len(C))]
                    valid = [(i, raws[i]) for i in range(len(C)) if C[i] > 0]
                    good = total = 0
                    gap = 0
                    for (i, r), (j, r2) in zip(valid, valid[1:]):
                        d = (r2 - r) & 0xFFFF
                        total += 1
                        if d >= C[i]:
                            good += 1
                            gap += d - C[i]
                    if total >= 20 and good / total >= 0.95:
                        avg = gap / good if good else 9999
                        if best is None or (good / total, -avg) > (best[0], -best[4]):
                            best = (good / total, o, raws, valid, avg)
                if best:
                    sc, o, raws, valid, avg = best
                    first = next((i for i in range(len(C)) if C[i] > 0), None)
                    start_key = ((-raws[first]) & 0xFFFF) if first is not None else 0
                    c = {'disp': o, 'width': 'WORD', 'op': '+', 'key': start_key, 'funcs': []}
                    put('typeDef', 'nestedTypesStart', c)
                    out['evidence']['nestedTypesStart'] = {
                        'score': round(sc, 4), 'disp': o, 'key': '0x%X' % start_key}

    # ---- 用已确认的 fieldDecode 语义反推 structOffsets ----
    # 候选条目里的 disp 就是目标结构体的真实偏移；这里只做“字段名 -> 名字”的映射，
    # 不依赖上一版的布局常数，因此 7.0/7.1 这类字段重排也能跟上。
    _struct_map = {
        'typeDef': 'Il2CppTypeDefinition',
        'method': 'Il2CppMethodDefinition',
        'field': 'Il2CppFieldDefinition',
        'property': 'Il2CppPropertyDefinition',
        'event': 'Il2CppEventDefinition',
        'parameter': 'Il2CppParameterDefinition',
        'genericContainer': 'Il2CppGenericContainer',
        'genericParameter': 'Il2CppGenericParameter',
        'image': 'Il2CppImageDefinition',
    }
    _skip_offsets = {
        # 这些是解码密钥而不是结构体布局；或者目标 structOffsets 不使用该名字
        ('property', 'nameIndex'), ('event', 'typeIndex'), ('event', 'nameIndex'),
        ('image', 'nameIndexXor'), ('parameter', 'nameIndexBase'),
        ('parameter', 'nameIndexXor'), ('field', 'nameIndexBase'), ('field', 'nameIndexXor'),
    }
    _width_hint = {
        ('typeDef', 'nameIndex'): 'DWORD', ('typeDef', 'namespaceIndex'): 'DWORD',
        ('typeDef', 'propertyStart'): 'DWORD', ('typeDef', 'methodStart'): 'DWORD',
        ('method', 'parameterStart'): 'DWORD', ('method', 'returnType'): 'DWORD',
        ('method', 'declaringType'): 'DWORD', ('method', 'iflags'): 'WORD',
        ('method', 'flags'): 'WORD', ('method', 'parameterCount'): 'BYTE',
        ('genericContainer', 'argc'): 'DWORD', ('genericContainer', 'parameterStart'): 'DWORD',
    }

    def _spec_parts(spec):
        op, _, key = str(spec).partition(':')
        op = {'sub': '-', 'add': '+', 'xor': '^'}.get(op, op)
        return op, int(key, 0)

    def _cand_for(struct, field, spec):
        op, key = _spec_parts(spec)
        wants = _width_hint.get((struct, field))
        hits = []
        for c in ctx.cands:
            if norm_op(c['op']) != op or c['key'] != key:
                continue
            if wants and c['width'] != wants:
                # 7.1 里有把 WORD/DWORD 导成 QWORD 的候选；只放宽到更宽的视图
                if not (wants in ('WORD', 'DWORD') and c['width'] == 'QWORD'):
                    continue
            hits.append(c)
        if not hits:
            return None
        # 同一 key 往往只在目标函数里出现一次；若多次出现，优先带目标函数上下文的条目
        fns = {
            'event': ('SetupEventsLocked',), 'property': ('SetupPropertiesLocked',),
            'parameter': ('SetupParameters',), 'field': ('SetupFieldsLocked',),
            'method': ('SetupMethodsLocked', 'SetupParameters', 'GetMethodName',
                       'GetMethodDeclClass', 'GetMethodInfoFromIndex'),
            'typeDef': ('SetupTypeInfoLocked', 'SetupFieldsLocked', 'SetupEventsLocked',
                        'SetupPropertiesLocked', 'SetupNestedLocked', 'IterNestedTypes',
                        'GetMethodInfo2', 'GetMethodNameFromIndex', 'RuntimeInit'),
            'genericContainer': ('GetGenericMethodParamInfo', 'BuildMethodName', 'SetupNestedLocked'),
            'genericParameter': ('GetGenericParameterInfo',),
            'image': ('RuntimeInit',),
        }.get(struct, ())
        preferred = [c for c in hits if any(f in f for f in c.get('funcs', []) for f in fns)]
        pool = preferred or hits
        disps = {c['disp'] for c in pool}
        if len(disps) != 1:
            # 多个偏移时优先选择带语义函数上下文的条目；仍不唯一就放弃
            if not preferred:
                return None
            pool = preferred
            disps = {c['disp'] for c in pool}
            if len(disps) != 1:
                return None
        return pool[0]

    for struct, fields in fd.items():
        target = _struct_map.get(struct)
        if not target:
            continue
        for field, spec in fields.items():
            if (struct, field) in _skip_offsets:
                continue
            if field == 'nameIndexXor' and struct == 'image':
                field = 'nameIndex'
            c = _cand_for(struct, field, spec)
            if c:
                setso(target, field, c['disp'])

    # image.nameIndexXor 的实际偏移
    ic = _cand_for('image', 'nameIndexXor', fd.get('image', {}).get('nameIndexXor', ''))
    if ic:
        setso('Il2CppImageDefinition', 'nameIndex', ic['disp'])

    # 方法表固定位置：nameIndex 通常为 0；slot/token 同槽位，7.0/7.1 名字不同
    if 'method' in fd:
        setso('Il2CppMethodDefinition', 'nameIndex', 0)
        tok = None
        for c in ctx.cands:
            if c['disp'] == 20 and any('SetupMethodsLocked' in f for f in c.get('funcs', [])):
                tok = c
                break
        if tok:
            setso('Il2CppMethodDefinition', 'slot', 20)
            setso('Il2CppMethodDefinition', 'token', 20)

    # 从反编译文本里找“某个 26 字节方法表访问”的字段偏移
    _decomp = []
    for _fp in _glob.glob(os.path.join(root, 'ida', 'decomp', '*.c')):
        _decomp.append(open(_fp, encoding='utf-8', errors='ignore').read())
    _all_decomp = ''.join(_decomp)

    def _lits(key):
        return [str(key), '0x%X' % key, '0x%x' % key]

    def _near_key(text, key, regex, window=800):
        """在 key 之前 window 字符里匹配 regex，返回最后一个分组。"""
        for lit in _lits(key):
            for m in _re.finditer(_re.escape(lit), text, _re.I):
                pre = text[max(0, m.start() - window):m.start()]
                ms = list(_re.finditer(regex, pre))
                if ms:
                    return ms[-1]
        return None

    # typeDef.namespaceIndex：优先由“解引用/数组下标”方式确定，其次才是固定偏移。
    # 7.1: *(_DWORD *)v2 - KEY  (0)；v12[0] - KEY  (0)
    td_fd = fd.get('typeDef', {})
    nsspec = td_fd.get('namespaceIndex')
    if nsspec and not _cand_for('typeDef', 'namespaceIndex', nsspec):
        _, nsk = _spec_parts(nsspec)
        mm = _near_key(_all_decomp, nsk,
                       r'(?:\*\(_DWORD \*\)\s*\w+|\*\s*\w+|\[\s*(\d+)\s*\])\s*-\s*$',
                       window=120)
        if mm:
            off = int(mm.group(1) or '0', 0) * 4
            if off < 70:
                setso('Il2CppTypeDefinition', 'namespaceIndex', off)

    # typeDef.method_count：读形如 *(_WORD *)(ptr + N) != KEY
    mspec = td_fd.get('method_count')
    if mspec:
        _, mk = _spec_parts(mspec)
        mm = _near_key(_all_decomp, mk,
                       r'\*\(_WORD \*\)\([^)]*?\+\s*(\d+)\s*\)\s*!=\s*$',
                       window=120)
        if mm:
            off = int(mm.group(1), 0)
            if off < 70:
                setso('Il2CppTypeDefinition', 'method_count', off)

    # typeDef.genericContainerIndex：形如 *(_WORD *)(ptr + N) ... - KEY
    gspec = td_fd.get('genericContainerIndex')
    if gspec and not _cand_for('typeDef', 'genericContainerIndex', gspec):
        _, gk = _spec_parts(gspec)
        for lit in _lits(gk):
            for m in _re.finditer(_re.escape(lit), _all_decomp, _re.I):
                pre = _all_decomp[max(0, m.start() - 800):m.start()]
                if not _re.search(r'\(_WORD \*\)', pre):
                    continue
                nums = _re.findall(r'\+\s*(\d+)\s*\)', pre)
                if nums:
                    off = int(nums[-1], 0)
                    if off < 70:
                        setso('Il2CppTypeDefinition', 'genericContainerIndex', off)
                    break

    # method.returnType / declaringType：26 字节方法表访问，如 26*v + 8
    mfd = fd.get('method', {})
    for field in ('returnType', 'declaringType'):
        spec = mfd.get(field)
        if not spec:
            continue
        _, k = _spec_parts(spec)
        mm = _near_key(_all_decomp, k,
                       r'26\s*(?:LL)?\s*\*\s*[^;\n]{0,100}?\+\s*(\d+)\s*\)',
                       window=1200)
        if mm:
            off = int(mm.group(1), 0)
            if off < 26:
                setso('Il2CppMethodDefinition', field, off)

    # typeDef bitfield：找相邻两个已知字段之间 2 字节的空洞
    tdo = so.get('Il2CppTypeDefinition', {})
    known = sorted((v, k) for k, v in tdo.items() if k != 'bitfield')
    bit = None
    for n, (off, nm) in enumerate(known):
        nxt = next(((o, n2) for o, n2 in known[n + 1:] if o > off), None)
        if nxt and nxt[0] - off == 4 and nxt[1] in ('genericContainerIndex', 'interfacesStart'):
            bit = off + 2
            break
    if bit is None:
        # 7.1: field_count(56) / interfacesStart(60)
        if 'field_count' in tdo and 'interfacesStart' in tdo and tdo['interfacesStart'] - tdo['field_count'] == 4:
            bit = tdo['field_count'] + 2
        elif 'method_count' in tdo and 'genericContainerIndex' in tdo and tdo['genericContainerIndex'] - tdo['method_count'] == 4:
            bit = tdo['method_count'] + 2
    if bit is not None:
        setso('Il2CppTypeDefinition', 'bitfield', bit)

    # 两个 default value 结构体布局相同；用更可靠的 fieldDefault 结果复制到 parameterDefault
    fdo = so.get('Il2CppFieldDefaultValue', {})
    pdo = so.get('Il2CppParameterDefaultValue', {})
    if len(fdo) == 3:
        for k, v in fdo.items():
            nk = 'parameterIndex' if k == 'fieldIndex' else k
            pdo[nk] = v
        so['Il2CppParameterDefaultValue'] = pdo

    os.makedirs(os.path.dirname(a.out or os.path.join(root, 'ida', 'fielddecode.auto.json')), exist_ok=True)
    outp = a.out or os.path.join(root, 'ida', 'fielddecode.auto.json')
    json.dump(out, open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('已写', outp)
    for st in fd:
        print(' ', st, sorted(fd[st]))
    for st in so:
        print(' ', st, so[st])


if __name__ == '__main__':
    main()
