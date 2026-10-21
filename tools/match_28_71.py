#!/usr/bin/env python3
"""Match a 7.1 dump against an older, unobfuscated 2.8 dump.

The 2.8 dump has no // FullName lines, so both dumps are parsed from their
class/method shape. Matching is deliberately conservative:

  * exact assembly + full name first
  * otherwise structural fingerprint (kind, method shapes, fields, props)
  * methods are matched inside an already matched class

Output is a JSON mapping plus a TSV report.  Low-confidence matches are kept
in the report but are not silently applied to any dump.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import heapq
import json
import math
import multiprocessing
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable


KNOWN = {
    'void', 'bool', 'byte', 'sbyte', 'short', 'ushort', 'int', 'uint',
    'long', 'ulong', 'float', 'double', 'string', 'object', 'char',
    'decimal', 'IntPtr', 'UIntPtr',
}
MODIFIERS = {
    'public', 'private', 'protected', 'internal', 'static', 'virtual',
    'override', 'abstract', 'sealed', 'extern', 'unsafe', 'new', 'readonly',
    'partial', 'async', 'const', 'fixed', 'volatile',
}
TYPE_DECL = re.compile(r'\b(class|struct|interface|enum)\s+([^\s:{]+)')
IMAGE_RE = re.compile(r'^// Image\s+(\d+):\s*(.*?)\s*-\s*(\d+)')
NAMESPACE_RE = re.compile(r'^// Namespace:\s*(.*)')
FULLNAME_RE = re.compile(r'^// FullName:\s*(.*)')
TYPEDEF_RE = re.compile(r'// TypeDefIndex:\s*(\d+)')
RVA_RE = re.compile(r'^\s*// RVA:\s*(-?0x[0-9A-Fa-f]+|-1)\b')


@dataclass
class Method:
    name: str
    decl: str
    rva: int | None
    ret: str
    params: tuple[str, ...]
    flags: frozenset[str]
    generic_arity: int
    ordinal: int = 0
    ret_raw: str = ''
    params_raw: tuple[str, ...] = ()

    @property
    def shape(self):
        return (self.ret, self.params, self.flags)


@dataclass
class TypeInfo:
    type_index: int
    ns: str
    name: str
    full: str
    kind: str
    assembly: str
    decl: str
    methods: list[Method] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    props: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    raw_fields: list[str] = field(default_factory=list)
    raw_props: list[str] = field(default_factory=list)
    raw_events: list[str] = field(default_factory=list)
    field_names: list[str] = field(default_factory=list)
    prop_names: list[str] = field(default_factory=list)
    event_names: list[str] = field(default_factory=list)
    enum_values: list[tuple[str, int]] = field(default_factory=list)
    constants: list[tuple[str, int]] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)

    @property
    def semantic(self):
        if not hasattr(self, '_semantic_cache'):
            self._semantic_cache = semantic_features(self)
        return self._semantic_cache

    @property
    def method_shapes(self):
        # Recall-oriented fingerprint (C for custom refs).  The per-class
        # C0/C1/SELF fingerprint is applied as a re-ranking signal below.
        if not hasattr(self, '_method_shapes_cache'):
            self._method_shapes_cache = [m.shape for m in self.methods]
        return self._method_shapes_cache

    @property
    def method_counts(self):
        if not hasattr(self, '_method_counts_cache'):
            self._method_counts_cache = collections.Counter(self.method_shapes)
        return self._method_counts_cache

    @property
    def field_counts(self):
        if not hasattr(self, '_field_counts_cache'):
            self._field_counts_cache = collections.Counter(self.fields)
        return self._field_counts_cache

    @property
    def prop_counts(self):
        if not hasattr(self, '_prop_counts_cache'):
            self._prop_counts_cache = collections.Counter(self.props)
        return self._prop_counts_cache

    @property
    def field_name_counts(self):
        if not hasattr(self, '_field_name_counts_cache'):
            self._field_name_counts_cache = collections.Counter(self.field_names)
        return self._field_name_counts_cache

    @property
    def prop_name_counts(self):
        if not hasattr(self, '_prop_name_counts_cache'):
            self._prop_name_counts_cache = collections.Counter(self.prop_names)
        return self._prop_name_counts_cache

    @property
    def usable_name_counts(self):
        if not hasattr(self, '_usable_name_counts_cache'):
            self._usable_name_counts_cache = collections.Counter(
                m.name for m in self.methods if method_name_usable(m.name))
        return self._usable_name_counts_cache

    @property
    def base_counts(self):
        if not hasattr(self, '_base_counts_cache'):
            self._base_counts_cache = collections.Counter(self.semantic['bases'])
        return self._base_counts_cache

    @property
    def raw_custom_refs(self):
        if not hasattr(self, '_raw_custom_refs_cache'):
            c = collections.Counter()
            for raw in (self.raw_fields or self.fields):
                x = custom_base_type(raw)
                if x:
                    c[x] += 1
            for m in self.methods:
                for raw in ((m.ret_raw or m.ret),) + tuple(m.params_raw or m.params):
                    x = custom_base_type(raw)
                    if x:
                        c[x] += 1
            self._raw_custom_refs_cache = c
        return self._raw_custom_refs_cache


def base_name(s: str) -> str:
    """Remove generic arguments while preserving namespace/nested dots."""
    dep = 0
    out = []
    for ch in s:
        if ch == '<':
            dep += 1
        elif ch == '>':
            dep = max(0, dep - 1)
        elif dep == 0:
            out.append(ch)
    return ''.join(out).strip()


def strip_mods(s: str) -> str:
    toks = s.strip().split()
    while toks and toks[0] in MODIFIERS:
        toks.pop(0)
    return ' '.join(toks)


def shape_type(t: str) -> str:
    t = re.sub(r'\b(const|ref|out|in|params|this)\b', '', t)
    t = re.sub(r'\s+', '', t)
    t = t.replace('[]', '[]')
    if t in KNOWN:
        return t
    if t.endswith('*'):
        return 'P'
    if '[' in t or t.endswith(']'):
        return 'A'
    if '<' in t:
        return 'G'
    # Keep stable engine/Bcl type names; custom/obfuscated class names are
    # collapsed to C so 7.1 and 2.8 do not need identical custom identifiers.
    base = t.split('.')[-1]
    if t.startswith('UnityEngine.') or t.startswith('System.'):
        return 'T:' + base
    if t.startswith('Mono.') or t.startswith('Microsoft.'):
        return 'T:' + base
    return 'C'


def split_params(s: str) -> list[str]:
    out, buf, dep = [], '', 0
    for ch in s:
        if ch in '<[(':
            dep += 1
        elif ch in '>])':
            dep = max(0, dep - 1)
        if ch == ',' and dep == 0:
            out.append(buf)
            buf = ''
        else:
            buf += ch
    if buf.strip():
        out.append(buf)
    return out


def param_types(decl: str) -> tuple[str, ...]:
    m = re.search(r'\((.*)\)', decl)
    if not m:
        return ()
    res = []
    for p in split_params(m.group(1)):
        p = p.strip()
        if '=' in p:
            p = p.split('=', 1)[0].strip()
        # remove attributes
        p = re.sub(r'^\[[^\]]*\]\s*', '', p)
        # strip parameter name: the last identifier is the name
        mm = re.match(r'(.+?)\s+[A-Za-z_]\w*$', p)
        if mm and not p.endswith(('>', ']', '*')):
            p = mm.group(1)
        res.append(re.sub(r'\s+', '', p))
    return tuple(res)


def param_shapes(decl: str) -> tuple[str, ...]:
    return tuple(shape_type(x) for x in param_types(decl))


def ret_raw(decl: str, method_name: str) -> str:
    # Find the method name immediately followed by '('.
    pos = decl.find(method_name + '(')
    if pos < 0:
        pos = decl.find(method_name)
    pre = strip_mods(decl[:pos]).strip() if pos >= 0 else ''
    if not pre:
        return 'void'
    # remove operator/generic noise; return type is the last token-ish
    pre = re.sub(r'\b(operator|implicit|explicit)\b', '', pre).strip()
    return pre.split()[-1] if pre.split() else 'void'


def ret_shape(decl: str, method_name: str) -> str:
    return shape_type(ret_raw(decl, method_name))


def parse_method(decl: str, rva: int | None, ordinal: int) -> Method | None:
    decl = decl.split('//', 1)[0].strip()
    decl = re.sub(r'\{\s*\}\s*$', '', decl).strip()
    decl = decl.rstrip(';').strip()
    if not decl or decl.startswith('//'):
        return None
    m = re.search(r'([~A-Za-z_\.<>][\w\.<>]*)\s*\(', decl)
    if not m:
        return None
    name = m.group(1)
    flags = frozenset(x for x in decl.split() if x in MODIFIERS)
    gen = 0
    # method generic arity: name<...>(, but class generic args may also appear
    gm = re.search(re.escape(name) + r'\s*<([^<>]*)>\s*\(', decl)
    if gm:
        gen = len(split_params(gm.group(1))) if gm.group(1).strip() else 0
    return Method(name, decl, rva, ret_shape(decl, name), param_shapes(decl),
                  flags, gen, ordinal,
                  ret_raw=ret_raw(decl, name), params_raw=param_types(decl))


def parse_dump(path: str) -> tuple[list[TypeInfo], list[tuple[str, int]]]:
    lines = open(path, encoding='utf-8', errors='ignore').read().splitlines()
    images: list[tuple[str, int]] = []
    for line in lines:
        m = IMAGE_RE.match(line)
        if m:
            images.append((m.group(2), int(m.group(3))))
    images.sort(key=lambda x: x[1])

    types: list[TypeInfo] = []
    cur: TypeInfo | None = None
    ns = ''
    full = ''
    section = ''
    pending_rva: int | None = None
    mid = 0

    def finish():
        nonlocal cur
        if cur is not None:
            # method ordinals already assigned while parsing
            types.append(cur)
            cur = None

    for line in lines:
        mn = NAMESPACE_RE.match(line)
        if mn:
            ns = mn.group(1).strip()
            continue
        mf = FULLNAME_RE.match(line)
        if mf:
            full = mf.group(1).strip()
            continue
        # class declaration
        if TYPEDEF_RE.search(line) and TYPE_DECL.search(line):
            finish()
            tm = TYPEDEF_RE.search(line)
            dm = TYPE_DECL.search(line)
            idx = int(tm.group(1))
            raw_name = dm.group(2)
            name = base_name(raw_name)
            kind = dm.group(1)
            if not full:
                full = (ns + '.' if ns else '') + name
            asm = images[-1][0] if images else ''
            for n, start in images:
                if start <= idx:
                    asm = n
                else:
                    break
            cur = TypeInfo(idx, ns, name, full or name, kind, asm, line.strip())
            decl_head = line.split('//', 1)[0].strip()
            if ':' in decl_head:
                base_part = decl_head.split(':', 1)[1].strip()
                cur.bases = [re.sub(r'\s+', '', x) for x in split_params(base_part)
                             if x.strip() and x.strip() != 'where']
            full = ''
            section = ''
            pending_rva = None
            mid = 0
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith('// Fields'):
            section = 'fields'
            continue
        if s.startswith('// Properties'):
            section = 'props'
            continue
        if s.startswith('// Events'):
            section = 'events'
            continue
        if s.startswith('// Methods') or s.startswith('// Constructors'):
            section = 'methods'
            continue
        if RVA_RE.match(line):
            rv = RVA_RE.match(line).group(1)
            pending_rva = -1 if rv == '-1' else int(rv, 16)
            continue
        if not s or s.startswith('//') or s.startswith('/*') or s.startswith('|'):
            continue
        if section == 'methods':
            meth = parse_method(s, pending_rva, mid)
            if meth is not None:
                mid += 1
                cur.methods.append(meth)
                pending_rva = None
            continue
        if section == 'fields':
            # field declaration before // 0x...
            left = s.split('//', 1)[0].strip()
            if left.endswith(';'):
                left = left[:-1].strip()
            if not left:
                continue
            # Enum members and const fields survive obfuscation much more
            # often than class names; keep their name/value pairs.
            if '=' in left:
                em = re.match(r'.*?\b([A-Za-z_]\w*)\s*=\s*(-?\d+)\s*$', left)
                if em:
                    name, val = em.group(1), int(em.group(2))
                    if cur.kind == 'enum' and name != 'value__':
                        cur.enum_values.append((name, val))
                    if re.search(r'\bconst\b', left):
                        cur.constants.append((name, val))
                continue
            # remove modifiers; type is before the last identifier
            mm = re.match(r'(.+?)\s+([A-Za-z_]\w*)$', left)
            if mm:
                raw = strip_mods(mm.group(1))
                cur.raw_fields.append(raw)
                cur.fields.append(shape_type(raw))
                cur.field_names.append(mm.group(2))
            continue
        if section == 'props':
            if '{' in s:
                left = s.split('{', 1)[0].strip()
                mm = re.match(r'(.+?)\s+([A-Za-z_]\w*)$', left)
                if mm:
                    raw = strip_mods(mm.group(1))
                    cur.raw_props.append(raw)
                    cur.props.append(shape_type(raw))
                    cur.prop_names.append(mm.group(2))
            continue
        if section == 'events':
            left = s.rstrip(';').strip()
            mm = re.match(r'(.+?)\s+([A-Za-z_]\w*)$', left)
            if mm:
                raw = strip_mods(mm.group(1))
                cur.raw_events.append(raw)
                cur.events.append(shape_type(raw))
                cur.event_names.append(mm.group(2))
    finish()
    return types, images


def jaccard(a: collections.Counter, b: collections.Counter) -> float:
    inter = sum((a & b).values())
    union = sum((a | b).values())
    return inter / union if union else 0.0


def count_ratio(a: int, b: int) -> float:
    return min(a, b) / max(a, b) if max(a, b) else 1.0


PRIM_ALIAS = {
    'String': 'string', 'Boolean': 'bool', 'Byte': 'byte', 'SByte': 'sbyte',
    'Int16': 'short', 'UInt16': 'ushort', 'Int32': 'int', 'UInt32': 'uint',
    'Int64': 'long', 'UInt64': 'ulong', 'Single': 'float', 'Double': 'double',
    'Char': 'char', 'Object': 'object', 'Void': 'void', 'Decimal': 'decimal',
}
STABLE_NS = ('System.', 'UnityEngine.', 'Mono.', 'Microsoft.', 'Unity.')


def type_ref_token(raw: str, self_names: set[str], ids: dict[str, str]) -> str:
    """Keep stable type names; give custom references per-class identities.

    C0/C1 are local identities, not the literal obfuscated name.  This keeps
    "same custom type repeated" vs "two different custom types" distinguishable
    without requiring 7.1 and 2.8 spellings to match.
    """
    raw = re.sub(r'\b(const|ref|out|in|params|this)\b', '', raw or '')
    raw = re.sub(r'^global::', '', raw.strip())
    raw = re.sub(r'\s+', '', raw)
    if not raw:
        return 'void'
    if raw.endswith('*'):
        return 'P:' + type_ref_token(raw[:-1], self_names, ids)
    if raw.endswith('[]'):
        return 'A:' + type_ref_token(raw[:-2], self_names, ids)
    if '[' in raw and raw.endswith(']'):
        # multidimensional array
        return 'A:' + type_ref_token(raw.rsplit('[', 1)[0], self_names, ids)
    if '<' in raw and raw.endswith('>'):
        outer, inner = raw.split('<', 1)
        inner = inner[:-1]
        args = split_params(inner)
        return ('G:' + type_ref_token(outer, self_names, ids) + '<' +
                ','.join(type_ref_token(x, self_names, ids) for x in args) + '>')
    raw = raw.split('::')[-1]
    base = raw.split('.')[-1]
    base = PRIM_ALIAS.get(base, base)
    if base in KNOWN:
        return 'T:' + base
    if raw.startswith(STABLE_NS):
        return 'T:' + base
    if base in self_names or raw in self_names:
        return 'SELF'
    if raw not in ids:
        ids[raw] = 'C%d' % len(ids)
    return ids[raw]


def semantic_features(t: TypeInfo):
    ids: dict[str, str] = {}
    self_names = {t.name.split('.')[-1], t.name}
    fields = [type_ref_token(x, self_names, ids) for x in (t.raw_fields or t.fields)]
    props = [type_ref_token(x, self_names, ids) for x in (t.raw_props or t.props)]
    events = [type_ref_token(x, self_names, ids) for x in (t.raw_events or t.events)]
    bases = [type_ref_token(x, self_names, ids) for x in t.bases]
    methods = []
    for m in t.methods:
        ret = type_ref_token(m.ret_raw or m.ret, self_names, ids)
        ps = [type_ref_token(x, self_names, ids)
              for x in (m.params_raw or m.params)]
        methods.append((ret, tuple(ps), m.flags))
    return {
        'fields': fields, 'props': props, 'events': events,
        'bases': bases, 'methods': methods,
        'method_counts': collections.Counter(methods),
        'field_counts': collections.Counter(fields),
        'prop_counts': collections.Counter(props),
        'event_counts': collections.Counter(events),
    }


def class_score_fast(a: TypeInfo, b: TypeInfo) -> float:
    """Cheap recall score: no difflib, no semantic re-hashing."""
    if a.kind != b.kind:
        return 0.0
    ms = jaccard(a.method_counts, b.method_counts)
    cnt = count_ratio(len(a.methods), len(b.methods))
    fs = jaccard(a.field_counts, b.field_counts)
    ps = count_ratio(len(a.props), len(b.props))
    es = count_ratio(len(a.events), len(b.events))
    ns = jaccard(a.usable_name_counts, b.usable_name_counts)
    if a.kind == 'enum' and (a.enum_values or b.enum_values):
        ea = collections.Counter(n for n, _ in a.enum_values)
        eb = collections.Counter(n for n, _ in b.enum_values)
        return 0.60 * jaccard(ea, eb) + 0.40 * ms
    return 0.40 * ms + 0.20 * cnt + 0.20 * fs + 0.05 * ps + 0.05 * es + 0.10 * ns


_ALIAS_TO_SOURCE: dict[str, str] = {}
_GRAPH_SRC: dict[int, collections.Counter] = {}
_GRAPH_DST: dict[int, collections.Counter] = {}


def _local_graph_token(t: TypeInfo):
    # One-hop structural token for a referenced type.
    return (t.kind, len(t.methods), len(t.fields), len(t.props),
            tuple(sorted(t.fields)))


def build_graph_tokens(types: list[TypeInfo]):
    by_name = {}
    for t in types:
        for key in (t.name, t.full):
            if key:
                by_name[(t.assembly, key)] = t
    out = {}
    for t in types:
        c = collections.Counter()
        for ref in t.raw_custom_refs:
            n = by_name.get((t.assembly, ref))
            if n is None:
                n = by_name.get((t.assembly, ref.split('.')[-1]))
            if n is not None:
                c[_local_graph_token(n)] += 1
            else:
                c[('UNK', ref.split('.')[-1])] += 1
        out[t.type_index] = c
    return out


def _custom_ref_counter(t: TypeInfo, target_side: bool = False) -> collections.Counter:
    base = t.raw_custom_refs
    if not target_side or not _ALIAS_TO_SOURCE:
        return base
    return collections.Counter({
        _ALIAS_TO_SOURCE.get(k, k): v for k, v in base.items()
    })


def class_score(a: TypeInfo, b: TypeInfo) -> float:
    if a.kind != b.kind:
        return 0.0
    # Recall: basic signature shapes, where custom types are C.
    ma, mb = a.method_counts, b.method_counts
    ms = jaccard(ma, mb)
    if max(len(a.method_shapes), len(b.method_shapes)) <= 200:
        seq = difflib.SequenceMatcher(None, a.method_shapes, b.method_shapes,
                                      autojunk=False).ratio()
    else:
        seq = 0.0
    cnt = count_ratio(len(a.methods), len(b.methods))
    fs = jaccard(a.field_counts, b.field_counts)
    ps = count_ratio(len(a.props), len(b.props))
    es = count_ratio(len(a.events), len(b.events))
    ns = jaccard(a.usable_name_counts, b.usable_name_counts)
    basic = (0.35 * ms + 0.15 * seq + 0.15 * cnt + 0.10 * fs +
             0.05 * ps + 0.05 * es + 0.15 * ns)

    # Enum member names are a strong signal when preserved, but 7.1 may
    # obfuscate member names too.  Treat them as soft evidence: if there is
    # no name overlap, fall back to the value sequence instead of punishing
    # the candidate.
    if a.kind == 'enum' and (a.enum_values or b.enum_values):
        ea = collections.Counter(n for n, _ in a.enum_values)
        eb = collections.Counter(n for n, _ in b.enum_values)
        names = jaccard(ea, eb)
        va = [v for _, v in a.enum_values]
        vb = [v for _, v in b.enum_values]
        vals = difflib.SequenceMatcher(None, va, vb, autojunk=False).ratio()
        if names >= 0.15:
            enum_score = 0.80 * names + 0.20 * vals
        elif vals >= 0.50:
            enum_score = vals
        else:
            # Names and values both disagree: no enum-specific evidence.
            return basic
        return 0.15 * basic + 0.85 * enum_score

    # Const field names/values are also mostly preserved.
    ca = collections.Counter(n for n, _ in a.constants)
    cb = collections.Counter(n for n, _ in b.constants)
    const_score = jaccard(ca, cb)

    # Precision re-ranking: same-class C0/C1/SELF references and stable
    # type names.  This must not be the only candidate signal, because local
    # C0/C1 numbering is not stable across versions.
    fa, fb = a.semantic, b.semantic
    sms = jaccard(fa['method_counts'], fb['method_counts'])
    if max(len(fa['methods']), len(fb['methods'])) <= 200:
        sseq = difflib.SequenceMatcher(None, fa['methods'], fb['methods'],
                                       autojunk=False).ratio()
    else:
        sseq = 0.0
    sfs = jaccard(fa['field_counts'], fb['field_counts'])
    sps = count_ratio(len(fa['props']), len(fb['props']))
    ses = count_ratio(len(fa['events']), len(fb['events']))
    semantic = 0.45 * sms + 0.25 * sseq + 0.20 * sfs + 0.05 * sps + 0.05 * ses
    base_sim = jaccard(a.base_counts, b.base_counts)
    alias_sim = jaccard(_custom_ref_counter(a), _custom_ref_counter(b, target_side=True))
    fname_sim = jaccard(a.field_name_counts, b.field_name_counts)
    pname_sim = jaccard(a.prop_name_counts, b.prop_name_counts)
    graph_sim = jaccard(_GRAPH_SRC.get(a.type_index, collections.Counter()),
                        _GRAPH_DST.get(b.type_index, collections.Counter()))
    ns_sim = 1.0 if a.ns and a.ns == b.ns else 0.0
    return (0.43 * basic + 0.20 * semantic + 0.08 * const_score +
            0.05 * base_sim + 0.08 * alias_sim +
            0.06 * fname_sim + 0.03 * pname_sim + 0.05 * graph_sim +
            0.02 * ns_sim)


def method_sim(a: Method, b: Method, a_sig=None, b_sig=None) -> float:
    ar, ap, afl = a_sig or (a.ret, a.params, a.flags)
    br, bp, bfl = b_sig or (b.ret, b.params, b.flags)
    if ar != br:
        r = 0.65 if {ar, br} <= {'int', 'uint', 'long', 'ulong'} else 0.15
    else:
        r = 1.0
    if not ap and not bp:
        p = 1.0
    else:
        p = difflib.SequenceMatcher(None, ap, bp,
                                    autojunk=False).ratio()
        n = max(len(ap), len(bp), 1)
        p *= 1.0 - 0.20 * abs(len(ap) - len(bp)) / n
    fl = 1.0 if afl == bfl else 0.85
    return ((0.25 * r + 0.65 * p + 0.10 * fl) *
            (1.0 if afl & {'static'} == bfl & {'static'} else 0.85))


def custom_base_type(raw: str) -> str | None:
    """Return the base name for a simple custom type, else None.

    Arrays/pointers are unwrapped.  Generics are intentionally skipped for
    now: mapping the outer generic without matching its arguments would create
    false aliases.
    """
    raw = re.sub(r'\b(const|ref|out|in|params|this)\b', '', raw or '')
    raw = re.sub(r'\s+', '', raw)
    while raw.endswith('[]'):
        raw = raw[:-2]
    while raw.endswith('*'):
        raw = raw[:-1]
    if not raw or '<' in raw or '>' in raw:
        return None
    base = raw.split('::')[-1].split('.')[-1]
    if base in KNOWN:
        return None
    if raw.startswith(STABLE_NS):
        return None
    return base


def method_signature(m: Method, target_side: bool = False):
    """Type-aware method signature used for actual method matching.

    Custom types are not collapsed to C.  On the 7.1 target side, a known
    alias is resolved back to the 2.8 real name.
    """
    def tok(raw: str) -> str:
        x = custom_base_type(raw)
        if x:
            if target_side and x in _ALIAS_TO_SOURCE:
                x = _ALIAS_TO_SOURCE[x]
            return 'A:' + x
        return shape_type(raw)

    ret = tok(m.ret_raw or m.ret)
    ps = tuple(tok(x) for x in (m.params_raw or m.params))
    return ret, ps, m.flags


def is_obf_name(full: str) -> bool:
    """Conservative class-name obfuscation heuristic for reporting."""
    base = full.split('.')[-1].split('<')[0]
    return bool(re.fullmatch(r'[A-Z]{8,}[0-9]*', base))


def method_name_usable(n: str) -> bool:
    if n in ('.ctor', '.cctor'):
        return False
    # obfuscated names are usually short all-caps / random; still allow common overrides
    if n in ('Equals', 'GetHashCode', 'ToString', 'CompareTo', 'Finalize'):
        return True
    if len(n) <= 3:
        return False
    if re.fullmatch(r'[A-Z]{4,}\d*', n) and not any(c.islower() for c in n):
        return False
    return True


def match_methods(src: TypeInfo, dst: TypeInfo):
    pairs = []
    used_src, used_dst = set(), set()
    s_sigs = [method_signature(m, False) for m in src.methods]
    d_sigs = [method_signature(m, True) for m in dst.methods]

    # 1) exact name + exact/fuzzy signature, using a name index.
    by_name = collections.defaultdict(list)
    src_name_count = collections.Counter(m.name for m in src.methods)
    for j, b in enumerate(dst.methods):
        by_name[b.name].append(j)
    for i, a in enumerate(src.methods):
        if not method_name_usable(a.name):
            continue
        cand = [(j, dst.methods[j]) for j in by_name.get(a.name, ())
                if j not in used_dst]
        if not cand:
            continue
        cand.sort(key=lambda x: -method_sim(a, x[1], s_sigs[i], d_sigs[x[0]]))
        j, b = cand[0]
        sim = method_sim(a, b, s_sigs[i], d_sigs[j])
        # A unique non-obfuscated method name on BOTH sides is a seed even
        # when the parameter types are still unresolved (A:BaseEntity vs
        # A:JDII...).  Do not require signature similarity here: this is the
        # anchor that creates the very aliases needed to resolve the types.
        if len(cand) == 1 and src_name_count[a.name] == 1:
            pairs.append((i, j, 'name'))
            used_src.add(i); used_dst.add(j)
        elif sim >= 0.90:
            pairs.append((i, j, 'name'))
            used_src.add(i); used_dst.add(j)

    # 2) LCS of type-aware signatures: handles inserted/deleted methods.
    sm = difflib.SequenceMatcher(None, s_sigs, d_sigs, autojunk=False)
    for a0, b0, n in sm.get_matching_blocks():
        for k in range(n):
            i, j = a0 + k, b0 + k
            if i in used_src or j in used_dst:
                continue
            if method_sim(src.methods[i], dst.methods[j], s_sigs[i], d_sigs[j]) >= 0.75:
                pairs.append((i, j, 'lcs'))
                used_src.add(i); used_dst.add(j)

    # 3) exact type-aware signature index.
    by_shape = collections.defaultdict(list)
    for j, b in enumerate(dst.methods):
        if j not in used_dst:
            by_shape[d_sigs[j]].append(j)
    for i, a in enumerate(src.methods):
        if i in used_src:
            continue
        js = [j for j in by_shape.get(s_sigs[i], ()) if j not in used_dst]
        if js:
            j = min(js, key=lambda x: abs(x - i))
            pairs.append((i, j, 'shape'))
            used_src.add(i); used_dst.add(j)

    # 4) Fuzzy signature matching only for small/medium classes.
    if len(src.methods) * len(dst.methods) <= 40000:
        scored = []
        for i, a in enumerate(src.methods):
            if i in used_src:
                continue
            for j, b in enumerate(dst.methods):
                if j in used_dst:
                    continue
                s = method_sim(a, b, s_sigs[i], d_sigs[j])
                if method_name_usable(a.name) and a.name == b.name:
                    s += 0.10
                scored.append((s, i, j))
        scored.sort(reverse=True)
        for s, i, j in scored:
            if s < 0.80:
                break
            if i in used_src or j in used_dst:
                continue
            pairs.append((i, j, 'shape'))
            used_src.add(i); used_dst.add(j)

    # 5) ordinal/nearest fallback for same type-aware signatures.
    by_shape_rem = collections.defaultdict(list)
    for j, b in enumerate(dst.methods):
        if j not in used_dst:
            by_shape_rem[d_sigs[j]].append(j)
    for i, a in enumerate(src.methods):
        if i in used_src:
            continue
        js = [j for j in by_shape_rem.get(s_sigs[i], ()) if j not in used_dst]
        if js:
            j = min(js, key=lambda x: abs(x - i))
            pairs.append((i, j, 'ordinal'))
            used_src.add(i); used_dst.add(j)
    return pairs


_WORK_SRC: list[TypeInfo] = []
_WORK_DST_BY_INDEX: dict[int, TypeInfo] = {}
_WORK_GROUPS: dict[tuple[str, str], list[TypeInfo]] = {}
_WORK_COUNTS: dict[tuple[str, str, int], list[TypeInfo]] = {}
_WORK_SHAPES: dict[tuple[str, str, tuple], list[int]] = {}
_WORK_FIELDS: dict[tuple[str, str, str], list[int]] = {}
_WORK_ENUMS: dict[tuple[str, str, str], list[int]] = {}
_WORK_FIELD_NAMES: dict[tuple[str, str, str], list[int]] = {}
_WORK_METHOD_NAMES: dict[tuple[str, str, str], list[int]] = {}
_WORK_EXACT_USED: set[int] = set()
_WORK_MIN_SCORE = 0.55
_WORK_TOP_K = 8
_MATCH_SRC: list[TypeInfo] = []
_MATCH_DST: list[TypeInfo] = []


def _candidate_worker(src_i: int):
    t = _WORK_SRC[src_i]
    n = len(t.methods)
    key = (t.assembly, t.kind)
    votes = collections.Counter()
    # Inverted index on method shapes: a shared rare shape is much stronger
    # than "same method count" and handles added/deleted methods directly.
    for shape in set(t.method_shapes):
        ids = _WORK_SHAPES.get((t.assembly, t.kind, shape), ())
        if not ids or len(ids) > 1200:
            continue
        w = 1.0 / math.log2(len(ids) + 2.0)
        for idx in ids:
            votes[idx] += w
    for shape in set(t.fields):
        ids = _WORK_FIELDS.get((t.assembly, t.kind, shape), ())
        if not ids or len(ids) > 1200:
            continue
        w = 0.35 / math.log2(len(ids) + 2.0)
        for idx in ids:
            votes[idx] += w
    for name in set(t.field_names):
        ids = _WORK_FIELD_NAMES.get((t.assembly, t.kind, name), ())
        if not ids or len(ids) > 1200:
            continue
        w = 1.2 / math.log2(len(ids) + 2.0)
        for idx in ids:
            votes[idx] += w
    for name in t.usable_name_counts:
        ids = _WORK_METHOD_NAMES.get((t.assembly, t.kind, name), ())
        if not ids or len(ids) > 1200:
            continue
        w = 1.0 / math.log2(len(ids) + 2.0)
        for idx in ids:
            votes[idx] += w
    if t.kind == 'enum':
        for name, _ in t.enum_values:
            ids = _WORK_ENUMS.get((t.assembly, t.kind, name), ())
            if not ids or len(ids) > 1200:
                continue
            w = 2.0 / math.log2(len(ids) + 2.0)
            for idx in ids:
                votes[idx] += w

    cheap: list[tuple[float, int]] = []
    seen = set()
    for idx, _ in votes.most_common(64):
        if idx in _WORK_EXACT_USED:
            continue
        b = _WORK_DST_BY_INDEX[idx]
        m = len(b.methods)
        if n and m and not (0.35 <= m / n <= 2.50):
            continue
        sc = class_score_fast(t, b)
        if sc >= _WORK_MIN_SCORE:
            cheap.append((sc, idx))
        seen.add(idx)
    # Fallback for common shapes / method-less classes.  If the sparse votes
    # did not produce enough strong candidates, widen to the method-count
    # bucket instead of silently leaving the source class unmatched.
    if len(cheap) < 8:
        if n <= 12:
            lo, hi = max(0, int(n * 0.25) - 1), int(n * 3.00) + 4
        else:
            lo, hi = max(0, int(n * 0.40) - 1), int(n * 2.20) + 4
        for cnt in range(lo, hi + 1):
            for b in _WORK_COUNTS.get((t.assembly, t.kind, cnt), ()):
                if b.type_index in _WORK_EXACT_USED or b.type_index in seen:
                    continue
                sc = class_score_fast(t, b)
                if sc >= _WORK_MIN_SCORE:
                    cheap.append((sc, b.type_index))
                if len(cheap) >= 128:
                    break
            if len(cheap) >= 128:
                break
    if not cheap:
        return src_i, []
    # Full score only for the best cheap candidates.
    cheap.sort(key=lambda x: -x[0])
    cands = []
    for _, idx in cheap[:20]:
        sc = class_score(t, _WORK_DST_BY_INDEX[idx])
        if sc >= _WORK_MIN_SCORE:
            cands.append((sc, idx))
    if not cands:
        return src_i, []
    best = heapq.nlargest(_WORK_TOP_K, cands, key=lambda x: x[0])
    return src_i, best


def _method_worker(item):
    src_i, dst_i = item
    return src_i, match_methods(_MATCH_SRC[src_i], _MATCH_DST[dst_i])


def main():
    ap = argparse.ArgumentParser()
    # The target is always the 7.1 dump being named; 2.8 only supplies names.
    ap.add_argument('--target', default='out/dump71.cs')
    ap.add_argument('--names', default='out/dump_2.8.cs')
    ap.add_argument('--out', default='out/match_28_71.json')
    ap.add_argument('--report', default='out/match_28_71_report.tsv')
    ap.add_argument('--alias-out', default='out/type_alias_28_71.json')
    ap.add_argument('--min-score', type=float, default=0.55)
    ap.add_argument('--jobs', type=int, default=min(8, os.cpu_count() or 4),
                    help='worker processes; keep low (4-8) because dump objects are large')
    # System/Unity classes are anchors only; the report focuses on game code.
    ap.add_argument('--focus-assembly', default='Mono.Security.dll,Assembly-CSharp.dll',
                    help='comma-separated assemblies to report; empty = all')
    ap.add_argument('--obf-only', action='store_true',
                    help='report only obfuscated-looking class names in focus assemblies')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    t0 = time.time()
    # 2.8 is the source (real names); 7.1 is the target (possibly obfuscated).
    src, _ = parse_dump(args.names)     # 2.8 source
    dst, _ = parse_dump(args.target)    # 7.1 target
    print(f'source 2.8 types={len(src)} methods={sum(len(t.methods) for t in src)} '
          f'({time.time()-t0:.1f}s)', flush=True)
    print(f'target 7.1 types={len(dst)} methods={sum(len(t.methods) for t in dst)}', flush=True)

    focus = {x.strip() for x in args.focus_assembly.split(',') if x.strip()}
    active_src = [i for i, t in enumerate(src)
                  if (not focus or t.assembly in focus)]
    active_dst = [i for i, t in enumerate(dst)
                  if (not focus or t.assembly in focus) and
                  (not args.obf_only or is_obf_name(t.full))]
    focus_set = set(active_src)
    obf_dst = [i for i in active_dst if is_obf_name(dst[i].full)]
    print(f'focus assemblies={sorted(focus) or "ALL"} '
          f'source_classes={len(active_src)} target_classes={len(active_dst)} '
          f'target_obf={len(obf_dst)} obf_only={args.obf_only}', flush=True)

    # Materialize read-only caches once, before forking.  Otherwise every
    # worker fills them independently and copy-on-write turns into OOM.
    cache_t0 = time.time()
    for t in src:
        _ = (t.semantic, t.method_counts, t.field_counts, t.prop_counts,
             t.field_name_counts, t.prop_name_counts, t.usable_name_counts,
             t.base_counts, t.raw_custom_refs)
    for t in dst:
        _ = (t.semantic, t.method_counts, t.field_counts, t.prop_counts,
             t.field_name_counts, t.prop_name_counts, t.usable_name_counts,
             t.base_counts, t.raw_custom_refs)
    global _GRAPH_SRC, _GRAPH_DST
    _GRAPH_SRC = build_graph_tokens(src)
    _GRAPH_DST = build_graph_tokens(dst)
    print(f'caches materialized in {time.time()-cache_t0:.1f}s', flush=True)

    # exact full-name matching inside the same assembly
    dst_by_key = collections.defaultdict(list)
    for t in dst:
        dst_by_key[(t.assembly, t.full)].append(t)
        dst_by_key[(t.assembly, t.name)].append(t)
    assigned: dict[int, tuple[TypeInfo, float, str]] = {}
    used_dst: set[int] = set()
    for t in src:
        for key in ((t.assembly, t.full), (t.assembly, t.name)):
            for c in dst_by_key.get(key, ()):
                if c.type_index not in used_dst:
                    assigned[t.type_index] = (c, 1.0, 'exact')
                    used_dst.add(c.type_index)
                    break
            if t.type_index in assigned:
                break

    # Structural candidates: score in forked workers, assign greedily in parent.
    groups = collections.defaultdict(list)
    counts = collections.defaultdict(list)
    shapes = collections.defaultdict(list)
    fields = collections.defaultdict(list)
    enums = collections.defaultdict(list)
    field_names = collections.defaultdict(list)
    method_names = collections.defaultdict(list)
    for b in dst:
        groups[(b.assembly, b.kind)].append(b)
        counts[(b.assembly, b.kind, len(b.methods))].append(b)
        for shape in set(b.method_shapes):
            shapes[(b.assembly, b.kind, shape)].append(b.type_index)
        for shape in set(b.fields):
            fields[(b.assembly, b.kind, shape)].append(b.type_index)
        for name in set(b.field_names):
            field_names[(b.assembly, b.kind, name)].append(b.type_index)
        for name in b.usable_name_counts:
            method_names[(b.assembly, b.kind, name)].append(b.type_index)
        for name, _ in b.enum_values:
            enums[(b.assembly, b.kind, name)].append(b.type_index)

    global _WORK_SRC, _WORK_DST_BY_INDEX, _WORK_GROUPS, _WORK_COUNTS
    global _WORK_SHAPES, _WORK_FIELDS, _WORK_ENUMS, _WORK_FIELD_NAMES, _WORK_METHOD_NAMES, _WORK_EXACT_USED, _WORK_MIN_SCORE
    _WORK_SRC = src
    _WORK_DST_BY_INDEX = {b.type_index: b for b in dst}
    _WORK_GROUPS = groups
    _WORK_COUNTS = counts
    _WORK_SHAPES = shapes
    _WORK_FIELDS = fields
    _WORK_ENUMS = enums
    _WORK_FIELD_NAMES = field_names
    _WORK_METHOD_NAMES = method_names
    _WORK_EXACT_USED = set(used_dst)
    _WORK_MIN_SCORE = args.min_score

    todo = [i for i in active_src if src[i].type_index not in assigned]
    proposals: list[tuple[float, int, int]] = []
    print(f'structural candidates for {len(todo)} classes, jobs={args.jobs}', flush=True)
    ctx = (multiprocessing.get_context('fork')
           if 'fork' in multiprocessing.get_all_start_methods()
           else multiprocessing.get_context())
    with ctx.Pool(processes=args.jobs) as pool:
        done = 0
        for src_i, best in pool.imap_unordered(_candidate_worker, todo, chunksize=32):
            for sc, dst_idx in best:
                proposals.append((sc, src_i, dst_idx))
            done += 1
            if done % 10000 == 0:
                print(f'  scored {done}/{len(todo)} ({time.time()-t0:.1f}s)', flush=True)

    proposals.sort(key=lambda x: -x[0])
    # Mutual-best first: it is much less likely to be an overload/plugin
    # collision than the greedy best match.
    best_src: dict[int, tuple[float, int]] = {}
    best_dst: dict[int, tuple[float, int]] = {}
    for sc, src_i, dst_idx in proposals:
        if src_i not in best_src or sc > best_src[src_i][0]:
            best_src[src_i] = (sc, dst_idx)
        if dst_idx not in best_dst or sc > best_dst[dst_idx][0]:
            best_dst[dst_idx] = (sc, src_i)
    mutual = []
    for src_i, (sc, dst_idx) in best_src.items():
        if best_dst.get(dst_idx, (-1, -1))[1] != src_i:
            continue
        sidx = src[src_i].type_index
        if sidx in assigned or dst_idx in used_dst:
            continue
        mutual.append((sc, src_i, dst_idx))
    mutual.sort(key=lambda x: -x[0])
    for sc, src_i, dst_idx in mutual:
        sidx = src[src_i].type_index
        assigned[sidx] = (_WORK_DST_BY_INDEX[dst_idx], sc, 'mutual')
        used_dst.add(dst_idx)
    # Fill the rest with the normal greedy pass.
    for sc, src_i, dst_idx in proposals:
        sidx = src[src_i].type_index
        if sidx in assigned or dst_idx in used_dst:
            continue
        assigned[sidx] = (_WORK_DST_BY_INDEX[dst_idx], sc, 'shape')
        used_dst.add(dst_idx)

    # Match methods in parallel for every assigned class.
    src_pos = {t.type_index: i for i, t in enumerate(src)}
    dst_pos = {t.type_index: i for i, t in enumerate(dst)}
    jobs = [(src_pos[sidx], dst_pos[b.type_index])
            for sidx, (b, _, _) in assigned.items()
            if src_pos[sidx] in focus_set]
    global _MATCH_SRC, _MATCH_DST
    _MATCH_SRC, _MATCH_DST = src, dst
    method_map: dict[int, list] = {}
    print(f'method matching for {len(jobs)} classes', flush=True)
    with ctx.Pool(processes=args.jobs) as pool:
        done = 0
        for src_i, mp in pool.imap_unordered(_method_worker, jobs, chunksize=16):
            method_map[src_i] = mp
            done += 1
            if done % 10000 == 0:
                print(f'  methods {done}/{len(jobs)} ({time.time()-t0:.1f}s)', flush=True)

    # Method-anchor -> type-alias propagation.  If a method is matched by its
    # non-obfuscated name, align parameters by position and vote on the
    # corresponding custom types.  Extra optional parameters are ignored.
    alias_votes: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    alias_evidence: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    alias_name_votes: collections.Counter = collections.Counter()
    for si in active_src:
        t = src[si]
        ent = assigned.get(t.type_index)
        if ent is None:
            continue
        target = ent[0]
        for i, j, why in method_map.get(si, ()):
            if why != 'name':
                continue
            a, b = t.methods[i], target.methods[j]
            for ra, rb in zip(a.params_raw or a.params, b.params_raw or b.params):
                sa, sb = custom_base_type(ra), custom_base_type(rb)
                if sa and sb and sa != sb:
                    alias_votes[sa][sb] += 1
                    alias_name_votes[(sa, sb)] += 1
                    ev = alias_evidence[(sa, sb)]
                    if len(ev) < 8:
                        ev.append(f'{t.full}::{a.name}')
            sa = custom_base_type(a.ret_raw or a.ret)
            sb = custom_base_type(b.ret_raw or b.ret)
            if sa and sb and sa != sb:
                alias_votes[sa][sb] += 1
                alias_name_votes[(sa, sb)] += 1
                ev = alias_evidence[(sa, sb)]
                if len(ev) < 8:
                    ev.append(f'{t.full}::{a.name} return')

    aliases = {}
    for src_type, counter in alias_votes.items():
        total = sum(counter.values())
        dst_type, votes = counter.most_common(1)[0]
        # One-vote aliases are retained as low-confidence candidates.  They
        # are useful for review but are not used in the automatic next pass.
        if votes >= 1 and votes / total >= 0.75:
            if votes >= 4 and votes / total >= 0.90:
                conf = 'high'
            elif votes >= 2 and votes / total >= 0.75:
                conf = 'medium'
            elif (votes == 1 and total == 1 and
                  alias_name_votes.get((src_type, dst_type), 0) >= 1):
                # Exact, unique method-name anchor: useful enough for round 2.
                conf = 'medium'
            else:
                conf = 'low'
            aliases[src_type] = {
                'target': dst_type,
                'votes': votes,
                'total': total,
                'confidence': conf,
                'evidence': alias_evidence.get((src_type, dst_type), []),
            }
    with open(args.alias_out, 'w', encoding='utf-8') as f:
        json.dump({
            'target_7.1': args.target,
            'names_2.8': args.names,
            'aliases': aliases,
        }, f, ensure_ascii=False, indent=2)
    print(f'type aliases={len(aliases)} -> {args.alias_out}', flush=True)
    for k in ('JDIIHHFJKBM', 'IGHPEPHIAON'):
        if k in aliases:
            print('alias', k, '->', aliases[k]['target'],
                  aliases[k]['votes'], '/', aliases[k]['total'], flush=True)

    # Round 2: use only high/medium aliases to resolve target-side custom
    # types, then retry classes that remained unmatched.  Low-confidence
    # aliases are deliberately excluded.
    global _ALIAS_TO_SOURCE
    _ALIAS_TO_SOURCE = {
        v['target']: k for k, v in aliases.items()
        if v['confidence'] in ('high', 'medium')
    }
    # Re-run method matching for already matched classes now that target-side
    # custom types can be resolved through aliases.  This is the main reason
    # method signatures must not be reduced to C before this pass.
    if _ALIAS_TO_SOURCE and method_map:
        refresh_jobs = [
            (src_pos[sidx], dst_pos[b.type_index])
            for sidx, (b, _, _) in assigned.items()
            if src_pos[sidx] in focus_set
        ]
        with ctx.Pool(processes=args.jobs) as pool:
            for src_i, mp in pool.imap_unordered(_method_worker, refresh_jobs,
                                                  chunksize=16):
                method_map[src_i] = mp
        print(f'method refresh with aliases={len(refresh_jobs)}', flush=True)

    # Re-collect aliases after the method refresh.  The first pass may not
    # have matched a method whose parameters were still in C form; the
    # refreshed method map can now contribute the missing evidence.
    alias_votes = collections.defaultdict(collections.Counter)
    alias_evidence = collections.defaultdict(list)
    alias_name_votes = collections.Counter()
    for si in active_src:
        t = src[si]
        ent = assigned.get(t.type_index)
        if ent is None:
            continue
        target = ent[0]
        for i, j, why in method_map.get(si, ()):
            if why != 'name':
                continue
            a, b = t.methods[i], target.methods[j]
            for ra, rb in zip(a.params_raw or a.params, b.params_raw or b.params):
                sa, sb = custom_base_type(ra), custom_base_type(rb)
                if sa and sb and sa != sb:
                    alias_votes[sa][sb] += 1
                    alias_name_votes[(sa, sb)] += 1
                    ev = alias_evidence[(sa, sb)]
                    if len(ev) < 32:
                        ev.append(f'{t.full}::{a.name}')
            sa = custom_base_type(a.ret_raw or a.ret)
            sb = custom_base_type(b.ret_raw or b.ret)
            if sa and sb and sa != sb:
                alias_votes[sa][sb] += 1
                alias_name_votes[(sa, sb)] += 1
                ev = alias_evidence[(sa, sb)]
                if len(ev) < 32:
                    ev.append(f'{t.full}::{a.name} return')

    aliases = {}
    for src_type, counter in alias_votes.items():
        total = sum(counter.values())
        dst_type, votes = counter.most_common(1)[0]
        if votes >= 1 and votes / total >= 0.75:
            if votes >= 4 and votes / total >= 0.90:
                conf = 'high'
            elif votes >= 2 and votes / total >= 0.75:
                conf = 'medium'
            elif votes == 1 and total == 1 and alias_name_votes.get((src_type, dst_type), 0) >= 1:
                conf = 'medium'
            else:
                conf = 'low'
            aliases[src_type] = {
                'target': dst_type, 'votes': votes, 'total': total,
                'confidence': conf,
                'evidence': alias_evidence.get((src_type, dst_type), []),
            }
    _ALIAS_TO_SOURCE = {
        v['target']: k for k, v in aliases.items()
        if v['confidence'] in ('high', 'medium')
    }
    with open(args.alias_out, 'w', encoding='utf-8') as f:
        json.dump({'target_7.1': args.target, 'names_2.8': args.names,
                   'aliases': aliases}, f, ensure_ascii=False, indent=2)
    print(f'type aliases refreshed={len(aliases)} -> {args.alias_out}', flush=True)
    for key in ('BaseEntity', 'IBaseEntity'):
        if key in aliases:
            a = aliases[key]
            print('alias', key, '->', a['target'], a['votes'], '/',
                  a['total'], a['confidence'], flush=True)

    round2_start = len(assigned)
    proposals2: list[tuple[float, int, int]] = []
    best2_src: dict[int, tuple[float, int]] = {}
    best2_dst: dict[int, float] = {}
    second_src = [i for i in active_src
                  if src[i].type_index not in assigned]
    if _ALIAS_TO_SOURCE and second_src:
        _WORK_EXACT_USED = set(used_dst)
        print(f'round2 aliases={len(_ALIAS_TO_SOURCE)} '
              f'candidates={len(second_src)}', flush=True)
        with ctx.Pool(processes=args.jobs) as pool:
            for src_i, best in pool.imap_unordered(_candidate_worker, second_src,
                                                   chunksize=32):
                for sc, dst_idx in best:
                    # Keep only targets not already used.
                    if dst_idx in used_dst:
                        continue
                    proposals2.append((sc, src_i, dst_idx))
                    best2_dst[dst_idx] = max(best2_dst.get(dst_idx, -1.0), sc)
                    if src_i not in best2_src or sc > best2_src[src_i][0]:
                        best2_src[src_i] = (sc, dst_idx)
        # Mutual-best first, then a small greedy fill.
        mutual2 = []
        for src_i, (sc, dst_idx) in best2_src.items():
            if best2_dst.get(dst_idx, -1.0) != sc:
                continue
            if src_i in assigned or dst_idx in used_dst:
                continue
            mutual2.append((sc, src_i, dst_idx))
        mutual2.sort(key=lambda x: -x[0])
        for sc, src_i, dst_idx in mutual2:
            sidx = src[src_i].type_index
            assigned[sidx] = (_WORK_DST_BY_INDEX[dst_idx], sc, 'round2_mutual')
            used_dst.add(dst_idx)
        proposals2.sort(key=lambda x: -x[0])
        for sc, src_i, dst_idx in proposals2:
            sidx = src[src_i].type_index
            if sidx in assigned or dst_idx in used_dst:
                continue
            assigned[sidx] = (_WORK_DST_BY_INDEX[dst_idx], sc, 'round2')
            used_dst.add(dst_idx)
        new_jobs = [(src_pos[sidx], dst_pos[b.type_index])
                    for sidx, (b, _, _) in assigned.items()
                    if src_pos[sidx] in focus_set and src_pos[sidx] not in method_map]
        if new_jobs:
            with ctx.Pool(processes=args.jobs) as pool:
                for src_i, mp in pool.imap_unordered(_method_worker, new_jobs,
                                                      chunksize=16):
                    method_map[src_i] = mp
        print(f'round2 added={len(assigned)-round2_start} '
              f'total_matched={len(assigned)}', flush=True)

    # emit mapping, keyed by the 7.1 target class.
    result = {'target_7.1': args.target, 'names_2.8': args.names,
              'focus_assembly': args.focus_assembly, 'obf_only': args.obf_only,
              'classes': [], 'only_7.1_classes': [], 'only_2.8_classes': []}
    stats = collections.Counter()
    src_by_idx = {t.type_index: i for i, t in enumerate(src)}
    by_target = {}
    for sidx, (b, sc, how) in assigned.items():
        by_target[b.type_index] = (sidx, sc, how)
    with open(args.report, 'w', encoding='utf-8') as rep:
        rep.write('7.1_TypeDefIndex\t7.1_FullName\t2.8_TypeDefIndex\t2.8_FullName\t'
                  'class_score\tclass_match\tmethods_matched\tmethods_high\t'
                  'methods_only_7.1\tmethods_only_2.8\tconfidence\n')
        for bi in active_dst:
            t = dst[bi]  # 7.1 target
            ent = by_target.get(t.type_index)
            if ent is None:
                stats['only_7.1_classes'] += 1
                result['only_7.1_classes'].append({
                    'type_index': t.type_index, 'full': t.full,
                    'assembly': t.assembly, 'kind': t.kind,
                    'methods': len(t.methods), 'fields': len(t.fields),
                })
                rep.write(f'{t.type_index}\t{t.full}\t\t\t0\tunmatched\t0\t0\t'
                          f'{len(t.methods)}\t0\t-\n')
                continue
            sidx, sc, how = ent
            s = src[src_by_idx[sidx]]  # 2.8 source
            si = src_by_idx[sidx]
            pairs = method_map.get(si, [])
            matched_src = {i for i, _, _ in pairs}
            matched_dst = {j for _, j, _ in pairs}
            only71 = [t.methods[j] for j in range(len(t.methods)) if j not in matched_dst]
            only28 = [s.methods[i] for i in range(len(s.methods)) if i not in matched_src]
            high = sum(1 for _, _, why in pairs if why == 'name')
            stats['matched'] += 1
            stats[how] += 1
            conf = ('high' if how == 'exact' or
                    (how == 'mutual' and sc >= 0.72) or
                    (sc >= 0.78 and high >= max(1, len(pairs) // 3)) else
                    ('medium' if sc >= 0.65 else 'low'))
            methods = []
            for i, j, why in pairs:
                a, c = s.methods[i], t.methods[j]  # 2.8, 7.1
                methods.append({
                    '7.1_name': c.name, '2.8_name': a.name,
                    '7.1_decl': c.decl, '2.8_decl': a.decl,
                    'confidence': 'high' if why == 'name' else ('medium' if why == 'shape' else 'low'),
                    'reason': why,
                })
            result['classes'].append({
                '7.1_type_index': t.type_index, '7.1_full': t.full,
                '2.8_type_index': s.type_index, '2.8_full': s.full,
                'class_score': round(sc, 4), 'class_match': how,
                'confidence': conf, 'methods': methods,
                'only_7.1_methods': [
                    {'name': m.name, 'decl': m.decl, 'rva': m.rva} for m in only71
                ],
                'only_2.8_methods': [
                    {'name': m.name, 'decl': m.decl, 'rva': m.rva} for m in only28
                ],
            })
            rep.write(f'{t.type_index}\t{t.full}\t{s.type_index}\t{s.full}\t'
                      f'{sc:.4f}\t{how}\t{len(pairs)}\t{high}\t'
                      f'{len(only71)}\t{len(only28)}\t{conf}\n')

        # 2.8 classes that disappeared in 7.1.  This list should be small if
        # the user's retention assumption is correct.
        for si in active_src:
            s = src[si]
            if s.type_index in assigned:
                continue
            stats['only_2.8_classes'] += 1
            result['only_2.8_classes'].append({
                'type_index': s.type_index, 'full': s.full,
                'assembly': s.assembly, 'kind': s.kind,
                'methods': len(s.methods), 'fields': len(s.fields),
            })
            rep.write(f'\t\t{s.type_index}\t{s.full}\t\t'
                      f'source_only\t0\t0\t0\t{len(s.methods)}\t-\n')

    focus_stats = collections.Counter()
    focus_stats['source_total'] = len(active_src)
    focus_stats['target_total'] = len(active_dst)
    for si in active_src:
        if src[si].type_index in assigned:
            focus_stats['source_matched'] += 1
        else:
            focus_stats['source_only'] += 1
    for bi in active_dst:
        t = dst[bi]
        ent = by_target.get(t.type_index)
        if ent is None:
            focus_stats['target_only'] += 1
            continue
        focus_stats['target_matched'] += 1
        sidx, sc, how = ent
        if how == 'exact':
            focus_stats['exact'] += 1
        else:
            focus_stats['shape'] += 1
        if is_obf_name(t.full):
            focus_stats['obf_matched'] += 1
            focus_stats['obf_' + how] += 1
    print('focus_stats', dict(focus_stats), f'total {time.time()-t0:.1f}s')
    if not args.dry_run:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print('wrote', args.out, args.report)


if __name__ == '__main__':
    main()
