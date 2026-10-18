#!/usr/bin/env python3
"""dump_align.py —— 忽略混淆名字，按类/方法形状对齐两个版本的 dump。

思路（BinDiff-lite for metadata）：
  * 类指纹 = 方法签名形状序列 + 方法数量
  * 类型形状：primitive / array / generic / class / pointer
  * 类匹配用 multiset Jaccard + 序列相似度
  * 类内方法按 名字 -> 签名形状 -> ordinal -> LCS 顺序匹配

用法:
  python3 tools/dump_align.py --from out/dump71.cs --to out/dump70.cs \
      --hooks out/hk_71_map.json --out out/hk_70_align.json
"""
import argparse
import collections
import difflib
import json
import re
import sys

import sig  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KNOWN = {'void','bool','byte','sbyte','short','ushort','int','uint','long','ulong',
         'float','double','string','object','char','decimal','IntPtr','UIntPtr'}


def shape_type(t):
    t = re.sub(r'\b(const|ref|out|in)\b', '', t).strip()
    t = re.sub(r'\s+', '', t)
    if t in KNOWN:
        return t
    if '[' in t or t.endswith(']'):
        return 'A'
    if '<' in t:
        return 'G'
    if t.endswith('*'):
        return 'P'
    return 'C'


def split_params(s):
    out, buf, dep = [], '', 0
    for ch in s:
        if ch in '<[(':
            dep += 1
        elif ch in '>])':
            dep = max(0, dep - 1)
        if ch == ',' and dep == 0:
            out.append(buf); buf = ''
        else:
            buf += ch
    if buf.strip():
        out.append(buf)
    return out


def ptypes(decl):
    m = re.search(r'\((.*)\)', decl)
    if not m:
        return ()
    res = []
    for p in split_params(m.group(1)):
        p = p.strip()
        if '=' in p:
            p = p.split('=', 1)[0].strip()
        mm = re.match(r'(.+?)(?:\s+[A-Za-z_]\w*)$', p)
        if mm and not p.endswith(('>', ']', '*')):
            p = mm.group(1)
        res.append(shape_type(p))
    return tuple(res)


def rtype(decl):
    m = re.search(r'([A-Za-z_\.<][\w\.<>]*)\s*\(', decl)
    if not m:
        return ''
    pre = decl[:m.start()].strip().split()
    mods = {'public','private','protected','internal','static','virtual','override',
            'abstract','sealed','extern','unsafe','new','readonly','partial','async'}
    while pre and pre[-1] in mods:
        pre.pop()
    return shape_type(pre[-1] if pre else '')


def raw_rtype(decl):
    """Return the unnormalized return type token (used as a stable-type bonus)."""
    m = re.search(r'([A-Za-z_\.<][\w\.<>]*)\s*\(', decl)
    if not m:
        return ''
    pre = decl[:m.start()].strip().split()
    mods = {'public','private','protected','internal','static','virtual','override',
            'abstract','sealed','extern','unsafe','new','readonly','partial','async'}
    while pre and pre[-1] in mods:
        pre.pop()
    return re.sub(r'\s+', '', pre[-1]) if pre else ''


def mshape(decl):
    return (rtype(decl), ptypes(decl))


def type_sim(a, b):
    """跨版本参数类型模糊相似度；只看形状，不看混淆名。"""
    if a == b:
        return 1.0
    prim = {'bool','byte','sbyte','short','ushort','int','uint','long','ulong',
            'float','double','string','object','char','decimal','void'}
    if a in prim and b in prim:
        # 数值类型互换 / 指针宽度变化时仍然保留一点相似度
        return 0.65
    if a == 'C' and b == 'C':
        return 0.90
    if a in ('A', 'G') and b == a:
        return 1.0
    return 0.15


def method_sim(a, b):
    """方法签名形状相似度；参数个数变化也允许匹配。"""
    ra, pa = a
    rb, pb = b
    r = type_sim(ra, rb)
    if not pa and not pb:
        ps = 1.0
    else:
        sm = difflib.SequenceMatcher(None, pa, pb, autojunk=False)
        ps = sm.ratio()
        n = max(len(pa), len(pb))
        if n:
            ps *= 1.0 - 0.25 * abs(len(pa) - len(pb)) / n
    return 0.30 * r + 0.70 * ps


def parse_dump(path):
    """Return {fullname: {full, methods:[{rva,decl,name,shape}]}} in declaration order."""
    lines = open(path, encoding='utf-8', errors='ignore').read().splitlines()
    types = {}
    cur = None
    full = ''
    for i, line in enumerate(lines):
        if line.startswith('// FullName: '):
            full = line[12:].strip()
            cur = types.setdefault(full, {'full': full, 'methods': []})
        m = re.match(r'// RVA: (0x[0-9A-Fa-f]+)\b', line)
        if not m or cur is None:
            continue
        rva = int(m.group(1), 16)
        decl = ''
        for j in range(i + 1, min(i + 6, len(lines))):
            s = lines[j].strip()
            if s and not s.startswith('//') and not s.startswith('{') and not s.startswith('}'):
                decl = s
                break
        nm = ''
        mm = re.search(r'([A-Za-z_\.<][\w\.<>]*)\s*\(', decl)
        if mm:
            nm = mm.group(1)
        cur['methods'].append({'rva': rva, 'decl': decl, 'name': nm, 'shape': mshape(decl)})
    return types


def class_seq(cls):
    return [m['shape'] for m in cls['methods']]


def class_score(a, b):
    if not a or not b:
        return 0.0
    ca, cb = collections.Counter(a), collections.Counter(b)
    inter = sum((ca & cb).values())
    union = sum((ca | cb).values())
    jac = inter / union if union else 0.0
    seq = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    cnt = 1.0 - abs(len(a) - len(b)) / max(len(a), len(b), 1)
    return 0.50 * jac + 0.40 * seq + 0.10 * cnt


def method_by_shape(tcls, shape):
    return [m for m in tcls['methods'] if m['shape'] == shape]


def method_by_name(tcls, name, shape):
    xs = [m for m in tcls['methods'] if name and m['name'] == name]
    exact = [m for m in xs if m['shape'] == shape]
    return exact or xs


def align_method(scls, tcls, sm):
    """Return (target_method, reason) for a source method, ignoring obfuscated names."""
    # 1. exact name (+ exact/fuzzy shape)
    xs = [m for m in tcls['methods'] if sm['name'] and m['name'] == sm['name']]
    if xs:
        xs.sort(key=lambda m: -method_sim(sm['shape'], m['shape']))
        if len(xs) == 1 or method_sim(sm['shape'], xs[0]['shape']) - \
                method_sim(sm['shape'], xs[1]['shape']) > 0.05:
            return xs[0], 'name'
    # 2. fuzzy signature over the whole target class (参数增减也允许)
    scored = [(method_sim(sm['shape'], m['shape']), i, m)
              for i, m in enumerate(tcls['methods'])]
    scored.sort(key=lambda x: (-x[0], x[1]))
    if scored:
        best = scored[0]
        second = scored[1][0] if len(scored) > 1 else 0.0
        if best[0] >= 0.88 and best[0] - second >= 0.04:
            return best[2], 'fuzzy'
    # 3. ordinal in source class
    try:
        idx = scls['methods'].index(sm)
    except ValueError:
        idx = -1
    if 0 <= idx < len(tcls['methods']):
        tm = tcls['methods'][idx]
        if tm['shape'] == sm['shape']:
            return tm, 'ordinal'
    # 4. LCS alignment of method shape sequences
    sseq = [m['shape'] for m in scls['methods']]
    tseq = [m['shape'] for m in tcls['methods']]
    smatcher = difflib.SequenceMatcher(None, sseq, tseq, autojunk=False)
    for a, b, n in smatcher.get_matching_blocks():
        if a <= idx < a + n:
            return tcls['methods'][b + (idx - a)], 'lcs'
    # 5. relaxed ordinal; explicit medium-confidence fallback
    if 0 <= idx < len(tcls['methods']):
        return tcls['methods'][idx], 'ordinal_relaxed'
    return None, 'none'


def find_source_method(scls, h):
    # RVA is the strongest key: do not pick the first same-named overload.
    try:
        rva = int(str(h.get('rva', '')), 16)
    except Exception:
        rva = None
    if rva is not None:
        for m in scls['methods']:
            if m['rva'] == rva:
                return m
    for m in scls['methods']:
        if h.get('dump_name') and m['name'] == h['dump_name']:
            return m
    sd = h.get('dump_decl', '')
    for m in scls['methods']:
        if m['decl'] == sd:
            return m
    return None


def load_func_ends(path):
    d = json.load(open(path, encoding='utf-8'))
    return {int(f['start']): int(f['end']) for f in d.get('funcs', [])}


def disasm_compare(src_pe, dst_pe, src_va, dst_va, src_end, dst_end, md):
    """Return BinDiff-lite disassembly score for two function starts."""
    sf = sig._func_features(src_pe, md, src_va, src_end)
    tf = sig._func_features(dst_pe, md, dst_va, dst_end)
    if not sf or not tf:
        return None
    cos = sig._cosine(sf.get('hist') or {}, tf.get('hist') or {})
    def ratio(a, b):
        return min(a, b) / max(a, b) if a and b else 0.0
    counts = (ratio(sf.get('insns'), tf.get('insns')) +
              ratio(sf.get('calls'), tf.get('calls')) +
              ratio(sf.get('blocks'), tf.get('blocks')) +
              ratio(sf.get('edges'), tf.get('edges'))) / 4.0
    def mnem(pe, va, en):
        o = pe.va2off(va)
        if o is None:
            return []
        out = []
        for ins in md.disasm(pe.D[o:o + min(0x20000, en - va + 32)], va):
            if ins.address >= en:
                break
            if ins.mnemonic not in ('int3', 'nop', 'nopw', 'nopl'):
                out.append(ins.mnemonic)
        return out
    lcs = difflib.SequenceMatcher(None, mnem(src_pe, src_va, src_end),
                                  mnem(dst_pe, dst_va, dst_end),
                                  autojunk=False).ratio()
    score = (0.35 * cos + 0.10 * (sf.get('prime') == tf.get('prime')) +
             0.15 * counts + 0.40 * lcs)
    return {'score': round(score, 4), 'hist': round(cos, 4),
            'lcs': round(lcs, 4), 'src_insns': sf.get('insns'),
            'dst_insns': tf.get('insns')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--from', dest='src', required=True)
    ap.add_argument('--to', dest='dst', required=True)
    ap.add_argument('--hooks', required=True, help='hk_71_map.json rows with hook_method/fullname/dump_name/dump_decl')
    ap.add_argument('--out', required=True)
    ap.add_argument('--class-score', type=float, default=0.58)
    ap.add_argument('--class-margin', type=float, default=0.03)
    ap.add_argument('--verify-disasm', action='store_true',
                    help='add capstone/BinDiff-lite disassembly verification')
    ap.add_argument('--reselect-low', action='store_true',
                    help='when disasm score is low, search other methods in the same target class')
    ap.add_argument('--reselect-medium', action='store_true',
                    help='also reselect medium-confidence disasm candidates inside the target class')
    ap.add_argument('--method-aware-class', action='store_true',
                    help='choose among class candidates using the source method disassembly, not class shape alone')
    ap.add_argument('--src-exe', default=None)
    ap.add_argument('--dst-exe', default=None)
    ap.add_argument('--src-funcs', default=None)
    ap.add_argument('--dst-funcs', default=None)
    ap.add_argument('--anchors', default=None,
                    help='optional IDA-confirmed hook map with rva_7_0/name fields')
    ap.add_argument('--precision', action='store_true',
                    help='emit only high-confidence matches; never emit ambiguous/low candidates')
    a = ap.parse_args()

    S = parse_dump(a.src)
    T = parse_dump(a.dst)
    verify = None
    if a.verify_disasm:
        if not (a.src_exe and a.dst_exe and a.src_funcs and a.dst_funcs):
            sys.exit('--verify-disasm requires --src-exe --dst-exe --src-funcs --dst-funcs')
        src_pe = sig.PE(a.src_exe); dst_pe = sig.PE(a.dst_exe)
        src_ends = load_func_ends(a.src_funcs); dst_ends = load_func_ends(a.dst_funcs)
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
        verify = (src_pe, dst_pe, src_ends, dst_ends, md)
    rows = json.load(open(a.hooks, encoding='utf-8'))['rows']
    # index target by method count for fast candidate generation
    by_count = collections.defaultdict(list)
    for full, cls in T.items():
        by_count[len(cls['methods'])].append((full, cls))
    result = {}
    for h in rows:
        name = h['hook_method']
        sfull = h.get('fullname', '')
        scls = S.get(sfull)
        if not scls:
            result[name] = {'status': 'missing_source_class', 'source_class': sfull}
            continue
        sseq = class_seq(scls)
        n = len(sseq)
        # exact class first
        candidates = []
        exact = T.get(sfull)
        if exact is not None:
            candidates.append((1.0, sfull, exact, 'exact_class'))
        lo, hi = max(1, int(n * 0.40)), int(n * 2.2) + 1
        for cnt in range(lo, hi + 1):
            for full, cls in by_count.get(cnt, []):
                if full == sfull:
                    continue
                sc = class_score(sseq, class_seq(cls))
                if sc >= a.class_score:
                    candidates.append((sc, full, cls, 'shape'))
        candidates.sort(key=lambda x: -x[0])
        if not candidates:
            result[name] = {'status': 'no_class', 'source_class': sfull,
                            'source_decl': h.get('dump_decl', '')}
            continue
        # Optional: resolve class ambiguity with the actual source method's
        # disassembly. Only top class candidates are examined (never the whole dump).
        if a.method_aware_class and verify:
            sm0 = find_source_method(scls, h)
            if sm0 is not None:
                sp, dp, sends, dends, md0 = verify
                sv0 = 0x140000000 + sm0['rva']
                se0 = sends.get(sv0)
                rescored = []
                for sc0, full0, cls0, how0 in candidates[:16]:
                    tm0, why0 = align_method(scls, cls0, sm0)
                    if tm0 is None:
                        continue
                    tv0 = 0x140000000 + tm0['rva']
                    de0 = dends.get(tv0)
                    if not se0 or not de0:
                        continue
                    vr0 = disasm_compare(sp, dp, sv0, tv0, se0, de0, md0)
                    if not vr0:
                        continue
                    combined = 0.50 * sc0 + 0.50 * vr0['score']
                    rescored.append((combined, sc0, full0, cls0, how0, vr0, tm0, why0))
                rescored.sort(key=lambda x: -x[0])
                if rescored and (len(rescored) == 1 or rescored[0][0] - rescored[1][0] >= 0.035):
                    best = rescored[0]
                    candidates = [(best[1], best[2], best[3], best[4])]
                    # Keep the method result so the normal path can use it.
                    candidates_method_hint = (best[6], best[7])
                else:
                    candidates_method_hint = None
            else:
                candidates_method_hint = None
        else:
            candidates_method_hint = None
        # Prefer exact class, otherwise require a margin unless unique.
        if candidates[0][3] == 'exact_class':
            chosen = [candidates[0]]
        elif len(candidates) == 1 or candidates[0][0] - candidates[1][0] >= a.class_margin:
            chosen = [candidates[0]]
        else:
            # 类形状并列时，用“类内方法形状”二次消歧。
            sm0 = find_source_method(scls, h)
            rescored = []
            if sm0 is not None:
                for sc0, full0, cls0, how0 in candidates[:16]:
                    # 先做一次轻量类内方法打分
                    ms = [(method_sim(sm0['shape'], m['shape']), m)
                          for m in cls0['methods']]
                    ms.sort(key=lambda x: -x[0])
                    best_ms = ms[0][0] if ms else 0.0
                    if h.get('dump_name'):
                        name_hit = any(m['name'] == h['dump_name'] for m in cls0['methods'])
                        if name_hit:
                            best_ms = max(best_ms, 1.0)
                    rescored.append((0.60 * sc0 + 0.40 * best_ms, sc0, full0, cls0, how0))
                rescored.sort(key=lambda x: -x[0])
            if len(rescored) == 1 or (rescored and rescored[0][0] - rescored[1][0] >= 0.04):
                best = rescored[0]
                chosen = [(best[1], best[2], best[3], best[4])]
            else:
                result[name] = {'status': 'ambiguous_class', 'source_class': sfull,
                                'class_candidates': [{'class': c[1], 'score': round(c[0], 4)}
                                                     for c in candidates[:5]]}
                continue
        sc, tfull, tcls, how = chosen[0]
        if 'candidates_method_hint' in locals() and candidates_method_hint is not None:
            sm = candidates_method_hint[0]
        else:
            sm = find_source_method(scls, h)
        if sm is None:
            result[name] = {'status': 'missing_source_method', 'source_class': sfull,
                            'target_class': tfull, 'class_score': round(sc, 4)}
            continue
        tm, reason = align_method(scls, tcls, sm)
        if tm is None:
            result[name] = {'status': 'no_method', 'source_class': sfull,
                            'target_class': tfull, 'class_score': round(sc, 4)}
            continue
        result[name] = {
            'status': 'matched',
            'confidence': 'high' if reason in ('name', 'shape') else 'medium',
            'source_class': sfull,
            'source_rva': '0x%X' % sm['rva'],
            'source_decl': sm['decl'],
            'target_class': tfull,
            'class_score': round(sc, 4),
            'class_match': how,
            'method_match': reason,
            'target_rva': '0x%X' % tm['rva'],
            'target_va': '0x%X' % (0x140000000 + tm['rva']),
            'target_name': tm['name'],
            'target_decl': tm['decl'],
        }
        if verify:
            sp, dp, sends, dends, md = verify
            sv = 0x140000000 + sm['rva']; tv = 0x140000000 + tm['rva']
            se = sends.get(sv); de = dends.get(tv)
            if se and de:
                vr = disasm_compare(sp, dp, sv, tv, se, de, md)
                if vr:
                    result[name]['disasm'] = vr
                    result[name]['disasm_status'] = (
                        'high' if vr['score'] >= 0.78 else
                        'medium' if vr['score'] >= 0.60 else 'low')
            # 低分候选自动在同一目标类内重新选：按方法形状先筛选，再比反汇编特征。
            _rs = result[name].get('disasm_status')
            if ((a.reselect_low and _rs == 'low') or
                    (a.reselect_medium and _rs == 'medium')):
                pool = []
                for cm in tcls['methods']:
                    ms0 = method_sim(sm['shape'], cm['shape'])
                    if ms0 < 0.72:
                        continue
                    pool.append((ms0, cm))
                pool.sort(key=lambda x: -x[0])
                rescored = []
                for ms0, cm in pool[:80]:
                    tv0 = 0x140000000 + cm['rva']
                    de0 = dends.get(tv0)
                    if not de0:
                        continue
                    vr0 = disasm_compare(sp, dp, sv, tv0, se, de0, md)
                    if not vr0:
                        continue
                    # Known/non-obfuscated return types (UnityEngine.Rigidbody etc.)
                    # are a strong extra signal when several candidates tie.
                    type_bonus = 0.15 if raw_rtype(sm['decl']) == raw_rtype(cm['decl']) else 0.0
                    # When duplicate getters have identical code, keep the source/target
                    # method ordinal as a tie breaker.
                    try:
                        si = scls['methods'].index(sm)
                        ti = tcls['methods'].index(cm)
                        ncls = max(len(scls['methods']), len(tcls['methods']), 1)
                        ordinal_bonus = 0.05 * max(0.0, 1.0 - abs(si - ti) / ncls)
                    except Exception:
                        ordinal_bonus = 0.0
                    sc0 = 0.55 * vr0['score'] + 0.25 * ms0 + 0.15 * type_bonus + 0.05 * ordinal_bonus
                    rescored.append((sc0, ms0, vr0, cm))
                rescored.sort(key=lambda x: -x[0])
                if rescored:
                    best0 = rescored[0]
                    second0 = rescored[1][0] if len(rescored) > 1 else 0.0
                    result[name]['reselect'] = {
                        'best_score': round(best0[0], 4),
                        'gap': round(best0[0] - second0, 4),
                        'candidates': len(rescored),
                        'top3': [{'rva': '0x%X' % x[3]['rva'],
                                  'score': round(x[0], 4),
                                  'disasm': round(x[2]['score'], 4),
                                  'shape': round(x[1], 4)}
                                 for x in rescored[:3]],
                    }
                    _gap_req = 0.02 if _rs == 'medium' else 0.04
                    if best0[0] >= 0.78 and best0[0] - second0 >= _gap_req:
                        old = {'rva': result[name].get('target_rva'),
                               'name': result[name].get('target_name')}
                        cm = best0[3]
                        result[name].update({
                            'target_rva': '0x%X' % cm['rva'],
                            'target_va': '0x%X' % (0x140000000 + cm['rva']),
                            'target_name': cm['name'],
                            'target_decl': cm['decl'],
                            'method_match': 'reselect',
                            'confidence': 'high',
                            'reselect_from': old,
                            'disasm': best0[2],
                            'disasm_status': 'high' if best0[2]['score'] >= 0.78 else 'medium',
                        })
    # Optional IDA-confirmed anchors. This is deliberately explicit: names/shape
    # alone cannot disambiguate overloads or identical getters.
    if a.anchors:
        ad = json.load(open(a.anchors, encoding='utf-8'))
        ah = ad.get('hooks', ad) if isinstance(ad, dict) else ad
        # target RVA -> method record
        by_rva = {}
        for full, cls in T.items():
            for m in cls['methods']:
                by_rva[m['rva']] = (full, m)
        n_anchor = 0
        for x in ah:
            if not isinstance(x, dict):
                continue
            nm = x.get('name')
            rv = x.get('rva_7_0') or x.get('rva') or x.get('target_rva')
            if not nm or rv is None:
                continue
            try:
                rvi = int(str(rv), 16)
            except Exception:
                continue
            hit = by_rva.get(rvi)
            if not hit:
                continue
            full, m = hit
            prev = result.get(nm, {})
            old = {k: prev.get(k) for k in ('target_rva', 'target_va', 'target_name', 'target_decl',
                                            'method_match', 'confidence')}
            prev.update({'status': 'matched', 'confidence': 'anchor',
                         'method_match': 'anchor', 'anchor_source': a.anchors,
                         'target_rva': '0x%X' % m['rva'],
                         'target_va': '0x%X' % (0x140000000 + m['rva']),
                         'target_class': full, 'target_name': m['name'],
                         'target_decl': m['decl'], 'old_auto': old})
            result[nm] = prev
            n_anchor += 1
        print('anchors applied:', n_anchor)
    if a.precision:
        accepted = {}
        rejected = {}
        for nm, v in result.items():
            ok = (v.get('status') == 'matched' and
                  v.get('disasm_status') == 'high' and
                  (v.get('method_match') in ('reselect', 'fuzzy', 'ordinal') or
                   (v.get('method_match') == 'name' and
                    v.get('source_class') == v.get('target_class'))))
            if ok:
                accepted[nm] = v
            else:
                rejected[nm] = v
        result = accepted
        json.dump(rejected, open(a.out + '.rejected.json', 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        print('precision: accepted %d, rejected %d' % (len(accepted), len(rejected)))
    json.dump(result, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    stats = collections.Counter(v['status'] for v in result.values())
    print(stats)
    for st in ('matched', 'ambiguous_class', 'no_class', 'no_method', 'missing_source_class', 'missing_source_method'):
        xs = [n for n, v in result.items() if v['status'] == st]
        if xs:
            print('\n%s (%d)' % (st, len(xs)))
            for n in xs:
                v = result[n]
                print(' ', n, v.get('target_class', ''), v.get('target_rva', ''),
                      v.get('class_match', ''), v.get('method_match', ''))


if __name__ == '__main__':
    main()
