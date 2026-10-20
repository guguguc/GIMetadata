#!/usr/bin/env python3
"""Shape-based name transfer from an old deobfuscated dump to a current dump.

This is intentionally separate from hook_resolve.py.  It does not resolve
hook addresses and does not need an IDA export; it compares class/method
metadata shapes and emits candidates for review.

Example:
    python3 tools/name_resolve.py \
        --src-dump dump/dump_deobfuscated.cs \
        --dst-dump out/dump67.cs \
        --out out/name_map67.json \
        --report out/name_map67_report.json \
        --jobs 1
"""
import argparse
import collections
import difflib
import json
import os
import re
import sys
import time
try:
    import networkx as nx
except Exception:
    nx = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dump_align as DA  # noqa: E402


def parse_dump_ext(path, old=False):
    """Parse either the old deobfuscated format or the current FullName format.

    Captures method shapes plus fields and declared base/interfaces; the latter
    are a second, independent fingerprint for classes whose names do not match.
    """
    lines = open(path, encoding='utf-8', errors='ignore', newline='').read().split('\n')
    types = {}
    ns = ''
    cur = None
    in_fields = False

    def new_class(full, name, kind=''):
        c = types.setdefault(full, {
            'full': full, 'name': name, 'kind': kind,
            'methods': [], 'fields': [], 'bases': []
        })
        if kind and not c.get('kind'):
            c['kind'] = kind
        return c

    for i, line in enumerate(lines):
        s = line.strip()
        if old:
            m = re.match(r'// Namespace:\s*(.*)', s)
            if m:
                ns = m.group(1).strip()
                continue
        else:
            if s.startswith('// FullName: '):
                full = s[len('// FullName: '):].strip()
                cur = new_class(full, full.split('.')[-1])
                in_fields = False
                continue
        m = re.match(
            r'^(?:public|private|internal|protected|sealed|abstract|static|partial|\s)*'
            r'(class|struct|interface|enum)\s+([^\s:{(]+)(.*)$', s)
        if m:
            name = m.group(2)
            if not old and cur is not None and cur.get('full', '').split('.')[-1] == name:
                full = cur['full']
            else:
                full = ((ns + '.') if (old and ns) else '') + name
            simple = full.split('.')[-1] if old else name
            cur = new_class(full, simple, m.group(1))
            rest = m.group(3).strip()
            if ':' in rest:
                bases = rest.split(':', 1)[1].split('{', 1)[0]
                for b in bases.split(','):
                    b = b.strip()
                    if b:
                        cur['bases'].append(b.split('<')[0].split('.')[-1])
            in_fields = False
            continue
        if cur is None:
            continue
        if s.startswith('// Fields'):
            in_fields = True
            continue
        if s.startswith(('// Properties', '// Methods', '// Events')):
            in_fields = False
            continue
        if in_fields and s and not s.startswith(('//', '[', '{', '}')):
            field = s.split('//', 1)[0].strip().rstrip(';')
            if '(' not in field and ';' not in field:
                toks = field.split()
                mods = {'public','private','protected','internal','static','readonly',
                        'volatile','const','new','unsafe','fixed'}
                while toks and toks[0] in mods:
                    toks.pop(0)
                if len(toks) >= 2:
                    # Last token is the field name; the rest is its type.
                    name = toks[-1]
                    typ = ' '.join(toks[:-1])
                    cur['fields'].append(DA.shape_type(typ))
            continue
        if not s.startswith('// RVA:'):
            continue
        decl = ''
        for j in range(i + 1, min(i + 6, len(lines))):
            q = lines[j].strip()
            if q and not q.startswith(('//', '[', '{', '}')):
                decl = q
                break
        if not decl or '(' not in decl:
            continue
        mm = re.search(r'([A-Za-z_\.<][\w\.<>]*)\s*\(', decl)
        if not mm:
            continue
        cur['methods'].append({
            'rva': int(re.match(r'// RVA: (0x[0-9A-Fa-f]+)', s).group(1), 16)
                   if re.match(r'// RVA: (0x[0-9A-Fa-f]+)', s) else 0,
            'decl': decl, 'name': mm.group(1), 'shape': DA.mshape(decl)
        })
    return types


def shapes(c):
    return [m['shape'] for m in c['methods']]


def method_name_set(c):
    return {m['name'] for m in c['methods'] if m['name'] not in ('.ctor', '.cctor')}


def candidate_classes(src, target, inv, field_inv, by_simple, by_full, limit=600):
    """Retrieve target classes that share a rare method shape or a class name."""
    cands = {}
    if src['full'] in by_full:
        cands[src['full']] = by_full[src['full']]
    for c in by_simple.get(src['name'], []):
        cands[c['full']] = c
    seq = shapes(src)
    if seq:
        # Rarer shapes are much more selective; take up to three.
        ranked = sorted(set(seq), key=lambda sh: len(inv.get(sh, ())))
        for sh in ranked[:3]:
            for full in inv.get(sh, ())[:limit]:
                cands[full] = target[full]
    # Static/data classes may have few or no methods; field shapes are the
    # only usable structural fingerprint for them.
    for sh in sorted(set(src.get('fields', [])),
                     key=lambda x: len(field_inv.get(x, ())))[:3]:
        for full in field_inv.get(sh, ())[:limit]:
            cands[full] = target[full]
    return list(cands.values())[:limit]


def _multiset_jaccard(a, b):
    if not a and not b:
        return 1.0
    ca, cb = collections.Counter(a), collections.Counter(b)
    return sum((ca & cb).values()) / max(1, sum((ca | cb).values()))


def _coverage(a, b):
    """Return (source coverage, target precision) for two shape multisets."""
    if not a and not b:
        return 1.0, 1.0
    ca, cb = collections.Counter(a), collections.Counter(b)
    inter = sum((ca & cb).values())
    return (inter / len(a) if a else 0.0,
            inter / len(b) if b else 0.0)


def score_class(src, dst):
    """Coverage-first class score.

    Jaccard penalises target classes that merely gained methods.  This score
    keeps source coverage high when methods were added, while target precision
    prevents a small old class from matching a huge unrelated class.
    """
    sseq, tseq = shapes(src), shapes(dst)
    if not sseq or not tseq:
        return 0.0
    src_cov, dst_prec = _coverage(sseq, tseq)
    seq = difflib.SequenceMatcher(None, sseq, tseq, autojunk=False).ratio()
    sf, tf = src.get('fields', []), dst.get('fields', [])
    field_cov, field_prec = _coverage(sf, tf)
    base_score = _multiset_jaccard(src.get('bases', []), dst.get('bases', []))
    count = 1.0 - abs(len(sseq) - len(tseq)) / max(1, len(sseq), len(tseq))
    score = (0.35 * src_cov + 0.20 * dst_prec + 0.20 * seq +
             0.10 * field_cov + 0.05 * field_prec +
             0.05 * base_score + 0.05 * count)
    if src.get('kind') and dst.get('kind') and src['kind'] != dst['kind']:
        score -= 0.15
    sn, tn = method_name_set(src), method_name_set(dst)
    if sn and tn:
        score += 0.02 * len(sn & tn) / max(1, len(sn | tn))
    return max(0.0, min(1.0, score))



def _param_sim(a, b):
    pa, pb = a[1], b[1]
    if not pa and not pb:
        return 1.0
    return difflib.SequenceMatcher(None, pa, pb, autojunk=False).ratio()


def align_methods(src, dst, used, method_anchors=None):
    """Method matching that tolerates target-side added methods.

    Return type is a hard constraint.  Name exactness is tried first, then
    parameter shape, then a shape-LCS block.  Ordinal alignment is deliberately
    not used as a primary signal.
    """
    out = []
    sseq = [m['shape'] for m in src['methods']]
    tseq = [m['shape'] for m in dst['methods']]
    blocks = []
    for a, b, n in difflib.SequenceMatcher(None, sseq, tseq, autojunk=False).get_matching_blocks():
        for k in range(n):
            blocks.append((a + k, b + k))
    block_map = dict(blocks)
    # Reserve explicit method anchors BEFORE ordinary shape matching.  An
    # earlier unanchored method could otherwise steal the same target method.
    anchored_indices = set()
    for si, sm in enumerate(src['methods']):
        forced = (method_anchors or {}).get((src['full'], sm['name']))
        if not forced:
            continue
        fm = next((m for m in dst['methods'] if m['name'] == forced
                   and (m.get('rva'), m.get('name'), m.get('decl')) not in used), None)
        if fm is not None:
            used.add((fm.get('rva'), fm.get('name'), fm.get('decl')))
            anchored_indices.add(si)
            out.append({'source': sm['name'], 'target': fm['name'],
                        'target_rva': '0x%X' % fm.get('rva', 0),
                        'reason': 'hook-anchor', 'source_decl': sm['decl'],
                        'target_decl': fm['decl']})

    for si, sm in enumerate(src['methods']):
        if si in anchored_indices:
            continue
        ret = sm['shape'][0]
        cands = []
        for ti, tm in enumerate(dst['methods']):
            if tm['shape'][0] != ret:
                continue
            key = (tm.get('rva'), tm.get('name'), tm.get('decl'))
            if key in used:
                continue
            ps = _param_sim(sm['shape'], tm['shape'])
            ns = 1.0 if sm['name'] == tm['name'] else 0.0
            cands.append((0.55 * ns + 0.45 * ps, ns, ps, ti, tm))
        if not cands:
            out.append({'source': sm['name'], 'reason': 'none'})
            continue
        cands.sort(key=lambda x: (-x[0], x[3]))
        best = cands[0]
        if si in block_map:
            ti = block_map[si]
            if ti < len(dst['methods']) and dst['methods'][ti]['shape'][0] == ret:
                key = (dst['methods'][ti].get('rva'), dst['methods'][ti].get('name'),
                       dst['methods'][ti].get('decl'))
                if key not in used and best[2] < 0.75:
                    best = (0.60, 0.0, 1.0, ti, dst['methods'][ti])
        tm = best[4]
        reason = 'name' if best[1] >= 1.0 else ('shape' if best[2] >= 0.70 else 'lcs')
        used.add((tm.get('rva'), tm.get('name'), tm.get('decl')))
        out.append({
            'source': sm['name'], 'target': tm['name'],
            'target_rva': '0x%X' % tm.get('rva', 0),
            'reason': reason, 'source_decl': sm['decl'],
            'target_decl': tm['decl'],
        })

    return out


_SCORE_CTX = {}


def _score_source(sf):
    """Worker: score one source class against the target index."""
    src = _SCORE_CTX['S'][sf]
    T = _SCORE_CTX['T']
    cands = candidate_classes(
        src, T, _SCORE_CTX['inv'], _SCORE_CTX['field_inv'],
        _SCORE_CTX['by_simple'], _SCORE_CTX['by_full'])
    scored = []
    for tc in cands:
        sc = score_class(src, tc)
        if sc > 0.25:
            scored.append((sc, tc['full']))
    scored.sort(key=lambda x: (-x[0], x[1]))
    if not scored:
        return sf, []
    best = scored[0][0]
    second = scored[1][0] if len(scored) > 1 else 0.0
    out = scored[:5]
    if best >= 0.78 and (second == 0.0 or best - second >= 0.035):
        return sf, out
    return sf, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src-dump', required=True)
    ap.add_argument('--dst-dump', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--report', default=None)
    ap.add_argument('--anchors', default=None,
                    help='optional JSON map old_class -> target_class; forced high-confidence anchors')
    ap.add_argument('--assignment', choices=['greedy', 'hungarian'],
                    default='hungarian',
                    help='one-to-one class assignment (default: hungarian/global)')
    ap.add_argument('--jobs', type=int, default=1,
                    help='parallel scoring worker count (default 1)')
    a = ap.parse_args()

    t0 = time.perf_counter()
    S = parse_dump_ext(a.src_dump, old=True)
    T = parse_dump_ext(a.dst_dump, old=False)
    print('source classes:', len(S), 'target classes:', len(T))

    by_simple = collections.defaultdict(list)
    by_full = collections.defaultdict(list)
    inv = collections.defaultdict(list)
    field_inv = collections.defaultdict(list)
    for full, c in T.items():
        by_full[full].append(c)
        by_simple[full.split('.')[-1]].append(c)
        for sh in set(shapes(c)):
            inv[sh].append(full)
        for sh in set(c.get('fields', [])):
            field_inv[sh].append(full)

    # Exact-name anchors first.  Full names are stronger than simple names.
    anchors = {}
    for sf, sc in S.items():
        cands = by_full.get(sf, [])
        why = 'exact-full'
        if not cands:
            cands = by_simple.get(sc['name'], [])
            why = 'exact-simple'
        if len(cands) == 1:
            anchors[sf] = (cands[0], why)

    # Explicit hook/class anchors take precedence over shape inference.
    method_anchors = {}
    if a.anchors:
        raw = json.load(open(a.anchors, encoding='utf-8'))
        if isinstance(raw, dict) and 'classes' in raw:
            class_map = raw.get('classes') or {}
            method_anchors = {tuple(k.split('::', 1)): v for k, v in (raw.get('methods') or {}).items()}
        else:
            class_map = raw
        for sf, tf in class_map.items():
            sc = S.get(sf)
            tc = T.get(tf)
            if sc is not None and tc is not None:
                anchors[sf] = (tc, 'hook-anchor')

    # Shape candidates for everything not anchored.  Each source class is
    # independent, so worker processes only return (score, target_name).
    edges = []
    top_candidates = {}
    unanchored = [sf for sf in S if sf not in anchors]
    _SCORE_CTX.update({'S': S, 'T': T, 'inv': inv, 'field_inv': field_inv,
                       'by_simple': by_simple, 'by_full': by_full})
    if a.jobs > 1 and len(unanchored) > 1:
        import multiprocessing as mp
        try:
            ctx = mp.get_context('fork')
            with ctx.Pool(processes=a.jobs) as pool:
                pairs = pool.map(_score_source, unanchored, chunksize=8)
        except (ValueError, OSError):
            pairs = [_score_source(sf) for sf in unanchored]
    else:
        pairs = [_score_source(sf) for sf in unanchored]
    for sf, scored in pairs:
        if not scored:
            continue
        top_candidates[sf] = [(score, T[full]) for score, full in scored]
        best, bfull = scored[0]
        second = scored[1][0] if len(scored) > 1 else 0.0
        if best >= 0.78 and (second == 0.0 or best - second >= 0.035):
            edges.append((best, sf, bfull))

    # One-to-one class assignment.  Global max-weight matching avoids the
    # "first source steals the best target" failure of greedy assignment.
    assigned = {}
    used_targets = set()
    if a.assignment == 'hungarian' and nx is not None:
        G = nx.Graph()
        emap = {}
        for sf, (tc, why) in anchors.items():
            sn, tn = 'S:' + sf, 'T:' + tc['full']
            G.add_edge(sn, tn, weight=10.0)
            emap[(sf, tc['full'])] = (1.0, why)
        for sf, scored in top_candidates.items():
            for score, tc in scored:
                if score < 0.65:
                    continue
                sn, tn = 'S:' + sf, 'T:' + tc['full']
                # Negative scores for weak edges make them optional rather
                # than forcing a maximum-cardinality matching.
                G.add_edge(sn, tn, weight=score - 0.55)
                emap[(sf, tc['full'])] = (score, 'shape')
        for u, v in nx.max_weight_matching(G, maxcardinality=False):
            if u.startswith('S:') and v.startswith('T:'):
                sf, tf = u[2:], v[2:]
            elif v.startswith('S:') and u.startswith('T:'):
                sf, tf = v[2:], u[2:]
            else:
                continue
            score, why = emap.get((sf, tf), (0.0, 'shape'))
            if score <= 0.0:
                continue
            assigned[sf] = (T[tf], 'high' if score >= 0.90 or why.startswith('exact') else 'medium',
                            score, why)
            used_targets.add(tf)
    else:
        # Deterministic greedy fallback (also used when networkx is absent).
        for sf, (tc, why) in anchors.items():
            if tc['full'] not in used_targets:
                assigned[sf] = (tc, 'high', 1.0, why)
                used_targets.add(tc['full'])
        edges.sort(key=lambda x: -x[0])
        for score, sf, tf in edges:
            if sf in assigned or tf in used_targets:
                continue
            assigned[sf] = (T[tf], 'high' if score >= 0.90 else 'medium', score,
                            'shape')
            used_targets.add(tf)

    classes = {}
    method_stats = collections.Counter()
    for sf, sc in S.items():
        if sf not in assigned:
            cand = top_candidates.get(sf, [])
            classes[sf] = {
                'source_name': sc['name'],
                'source_kind': sc['kind'],
                'source_method_count': len(sc['methods']),
                'status': 'ambiguous' if cand else 'unresolved',
                'candidates': [
                    {'target': tc['full'], 'score': round(score, 4),
                     'target_method_count': len(tc['methods'])}
                    for score, tc in cand
                ],
            }
            method_stats['unresolved_classes'] += 1
            continue
        tc, conf, score, why = assigned[sf]
        used = set()
        methods = align_methods(sc, tc, used, method_anchors)
        for m in methods:
            method_stats[m['reason']] += 1
        classes[sf] = {
            'source_name': sc['name'],
            'source_kind': sc['kind'],
            'source_method_count': len(sc['methods']),
            'target': tc['full'],
            'target_kind': tc.get('kind', ''),
            'target_method_count': len(tc['methods']),
            'confidence': conf,
            'score': round(score, 4),
            'reason': why,
            'methods': methods,
        }

    result = {
        'source_dump': os.path.abspath(a.src_dump),
        'target_dump': os.path.abspath(a.dst_dump),
        'classes': classes,
    }
    json.dump(result, open(a.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)

    class_stats = collections.Counter(
        v.get('status', 'assigned') for v in classes.values())
    report = {
        'total_seconds': round(time.perf_counter() - t0, 3),
        'source_classes': len(S),
        'target_classes': len(T),
        'assignment': a.assignment,
        'class_status': dict(class_stats),
        'method_reasons': dict(method_stats),
    }
    if a.report:
        json.dump(report, open(a.report, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
    print(json.dumps(report, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
