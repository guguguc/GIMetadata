#!/usr/bin/env python3
"""Fuzzy hook-name transfer into an old deobfuscated dump.

Pipeline:
    hooks.json (7.1 hook name + RVA)
        -> structure dump (7.1) to get the source method shape
        -> old deobfuscated dump to find class/method candidates

No IDA export is required.  The output is deliberately candidate-oriented:
exact class::method hits are reliable; shape/name candidates need review.

Example:
    python3 tools/hook_old_name.py \
        --hooks hk.json \
        --structure-dump out/dump71.cs \
        --old-dump dump/dump_deobfuscated.cs \
        --out out/hk69_old_candidates.json \
        --tsv out/hk69_old_candidates.tsv
"""
import argparse
import difflib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dump_align as DA  # noqa: E402
from name_resolve import parse_dump_ext  # noqa: E402


def parse_old_dump(path):
    """Parse the old deobfuscated format without treating embedded CR as newlines."""
    lines = open(path, encoding='utf-8', errors='ignore', newline='').read().split('\n')
    types = {}
    ns = ''
    cur = None
    for i, line in enumerate(lines):
        s = line.strip()
        m = re.match(r'// Namespace:\s*(.*)', s)
        if m:
            ns = m.group(1).strip()
            continue
        m = re.match(
            r'^(?:public|private|internal|protected|sealed|abstract|static|partial|\s)*'
            r'(class|struct|interface|enum)\s+([^\s:{(]+)', s)
        if m:
            name = m.group(2)
            full = (ns + '.' + name) if ns else name
            cur = types.setdefault(full, {
                'full': full, 'name': full.split('.')[-1],
                'kind': m.group(1), 'methods': []
            })
            continue
        if cur is None or not s.startswith('// RVA:'):
            continue
        decl = ''
        for j in range(i + 1, min(i + 6, len(lines))):
            q = lines[j].strip()
            if q and not q.startswith(('//', '[', '{', '}')):
                decl = q
                break
        if not decl or '(' not in decl:
            continue
        mm = re.search(r'(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(', decl)
        if not mm:
            continue
        cur['methods'].append({
            'name': mm.group(1), 'decl': decl, 'shape': DA.mshape(decl)
        })
    return types


def _norm(s):
    return re.sub(r'[^a-z0-9]+', '', s.lower())


def _sim(a, b):
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def class_score(hook_class, old):
    best = max(_sim(hook_class, old['name']), _sim(hook_class, old['full']))
    if old['name'].lower() in hook_class.lower():
        best = max(best, 0.88)
    return best


def method_score(hook_method, old_method):
    best = _sim(hook_method, old_method)
    base = re.sub(r'^(get|set)_', '', old_method, flags=re.I)
    return max(best, _sim(hook_method, base))


def _field_jaccard(a, b):
    if not a and not b:
        return 1.0
    ca, cb = {}, {}
    for x in a:
        ca[x] = ca.get(x, 0) + 1
    for x in b:
        cb[x] = cb.get(x, 0) + 1
    inter = sum(min(v, cb.get(k, 0)) for k, v in ca.items())
    union = sum(ca.values()) + sum(cb.values()) - inter
    return inter / union if union else 1.0


def _base_jaccard(a, b):
    if not a and not b:
        return 1.0
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else 1.0


def _norm_ret(m):
    # raw return type without namespace is the strongest cross-dump signal.
    return DA.raw_rtype(m['decl']).split('.')[-1]


def _shape_score(src_cls, old_cls):
    sm = DA.class_score([m['shape'] for m in src_cls['methods']],
                        [m['shape'] for m in old_cls['methods']])
    fs = _field_jaccard(src_cls.get('fields', []), old_cls.get('fields', []))
    bs = _base_jaccard(src_cls.get('bases', []), old_cls.get('bases', []))
    return 0.55 * sm + 0.25 * fs + 0.20 * bs, sm, fs, bs


def _exact_class_review(hook, src, old_classes, src_cls):
    """Exact old class name, different method: review by return type + shape."""
    if src is None or src_cls is None:
        return None
    sshape = src[1]['shape']
    parts = hook.split('_')
    best = None
    for i in range(1, len(parts)):
        cp = '_'.join(parts[:i])
        mp = '_'.join(parts[i:])
        for oc in old_classes.values():
            if not (oc['name'] == cp or oc['full'].replace('.', '_') == cp
                    or oc['full'] == cp):
                continue
            if any(m['name'] == mp for m in oc['methods']):
                # Exact class+method is handled by the normal candidate path.
                return None
            for om in oc['methods']:
                if om['shape'][0] != sshape[0]:
                    continue
                if _norm_ret(om) != _norm_ret(src[1]) and sshape[0] != 'C':
                    continue
                ms = DA.method_sim(sshape, om['shape'])
                if ms < 0.78:
                    continue
                ns = max(_sim(mp, om['name']), _sim(mp.split('_')[-1], om['name']))
                if ns < 0.60:
                    continue
                score = 0.70 * ms + 0.30 * ns
                if best is None or score > best[0]:
                    best = (score, ms, ns, oc, om, mp)
    if best is None:
        return None
    score, ms, ns, oc, om, mp = best
    return {
        'class': oc['full'], 'method': om['name'],
        'class_score': 1.0, 'method_score': round(ms, 4),
        'name_score': round(ns, 4), 'score': round(score, 4),
        'source_method': mp, 'decl': om['decl'],
    }


def _class_shape_review(hook, src, old_classes, src_cls):
    """Find a differently-named old class by structure, then a method with
    the same return type and a fuzzy parameter signature.  Always REVIEW."""
    if src is None or src_cls is None:
        return None
    sshape = src[1]['shape']
    n = len(src_cls['methods'])
    if n < 2:
        return None
    lo, hi = max(1, int(n * 0.40)), int(n * 2.2) + 1
    scored = []
    for oc in old_classes.values():
        if not (lo <= len(oc['methods']) <= hi):
            continue
        total, ms, fs, bs = _shape_score(src_cls, oc)
        if ms < 0.78 or total < 0.76:
            continue
        scored.append((total, ms, fs, bs, oc))
    scored.sort(key=lambda x: -x[0])
    if not scored:
        return None
    best = scored[0]
    second = scored[1][0] if len(scored) > 1 else 0.0
    if second and best[0] - second < 0.035:
        return None
    oc = best[4]
    # Return type must match exactly.  Parameter signature may be fuzzy.
    m_cands = []
    for om in oc['methods']:
        if om['shape'][0] != sshape[0]:
            continue
        # compare raw primitive return names too; C is intentionally shape-only
        if _norm_ret(om) != _norm_ret(src[1]) and sshape[0] != 'C':
            continue
        ms = DA.method_sim(sshape, om['shape'])
        m_cands.append((ms, om))
    if not m_cands:
        return None
    m_cands.sort(key=lambda x: -x[0])
    mms, om = m_cands[0]
    if mms < 0.70:
        return None
    return {
        'class': oc['full'], 'method': om['name'],
        'class_score': round(best[0], 4),
        'method_score': round(mms, 4),
        'shape_score': round(best[1], 4),
        'field_score': round(best[2], 4),
        'base_score': round(best[3], 4),
        'return_type': om['decl'].split('(')[0].strip(),
        'decl': om['decl'],
    }


def load_hooks(path):
    j = json.load(open(path, encoding='utf-8'))
    return j.get('hooks', j)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hooks', required=True, help='hk.json with hooks[].method/rva')
    ap.add_argument('--structure-dump', required=True,
                    help='dump.cs of the hook source version (e.g. out/dump71.cs)')
    ap.add_argument('--old-dump', required=True,
                    help='old deobfuscated dump.cs')
    ap.add_argument('--out', required=True, help='candidate JSON')
    ap.add_argument('--tsv', default=None, help='candidate TSV')
    ap.add_argument('--review-tsv', default=None,
                    help='REVIEW-only fallback TSV')
    ap.add_argument('--top', type=int, default=5)
    ap.add_argument('--min-class', type=float, default=0.72)
    ap.add_argument('--min-shape', type=float, default=0.80)
    ap.add_argument('--class-shape', action='store_true',
                    help='enable class/method fallback; always REVIEW, never EXACT')
    a = ap.parse_args()

    if a.class_shape:
        T = parse_dump_ext(a.structure_dump, old=False)
        O = parse_dump_ext(a.old_dump, old=True)
    else:
        T = DA.parse_dump(a.structure_dump)
        O = parse_old_dump(a.old_dump)
    rva_map = {m['rva']: (f, m) for f, c in T.items() for m in c['methods']}
    old_methods = [(c, m) for c in O.values() for m in c['methods']]
    hooks = load_hooks(a.hooks)

    out = []
    review_done = set()
    for h in hooks:
        name = h['method']
        src = rva_map.get(int(str(h.get('rva', '0')), 0))
        sshape = src[1]['shape'] if src else None
        parts = name.split('_')
        cands = []
        for oldc, om in old_methods:
            sh = DA.method_sim(sshape, om['shape']) if sshape else 0.5
            if sh < a.min_shape:
                continue
            best = 0.0
            why = None
            for i in range(1, len(parts)):
                cp = '_'.join(parts[:i])
                mp = '_'.join(parts[i:])
                cs = class_score(cp, oldc)
                if cs < a.min_class:
                    continue
                ms = method_score(mp, om['name'])
                score = 0.50 * cs + 0.30 * ms + 0.20 * sh
                if score > best:
                    best = score
                    why = (cp, mp, round(cs, 4), round(ms, 4), round(sh, 4))
            if best >= 0.55:
                cands.append({
                    'score': round(best, 4), 'class': oldc['full'],
                    'method': om['name'], 'why': why, 'decl': om['decl']
                })
        cands.sort(key=lambda x: -x['score'])
        dedup = []
        seen = set()
        for c in cands:
            key = (c['class'], c['method'])
            if key in seen:
                continue
            seen.add(key)
            dedup.append(c)
            if len(dedup) >= a.top:
                break
        item = {
            'hook': name,
            'rva': h.get('rva'),
            'src_class': src[0] if src else None,
            'src_method': src[1]['name'] if src else None,
            'src_decl': src[1]['decl'] if src else None,
            'candidates': dedup,
        }
        if a.class_shape and name not in review_done:
            src_cls = T.get(src[0]) if src else None
            rev = _exact_class_review(name, src, O, src_cls)
            if rev:
                item['class_review'] = [rev]
                review_done.add(name)
            else:
                rev = _class_shape_review(name, src, O, src_cls)
                if rev:
                    item['class_shape_review'] = [rev]
                    review_done.add(name)
        out.append(item)

    json.dump(out, open(a.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    if a.tsv:
        with open(a.tsv, 'w', encoding='utf-8') as f:
            f.write('hook\tscore\told_class\told_method\twhy\tsrc_class\tsrc_method\n')
            for x in out:
                for c in x['candidates']:
                    f.write('%s\t%.4f\t%s\t%s\t%s\t%s\t%s\n' % (
                        x['hook'], c['score'], c['class'], c['method'],
                        c['why'], x['src_class'], x['src_method']))
    if a.review_tsv:
        with open(a.review_tsv, 'w', encoding='utf-8') as f:
            f.write('hook\tstatus\told_class\told_method\tscore\tname_score\tmethod_score\n')
            for x in out:
                for key, status in (('class_review', 'REVIEW_CLASS'),
                                    ('class_shape_review', 'REVIEW_SHAPE')):
                    for r in x.get(key, []):
                        f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (
                            x['hook'], status, r['class'], r['method'],
                            r.get('score', ''), r.get('name_score', ''),
                            r.get('method_score', '')))
    print('hooks', len(out), 'with candidates',
          sum(1 for x in out if x['candidates']))
    print('output', a.out)


if __name__ == '__main__':
    main()
