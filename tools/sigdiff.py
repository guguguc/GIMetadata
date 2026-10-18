#!/usr/bin/env python3
"""sigdiff.py —— BinDiff-lite cross-version matcher for existing sig.py signatures.

Unlike sig.py's first-stage byte scan, this tool:
  * snaps every matched byte window to a real function start via --funcs;
  * scores candidates with BinDiff-style features (mnemonic histogram, prime,
    instruction/call/block counts) in addition to loose/strict token matches;
  * reports unique, ambiguous and missed matches instead of returning the first hit.

Example:
  python3 tools/sigdiff.py scan version/7.0/gi.exe \
      --sigs version/7.1/sigs_hooks.json \
      --funcs /tmp/opencode/funcs70_dump.json \
      --sections il2cpp --out /tmp/opencode/hook70_diff.json
"""
import argparse
import binascii
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sig  # noqa: E402


def _ratio(a, b):
    if a is None or b is None or a <= 0 or b <= 0:
        return 0.0
    return min(a, b) / max(a, b)


def _features_score(sf, tf):
    if not sf or not tf:
        return 0.0
    cos = sig._cosine(sf.get('hist') or {}, tf.get('hist') or {})
    prime = 1.0 if sf.get('prime') == tf.get('prime') else 0.0
    counts = (_ratio(sf.get('insns'), tf.get('insns')) +
              _ratio(sf.get('calls'), tf.get('calls')) +
              _ratio(sf.get('blocks'), tf.get('blocks')) +
              _ratio(sf.get('edges'), tf.get('edges'))) / 4.0
    return 0.50 * cos + 0.20 * prime + 0.30 * counts


def _token_score(pe, md, window_va, sg):
    off = pe.va2off(window_va)
    if off is None:
        return 0.0, 0.0
    ins = []
    for x in md.disasm(pe.D[off:off + 256], window_va):
        ins.append(x)
        if len(ins) >= sg['n']:
            break
    if len(ins) < sg['n']:
        return 0.0, 0.0
    lo = [sig.toks_of(x, False) for x in ins]
    st = [sig.toks_of(x, True) for x in ins]
    ls = sum(1 for i in range(sg['n']) if lo[i] == sg['loose'][i]) / sg['n']
    ts = sum(1 for i in range(sg['n']) if st[i] == sg['strict'][i]) / sg['n']
    return ls, ts


def cmd_scan(a):
    pe = sig.PE(a.exe)
    sec = pe.section_bytes(a.sections)
    if sec is None:
        sys.exit('section not found: %s' % a.sections)
    tva, tbytes = sec
    funcs = sig.load_funcs(a.funcs)
    if not funcs:
        sys.exit('--funcs function table required for start snapping')
    # function start -> end
    fmap = {st: en for st, en, _ in funcs}
    md = sig.Cs(sig.CS_ARCH_X86, sig.CS_MODE_64)
    md.detail = True
    sigs = json.load(open(a.sigs, encoding='utf-8'))
    print('sigs %d, section %s (%.1f MB), functions %d' %
          (len(sigs), a.sections, len(tbytes) / 1e6, len(funcs)))
    feature_cache = {}
    hits = {}
    ambiguous = {}
    missed = []
    for sg in sigs:
        try:
            pb = binascii.unhexlify(sg['pat'])
            pm = binascii.unhexlify(sg['pmask'])
        except Exception:
            missed.append(sg['name']); continue
        fo, fl = sig._longest_fixed(pb, pm)
        if fl < 3:
            missed.append(sg['name']); continue
        needle = pb[fo:fo + fl]
        cand = []
        pos = 0
        while True:
            k = tbytes.find(needle, pos)
            if k < 0:
                break
            pos = k + 1
            base = k - fo
            if base < 0 or base + len(pb) > len(tbytes):
                continue
            if any(pm[i] and tbytes[base + i] != pb[i] for i in range(len(pb))):
                continue
            start = sig.snap_func(funcs, tva + base)
            if start is not None:
                cand.append((tva + base, start))
            if len(cand) > a.max_candidates:
                break
        best = {}
        for window, start in cand:
            ls, ts = _token_score(pe, md, window, sg)
            if ls < a.min_loose:
                continue
            if start not in feature_cache:
                feature_cache[start] = sig._func_features(pe, md, start, fmap.get(start, start + 0x4000))
            fs = _features_score(sg.get('features'), feature_cache[start])
            score = 0.45 * ls + 0.25 * ts + 0.30 * fs
            old = best.get(start)
            if old is None or score > old[0]:
                best[start] = (score, window, ls, ts, fs)
        if not best:
            missed.append(sg['name'])
            continue
        ranked = sorted(best.items(), key=lambda kv: -kv[1][0])
        top_start, top = ranked[0]
        second = ranked[1][1][0] if len(ranked) > 1 else 0.0
        rec = {'name': sg['name'], 'function_start': '0x%X' % top_start,
               'window': '0x%X' % top[1], 'score': round(top[0], 4),
               'loose': round(top[2], 4), 'strict': round(top[3], 4),
               'features': round(top[4], 4), 'second': round(second, 4),
               'candidates': len(ranked)}
        if top[0] >= a.min_score and top[0] - second >= a.margin:
            hits[sg['name']] = rec
        else:
            rec['top3'] = [{'start': '0x%X' % s, 'score': round(v[0], 4)}
                           for s, v in ranked[:3]]
            ambiguous[sg['name']] = rec
    # BinDiff-style output: only unique high-confidence matches are accepted.
    out = {'hits': hits, 'ambiguous': ambiguous, 'missed': missed,
           'stats': {'sigs': len(sigs), 'hit': len(hits),
                     'ambiguous': len(ambiguous), 'missed': len(missed)}}
    json.dump(out, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('hit %d, ambiguous %d, missed %d -> %s' %
          (len(hits), len(ambiguous), len(missed), a.out))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('scan')
    s.add_argument('exe')
    s.add_argument('--sigs', required=True)
    s.add_argument('--funcs', required=True)
    s.add_argument('--sections', default='.text')
    s.add_argument('--out', default='/tmp/opencode/sigdiff.json')
    s.add_argument('--min-score', type=float, default=0.68)
    s.add_argument('--margin', type=float, default=0.04)
    s.add_argument('--min-loose', type=float, default=0.50)
    s.add_argument('--max-candidates', type=int, default=256)
    a = ap.parse_args()
    if a.cmd == 'scan':
        cmd_scan(a)


if __name__ == '__main__':
    main()
