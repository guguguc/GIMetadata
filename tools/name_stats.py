#!/usr/bin/env python3
"""Count obfuscated 7.1 source classes that have an exact old-dump name.

This joins three deterministic inputs:

  * hk.json                  hook name -> 7.1 rva
  * out/dump71.cs            7.1 rva -> source class/method
  * hk69_old_audit.tsv       hook -> EXACT/REVIEW/UNRESOLVED old name

It does not decompile or query IDA.  Obfuscation is the local convention used
by the dumper: a class with no namespace and a long all-uppercase identifier.

Example:
    python3 tools/name_stats.py \
        --audit out/hk69_old_audit.tsv \
        --structure-dump out/dump71.cs \
        --hooks hk.json \
        --out out/name_stats71.json \
        --tsv out/name_stats71.tsv
"""
import argparse
import json
import re
import sys

import dump_align as DA


def is_obfuscated_class(name):
    return bool(name) and "." not in name and bool(re.fullmatch(r"[A-Z]{8,}", name))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit', required=True,
                    help='hook/status/old_class/old_method TSV')
    ap.add_argument('--structure-dump', required=True,
                    help='7.1 dump.cs (or another source-version dump)')
    ap.add_argument('--hooks', required=True, help='hk.json with hooks[].method/rva')
    ap.add_argument('--out', default=None, help='summary JSON')
    ap.add_argument('--tsv', default=None, help='per-hook TSV')
    a = ap.parse_args()

    T = DA.parse_dump(a.structure_dump)
    rva_map = {m['rva']: (full, m) for full, c in T.items() for m in c['methods']}
    hooks = json.load(open(a.hooks, encoding='utf-8'))
    hooks = hooks.get('hooks', hooks)
    hook_by_name = {h['method']: h for h in hooks}

    rows = []
    with open(a.audit, encoding='utf-8') as f:
        header = f.readline().rstrip('\n').split('\t')
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < len(header):
                continue
            row = dict(zip(header, p))
            if row.get('status') != 'EXACT':
                continue
            h = hook_by_name.get(row.get('hook'))
            src = rva_map.get(int(str(h.get('rva', '0')), 16)) if h else None
            src_class = src[0] if src else ''
            rows.append({
                'hook': row.get('hook'),
                'source_class': src_class,
                'obfuscated': is_obfuscated_class(src_class),
                'old_class': row.get('old_class', ''),
                'old_method': row.get('old_method', ''),
                'rva': h.get('rva') if h else '',
                'src_method': src[1]['name'] if src else '',
            })

    hook_obf = sum(1 for r in rows if r['obfuscated'])
    hook_real = len(rows) - hook_obf
    unique = {r['source_class'] for r in rows if r['source_class']}
    unique_obf = {r['source_class'] for r in rows if r['obfuscated']}
    missing_rva = sum(1 for r in rows if not r['source_class'])

    summary = {
        'exact_hooks': len(rows),
        'rva_missing': missing_rva,
        'hook_entries_obfuscated': hook_obf,
        'hook_entries_real': hook_real,
        'unique_source_classes': len(unique),
        'unique_obfuscated_classes': len(unique_obf),
        'unique_real_classes': len(unique) - len(unique_obf),
        'obfuscated_classes': sorted(unique_obf),
        'real_classes': sorted(unique - unique_obf),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=1))

    if a.out:
        json.dump(summary, open(a.out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
    if a.tsv:
        with open(a.tsv, 'w', encoding='utf-8') as f:
            f.write('hook\trva\tsrc_method\tsource_class\tobfuscated\told_class\told_method\n')
            for r in rows:
                f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (
                    r['hook'], r['rva'], r['src_method'], r['source_class'],
                    '1' if r['obfuscated'] else '0', r['old_class'], r['old_method']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
