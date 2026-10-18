#!/usr/bin/env python3
"""从 dump.cs 的 `// RVA:` 行生成 sig.py / sigdiff.py 的函数边界表。

用法:
  python3 tools/dump_funcs.py out/dump70.cs -o /tmp/opencode/funcs70.json
"""
import argparse, json, re


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dump')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--image-base', default='0x140000000')
    a = ap.parse_args()
    base = int(a.image_base, 0)
    starts = set()
    for line in open(a.dump, encoding='utf-8', errors='ignore'):
        m = re.match(r'// RVA: (0x[0-9A-Fa-f]+)\b', line)
        if m:
            starts.add(base + int(m.group(1), 16))
    starts = sorted(starts)
    funcs = []
    for i, st in enumerate(starts):
        en = starts[i + 1] if i + 1 < len(starts) else st + 0x1000
        funcs.append({'name': 'sub_%X' % st, 'start': st, 'end': en,
                      'size': en - st, 'thunk': False,
                      'jmp_target': None, 'callees': []})
    json.dump({'funcs': funcs}, open(a.out, 'w'), indent=0)
    print('wrote %d funcs -> %s' % (len(funcs), a.out))


if __name__ == '__main__':
    main()
