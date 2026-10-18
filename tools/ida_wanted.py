#!/usr/bin/env python3
"""ida_wanted.py —— 从 sig_hits.json 解析“必须强制反编译”的函数地址。

用法:
    python3 tools/ida_wanted.py version/7.0/sig_hits.json
    python3 tools/ida_wanted.py version/7.0/sig_hits.json --command

输出:
    默认：空格分隔的 0x... 地址，可直接追加给 tools/ida_headless.sh
    --command：打印完整的 IDA 导出命令
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('hits')
    ap.add_argument('--list', default=os.path.join(HERE, 'ida_wanted.txt'))
    ap.add_argument('--command', action='store_true')
    ap.add_argument('--root', default=None, help='目标版本目录（默认从 hits 路径推断）')
    a = ap.parse_args()

    H = json.load(open(a.hits, encoding='utf-8'))
    hv = H.get('hits', H) if isinstance(H, dict) else {}
    names = []
    for line in open(a.list, encoding='utf-8'):
        line = line.strip()
        if line and not line.startswith('#'):
            names.append(line)
    eas = []
    miss = []
    for n in names:
        v = hv.get(n)
        if v is None:
            miss.append(n)
            continue
        eas.append(int(v))
    print(' '.join('0x%X' % x for x in eas))
    if miss:
        print('# missing in %s: %s' % (os.path.basename(a.hits), ', '.join(miss)), file=sys.stderr)
    if a.command:
        root = a.root or os.path.dirname(os.path.abspath(a.hits))
        out = os.path.join(root, 'ida.extra.json')
        dec = os.path.join(root, 'ida', 'decomp_wanted')
        print()
        print('IDAT=/path/to/idat64 \\')
        print('GI_TEXT=%s \\' % os.path.relpath(dec, ROOT))
        print('tools/ida_headless.sh \\')
        print('    %s \\' % os.path.relpath(os.path.join(root, 'gi.exe'), ROOT))
        print('    %s \\' % os.path.relpath(out, ROOT))
        print('    %s \\' % os.path.relpath(a.hits, ROOT))
        for x in eas:
            print('    0x%X \\' % x)
        print('    # 结束后运行: python3 tools/offline_extract.py %s' % os.path.relpath(root, ROOT))


if __name__ == '__main__':
    main()
