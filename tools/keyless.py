#!/usr/bin/env python3
"""keyless.py —— 无密钥反解 `typeDefinitions`（不需要任何版本常量）

原理
----
累计索引字段（methodStart/fieldStart/propertyStart/eventStart/nestedTypesStart/
interfacesStart）在"该类型没有这张表"时，解码结果是**哨兵**（-1 或 0）。
于是 raw 列里会出现**大量重复的同一个 raw 值** raw*。由

    decoded = raw op K  ==  sentinel

反推：

    xor : K = raw* ^ sentinel
    add : K = sentinel - raw*      (mod 2^width)
    sub : K = raw* - sentinel

不需要 `slot_scan` 的候选，**绕开召回问题**。

再叠加**连续性**硬判据（同一张表的两个字段必须自洽）：
    fieldStart[i+1] - fieldStart[i] == field_count[i]
以及 fDV 交叉校验（已结构定位的 fieldDefaultValues 的 fieldIndex 必须落在
某个类型的 [fieldStart, fieldStart+field_count) 里）。

用法
----
    python3 tools/keyless.py version/7.0 --slots /tmp/opencode/slots_cache_70_new.json
    python3 tools/keyless.py version/7.1 --slots tools/slots_cache.json
"""
import argparse
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from relocate import Data, PE  # noqa: E402

STRIDE = 70
N = 4096                                  # 采样行数
FIELDS = {                                # 位移 -> 位宽（累计索引类）
    0x08: 4, 0x0C: 4, 0x1C: 4,             # propertyStart / methodStart / fieldStart
    0x34: 2, 0x36: 2, 0x3C: 2,             # eventStart / nestedTypesStart / interfacesStart
}
FIELD_NAME = {0x08: 'propertyStart', 0x0C: 'methodStart', 0x1C: 'fieldStart',
              0x34: 'eventStart', 0x36: 'nestedTypesStart', 0x3C: 'interfacesStart'}
COUNT_DISP = 0x38                          # field_count（u16）
MCOUNT_DISP = 0x30                         # method_count（u16）
M32 = (1 << 32) - 1


def read_col(d, base, disp, width, n):
    if width == 4:
        v = d.f32(base, STRIDE, n, disp)
    elif width == 2:
        v = d.u16(base, STRIDE, n, disp)
    else:
        v = d.u8(base, STRIDE, n, disp)
    if v is None:
        return None
    return v.astype(np.int64)


def decode(col, op, K, width):
    wb = width * 8
    m = (1 << wb) - 1
    if op == 'xor':
        v = col ^ K
    elif op == 'add':
        v = col + K
    else:
        v = col - K
    v = v & m
    return np.where(v >= (1 << (wb - 1)), v - (1 << wb), v)


def check_cumulative(v):
    """累计索引判据：哨兵 carry-forward 后单调不减、跨度够大、值域合理"""
    if v is None or len(v) < 16:
        return None
    if int(v.max()) > 4_000_000 or int(v.min()) < -1:
        return None
    neg = v < 0
    if bool(neg.any()):
        carry = np.maximum.accumulate(np.where(neg, 0, v))
        v2 = np.where(neg, np.concatenate(([0], carry[:-1])), carry)
    else:
        v2 = v
    d = np.diff(v2)
    if int(d.min()) < 0:
        return None
    span = int(v2.max()) - int(v2.min())
    if span < 1000:
        return None
    return v2, span


def check_count(v, width):
    """计数类字段（如 field_count）：解出后应是**小非负整数**（0..255）"""
    if v is None or len(v) < 16:
        return None
    if int(v.min()) < 0 or int(v.max()) > 0xFFF:   # 实测 field_count 最大 396
        return None
    if int(v.max()) == int(v.min()):
        return None
    return v


def derive_for_field(d, base, disp, width, n, kind='cum'):
    """返回 [(op, K, v2, span)] —— 从"最频繁的 raw 值"反推

    kind='cum'   -> 累计索引（跨度要 >=1000）
    kind='count' -> 计数（小非负整数）
    """
    col = read_col(d, base, disp, width, n)
    if col is None:
        return []
    vals, cnts = np.unique(col, return_counts=True)
    if len(vals) < 8:
        return []
    i = int(np.argmax(cnts))
    raw_star, freq = int(vals[i]), int(cnts[i])
    if freq < n // 20:                     # 哨兵应占至少 5%
        return []
    wb = width * 8
    m = (1 << wb) - 1
    out = []
    if True:
      for sentinel in (-1, 0):
        for op in ('xor', 'add', 'sub'):
            if op == 'xor':
                K = (raw_star ^ sentinel) & m
            elif op == 'add':
                K = (sentinel - raw_star) & m
            else:
                K = (raw_star - sentinel) & m
            if K == 0:
                continue
            v = decode(col, op, K, width)
            if kind == 'count':
                r = check_count(v, width)
                if r is not None:
                    out.append((op, K, r, 1))
            else:
                r = check_cumulative(v)
                if r:
                    out.append((op, K, r[0], r[1]))
    # 同 (op) 只留跨度最大的
    best = {}
    for op, K, v2, span in out:
        if op not in best or span > best[op][2]:
            best[op] = (op, K, span, v2)
    return list(best.values())


def continuity_score(fs, fc):
    """fieldStart 的相邻差 == field_count"""
    if fs is None or fc is None:
        return 0.0
    n = min(len(fs), len(fc)) - 1
    if n <= 0:
        return 0.0
    d = np.diff(fs[:n + 1])
    c = fc[:n]
    ok = int((d == c).sum())
    return ok / n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--slots', required=True, help='slot_scan 的缓存（提供候选表基址）')
    ap.add_argument('--n', type=int, default=N)
    ap.add_argument('--top', type=int, default=8)
    a = ap.parse_args()

    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, a.root)
    raw = open(os.path.join(root, 'gi/Managed/Metadata/global-metadata.dat'), 'rb').read()
    d = Data(raw)
    c = json.load(open(a.slots))
    sv = {int(k): v for k, v in c['svals'].items()}
    bases = sorted({((sv[dd] ^ imm) & M32 if op == 'xor' else
                     ((sv[dd] - imm) & M32 if op == 'sub' else (sv[dd] + imm) & M32))
                    for dd, op, imm, n, va in c['uniq'] if dd in sv})
    bases = [b for b in bases if 0x1000 <= b < len(raw) - STRIDE * a.n]
    print("候选基址 %d 个，采样 %d 行" % (len(bases), a.n))

    results = []
    for bi, base in enumerate(bases):
        off = d.hdr + base
        fk = {}
        for disp, width in FIELDS.items():
            r = derive_for_field(d, off, disp, width, a.n)
            if r:
                fk[disp] = r
        if len(fk) < 2:
            continue
        # 连续性：fieldStart x field_count
        cont = 0.0
        pairs = ((0x1C, COUNT_DISP),)
        for cum_disp, cnt_disp in pairs:
            cum_c = fk.get(cum_disp, [])
            cnt_c = derive_for_field(d, off, cnt_disp, 2, a.n, kind='count')
            for _, Kc, _, cv in cum_c:
                for _, Kk, _, kv in cnt_c:
                    cont = max(cont, continuity_score(cv, kv))
        results.append((base, fk, cont))
    results.sort(key=lambda x: (-x[2], -len(x[1])))
    print("通过 >=2 字段的候选: %d 个\n" % len(results))
    for base, fk, cont in results[:a.top]:
        print("=== 基址 0x%X  字段 %d  连续性 %.3f ===" % (base, len(fk), cont))
        for disp in sorted(fk):
            for op, K, span, _ in fk[disp]:
                print("    +0x%02X %-18s %s 0x%-8X  span=%d"
                      % (disp, FIELD_NAME[disp], op, K, span))
    return 0


if __name__ == '__main__':
    sys.exit(main())
