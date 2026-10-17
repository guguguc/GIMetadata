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


def derive_for_field(d, base, disp, width, n, kind='cum', topk=1):
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
    order = np.argsort(-cnts)[:max(1, topk)]
    cands = [(int(vals[i]), int(cnts[i])) for i in order if int(cnts[i]) >= n // 50]
    if not cands:
        return []
    wb = width * 8
    m = (1 << wb) - 1
    out = []
    for raw_star, freq in cands:
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


def continuity_score(fs, fc, min_rows=100):
    """fieldStart 的相邻差 == field_count —— **只在 count>0 的行上统计**

    ⚠️ 若两边大量是哨兵/0，`diff==count` 会**平凡成立**（实测 0.99 的假阳性）。
    所以必须限定在 count>0 的行，且要求这种行足够多。
    """
    if fs is None or fc is None:
        return 0.0
    n = min(len(fs), len(fc)) - 1
    if n <= 0:
        return 0.0
    d = np.diff(fs[:n + 1])
    c = fc[:n]
    mask = c > 0
    if int(mask.sum()) < min_rows:
        return 0.0
    ok = int(((d == c) & mask).sum())
    return ok / int(mask.sum())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--slots', required=True, help='slot_scan 的缓存（提供候选表基址）')
    ap.add_argument('--n', type=int, default=N)
    ap.add_argument('--top', type=int, default=8)
    ap.add_argument('--base', default=None, help='直接指定基址（十六进制），跳过搜索')
    ap.add_argument('--all-disps', action='store_true',
                    help='不知道字段布局时：扫 0x00..0x60 所有位移，并做 (累计,计数) 配对')
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

    if a.base:
        bases = [int(a.base, 16)]
        print("直接指定基址 0x%X" % bases[0])
    results = []
    for bi, base in enumerate(bases):
        off = d.hdr + base
        fk = {}
        for disp, width in FIELDS.items():
            r = derive_for_field(d, off, disp, width, a.n)
            if r:
                fk[disp] = r
        if len(fk) < 2 and not a.base:
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
    if a.all_disps and results:
        base0 = results[0][0]
        off0 = d.hdr + base0
        print("=== [--all-disps] 基址 0x%X：所有能解出累计索引的位移 ===" % base0)
        cums, cnts = [], []
        for disp in range(0x00, 0x61):
            for w in (4, 2):
                if disp % w:
                    continue
                for op, K, span, v in derive_for_field(d, off0, disp, w, a.n):
                    cums.append((disp, w, op, K, span, v))
            for w in (1, 2):
                if disp % w:
                    continue
                for op, K, _, v in derive_for_field(d, off0, disp, w, a.n, kind='count'):
                    cnts.append((disp, w, op, K, v))
        for disp, w, op, K, span, _ in sorted(cums):
            print("  +0x%02X w=%d %-4s 0x%-9X span=%d" % (disp, w, op, K, span))
        pairs = []
        for dc, wc, oc, kc, sp, vc in cums:
            for dk, wk, ok_, kk, vk in cnts:
                if dc == dk:
                    continue
                sc = continuity_score(vc, vk)
                if sc > 0.3:
                    pairs.append((round(sc, 3), dc, wc, oc, kc, sp, dk, wk, ok_, kk))
        pairs.sort(reverse=True)
        print("\n  (累计,计数) 配对（连续性 >0.3）:")
        for r in pairs[:10]:
            print("    %.3f  累计 +0x%02X(w%d) %-4s 0x%-9X span=%-6d  计数 +0x%02X(w%d) %-4s 0x%X" % r)
        print()
    for base, fk, cont in results[:a.top]:
        print("=== 基址 0x%X  字段 %d  连续性 %.3f ===" % (base, len(fk), cont))
        for disp in sorted(fk):
            for op, K, span, _ in fk[disp]:
                print("    +0x%02X %-18s %s 0x%-8X  span=%d"
                      % (disp, FIELD_NAME[disp], op, K, span))
    return 0


if __name__ == '__main__':
    sys.exit(main())


# ============================================================================
#  供 relocate.py 调用：无密钥定位 typeDefinitions
# ============================================================================
def _decode_full(d, base, disp, w, op, K, n):
    col = read_col(d, base, disp, w, n)
    if col is None:
        return None
    return decode(col, op, K, w)


def validate_full(d, off, disp, w, op, K, n=88902, kind='cum'):
    """**全表**校验（`off` 是**文件偏移** = d.hdr + 表偏移）"""
    v = _decode_full(d, off, disp, w, op, K, n)
    if v is None:
        return None
    if kind == 'count':
        return v if (int(v.min()) >= 0 and int(v.max()) <= 0xFFF) else None
    if int(v.min()) < -1 or int(v.max()) > 6_000_000:
        return None
    neg = v < 0
    if bool(neg.any()):
        carry = np.maximum.accumulate(np.where(neg, 0, v))
        v2 = np.where(neg, np.concatenate(([0], carry[:-1])), carry)
    else:
        v2 = v
    if int(np.diff(v2).min()) < 0:
        return None
    return v2


def find_typedefs(d, bases, n=4096, full=88902, layout_search=True,
                  min_cont=0.5, verbose=False):
    """返回 {'base','fields','continuity','validated'} 或 None

    1) 采样：候选基址 × 已知位移 -> 反推 key（哨兵法）
    2) 排序：字段数 + 连续性
    3) 全表校验：不合格就淘汰（**关键**：采样会给出假密钥）
    4) 可选 layout_search：扫 0x00..0x60 所有位移，用全表连续性定布局
    """
    # ---- 采样：给每个候选基址打分（字段数 + 连续性）----
    scored = []
    for base in bases:
        off = d.hdr + base
        fk = {}
        for disp, w in FIELDS.items():
            r = derive_for_field(d, off, disp, w, n)
            if r:
                fk[disp] = r
        if len(fk) < 2:
            continue
        cont = 0.0
        for _, _, _, cv in fk.get(0x1C, []):
            for _, _, _, kv in derive_for_field(d, off, COUNT_DISP, 2, n, kind='count'):
                cont = max(cont, continuity_score(cv, kv))
        # ★ 布局可能变了：用**全位移**采样一遍，取最佳连续性（给基址打分用）
        lcont = cont
        lc, lk = None, None
        if cont < 0.5:
            for dl in range(0x00, 0x61):
                if dl % 2:
                    continue
                for w in (4, 2):
                    if dl % w:
                        continue
                    for _op, _K, _sp, _v in derive_for_field(d, off, dl, w, n):
                        if w == 4:
                            for _op2, _K2, _s2, _v2 in derive_for_field(d, off, dl + 2, 2, n, kind='count'):
                                sc2 = continuity_score(_v, _v2)
                                if sc2 > lcont:
                                    lcont, lc, lk = sc2, dl, dl + 2
        scored.append({'base': base, 'fields': fk, 'continuity': cont,
                       'layout_cont': lcont, 'layout_pair': (lc, lk), 'validated': False})
    if not scored:
        return None
    scored.sort(key=lambda x: (-max(x['continuity'], x.get('layout_cont', 0)), -len(x['fields'])))

    # ---- **以全表校验为准**：按采样分排序，逐个验，第一个通过的就是答案 ----
    best = None
    for cand in scored[:20]:
        base = cand['base']
        off = d.hdr + base
        # 采样级布局搜索（布局可能变了：已知位移不可信）
        cums_t, cnts_t = [], []
        for dl in range(0x00, 0x61):
            for w in (4, 2):
                if dl % w:
                    continue
                for op, K, sp, v in derive_for_field(d, off, dl, w, n):
                    cums_t.append((dl, w, op, K, v))
            for w in (1, 2):
                if dl % w:
                    continue
                for op, K, _sp, v in derive_for_field(d, off, dl, w, n, kind='count'):
                    cnts_t.append((dl, w, op, K, v))
        pairs_t = []
        for dc, wc, oc, kc, vc in cums_t:
            for dk, wk, ok_, kk, vk in cnts_t:
                if dc == dk:
                    continue
                sc2 = continuity_score(vc, vk)
                if sc2 >= 0.75:
                    pairs_t.append((sc2, dc, wc, oc, kc, dk, wk, ok_, kk))
        pairs_t.sort(reverse=True)
        for sc2, dc, wc, oc, kc, dk, wk, ok_, kk in pairs_t[:5]:
            if (validate_full(d, off, dc, wc, oc, kc, full, 'cum') is not None and
                    validate_full(d, off, dk, wk, ok_, kk, full, 'count') is not None):
                best = cand
                best['validated'] = True
                best['seed_pair'] = (sc2, dc, wc, oc, kc, dk, wk, ok_, kk)
                break
        if best:
            break
    if best is None:
        best = scored[0]          # 全都过不了 -> 返回采样最优，标记未通过
    base = best['base']

    # ---- 全表校验 + 布局搜索 ----
    base = best['base']
    off = d.hdr + base
    cums, cnts = [], []
    disps = range(0x00, 0x61) if layout_search else FIELDS.keys()
    for disp in disps:
        for w in (4, 2):
            if disp % w:
                continue
            for op, K, _span, _vv in derive_for_field(d, off, disp, w, n):
                v = validate_full(d, off, disp, w, op, K, full, 'cum')
                if v is not None:
                    cums.append((disp, w, op, K, int(v.max()), v))
    for disp in (range(0x00, 0x61) if layout_search else (COUNT_DISP,)):
        for w in (1, 2):
            if disp % w:
                continue
            for op, K, _sp, _vv in derive_for_field(d, off, disp, w, n, kind="count"):
                v = validate_full(d, off, disp, w, op, K, full, 'count')
                if v is not None:
                    cnts.append((disp, w, op, K, v))
    pairs = []
    for dc, wc, oc, kc, mx, vc in cums:
        for dk, wk, ok_, kk, vk in cnts:
            if dc == dk:
                continue
            sc = continuity_score(vc, vk)
            if sc >= min_cont:
                pairs.append((sc, dc, wc, oc, kc, mx, dk, wk, ok_, kk))
    pairs.sort(reverse=True)
    best['pairs'] = pairs[:8]
    best['cums'] = [(dc, wc, oc, kc, mx) for dc, wc, oc, kc, mx, _ in sorted(cums)]
    best['validated'] = bool(pairs)
    return best


def layout_search_fdv(d, base, fdv_off, fdv_idx_disp=8, fdv_n=73818,
                      n=4096, full=88902, topk=8, min_cov=0.999):
    """**布局自动识别**：`(累计,计数)` 配对必须**全表铺满** + fDV 覆盖率裁决。

    ⚠️ **不能用"单调"**：7.0 的 typeDef 是**乱序**的，单调会误杀真布局。
    正确判据是「所有类型的 [start,start+count) 恰好拼成 [0, N)」。
    """
    import struct
    off = d.hdr + base
    cums, cnts = [], []
    for disp in range(0x00, 0x61):
        for w in (4, 2):
            if disp % w:
                continue
            for op, K, _sp, _v in derive_for_field(d, off, disp, w, n, topk=topk):
                cums.append((disp, w, op, K))
        for w in (1, 2):
            if disp % w:
                continue
            for op, K, _sp, _v in derive_for_field(d, off, disp, w, n, kind='count', topk=topk):
                cnts.append((disp, w, op, K))
    fidx = sorted({struct.unpack_from('<i', d.raw, fdv_off + 12 * i + fdv_idx_disp)[0]
                   for i in range(fdv_n)} - {-1})

    def cov_of(fs, fc):
        if not fidx:
            return 1.0
        N = int(max(int(fs[fs >= 0].max(initial=0)) + int(fc.max(initial=0)) + 8, 16))
        covered = np.zeros(N, dtype=bool)
        for s, c in zip(fs.tolist(), fc.tolist()):
            if c > 0 and 0 <= s < N:
                covered[s:min(s + c, N)] = True
        arr = np.array(fidx, dtype=np.int64)
        arr = arr[arr < N]
        return float(covered[arr].mean()) if len(arr) else 1.0

    pairs = []
    for dc, wc, oc, kc in cums:
        for dk, wk, ok_, kk in cnts:
            if dc == dk:
                continue
            fs = _decode_full(d, off, dc, wc, oc, kc, full)
            fc = _decode_full(d, off, dk, wk, ok_, kk, full)
            if fs is None or fc is None:
                continue
            tot = ranges_tile(fs, fc)          # ★ 铺满（全表）
            if tot is None:
                continue
            c = cov_of(fs, fc)
            if c >= min_cov:
                pairs.append((round(c, 5), tot, dc, wc, oc, kc, dk, wk, ok_, kk))
    pairs.sort(key=lambda x: (-x[0], -x[1]))
    return {'cums': cums, 'cnts': cnts, 'pairs': pairs}


def ranges_tile(fs, fc, maxn=3_000_000):
    """**区间铺满**判据：所有类型的 [start, start+count) 必须恰好拼成 [0, N)

    比"单调"强得多，而且**不要求类型按 start 排序**（7.0 实测是乱序的）。
    """
    if fs is None or fc is None:
        return None
    segs = sorted((int(s), int(s) + int(c)) for s, c in zip(fs.tolist(), fc.tolist())
                  if c > 0 and s >= 0)
    if not segs:
        return None
    cur = 0
    for a, b in segs:
        if a != cur:
            return None
        cur = b
        if cur > maxn:
            return None
    return cur if cur > 0 else None
