#!/usr/bin/env python3
"""ida_apply.py —— 把 IDA 导出的常量（`ida_export.py` 的产物）**配对**到表名。

思路：
  `ida_export.py` 给出 (slot, op, key, value, funcs)
  `table_funcs.json` 给出 (函数 -> 该函数读哪些表)
  两者相交 -> 候选；再用已自动检测到的值（relocate ④/⑧）和计数公式消歧。

用法：
    python3 tools/ida_apply.py /tmp/ida_export.json \
        --detected /tmp/detected.json --out /tmp/tables.json

  `--detected` 形如 {"fieldsOffset": "0x8D07B4", ...}（relocate 输出里摘出来即可）
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(p):
    return json.load(open(p, encoding='utf-8'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('export')
    ap.add_argument('--funcs', default=os.path.join(HERE, 'table_funcs.json'))
    ap.add_argument('--detected', default=None)
    ap.add_argument('--hits', default=None, help='sig.py scan --json（地址 -> 名字），用于补名字')
    ap.add_argument('--version-json', default=os.path.join(os.path.dirname(HERE), 'version.json'),
                    help='用它的 tables[].stride 做消歧（步长跨版本稳定）')
    ap.add_argument('--order', default=None,
                    help='旧版本的 ida_export.json：从它**学**函数内读取顺序，再套到新版本')
    ap.add_argument('--allow-guess', action='store_true',
                    help='允许"只剩一个候选就采用"（默认关：实测会张冠李戴 ✗）')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    exp = load(a.export)
    fmap = load(a.funcs)
    detected = {}
    if a.detected and os.path.exists(a.detected):
        detected = {k: int(v, 0) if isinstance(v, str) else int(v)
                    for k, v in load(a.detected).items()}

    # 地址 -> 名字（IDA 只有 sub_xxx，用 sig 命中表补上我们的名字）
    ea2name = {}
    if a.hits and os.path.exists(a.hits):
        for nm, va in load(a.hits).get('hits', {}).items():
            ea2name[int(va, 16) if isinstance(va, str) else int(va)] = nm

    def resolve(t):
        names = list(t.get('funcs', []))
        for e in t.get('func_eas', []):
            try:
                va = int(e, 16)
            except Exception:
                continue
            if va in ea2name:
                names.append(ea2name[va])
        return sorted(set(names))

    # 每张表的期望步长（跨版本稳定）。IDA 导出里带了 strides/callees。
    stride_of = {}
    try:
        from gen_version import load_json_with_comments as _L
        _J = _L(a.version_json)
        for k, cfg in _J.get('tables', {}).items():
            if cfg.get('stride'):
                stride_of[k] = cfg['stride']
    except Exception as e:
        print('⚠ 读 version.json 的 stride 失败:', e)

    def fits_stride(name, c):
        st = stride_of.get(name)
        if not st:
            return None                       # 未知 -> 不参与判断
        return st in (c.get('strides') or [])

    def value_divisible(name, c):
        """count 表：value 必须能被步长整除"""
        if not name.lower().endswith('count'):
            return None
        st = stride_of.get(name)
        if not st or not c.get('value'):
            return None
        try:
            return int(c['value'], 16) % st == 0
        except Exception:
            return None

    # ---- 从旧版本**学**「函数内读取顺序」----
    # 前提：源码里读表的先后是稳定的（跨版本）—— 未验证 ✗，但机制已就绪
    learned = {}
    if a.order and os.path.exists(a.order):
        olde = load(a.order)
        ofuncs = None
        old_truth = {}
        try:
            from gen_version import load_json_with_comments as _L2
            from relocate import PE as _PE
            _J2 = _L2(a.version_json)
            _mhy = None
            for k, v in _J2.get('addresses', {}).items():
                if 'mhy' in k.lower():
                    _mhy = int(v, 0)
            _pe = _PE(os.path.join(os.path.dirname(HERE), 'version/7.1', 'gi.exe')) \
                if '7.1' in a.version_json or True else None
            if _mhy and _pe:
                M32 = (1 << 32) - 1
                for nm, cfg in _J2.get('tables', {}).items():
                    if 'slot' not in cfg or not cfg.get('stride'):
                        continue
                    raw = _pe.u32(_mhy + int(cfg['slot'], 0))
                    key = int(cfg['key'], 0) if isinstance(cfg['key'], str) else cfg['key']
                    op = cfg['op']
                    val = ((raw - key) & M32) if op == '-' else (((raw ^ key) & M32) if op == '^' else (raw + key) & M32)
                    old_truth[val] = nm
        except Exception as e:
            print('⚠ 学习顺序失败:', e)
        if old_truth:
            byf = {}
            for t in olde.get('tables', []):
                v = t.get('value')
                nm = old_truth.get(int(v, 16)) if v else None
                # ★ 保留 None 占位！跳过会让"新导出"的位置整体偏移 ✗
                for fn in set(t.get('funcs') or []):      # ★ 去重！否则同一条目被加两次 -> 位置翻倍
                    byf.setdefault(fn, []).append((t.get('seq', 0), nm))
            for fn, rows in byf.items():
                rows.sort()
                learned[fn] = [nm for _, nm in rows]
            print('学到 %d 个函数的读取顺序（%d 张表）'
                  % (len(learned), sum(len(v) for v in learned.values())))

    tables = exp.get('tables', [])
    print('IDA 导出：%d 个 (slot,op,key)，MHY 全局 = %s' % (len(tables), exp.get('mhy_global')))

    # ---- 1) 按「函数 -> 表」建候选 ----
    by_table = {}
    for t in tables:
        for fn in resolve(t):
            for name in fmap.get(fn, []):
                by_table.setdefault(name, []).append(t)

    # ---- 2) 消歧（**一对一**：一个候选只能给一张表）----
    result, unresolved = {}, {}
    used = set()

    # ★ 按「学到的函数内顺序」逐位分配（最可能正确的自动方式）
    if learned:
        for t in tables:
            for fn in set(t.get('funcs') or []):
                names = learned.get(fn)
                if not names:
                    continue
                # 该函数导出的所有条目按 seq 排序
                sibs = sorted([x for x in tables if fn in set(x.get('funcs') or [])],
                              key=lambda x: x.get('seq', 0))
                i = sibs.index(t)
                if i < len(names):
                    nm = names[i]
                    k = (t['slot'], t['op'], t['key'])
                    if nm and nm not in result and k not in used:
                        t['how'] = 'order-match(学自旧版顺序)'
                        result[nm] = t
                        used.add(k)

    def key_of(c):
        return (c['slot'], c['op'], c['key'])

    # 2a) 先用 --detected 做精确 value 匹配（最硬，允许同值不同表：按 stride/名字再分）
    for name in sorted(by_table):
        if name not in detected:
            continue
        hit = [c for c in by_table[name]
               if c.get('value') and int(c['value'], 16) == detected[name]]
        if len(hit) == 1:
            hit[0]['how'] = 'value-match(最强)'
            result[name] = hit[0]
            used.add(key_of(hit[0]))

    # 2b) 单候选 + 未被占用
    for name, cands in sorted(by_table.items()):
        if name in result:
            continue
        uniq = {(c['slot'], c['op'], c['key']): c for c in cands}
        free = {k: c for k, c in uniq.items() if k not in used}
        # ★ 步长消歧（跨版本稳定）：只留 stride 对得上的
        by_stride = {k: c for k, c in free.items() if fits_stride(name, c) is not False}
        if by_stride and len(by_stride) < len(free):
            free = by_stride
            for c in free.values():
                c.setdefault('how', 'stride-match')
        # ★ count 表：再要求 value 能被步长整除
        by_div = {k: c for k, c in free.items() if value_divisible(name, c) is not False}
        if by_div and len(by_div) < len(free):
            free = by_div
        if len(free) == 1 and a.allow_guess:
            c = list(free.values())[0]
            c['how'] = 'single-candidate(猜)'
            result[name] = c
            used.add(key_of(c))
        elif len(free) == 1:
            unresolved[name] = list(free.values())   # 有且仅有一个候选 -> 仍然只是**候选**
        else:
            unresolved[name] = list(free.values()) if free else list(uniq.values())

    print('\n=== 已确定 %d 张表 ===' % len(result))
    for name, t in sorted(result.items()):
        print('  %-42s slot %-6s %s %-12s -> %-10s  [%s]  (%s)'
              % (name, t['slot'], t['op'], t['key'], t.get('value'),
                 t.get('how', '?'), ','.join(resolve(t)[:2])))

    if unresolved:
        print('\n=== 需要消歧 %d 张（同一函数读了多张表）===' % len(unresolved))
        for name, cands in sorted(unresolved.items()):
            print('  %s:' % name)
            for c in cands[:6]:
                print('     slot %-6s %s %-12s value=%-10s  (%s)'
                      % (c['slot'], c['op'], c['key'], c.get('value'),
                         ','.join(resolve(c)[:2])))

    frag = {'tables': {k: {'slot': v['slot'], 'op': v['op'], 'key': v['key']}
                       for k, v in result.items()}}
    if a.out:
        json.dump(frag, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('⚠ 这些只是**建议**：必须用 relocate / verify.py 复核（见 UPDATE §5.12.6）')
        print('\n已写 %s' % a.out)
    print('\n可直接填 version.json 的片段（%d 项）:' % len(result))
    print(json.dumps(frag, ensure_ascii=False, indent=1)[:1200])


if __name__ == '__main__':
    sys.exit(main())
