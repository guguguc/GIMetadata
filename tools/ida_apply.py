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
