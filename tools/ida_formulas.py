#!/usr/bin/env python3
"""ida_formulas.py —— 用「模板匹配」把 `keyFormulas`（43 个系数）自动化。

原理
----
同一套混淆算法每版**结构不变**，只有系数变。所以：

  ① 用**旧版本**的导出 + `version.json`（已知真值），找到每条公式对应的
     Hex-Rays 文本行（按"包含该公式的已知系数"定位）；
  ② 把那一行里的**所有数字**替换成 `#`，得到**模板**；
  ③ 在新版本的导出里找**同一个模板**的行 → 按顺序取出数字 → 就是新系数 ✓。

用法
----
    python3 tools/ida_formulas.py --old /tmp/ida71.json --new /tmp/ida70.json \
        --version-json version.json --out /tmp/keyformulas70.json
"""
import argparse
import difflib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

NUM = re.compile(r'0x[0-9A-Fa-f]+|\b\d+\b')


def _windows(lines, func=None, k=6):
    """把同一函数的连续 1..k 行拼起来（7.0 的公式经常被反编译器拆成多行）。"""
    by = {}
    for f in lines:
        if func is not None and f.get('func') != func:
            continue
        by.setdefault(f.get('func'), []).append(f.get('text', ''))
    out = []
    for fn, arr in by.items():
        for i in range(len(arr)):
            t = ''
            for j in range(i, min(i + k, len(arr))):
                t += ' ' + arr[j]
                out.append({'func': fn, 'text': t})
    return out


def K(x):
    return int(x, 0) if isinstance(x, str) else int(x)


def norm(text):
    """归一化：去掉 uLL/LL/u、统一小写、压空白"""
    t = re.sub(r'\b(0x[0-9A-Fa-f]+|\d+)(u?LL|LL|u|U|i64|I64)\b', r'\1', text)
    t = t.replace('0X', '0x').lower()
    t = re.sub(r'\s+', ' ', t).strip()
    return t


def template(text):
    """把数字换成 #，变量名换成 v（跨版本变量名会变），得到可比模板"""
    t = norm(text)
    t = NUM.sub('#', t)
    t = re.sub(r'\b[a-z_]\w*\b', 'v', t)
    return t


def constants(text):
    return [int(x, 0) for x in NUM.findall(norm(text))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--version-json', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    from gen_version import load_json_with_comments as L
    J = L(a.version_json)
    olde = json.load(open(a.old, encoding='utf-8'))
    newe = json.load(open(a.new, encoding='utf-8'))

    old_lines = olde.get('formulas', [])
    new_lines = newe.get('formulas', [])
    print('旧导出 %d 条公式行；新导出 %d 条' % (len(old_lines), len(new_lines)))

    result = {}
    for name, ks in J.get('keyFormulas', {}).items():
        want = set()
        for v in ks.values():
            try:
                want.add(K(v) & 0xFFFFFFFFFFFFFFFF)
            except (TypeError, ValueError):
                pass
        # ① 找"包含最多已知系数"的旧行
        best, best_hit = None, -1
        for f in old_lines:
            cs = {c & 0xFFFFFFFFFFFFFFFF for c in constants(f.get('text', ''))}
            hit = len(want & cs)
            if hit > best_hit:
                best, best_hit = f, hit
        if best is None or best_hit < 2:
            print('  %-22s ✗ 旧导出里找不到（命中 %d 个系数）' % (name, max(best_hit, 0)))
            continue
        tpl = template(best['text'])
        # ② 在新导出里找同模板
        cand = [f for f in new_lines if template(f.get('text', '')) == tpl]
        if len(cand) > 1:
            # 同一模板多行 -> 用**函数名**消歧（公式都在固定的函数里）
            same = [f for f in cand if f.get('func') == best.get('func')]
            if len(same) == 1:
                cand = same
        if len(cand) > 1:
            # 同模板多行：若**常数序列完全相同**（同一公式在不同调用点复用），直接采信 ✓
            seqs = {tuple(constants(f.get('text', ''))) for f in cand}
            if len(seqs) == 1:
                cs = list(next(iter(seqs)))
                print('  %-22s ✓ 同模板 %d 行但常数一致，采信: %s'
                      % (name, len(cand), [hex(c) for c in cs]))
                result[name] = [('0x%X' % c) for c in cs]
                continue
        if len(cand) != 1:
            # 多行拼接兜底：跨版本时反编译器常把公式拆成多行 ✗
            bestw, bestr = None, 0.0
            for w in _windows(new_lines, best.get('func'), k=6):
                r = difflib.SequenceMatcher(None, tpl, template(w['text'])).ratio()
                if r > bestr:
                    bestr, bestw = r, w
            if bestw is not None and bestr >= 0.95:
                cs = constants(bestw['text'])
                print('  %-22s ✓ 多行拼接(%.2f)，取到 %d 个常数: %s'
                      % (name, bestr, len(cs), [hex(c) for c in cs]))
                result[name] = [('0x%X' % c) for c in cs]
                continue
            print('  %-22s ✗ 新导出同模板行 %d 个（模糊最优 %.2f）' % (name, len(cand), bestr))
            continue
        cs = constants(cand[0]['text'])
        print('  %-22s ✓ 模板命中，取到 %d 个常数: %s' % (name, len(cs), [hex(c) for c in cs]))
        result[name] = [('0x%X' % c) for c in cs]

    if a.out:
        json.dump(result, open(a.out, 'w'), ensure_ascii=False, indent=1)
        print('\n已写 %s' % a.out)
    print('\n自动恢复 %d / %d 个公式' % (len(result), len(J.get('keyFormulas', {}))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
