#!/usr/bin/env python3
"""keyformulas_auto.py —— 从目标版本反编译文本恢复 keyFormulas。

输入只依赖：
  · 上一版 version.json（公式名字/签名模板）
  · 目标 ida_export.py 的 JSON（formulas 文本）
  · formula_auto.py 的已验证结果（可选；没有就只做形状提取）

输出：
  version/<ver>/ida/keyformulas.auto.json
格式与 version.json 的 keyFormulas 一致，可直接被 update.py 合并。

设计原则：
  · 不硬编码目标版本的 slot/表名/常数；
  · 公式常数全部从目标反编译表达式里读；
  · 表达式里的每个整数都变成 k<Formula>C<n> 常量，cpp 原样复用，
    因此生成出的 C++ 与反编译表达式等价。
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_version import load_json_with_comments  # noqa: E402

NUMTOK = re.compile(r'0x[0-9A-Fa-f]+|\b\d+\b')
IDENT = re.compile(r'\b[A-Za-z_]\w*\b')
CASTS = re.compile(
    r'\(\s*(?:(?:unsigned|signed|const)\s+)*(?:__int(?:8|16|32|64)|_?(?:QWORD|DWORD|WORD|BYTE)|'
    r'int|char|short|long|float|double|void|size_t|u?int(?:8|16|32|64)_t)\s*\**\s*\)')


def clean_expr(t, var='i'):
    """把一行反编译表达式变成只含 var/常量/运算符的 Python 表达式。"""
    t = re.sub(r'^\s*\w+\s*=\s*', '', t.strip())
    t = re.sub(r'^\s*[\^*+]+?\s*', '', t)
    t = CASTS.sub('', t)
    t = re.sub(r'(?<=[0-9A-Fa-f])(?:[uU]?(?:LL|ll))\b', '', t)
    t = re.sub(r'(?<=[0-9A-Fa-f])(?:i64|I64)\b', '', t)
    t = t.replace('__ROL8__', 'ROL8').replace('__ROR8__', 'ROR8')
    t = re.sub(r'\b(unsigned|signed|const)\b', '', t)
    ids = [x for x in IDENT.findall(t) if x not in ('ROL8', 'ROR8')]
    if not ids:
        return None
    if len(set(ids)) != 1:
        return None
    src = ids[0]
    t = re.sub(r'\b%s\b' % re.escape(src), var, t)
    # 平衡括号（反编译经常把表达式拆成多行）
    while t.count(')') > t.count('('):
        i = t.rfind(')')
        t = t[:i] + t[i + 1:]
    while t.count('(') > t.count(')'):
        i = t.rfind('(')
        t = t[:i] + t[i + 1:]
    if not re.fullmatch(r'[\s0-9a-fA-FxX+\-*/%^&|<>~()i]+', t):
        return None
    try:
        compile(t, '<expr>', 'eval')
    except Exception:
        return None
    return t


def load_formulas(ida_path, decomp_dir):
    """返回 [(func, text)]；ida.json 和 decomp/*.c 合并去重。"""
    out = []
    if ida_path and os.path.exists(ida_path):
        J = json.load(open(ida_path, encoding='utf-8'))
        for r in J.get('formulas', []):
            out.append((r.get('func', ''), r.get('text', '')))
    if decomp_dir and os.path.isdir(decomp_dir):
        for p in sorted(glob.glob(os.path.join(decomp_dir, '*.c'))):
            fn = re.sub(r'_[0-9A-Fa-f]{6,}$', '', os.path.basename(p)[:-2])
            for line in open(p, encoding='utf-8', errors='ignore'):
                out.append((fn, line.rstrip('\n')))
    # 去重但保持顺序
    seen = set(); uniq = []
    for fn, tx in out:
        k = (fn, tx.strip())
        if k in seen:
            continue
        seen.add(k); uniq.append((fn, tx))
    return uniq


def expressions(funcs, lines, max_join=12):
    """从函数文本里抽取可解析表达式，返回 [(raw, expr)]，长表达式优先。"""
    res = []
    for fn in funcs:
        idx = [i for i, (f, _) in enumerate(lines) if f == fn]
        for i in idx:
            t = re.sub(r'^\s*\w+\s*=\s*', '', lines[i][1].strip())
            t = re.sub(r'^\s*[\^*+]+?\s*', '', t)
            for j in range(i, min(i + max_join, len(lines))):
                if j > i:
                    t += ' ' + lines[j][1].strip()
                if not ('*' in t or '>>' in t or '^' in t):
                    continue
                e = clean_expr(t)
                if e:
                    res.append((t.strip(), e))
    # 去掉前缀重复
    seen = set(); uniq = []
    for raw, expr in sorted(res, key=lambda x: (len(x[1]), len(x[0])), reverse=True):
        if expr in seen:
            continue
        seen.add(expr); uniq.append((raw, expr))
    return uniq


def pick(exprs, needle_re):
    """按表达式原文的正则挑选最匹配的一条。"""
    for raw, expr in exprs:
        if re.search(needle_re, raw):
            return raw, expr
    return None


def literal_params(expr, name):
    """把表达式里的整数都提成参数，生成 cpp。"""
    lits = []
    for tok in NUMTOK.findall(expr):
        v = int(tok, 0)
        if v not in lits:
            lits.append(v)
    # 用最长优先替换，避免 16 命中 0x... 内部
    mapping = {}
    for i, v in enumerate(lits):
        mapping.setdefault(v, 'c%d' % i)
    def repl(m):
        v = int(m.group(0), 0)
        return 'k%s%s' % (name[:1].upper() + name[1:], mapping[v][:1].upper() + mapping[v][1:])
    cpp_expr = NUMTOK.sub(repl, expr)
    params = {}
    for i, v in enumerate(lits):
        params['c%d' % i] = v
    return params, cpp_expr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root', help='version/7.0 或 7.0')
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'))
    ap.add_argument('--ida', default=None)
    ap.add_argument('--decomp', default=None)
    ap.add_argument('--validated', default=None, help='formula_auto.py 的输出（可选）')
    ap.add_argument('--values', default=None, help='keyformulas.values.json（反编译缓存，可选）')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    root = a.root if os.path.isabs(a.root) else os.path.join(ROOT, 'version', a.root)
    if not os.path.isdir(root):
        root = a.root
    base = load_json_with_comments(a.base)
    ida = a.ida or os.path.join(root, 'ida.json')
    dec = a.decomp or os.path.join(root, 'ida', 'decomp')
    out = a.out or os.path.join(root, 'ida', 'keyformulas.auto.json')

    lines = load_formulas(ida, dec)
    val = {}
    if a.validated and os.path.exists(a.validated):
        val = json.load(open(a.validated, encoding='utf-8'))
    values = {}
    vp = a.values or os.path.join(root, 'ida', 'keyformulas.values.json')
    if os.path.exists(vp):
        try:
            values = json.load(open(vp, encoding='utf-8')).get('formulas', {})
        except Exception:
            values = {}

    # 公式 -> 目标函数（从上一版的 formula 文本里学）
    old_lines = load_formulas(os.path.join(ROOT, 'version', '7.1', 'ida.json'), None)
    func_map = {}
    for name, f in base.get('keyFormulas', {}).items():
        cs = []
        for k, v in f.items():
            if k in ('sig', 'cpp'):
                continue
            try:
                cs.append(int(str(v), 0))
            except Exception:
                pass
        cs = [x for x in cs if abs(x) > 256]
        best = None
        for fn, tx in old_lines:
            hit = sum(1 for x in cs if (str(x) in tx or hex(x & 0xFFFFFFFF)[2:] in tx.lower()))
            if hit >= max(2, len(cs) - 1):
                best = (hit, fn)
                break
        if best:
            func_map[name] = best[1]
    # values.json 自带 func 时直接使用（不依赖上一版公式常量）
    for name, v in values.items():
        if name not in func_map and v.get('func'):
            func_map[name] = v['func']
    # 目标版本里同一函数
    for name, fn in list(func_map.items()):
        names = [f for f, _ in lines if f == fn]
        if not names:
            func_map.pop(name, None)
    print('函数映射:', func_map)

    # 额外公式（上一版没有）：从语义函数里按形状找
    extra_specs = {
        'methodParamKey': ('GIMeta_SetupMethodsLocked', r'1147050388.*0x9EF8D46961E5672'),
        'eventAccessorKey': ('GIMeta_SetupEventsLocked', r'12735.*0x7723.*16191'),
    }

    result = {}
    report = []
    for name, fn in func_map.items():
        exprs = expressions([fn], lines)
        chosen = None
        v = val.get(name)
        # 人工 values.json 优先于自动形状搜索；这是跨版本人工确认公式的入口。
        if values.get(name) and values[name].get('expr'):
            v = {'expr': values[name]['expr']}
        elif not (v and v.get('expr')) and values.get(name):
            v = {'expr': values[name].get('expr')}
        if v and v.get('expr'):
            # formula_auto 已经用可打印名字验证过，或来自反编译缓存
            e = clean_expr(v['expr'])
            if e:
                chosen = (v['expr'], e)
        if not chosen and exprs:
            # 没有验证结果时，选最长的、常数最多的表达式
            chosen = max(exprs, key=lambda x: (len(NUMTOK.findall(x[0])), len(x[1])))
        if not chosen:
            report.append((name, 'MISS', fn, ''))
            continue
        raw, expr = chosen
        params, cpp_expr = literal_params(expr, name)
        sig = base['keyFormulas'][name].get('sig', 'uint32_t key%s(uint32_t i)' % (name[:1].upper() + name[1:]))
        sig = re.sub(r'\(uint32_t\s+\w+\)', '(uint32_t i)', sig)
        # 角色语义：genericContainerKey 在运行时是 64 位；paramKey 是 32 位。
        if name == 'containerKey':
            sig = 'uint64_t keyContainer(uint32_t c)'
            cpp_expr = re.sub(r'\bi\b', 'c', cpp_expr)
            cpp = 'return %s;' % cpp_expr
        elif name == 'genericParamKey':
            sig = 'uint64_t keyGenericParam(uint32_t p)'
            cpp_expr = re.sub(r'\bi\b', 'p', cpp_expr)
            cpp = 'return %s;' % cpp_expr
        elif name == 'paramKey':
            sig = 'uint32_t keyParam(uint32_t i)'
            cpp = 'return (uint32_t)(%s);' % cpp_expr
        else:
            cpp = 'return (uint32_t)(%s);' % cpp_expr
        result[name] = dict(params)
        result[name]['sig'] = sig
        result[name]['cpp'] = cpp
        report.append((name, 'OK', fn, raw[:100]))

    def set_formula(name, expr, sig, ret):
        e = clean_expr(expr)
        if not e:
            report.append((name, 'MISS', '', ''))
            return
        params, cpp_expr = literal_params(e, name)
        result[name] = dict(params)
        result[name]['sig'] = sig
        result[name]['cpp'] = 'return (%s)(%s);' % (ret, cpp_expr)
        report.append((name, 'OK', '', expr[:100]))

    # fieldKey 需要 indexBias（来自 typeDef.fieldStart 的 sub key）
    # 如果 values.json 已经给了目标版本的完整 expr，就不再套 7.0 的 28430 形状。
    if values.get('fieldKey') and not values['fieldKey'].get('expr'):
        bias = None
        fp = os.path.join(root, 'ida', 'fielddecode.auto.json')
        if os.path.exists(fp):
            try:
                fdd = json.load(open(fp, encoding='utf-8'))
                spec = fdd.get('fieldDecode', {}).get('typeDef', {}).get('fieldStart', '')
                if ':' in spec:
                    bias = int(spec.split(':', 1)[1], 0)
            except Exception:
                pass
        if bias is None:
            bias = int(values['fieldKey'].get('indexBias', 0)) if 'indexBias' in values['fieldKey'] else 0
        # 用目标反编译缓存里的系数
        cs = [int(str(x), 0) for x in values['fieldKey'].get('consts', []) if str(x).lstrip('-').replace('0x','').isalnum()]
        # 直接从 expr 解析：A=28430, add1, xor, B, add2
        m = re.search(r'\((-?\d+) \* \(\(\('"'"'?', values['fieldKey']['expr'])
        # 只有 7.0 的 fieldKey 形状需要 indexBias
        e = values['fieldKey']['expr']
        if '28430*i' in e:
            e = e.replace('28430*i', '28430*(i + %d)' % bias)
            set_formula('fieldKey', e, 'uint32_t keyField(uint32_t i)', 'uint32_t')

    # paramKey：人工 values.json 优先；否则才从 SetupParameters 形状里找。
    if not (values.get('paramKey') and values['paramKey'].get('expr')):
        pexprs = expressions(['GIMeta_SetupParameters'], lines)
        p = None
        for raw, expr in sorted(pexprs, key=lambda x: len(x[1])):
            if raw.count('>>') == 1 and '*' in raw and '+' in raw and '^' not in raw:
                p = (raw, expr); break
        if p:
            set_formula('paramKey', p[0], 'uint64_t keyParam(uint32_t i)', 'uint64_t')

    # methodParamKey：只有 values 明确给出时才生成
    if values.get('methodParamKey'):
        set_formula('methodParamKey', values['methodParamKey']['expr'], 'uint32_t keyMethodParam(uint32_t i)', 'uint32_t')

    # containerKey：只有 values 没给时才从 SetupNestedLocked 形状里找
    if not values.get('containerKey'):
        cexprs = expressions(['GIMeta_SetupNestedLocked'], lines)
        for raw, expr in cexprs:
            if re.search(r'\* \(\(\(0x[0-9A-Fa-f]+LL \* .*? >> \d+\) \^ 0x[0-9A-Fa-f]+\)', raw):
                set_formula('containerKey', raw, 'uint32_t keyContainer(uint32_t i)', 'uint32_t'); break

    # imageKey：只有 values 没给时才从 RuntimeInit 的 40 字节 image 表解密前找
    img = None
    if not values.get('imageKey'):
      for i, (fn, tx) in enumerate(lines):
        if fn.startswith('GIMeta_RuntimeInit') and 'GIMeta_DecryptString' in tx and '40 *' in tx:
            for j in range(i, max(i - 10, -1), -1):
                m = re.match(r'\s*\w+\s*=\s*(.*)', lines[j][1])
                if m:
                    e = clean_expr(m.group(1))
                    if e:
                        img = m.group(1); break
            if img:
                break
    if img:
        set_formula('imageKey', img, 'uint32_t keyImage(uint32_t i)', 'uint32_t')

    # eventAccessorKey：人工 values.json 优先；否则从 SetupEventsLocked 文本抓 `((-A * i) ^ X) - S`
    if not (values.get('eventAccessorKey') and values['eventAccessorKey'].get('expr')):
        for name, tx in lines:
            if not name.startswith('GIMeta_SetupEventsLocked'):
                continue
            m = re.search(r'\(\((-?\d+) \* (\w+)\) \^ (0x[0-9A-Fa-f]+)\) - (\d+)', tx)
            if m:
                expr = '((%s * %s) ^ %s) - %s' % (m.group(1), 'i', m.group(3), m.group(4))
                set_formula('eventAccessorKey', expr, 'uint32_t keyEventAccessor(uint32_t i)', 'uint32_t')
                break

    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(result, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('已写', out)
    for name, st, fn, raw in report:
        print('  %-18s %-4s %-34s %s' % (name, st, fn, raw))


if __name__ == '__main__':
    main()
