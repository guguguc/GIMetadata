#!/usr/bin/env python3
"""通用换版本编排器（以旧 version.json 为唯一基线）。

它不要求目标版本已经有 version.json。流程：
  1. 拷贝上一版 JSON 作为模板；
  2. 跑 relocate.py（结构自证 + 旧 JSON 提示 + 无密钥 typeDefs）；
  3. 读目标版本的 IDA 导出，按 learn_ida_map.py 学到的「函数读取顺序」填表；
  4. 写 version.draft.json 和 update-report.md：
       - 自动定位（可信）
       - IDA 候选（需抽查）
       - 仍用旧值（必须人工/语义 A/B）
       - 旧 slot 提示（默认不可信，7.0 实测 0/16）

用法：
  python3 tools/update.py 7.0 \
      --base version.json \
      --slots version/7.0/slots.json \
      --ida   version/7.0/ida.json

默认只写 version/<ver>/version.draft.json + update-report.md，不改 version.json。
确认后再 --apply。
"""
import argparse
import copy
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, 'tools')
sys.path.insert(0, TOOLS)
from gen_version import load_json_with_comments  # noqa: E402
import sig as S  # noqa: E402

OP_NORM = {'xor': '^', 'add': '+', 'sub': '-'}


def table_value_map(exe, mhy, J):
    pe = S.PE(exe)
    out = {}
    for n, t in J.get('tables', {}).items():
        try:
            slot = int(str(t['slot']), 0)
            raw = int.from_bytes(pe.D[pe.va2off(mhy + slot):pe.va2off(mhy + slot) + 4], 'little')
            key = int(str(t['key']), 0)
            if t['op'] == '^':
                out[n] = raw ^ key
            elif t['op'] == '-':
                out[n] = (raw - key) & 0xFFFFFFFF
            else:
                out[n] = (raw + key) & 0xFFFFFFFF
        except Exception:
            pass
    return out


def load_json(path):
    return load_json_with_comments(path)


def resolve_root(arg):
    if os.path.isdir(arg):
        return os.path.abspath(arg)
    cand = os.path.join(ROOT, 'version', arg)
    if os.path.isdir(cand):
        return cand
    raise SystemExit('target dir not found: %s' % arg)


def resolve_path(p, base=ROOT):
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.join(base, p)


def flatten_json(obj, prefix='', top=True):
    """把嵌套 JSON 压成 path -> leaf，忽略 _update/_origin。"""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if top and k in ('_update', '_origin'):
                continue
            p = '%s.%s' % (prefix, k) if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(flatten_json(v, p, False))
            else:
                out[p] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = '%s[%d]' % (prefix, i)
            if isinstance(v, (dict, list)):
                out.update(flatten_json(v, p, False))
            else:
                out[p] = v
    return out


class Provenance:
    def __init__(self, base, label):
        self.prev = flatten_json(base)
        self.origin = {p: label for p in self.prev}

    def mark(self, draft, source):
        cur = flatten_json(draft)
        for p, v in cur.items():
            if p not in self.prev or self.prev[p] != v:
                self.origin[p] = source
        # 删除的字段不写回 draft；origin 中也不保留不存在的 path
        for p in list(self.origin):
            if p not in cur:
                del self.origin[p]
        self.prev = cur

    def result(self):
        return dict(sorted(self.origin.items()))


def parse_relocate_log(log):
    auto = {}
    # ⑦ 反查：结构自证得到的值 -> 唯一 (slot,op,key)
    for m in re.finditer(
        r'^\s+(\w+)\s+(0x[0-9A-Fa-f]+)\s+->\s+slot\s+(0x[0-9A-Fa-f]+)\s+(xor|add|sub)\s+(0x[0-9A-Fa-f]+)\s+✅',
        log, re.M):
        name, val, slot, op, key = m.groups()
        auto[name] = (int(val, 16), int(slot, 16), OP_NORM[op], int(key, 16))
    # ⑥ 旧 slot 提示：只记录，不当证据
    weak = {}
    for m in re.finditer(
        r'^\s+(\w+)\s+slot\s+(0x[0-9A-Fa-f]+)\s+✅ 唯一 -> (0x[0-9A-Fa-f]+)\s+\[弱证据\]',
        log, re.M):
        weak[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    # ⑧ 无密钥 typeDefs
    base = None
    m = re.search(r'\[⑧ 无密钥\]\s+基址\s+(0x[0-9A-Fa-f]+)', log)
    if m:
        base = int(m.group(1), 16)
    layout = {}
    for name in ('fieldStart', 'fieldCount'):
        m = re.search(name + r'\s+\+0x([0-9A-Fa-f]+)\s+(add|sub|xor)\s+(0x[0-9A-Fa-f]+)', log)
        if m:
            layout[name] = (int(m.group(1), 16), OP_NORM[m.group(2)], int(m.group(3), 16))
    # ① MHY 锚：'MHY\0' -> ['0x...']
    m = re.search(r"'MHY\\0'\s*->\s*\['(0x[0-9A-Fa-f]+)'\]", log)
    mhy = int(m.group(1), 16) if m else None
    return auto, weak, base, layout, mhy


def reverse_slot(slots, value):
    """在 slot_scan 缓存里反查 value 对应的唯一 (slot,op,key)。"""
    if not slots or not os.path.exists(slots):
        return None
    C = json.load(open(slots, encoding='utf-8'))
    sv = {int(k): int(v) for k, v in C.get('svals', {}).items()}
    hits = []
    for ent in C.get('uniq', []):
        slot, op, key = int(ent[0]), OP_NORM.get(ent[1], ent[1]), int(ent[2])
        if slot not in sv:
            continue
        raw = sv[slot]
        if op == '^':
            val = raw ^ key
        elif op == '-':
            val = (raw - key) & 0xFFFFFFFF
        elif op == '+':
            val = (raw + key) & 0xFFFFFFFF
        else:
            continue
        if val == value:
            hits.append((slot, OP_NORM.get(op, op), key))
    uniq = []
    for h in hits:
        if h not in uniq:
            uniq.append(h)
    return uniq[0] if len(uniq) == 1 else None


def apply_ida_map(draft, params, ida_path, map_path, report):
    if not ida_path or not os.path.exists(ida_path) or not os.path.exists(map_path):
        return []
    E = json.load(open(ida_path, encoding='utf-8'))
    M = json.load(open(map_path, encoding='utf-8'))
    funcs = M.get('funcs', {})
    by_func = {}
    for t in E.get('tables', []):
        for f in t.get('funcs', []):
            by_func.setdefault(f, []).append(t)
    filled = []
    for f, names in funcs.items():
        ts = by_func.get(f, [])
        seen = set()
        uniq = []
        for t in sorted(ts, key=lambda x: x.get('seq', 0)):
            k = (t['slot'], t['op'], t['key'])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(t)
        for t, name in zip(uniq, names):
            if not name:
                continue
            slot = int(str(t['slot']), 0)
            op = OP_NORM.get(t['op'], t['op'])
            key = int(str(t['key']), 0)
            if name.startswith('registrationFields.'):
                k = name.split('.', 1)[1]
                if k in draft.get('registrationFields', {}):
                    draft['registrationFields'][k] = '0x%X' % int(str(t['value']), 0)
                    filled.append((name, 'value 0x%X' % int(str(t['value']), 0), f))
                continue
            if name not in draft.get('tables', {}):
                continue
            ent = copy.deepcopy(draft['tables'][name])
            ent['slot'] = '0x%X' % slot
            ent['op'] = op
            ent['key'] = '0x%X' % key
            draft['tables'][name] = ent
            filled.append((name, 'slot 0x%X %s 0x%X' % (slot, op, key), f))
    # 同一张表被多个函数填过：保留第一次，报告里标出重复
    seen = set()
    uniq_filled = []
    for name, what, f in filled:
        if name in seen:
            continue
        seen.add(name)
        uniq_filled.append((name, what, f))
    return uniq_filled


def write_report(path, root, base_path, auto, weak, tdoff, layout, ida_filled, draft, ida_path, slots_path, relocate_log, mhy=None):
    base = load_json(base_path)
    total_tables = sorted(base.get('tables', {}).keys())
    auto_names = set(auto.keys())
    ida_names = {n for n, _, _ in ida_filled if not n.startswith('registrationFields.')}
    reg_names = {n for n, _, _ in ida_filled if n.startswith('registrationFields.')}
    if tdoff:
        auto_names.add('typeDefinitionsOffset')
    remaining = [n for n in total_tables if n not in auto_names and n not in ida_names]
    fd_total = sum(len(v) for v in base.get('fieldDecode', {}).values())
    so_total = sum(len(v) for v in base.get('structOffsets', {}).values())
    ida_fd = 0
    if ida_path and os.path.exists(ida_path):
        try:
            ida_fd = len(json.load(open(ida_path, encoding='utf-8')).get('fieldDecode', []))
        except Exception:
            ida_fd = 0

    L = []
    L.append('# %s 换版本自动化报告' % os.path.basename(root))
    L.append('')
    L.append('- 基线 JSON: `%s`' % os.path.relpath(base_path, ROOT))
    L.append('- 目标目录: `%s`' % os.path.relpath(root, ROOT))
    L.append('- 生成时间: %s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    L.append('- relocate 日志: `%s`' % (relocate_log or '(未保存)'))
    L.append('')
    L.append('## 1. 自动定位（可信）')
    L.append('')
    L.append('| 表 | 值 | 新 slot / op / key |')
    L.append('|---|---:|---|')
    for n, (val, slot, op, key) in sorted(auto.items()):
        L.append('| %s | `0x%X` | `0x%X %s 0x%X` |' % (n, val, slot, op, key))
    if tdoff:
        rev = reverse_slot(slots_path, tdoff)
        if rev:
            L.append('| typeDefinitionsOffset | `0x%X` | `0x%X %s 0x%X`（反查） |' % (tdoff, rev[0], rev[1], rev[2]))
        else:
            L.append('| typeDefinitionsOffset | `0x%X` | 基址已找到，slot 反查不唯一 |' % tdoff)
    if mhy:
        L.append('')
        L.append('MHY 表地址：`0x%X`（relocate ①）' % mhy)
    L.append('')
    if layout:
        L.append('typeDefs 无密钥布局：')
        L.append('')
        for n in ('fieldStart', 'fieldCount'):
            if n in layout:
                disp, op, key = layout[n]
                L.append('- `%s` +0x%X %s 0x%X' % (n, disp, op, key))
        L.append('')
    L.append('## 2. IDA 映射填充（需抽查）')
    L.append('')
    if ida_filled:
        L.append('映射来自 `tools/ida_table_map.json`（函数内读取顺序）。函数改名/优化会改变顺序，必须抽查。')
        L.append('')
        L.append('| 条目 | 新值 | 来源函数 |')
        L.append('|---|---|---|')
        for n, what, f in ida_filled:
            L.append('| %s | `%s` | `%s` |' % (n, what, f))
    else:
        L.append('没有 IDA 导出或没有可映射项。')
    L.append('')
    L.append('## 3. 旧 slot 提示（默认不可信）')
    L.append('')
    if weak:
        L.append('这些只是“旧 slot 在新版本里唯一命中”，**不是结构证据**。7.0 实测 16 个全错。')
        L.append('')
        L.append('| 表 | 旧 slot | 命中值 |')
        L.append('|---|---:|---:|')
        for n, (slot, val) in sorted(weak.items()):
            L.append('| %s | `0x%X` | `0x%X` |' % (n, slot, val))
    else:
        L.append('无。')
    L.append('')
    L.append('## 4. 仍用旧值 / 必须人工')
    L.append('')
    L.append('### 表（%d 张）' % len(remaining))
    L.append('')
    if remaining:
        L.append(', '.join('`%s`' % x for x in remaining))
    else:
        L.append('无')
    L.append('')
    L.append('### 其它')
    L.append('')
    L.append('| 类别 | 条目数 | 状态 |')
    L.append('|---|---:|---|')
    L.append('| `fieldDecode` 字段 | %d | IDA 原始候选 %d 条，需按范围/语义筛选 |' % (fd_total, ida_fd))
    L.append('| `structOffsets` 偏移 | %d | IDA 可提供 disp 候选；7.0 实测 34/43 可出现，仍需确认 |' % so_total)
    L.append('| `keyFormulas` | %d | IDA 公式常量 + semantic_ab.py 选 A/B |' % len(base.get('keyFormulas', {})))
    L.append('| `stringDecrypt` / 字符串 key | 1 | 需用可打印率/名字二次证据 |')
    L.append('| `addresses` MHY/Table0/Table1/CR | 4 | MHY 由 relocate 锚定；其余按注册函数/IDA |')
    L.append('')
    L.append('## 5. 下一步')
    L.append('')
    L.append('```bash')
    L.append('# 没有 slot 缓存时先扫（约 10 分钟）')
    L.append('python3 tools/slot_scan.py %s/gi.exe %s/gi/Managed/Metadata/global-metadata.dat --out %s/slots.json'
             % (os.path.relpath(root, ROOT), os.path.relpath(root, ROOT), os.path.relpath(root, ROOT)))
    L.append('')
    L.append('# 填完人工项后构建/对比')
    L.append('make dump VERSION=%s' % os.path.basename(root))
    L.append('```')
    L.append('')
    L.append('> 草稿：`%s`。它可直接被 `gen_version.py` 读取，但**未填项仍是旧版本的常量**，不要直接发布。'
             % os.path.relpath(draft, ROOT))
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(L) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', help='version/7.0 或 7.0')
    ap.add_argument('--base', default=os.path.join(ROOT, 'version.json'), help='上一版 version.json（默认根 7.1）')
    ap.add_argument('--slots', default=None, help='目标版本的 slot_scan 缓存；默认 <target>/slots.json')
    ap.add_argument('--ida', default=None, help='目标版本的 IDA 导出；默认 <target>/ida.json')
    ap.add_argument('--ida-map', default=os.path.join(TOOLS, 'ida_table_map.json'))
    ap.add_argument('--no-ida-map', action='store_true')
    ap.add_argument('--typeCount', type=int, default=683574)
    ap.add_argument('--emit', default=None)
    ap.add_argument('--report', default=None)
    ap.add_argument('--apply', action='store_true',
                    help='覆盖 <target>/version.json（目标已有 JSON 时默认只写 version.draft.json）')
    ap.add_argument('--check', action='store_true',
                    help='仅最终验证：与目标已有 version.json 对照；默认冷启动不读它')
    ap.add_argument('--no-auto', action='store_true',
                    help='不自动运行 offline_extract/fielddecode_auto/keyformulas_auto/table_roles')
    ap.add_argument('--no-origin', action='store_true',
                    help='不写 _origin（默认写入每个字段的来源）')
    args = ap.parse_args()

    auto_ran = []
    root = resolve_root(args.target)
    base_path = resolve_path(args.base)
    if not os.path.exists(base_path):
        raise SystemExit('base json not found: %s' % base_path)
    slots = resolve_path(args.slots) if args.slots else os.path.join(root, 'slots.json')
    if not os.path.exists(slots):
        slots = None
    ida = resolve_path(args.ida) if args.ida else os.path.join(root, 'ida.json')
    if not os.path.exists(ida):
        ida = None

    # 0) 若存在逐函数反编译文本，先离线补扫 ida.json（IDA 正则会漏 int/变量中转）
    if ida and not args.no_auto and os.path.isdir(os.path.join(root, 'ida', 'decomp')):
        try:
            oe_cmd = [sys.executable, os.path.join(TOOLS, 'offline_extract.py'), root,
                      '--ida', ida, '--ida-map', args.ida_map]
            pr = subprocess.run(oe_cmd, capture_output=True, text=True)
            if pr.returncode == 0:
                auto_ran.append('offline_extract')
            else:
                print('offline_extract failed:', (pr.stdout + pr.stderr)[-500:])
        except Exception as e:
            print('offline_extract failed:', e)

    emit = resolve_path(args.emit) if args.emit else None
    target_json = os.path.join(root, 'version.json')
    had_target = os.path.exists(target_json)
    if not emit:
        # 新版本还没有 version.json 时直接生成它；已有则先写 draft，避免覆盖人工成果。
        if args.apply or not had_target:
            emit = target_json
        else:
            emit = os.path.join(root, 'version.draft.json')
    report = resolve_path(args.report) if args.report else os.path.join(root, 'update-report.md')
    tmp_emit = os.path.join(tempfile.gettempdir(), 'relocate_%s.json' % os.path.basename(root))
    log_path = os.path.join(tempfile.gettempdir(), 'relocate_%s.log' % os.path.basename(root))

    cmd = [sys.executable, os.path.join(TOOLS, 'relocate.py'), root,
           '--hint', base_path, '--typeCount', str(args.typeCount)]
    if slots:
        cmd += ['--slots', slots]
    cmd += ['--emit', tmp_emit]
    print('$', ' '.join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True)
    log = p.stdout + p.stderr
    open(log_path, 'w', encoding='utf-8').write(log)
    if p.returncode != 0:
        print(log[-4000:])
        raise SystemExit('relocate failed (%d)' % p.returncode)

    auto, weak, tdoff, layout, mhy = parse_relocate_log(log)
    if not tdoff and os.path.exists(tmp_emit):
        try:
            e = json.load(open(tmp_emit, encoding='utf-8'))
            if e.get('typeDefinitionsOffset'):
                tdoff = int(str(e['typeDefinitionsOffset']), 0)
        except Exception:
            pass

    base = load_json(base_path)
    draft = copy.deepcopy(base)
    prov = Provenance(base, 'base:%s' % os.path.relpath(base_path, ROOT))
    # 0) 离线补充表（offline_extract.py 产出的可直接命名表）
    extra_filled = []
    _extra_path = os.path.join(root, 'ida', 'tables_extra.json')
    if os.path.exists(_extra_path):
        try:
            _extra = json.load(open(_extra_path, encoding='utf-8'))
            for _name, _t in _extra.items():
                if _name in draft.get('tables', {}):
                    _ent = copy.deepcopy(draft['tables'][_name])
                    _ent['slot'] = _t['slot']
                    _ent['op'] = _t['op']
                    _ent['key'] = _t['key']
                    draft['tables'][_name] = _ent
                    extra_filled.append(_name)
        except Exception:
            extra_filled = []
    # 0.1) MHY 锚
    if mhy:
        draft.setdefault('addresses', {})['mhyTableVA'] = '0x%X' % mhy
    # 1) relocate 结构自证
    for name, (val, slot, op, key) in auto.items():
        if name in draft.get('tables', {}):
            ent = copy.deepcopy(draft['tables'][name])
            ent['slot'] = '0x%X' % slot
            ent['op'] = op
            ent['key'] = '0x%X' % key
            draft['tables'][name] = ent
    # 2) typeDefs 基址 + 布局
    if tdoff:
        rev = reverse_slot(slots, tdoff)
        if rev and 'typeDefinitionsOffset' in draft.get('tables', {}):
            ent = copy.deepcopy(draft['tables']['typeDefinitionsOffset'])
            ent['slot'] = '0x%X' % rev[0]
            ent['op'] = rev[1]
            ent['key'] = '0x%X' % rev[2]
            draft['tables']['typeDefinitionsOffset'] = ent
    if layout:
        op_json = {'^': 'xor', '+': 'add', '-': 'sub'}
        if 'fieldStart' in layout:
            disp, op, key = layout['fieldStart']
            draft.setdefault('fieldDecode', {}).setdefault('typeDef', {})['fieldStart'] = '%s:0x%X' % (op_json.get(op, op), key)
            draft.setdefault('structOffsets', {}).setdefault('Il2CppTypeDefinition', {})['fieldStart'] = disp
            draft.setdefault('typeDefOffsets', {})['fieldStart'] = disp
        if 'fieldCount' in layout:
            disp, op, key = layout['fieldCount']
            draft.setdefault('fieldDecode', {}).setdefault('typeDef', {})['field_count'] = '%s:0x%X' % (op_json.get(op, op), key)
            draft.setdefault('structOffsets', {}).setdefault('Il2CppTypeDefinition', {})['field_count'] = disp
            draft.setdefault('typeDefOffsets', {})['field_count'] = disp
    # 3) IDA 函数读取顺序映射
    ida_filled = []
    if ida and not args.no_ida_map:
        ida_filled = apply_ida_map(draft, None, ida, args.ida_map, report)

    # 4) 高置信度结果最后覆盖 7.1 读序（读序只用于多表消歧）
    for name, (val, slot, op, key) in auto.items():
        if name in draft.get('tables', {}):
            ent = copy.deepcopy(draft['tables'][name])
            ent['slot'] = '0x%X' % slot
            ent['op'] = op
            ent['key'] = '0x%X' % key
            draft['tables'][name] = ent
    if tdoff:
        rev = reverse_slot(slots, tdoff)
        if rev and 'typeDefinitionsOffset' in draft.get('tables', {}):
            ent = copy.deepcopy(draft['tables']['typeDefinitionsOffset'])
            ent['slot'] = '0x%X' % rev[0]
            ent['op'] = rev[1]
            ent['key'] = '0x%X' % rev[2]
            draft['tables']['typeDefinitionsOffset'] = ent
    if layout:
        op_json = {'^': 'xor', '+': 'add', '-': 'sub'}
        if 'fieldStart' in layout:
            disp, op, key = layout['fieldStart']
            draft.setdefault('fieldDecode', {}).setdefault('typeDef', {})['fieldStart'] = '%s:0x%X' % (op_json.get(op, op), key)
            draft.setdefault('structOffsets', {}).setdefault('Il2CppTypeDefinition', {})['fieldStart'] = disp
            draft.setdefault('typeDefOffsets', {})['fieldStart'] = disp
        if 'fieldCount' in layout:
            disp, op, key = layout['fieldCount']
            draft.setdefault('fieldDecode', {}).setdefault('typeDef', {})['field_count'] = '%s:0x%X' % (op_json.get(op, op), key)
            draft.setdefault('structOffsets', {}).setdefault('Il2CppTypeDefinition', {})['field_count'] = disp
            draft.setdefault('typeDefOffsets', {})['field_count'] = disp
    _extra_path = os.path.join(root, 'ida', 'tables_extra.json')
    if os.path.exists(_extra_path):
        try:
            _extra = json.load(open(_extra_path, encoding='utf-8'))
            for _name, _t in _extra.items():
                if _name in draft.get('tables', {}):
                    _ent = copy.deepcopy(draft['tables'][_name])
                    _ent['slot'] = _t['slot']
                    _ent['op'] = _t['op']
                    _ent['key'] = _t['key']
                    draft['tables'][_name] = _ent
        except Exception:
            pass

    prov.mark(draft, 'auto:relocate+ida')
    # 4.5) 自动恢复 fieldDecode / keyFormulas（可选）
    seed = os.path.join(tempfile.gettempdir(), 'draft_seed_%s.json' % os.path.basename(root))
    if not args.no_auto:
        try:
            json.dump(draft, open(seed, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            fd_cmd = [sys.executable, os.path.join(TOOLS, 'fielddecode_auto.py'), root,
                      '--draft', seed,
                      '--keyformulas', os.path.join(root, 'ida', 'keyformulas.auto.json'),
                      '--out', os.path.join(root, 'ida', 'fielddecode.auto.json')]
            if os.path.isdir(os.path.join(root, 'ida', 'decomp')):
                pr = subprocess.run(fd_cmd, capture_output=True, text=True)
                if pr.returncode == 0:
                    auto_ran.append('fielddecode_auto')
                else:
                    print('fielddecode_auto failed:', (pr.stdout + pr.stderr)[-500:])
            kf_cmd = [sys.executable, os.path.join(TOOLS, 'keyformulas_auto.py'), root,
                      '--base', base_path,
                      '--values', os.path.join(root, 'ida', 'keyformulas.values.json'),
                      '--out', os.path.join(root, 'ida', 'keyformulas.auto.json')]
            if os.path.exists(os.path.join(root, 'ida', 'keyformulas.values.json')):
                pr = subprocess.run(kf_cmd, capture_output=True, text=True)
                if pr.returncode == 0:
                    auto_ran.append('keyformulas_auto')
                else:
                    print('keyformulas_auto failed:', (pr.stdout + pr.stderr)[-500:])
            cnt_cmd = [sys.executable, os.path.join(TOOLS, 'count_auto.py'), root,
                       '--base', base_path, '--exe', os.path.join(root, 'gi.exe'),
                       '--out', os.path.join(root, 'ida', 'count.auto.json')]
            if os.path.isdir(os.path.join(root, 'ida', 'decomp')):
                pr = subprocess.run(cnt_cmd, capture_output=True, text=True)
                if pr.returncode == 0:
                    auto_ran.append('count_auto')
                else:
                    print('count_auto failed:', (pr.stdout + pr.stderr)[-500:])
        except Exception as e:
            print('auto tools failed:', e)

    # 5) fieldDecode / structOffsets 自证结果
    fd_auto = {}
    _fd_path = os.path.join(root, 'ida', 'fielddecode.auto.json')
    if os.path.exists(_fd_path):
        try:
            fd_auto = json.load(open(_fd_path, encoding='utf-8'))
            for st, fs in fd_auto.get('fieldDecode', {}).items():
                draft.setdefault('fieldDecode', {}).setdefault(st, {}).update(fs)
            for st, fs in fd_auto.get('structOffsets', {}).items():
                draft.setdefault('structOffsets', {}).setdefault(st, {}).update(fs)
        except Exception:
            fd_auto = {}
    prov.mark(draft, 'auto:fielddecode')
    # 5.1) 字符串密钥（stringkeys.json 的已验证部分）
    sd_auto = {}
    _sd_path = os.path.join(root, 'ida', 'stringkeys.json')
    if os.path.exists(_sd_path):
        try:
            _sd = json.load(open(_sd_path, encoding='utf-8')).get('stringDecrypt', {})
            for k in ('keyMulA', 'keyMulB', 'keySeed', 'keyStep', 'offsetMask', 'lengthShift', 'entryXor'):
                if k in _sd:
                    draft.setdefault('stringDecrypt', {})[k] = _sd[k]
                    sd_auto[k] = _sd[k]
        except Exception:
            sd_auto = {}
    prov.mark(draft, 'auto:stringkeys')
    # 6) keyFormulas 反编译恢复结果
    kf_auto = {}
    _kf_path = os.path.join(root, 'ida', 'keyformulas.auto.json')
    if os.path.exists(_kf_path):
        try:
            kf_auto = json.load(open(_kf_path, encoding='utf-8'))
            if kf_auto:
                # 目标版本没有的旧 key 公式必须删除，否则 decodeExpr/生成头文件会继续引用旧形状。
                draft['keyFormulas'] = dict(kf_auto)
        except Exception:
            kf_auto = {}
    prov.mark(draft, 'auto:keyformulas')
    # 6.1) T0/T1 计数公式（RuntimeInit 消费者）
    cnt_auto = {}
    _cnt_path = os.path.join(root, 'ida', 'count.auto.json')
    if os.path.exists(_cnt_path):
        try:
            cnt_auto = json.load(open(_cnt_path, encoding='utf-8'))
            for name, f in cnt_auto.items():
                if name.endswith('CountFormula'):
                    draft[name] = f
        except Exception:
            cnt_auto = {}

    prov.mark(draft, 'auto:countformulas')
    # 7) 表角色修正（fieldsOffset/fieldOffset/methodSpecs/...）
    if not args.no_auto:
        try:
            json.dump(draft, open(seed, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            tr_cmd = [sys.executable, os.path.join(TOOLS, 'table_roles.py'), root,
                      '--draft', seed, '--ida', ida or os.path.join(root, 'ida.json'),
                      '--base', base_path, '--apply']
            pr = subprocess.run(tr_cmd, capture_output=True, text=True)
            if pr.returncode == 0:
                draft = load_json(seed)
                auto_ran.append('table_roles')
            else:
                print('table_roles failed:', (pr.stdout + pr.stderr)[-500:])
        except Exception as e:
            print('table_roles failed:', e)

    prov.mark(draft, 'auto:table_roles')
    # 7.05) 可选的人工 addresses 覆盖（只用于目标版本确实无法自动推导的地址）
    addr_override = {}
    _ao_path = os.path.join(root, 'ida', 'addresses.override.json')
    if os.path.exists(_ao_path):
        try:
            addr_override = json.load(open(_ao_path, encoding='utf-8'))
            for k, v in addr_override.items():
                draft.setdefault('addresses', {})[k] = v
            auto_ran.append('addresses_override')
        except Exception:
            addr_override = {}
    prov.mark(draft, 'manual:addresses.override')
    # 7.1) registrationFields：T0/T1 偏移、掩码、generic class 表
    reg_auto = {}
    if not args.no_auto:
        try:
            json.dump(draft, open(seed, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            rg_cmd = [sys.executable, os.path.join(TOOLS, 'regfields_auto.py'), root,
                      '--draft', seed, '--base', base_path,
                      '--out', os.path.join(root, 'ida', 'regfields.auto.json')]
            pr = subprocess.run(rg_cmd, capture_output=True, text=True)
            if pr.returncode == 0:
                reg_auto = json.load(open(os.path.join(root, 'ida', 'regfields.auto.json'), encoding='utf-8'))
                draft.setdefault('registrationFields', {}).update(reg_auto)
                auto_ran.append('regfields_auto')
            else:
                print('regfields_auto failed:', (pr.stdout + pr.stderr)[-500:])
        except Exception as e:
            print('regfields_auto failed:', e)
    prov.mark(draft, 'auto:regfields')
    # 8) decodeExpr：根据最终 fieldDecode/keyFormulas 重生成，避免继承上一版公式形状
    de_auto = {}
    if not args.no_auto:
        try:
            json.dump(draft, open(seed, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            de_cmd = [sys.executable, os.path.join(TOOLS, 'decodeexpr_auto.py'), root,
                      '--draft', seed,
                      '--out', os.path.join(root, 'ida', 'decodeexpr.auto.json')]
            pr = subprocess.run(de_cmd, capture_output=True, text=True)
            if pr.returncode == 0:
                de_auto = json.load(open(os.path.join(root, 'ida', 'decodeexpr.auto.json'), encoding='utf-8'))
                draft['decodeExpr'] = de_auto
                auto_ran.append('decodeexpr_auto')
            else:
                print('decodeexpr_auto failed:', (pr.stdout + pr.stderr)[-500:])
        except Exception as e:
            print('decodeexpr_auto failed:', e)

    prov.mark(draft, 'auto:decodeexpr')
    if not args.no_origin:
        draft['_origin'] = prov.result()

    draft['_update'] = {
        'base': os.path.relpath(base_path, ROOT),
        'target': os.path.relpath(root, ROOT),
        'generated': datetime.datetime.now().isoformat(timespec='seconds'),
        'relocate_auto': sorted(auto.keys()),
        'ida_filled': [n for n, _, _ in ida_filled],
        'extra_filled': extra_filled,
        'fieldDecode_auto': sorted(fd_auto.get('fieldDecode', {}).keys()) if fd_auto else [],
        'structOffsets_auto': sorted(fd_auto.get('structOffsets', {}).keys()) if fd_auto else [],
        'keyFormulas_auto': sorted(kf_auto.keys()) if kf_auto else [],
        'countFormulas_auto': sorted(cnt_auto.keys()) if cnt_auto else [],
        'registrationFields_auto': sorted(reg_auto.keys()) if reg_auto else [],
        'addresses_override': sorted(addr_override.keys()) if addr_override else [],
        'decodeExpr_auto': sorted(de_auto.keys()) if de_auto else [],
        'stringDecrypt_auto': sorted(sd_auto.keys()) if sd_auto else [],
        'typeDefinitionsOffset': ('0x%X' % tdoff) if tdoff else None,
        'mhyTableVA': ('0x%X' % mhy) if mhy else None,
        'auto_ran': auto_ran,
        'note': 'draft: 未列出的常量仍是旧版本值；不能直接发布。',
    }
    with open(emit, 'w', encoding='utf-8') as fh:
        json.dump(draft, fh, ensure_ascii=False, indent=2)

    write_report(report, root, base_path, auto, weak, tdoff, layout, ida_filled, emit, ida, slots, log_path, mhy)

    # 与目标现有 JSON 对照（如果存在），只统计表 slot/op/key
    same = None
    value_same = value_diff = None
    if args.check and had_target and os.path.exists(target_json):
        try:
            T = load_json(target_json)
            same = 0
            for n, t in base.get('tables', {}).items():
                if n in T.get('tables', {}) and n in draft.get('tables', {}):
                    a, b = draft['tables'][n], T['tables'][n]
                    if (str(a.get('slot')).lower(), a.get('op'), str(a.get('key')).lower()) == \
                       (str(b.get('slot')).lower(), b.get('op'), str(b.get('key')).lower()):
                        same += 1
            # 更实用：比较解码后的表值（不同 slot/op/key 也可能等价）
            mhy = int(str(T.get('addresses', {}).get('mhyTableVA', '0')), 0)
            exe = os.path.join(root, 'gi.exe')
            if mhy and os.path.exists(exe):
                dv = table_value_map(exe, mhy, draft)
                tv = table_value_map(exe, mhy, T)
                value_same = sorted(n for n in tv if n in dv and dv[n] == tv[n])
                value_diff = sorted(n for n in tv if n in dv and dv[n] != tv[n])
                with open(report, 'a', encoding='utf-8') as fh:
                    fh.write('\n## 6. 与目标现有 JSON 的值对照\n\n')
                    fh.write('只用于自测/回归；新版本还没有 version.json 时跳过。\n\n')
                    fh.write('- 解码后的表值一致：**%d / %d**\n' % (len(value_same), len(tv)))
                    fh.write('- 值不一致（草稿仍是旧值或需人工）：%s\n\n'
                             % (', '.join('`%s`' % x for x in value_diff) or '无'))
        except Exception:
            same = None
    elif args.check:
        with open(report, 'a', encoding='utf-8') as fh:
            fh.write('\n## 6. 与目标现有 JSON 的值对照\n\n')
            fh.write('目标原本没有 `version.json`，本次直接生成；没有可对照的旧目标 JSON。\n\n')

    print('\n=== update summary ===')
    print('target        :', os.path.relpath(root, ROOT))
    print('base          :', os.path.relpath(base_path, ROOT))
    print('relocate auto :', ', '.join(sorted(auto.keys())) or '(none)')
    print('MHY           :', ('0x%X' % mhy) if mhy else '(not found)')
    print('typeDefs      :', ('0x%X' % tdoff) if tdoff else '(not found)')
    print('layout        :', {k: ('+0x%X %s 0x%X' % v) for k, v in layout.items()})
    print('IDA filled    :', ', '.join(n for n, _, _ in ida_filled) or '(none)')
    if args.check and same is not None:
        print('tables match  : %d / %d (vs %s)' % (same, len(base.get('tables', {})), os.path.relpath(target_json, ROOT)))
    elif args.check:
        print('tables match  : (new target; no prior version.json)')
    else:
        print('tables match  : (cold-start; pass --check to compare)')
    print('draft         :', os.path.relpath(emit, ROOT))
    print('report        :', os.path.relpath(report, ROOT))
    print('relocate log  :', log_path)

    if args.apply:
        with open(target_json, 'w', encoding='utf-8') as fh:
            json.dump(draft, fh, ensure_ascii=False, indent=2)
        print('applied       :', os.path.relpath(target_json, ROOT))


if __name__ == '__main__':
    main()
