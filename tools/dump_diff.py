#!/usr/bin/env python3
"""
dump_diff.py —— 按 (类, 方法名, 参数个数) 对齐两份 dump，统计 RVA 是否一致。

用法:
    python3 tools/dump_diff.py ~/dump.cs out/dump.cs

设计:
  · 两份 dump 格式不同也能对齐（各自解析成 key -> [RVA...]）
  · 同名同参数个数的重载：比较**排序后的 RVA 列表**
  · 输出：完全一致 / RVA 不一致 / 只在一方出现，并给前若干个例子
"""
import re
import sys
from collections import defaultdict, Counter

RE_CLASS_OURS = re.compile(r'\bclass\s+([\w.]+)')
RE_CLASS_REF = re.compile(r'^\s*class\s+([\w.]+)')
RE_RVA_OURS = re.compile(r'//\s*RVA:\s*0x([0-9A-Fa-f]+)\s+Offset')
RE_RVA_REF = re.compile(r'\|RVA:\s*\+0x([0-9A-Fa-f]+)\|')
RE_PC_REF = re.compile(r'\[ParamsCount:\s*(\d+)\]')



TYPE_MAP = {
    'System.Void': 'void', 'System.Boolean': 'bool', 'System.Char': 'char',
    'System.SByte': 'sbyte', 'System.Byte': 'byte', 'System.Int16': 'short',
    'System.UInt16': 'ushort', 'System.Int32': 'int', 'System.UInt32': 'uint',
    'System.Int64': 'long', 'System.UInt64': 'ulong', 'System.Single': 'float',
    'System.Double': 'double', 'System.String': 'string', 'System.Object': 'object',
    'System.IntPtr': 'IntPtr', 'System.UIntPtr': 'UIntPtr',
}


def norm_type(t):
    t = t.strip()
    for k, v in TYPE_MAP.items():
        t = t.replace(k, v)
    t = re.sub(r'\bSystem\.', '', t)
    t = re.sub(r'\s+', '', t)
    return t


def _split_top(s):
    """按顶层逗号切参数"""
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '<([{':
            depth += 1
        elif ch in '>)]}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def param_types(inner):
    """参数列表 -> 类型元组（去掉最后一个标识符=参数名）"""
    types = []
    for seg in _split_top(inner):
        seg = seg.strip()
        if not seg:
            continue
        # 去掉 ref/out/in/params
        seg = re.sub(r'^(ref|out|in|params)\s+', '', seg)
        toks = seg.rsplit(None, 1)
        typ = toks[0] if len(toks) == 2 and re.match(r'^[A-Za-z_]\w*$', toks[1]) else seg
        types.append(norm_type(typ))
    return tuple(types)


def method_key(line):
    """从方法签名里取 (名字, 参数个数)；不是方法返回 None。"""
    s = line.strip()
    if '(' not in s:
        return None
    i = s.find('(')
    # 名字：'(' 前面最后一个标识符
    m = re.search(r'([A-Za-z_<>.][\w<>.]*)\s*$', s[:i])
    if not m:
        return None
    name = m.group(1).split('.')[-1]
    inner = s[i + 1:s.rfind(')')] if ')' in s else s[i + 1:]
    return name, param_types(inner)


def parse_ours(path):
    out = defaultdict(list)
    cls = '?'
    pending = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            m = RE_CLASS_OURS.search(line)
            if m and 'class ' in line:
                cls = m.group(1)
                continue
            m = RE_RVA_OURS.search(line)
            if m:
                pending = int(m.group(1), 16)
                continue
            if pending is not None:
                k = method_key(line)
                if k:
                    out[(cls.split('.')[-1], k[0], k[1])].append(pending)
                    pending = None
                elif ';' in line or '{' in line:
                    pending = None      # 是字段/属性，不是方法
    return out


def parse_ref(path):
    out = defaultdict(list)
    cls = '?'
    pending = None
    pc = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            m = RE_CLASS_REF.match(line)
            if m:
                cls = m.group(1)
                continue
            m = RE_RVA_REF.search(line)
            if m:
                pending = int(m.group(1), 16)
                q = RE_PC_REF.search(line)
                pc = int(q.group(1)) if q else None
                continue
            if pending is not None:
                k = method_key(line)
                if k:
                    key = k[1] if k[1] else tuple(['?'] * (pc or 0))
                    out[(cls.split('.')[-1], k[0], key)].append(pending)
                    pending = None
                    pc = None
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    def detect(path):
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if '[Flags:' in line or '|RVA: +0x' in line:
                    return 'ref'
                if '// RVA: 0x' in line:
                    return 'ours'
        return 'ours'
    f1, f2 = sys.argv[1], sys.argv[2]
    a = parse_ours(f1) if detect(f1) == 'ours' else parse_ref(f1)
    b = parse_ours(f2) if detect(f2) == 'ours' else parse_ref(f2)
    print('ours   : %d 个 key, %d 个方法' % (len(a), sum(len(v) for v in a.values())))
    print('ref    : %d 个 key, %d 个方法' % (len(b), sum(len(v) for v in b.values())))

    same = diff = 0
    bad = []
    only_a = set(a) - set(b)
    only_b = set(b) - set(a)
    for k in set(a) & set(b):
        if sorted(a[k]) == sorted(b[k]):
            same += 1
        else:
            diff += 1
            if len(bad) < 10:
                bad.append((k, sorted(a[k]), sorted(b[k])))
    print('\n共同 key %d：RVA 完全一致 %d，不一致 %d' % (len(set(a) & set(b)), same, diff))
    print('只在一方出现：ours %d，ref %d' % (len(only_a), len(only_b)))
    print('\n不一致示例:')
    for k, x, y in bad:
        print('  %s.%s%s  ours=%s ref=%s'
              % (k[0], k[1], list(k[2]), [hex(v) for v in x], [hex(v) for v in y]))
    print('\n只在一方出现示例（ours）:', sorted(only_a)[:5])
    print('只在一方出现示例（ref ）:', sorted(only_b)[:5])
    return 0


if __name__ == '__main__':
    sys.exit(main())
