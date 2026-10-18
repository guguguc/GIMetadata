#!/usr/bin/env python3
"""ida_funcs_export.py —— 只导出“已知/有用”的函数表，不做全量。

在 IDA 里运行（GUI Script file 或 MCP py_eval）：

  GI_NAMES=/path/to/names.txt
  GI_HITS=/path/to/sig_hits.json      # 可选；优先用 name -> EA
  GI_FUNCS_OUT=/path/to/funcs.json

names 文件格式：
  0x1404F69D0 GIMeta_TypeAttrGetter
  或每行一个函数名（配合 GI_HITS）

输出：
  {"funcs": [{"name","start","end","size","thunk","jmp_target","callees"}]}
"""
import json
import os

import ida_funcs
import ida_name
import idautils
import idc


def load_names():
    names = []
    hits_path = os.environ.get('GI_HITS')
    hits = {}
    if hits_path and os.path.exists(hits_path):
        H = json.load(open(hits_path, encoding='utf-8'))
        hits = H.get('hits', H) if isinstance(H, dict) else {}
    names_path = os.environ.get('GI_NAMES')
    if names_path and os.path.exists(names_path):
        for line in open(names_path, encoding='utf-8'):
            line = line.split('#')[0].strip()
            if not line:
                continue
            p = line.split()
            if len(p) >= 2 and p[0].lower().startswith('0x'):
                names.append((p[1], int(p[0], 16)))
            else:
                nm = p[-1]
                ea = hits.get(nm)
                if ea is None:
                    ea = ida_name.get_name_ea(ida_name.BADADDR, nm)
                if ea != ida_name.BADADDR:
                    names.append((nm, int(ea)))
    else:
        for nm, ea in hits.items():
            names.append((nm, int(ea)))
    return names


def callees_of(ea):
    out = set()
    f = ida_funcs.get_func(ea)
    if not f:
        return []
    try:
        heads = idautils.Heads(int(f.start_ea), int(f.end_ea))
    except Exception:
        heads = []
    for head in heads:
        try:
            if idc.print_insn_mnem(head) != 'call':
                continue
            got = False
            try:
                tgt = idc.get_operand_value(head, 0)
                if tgt:
                    out.add(int(tgt)); got = True
            except Exception:
                pass
            try:
                for t in idautils.CodeRefsFrom(head, 0):
                    out.add(int(t)); got = True
            except Exception:
                pass
            if not got:
                for x in idautils.XrefsFrom(head, 0):
                    if getattr(x, 'iscode', True):
                        out.add(int(x.to))
        except Exception:
            pass
    return sorted(out)


def main():
    out_path = os.environ.get('GI_FUNCS_OUT') or '/tmp/funcs.json'
    funcs = []
    seen = set()
    for name, ea in load_names():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        start = int(f.start_ea)
        if start in seen:
            continue
        seen.add(start)
        first = idc.print_insn_mnem(start)
        thunk = bool(ida_funcs.is_thunk(start)) if hasattr(ida_funcs, 'is_thunk') else False
        jmp_target = None
        if first == 'jmp':
            try:
                jmp_target = int(idc.get_operand_value(start, 0))
            except Exception:
                pass
        funcs.append({
            'name': ida_funcs.get_func_name(start) or name,
            'start': start,
            'end': int(f.end_ea),
            'size': int(f.end_ea) - start,
            'thunk': thunk or first == 'jmp',
            'jmp_target': jmp_target,
            'callees': callees_of(start),
        })
    json.dump({'funcs': funcs}, open(out_path, 'w', encoding='utf-8'), indent=1)
    print('wrote %d funcs -> %s' % (len(funcs), out_path))


if __name__ == '__main__':
    main()
