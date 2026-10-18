#!/usr/bin/env python3
"""Export hook-relevant functions from the currently open IDA database.

Run this *inside IDA* (File -> Script file..., or with idat64 -S).

It is deliberately separate from ida_export.py: that script exports version
constants, this one exports the function/xref/callee data consumed by
tools/hook_resolve.py.

Examples
--------
Source side (7.1), keyed by hook name:

    python3 - <<'PY'   # in IDA: File -> Script file...
    PY
    # or:
    idat64 -A -S"tools/ida_hook_export.py /tmp/src_export.json <hooks.json>" \
        version/7.1/gi.exe.i64

Target side (7.0), explicit addresses:

    GI_HOOK_ADDRS=0x14E645D90,0x14DF02AB0 \
    GI_HOOK_OUT=/tmp/dst_export.json \
    idat64 -A -S"tools/ida_hook_export.py" version/7.0/gi.exe.i64

Input hook JSON:
    {"rows": [{"hook_method": "...", "rva": "0x...", ...}]}

Environment / arguments:
    argv[1] or GI_HOOK_OUT     output JSON
    argv[2] or GI_HOOKS        source hook map (rows with hook_method/rva)
    GI_HOOK_ADDRS              comma-separated hex addresses (target mode)
    GI_HOOK_ADDRS_FILE         JSON/text file with addresses (target mode)
    GI_IMAGE_BASE              override image base (default: IDA imagebase)

Output:
    source mode: {"source": "...", "functions": {hook_method: {...}}}
    address mode: {"source": "...", "functions": [{"addr": "...", ...}]}

Each function contains:
    addr/va, rva, name, size, lookup, callees, xrefs, decomp (if available)
"""
import json
import os
import re
import sys

import ida_funcs
import ida_hexrays
import ida_name
import ida_nalt
import idautils
import idc


def hx(v):
    return "0x%X" % int(v)


def callees_of(ea):
    out = {}
    f = ida_funcs.get_func(ea)
    if not f:
        return []
    for head in idautils.Heads(int(f.start_ea), int(f.end_ea)):
        try:
            if idc.print_insn_mnem(head) != "call":
                continue
            targets = set()
            try:
                v = idc.get_operand_value(head, 0)
                if v:
                    targets.add(int(v))
            except Exception:
                pass
            try:
                for t in idautils.CodeRefsFrom(head, 0):
                    targets.add(int(t))
            except Exception:
                pass
            for t in targets:
                if t not in out:
                    out[t] = {"addr": hx(t), "name": ida_name.get_name(t) or "",
                              "type": "internal"}
        except Exception:
            pass
    return list(out.values())


def xrefs_to(ea):
    out = []
    for x in idautils.XrefsTo(ea):
        d = {"addr": hx(x.frm), "type": "code" if x.iscode else "data"}
        if x.iscode:
            f = ida_funcs.get_func(x.frm)
            if f:
                d["fn"] = {"addr": hx(f.start_ea),
                           "name": ida_funcs.get_func_name(f.start_ea) or "",
                           "size": hx(f.end_ea - f.start_ea)}
            else:
                d["fn"] = None
        out.append(d)
    return out


def function_record(ea, hook=None):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    start = int(f.start_ea)
    end = int(f.end_ea)
    rec = {
        "addr": hx(start),
        "va": hx(start),
        "rva": hx(start - int(ida_nalt.get_imagebase())),
        "name": ida_funcs.get_func_name(start) or "",
        "size": hx(end - start),
        "lookup": {"addr": hx(start),
                   "name": ida_funcs.get_func_name(start) or "",
                   "size": hx(end - start)},
        "callees": callees_of(start),
        "xrefs": xrefs_to(start),
    }
    if hook:
        rec.update({k: hook.get(k) for k in
                    ("hook_method", "fullname", "dump_name", "dump_decl")
                    if hook.get(k) is not None})
        rec["class"] = hook.get("fullname")
        rec["method"] = hook.get("dump_name")
        rec["decl"] = hook.get("dump_decl")
    try:
        cf = ida_hexrays.decompile(start)
        rec["decomp"] = str(cf) if cf is not None else ""
    except Exception as e:
        rec["decomp"] = ""
        rec["decomp_error"] = str(e)
    return rec


def main():
    args = sys.argv[1:]
    out_path = args[0] if args else os.environ.get("GI_HOOK_OUT")
    hooks_path = args[1] if len(args) > 1 else os.environ.get("GI_HOOKS")
    addr_env = os.environ.get("GI_HOOK_ADDRS", "")
    addr_file = os.environ.get("GI_HOOK_ADDRS_FILE", "")
    base = os.environ.get("GI_IMAGE_BASE")
    if base:
        base = int(base, 0)
    else:
        base = int(ida_nalt.get_imagebase())
    if not out_path:
        out_path = "/tmp/ida_hook_export.json"

    # address mode: explicit VAs, usually the target 7.0 candidate set
    if addr_file:
        raw = open(addr_file, encoding="utf-8").read()
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                vals = d.get("addrs") or d.get("target_va") or d.get("targets") or []
            else:
                vals = d
            addr_env = ",".join(str(x) for x in vals)
        except Exception:
            # also accept one address per line, comments allowed
            vals = []
            for line in raw.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    vals.append(line)
            addr_env = ",".join(vals)
    if addr_env:
        addrs = []
        for x in re.split(r"[,\s]+", addr_env.strip()):
            if x:
                addrs.append(int(x, 0))
        funcs = []
        for a in addrs:
            rec = function_record(a)
            if rec:
                funcs.append(rec)
        out = {"source": "ida-hook-export-addrs", "image_base": hx(base),
               "functions": funcs}
        json.dump(out, open(out_path, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("wrote %d/%d functions -> %s" % (len(funcs), len(addrs), out_path))
        return

    # hook-map mode: rows contain rva (and source metadata)
    if not hooks_path or not os.path.exists(hooks_path):
        raise SystemExit("need hook JSON (argv[2] or GI_HOOKS) or GI_HOOK_ADDRS")
    d = json.load(open(hooks_path, encoding="utf-8"))
    rows = d.get("rows", d if isinstance(d, list) else [])
    funcs = {}
    for h in rows:
        nm = h.get("hook_method") or h.get("name")
        if not nm:
            continue
        rv = h.get("rva") or h.get("rva_7_1") or h.get("rva_7_0")
        if rv is None:
            continue
        va = base + int(str(rv), 16)
        rec = function_record(va, h)
        if rec:
            funcs[nm] = rec
    out = {"source": "ida-hook-export-hooks", "image_base": hx(base),
           "functions": funcs}
    json.dump(out, open(out_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("wrote %d/%d hooks -> %s" % (len(funcs), len(rows), out_path))


if __name__ == "__main__":
    main()
