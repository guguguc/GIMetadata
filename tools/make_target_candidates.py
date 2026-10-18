#!/usr/bin/env python3
"""Build the target-side candidate address list used by IDA exports.

The 70-address cache was:
    LCAvatarCombat   15
    LCSelectPickup    7
    UITriggerHandler 48
    -------------------
    total            70

Groups are intentionally explicit here: they describe which method shapes
belong to each source hook group.  The class names are target 7.0 classes;
they are not target answers, only candidate containers.

Usage:
    python3 tools/make_target_candidates.py \
        --dst-dump out/dump70.cs \
        --groups tools/hook_groups_70.json \
        --out out/ida70_group_addresses.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dump_align as DA


def load_groups(path):
    d = json.load(open(path, encoding="utf-8"))
    if isinstance(d, dict) and "groups" in d:
        d = d["groups"]
    out = {}
    for full, shapes in d.items():
        out[full] = []
        for s in shapes:
            if isinstance(s, dict):
                rt, ps = s.get("ret", "void"), s.get("params", [])
            else:
                rt, ps = s[0], s[1]
            out[full].append((rt, tuple(ps)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst-dump", required=True)
    ap.add_argument("--groups", required=True,
                    help='JSON: {class: [["ret", ["param_shape"]], ...]}')
    ap.add_argument("--out", required=True)
    ap.add_argument("--image-base", default="0x140000000")
    a = ap.parse_args()

    base = int(a.image_base, 0)
    T = DA.parse_dump(a.dst_dump)
    groups = load_groups(a.groups)
    addrs = []
    report = {}
    for full, shapes in groups.items():
        cls = T.get(full)
        if not cls:
            report[full] = {"count": 0, "error": "class not found"}
            continue
        got = []
        for m in cls["methods"]:
            if m["shape"] in shapes:
                addr = "0x%X" % (base + m["rva"])
                if addr not in addrs:
                    addrs.append(addr)
                    got.append({"addr": addr, "name": m["name"],
                                "decl": m["decl"], "shape": m["shape"]})
        report[full] = {"count": len(got), "methods": got}

    out = {"image_base": a.image_base, "count": len(addrs),
           "addrs": addrs, "groups": report}
    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("candidates: %d" % len(addrs))
    for full, r in report.items():
        print("  %-30s %d" % (full, r.get("count", 0)))
    print("addrs: " + ",".join(addrs))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
