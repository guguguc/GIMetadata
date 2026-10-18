#!/usr/bin/env python3
"""One-command hook relocation pipeline.

Default mode never requires an IDA export:

    python3 tools/hooks_pipeline.py --src-version 7.1 --dst-version 7.2

It uses:
    dump_funcs.py
    dump_align.py
    hook_resolve.py

IDA is optional:
    --ida-mode none    no IDA at all (class/shape/body evidence only)
    --ida-mode cache   use pre-generated --src-export/--dst-export files
    --ida-mode mcp     query the target IDA MCP for xrefs

The source hook map and output names can be overridden for unusual versions.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run(cmd, dry=False, log=None):
    if log:
        log("command: " + " ".join(cmd))
    else:
        print("+", " ".join(cmd))
    if dry:
        return 0.0
    t0 = time.perf_counter()
    subprocess.run(cmd, cwd=ROOT, check=True)
    return time.perf_counter() - t0


def vkey(v):
    return v.replace(".", "")


def first_existing(paths):
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-version", required=True)
    ap.add_argument("--dst-version", required=True)
    ap.add_argument("--src-dump", default=None)
    ap.add_argument("--dst-dump", default=None)
    ap.add_argument("--hooks", default=None)
    ap.add_argument("--base", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--report", default=None)
    ap.add_argument("--cache-dir", default="out/cache")
    ap.add_argument("--src-exe", default=None)
    ap.add_argument("--dst-exe", default=None)
    ap.add_argument("--src-export", default=None,
                    help="source IDA export JSON; optional, explicit is preferred")
    ap.add_argument("--dst-export", default=None,
                    help="target IDA export JSON; optional")
    ap.add_argument("--auto-export", action="store_true",
                    help="allow convention-based auto-discovery of ida<ver>_*.json")
    ap.add_argument("--ida-url", default="http://127.0.0.1:13337/mcp")
    ap.add_argument("--ida-mode", choices=["none", "cache", "mcp"], default="none")
    ap.add_argument("--max-body", type=int, default=300)
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel worker count (candidate generation + scoring)")
    ap.add_argument("--class-score", type=float, default=0.58)
    ap.add_argument("--class-margin", type=float, default=0.03)
    ap.add_argument("--force-base", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log", default=None,
                    help="human-readable pipeline log; default out/cache/hooks_pipeline_<src>_<dst>.log")
    ap.add_argument("--timing-json", default=None,
                    help="structured timing output; default out/cache/hooks_pipeline_<src>_<dst>_timing.json")
    ap.add_argument("--verify-hooks", default=None,
                    help="optional reference JSON; used ONLY for final validation")
    a = ap.parse_args()

    sk, dk = vkey(a.src_version), vkey(a.dst_version)
    src_dump = a.src_dump or os.path.join(ROOT, "out", "dump%s.cs" % sk)
    dst_dump = a.dst_dump or os.path.join(ROOT, "out", "dump%s.cs" % dk)
    hooks = a.hooks or first_existing([
        os.path.join(ROOT, "out", "hk_%s_all_named_map.json" % sk),
        os.path.join(ROOT, "out", "hk_%s_map.json" % sk),
    ])
    base = a.base or os.path.join(ROOT, "out", "hk%s_best.json" % dk)
    out = a.out or os.path.join(ROOT, "out", "hk%s_auto_resolved.json" % dk)
    report = a.report or os.path.join(ROOT, "out", "hk%s_auto_resolved_report.json" % dk)
    src_exe = a.src_exe or os.path.join(ROOT, "version", a.src_version, "gi.exe")
    dst_exe = a.dst_exe or os.path.join(ROOT, "version", a.dst_version, "gi.exe")
    cache = os.path.join(ROOT, a.cache_dir)
    os.makedirs(cache, exist_ok=True)
    log_path = a.log or os.path.join(cache, "hooks_pipeline_%s_%s.log" % (sk, dk))
    timing_path = a.timing_json or os.path.join(cache, "hooks_pipeline_%s_%s_timing.json" % (sk, dk))
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    t_start = time.perf_counter()
    records = []

    def log(msg):
        dt = time.perf_counter() - t_start
        line = "[%8.3fs] %s" % (dt, msg)
        print(line)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def timed(label, fn):
        t0 = time.perf_counter()
        try:
            return fn()
        finally:
            dt = time.perf_counter() - t0
            records.append({"phase": label, "seconds": round(dt, 4)})
            log("phase %-22s %.3fs" % (label, dt))

    log("pipeline start src=%s dst=%s ida_mode=%s" % (a.src_version, a.dst_version, a.ida_mode))

    src_export = a.src_export
    dst_export = a.dst_export
    if a.auto_export:
        src_export = src_export or first_existing([
            os.path.join(ROOT, "out", "ida%s_source_export.json" % sk),
            os.path.join(ROOT, "out", "ida%s_export.json" % sk),
        ])
        dst_export = dst_export or first_existing([
            os.path.join(ROOT, "out", "ida%s_candidates.json" % dk),
            os.path.join(ROOT, "out", "ida%s_group_candidates.json" % dk),
        ])
    funcs_src = os.path.join(cache, "funcs_%s.json" % sk)
    funcs_dst = os.path.join(cache, "funcs_%s.json" % dk)

    if not os.path.exists(src_dump):
        raise SystemExit("missing source dump: " + src_dump)
    if not os.path.exists(dst_dump):
        raise SystemExit("missing target dump: " + dst_dump)
    if not hooks or not os.path.exists(hooks):
        raise SystemExit("missing source hook map")
    for p in (src_exe, dst_exe):
        if not os.path.exists(p):
            raise SystemExit("missing executable: " + p)

    # 1) function boundaries
    def _funcs():
        for dump, out_f in ((src_dump, funcs_src), (dst_dump, funcs_dst)):
            if a.force_base or not os.path.exists(out_f):
                run([sys.executable, "tools/dump_funcs.py", dump, "-o", out_f],
                    dry=a.dry_run, log=log)
            else:
                log("reuse funcs: " + out_f)
    timed("func-boundaries", _funcs)

    # 2) initial candidate base
    def _base():
        if a.force_base or not os.path.exists(base):
            run([sys.executable, "tools/dump_align.py",
                 "--from", src_dump, "--to", dst_dump,
                 "--hooks", hooks, "--out", base,
                 "--verify-disasm",
                 "--reselect-low", "--reselect-medium",
                 "--class-score", str(a.class_score),
                 "--class-margin", str(a.class_margin),
                 "--src-exe", src_exe, "--dst-exe", dst_exe,
                 "--src-funcs", funcs_src, "--dst-funcs", funcs_dst,
                 "--jobs", str(a.jobs)],
                dry=a.dry_run, log=log)
        else:
            log("reuse base: " + base)
    timed("base-candidates", _base)

    # 3) final evidence resolver
    resolver_timing = os.path.join(cache, "hook_resolve_%s_%s_timing.json" % (sk, dk))
    cmd = [sys.executable, "tools/hook_resolve.py",
           "--src-dump", src_dump, "--dst-dump", dst_dump,
           "--hooks", hooks, "--base", base,
           "--src-exe", src_exe, "--dst-exe", dst_exe,
           "--out", out, "--report", report,
           "--max-body", str(a.max_body),
           "--jobs", str(a.jobs),
           "--timing-json", resolver_timing]
    if a.ida_mode == "none":
        cmd += ["--no-ida"]
        if src_export and os.path.exists(src_export):
            cmd += ["--src-export", src_export]
        if dst_export and os.path.exists(dst_export):
            cmd += ["--dst-export", dst_export]
    elif a.ida_mode == "cache":
        if not src_export or not os.path.exists(src_export):
            print("warning: no source export; continuing without source xrefs",
                  file=sys.stderr)
        else:
            cmd += ["--src-export", src_export]
        if dst_export and os.path.exists(dst_export):
            cmd += ["--dst-export", dst_export]
        else:
            print("warning: no target export; running without target xrefs",
                  file=sys.stderr)
    else:  # mcp
        if src_export and os.path.exists(src_export):
            cmd += ["--src-export", src_export]
        cmd += ["--ida-url", a.ida_url]
    def _resolve():
        run(cmd, dry=a.dry_run, log=log)
    timed("hook-resolve", _resolve)

    # 4) optional independent validation; never used for finding
    if a.verify_hooks and not a.dry_run and os.path.exists(out):
        def _validate():
            R = json.load(open(out, encoding="utf-8"))
            H = {x["name"]: x for x in json.load(open(a.verify_hooks, encoding="utf-8"))["hooks"]}
            ok = bad = miss = 0
            for n, h in H.items():
                rv = h.get("rva_7_0")
                if not rv:
                    continue
                t = R.get(n, {}).get("target_rva")
                if not t:
                    miss += 1
                elif int(t, 16) == int(rv, 16):
                    ok += 1
                else:
                    bad += 1
            log("validation same=%d diff=%d missing=%d" % (ok, bad, miss))
        timed("validation", _validate)

    total = time.perf_counter() - t_start
    records.append({"phase": "total", "seconds": round(total, 4)})
    manifest = {
        "src_version": a.src_version, "dst_version": a.dst_version,
        "ida_mode": a.ida_mode, "started": datetime.now().isoformat(timespec="seconds"),
        "total_seconds": round(total, 4),
        "phases": records,
        "paths": {"src_dump": src_dump, "dst_dump": dst_dump, "hooks": hooks,
                  "base": base, "out": out, "report": report,
                  "src_export": src_export, "dst_export": dst_export,
                  "log": log_path, "resolver_timing": resolver_timing},
    }
    json.dump(manifest, open(timing_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    log("timing written: " + timing_path)
    log("pipeline done total=%.3fs output=%s" % (total, out))
    print("output:", out)
    print("report:", report)
    print("timing:", timing_path)


if __name__ == "__main__":
    main()
