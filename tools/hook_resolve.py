#!/usr/bin/env python3
"""Resolve uncertain 7.x -> 7.y hook mappings using metadata + call evidence.

This is the automated version of the manual work:

  * class candidates come from method-shape alignment, never from hooks_7.0
  * method candidates must have the same shape
  * the source/target method modifiers and preserved names are used as evidence
  * direct-call sites are compared by their *relative position inside the caller*
  * the caller class/method shape is compared, including nested classes
  * for duplicate getters the same-shape group is assigned in source order

The target xrefs can either be loaded from an IDA export JSON or queried live
from the local IDA MCP server.  No target `hooks_7.0.json` data is used.
"""
import argparse
import bisect
import collections
import difflib
import hashlib
import json
import math
import os
import pickle
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dump_align as DA
import sig
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


# --------------------------------------------------------------------- utils
def load_hooks(path):
    d = json.load(open(path, encoding="utf-8"))
    return d.get("rows", d)


def src_method(S, h):
    scls = S.get(h.get("fullname", ""))
    if not scls:
        return None, None, None
    rva = h.get("rva")
    sm = None
    if rva:
        rv = int(str(rva), 16)
        sm = next((m for m in scls["methods"] if m["rva"] == rv), None)
    if sm is None:
        sm = DA.find_source_method(scls, h)
    # Hook names are often "Class_Method".  If the source map points at a
    # different (usually next/previous) method in the same class, prefer the
    # uniquely named source method.  This is a metadata-only correction; it
    # does not use the target answer.
    nm = h.get("hook_method", "").rsplit("_", 1)[-1]
    if nm:
        xs = [m for m in scls["methods"] if m["name"] == nm]
        if len(xs) == 1:
            sm = xs[0]
    if sm is None:
        return scls, None, None
    return scls, sm, scls["methods"].index(sm)


def method_mods(decl):
    w = set(re.findall(r"\b(?:public|private|protected|internal|static|virtual|abstract|override|sealed)\b", decl))
    # access is one flag, the rest are independent flags
    access = next((x for x in ("public", "private", "protected", "internal") if x in w), "private")
    return (
        access,
        "static" in w,
        "virtual" in w or "abstract" in w or "override" in w,
        "abstract" in w,
    )


def mod_score(a, b):
    aa = a[0] == b[0]
    # access dominates, static/virtual are useful but not mandatory when
    # compiler-generated overrides change the emission order
    return (0.60 * aa +
            0.20 * (a[1] == b[1]) +
            0.20 * (a[2] == b[2]))


def _raw_decl(decl):
    # DA.raw_rtype correctly skips modifiers and extracts the return type;
    # a naive regex would capture the method name instead.
    rt = (DA.raw_rtype(decl or "") or "").split(".")[-1]
    pm = re.search(r'\((.*)\)', decl or "")
    ps = []
    if pm:
        depth = 0; buf = ""
        for ch in pm.group(1):
            if ch in "<[(": depth += 1
            elif ch in ">])": depth = max(0, depth - 1)
            if ch == ',' and depth == 0:
                ps.append(buf); buf = ""
            else:
                buf += ch
        if buf.strip(): ps.append(buf)
    out = []
    for x in ps:
        x = x.split('=', 1)[0].strip()
        # remove parameter name
        mm = re.match(r'(.+?)(?:\s+[A-Za-z_]\w*)$', x)
        if mm and not x.endswith(('>', ']', '*')): x = mm.group(1)
        out.append(x.strip().split(".")[-1])
    return rt, out


KNOWN_TYPES = {
    "void", "bool", "byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong",
    "float", "double", "string", "object", "char", "decimal",
    "Vector2", "Vector3", "Vector4", "Quaternion", "Color", "Transform", "Animator",
    "Rigidbody", "GameObject", "Component", "Camera", "Text", "Button", "Collider",
    "RigidbodyConstraints", "CursorLockMode", "IntPtr",
}


def is_accessor_hook(name):
    return "_set_" in name or "_get_" in name


def accessor_modifier_issue(name, sdecl, tdecl):
    """Hard accessor check: a property setter/getter must not turn into a
    different access level/static kind, or into a virtual lifecycle method.

    This is deliberately narrow: it only runs for hooks whose semantic name
    contains _set_/_get_, so it does not alter ordinary method scoring.
    """
    if not is_accessor_hook(name):
        return None
    s = method_mods(sdecl)
    t = method_mods(tdecl)
    if s[0] != t[0]:
        return "accessor access %s != %s" % (s[0], t[0])
    if s[1] != t[1]:
        return "accessor static %s != %s" % (s[1], t[1])
    if (not s[2]) and t[2]:
        return "accessor non-virtual source became virtual target"
    return None


def signature_issues(sdecl, tdecl):
    """Return hard type-name contradictions that shape matching would miss."""
    sr, sp = _raw_decl(sdecl)
    tr, tp = _raw_decl(tdecl)
    issues = []
    if sr in KNOWN_TYPES and tr in KNOWN_TYPES and sr != tr:
        issues.append("return %s != %s" % (sr, tr))
    elif (sr in KNOWN_TYPES) != (tr in KNOWN_TYPES):
        # one side is a known primitive/engine type, the other is an
        # obfuscated user type: highly suspicious for a simple getter.
        if sr in KNOWN_TYPES or tr in KNOWN_TYPES:
            issues.append("return type kind %s != %s" % (sr, tr))
    if len(sp) != len(tp):
        issues.append("param count %d != %d" % (len(sp), len(tp)))
    else:
        for i, (a, b) in enumerate(zip(sp, tp)):
            if a in KNOWN_TYPES and b in KNOWN_TYPES and a != b:
                issues.append("param%d %s != %s" % (i, a, b))
    return issues


    # The dumper uses dots for both namespaces and nested types.  Pick the
    # longest existing prefix as the outer type when the caller has the dump.
    return None


def nested_under(full, outer):
    return bool(full and outer and full.startswith(outer + "."))


def nearest_method(starts, addr):
    """starts: sorted [(start, end, class_full, method)]."""
    i = bisect.bisect_right(starts, (addr, 1 << 63)) - 1
    if i < 0:
        return None
    st, en, cl, m = starts[i]
    if st <= addr < en:
        return cl, m, st, en
    return None


def method_starts(D):
    xs = []
    for full, c in D.items():
        for m in c["methods"]:
            st = 0x140000000 + m["rva"]
            xs.append((st, full, m))
    xs.sort(key=lambda z: z[0])
    out = []
    for i, (st, full, m) in enumerate(xs):
        en = xs[i + 1][0] if i + 1 < len(xs) else st + 0x1000
        out.append((st, en, full, m))
    return out


# --------------------------------------------------------------- IDA xrefs
def ida_call(code, url, timeout=120):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "py_eval", "arguments": {"code": code}}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    txt = d["result"]["content"][0]["text"]
    return json.loads(txt)


def mcp_call(name, args, url, timeout=120):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args}}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    txt = d["result"]["content"][0]["text"]
    return json.loads(txt)


def export_target_cache(addrs, url, path):
    """Ask the live target IDA for a complete export_funcs cache."""
    data = mcp_call("export_funcs", {"addrs": list(addrs), "format": "json"}, url,
                    timeout=600)
    # export_funcs returns {"functions":[...]}; write exactly that shape.
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return len(data.get("functions", [])) if isinstance(data, dict) else 0


def target_xrefs_ida(addrs, url):
    if not addrs:
        return {}
    code = r'''
import idautils, ida_funcs, ida_xref, json
addrs=%r
out={}
for a in addrs:
    ea=int(a,16); xs=[]
    for x in idautils.XrefsTo(ea, ida_xref.XREF_CODE):
        cf=ida_funcs.get_func(x.frm)
        xs.append({'from':x.frm,
                   'start':cf.start_ea if cf else None,
                   'end':cf.end_ea if cf else None,
                   'norm':(x.frm-cf.start_ea)/max(1,cf.end_ea-cf.start_ea) if cf else None})
    out[a]=xs
print(json.dumps(out))
''' % list(addrs)
    d = ida_call(code, url)
    return json.loads(d["stdout"])


def load_target_export(path):
    """Accept ida export_funcs output (list) and make addr -> function dict."""
    if not path or not os.path.exists(path):
        return {}
    d = json.load(open(path, encoding="utf-8"))
    fs = d.get("functions", d if isinstance(d, list) else [])
    out = {}
    for f in fs:
        if not isinstance(f, dict) or "addr" not in f:
            continue
        out[f["addr"].lower()] = f
    return out


def target_xrefs_from_export(exp, addrs):
    out = {}
    for a in addrs:
        f = exp.get(a.lower())
        if not f:
            continue
        xs = []
        for x in (f.get("xrefs") or {}).get("to", []):
            if x.get("type") != "code":
                continue
            # exported xrefs carry only the call address; caller bounds are
            # filled by the dump-derived start table below.
            xs.append({"from": int(x["addr"], 16), "start": None, "end": None, "norm": None})
        out[a] = xs
    return out


def fill_xref_bounds(xrefs, starts):
    for a, xs in xrefs.items():
        for x in xs:
            if x.get("norm") is not None:
                continue
            hit = nearest_method(starts, x["from"])
            if hit:
                _, _, st, en = hit
                x["start"], x["end"] = st, en
                x["norm"] = (x["from"] - st) / max(1, en - st)
    return xrefs


# --------------------------------------------------------------- PE bodies
def build_ends(D):
    by = {}
    for full, c in D.items():
        for m in c["methods"]:
            by[0x140000000 + m["rva"]] = (full, m)
    starts = sorted(by)
    out = {}
    for i, st in enumerate(starts):
        out[st] = (starts[i + 1] if i + 1 < len(starts) else st + 0x1000, by[st])
    return out


def body_score(src_pe, dst_pe, md, sva, tva, sends, tends):
    se = sends.get(sva)
    te = tends.get(tva)
    if not se or not te:
        return 0.0, {}
    # Reuse the same feature definition as dump_align/sig.
    try:
        sf = sig._func_features(src_pe, md, sva, se[0])
        tf = sig._func_features(dst_pe, md, tva, te[0])
        if not sf or not tf:
            return 0.0, {}
        cos = sig._cosine(sf.get("hist") or {}, tf.get("hist") or {})
        def ratio(a, b):
            return min(a, b) / max(a, b) if a and b else 0.0
        counts = (ratio(sf.get("insns"), tf.get("insns")) +
                  ratio(sf.get("calls"), tf.get("calls")) +
                  ratio(sf.get("blocks"), tf.get("blocks")) +
                  ratio(sf.get("edges"), tf.get("edges"))) / 4.0
        lcs = 0.0
        try:
            so = src_pe.va2off(sva); to = dst_pe.va2off(tva)
            if so is not None and to is not None:
                a = []
                for ins in md.disasm(src_pe.D[so:so + min(0x20000, se[0] - sva + 32)], sva):
                    if ins.address >= se[0]: break
                    if ins.mnemonic not in ("int3", "nop", "nopw", "nopl"): a.append(ins.mnemonic)
                b = []
                for ins in md.disasm(dst_pe.D[to:to + min(0x20000, te[0] - tva + 32)], tva):
                    if ins.address >= te[0]: break
                    if ins.mnemonic not in ("int3", "nop", "nopw", "nopl"): b.append(ins.mnemonic)
                lcs = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
        except Exception:
            pass
        sc = 0.40 * cos + 0.30 * counts + 0.30 * lcs
        return sc, {"score": round(sc, 4), "hist": round(cos, 4), "lcs": round(lcs, 4)}
    except Exception:
        return 0.0, {}


# --------------------------------------------------------------- confidence
def confidence_level(r, old=None):
    """Return (level, score, reasons) for a chosen row or a preserved baseline."""
    if r is None:
        if old is None:
            return "low", None, ["no candidate"]
        c = old.get("confidence")
        ds = old.get("disasm") or {}
        sc = ds.get("score") if isinstance(ds, dict) else None
        if c == "high" or old.get("disasm_status") == "high":
            lv = "high"
        elif c == "medium" or old.get("disasm_status") == "medium":
            lv = "medium"
        else:
            lv = "low"
        return lv, sc, ["baseline " + str(c or old.get("disasm_status") or "unknown")]
    reasons = []
    if r.get("sig_issues"):
        reasons.extend("signature: " + x for x in r["sig_issues"])
    cd = r.get("call_delta")
    if cd is not None:
        reasons.append("call_delta=%.4f" % cd)
    if r.get("lcs_align"):
        reasons.append("class_lcs=1")
    if r.get("align"):
        reasons.append("method_align=1")
    if r.get("name"):
        reasons.append("name_match")
    if r.get("mod", 0) >= 0.6:
        reasons.append("modifier_match=%.2f" % r.get("mod", 0))
    if r.get("body"):
        reasons.append("body=%.3f" % r.get("body", 0))
    reasons.append("class_score=%.3f" % r.get("class_score", 0))
    # Confidence is evidence-class, not a calibrated probability.
    if cd is not None and cd <= 0.003:
        lv = "high"
    elif cd is not None and cd <= 0.012:
        lv = "medium"
    elif r.get("lcs_align") and r.get("mod", 0) >= 0.6 and r.get("class_score", 0) >= 0.60:
        lv = "high"
    elif r.get("align") and r.get("mod", 0) >= 0.6:
        lv = "medium"
    elif r.get("body", 0) >= 0.90:
        lv = "medium"
    else:
        lv = "low"
    if r.get("sig_issues"):
        lv = "low"
    return lv, r.get("score"), reasons


def enrich_confidence(out, report, base, T):
    """Add per-entry confidence fields without changing the selected address."""
    for name, v in out.items():
        old = base.get(name, {})
        # report rows are keyed by VA, while the result stores both RVA and VA.
        target = v.get("target_va") or v.get("target_rva")
        old_target = old.get("target_va") or old.get("target_rva")
        row = None
        if target:
            row = next((r for r in report.get(name, [])
                        if r.get("addr", "").lower() == str(target).lower()), None)
        if row is None and old_target:
            row = next((r for r in report.get(name, [])
                        if r.get("addr", "").lower() == str(old_target).lower()), None)
        if row is None and v.get("target_rva"):
            va = "0x%X" % (0x140000000 + int(v["target_rva"], 16))
            row = next((r for r in report.get(name, [])
                        if r.get("addr", "").lower() == va.lower()), None)
        lv, score, reasons = confidence_level(row, old)
        # The selected target may differ from the baseline target (especially
        # for rescued entries).  Always compare the source declaration with
        # the actually selected target declaration.
        sdecl = v.get("source_decl") or old.get("source_decl", "")
        tdecl = v.get("target_decl") or old.get("target_decl", "")
        si = signature_issues(sdecl, tdecl)
        if si:
            reasons.extend("signature: " + x for x in si)
            lv = "low"
        # Exact class/name/signature is a strong metadata confirmation even
        # when no call-site exists (mostly Unity/engine methods).
        exact_meta = False
        try:
            sc = v.get("source_class") or old.get("source_class")
            sd = v.get("source_decl") or old.get("source_decl")
            tc = v.get("target_class"); td = v.get("target_decl")
            sn = old.get("target_name")
            # source class is in old; target name metadata exact if class
            # and declaration both match.
            exact_meta = bool(sc and tc and sc == tc and sd and td and sd == td)
        except Exception:
            pass
        if exact_meta and lv == "low":
            lv = "medium"
            reasons.append("exact_class+signature")
        if exact_meta and lv == "medium":
            lv = "high"
            reasons.append("exact_class+signature")
        v["confidence_level"] = lv
        v["confidence_score"] = round(score, 4) if isinstance(score, (int, float)) else None
        v["confidence_reasons"] = reasons
        v["review_required"] = bool(v.get("review_required") or lv != "high" or not exact_meta)


# --------------------------------------------------------------- dump cache
def load_dump_cached(path, cache_dir):
    """Load DA.parse_dump output through a pickle cache keyed by file identity."""
    st = os.stat(path)
    key = hashlib.sha1(("%s:%s:%s" % (os.path.abspath(path), st.st_size, st.st_mtime_ns)).encode()).hexdigest()[:16]
    os.makedirs(cache_dir, exist_ok=True)
    # bump this when the parsed dump schema changes (e.g. class kind)
    cp = os.path.join(cache_dir, "dump_v2_%s_%s.pkl" % (os.path.basename(path).replace(".", "_"), key))
    if os.path.exists(cp):
        try:
            return pickle.load(open(cp, "rb"))
        except Exception:
            pass
    d = DA.parse_dump(path)
    try:
        tmp = cp + ".tmp"
        pickle.dump(d, open(tmp, "wb"), protocol=5)
        os.replace(tmp, cp)
    except Exception:
        pass
    return d


# ------------------------------------------------------- parallel candidates
_JOB_CTX = None


def _build_job(h, S, T, base, by_count, max_classes,
               sseq_by_full, tseq_by_full, name_index, score_cache):
    name = h["hook_method"]
    b = base.get(name, {})
    if b.get("status") not in ("matched", "ambiguous_class", "no_class", "no_method"):
        return name, None
    scls, sm, si = src_method(S, h)
    if not scls or not sm:
        return name, None
    sfull = h.get("fullname", "")
    sseq = sseq_by_full.get(sfull)
    if sseq is None:
        sseq = DA.class_seq(scls)
        sseq_by_full[sfull] = sseq
    n = len(sseq)
    cnames = []
    if b.get("target_class"):
        cnames.append(b["target_class"])
    for x in b.get("class_candidates", []):
        if x.get("class"):
            cnames.append(x["class"])
    for cnt in range(max(1, int(n * 0.45)), int(n * 2.2) + 2):
        for full in by_count.get(cnt, []):
            cnames.append(full)
    # name/shape index is built once; retain T iteration order.
    for full in name_index.get((sm["name"], sm["shape"]), []):
        c = T.get(full)
        if not c:
            continue
        if len(c["methods"]) < max(1, int(n * 0.4)) or len(c["methods"]) > int(n * 2.2) + 2:
            continue
        cnames.append(full)
    cnames = list(dict.fromkeys(cnames))
    scored_cls = []
    for full in cnames:
        c = T.get(full)
        if not c:
            continue
        ckey = (sfull, full)
        sc = score_cache.get(ckey)
        if sc is None:
            sc = DA.class_score(sseq, tseq_by_full[full])
            score_cache[ckey] = sc
        outer_bonus = 0.0
        if "." in h.get("fullname", ""):
            parts = h["fullname"].split(".")
            for k in range(len(parts) - 1, 0, -1):
                so = ".".join(parts[:k])
                if so not in S:
                    continue
                tparts = full.split(".")
                for j in range(len(tparts) - 1, 0, -1):
                    to = ".".join(tparts[:j])
                    if to in T and len(tparts) - j == 1:
                        okey = (so, to)
                        osc = score_cache.get(okey)
                        if osc is None:
                            osc = DA.class_score(sseq_by_full.setdefault(so, DA.class_seq(S[so])), tseq_by_full[to])
                            score_cache[okey] = osc
                        outer_bonus = max(outer_bonus, 0.35 * osc)
                        break
                if outer_bonus:
                    break
        scored_cls.append((sc + outer_bonus, sc, outer_bonus, full, c))
    scored_cls.sort(key=lambda x: -x[0])
    best_raw = scored_cls[0][1] if scored_cls else 0.0
    scored_cls = [x for x in scored_cls
                  if x[1] >= best_raw - 0.10 or
                  (b.get("target_class") and x[3] == b["target_class"])]
    scored_cls.sort(key=lambda x: -x[0])
    csel = scored_cls[:max_classes]
    if b.get("target_class") and not any(x[3] == b["target_class"] for x in csel):
        c = T.get(b["target_class"])
        if c:
            sc = score_cache.get((sfull, b["target_class"]))
            if sc is None:
                sc = DA.class_score(sseq, tseq_by_full[b["target_class"]])
                score_cache[(sfull, b["target_class"])] = sc
            csel.append((sc, sc, 0.0, b["target_class"], c))
    amap = []
    for sc, rawsc, ob, full, c in csel:
        for m in c["methods"]:
            if m["shape"] != sm["shape"]:
                continue
            addr = "0x%X" % (0x140000000 + m["rva"])
            if addr not in amap:
                amap.append(addr)
    if not amap:
        return name, None
    return name, {"h": h, "b": b, "scls": scls, "sm": sm, "si": si,
                  "csel": csel, "addrs": amap}


def _job_worker(h):
    return _build_job(h, *_JOB_CTX)


# ---------------------------------------------------------- parallel scoring
_SCORE_CTX = None


def _score_job(item, src_xrefs, dst_xrefs, smap, tmap,
               src_pe, dst_pe, md, sends, tends, max_body):
    name, j = item
    sm, scls, si = j["sm"], j["scls"], j["si"]
    sx = [x for x in src_xrefs.get(name, []) if x.get("norm") is not None]
    rows = []
    for sc, rawsc, ob, full, c in j["csel"]:
        for m in c["methods"]:
            if m["shape"] != sm["shape"]:
                continue
            addr = "0x%X" % (0x140000000 + m["rva"])
            tx = [x for x in dst_xrefs.get(addr.lower(), []) if x.get("norm") is not None]
            call = 0.0
            call_delta = None
            call_caller = None
            for x in sx:
                for y in tx:
                    dlt = abs(x["norm"] - y["norm"])
                    v = math.exp(-dlt / 0.030)
                    if v > call:
                        call = v
                        call_delta = dlt
                        call_caller = (x, y)
            caller_ev = 0.0
            caller_detail = None
            if call_caller:
                x, y = call_caller
                sh = nearest_method(smap, x["from"])
                th = nearest_method(tmap, y["from"])
                if sh and th:
                    scl, smm, _, _ = sh
                    tcl, tmm, _, _ = th
                    cs = 1.0 if smm["shape"] == tmm["shape"] else 0.0
                    cm = mod_score(method_mods(smm["decl"]), method_mods(tmm["decl"]))
                    sn = nested_under(scl, j["h"].get("fullname", ""))
                    tn = nested_under(tcl, full)
                    cn = 1.0 if sn == tn else (0.5 if not sn and not tn else 0.0)
                    caller_ev = 0.45 * cs + 0.30 * cm + 0.25 * cn
                    caller_detail = {"src": scl + "::" + smm["name"],
                                     "dst": tcl + "::" + tmm["name"],
                                     "shape": cs, "mods": round(cm, 3), "nested": cn}
            ms = 1.0 if m["shape"] == sm["shape"] else 0.0
            mod = mod_score(method_mods(sm["decl"]), method_mods(m["decl"]))
            sig_issues = signature_issues(sm["decl"], m["decl"])
            # Class kind is a hard structural constraint.  It catches cases
            # where the method signature happens to match but the candidate
            # class is a struct/enum instead of a class (or vice versa).
            sk = scls.get("kind")
            tk = c.get("kind")
            if sk and tk and sk != tk:
                sig_issues.append("class kind %s != %s" % (sk, tk))
            accessor_issue = accessor_modifier_issue(name, sm["decl"], m["decl"])
            if accessor_issue:
                # A setter/getter must not collapse into a virtual lifecycle
                # method with the same argument shape (LateTick vs setter).
                continue
            name_hit = 1.0 if m["name"] == sm["name"] else 0.0
            al, why = DA.align_method(scls, c, sm)
            align = 1.0 if al is not None and al["rva"] == m["rva"] else 0.0
            lcs_align = 0.0
            try:
                smat = difflib.SequenceMatcher(
                    None, [x["shape"] for x in scls["methods"]],
                    [x["shape"] for x in c["methods"]], autojunk=False)
                for bl in smat.get_matching_blocks():
                    if bl.a <= si < bl.a + bl.size:
                        if (bl.b + (si - bl.a)) == c["methods"].index(m):
                            lcs_align = 1.0
                        break
            except Exception:
                pass
            try:
                ordinal = 1.0 - abs(si - c["methods"].index(m)) / max(1, len(scls["methods"]), len(c["methods"]))
            except Exception:
                ordinal = 0.0
            body = 0.0
            bd = {}
            if src_pe and dst_pe and len(rows) < max_body:
                bd = {}
                sv = 0x140000000 + sm["rva"]
                tv = 0x140000000 + m["rva"]
                body, bd = body_score(src_pe, dst_pe, md, sv, tv, sends, tends)
            score = (0.32 * call + 0.10 * caller_ev + 0.11 * align +
                     0.08 * lcs_align + 0.07 * mod + 0.05 * name_hit +
                     0.04 * ms + 0.04 * rawsc + 0.01 * ordinal +
                     0.18 * body)
            rows.append({
                "score": score, "call": call, "call_delta": call_delta,
                "caller": caller_ev, "caller_detail": caller_detail,
                "align": align, "lcs_align": lcs_align, "mod": mod,
                "name": name_hit, "sig_issues": sig_issues,
                "class_score": rawsc, "outer_bonus": ob, "ordinal": ordinal,
                "body": body, "body_detail": bd, "addr": addr, "full": full,
                "method": m, "class": c,
            })
    rows.sort(key=lambda x: -x["score"])
    return name, rows


def _score_worker(item):
    return _score_job(item, *_SCORE_CTX)


# --------------------------------------------------------------- resolver
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-dump", required=True)
    ap.add_argument("--dst-dump", required=True)
    ap.add_argument("--hooks", required=True)
    ap.add_argument("--base", required=True, help="current hk70_best.json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--src-export", default=None)
    ap.add_argument("--dst-export", default=None)
    ap.add_argument("--dst-xrefs", default=None,
                    help="cached target xrefs JSON, or live IDA MCP if omitted")
    ap.add_argument("--save-dst-export", default=None,
                    help="after candidate generation, ask target IDA MCP for an export_funcs cache")
    ap.add_argument("--ida-url", default="http://127.0.0.1:13337/mcp")
    ap.add_argument("--no-ida", action="store_true",
                    help="never query IDA MCP; use only dumps/exports/body evidence")
    ap.add_argument("--src-exe", default=None)
    ap.add_argument("--dst-exe", default=None)
    ap.add_argument("--max-classes", type=int, default=18)
    ap.add_argument("--max-body", type=int, default=300)
    ap.add_argument("--report", default=None)
    ap.add_argument("--timing-json", default=None,
                    help="write per-phase timing JSON")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel worker count for candidate generation/scoring (default 1)")
    ap.add_argument("--dump-cache-dir", default="out/cache",
                    help="pickle cache for parsed dumps (default out/cache)")
    a = ap.parse_args()

    t0 = time.perf_counter()
    timings = []

    def tick(label):
        dt = time.perf_counter() - t0
        timings.append({"phase": label, "seconds": round(dt, 4)})
        print("[timing] %-22s %.3fs" % (label, dt), file=sys.stderr)

    S = load_dump_cached(a.src_dump, a.dump_cache_dir)
    T = load_dump_cached(a.dst_dump, a.dump_cache_dir)
    hooks = load_hooks(a.hooks)
    base = json.load(open(a.base, encoding="utf-8"))
    smap = method_starts(S)
    tmap = method_starts(T)
    src_exp = json.load(open(a.src_export, encoding="utf-8"))["functions"] if a.src_export else {}
    dst_exp = load_target_export(a.dst_export)
    src_pe = sig.PE(a.src_exe) if a.src_exe else None
    dst_pe = sig.PE(a.dst_exe) if a.dst_exe else None
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    sends = build_ends(S)
    tends = build_ends(T)
    tick("load-dumps")

    # target class candidates
    by_count = collections.defaultdict(list)
    for full, c in T.items():
        by_count[len(c["methods"])].append(full)

    # Candidate-generation caches.  These are deterministic indexes of the
    # same immutable dump data; they only remove repeated scans/computations.
    tseq_by_full = {full: DA.class_seq(c) for full, c in T.items()}
    sseq_by_full = {}
    name_index = collections.defaultdict(list)
    for full, c in T.items():
        for m in c["methods"]:
            name_index[(m["name"], m["shape"])].append(full)
    score_cache = {}
    # candidate cache
    jobs = {}
    all_addrs = set()
    global _JOB_CTX
    _JOB_CTX = (S, T, base, by_count, a.max_classes,
                sseq_by_full, tseq_by_full, name_index, score_cache)
    if a.jobs > 1:
        import multiprocessing as mp
        try:
            ctx = mp.get_context("fork")
        except ValueError:
            ctx = mp.get_context()
        with ctx.Pool(processes=a.jobs) as pool:
            pairs = pool.map(_job_worker, hooks, chunksize=1)
    else:
        pairs = [_build_job(h, *_JOB_CTX) for h in hooks]
    for name, job in pairs:
        if not job:
            continue
        jobs[name] = job
        all_addrs.update(a.lower() for a in job["addrs"])
    tick("candidate-generation")

    # Optional: create a reusable --dst-export cache from the live target IDA.
    if a.save_dst_export:
        try:
            n = export_target_cache(sorted(all_addrs), a.ida_url, a.save_dst_export)
            print("target export cache: %d functions -> %s" % (n, a.save_dst_export))
        except Exception as e:
            print("warning: could not save target export cache:", e, file=sys.stderr)

    # xrefs
    dst_xrefs = {}
    if a.dst_export:
        dst_xrefs.update(target_xrefs_from_export(dst_exp, all_addrs))
    if a.dst_xrefs and os.path.exists(a.dst_xrefs):
        d = json.load(open(a.dst_xrefs, encoding="utf-8"))
        for k, v in (d.get("xrefs", d) if isinstance(d, dict) else {}).items():
            if isinstance(k, str):
                dst_xrefs.setdefault(k.lower(), v)
    missing = sorted(set(x.lower() for x in all_addrs) - set(dst_xrefs))
    if missing and not a.no_ida:
        try:
            got = target_xrefs_ida(missing, a.ida_url)
            for k, v in got.items():
                dst_xrefs[k.lower()] = v
        except Exception as e:
            print("warning: target xrefs unavailable:", e, file=sys.stderr)
    if os.environ.get("HOOK_DEBUG_XREFS"):
        print("DBG dst_xrefs=%d all_addrs=%d missing=%d" % (len(dst_xrefs), len(all_addrs), len(missing)), file=sys.stderr)
    # normalize export xrefs and add caller bounds
    for k, xs in dst_xrefs.items():
        for x in xs:
            if x.get("norm") is None:
                hit = nearest_method(tmap, x["from"])
                if hit:
                    _, _, st, en = hit
                    x["start"], x["end"] = st, en
                    x["norm"] = (x["from"] - st) / max(1, en - st)

    src_xrefs = {}
    for name, j in jobs.items():
        xs = []
        for x in (src_exp.get(name, {}).get("xrefs", [])):
            if x.get("type") != "code":
                continue
            addr = int(x["addr"], 16)
            fn = x.get("fn") or {}
            st = None
            nm = fn.get("name", "")
            m = re.search(r"([0-9A-Fa-f]{6,})", nm)
            if m:
                st = int(m.group(1), 16)
            sz = fn.get("size")
            en = st + int(sz, 16) if st is not None and str(sz).startswith("0x") else None
            if not st:
                hit = nearest_method(smap, addr)
                if hit:
                    _, _, st, en = hit
            xs.append({"from": addr, "start": st, "end": en,
                       "norm": (addr - st) / max(1, en - st) if st and en else None})
        src_xrefs[name] = xs
    tick("xrefs")

    # score every candidate
    global _SCORE_CTX
    _SCORE_CTX = (src_xrefs, dst_xrefs, smap, tmap,
                  src_pe, dst_pe, md, sends, tends, a.max_body)
    if a.jobs > 1 and len(jobs) > 1:
        import multiprocessing as mp
        try:
            ctx = mp.get_context("fork")
        except ValueError:
            ctx = mp.get_context()
        with ctx.Pool(processes=a.jobs) as pool:
            pairs = pool.map(_score_worker, list(jobs.items()), chunksize=1)
    else:
        pairs = [_score_job((name, j), *_SCORE_CTX) for name, j in jobs.items()]
    report = {}
    for name, rows in pairs:
        report[name] = rows
    tick("scoring")

    # same-shape group assignment: preserve source order and avoid assigning
    # two hooks to one target method.
    groups = collections.defaultdict(list)
    for name, rows in report.items():
        if not rows:
            continue
        h = jobs[name]["h"]
        groups[(h.get("fullname", ""), jobs[name]["sm"]["shape"])].append(name)
    chosen = {}
    for g, names in groups.items():
        names.sort(key=lambda nm: jobs[nm]["si"])
        if len(names) == 1:
            rows = report[names[0]]
            if rows:
                chosen[names[0]] = rows[0]
            continue
        # small groups only; use combinations of top candidates.
        pools = []
        for nm in names:
            # unique target addresses, deduplicate keeping the best row
            seen = set(); pool = []
            for r in report[nm]:
                if r["addr"] in seen:
                    continue
                seen.add(r["addr"]); pool.append(r)
            pools.append(pool[:8])
        best = None
        def rec(i, used, acc, cost):
            nonlocal best
            if i == len(pools):
                if best is None or cost > best[0]:
                    best = (cost, list(acc))
                return
            for r in pools[i]:
                if r["addr"] in used:
                    continue
                used.add(r["addr"]); acc.append(r)
                rec(i + 1, used, acc, cost + r["score"])
                acc.pop(); used.remove(r["addr"])
        rec(0, set(), [], 0.0)
        if best:
            for nm, r in zip(names, best[1]):
                chosen[nm] = r
    tick("group-assignment")

    # write result; keep old result when the new candidate is not strong
    out = {}
    for h in hooks:
        name = h["hook_method"]
        old = base.get(name, {})
        r = chosen.get(name)
        if not r:
            out[name] = old
            continue
        # confidence gates: either a close call-site match, or strong
        # class/method metadata agreement.
        call_ok = r.get("call_delta") is not None and r["call_delta"] <= 0.035
        meta_ok = (r["align"] >= 1.0 and r["mod"] >= 0.60 and
                   r["class_score"] >= 0.72)
        body_ok = r["body"] >= 0.72
        if not (call_ok or meta_ok or body_ok):
            out[name] = old
            continue
        old_accessor_bad = bool(accessor_modifier_issue(
            name, jobs[name]["sm"]["decl"], old.get("target_decl", "")))
        # don't overwrite an already high-confidence correct mapping unless
        # the evidence is clearly better; this keeps the 56 stable entries.
        if (old.get("status") == "matched"
                and old.get("confidence") in ("high", "medium")
                and not old_accessor_bad):
            # only replace if the old mapping is structurally impossible,
            # or the new candidate wins on class-sequence alignment plus a
            # real score margin over the old candidate.  This keeps the
            # already-correct high-confidence entries stable.
            old_shape = None
            old_row = None
            try:
                old_full = old.get("target_class")
                old_rva = int(old.get("target_rva", "0x0"), 16)
                om = next((m for m in T[old_full]["methods"] if m["rva"] == old_rva), None)
                old_shape = om["shape"] if om else None
                old_addr = "0x%X" % (0x140000000 + old_rva)
                old_row = next((x for x in report.get(name, []) if x["addr"] == old_addr), None)
            except Exception:
                pass
            # A class-sequence/LCS hit is a genuine class-selection
            # correction (MessagePush ABEL vs LBK), not a blind rescore.
            lcs_fix = (r.get("lcs_align", 0) >= 1.0 and
                       (old_row is None or old_row.get("lcs_align", 0) < 1.0) and
                       (old_row is None or r["score"] >= old_row.get("score", 0) + 0.025))
            # A close direct-call-site match is a genuine correction for
            # duplicate wrappers (UI Trigger, Entity getters, ...).
            old_call = old_row.get("call_delta") if old_row else None
            call_fix = (r.get("call_delta") is not None and
                        r["call_delta"] <= 0.012 and
                        (old_call is None or old_call > 0.02))
            # Never change a previously matched high/medium entry on body /
            # shape-alone evidence.  Require a cross-version call-site or
            # class-sequence correction.  Missing/ambiguous entries are free
            # to be filled by the new evidence.
            if old.get("confidence") == "high":
                # High-confidence entries are only replaced by a genuine
                # class-sequence correction.  Call-site matches are useful
                # for medium duplicates but can otherwise overturn a stable
                # mapping (e.g. a callback wrapper).
                if not lcs_fix:
                    out[name] = old
                    continue
            elif not (lcs_fix or call_fix):
                out[name] = old
                continue
        m = r["method"]
        out[name] = {
            "status": "matched",
            "confidence": "auto-evidence",
            "source_class": h.get("fullname"),
            "source_rva": h.get("rva"),
            "source_decl": jobs[name]["sm"]["decl"],
            "target_class": r["full"],
            "class_score": round(r["class_score"], 4),
            "class_match": "auto-shape",
            "method_match": "auto-evidence",
            "target_rva": "0x%X" % m["rva"],
            "target_va": "0x%X" % (0x140000000 + m["rva"]),
            "target_name": m["name"],
            "target_decl": m["decl"],
            "evidence": {k: (round(v, 4) if isinstance(v, float) else v)
                         for k, v in r.items()
                         if k not in ("method", "class")},
            "old_auto": {k: old.get(k) for k in ("target_rva", "target_va", "target_name",
                                                 "target_class", "confidence")},
        }

    enrich_confidence(out, report, base, T)
    tick("write-result")

    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if a.report:
        rep = {}
        for name, rows in report.items():
            rep[name] = [{k: (round(v, 4) if isinstance(v, float) else v)
                          for k, v in r.items() if k not in ("method", "class")}
                         for r in rows[:12]]
        json.dump(rep, open(a.report, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if a.timing_json:
        json.dump({"total_seconds": round(time.perf_counter() - t0, 4),
                   "phases": timings}, open(a.timing_json, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    print("wrote", a.out, "resolved", sum(1 for v in out.values() if v.get("confidence") == "auto-evidence"))
    for name, v in out.items():
        if v.get("confidence") == "auto-evidence":
            print(" ", name, v["target_va"], v["target_class"], v["target_name"])


if __name__ == "__main__":
    main()
