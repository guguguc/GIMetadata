use crate::body::body_score;
use crate::mcp;
use crate::dump::{align_method, class_score, class_seq, parse_dump, Class, Dump, Method};
use crate::pe::Pe;
use anyhow::{Context, Result};
use capstone::prelude::*;
use indexmap::IndexMap;
use rayon::prelude::*;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const IMAGE_BASE: u64 = 0x140000000;

type Csel = Vec<(f64, f64, f64, String, Class)>;
type Starts = Vec<(u64, u64, String, crate::shape::Shape, String, String)>;
type Job = (Value, Class, Method, usize, Csel);

#[derive(Clone, Debug)]
struct Row {
    score: f64,
    call: f64,
    call_delta: Option<f64>,
    caller: f64,
    caller_detail: Option<Value>,
    align: f64,
    lcs_align: f64,
    mod_: f64,
    name: f64,
    class_score: f64,
    outer_bonus: f64,
    ordinal: f64,
    body: f64,
    body_detail: Value,
    sig_issues: Vec<String>,
    addr: String,
    full: String,
    method: Method,
}

fn method_mods(decl: &str) -> (String, bool, bool, bool) {
    let w: HashSet<&str> = decl.split(|c: char| !c.is_alphanumeric() && c != '_').collect();
    let access = ["public", "private", "protected", "internal"]
        .iter().find(|x| w.contains(**x)).unwrap_or(&"private").to_string();
    (
        access,
        w.contains("static"),
        w.contains("virtual") || w.contains("abstract") || w.contains("override"),
        w.contains("abstract"),
    )
}

fn mod_score(a: (String, bool, bool, bool), b: (String, bool, bool, bool)) -> f64 {
    0.60 * (a.0 == b.0) as u8 as f64
        + 0.20 * (a.1 == b.1) as u8 as f64
        + 0.20 * (a.2 == b.2) as u8 as f64
}

fn is_accessor_hook(name: &str) -> bool {
    name.contains("_set_") || name.contains("_get_")
}

fn accessor_issue(name: &str, sdecl: &str, tdecl: &str) -> Option<String> {
    if !is_accessor_hook(name) { return None; }
    let a = method_mods(sdecl); let b = method_mods(tdecl);
    if a.0 != b.0 { return Some("accessor access".into()); }
    if a.1 != b.1 { return Some("accessor static".into()); }
    if !a.2 && b.2 { return Some("accessor non-virtual source became virtual target".into()); }
    None
}

const KNOWN_TYPES: &[&str] = &[
    "void", "bool", "byte", "sbyte", "short", "ushort", "int", "uint", "long",
    "ulong", "float", "double", "string", "object", "char", "decimal",
    "Vector2", "Vector3", "Vector4", "Quaternion", "Color", "Transform",
    "Animator", "Rigidbody", "GameObject", "Component", "Camera", "Text",
    "Button", "Collider", "RigidbodyConstraints", "CursorLockMode", "IntPtr",
];

fn raw_decl(decl: &str) -> (String, Vec<String>) {
    let rt = crate::shape::raw_rtype(decl).rsplit('.').next().unwrap_or("").to_string();
    let Some(open) = decl.find('(') else { return (rt, Vec::new()); };
    let Some(close) = decl.rfind(')') else { return (rt, Vec::new()); };
    if close <= open { return (rt, Vec::new()); }
    let body = &decl[open + 1..close];
    let mut ps = Vec::new(); let mut buf = String::new(); let mut depth = 0i32;
    for ch in body.chars() {
        match ch { '<' | '[' | '(' => depth += 1, '>' | ']' | ')' => depth -= 1, _ => {} }
        if ch == ',' && depth == 0 { ps.push(buf.clone()); buf.clear(); } else { buf.push(ch); }
    }
    if !buf.trim().is_empty() { ps.push(buf); }
    let mut out = Vec::new();
    for p in ps {
        let p = p.split('=').next().unwrap_or("").trim();
        let mut q = p.to_string();
        if !p.ends_with('>') && !p.ends_with(']') && !p.ends_with('*') {
            if let Some(pos) = p.rfind(char::is_whitespace) {
                if p[pos + 1..].chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false) {
                    q = p[..pos].trim().to_string();
                }
            }
        }
        out.push(q.rsplit('.').next().unwrap_or("").to_string());
    }
    (rt, out)
}

fn signature_issues(sdecl: &str, tdecl: &str) -> Vec<String> {
    let (sr, sp) = raw_decl(sdecl);
    let (tr, tp) = raw_decl(tdecl);
    let mut issues = Vec::new();
    if KNOWN_TYPES.contains(&sr.as_str()) && KNOWN_TYPES.contains(&tr.as_str()) && sr != tr {
        issues.push(format!("return {} != {}", sr, tr));
    } else if KNOWN_TYPES.contains(&sr.as_str()) != KNOWN_TYPES.contains(&tr.as_str()) {
        if KNOWN_TYPES.contains(&sr.as_str()) || KNOWN_TYPES.contains(&tr.as_str()) {
            issues.push(format!("return type kind {} != {}", sr, tr));
        }
    }
    if sp.len() != tp.len() {
        issues.push(format!("param count {} != {}", sp.len(), tp.len()));
    } else {
        for (i, (a, b)) in sp.iter().zip(tp.iter()).enumerate() {
            if KNOWN_TYPES.contains(&a.as_str()) && KNOWN_TYPES.contains(&b.as_str()) && a != b {
                issues.push(format!("param{} {} != {}", i, a, b));
            }
        }
    }
    issues
}

fn hook_name(h: &Value) -> String {
    h.get("hook_method").and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn load_hooks(path: &Path) -> Result<Vec<Value>> {
    let v: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if let Some(a) = v.get("rows").and_then(|x| x.as_array()) {
        Ok(a.clone())
    } else if let Some(a) = v.as_array() {
        Ok(a.clone())
    } else {
        anyhow::bail!("hooks JSON has no rows array")
    }
}

fn src_method<'a>(s: &'a Dump, h: &Value) -> Option<(&'a Class, &'a Method, usize)> {
    let fullname = h.get("fullname").and_then(|x| x.as_str()).unwrap_or("");
    let cls = s.get(fullname)?;
    let rva = h.get("rva").and_then(|x| x.as_str())
        .and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok());
    let mut idx = None;
    if let Some(rva) = rva {
        idx = cls.methods.iter().position(|m| m.rva == rva);
    }
    // Python's find_source_method fallback: exact dump_name, then exact
    // dump_decl.  This matters when a hook map keeps an old RVA (Camera).
    if idx.is_none() {
        if let Some(dn) = h.get("dump_name").and_then(|x| x.as_str()) {
            if !dn.is_empty() {
                idx = cls.methods.iter().position(|m| m.name == dn);
            }
        }
    }
    if idx.is_none() {
        if let Some(dd) = h.get("dump_decl").and_then(|x| x.as_str()) {
            if !dd.is_empty() {
                idx = cls.methods.iter().position(|m| m.decl == dd);
            }
        }
    }
    // Match the Python resolver: a uniquely named source method wins over an
    // RVA that points at its neighbour.  Some hook maps contain duplicate
    // hook names whose RVA lands on a different method in the same class.
    let suffix = hook_name(h).rsplit('_').next().unwrap_or("").to_string();
    if !suffix.is_empty() {
        let xs: Vec<usize> = cls.methods.iter().enumerate()
            .filter(|(_, m)| m.name == suffix).map(|(i, _)| i).collect();
        if xs.len() == 1 { idx = Some(xs[0]); }
    }
    let idx = idx?;
    Some((cls, &cls.methods[idx], idx))
}

fn lcs_align(scls: &Class, tcls: &Class, si: usize, ti: usize) -> bool {
    let a: Vec<&crate::shape::Shape> = scls.methods.iter().map(|m| &m.shape).collect();
    let b: Vec<&crate::shape::Shape> = tcls.methods.iter().map(|m| &m.shape).collect();
    for (ai, bj, n) in crate::shape::matching_blocks(&a, &b) {
        if si >= ai && si < ai + n {
            return bj + (si - ai) == ti;
        }
    }
    false
}

fn parse_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

pub struct ResolveArgs {
    pub src_dump: String,
    pub dst_dump: String,
    pub hooks: String,
    pub base: String,
    pub out: String,
    pub report: Option<String>,
    pub src_exe: Option<String>,
    pub dst_exe: Option<String>,
    pub src_export: Option<String>,
    pub dst_export: Option<String>,
    pub max_body: usize,
    pub class_score: f64,
    pub class_margin: f64,
    pub ida_mode: String,
    pub ida_url: String,
    pub jobs: usize,
    pub timing_json: Option<String>,
    pub save_dst_export: Option<String>,
}

#[derive(Clone, Debug)]
struct Xref {
    from: u64,
    norm: Option<f64>,
}

fn hex_u64(v: &Value) -> Option<u64> {
    v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
}

fn build_ends(d: &Dump) -> HashMap<u64, u64> {
    // Python's build_ends uses the global sorted method-start table, not a
    // per-class table.  Function ends therefore cross class boundaries.
    let mut starts: Vec<u64> = d.values()
        .flat_map(|c| c.methods.iter().map(|m| IMAGE_BASE + m.rva as u64))
        .collect();
    starts.sort_unstable();
    starts.dedup();
    starts.iter().enumerate()
        .map(|(i, st)| (*st, *starts.get(i + 1).unwrap_or(&(st + 0x1000))))
        .collect()
}

fn starts_map(d: &Dump) -> Vec<(u64, u64, String, crate::shape::Shape, String, String)> {
    let mut all: Vec<(u64, String, crate::shape::Shape, String, String)> = Vec::new();
    for (full, c) in d {
        for m in &c.methods {
            all.push((IMAGE_BASE + m.rva as u64, full.clone(), m.shape.clone(), m.decl.clone(), m.name.clone()));
        }
    }
    all.sort_by_key(|x| x.0);
    let mut out = Vec::new();
    for (i, x) in all.iter().enumerate() {
        let end = all.get(i + 1).map(|z| z.0).unwrap_or(x.0 + 0x1000);
        out.push((x.0, end, x.1.clone(), x.2.clone(), x.3.clone(), x.4.clone()));
    }
    out
}

fn nearest(starts: &[(u64, u64, String, crate::shape::Shape, String, String)], addr: u64)
    -> Option<(String, crate::shape::Shape, String, String)> {
    let i = starts.partition_point(|x| x.0 <= addr);
    if i == 0 { return None; }
    let x = &starts[i - 1];
    if addr >= x.0 && addr < x.1 {
        Some((x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()))
    } else { None }
}

fn nested_under(full: &str, outer: &str) -> bool {
    !full.is_empty() && !outer.is_empty() && full.starts_with(&(outer.to_string() + "."))
}

fn nearest_bounds(
    starts: &[(u64, u64, String, crate::shape::Shape, String, String)],
    addr: u64,
) -> Option<(u64, u64)> {
    let i = starts.partition_point(|x| x.0 <= addr);
    if i == 0 { return None; }
    let x = &starts[i - 1];
    if addr >= x.0 && addr < x.1 { Some((x.0, x.1)) } else { None }
}

fn caller_start_from_name(name: &str) -> Option<u64> {
    let re = regex::Regex::new(r"([0-9A-Fa-f]{6,})").ok()?;
    let m = re.captures(name)?;
    u64::from_str_radix(&m[1], 16).ok()
}

fn load_src_xrefs(path: &Option<String>, starts: &Starts)
    -> HashMap<String, Vec<Xref>> {
    let mut out = HashMap::new();
    let Some(path) = path else { return out; };
    let Ok(text) = fs::read_to_string(path) else { return out; };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return out; };
    let Some(fs_) = v.get("functions").and_then(|x| x.as_object()) else { return out; };
    for (name, f) in fs_ {
        let mut xs = Vec::new();
        if let Some(arr) = f.get("xrefs").and_then(|x| x.as_array()) {
            for x in arr {
                if x.get("type").and_then(|z| z.as_str()) != Some("code") { continue; }
                let Some(from) = hex_u64(x.get("addr").unwrap_or(&Value::Null)) else { continue; };
                // Python prefers the caller bounds embedded in the source
                // export, then falls back to the dump start table.
                let mut st = None;
                let mut en = None;
                if let Some(fn_) = x.get("fn") {
                    if let Some(nm) = fn_.get("name").and_then(|z| z.as_str()) {
                        st = caller_start_from_name(nm);
                    }
                    if let Some(sz) = fn_.get("size").and_then(|z| z.as_str()) {
                        if let (Some(s), true) = (st, sz.starts_with("0x")) {
                            en = u64::from_str_radix(&sz[2..], 16).ok().map(|n| s + n);
                        }
                    }
                    if st.is_none() {
                        if let Some((s, e)) = nearest_bounds(starts, from) {
                            st = Some(s); en = Some(e);
                        }
                    }
                } else if let Some((s, e)) = nearest_bounds(starts, from) {
                    st = Some(s); en = Some(e);
                }
                let norm = match (st, en) {
                    (Some(s), Some(e)) if e > s => Some((from - s) as f64 / (e - s) as f64),
                    _ => None,
                };
                xs.push(Xref { from, norm });
            }
        }
        out.insert(name.clone(), xs);
    }
    out
}

fn load_dst_xrefs(path: &Option<String>, starts: &[(u64, u64, String, crate::shape::Shape, String, String)])
    -> HashMap<String, Vec<Xref>> {
    let mut out = HashMap::new();
    let Some(path) = path else { return out; };
    let Ok(text) = fs::read_to_string(path) else { return out; };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return out; };
    let Some(fs_) = v.get("functions").and_then(|x| x.as_array()) else { return out; };
    for f in fs_ {
        let Some(addr) = f.get("addr").and_then(|x| x.as_str()) else { continue; };
        let mut xs = Vec::new();
        if let Some(arr) = f.get("xrefs").and_then(|x| x.get("to")).and_then(|x| x.as_array()) {
            for x in arr {
                if x.get("type").and_then(|z| z.as_str()) != Some("code") { continue; }
                let Some(from) = hex_u64(x.get("addr").unwrap_or(&Value::Null)) else { continue; };
                let norm = nearest_bounds(starts, from)
                    .map(|(s, e)| (from - s) as f64 / (e - s).max(1) as f64);
                xs.push(Xref { from, norm });
            }
        }
        out.insert(addr.to_lowercase(), xs);
    }
    out
}


fn build_job(
    h: &Value,
    s: &Dump,
    t: &Dump,
    base_map: &Map<String, Value>,
    by_count: &HashMap<usize, Vec<String>>,
    tseq: &HashMap<String, Vec<crate::shape::Shape>>,
    name_index: &HashMap<(String, crate::shape::Shape), Vec<String>>,
) -> Option<(String, Job)> {
    let name = hook_name(h);
    let (scls, sm, si) = src_method(s, h)?;
    let sfull = h.get("fullname").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let sseq = class_seq(scls);
    let mut cnames: Vec<String> = Vec::new();
    if let Some(x) = base_map.get(&name).and_then(|v| v.get("target_class")).and_then(|v| v.as_str()) {
        cnames.push(x.to_string());
    }
    if let Some(x) = base_map.get(&name).and_then(|v| v.get("class_candidates")).and_then(|v| v.as_array()) {
        for z in x { if let Some(x) = z.get("class").and_then(|x| x.as_str()) { cnames.push(x.to_string()); } }
    }
    let lo = (sseq.len() as f64 * 0.45).max(1.0) as usize;
    let hi = (sseq.len() as f64 * 2.2) as usize + 2;
    for cnt in lo..=hi {
        if let Some(v) = by_count.get(&cnt) { cnames.extend(v.iter().cloned()); }
    }
    if let Some(v) = name_index.get(&(sm.name.clone(), sm.shape.clone())) { cnames.extend(v.iter().cloned()); }
    let mut seen = HashSet::new();
    cnames.retain(|x| seen.insert(x.clone()));
    let mut scored: Vec<(f64, f64, f64, String, Class)> = Vec::new();
    for full in cnames {
        let Some(c) = t.get(&full) else { continue };
        let n = c.methods.len();
        if n < (sseq.len() as f64 * 0.40).max(1.0) as usize || n > (sseq.len() as f64 * 2.2) as usize + 2 { continue; }
        let sc = class_score(&sseq, &tseq[&full]);
        let mut outer_bonus = 0.0f64;
        if sfull.contains('.') {
            let sp: Vec<&str> = sfull.split('.').collect();
            let tp: Vec<&str> = full.split('.').collect();
            for k in (1..sp.len()).rev() {
                let so = sp[..k].join(".");
                let Some(soc) = s.get(&so) else { continue };
                for j in (1..tp.len()).rev() {
                    let to = tp[..j].join(".");
                    if let Some(_toc) = t.get(&to) {
                        if tp.len() - j == 1 {
                            let osc = class_score(&class_seq(soc), &tseq[&to]);
                            outer_bonus = outer_bonus.max(0.35 * osc);
                            break;
                        }
                    }
                }
                if outer_bonus > 0.0 { break; }
            }
        }
        scored.push((sc + outer_bonus, sc, outer_bonus, full.clone(), c.clone()));
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let best_raw = scored.first().map(|x| x.1).unwrap_or(0.0);
    scored.retain(|x| x.1 >= best_raw - 0.10
        || base_map.get(&name).and_then(|v| v.get("target_class")).and_then(|v| v.as_str()) == Some(&x.3));
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if scored.is_empty() { return None; }
    let csel = scored.into_iter().take(18).collect();
    Some((name, (h.clone(), scls.clone(), sm.clone(), si, csel)))
}

fn round4(x: f64) -> f64 { (x * 10000.0).round() / 10000.0 }

pub fn run(a: ResolveArgs) -> Result<()> {
    let t0 = std::time::Instant::now();
    let s = parse_dump(Path::new(&a.src_dump))?;
    let t = parse_dump(Path::new(&a.dst_dump))?;
    let hooks = load_hooks(Path::new(&a.hooks))?;
    let base: Value = serde_json::from_str(&fs::read_to_string(&a.base)?)?;
    let base_map = base.as_object().cloned().unwrap_or_default();

    let by_count: HashMap<usize, Vec<String>> = {
        let mut m: HashMap<usize, Vec<String>> = HashMap::new();
        for (full, c) in &t { m.entry(c.methods.len()).or_default().push(full.clone()); }
        m
    };
    let tseq: HashMap<String, Vec<crate::shape::Shape>> =
        t.iter().map(|(k, c)| (k.clone(), class_seq(c))).collect();
    let mut name_index: HashMap<(String, crate::shape::Shape), Vec<String>> = HashMap::new();
    for (full, c) in &t {
        for m in &c.methods { name_index.entry((m.name.clone(), m.shape.clone())).or_default().push(full.clone()); }
    }
    let src_starts = starts_map(&s);
    let dst_starts = starts_map(&t);
    let src_xrefs = load_src_xrefs(&a.src_export, &src_starts);
    let mut dst_xrefs = load_dst_xrefs(&a.dst_export, &dst_starts);
    let src_pe = a.src_exe.as_ref().map(|p| Pe::open(Path::new(p))).transpose()?;
    let dst_pe = a.dst_exe.as_ref().map(|p| Pe::open(Path::new(p))).transpose()?;
    let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().ok();
    let ends_s = build_ends(&s);
    let ends_t = build_ends(&t);

    let job_pairs: Vec<(String, Job)> = if a.jobs > 1 {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(a.jobs).build()?;
        pool.install(|| hooks.par_iter()
            .filter_map(|h| build_job(h, &s, &t, &base_map, &by_count, &tseq, &name_index))
            .collect())
    } else {
        hooks.iter()
            .filter_map(|h| build_job(h, &s, &t, &base_map, &by_count, &tseq, &name_index))
            .collect()
    };
    let mut jobs: IndexMap<String, Job> = IndexMap::new();
    for (name, job) in job_pairs { jobs.insert(name, job); }

    // Target addresses that need xrefs.  Python queries only cache-missing
    // candidate addresses, not every address in the dump.
    let mut all_addrs: Vec<String> = Vec::new();
    {
        let mut seen = HashSet::new();
        for (_h, _scls, sm, _si, csel) in jobs.values() {
            for (_total, _raw, _ob, _full, c) in csel {
                for m in &c.methods {
                    if m.shape != sm.shape { continue; }
                    let addr = format!("0x{:X}", IMAGE_BASE + m.rva as u64);
                    if seen.insert(addr.clone()) { all_addrs.push(addr); }
                }
            }
        }
    }
    if a.ida_mode == "mcp" {
        if let Some(path) = &a.save_dst_export {
            match mcp::export_funcs(&all_addrs, &a.ida_url) {
                Ok(v) => {
                    fs::write(path, serde_json::to_string_pretty(&v)?)?;
                    eprintln!("target export cache: {} functions -> {}", all_addrs.len(), path);
                }
                Err(e) => eprintln!("warning: could not save target export: {e}"),
            }
        }
        let missing: Vec<String> = all_addrs.iter()
            .map(|x| x.to_lowercase())
            .filter(|x| !dst_xrefs.contains_key(x))
            .collect();
        if !missing.is_empty() {
            match mcp::target_xrefs(&missing, &a.ida_url) {
                Ok(v) => {
                    if let Some(obj) = v.as_object() {
                        for (addr, xs) in obj {
                            let mut out = Vec::new();
                            if let Some(arr) = xs.as_array() {
                                for x in arr {
                                    let Some(from) = x.get("from").and_then(|z| z.as_u64()) else { continue; };
                                    let norm = x.get("norm").and_then(|z| z.as_f64())
                                        .or_else(|| nearest_bounds(&dst_starts, from)
                                            .map(|(s, e)| (from - s) as f64 / (e - s).max(1) as f64));
                                    out.push(Xref { from, norm });
                                }
                            }
                            dst_xrefs.insert(addr.to_lowercase(), out);
                        }
                    }
                }
                Err(e) => eprintln!("warning: target xrefs unavailable: {e}"),
            }
        }
    }

    // score candidates
    let jobs_vec: Vec<(&String, &Job)> = jobs.iter().collect();
    let pairs: Vec<(String, Vec<Row>)> = if a.jobs > 1 {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(a.jobs).build()?;
        pool.install(|| jobs_vec.par_iter()
            .map(|(name, job)| ((*name).clone(), score_job(name, job, &a,
                &src_pe, &dst_pe, &src_starts, &dst_starts, &src_xrefs, &dst_xrefs,
                &ends_s, &ends_t)))
            .collect())
    } else {
        jobs_vec.iter()
            .map(|(name, job)| ((*name).clone(), score_job(name, job, &a,
                &src_pe, &dst_pe, &src_starts, &dst_starts, &src_xrefs, &dst_xrefs,
                &ends_s, &ends_t)))
            .collect()
    };
    let mut report: IndexMap<String, Vec<Row>> = IndexMap::new();
    for (name, rows) in pairs { report.insert(name, rows); }

    // group assignment
    let mut groups: HashMap<(String, crate::shape::Shape), Vec<String>> = HashMap::new();
    for (name, (h, _, _, _, _)) in &jobs {
        let fullname = h.get("fullname").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if let Some((_, _, sm, _, _)) = jobs.get(name) {
            groups.entry((fullname, sm.shape.clone())).or_default().push(name.clone());
        }
    }
    let mut chosen: HashMap<String, Row> = HashMap::new();
    for (_g, mut names) in groups {
        names.sort_by_key(|n| jobs[n].3);
        if names.len() == 1 {
            if let Some(r) = report.get(&names[0]).and_then(|x| x.first()) { chosen.insert(names[0].clone(), r.clone()); }
            continue;
        }
        let pools: Vec<Vec<Row>> = names.iter().map(|n| {
            let mut seen = HashSet::new();
            report.get(n).map(|rows| rows.iter().filter(|r| seen.insert(r.addr.clone())).take(8).cloned().collect()).unwrap_or_default()
        }).collect();
        let mut best: Option<(f64, Vec<Row>)> = None;
        fn rec(i: usize, pools: &[Vec<Row>], used: &mut HashSet<String>, acc: &mut Vec<Row>, cost: f64, best: &mut Option<(f64, Vec<Row>)>) {
            if i == pools.len() {
                if best.as_ref().map(|x| cost > x.0).unwrap_or(true) { *best = Some((cost, acc.clone())); }
                return;
            }
            for r in &pools[i] {
                if used.contains(&r.addr) { continue; }
                used.insert(r.addr.clone()); acc.push(r.clone());
                rec(i + 1, pools, used, acc, cost + r.score, best);
                acc.pop(); used.remove(&r.addr);
            }
        }
        rec(0, &pools, &mut HashSet::new(), &mut Vec::new(), 0.0, &mut best);
        if let Some((_, rows)) = best {
            for (n, r) in names.iter().zip(rows) { chosen.insert(n.clone(), r); }
        }
    }

    // write result
    let mut out = Map::new();
    for h in &hooks {
        let name = hook_name(h);
        let old = base_map.get(&name).cloned().unwrap_or(Value::Null);
        let Some(r) = chosen.get(&name) else { out.insert(name, old); continue; };
        let call_ok = r.call_delta.map(|d| d <= 0.035).unwrap_or(false);
        let meta_ok = r.align >= 1.0 && r.mod_ >= 0.60 && r.class_score >= 0.72;
        let body_ok = r.body >= 0.72;
        if !(call_ok || meta_ok || body_ok) { out.insert(name, old); continue; }
        if let Some(old)=old.as_object() {
            let old_bad = old.get("target_decl").and_then(|x| x.as_str())
                .map(|d| accessor_issue(&name, &jobs.get(&name).map(|x| x.2.decl.clone()).unwrap_or_default(), d).is_some())
                .unwrap_or(false);
            if !old_bad && old.get("status").and_then(|x| x.as_str()) == Some("matched")
                && matches!(old.get("confidence").and_then(|x| x.as_str()), Some("high") | Some("medium")) {
                let old_va = old.get("target_va").and_then(|x| x.as_str())
                    .and_then(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok());
                let old_rva = old.get("target_rva").and_then(|x| x.as_str())
                    .and_then(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok());
                let old_addr = old_va.or(old_rva.map(|x| IMAGE_BASE + x))
                    .map(|x| format!("0x{:X}", x));
                let old_row = old_addr.as_ref().and_then(|a| report.get(&name)
                    .and_then(|rows| rows.iter().find(|q| q.addr.eq_ignore_ascii_case(a))));
                let lcs_fix = r.lcs_align >= 1.0
                    && old_row.map(|q| q.lcs_align < 1.0).unwrap_or(true)
                    && old_row.map(|q| r.score >= q.score + 0.025).unwrap_or(true);
                let call_fix = r.call_delta.map(|d| d <= 0.012).unwrap_or(false)
                    && old_row.map(|q| q.call_delta.map(|d| d > 0.02).unwrap_or(true)).unwrap_or(true);
                if old.get("confidence").and_then(|x| x.as_str()) == Some("high") {
                    if !lcs_fix { out.insert(name, old.clone().into()); continue; }
                } else if !(lcs_fix || call_fix) {
                    out.insert(name, old.clone().into()); continue;
                }
            }
        }
        let m = &r.method;
        let source_decl = jobs.get(&name).map(|x| x.2.decl.clone()).unwrap_or_default();
        let mut v = Map::new();
        v.insert("status".into(), json!("matched"));
        v.insert("confidence".into(), json!("auto-evidence"));
        v.insert("source_class".into(), h.get("fullname").cloned().unwrap_or(Value::Null));
        v.insert("source_rva".into(), h.get("rva").cloned().unwrap_or(Value::Null));
        v.insert("source_decl".into(), json!(source_decl));
        v.insert("target_class".into(), json!(r.full));
        v.insert("class_score".into(), json!((r.class_score * 10000.0).round() / 10000.0));
        v.insert("class_match".into(), json!("auto-shape"));
        v.insert("method_match".into(), json!("auto-evidence"));
        v.insert("target_rva".into(), json!(format!("0x{:X}", m.rva)));
        v.insert("target_va".into(), json!(format!("0x{:X}", IMAGE_BASE + m.rva as u64)));
        v.insert("target_name".into(), json!(m.name));
        v.insert("target_decl".into(), json!(m.decl));
        v.insert("evidence".into(), json!({
            "score": round4(r.score),
            "call": round4(r.call),
            "call_delta": r.call_delta.map(round4),
            "caller": round4(r.caller),
            "caller_detail": r.caller_detail,
            "align": round4(r.align),
            "lcs_align": round4(r.lcs_align),
            "mod": round4(r.mod_),
            "name": round4(r.name),
            "sig_issues": r.sig_issues,
            "class_score": round4(r.class_score),
            "outer_bonus": round4(r.outer_bonus),
            "ordinal": round4(r.ordinal),
            "body": round4(r.body),
            "body_detail": r.body_detail,
            "addr": r.addr,
            "full": r.full
        }));
        out.insert(name, Value::Object(v));
    }

    // Add confidence fields without changing selected addresses.
    for (name, v) in out.iter_mut() {
        let old = base_map.get(name).cloned().unwrap_or(Value::Null);
        let target = v.get("target_va").and_then(|x| x.as_str()).map(|x| x.to_lowercase())
            .or_else(|| v.get("target_rva").and_then(|x| x.as_str()).map(|x| x.to_lowercase()));
        let old_target = old.get("target_va").and_then(|x| x.as_str()).map(|x| x.to_lowercase())
            .or_else(|| old.get("target_rva").and_then(|x| x.as_str()).map(|x| x.to_lowercase()));
        let mut row: Option<&Row> = None;
        if let Some(t) = &target {
            row = report.get(name).and_then(|rs| rs.iter().find(|r| r.addr.to_lowercase() == *t));
        }
        if row.is_none() {
            if let Some(t) = &old_target {
                row = report.get(name).and_then(|rs| rs.iter().find(|r| r.addr.to_lowercase() == *t));
            }
        }
        let mut reasons: Vec<String> = Vec::new();
        let issues = row.map(|r| r.sig_issues.clone()).unwrap_or_default();
        for x in &issues { reasons.push(format!("signature: {}", x)); }
        let (mut level, mut score) = if let Some(r) = row {
            if let Some(d) = r.call_delta { reasons.push(format!("call_delta={:.4}", d)); }
            if r.lcs_align >= 1.0 { reasons.push("class_lcs=1".into()); }
            if r.align >= 1.0 { reasons.push("method_align=1".into()); }
            if r.name >= 1.0 { reasons.push("name_match".into()); }
            if r.mod_ >= 0.6 { reasons.push(format!("modifier_match={:.2}", r.mod_)); }
            if r.body > 0.0 { reasons.push(format!("body={:.3}", r.body)); }
            reasons.push(format!("class_score={:.3}", r.class_score));
            let lv = if let Some(d) = r.call_delta {
                if d <= 0.003 { "high" } else if d <= 0.012 { "medium" } else { "" }
            } else { "" };
            let lv = if !lv.is_empty() { lv }
                else if r.lcs_align >= 1.0 && r.mod_ >= 0.6 && r.class_score >= 0.60 { "high" }
                else if r.align >= 1.0 && r.mod_ >= 0.6 { "medium" }
                else if r.body >= 0.90 { "medium" }
                else { "low" };
            (lv.to_string(), Some(r.score))
        } else {
            let c = old.get("confidence").and_then(|x| x.as_str()).unwrap_or("");
            let ds = old.get("disasm_status").and_then(|x| x.as_str()).unwrap_or("");
            let lv = if c == "high" || ds == "high" { "high" }
                else if c == "medium" || ds == "medium" { "medium" } else { "low" };
            reasons.push(format!("baseline {}", if c.is_empty() { ds } else { c }));
            let sc = old.get("disasm").and_then(|x| x.get("score")).and_then(|x| x.as_f64());
            (lv.to_string(), sc)
        };
        if !issues.is_empty() { level = "low".into(); }
        let out_sdecl = v.get("source_decl").and_then(|x| x.as_str()).unwrap_or("");
        let out_tdecl = v.get("target_decl").and_then(|x| x.as_str()).unwrap_or("");
        let out_issues = signature_issues(out_sdecl, out_tdecl);
        for x in &out_issues { reasons.push(format!("signature: {}", x)); }
        if !out_issues.is_empty() { level = "low".into(); }
        let exact_meta = {
            let sc = v.get("source_class").and_then(|x| x.as_str());
            let tc = v.get("target_class").and_then(|x| x.as_str());
            let sd = v.get("source_decl").and_then(|x| x.as_str());
            let td = v.get("target_decl").and_then(|x| x.as_str());
            sc.is_some() && sc == tc && sd.is_some() && sd == td
        };
        if exact_meta && level == "low" { level = "medium".into(); reasons.push("exact_class+signature".into()); }
        if exact_meta && level == "medium" { level = "high".into(); reasons.push("exact_class+signature".into()); }
        v["confidence_level"] = json!(level);
        v["confidence_score"] = json!(score.map(|x| (x * 10000.0).round() / 10000.0));
        v["confidence_reasons"] = json!(reasons);
        v["review_required"] = json!(
            v.get("review_required").and_then(|x| x.as_bool()).unwrap_or(false)
            || level != "high" || !exact_meta);
        if v.get("confidence").and_then(|x| x.as_str()) == Some("auto-evidence") {
            let mut oa = Map::new();
            for k in ["target_rva", "target_va", "target_name", "target_class", "confidence"] {
                oa.insert(k.into(), old.get(k).cloned().unwrap_or(Value::Null));
            }
            v["old_auto"] = Value::Object(oa);
        }
    }

    let outv = Value::Object(out);
    fs::write(&a.out, serde_json::to_string_pretty(&outv)?)?;
    if let Some(p) = &a.report {
        let mut rep = Map::new();
        for (k, rows) in &report {
            let arr: Vec<Value> = rows.iter().take(12).map(|r| json!({
                "score": (r.score * 10000.0).round() / 10000.0,
                "call": r.call,
                "call_delta": r.call_delta,
                "caller": r.caller,
                "caller_detail": r.caller_detail,
                "align": r.align,
                "lcs_align": r.lcs_align,
                "mod": r.mod_,
                "name": r.name,
                "sig_issues": r.sig_issues,
                "class_score": r.class_score,
                "outer_bonus": r.outer_bonus,
                "ordinal": r.ordinal,
                "body": r.body,
                "body_detail": r.body_detail,
                "addr": r.addr,
                "full": r.full,
            })).collect();
            rep.insert(k.clone(), Value::Array(arr));
        }
        fs::write(p, serde_json::to_string_pretty(&Value::Object(rep))?)?;
    }
    eprintln!("[timing] total {:.3}s", t0.elapsed().as_secs_f64());
    println!("wrote {} entries", jobs.len());
    Ok(())
}


fn score_job(
    name: &str,
    job: &Job,
    a: &ResolveArgs,
    src_pe: &Option<Pe>,
    dst_pe: &Option<Pe>,
    src_starts: &Starts,
    dst_starts: &Starts,
    src_xrefs: &HashMap<String, Vec<Xref>>,
    dst_xrefs: &HashMap<String, Vec<Xref>>,
    ends_s: &HashMap<u64, u64>,
    ends_t: &HashMap<u64, u64>,
) -> Vec<Row> {
    let (h, scls, sm, si, csel) = job;
    let cs0 = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().ok();
    let mut rows: Vec<Row> = Vec::new();
    for (_total, rawsc, outer_bonus, full, c) in csel {
        for m in &c.methods {
            if m.shape != sm.shape { continue; }
            if accessor_issue(name, &sm.decl, &m.decl).is_some() { continue; }
            let mod_ = mod_score(method_mods(&sm.decl), method_mods(&m.decl));
            let mut sig_issues = signature_issues(&sm.decl, &m.decl);
            if !scls.kind.is_empty() && !c.kind.is_empty() && scls.kind != c.kind {
                sig_issues.push(format!("class kind {} != {}", scls.kind, c.kind));
            }
            let name_hit = (m.name == sm.name) as u8 as f64;
            let align = match align_method(scls, c, sm) {
                Some((al, _why)) if al.rva == m.rva => 1.0,
                _ => 0.0,
            };
            let ti = c.methods.iter().position(|x| x.rva == m.rva).unwrap_or(0);
            let lcs_align = lcs_align(scls, c, *si, ti) as u8 as f64;
            let ordinal = 1.0 - (*si as f64 - ti as f64).abs()
                / scls.methods.len().max(c.methods.len()).max(1) as f64;
            let sx: Vec<&Xref> = src_xrefs.get(name)
                .map(|x| x.iter().filter(|q| q.norm.is_some()).collect())
                .unwrap_or_default();
            let tx: Vec<&Xref> = dst_xrefs.get(&format!("0x{:X}", IMAGE_BASE + m.rva as u64).to_lowercase())
                .map(|x| x.iter().filter(|q| q.norm.is_some()).collect())
                .unwrap_or_default();
            if std::env::var("HOOK_DEBUG_XREFS").ok().as_deref() == Some(name) {
                eprintln!("DBG {} src={:?} dst={:?}", name,
                    sx.iter().map(|x| (x.from, x.norm)).collect::<Vec<_>>(),
                    tx.iter().map(|x| (x.from, x.norm)).collect::<Vec<_>>());
            }
            let mut call = 0.0f64;
            let mut call_delta = None;
            let mut call_pair: Option<(&Xref, &Xref)> = None;
            for x in &sx {
                for y in &tx {
                    let d = (x.norm.unwrap() - y.norm.unwrap()).abs();
                    let v = (-d / 0.030).exp();
                    if v > call {
                        call = v;
                        call_delta = Some(d);
                        call_pair = Some((x, y));
                    }
                }
            }
            let mut caller = 0.0f64;
            let mut caller_detail = None;
            if let Some((x, y)) = call_pair {
                if let (Some((scl, sshape, sdecl, sname)),
                        Some((tcl, tshape, tdecl, tname))) =
                    (nearest(&src_starts, x.from), nearest(&dst_starts, y.from))
                {
                    let sh = (sshape == tshape) as u8 as f64;
                    let cm = mod_score(method_mods(&sdecl), method_mods(&tdecl));
                    let sfn = h.get("fullname").and_then(|z| z.as_str()).unwrap_or("");
                    let sn = nested_under(&scl, sfn);
                    let tn = nested_under(&tcl, full);
                    let cn = if sn == tn { 1.0 } else if !sn && !tn { 0.5 } else { 0.0 };
                    caller = 0.45 * sh + 0.30 * cm + 0.25 * cn;
                    caller_detail = Some(json!({
                        "src": format!("{scl}::{sname}"),
                        "dst": format!("{tcl}::{tname}"),
                        "shape": sh,
                        "mods": (cm * 1000.0).round() / 1000.0,
                        "nested": cn,
                    }));
                }
            }
            let mut body = 0.0;
            let mut body_detail = json!({});
            if rows.len() < a.max_body {
                if let (Some(sp), Some(dp), Some(cs0)) = (src_pe, dst_pe, cs0.as_ref()) {
                    let sv = IMAGE_BASE + sm.rva as u64;
                    let tv = IMAGE_BASE + m.rva as u64;
                    if let (Some(se), Some(te)) = (ends_s.get(&sv), ends_t.get(&tv)) {
                        (body, body_detail) = body_score(cs0, sp, dp, sv, tv, *se, *te);
                    }
                }
            }
            let score = 0.32 * call + 0.10 * caller + 0.11 * align + 0.08 * lcs_align
                + 0.07 * mod_ + 0.05 * name_hit + 0.04 * 1.0
                + 0.04 * *rawsc + 0.01 * ordinal + 0.18 * body;
            rows.push(Row {
                score, call, call_delta, caller, caller_detail, align, lcs_align,
                mod_, name: name_hit, class_score: *rawsc, outer_bonus: *outer_bonus,
                ordinal, body, body_detail,
                addr: format!("0x{:X}", IMAGE_BASE + m.rva as u64),
                sig_issues,
                full: full.clone(), method: m.clone(),
            });
        }
    }    rows.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    rows
}
