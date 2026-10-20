//! Base-candidate generation, ported from tools/dump_align.py.
//!
//! This is deliberately separate from the final evidence resolver: the base
//! stage chooses a class/method from shape and optional disassembly evidence,
//! then the resolver refines it with xrefs and body features.

use crate::body::disasm_compare;
use crate::dump::{align_method, class_score, class_seq, parse_dump, Class, Dump, Method};
use crate::pe::Pe;
use crate::shape::{method_sim, raw_rtype, Shape};
use anyhow::{bail, Context, Result};
use capstone::prelude::*;
use indexmap::IndexMap;
use rayon::prelude::*;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const IMAGE_BASE: u64 = 0x140000000;

pub struct BaseArgs {
    pub src_dump: String,
    pub dst_dump: String,
    pub hooks: String,
    pub out: String,
    pub class_score: f64,
    pub class_margin: f64,
    pub verify_disasm: bool,
    pub reselect_low: bool,
    pub reselect_medium: bool,
    pub method_aware_class: bool,
    pub src_exe: Option<String>,
    pub dst_exe: Option<String>,
    pub src_funcs: Option<String>,
    pub dst_funcs: Option<String>,
    pub jobs: usize,
    pub timing_json: Option<String>,
}

struct Verify {
    src: Pe,
    dst: Pe,
    src_ends: HashMap<u64, u64>,
    dst_ends: HashMap<u64, u64>,
}

fn load_func_ends(path: &str) -> Result<HashMap<u64, u64>> {
    let v: Value = serde_json::from_str(&fs::read_to_string(path)
        .with_context(|| format!("read {path}"))?)?;
    let mut out = HashMap::new();
    for f in v.get("funcs").and_then(|x| x.as_array()).into_iter().flatten() {
        let start = f.get("start").and_then(|x| x.as_u64());
        let end = f.get("end").and_then(|x| x.as_u64());
        if let (Some(s), Some(e)) = (start, end) { out.insert(s, e); }
    }
    Ok(out)
}

fn find_source_method<'a>(scls: &'a Class, h: &Value) -> Option<&'a Method> {
    if let Some(rva) = h.get("rva").and_then(|x| x.as_str())
        .and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok())
    {
        if let Some(m) = scls.methods.iter().find(|m| m.rva == rva) { return Some(m); }
    }
    if let Some(dn) = h.get("dump_name").and_then(|x| x.as_str()) {
        if !dn.is_empty() {
            if let Some(m) = scls.methods.iter().find(|m| m.name == dn) { return Some(m); }
        }
    }
    if let Some(dd) = h.get("dump_decl").and_then(|x| x.as_str()) {
        if !dd.is_empty() {
            if let Some(m) = scls.methods.iter().find(|m| m.decl == dd) { return Some(m); }
        }
    }
    None
}

fn round4(x: f64) -> f64 { (x * 10000.0).round() / 10000.0 }

fn load_hooks(path: &str) -> Result<Vec<Value>> {
    let v: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if let Some(a) = v.get("rows").and_then(|x| x.as_array()) { Ok(a.clone()) }
    else if let Some(a) = v.as_array() { Ok(a.clone()) }
    else { bail!("hooks JSON has no rows array") }
}

fn process_hook(
    h: &Value,
    s: &Dump,
    t: &Dump,
    by_count: &HashMap<usize, Vec<String>>,
    tseq: &HashMap<String, Vec<Shape>>,
    verify: Option<&Verify>,
    class_score_min: f64,
    class_margin: f64,
    reselect_low: bool,
    reselect_medium: bool,
) -> (String, Value) {
    let name = h.get("hook_method").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let sfull = h.get("fullname").and_then(|x| x.as_str()).unwrap_or("");
    let Some(scls) = s.get(sfull) else {
        return (name.clone(), json!({"status": "missing_source_class", "source_class": sfull}));
    };
    let sseq = class_seq(scls);
    let n = sseq.len();
    let cs = if verify.is_some() {
        Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().ok()
    } else { None };

    let mut candidates: Vec<(f64, String, Class, &'static str)> = Vec::new();
    if let Some(c) = t.get(sfull) {
        candidates.push((1.0, sfull.to_string(), c.clone(), "exact_class"));
    }
    let lo = ((n as f64 * 0.40) as usize).max(1);
    let hi = (n as f64 * 2.2) as usize + 1;
    for cnt in lo..=hi {
        if let Some(v) = by_count.get(&cnt) {
            for full in v {
                if full == sfull { continue; }
                let Some(c) = t.get(full) else { continue };
                let sc = class_score(&sseq, &tseq[full]);
                if sc >= class_score_min {
                    candidates.push((sc, full.clone(), c.clone(), "shape"));
                }
            }
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if candidates.is_empty() {
        return (name.clone(), json!({
            "status": "no_class", "source_class": sfull,
            "source_decl": h.get("dump_decl").cloned().unwrap_or(Value::Null)
        }));
    }

    let mut chosen: Option<(f64, String, Class, &'static str)> = None;
    if candidates[0].3 == "exact_class" {
        chosen = Some(candidates[0].clone());
    } else if candidates.len() == 1 || candidates[0].0 - candidates[1].0 >= class_margin {
        chosen = Some(candidates[0].clone());
    } else if let Some(sm0) = find_source_method(scls, h) {
        // Class-shape ties: use the best in-class method shape.
        let mut rescored: Vec<(f64, f64, String, Class, &'static str)> = Vec::new();
        for (sc0, full0, cls0, how0) in candidates.iter().take(16) {
            let mut best_ms = cls0.methods.iter()
                .map(|m| method_sim(&sm0.shape, &m.shape))
                .fold(0.0f64, f64::max);
            if let Some(dn) = h.get("dump_name").and_then(|x| x.as_str()) {
                if !dn.is_empty() && cls0.methods.iter().any(|m| m.name == dn) {
                    best_ms = best_ms.max(1.0);
                }
            }
            rescored.push((0.60 * sc0 + 0.40 * best_ms, *sc0, full0.clone(), cls0.clone(), how0));
        }
        rescored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        if !rescored.is_empty()
            && (rescored.len() == 1 || rescored[0].0 - rescored[1].0 >= 0.04)
        {
            let b = rescored[0].clone();
            chosen = Some((b.1, b.2, b.3, b.4));
        }
    }
    let Some((sc, tfull, tcls, how)) = chosen else {
        let cls: Vec<Value> = candidates.iter().take(5)
            .map(|c| json!({"class": c.1, "score": round4(c.0)})).collect();
        return (name.clone(), json!({
            "status": "ambiguous_class", "source_class": sfull,
            "class_candidates": cls
        }));
    };

    let Some(sm) = find_source_method(scls, h) else {
        return (name.clone(), json!({
            "status": "missing_source_method", "source_class": sfull,
            "target_class": tfull, "class_score": round4(sc)
        }));
    };
    let Some((tm, reason)) = align_method(scls, &tcls, sm) else {
        return (name.clone(), json!({
            "status": "no_method", "source_class": sfull,
            "target_class": tfull, "class_score": round4(sc)
        }));
    };
    let mut v = Map::new();
    v.insert("status".into(), json!("matched"));
    v.insert("confidence".into(), json!(if reason == "name" { "high" } else { "medium" }));
    v.insert("source_class".into(), json!(sfull));
    v.insert("source_rva".into(), json!(format!("0x{:X}", sm.rva)));
    v.insert("source_decl".into(), json!(sm.decl));
    v.insert("target_class".into(), json!(tfull));
    v.insert("class_score".into(), json!(round4(sc)));
    v.insert("class_match".into(), json!(how));
    v.insert("method_match".into(), json!(reason));
    v.insert("target_rva".into(), json!(format!("0x{:X}", tm.rva)));
    v.insert("target_va".into(), json!(format!("0x{:X}", IMAGE_BASE + tm.rva as u64)));
    v.insert("target_name".into(), json!(tm.name));
    v.insert("target_decl".into(), json!(tm.decl));

    if let (Some(ver), Some(cs)) = (verify, cs.as_ref()) {
        let sv = IMAGE_BASE + sm.rva as u64;
        let tv = IMAGE_BASE + tm.rva as u64;
        let se = ver.src_ends.get(&sv).copied();
        let de = ver.dst_ends.get(&tv).copied();
        if let (Some(se), Some(de)) = (se, de) {
            if let Some(vr) = disasm_compare(cs, &ver.src, &ver.dst, sv, tv, se, de) {
                let ds = vr.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                let status = if ds >= 0.78 { "high" } else if ds >= 0.60 { "medium" } else { "low" };
                v.insert("disasm".into(), vr);
                v.insert("disasm_status".into(), json!(status));
                if (reselect_low && status == "low") || (reselect_medium && status == "medium") {
                    reselect(scls, sm, &tcls, sv, se, &mut v, ver, cs);
                }
            }
        }
    }
    (name, Value::Object(v))
}

fn reselect(
    scls: &Class,
    sm: &Method,
    tcls: &Class,
    sv: u64,
    se: u64,
    v: &mut Map<String, Value>,
    ver: &Verify,
    cs: &Capstone,
) {
    let mut pool: Vec<(f64, &Method)> = tcls.methods.iter()
        .map(|m| (method_sim(&sm.shape, &m.shape), m))
        .filter(|x| x.0 >= 0.72).collect();
    pool.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let si = scls.methods.iter().position(|m| m.rva == sm.rva).unwrap_or(0);
    let ncls = scls.methods.len().max(tcls.methods.len()).max(1) as f64;
    let mut rescored: Vec<(f64, f64, Value, &Method)> = Vec::new();
    for (ms0, cm) in pool.into_iter().take(80) {
        let tv0 = IMAGE_BASE + cm.rva as u64;
        let Some(de0) = ver.dst_ends.get(&tv0).copied() else { continue; };
        let Some(vr0) = disasm_compare(cs, &ver.src, &ver.dst, sv, tv0, se, de0) else { continue; };
        let ds = vr0.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let type_bonus = if raw_rtype(&sm.decl) == raw_rtype(&cm.decl) { 0.15 } else { 0.0 };
        let ti = tcls.methods.iter().position(|m| m.rva == cm.rva).unwrap_or(0);
        let ordinal_bonus = 0.05 * (1.0 - (si as f64 - ti as f64).abs() / ncls).max(0.0);
        rescored.push((0.55 * ds + 0.25 * ms0 + 0.15 * type_bonus + 0.05 * ordinal_bonus,
                       ms0, vr0, cm));
    }
    rescored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let Some(best) = rescored.first() else { return; };
    let second = rescored.get(1).map(|x| x.0).unwrap_or(0.0);
    let gap = best.0 - second;
    let status = v.get("disasm_status").and_then(|x| x.as_str()).unwrap_or("low").to_string();
    let top3: Vec<Value> = rescored.iter().take(3).map(|x| json!({
        "rva": format!("0x{:X}", x.3.rva),
        "score": round4(x.0),
        "disasm": x.2.get("score").and_then(|z| z.as_f64()).map(round4),
        "shape": round4(x.1),
    })).collect();
    v.insert("reselect".into(), json!({
        "best_score": round4(best.0),
        "gap": round4(gap),
        "candidates": rescored.len(),
        "top3": top3,
    }));
    let required = if status == "medium" { 0.02 } else { 0.04 };
    if best.0 >= 0.78 && gap >= required {
        let old = json!({
            "rva": v.get("target_rva").cloned().unwrap_or(Value::Null),
            "name": v.get("target_name").cloned().unwrap_or(Value::Null),
        });
        let cm = best.3;
        let ds = best.2.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
        v.insert("target_rva".into(), json!(format!("0x{:X}", cm.rva)));
        v.insert("target_va".into(), json!(format!("0x{:X}", IMAGE_BASE + cm.rva as u64)));
        v.insert("target_name".into(), json!(cm.name));
        v.insert("target_decl".into(), json!(cm.decl));
        v.insert("method_match".into(), json!("reselect"));
        v.insert("confidence".into(), json!("high"));
        v.insert("reselect_from".into(), old);
        v.insert("disasm".into(), best.2.clone());
        v.insert("disasm_status".into(), json!(if ds >= 0.78 { "high" } else { "medium" }));
    }
}

pub fn run(a: BaseArgs) -> Result<()> {
    let t0 = std::time::Instant::now();
    let s = parse_dump(Path::new(&a.src_dump))?;
    let t = parse_dump(Path::new(&a.dst_dump))?;
    let hooks = load_hooks(&a.hooks)?;
    let by_count: HashMap<usize, Vec<String>> = {
        let mut m: HashMap<usize, Vec<String>> = HashMap::new();
        for (full, c) in &t { m.entry(c.methods.len()).or_default().push(full.clone()); }
        m
    };
    let tseq: HashMap<String, Vec<Shape>> =
        t.iter().map(|(k, c)| (k.clone(), class_seq(c))).collect();

    let verify = if a.verify_disasm {
        let (Some(se), Some(de), Some(sf), Some(df)) =
            (&a.src_exe, &a.dst_exe, &a.src_funcs, &a.dst_funcs)
        else {
            bail!("--verify-disasm requires --src-exe --dst-exe --src-funcs --dst-funcs");
        };
        Some(Verify {
            src: Pe::open(Path::new(se))?,
            dst: Pe::open(Path::new(de))?,
            src_ends: load_func_ends(sf)?,
            dst_ends: load_func_ends(df)?,
        })
    } else { None };

    let pairs: Vec<(String, Value)> = if a.jobs > 1 {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(a.jobs).build()?;
        pool.install(|| hooks.par_iter().map(|h| {
            process_hook(h, &s, &t, &by_count, &tseq, verify.as_ref(),
                a.class_score, a.class_margin, a.reselect_low, a.reselect_medium)
        }).collect())
    } else {
        hooks.iter().map(|h| {
            process_hook(h, &s, &t, &by_count, &tseq, verify.as_ref(),
                a.class_score, a.class_margin, a.reselect_low, a.reselect_medium)
        }).collect()
    };
    let result: IndexMap<String, Value> = pairs.into_iter().collect();
    fs::write(&a.out, serde_json::to_string_pretty(&Value::Object(result.clone().into_iter().collect()))?)?;
    if let Some(path) = &a.timing_json {
        fs::write(path, serde_json::to_string_pretty(&json!({
            "total_seconds": (t0.elapsed().as_secs_f64() * 10000.0).round() / 10000.0,
            "phases": [
                {"phase": "load-dumps", "seconds": 0.0},
                {"phase": "candidate-generation", "seconds": (t0.elapsed().as_secs_f64() * 10000.0).round() / 10000.0},
                {"phase": "write-result", "seconds": (t0.elapsed().as_secs_f64() * 10000.0).round() / 10000.0}
            ]
        }))?)?;
    }
    let stats = result.values().filter_map(|v| v.get("status").and_then(|x| x.as_str()))
        .fold(HashMap::<&str, usize>::new(), |mut m, x| { *m.entry(x).or_default() += 1; m });
    println!("{:?}", stats);
    Ok(())
}
