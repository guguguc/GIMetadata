use crate::shape::{mshape, Shape};
use anyhow::{Context, Result};
use indexmap::IndexMap;
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Method {
    pub name: String,
    pub decl: String,
    pub rva: u32,
    pub shape: Shape,
}

#[derive(Clone, Debug, Default)]
pub struct Class {
    pub full: String,
    pub kind: String,
    pub methods: Vec<Method>,
}

pub type Dump = IndexMap<String, Class>;

pub fn parse_dump(path: &Path) -> Result<Dump> {
    let bytes = fs::read(path)
        .with_context(|| format!("read {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.split('\n').collect();
    let full_re = Regex::new(r"^// FullName:\s*(.*)$").unwrap();
    let kind_re = Regex::new(r"\b(class|struct|interface|enum)\s+").unwrap();
    let rva_re = Regex::new(r"^// RVA:\s*(0x[0-9A-Fa-f]+)").unwrap();
    let name_re = Regex::new(r"([A-Za-z_\.<][\w\.<>]*)\s*\(").unwrap();
    let mut out = Dump::new();
    let mut cur: Option<String> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if let Some(c) = full_re.captures(line) {
            let full = c[1].trim().to_string();
            out.entry(full.clone()).or_insert_with(|| Class {
                full: full.clone(), ..Default::default()
            });
            cur = Some(full);
            continue;
        }
        let Some(full) = cur.as_ref() else { continue };
        if !line.starts_with("//") {
            if let Some(c) = kind_re.captures(line) {
                if let Some(cls) = out.get_mut(full) {
                    if cls.kind.is_empty() { cls.kind = c[1].to_string(); }
                }
            }
        }
        let Some(c) = rva_re.captures(line) else { continue };
        let rva = u32::from_str_radix(&c[1][2..], 16).unwrap_or(0);
        let mut decl = String::new();
        for q in lines.iter().skip(i + 1).take(5) {
            let q = q.trim();
            if !q.is_empty() && !q.starts_with("//")
                && !q.starts_with('{') && !q.starts_with('}') {
                // Match the Python parser: an attribute line before a method
                // is consumed as the declaration and yields an empty-name
                // placeholder method.  These placeholders affect class
                // fingerprints, so parity requires preserving them.
                decl = q.to_string();
                break;
            }
        }
        if decl.is_empty() { continue; }
        let mname = name_re.captures(&decl).map(|m| m[1].to_string()).unwrap_or_default();
        let shape = mshape(&decl);
        if let Some(cls) = out.get_mut(full) {
            cls.methods.push(Method { name: mname, decl, rva, shape });
        }
    }
    Ok(out)
}

pub fn class_seq(c: &Class) -> Vec<Shape> {
    c.methods.iter().map(|m| m.shape.clone()).collect()
}

pub fn class_score(a: &[Shape], b: &[Shape]) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    let mut ca = IndexMap::<&Shape, usize>::new();
    let mut cb = IndexMap::<&Shape, usize>::new();
    for x in a { *ca.entry(x).or_default() += 1; }
    for x in b { *cb.entry(x).or_default() += 1; }
    let inter: usize = ca.iter().map(|(k, v)| (*v).min(*cb.get(k).unwrap_or(&0))).sum();
    let union: usize = ca.values().sum::<usize>() + cb.values().sum::<usize>() - inter;
    let jac = if union == 0 { 0.0 } else { inter as f64 / union as f64 };
    let seq = crate::shape::sequence_ratio(a, b);
    let cnt = 1.0 - (a.len() as f64 - b.len() as f64).abs() / a.len().max(b.len()).max(1) as f64;
    0.50 * jac + 0.40 * seq + 0.10 * cnt
}

pub fn method_by_name<'a>(c: &'a Class, name: &str, shape: &Shape) -> Vec<&'a Method> {
    let mut xs: Vec<&Method> = c.methods.iter().filter(|m| m.name == name).collect();
    let exact: Vec<&Method> = xs.iter().copied().filter(|m| &m.shape == shape).collect();
    if !exact.is_empty() { xs = exact; }
    xs
}

pub fn align_method<'a>(scls: &Class, tcls: &'a Class, sm: &Method) -> Option<(&'a Method, &'static str)> {
    // 1. exact name, close shape
    let xs = method_by_name(tcls, &sm.name, &sm.shape);
    if !xs.is_empty() {
        let mut v = xs.clone();
        v.sort_by(|a, b| crate::shape::method_sim(&sm.shape, &b.shape)
            .partial_cmp(&crate::shape::method_sim(&sm.shape, &a.shape)).unwrap());
        if v.len() == 1 || crate::shape::method_sim(&sm.shape, &v[0].shape)
            - crate::shape::method_sim(&sm.shape, &v[1].shape) > 0.05 {
            return Some((v[0], "name"));
        }
    }
    // 2. fuzzy signature
    let mut scored: Vec<(f64, usize, &Method)> = tcls.methods.iter().enumerate()
        .map(|(i, m)| (crate::shape::method_sim(&sm.shape, &m.shape), i, m)).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
    if let Some(best) = scored.first() {
        let second = scored.get(1).map(|x| x.0).unwrap_or(0.0);
        if best.0 >= 0.88 && best.0 - second >= 0.04 {
            return Some((best.2, "fuzzy"));
        }
    }
    // 3. ordinal
    if let Some(idx) = scls.methods.iter().position(|m| m.rva == sm.rva) {
        if idx < tcls.methods.len() && tcls.methods[idx].shape == sm.shape {
            return Some((&tcls.methods[idx], "ordinal"));
        }
    }
    // 4. LCS matching blocks
    let sseq: Vec<&Shape> = scls.methods.iter().map(|m| &m.shape).collect();
    let tseq: Vec<&Shape> = tcls.methods.iter().map(|m| &m.shape).collect();
    let idx = scls.methods.iter().position(|m| m.rva == sm.rva).unwrap_or(0);
    let lcs = lcs_blocks(&sseq, &tseq);
    for (a, b, n) in lcs {
        if a <= idx && idx < a + n { return Some((&tcls.methods[b + (idx - a)], "lcs")); }
    }
    // 5. relaxed ordinal
    if idx < tcls.methods.len() { return Some((&tcls.methods[idx], "ordinal_relaxed")); }
    None
}

fn lcs_blocks<T: Eq + std::hash::Hash + Clone>(a: &[T], b: &[T]) -> Vec<(usize, usize, usize)> {
    crate::shape::matching_blocks(a, b)
}

/// Port of tools/dump_funcs.py: write the sorted RVA boundary table.
pub fn write_funcs(dump: &Path, out: &Path, image_base: u64) -> Result<usize> {
    let bytes = fs::read(dump).with_context(|| format!("read {}", dump.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let re = Regex::new(r"^// RVA:\s*(0x[0-9A-Fa-f]+)\b").unwrap();
    let mut starts: Vec<u64> = Vec::new();
    for line in text.lines() {
        if let Some(c) = re.captures(line) {
            if let Ok(rva) = u64::from_str_radix(&c[1][2..], 16) {
                starts.push(image_base + rva);
            }
        }
    }
    starts.sort_unstable();
    starts.dedup();
    let funcs: Vec<serde_json::Value> = starts.iter().enumerate().map(|(i, st)| {
        let end = starts.get(i + 1).copied().unwrap_or(st + 0x1000);
        serde_json::json!({
            "name": format!("sub_{:X}", st),
            "start": st,
            "end": end,
            "size": end - st,
            "thunk": false,
            "jmp_target": null,
            "callees": []
        })
    }).collect();
    fs::write(out, serde_json::to_string(&serde_json::json!({"funcs": funcs}))?)?;
    Ok(starts.len())
}
