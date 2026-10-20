use crate::pe::Pe;
use crate::shape::sequence_ratio;
use capstone::prelude::*;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug, Default)]
pub struct Features {
    pub hist: HashMap<String, usize>,
    pub prime: u64,
    pub insns: usize,
    pub calls: usize,
    pub blocks: usize,
    pub edges: usize,
}

const PRIMES: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211, 223, 227, 229];

fn prime_of(mn: &str) -> u64 {
    // Match Python sig._prime_of: primes are assigned in first-encounter
    // order and reused for the whole process.
    static MAP: OnceLock<Mutex<(HashMap<String, u64>, usize)>> = OnceLock::new();
    let m = MAP.get_or_init(|| Mutex::new((HashMap::new(), 0)));
    let mut guard = m.lock().unwrap();
    let (map, next) = &mut *guard;
    if let Some(p) = map.get(mn) { return *p; }
    let p = PRIMES[*next % PRIMES.len()];
    *next += 1;
    map.insert(mn.to_string(), p);
    p
}

pub fn func_features(cs: &Capstone, pe: &Pe, start: u64, end: u64) -> Option<Features> {
    let off = pe.va2off(start)?;
    let n = (end.saturating_sub(start) + 32).min(0x4000) as usize;
    let bytes = pe.data.get(off..off + n)?;
    let mut f = Features::default();
    f.prime = 1;
    for ins in cs.disasm_all(bytes, start).ok()?.iter() {
        if ins.address() >= end { break; }
        let mn = ins.mnemonic().unwrap_or("");
        if matches!(mn, "int3" | "nop" | "nopw" | "nopl") { continue; }
        *f.hist.entry(mn.to_string()).or_default() += 1;
        f.prime = f.prime.wrapping_mul(prime_of(mn));
        f.insns += 1;
        if mn == "call" { f.calls += 1; }
        if matches!(mn, "jmp" | "je" | "jne" | "jz" | "jnz" | "ja" | "jb" | "jg" | "jl" |
            "jle" | "jge" | "jae" | "jbe" | "js" | "jns") { f.blocks += 1; }
        if mn == "ret" { f.edges += 1; }
    }
    if f.insns == 0 { return None; }
    f.blocks += 1;
    f.edges += f.blocks - 1;
    Some(f)
}

pub fn cosine(a: &HashMap<String, usize>, b: &HashMap<String, usize>) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    let mut dot = 0f64;
    for (k, v) in a { dot += (*v as f64) * (*b.get(k).unwrap_or(&0) as f64); }
    let na: f64 = a.values().map(|v| (*v as f64) * (*v as f64)).sum::<f64>().sqrt();
    let nb: f64 = b.values().map(|v| (*v as f64) * (*v as f64)).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 { 0.0 } else { dot / (na * nb) }
}

fn ratio(a: usize, b: usize) -> f64 {
    if a == 0 || b == 0 { 0.0 } else { a.min(b) as f64 / a.max(b) as f64 }
}

fn mnemonics(cs: &Capstone, pe: &Pe, start: u64, end: u64) -> Vec<String> {
    let Some(off) = pe.va2off(start) else { return Vec::new() };
    let n = (end.saturating_sub(start) + 32).min(0x20000) as usize;
    let Some(bytes) = pe.data.get(off..off + n) else { return Vec::new() };
    let mut out = Vec::new();
    if let Ok(insns) = cs.disasm_all(bytes, start) {
        for ins in insns.iter() {
            if ins.address() >= end { break; }
            let mn = ins.mnemonic().unwrap_or("");
            if !matches!(mn, "int3" | "nop" | "nopw" | "nopl") { out.push(mn.to_string()); }
        }
    }
    out
}

pub fn disasm_compare(cs: &Capstone, src: &Pe, dst: &Pe, sva: u64, tva: u64, se: u64, te: u64)
    -> Option<serde_json::Value> {
    let sf = func_features(cs, src, sva, se)?;
    let tf = func_features(cs, dst, tva, te)?;
    let cos = cosine(&sf.hist, &tf.hist);
    let counts = (ratio(sf.insns, tf.insns) + ratio(sf.calls, tf.calls)
        + ratio(sf.blocks, tf.blocks) + ratio(sf.edges, tf.edges)) / 4.0;
    let a = mnemonics(cs, src, sva, se);
    let b = mnemonics(cs, dst, tva, te);
    let lcs = sequence_ratio(&a, &b);
    let score = 0.35 * cos + 0.10 * (sf.prime == tf.prime) as u8 as f64
        + 0.15 * counts + 0.40 * lcs;
    Some(serde_json::json!({
        "score": (score * 10000.0).round() / 10000.0,
        "hist": (cos * 10000.0).round() / 10000.0,
        "lcs": (lcs * 10000.0).round() / 10000.0,
        "src_insns": sf.insns,
        "dst_insns": tf.insns
    }))
}

pub fn body_score(cs: &Capstone, src: &Pe, dst: &Pe, sva: u64, tva: u64, se: u64, te: u64) -> (f64, serde_json::Value) {
    let Some(sf) = func_features(cs, src, sva, se) else { return (0.0, serde_json::json!({})); };
    let Some(tf) = func_features(cs, dst, tva, te) else { return (0.0, serde_json::json!({})); };
    let cos = cosine(&sf.hist, &tf.hist);
    let counts = (ratio(sf.insns, tf.insns) + ratio(sf.calls, tf.calls)
        + ratio(sf.blocks, tf.blocks) + ratio(sf.edges, tf.edges)) / 4.0;
    let a = mnemonics(cs, src, sva, se);
    let b = mnemonics(cs, dst, tva, te);
    let lcs = sequence_ratio(&a, &b);
    let score = 0.40 * cos + 0.30 * counts + 0.30 * lcs;
    (score, serde_json::json!({
        "score": (score * 10000.0).round() / 10000.0,
        "hist": (cos * 10000.0).round() / 10000.0,
        "lcs": (lcs * 10000.0).round() / 10000.0,
    }))
}
