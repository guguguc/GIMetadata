use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Shape {
    pub ret: String,
    pub params: Vec<String>,
}

const KNOWN: &[&str] = &[
    "void", "bool", "byte", "sbyte", "short", "ushort", "int", "uint", "long",
    "ulong", "float", "double", "string", "object", "char", "decimal", "IntPtr",
    "UIntPtr",
];

pub fn shape_type(t: &str) -> String {
    let t = t.trim();
    // Remove modifiers as whole words.  Do not use str::replace: it turns
    // `uint` into `ut` and `string` into `strg` by removing the `in` inside.
    let t = t.split_whitespace()
        .filter(|w| !matches!(*w, "const" | "ref" | "out" | "in"))
        .collect::<String>();
    if KNOWN.contains(&t.as_str()) {
        return t;
    }
    if t.contains('[') || t.ends_with(']') {
        return "A".into();
    }
    if t.contains('<') {
        return "G".into();
    }
    if t.ends_with('*') {
        return "P".into();
    }
    "C".into()
}

fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '<' | '[' | '(' => depth += 1,
            '>' | ']' | ')' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            out.push(buf.trim().to_string());
            buf.clear();
        } else {
            buf.push(ch);
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf.trim().to_string());
    }
    out
}

fn params_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\((.*)\)").unwrap())
}

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(.+?)(?:\s+[A-Za-z_]\w*)$").unwrap())
}

fn rtype_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([A-Za-z_\.<][\w\.<>]*)\s*\(").unwrap())
}

pub fn parse_params(decl: &str) -> Vec<String> {
    let Some(m) = params_re().captures(decl) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in split_params(&m[1]) {
        let p = p.split('=').next().unwrap_or("").trim().to_string();
        let q = if !p.ends_with('>') && !p.ends_with(']') && !p.ends_with('*') {
            name_re().captures(&p).map(|c| c[1].to_string()).unwrap_or(p)
        } else {
            p
        };
        // Keep the full type token.  Python's shape_type classifies a
        // generic/array by its punctuation before considering the namespace,
        // so stripping at the last dot would turn `List<Foo>` into `Foo>`.
        out.push(shape_type(&q));
    }
    out
}

pub fn raw_rtype(decl: &str) -> String {
    let Some(m) = rtype_re().captures(decl) else {
        return String::new();
    };
    let pre = decl[..m.get(0).unwrap().start()].trim();
    let mods = [
        "public", "private", "protected", "internal", "static", "virtual",
        "override", "abstract", "sealed", "extern", "unsafe", "new", "readonly",
        "partial", "async",
    ];
    let toks: Vec<&str> = pre.split_whitespace().collect();
    toks.iter()
        .rev()
        .find(|t| !mods.contains(t))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

pub fn mshape(decl: &str) -> Shape {
    Shape {
        ret: shape_type(&raw_rtype(decl)),
        params: parse_params(decl),
    }
}

pub fn type_sim(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let prim = [
        "bool", "byte", "sbyte", "short", "ushort", "int", "uint", "long",
        "ulong", "float", "double", "string", "object", "char", "decimal", "void",
    ];
    if prim.contains(&a) && prim.contains(&b) {
        return 0.65;
    }
    if a == "C" && b == "C" {
        return 0.90;
    }
    if (a == "A" || a == "G") && a == b {
        return 1.0;
    }
    0.15
}

pub fn method_sim(a: &Shape, b: &Shape) -> f64 {
    let r = type_sim(&a.ret, &b.ret);
    let ps = if a.params.is_empty() && b.params.is_empty() {
        1.0
    } else {
        let ratio = sequence_ratio(&a.params, &b.params);
        let n = a.params.len().max(b.params.len()) as f64;
        ratio * (1.0 - 0.25 * (a.params.len() as f64 - b.params.len() as f64).abs() / n)
    };
    0.30 * r + 0.70 * ps
}

fn find_longest_match<T: Eq + std::hash::Hash + Clone>(
    a: &[T], b: &[T], alo: usize, ahi: usize, blo: usize, bhi: usize,
    b2j: &HashMap<T, Vec<usize>>,
) -> (usize, usize, usize) {
    let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for i in alo..ahi {
        let mut newj2len: HashMap<usize, usize> = HashMap::new();
        if let Some(js) = b2j.get(&a[i]) {
            for &j in js {
                if j < blo { continue; }
                if j >= bhi { break; }
                let k = j2len.get(&j.wrapping_sub(1)).copied().unwrap_or(0) + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }
    (besti, bestj, bestsize)
}

/// Python difflib.SequenceMatcher(..., autojunk=False).get_matching_blocks().
pub fn matching_blocks<T: Eq + std::hash::Hash + Clone>(a: &[T], b: &[T]) -> Vec<(usize, usize, usize)> {
    let mut b2j: HashMap<T, Vec<usize>> = HashMap::new();
    for (j, x) in b.iter().enumerate() {
        b2j.entry(x.clone()).or_default().push(j);
    }
    let mut queue = vec![(0usize, a.len(), 0usize, b.len())];
    let mut out = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest_match(a, b, alo, ahi, blo, bhi, &b2j);
        if k > 0 {
            out.push((i, j, k));
            if alo < i && blo < j { queue.push((alo, i, blo, j)); }
            if i + k < ahi && j + k < bhi { queue.push((i + k, ahi, j + k, bhi)); }
        }
    }
    out.sort_by_key(|x| (x.0, x.1));
    out
}

pub fn sequence_ratio<T: Eq + std::hash::Hash + Clone>(a: &[T], b: &[T]) -> f64 {
    if a.is_empty() && b.is_empty() { return 1.0; }
    let total: usize = matching_blocks(a, b).iter().map(|x| x.2).sum();
    2.0 * total as f64 / (a.len() + b.len()) as f64
}
