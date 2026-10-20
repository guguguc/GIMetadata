//! One-command pipeline, modeled on tools/hooks_pipeline.py.

use super::base::{self, BaseArgs};
use super::resolver::{self, ResolveArgs};
use crate::dump::write_funcs;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const IMAGE_BASE: u64 = 0x140000000;

pub struct FullArgs {
    pub src_version: String,
    pub dst_version: String,
    pub src_dump: Option<String>,
    pub dst_dump: Option<String>,
    pub hooks: Option<String>,
    pub base: Option<String>,
    pub out: Option<String>,
    pub report: Option<String>,
    pub cache_dir: String,
    pub src_exe: Option<String>,
    pub dst_exe: Option<String>,
    pub src_export: Option<String>,
    pub dst_export: Option<String>,
    pub auto_export: bool,
    pub ida_mode: String,
    pub ida_url: String,
    pub max_body: usize,
    pub jobs: usize,
    pub class_score: f64,
    pub class_margin: f64,
    pub force_base: bool,
    pub dry_run: bool,
    pub log: Option<String>,
    pub timing_json: Option<String>,
    pub verify_hooks: Option<String>,
}

struct Logger {
    start: Instant,
    file: Option<File>,
}

impl Logger {
    fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Ok(Self { start: Instant::now(), file })
    }
    fn log(&mut self, msg: &str) {
        let dt = self.start.elapsed().as_secs_f64();
        let line = format!("[{dt:8.3}s] {msg}");
        println!("{line}");
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn vkey(v: &str) -> String { v.replace('.', "") }

fn root() -> PathBuf {
    // tools/pipeline -> repository root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn first_existing(root: &Path, names: &[String]) -> Option<PathBuf> {
    names.iter().map(|n| root.join(n)).find(|p| p.exists())
}

fn resolve_path(root: &Path, value: Option<String>, default: PathBuf) -> PathBuf {
    value.map(|x| root.join(x)).unwrap_or(default)
}

fn run_phase<F>(label: &str, phases: &mut Vec<Value>, f: F) -> Result<()>
where F: FnOnce() -> Result<()> {
    let t = Instant::now();
    let r = f();
    let dt = t.elapsed().as_secs_f64();
    phases.push(json!({"phase": label, "seconds": (dt * 10000.0).round() / 10000.0}));
    r
}

fn is_iso_epoch() -> String {
    // Keep the manifest useful without pulling in a date dependency.
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("unix:{secs}")
}

pub fn run(a: FullArgs) -> Result<()> {
    let root = root();
    let sk = vkey(&a.src_version);
    let dk = vkey(&a.dst_version);
    let cache = root.join(&a.cache_dir);
    fs::create_dir_all(&cache)?;

    let src_dump = resolve_path(&root, a.src_dump, root.join("out").join(format!("dump{sk}.cs")));
    let dst_dump = resolve_path(&root, a.dst_dump, root.join("out").join(format!("dump{dk}.cs")));
    let hooks = a.hooks.map(|x| root.join(x)).or_else(|| first_existing(&root, &[
        format!("out/hk_{sk}_all_named_map.json"),
        format!("out/hk_{sk}_map.json"),
    ]));
    let base = resolve_path(&root, a.base, root.join("out").join(format!("hk{dk}_best.json")));
    let out = resolve_path(&root, a.out, root.join("out").join(format!("hk{dk}_auto_resolved.json")));
    let report = resolve_path(&root, a.report, root.join("out").join(format!("hk{dk}_auto_resolved_report.json")));
    let src_exe = resolve_path(&root, a.src_exe, root.join("version").join(&a.src_version).join("gi.exe"));
    let dst_exe = resolve_path(&root, a.dst_exe, root.join("version").join(&a.dst_version).join("gi.exe"));

    let log_path = a.log.map(|x| root.join(x))
        .unwrap_or_else(|| cache.join(format!("hooks_pipeline_{sk}_{dk}.log")));
    let timing_path = a.timing_json.map(|x| root.join(x))
        .unwrap_or_else(|| cache.join(format!("hooks_pipeline_{sk}_{dk}_timing.json")));
    let mut logger = Logger::new(&log_path)?;
    let mut phases: Vec<Value> = Vec::new();
    let total_start = Instant::now();
    logger.log(&format!("pipeline start src={} dst={} ida_mode={}", a.src_version, a.dst_version, a.ida_mode));

    if !src_dump.exists() { bail!("missing source dump: {}", src_dump.display()); }
    if !dst_dump.exists() { bail!("missing target dump: {}", dst_dump.display()); }
    let Some(hooks) = hooks else { bail!("missing source hook map"); };
    if !hooks.exists() { bail!("missing source hook map: {}", hooks.display()); }
    if !src_exe.exists() { bail!("missing executable: {}", src_exe.display()); }
    if !dst_exe.exists() { bail!("missing executable: {}", dst_exe.display()); }

    let mut src_export = a.src_export.map(|x| root.join(x));
    let mut dst_export = a.dst_export.map(|x| root.join(x));
    if a.auto_export {
        if src_export.is_none() {
            src_export = first_existing(&root, &[
                format!("out/ida{sk}_source_export.json"),
                format!("out/ida{sk}_export.json"),
            ]);
        }
        if dst_export.is_none() {
            dst_export = first_existing(&root, &[
                format!("out/ida{dk}_candidates.json"),
                format!("out/ida{dk}_group_candidates.json"),
            ]);
        }
    }
    let funcs_src = cache.join(format!("funcs_{sk}.json"));
    let funcs_dst = cache.join(format!("funcs_{dk}.json"));

    // 1. function boundaries
    run_phase("func-boundaries", &mut phases, || {
        for (dump, out_f) in [(&src_dump, &funcs_src), (&dst_dump, &funcs_dst)] {
            if a.force_base || !out_f.exists() {
                if a.dry_run {
                    logger.log(&format!("command: dump_funcs {} -> {}", dump.display(), out_f.display()));
                } else {
                    let n = write_funcs(dump, out_f, IMAGE_BASE)?;
                    logger.log(&format!("wrote {n} funcs -> {}", out_f.display()));
                }
            } else {
                logger.log(&format!("reuse funcs: {}", out_f.display()));
            }
        }
        Ok(())
    })?;
    logger.log("phase func-boundaries done");

    // 2. base candidates
    run_phase("base-candidates", &mut phases, || {
        if a.force_base || !base.exists() {
            if a.dry_run {
                logger.log(&format!("command: base generation -> {}", base.display()));
                return Ok(());
            }
            logger.log(&format!("command: base generation -> {}", base.display()));
            base::run(BaseArgs {
                src_dump: src_dump.to_string_lossy().into_owned(),
                dst_dump: dst_dump.to_string_lossy().into_owned(),
                hooks: hooks.to_string_lossy().into_owned(),
                out: base.to_string_lossy().into_owned(),
                class_score: a.class_score,
                class_margin: a.class_margin,
                verify_disasm: true,
                reselect_low: true,
                reselect_medium: true,
                method_aware_class: false,
                src_exe: Some(src_exe.to_string_lossy().into_owned()),
                dst_exe: Some(dst_exe.to_string_lossy().into_owned()),
                src_funcs: Some(funcs_src.to_string_lossy().into_owned()),
                dst_funcs: Some(funcs_dst.to_string_lossy().into_owned()),
                jobs: a.jobs,
                timing_json: None,
            })?;
        } else {
            logger.log(&format!("reuse base: {}", base.display()));
        }
        Ok(())
    })?;
    logger.log("phase base-candidates done");

    // 3. final evidence resolver
    let resolver_timing = cache.join(format!("hook_resolve_{sk}_{dk}_timing.json"));
    run_phase("hook-resolve", &mut phases, || {
        if a.dry_run {
            logger.log("command: hook resolver (dry-run)");
            return Ok(());
        }
        let src_export = src_export.clone().filter(|p| p.exists());
        let dst_export = dst_export.clone().filter(|p| p.exists());
        if a.ida_mode == "cache" && src_export.is_none() {
            logger.log("warning: no source export; continuing without source xrefs");
        }
        if a.ida_mode == "cache" && dst_export.is_none() {
            logger.log("warning: no target export; running without target xrefs");
        }
        resolver::run(ResolveArgs {
            src_dump: src_dump.to_string_lossy().into_owned(),
            dst_dump: dst_dump.to_string_lossy().into_owned(),
            hooks: hooks.to_string_lossy().into_owned(),
            base: base.to_string_lossy().into_owned(),
            out: out.to_string_lossy().into_owned(),
            report: Some(report.to_string_lossy().into_owned()),
            src_exe: Some(src_exe.to_string_lossy().into_owned()),
            dst_exe: Some(dst_exe.to_string_lossy().into_owned()),
            src_export: src_export.map(|p| p.to_string_lossy().into_owned()),
            dst_export: dst_export.map(|p| p.to_string_lossy().into_owned()),
            max_body: a.max_body,
            class_score: a.class_score,
            class_margin: a.class_margin,
            ida_mode: a.ida_mode.clone(),
            ida_url: a.ida_url.clone(),
            jobs: a.jobs,
            timing_json: Some(resolver_timing.to_string_lossy().into_owned()),
            save_dst_export: None,
        })
    })?;
    logger.log("phase hook-resolve done");

    // 4. optional independent validation
    if let Some(verify_path) = &a.verify_hooks {
        if !a.dry_run {
            if let Ok(raw) = fs::read_to_string(root.join(verify_path)) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    let outv: Value = serde_json::from_str(&fs::read_to_string(&out)?)?;
                    let mut ok = 0usize; let mut bad = 0usize; let mut miss = 0usize;
                    if let Some(hs) = v.get("hooks").and_then(|x| x.as_array()) {
                        for h in hs {
                            let name = h.get("name").and_then(|x| x.as_str()).unwrap_or("");
                            let Some(rv) = h.get("rva_7_0").and_then(|x| x.as_str()) else { continue; };
                            let Some(rv) = u64::from_str_radix(rv.trim_start_matches("0x"), 16).ok() else { continue; };
                            let t = outv.get(name).and_then(|x| x.get("target_rva")).and_then(|x| x.as_str());
                            match t.and_then(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok()) {
                                Some(x) if x == rv => ok += 1,
                                Some(_) => bad += 1,
                                None => miss += 1,
                            }
                        }
                    }
                    logger.log(&format!("validation same={ok} diff={bad} missing={miss}"));
                }
            }
        }
    }

    let total = total_start.elapsed().as_secs_f64();
    phases.push(json!({"phase": "total", "seconds": (total * 10000.0).round() / 10000.0}));
    let manifest = json!({
        "src_version": a.src_version,
        "dst_version": a.dst_version,
        "ida_mode": a.ida_mode,
        "started": is_iso_epoch(),
        "total_seconds": (total * 10000.0).round() / 10000.0,
        "phases": phases,
        "paths": {
            "src_dump": src_dump, "dst_dump": dst_dump, "hooks": hooks,
            "base": base, "out": out, "report": report,
            "src_export": src_export, "dst_export": dst_export,
            "log": log_path, "resolver_timing": resolver_timing,
        }
    });
    if !a.dry_run {
        fs::write(&timing_path, serde_json::to_string_pretty(&manifest)?)
            .with_context(|| format!("write {}", timing_path.display()))?;
    }
    logger.log(&format!("timing written: {}", timing_path.display()));
    logger.log(&format!("pipeline done total={total:.3}s output={}", out.display()));
    println!("output: {}", out.display());
    println!("report: {}", report.display());
    println!("timing: {}", timing_path.display());
    Ok(())
}
