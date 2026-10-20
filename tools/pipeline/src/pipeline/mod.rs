//! Pipeline front-end.
//!
//! The resolver itself lives in [`resolver`].  Keep the command-line parsing
//! and, later, the dump/base/export orchestration here so the final artifact
//! remains a single executable.

mod base;
mod full;
mod resolver;

use anyhow::{bail, Result};

const USAGE: &str = "\
usage: pipeline pipeline --src-dump FILE --dst-dump FILE --hooks FILE --base FILE --out FILE
       [--report FILE] [--src-exe FILE] [--dst-exe FILE]
       [--src-export FILE] [--dst-export FILE]
       [--max-body N] [--class-score F] [--class-margin F]
       [--jobs N] [--ida-mode none|cache|mcp] [--ida-url URL]
       [--timing-json FILE] [--save-dst-export FILE]";

fn parse_f64(k: &str, v: &str) -> Result<f64> {
    v.parse::<f64>()
        .map_err(|_| anyhow::anyhow!("{k}: expected a number, got {v:?}"))
}

fn parse_usize(k: &str, v: &str) -> Result<usize> {
    v.parse::<usize>()
        .map_err(|_| anyhow::anyhow!("{k}: expected a non-negative integer, got {v:?}"))
}

/// Run `pipeline` with the arguments following the subcommand.
pub fn run_resolver(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("{USAGE}");
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() % 2 != 0 {
        bail!("missing value for {}\n{USAGE}", args[args.len() - 1]);
    }

    let mut a = resolver::ResolveArgs {
        src_dump: String::new(),
        dst_dump: String::new(),
        hooks: String::new(),
        base: String::new(),
        out: String::new(),
        report: None,
        src_exe: None,
        dst_exe: None,
        src_export: None,
        dst_export: None,
        max_body: 300,
        class_score: 0.58,
        class_margin: 0.03,
        ida_mode: "none".into(),
        ida_url: "http://127.0.0.1:13337/mcp".into(),
        jobs: 1,
        timing_json: None,
        save_dst_export: None,
    };
    let mut i = 0;
    while i + 1 < args.len() {
        let k = args[i].as_str();
        let v = args[i + 1].clone();
        match k {
            "--src-dump" => a.src_dump = v,
            "--dst-dump" => a.dst_dump = v,
            "--hooks" => a.hooks = v,
            "--base" => a.base = v,
            "--out" => a.out = v,
            "--report" => a.report = Some(v),
            "--src-exe" => a.src_exe = Some(v),
            "--dst-exe" => a.dst_exe = Some(v),
            "--src-export" => a.src_export = Some(v),
            "--dst-export" => a.dst_export = Some(v),
            "--max-body" => a.max_body = parse_usize(k, &v)?,
            "--class-score" => a.class_score = parse_f64(k, &v)?,
            "--class-margin" => a.class_margin = parse_f64(k, &v)?,
            "--jobs" => {
                a.jobs = parse_usize(k, &v)?;
                if a.jobs == 0 { bail!("--jobs must be at least 1"); }
            },
            "--ida-mode" => {
                if !matches!(v.as_str(), "none" | "cache" | "mcp") {
                    bail!("--ida-mode must be none, cache or mcp");
                }
                a.ida_mode = v;
            },
            "--ida-url" => a.ida_url = v,
            "--timing-json" => a.timing_json = Some(v),
            "--save-dst-export" => a.save_dst_export = Some(v),
            "--no-ida" => a.ida_mode = "none".into(),
            _ => bail!("unknown argument: {k}\n{USAGE}"),
        }
        i += 2;
    }

    for (flag, value) in [
        ("--src-dump", &a.src_dump),
        ("--dst-dump", &a.dst_dump),
        ("--hooks", &a.hooks),
        ("--base", &a.base),
        ("--out", &a.out),
    ] {
        if value.is_empty() {
            bail!("missing required argument {flag}\n{USAGE}");
        }
    }
    if a.class_score != 0.58 || a.class_margin != 0.03 {
        eprintln!("warning: --class-score/--class-margin are only used by base generation; the resolver currently ignores them");
    }
    resolver::run(a)
}


const FULL_USAGE: &str = "\
usage: pipeline --src-version V --dst-version V
       [--src-dump FILE] [--dst-dump FILE] [--hooks FILE] [--base FILE]
       [--out FILE] [--report FILE] [--cache-dir DIR]
       [--src-exe FILE] [--dst-exe FILE] [--src-export FILE] [--dst-export FILE]
       [--auto-export] [--ida-mode none|cache|mcp] [--ida-url URL]
       [--max-body N] [--jobs N] [--class-score F] [--class-margin F]
       [--force-base] [--dry-run] [--log FILE] [--timing-json FILE]
       [--verify-hooks FILE]";

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    if *i + 1 >= args.len() { bail!("missing value for {flag}\n{FULL_USAGE}"); }
    *i += 2;
    Ok(args[*i - 1].clone())
}

pub fn run_full(args: &[String]) -> Result<()> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{FULL_USAGE}");
        return Ok(());
    }
    let mut a = full::FullArgs {
        src_version: String::new(),
        dst_version: String::new(),
        src_dump: None, dst_dump: None, hooks: None, base: None,
        out: None, report: None,
        cache_dir: "out/cache".into(),
        src_exe: None, dst_exe: None, src_export: None, dst_export: None,
        auto_export: false,
        ida_mode: "none".into(),
        ida_url: "http://127.0.0.1:13337/mcp".into(),
        max_body: 300, jobs: 1, class_score: 0.58, class_margin: 0.03,
        force_base: false, dry_run: false,
        log: None, timing_json: None, verify_hooks: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--auto-export" => { a.auto_export = true; i += 1; }
            "--force-base" => { a.force_base = true; i += 1; }
            "--dry-run" => { a.dry_run = true; i += 1; }
            "--help" | "-h" => { println!("{FULL_USAGE}"); return Ok(()); }
            "--src-version" => a.src_version = take_value(args, &mut i, "--src-version")?,
            "--dst-version" => a.dst_version = take_value(args, &mut i, "--dst-version")?,
            "--src-dump" => a.src_dump = Some(take_value(args, &mut i, "--src-dump")?),
            "--dst-dump" => a.dst_dump = Some(take_value(args, &mut i, "--dst-dump")?),
            "--hooks" => a.hooks = Some(take_value(args, &mut i, "--hooks")?),
            "--base" => a.base = Some(take_value(args, &mut i, "--base")?),
            "--out" => a.out = Some(take_value(args, &mut i, "--out")?),
            "--report" => a.report = Some(take_value(args, &mut i, "--report")?),
            "--cache-dir" => a.cache_dir = take_value(args, &mut i, "--cache-dir")?,
            "--src-exe" => a.src_exe = Some(take_value(args, &mut i, "--src-exe")?),
            "--dst-exe" => a.dst_exe = Some(take_value(args, &mut i, "--dst-exe")?),
            "--src-export" => a.src_export = Some(take_value(args, &mut i, "--src-export")?),
            "--dst-export" => a.dst_export = Some(take_value(args, &mut i, "--dst-export")?),
            "--ida-url" => a.ida_url = take_value(args, &mut i, "--ida-url")?,
            "--max-body" => { let v = take_value(args, &mut i, "--max-body")?; a.max_body = parse_usize("--max-body", &v)?; }
            "--jobs" => { let v = take_value(args, &mut i, "--jobs")?; a.jobs = parse_usize("--jobs", &v)?; if a.jobs == 0 { bail!("--jobs must be at least 1"); } }
            "--class-score" => { let v = take_value(args, &mut i, "--class-score")?; a.class_score = parse_f64("--class-score", &v)?; }
            "--class-margin" => { let v = take_value(args, &mut i, "--class-margin")?; a.class_margin = parse_f64("--class-margin", &v)?; }
            "--log" => a.log = Some(take_value(args, &mut i, "--log")?),
            "--timing-json" => a.timing_json = Some(take_value(args, &mut i, "--timing-json")?),
            "--verify-hooks" => a.verify_hooks = Some(take_value(args, &mut i, "--verify-hooks")?),
            "--ida-mode" => {
                let v = take_value(args, &mut i, "--ida-mode")?;
                if !matches!(v.as_str(), "none" | "cache" | "mcp") { bail!("--ida-mode must be none, cache or mcp"); }
                a.ida_mode = v;
            }
            k => bail!("unknown argument: {k}\n{FULL_USAGE}"),
        }
    }
    if a.src_version.is_empty() || a.dst_version.is_empty() {
        bail!("missing --src-version/--dst-version\n{FULL_USAGE}");
    }
    full::run(a)
}
