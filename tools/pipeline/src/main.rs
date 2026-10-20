mod body;
mod dump;
mod mcp;
mod pe;
mod pipeline;
mod shape;

use anyhow::{Context, Result};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: pipeline --src-version V --dst-version V [options]");
        eprintln!("       pipeline resolve [resolver options]");
        eprintln!("       pipeline dump-info FILE");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "dump-info" => {
            let Some(path) = args.get(2) else {
                anyhow::bail!("usage: pipeline dump-info FILE");
            };
            let d = dump::parse_dump(Path::new(path))?;
            let classes = d.len();
            let methods: usize = d.values().map(|c| c.methods.len()).sum();
            println!("classes={classes} methods={methods}");
            if args.get(3).map(|x| x == "--per-class").unwrap_or(false) {
                for (full, c) in &d {
                    println!("{}\t{}", full, c.methods.len());
                }
            }
            if args.get(3).map(|x| x == "--shapes").unwrap_or(false) {
                if let Some(name) = args.get(4) {
                    if let Some(c) = d.get(name) {
                        for m in &c.methods {
                            println!("{}\t0x{:X}\t{:?}", m.name, m.rva, m.shape);
                        }
                    }
                }
            }
            Ok(())
        }
        // Advanced/legacy entry points remain explicit subcommands.  The
        // normal pipeline no longer needs a `pipeline` subcommand.
        "resolve" => pipeline::run_resolver(&args[2..]),
        _ => pipeline::run_full(&args[1..]),
    }
}
