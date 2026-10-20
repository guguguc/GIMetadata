# pipeline

Rust port of the Python hook relocation resolver and pipeline.

The crate builds a single ELF executable named `pipeline`.

Layout:

```text
src/
  main.rs             command dispatcher
  pipeline/
    mod.rs            pipeline command / orchestration entry point
    resolver.rs       hook resolver core
  body.rs             body comparison
  dump.rs             dump parser and class alignment
  pe.rs               PE reader
  shape.rs            type/method shape helpers
```

Build:

```bash
cargo build --release
```

Or produce a copy of the final ELF at the crate root:

```bash
./build.sh
# tools/pipeline/pipeline
```

Usage:

```bash
pipeline dump-info out/dump71.cs
pipeline --src-version 7.1 --dst-version 6.7.0 \
  --src-dump out/dump71.cs --dst-dump out/dump67.cs \
  --hooks out/hk_71_all_named_map.json --base out/hk67_95_pipeline_best.json \
  --src-export out/ida71_source_export.json \
  --dst-export out/ida67_candidates_full.json \
  --src-exe version/7.1/gi.exe --dst-exe version/6.7.0/gi.exe \
  --out out/hk67_auto_resolved.json \
  --report out/hk67_auto_resolved_report.json
```

Parity policy:

* Result/report JSON is compared structurally (not byte-for-byte).
* Field order, indentation and float formatting are not part of parity.
* Cache files are Rust-native and not compatible with Python pickle.
* Capstone/body scoring and group assignment semantics are part of parity.

The Python implementation remains the reference oracle.
