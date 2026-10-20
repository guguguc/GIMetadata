#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release
install -m 755 target/release/pipeline ./pipeline
file ./pipeline
