#!/usr/bin/env bash
# ida_headless.sh —— 用 IDA 的**无头模式**导出常量（不需要 GUI）
#
# 用法:
#   tools/ida_headless.sh <target.exe> <out.json> [hits.json]
#
# 环境变量:
#   IDAT   idat64 的路径（默认 idat64；Windows 上是 idat64.exe）
#
# 注意:
#   · 首次对 400MB 的 gi.exe 跑会自动分析，**非常慢**（小时级）。
#     如果已经有 .i64/.idb，直接给它，或者先手动分析一次并存库。
#   · 需要 Hex-Rays 反编译器授权（脚本会调 decompile）。
set -euo pipefail
TARGET="${1:?usage: $0 <target.exe> <out.json> [hits.json]}"
OUT="${2:?usage: $0 <target.exe> <out.json> [hits.json]}"
HITS="${3:-/tmp/h.json}"
IDAT="${IDAT:-idat64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "[ida_headless] $IDAT -A -S\"$HERE/ida_export.py $OUT $HITS\" $TARGET"
"$IDAT" -A -S"$HERE/ida_export.py $OUT $HITS" "$TARGET"
echo "[ida_headless] 完成，检查 $OUT"
