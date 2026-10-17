#!/usr/bin/env bash
# ida_headless.sh —— 用 IDA 的**无头模式**导出常量（不需要 GUI）
#
# 用法:
#   tools/ida_headless.sh <exe 或 .i64/.idb> <out.json> [hits.json]
#
# 环境变量:
#   IDAT   idat64 的路径（默认 idat64；Windows 上是 idat64.exe）
#
# 数据库复用（重要）:
#   · 传 gi.exe 时，如果同目录有 **比 exe 新的** gi.i64 -> 自动用它 ✓（省掉小时级分析）
#   · 也可以直接传 gi.i64 ✓
#   · .i64 比 exe 旧会告警（-A 模式下 IDA 可能尝试重建，会很慢 ✗）
#
# 注意:
#   · 首次对 400MB 的 gi.exe 跑会自动分析，**小时级** ✗
#   · 需要 Hex-Rays 反编译器授权（脚本会调 decompile）
set -euo pipefail
TARGET="${1:?usage: $0 <exe|.i64> <out.json> [hits.json]}"
OUT="${2:?usage: $0 <exe|.i64> <out.json> [hits.json]}"
HITS="${3:-/tmp/h.json}"
IDAT="${IDAT:-idat64}"
HERE="$(cd "$(dirname "$0")" && pwd)"

DB="$TARGET"
case "$TARGET" in
  *.i64|*.idb) DB="$TARGET" ;;                       # 直接给了数据库
  *.exe)
    CAND="${TARGET%.exe}.i64"
    if [[ -f "$CAND" ]]; then
      if [[ "$CAND" -ot "$TARGET" ]]; then
        echo "[ida_headless] ⚠ $CAND 比 exe 旧（可能触发重建，很慢）" >&2
      else
        echo "[ida_headless] 复用已分析的数据库 $CAND" >&2
      fi
      DB="$CAND"
    fi
    ;;
esac

if [[ ! -x "$(command -v "$IDAT" || true)" ]]; then
  echo "[ida_headless] ✗ 找不到 $IDAT（用 IDAT=/path/to/idat64 指定）" >&2
  exit 1
fi
# ✅ 实测：正确顺序是 `-A -S"<script> <args>" <input>`（脚本参数必须在同一个引号里）
ARGS="$OUT $HITS"
[[ "${IDA_FULL:-0}" == "1" ]] || ARGS="$ARGS --fast"
echo "[ida_headless] $IDAT -A -S\"$HERE/ida_export.py $ARGS\" \"$DB\""
"$IDAT" -A -S"$HERE/ida_export.py $ARGS" "$DB"
echo "[ida_headless] 完成，检查 $OUT"
