#!/usr/bin/env bash
# Profile-guided optimization (PGO) build for the Tessera Rust gateway.
#
# Two-stage workflow:
#   1. Compile an instrumented gateway binary that writes profile data
#      under PGO_DIR while it serves traffic.
#   2. Drive the instrumented binary with `tessera-bench mixed` for a
#      configurable duration, then merge the raw profile data with
#      `llvm-profdata merge`.
#   3. Recompile the gateway with `-Cprofile-use` pointing at the merged
#      profile, producing a release binary tuned to the recorded
#      workload.
#
# Requirements:
#   - cargo-pgo (`cargo install cargo-pgo`)
#   - llvm-profdata (`brew install llvm` on macOS, package `llvm` on
#     most Linuxes; the script picks the first one on PATH)
#   - The `tessera-bench` binary built in release mode
#   - A free TCP port; defaults to 18081 (override via PGO_BENCH_PORT)
#
# Output:
#   - Instrumented binary: target/x86_64-*/release/tessera-gateway (stage 1)
#   - Profile artifacts: rust/target/pgo-data/*.profraw and merged.profdata
#   - PGO-optimized binary: target/x86_64-*/release/tessera-gateway (stage 3)
#
# This script is idempotent: re-running with the same workload produces
# the same artifacts modulo timestamp jitter. Production releases that
# care about reproducibility should pin the bench duration and set the
# host into a known state (no other CPU load) before invoking.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PGO_BENCH_PORT="${PGO_BENCH_PORT:-18081}"
PGO_BENCH_DURATION="${PGO_BENCH_DURATION:-60s}"
PGO_BENCH_CONCURRENCY="${PGO_BENCH_CONCURRENCY:-1000}"
PGO_BENCH_WARMUP="${PGO_BENCH_WARMUP:-10s}"
PGO_DIR="${PGO_DIR:-$ROOT/target/pgo-data}"

if ! command -v cargo-pgo >/dev/null 2>&1; then
  cat >&2 <<EOF
cargo-pgo not found. Install with:
  cargo install cargo-pgo
EOF
  exit 1
fi

if ! command -v llvm-profdata >/dev/null 2>&1; then
  cat >&2 <<EOF
llvm-profdata not found. Install with:
  macOS:  brew install llvm  (then add the brew llvm bin dir to PATH)
  Linux:  install the 'llvm' package from your distro
EOF
  exit 1
fi

echo "[1/3] Building instrumented gateway via cargo-pgo ..."
mkdir -p "$PGO_DIR"
LLVM_PROFILE_FILE="$PGO_DIR/tessera-%p-%m.profraw" \
  cargo pgo build -- -p tessera-gateway

echo "[1/3] Building tessera-bench in release mode (no instrumentation) ..."
cargo build --release -p tessera-bench
cargo build --release -p tessera-bench --example spawn_primitives

INSTRUMENTED_BIN="$(find target -path '*release/tessera-gateway' | head -1)"
if [ -z "$INSTRUMENTED_BIN" ]; then
  echo "could not locate instrumented tessera-gateway binary" >&2
  exit 1
fi
SPAWNER_BIN="$ROOT/target/release/examples/spawn_primitives"

echo "[2/3] Starting instrumented primitives router on 127.0.0.1:$PGO_BENCH_PORT ..."
TESSERA_BENCH_ADDR="127.0.0.1:$PGO_BENCH_PORT" "$SPAWNER_BIN" &
SPAWNER_PID=$!
trap "kill $SPAWNER_PID 2>/dev/null || true" EXIT
sleep 1

echo "[2/3] Driving mixed workload for $PGO_BENCH_DURATION at concurrency $PGO_BENCH_CONCURRENCY ..."
"$ROOT/target/release/tessera-bench" mixed \
  --target "http://127.0.0.1:$PGO_BENCH_PORT" \
  --duration "$PGO_BENCH_DURATION" \
  --concurrency "$PGO_BENCH_CONCURRENCY" \
  --warmup "$PGO_BENCH_WARMUP" \
  --run-label "pgo-collect"

echo "[2/3] Stopping instrumented router ..."
kill $SPAWNER_PID || true
wait $SPAWNER_PID 2>/dev/null || true
trap - EXIT

echo "[3/3] Merging profile data ..."
MERGED="$PGO_DIR/merged.profdata"
llvm-profdata merge -o "$MERGED" "$PGO_DIR"/*.profraw

echo "[3/3] Recompiling gateway with -Cprofile-use=$MERGED ..."
cargo pgo optimize build -- -p tessera-gateway

cat <<EOF

PGO build complete.
  Profile data:  $PGO_DIR
  Merged:        $MERGED
  Optimized binary lives under target/<triple>/release/tessera-gateway

Re-run rust/bench/results.md against the optimized binary to capture
the PGO row in the comparison table.
EOF
