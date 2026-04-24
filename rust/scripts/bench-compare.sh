#!/usr/bin/env bash
#
# bench-compare.sh: spin up the Rust primitives router AND the
# AgentMesh Python proxy side by side, run the tessera-bench
# `compare` workload against both, and capture the markdown summary
# to `rust/bench/results.md`.
#
# Usage:
#   ./scripts/bench-compare.sh [duration] [concurrency]
#
# Defaults: duration=30s, concurrency=200.
#
# Requirements:
#   - cargo
#   - python3.12 with `tessera-mesh` and `agentmesh-mesh` installed
#     (typically your existing Tessera venv with AgentMesh editable-
#     installed)
#   - lsof + curl + sleep available on PATH
#
# Set AGENTMESH_VENV to override which Python interpreter starts
# the AgentMesh proxy. Defaults to ~/AgentMesh/.venv/bin/python.

set -euo pipefail

DURATION="${1:-30s}"
CONCURRENCY="${2:-200}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_TARGET_PORT=18081
PYTHON_TARGET_PORT=18082
AGENTMESH_VENV="${AGENTMESH_VENV:-$HOME/AgentMesh/.venv/bin/python}"

RUST_PID=""
PY_PID=""

cleanup() {
    if [ -n "$RUST_PID" ] && kill -0 "$RUST_PID" 2>/dev/null; then
        echo "[bench-compare] stopping Rust primitives router (pid $RUST_PID)"
        kill -TERM "$RUST_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$RUST_PID" 2>/dev/null || true
    fi
    if [ -n "$PY_PID" ] && kill -0 "$PY_PID" 2>/dev/null; then
        echo "[bench-compare] stopping Python AgentMesh proxy (pid $PY_PID)"
        kill -TERM "$PY_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$PY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

cd "$ROOT"

echo "[bench-compare] building tessera-bench in release mode ..."
cargo build --release -p tessera-bench --example spawn_primitives
cargo build --release -p tessera-bench --bin tessera-bench

echo "[bench-compare] starting Rust primitives router on :$RUST_TARGET_PORT ..."
TESSERA_BENCH_ADDR="127.0.0.1:$RUST_TARGET_PORT" \
    "$ROOT/target/release/examples/spawn_primitives" >/tmp/bench-rust.log 2>&1 &
RUST_PID=$!

if [ ! -x "$AGENTMESH_VENV" ]; then
    echo "[bench-compare] WARNING: $AGENTMESH_VENV not executable; skipping Python target"
    AGENTMESH_OK=false
else
    echo "[bench-compare] starting AgentMesh proxy on :$PYTHON_TARGET_PORT ..."
    "$AGENTMESH_VENV" -c "
from agentmesh.proxy import MeshProxy
proxy = MeshProxy(
    signing_key=b'bench-compare-32bytes-key!!!!!!!',
    enable_rag_guard=False,
    enable_telemetry=False,
)
proxy.run(host='127.0.0.1', port=$PYTHON_TARGET_PORT)
" >/tmp/bench-python.log 2>&1 &
    PY_PID=$!
    AGENTMESH_OK=true
fi

# Wait for both targets to come up.
echo "[bench-compare] waiting for targets to respond ..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:$RUST_TARGET_PORT/healthz" >/dev/null 2>&1; then
        echo "[bench-compare] Rust target healthy"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "[bench-compare] ERROR: Rust target never responded; see /tmp/bench-rust.log"
        exit 1
    fi
    sleep 1
done

if [ "$AGENTMESH_OK" = "true" ]; then
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf "http://127.0.0.1:$PYTHON_TARGET_PORT/healthz" >/dev/null 2>&1; then
            echo "[bench-compare] Python AgentMesh target healthy"
            break
        fi
        if [ "$i" -eq 10 ]; then
            echo "[bench-compare] WARNING: Python target never responded; running Rust-only"
            AGENTMESH_OK=false
        fi
        sleep 1
    done
fi

mkdir -p "$ROOT/bench/results"

if [ "$AGENTMESH_OK" = "true" ]; then
    echo "[bench-compare] running mixed compare against Rust ($RUST_TARGET_PORT) and Python ($PYTHON_TARGET_PORT)"
    "$ROOT/target/release/tessera-bench" compare \
        --rust-target "http://127.0.0.1:$RUST_TARGET_PORT" \
        --python-target "http://127.0.0.1:$PYTHON_TARGET_PORT" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --warmup 5s \
        --workload mixed \
        --report-file "$ROOT/bench/results.md" \
        --csv-dir "$ROOT/bench/results"
    echo "[bench-compare] running single-endpoint compare (/v1/evaluate) "
    "$ROOT/target/release/tessera-bench" compare \
        --rust-target "http://127.0.0.1:$RUST_TARGET_PORT" \
        --python-target "http://127.0.0.1:$PYTHON_TARGET_PORT" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --warmup 5s \
        --workload evaluate \
        --report-file "$ROOT/bench/results.md" \
        --csv-dir "$ROOT/bench/results"
else
    echo "[bench-compare] running Rust-only baseline (no Python target available)"
    "$ROOT/target/release/tessera-bench" mixed \
        --target "http://127.0.0.1:$RUST_TARGET_PORT" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --warmup 5s \
        --report-file "$ROOT/bench/results.md" \
        --csv-dir "$ROOT/bench/results"
fi

echo "[bench-compare] done. See $ROOT/bench/results.md for the appended summary."
