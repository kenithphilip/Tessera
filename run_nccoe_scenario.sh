#!/bin/bash
# Run the NCCoE reference scenario and tests

set -e

cd /Users/kenith.philip/Tessera

echo "=== Running NCCoE Scenario ==="
.venv/bin/python3.12 examples/nccoe_reference/scenario.py

echo ""
echo "=== Running NCCoE Scenario Tests ==="
.venv/bin/pytest tests/test_nccoe_reference_scenario.py -v --tb=short

echo ""
echo "=== Running Full Test Suite ==="
.venv/bin/pytest tests/ -q

echo ""
echo "✓ All tasks completed"
