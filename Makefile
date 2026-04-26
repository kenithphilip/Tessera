# Tessera developer + operator Makefile
#
# Conventions follow AgentMesh's Makefile (## comment per target,
# .PHONY block, help target as the default). Targets are kept thin:
# they shell out to the canonical Python entry points so the
# Makefile never embeds policy that could drift from the runbook.

# Allow PYTHON override (e.g. `make PYTHON=.venv/bin/python smoke`).
# Default to python3 because some pyenv shims don't ship `python`.
PYTHON ?= python3

.PHONY: help smoke smoke-real test test-fast lint clean install

# Default target: print the help table.
help:
	@echo "Tessera developer targets"
	@echo ""
	@echo "  make install       Install -e '.[dev,agentdojo]' (Python 3.12+ venv)"
	@echo "  make test          Full pytest suite, quiet"
	@echo "  make test-fast     pytest -x --ff (stop on first failure, run fails first)"
	@echo "  make lint          ruff check + ruff format --check"
	@echo "  make smoke         AgentDojo dispatcher dry-run (no API keys required)"
	@echo "  make smoke-real    AgentDojo: one cell against claude-haiku-4-5"
	@echo "                     (requires ANTHROPIC_API_KEY)"
	@echo "  make clean         Remove build artifacts and __pycache__"
	@echo ""
	@echo "Live-API runbook:   docs/benchmarks/REAL_RUN_RUNBOOK.md"

## Install Tessera in editable mode with dev + agentdojo extras
install:
	$(PYTHON) -m pip install -e '.[dev,agentdojo]'

## Run the full Python test suite, quiet
test:
	$(PYTHON) -m pytest -q

## Stop on first failure; run previously-failed tests first
test-fast:
	$(PYTHON) -m pytest -x --ff -q

## ruff lint + format check (no fixes; use `ruff check --fix` for fixes)
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

## AgentDojo dispatcher dry-run (no API keys; verifies matrix shape only)
smoke:
	$(PYTHON) -m benchmarks.agentdojo_live.submit \
	    --models claude-haiku-4-5 \
	    --suites travel \
	    --attacks important_instructions \
	    --seeds 0 \
	    --max-pairs 1 \
	    --dry-run

## One real AgentDojo trial against Claude Haiku (cheapest live smoke)
##   Requires ANTHROPIC_API_KEY in the environment.
smoke-real:
	@if [ -z "$$ANTHROPIC_API_KEY" ]; then \
	    echo "ANTHROPIC_API_KEY not set. See docs/benchmarks/REAL_RUN_RUNBOOK.md"; \
	    exit 1; \
	fi
	$(PYTHON) -m benchmarks.agentdojo_live.run_haiku \
	    --suite travel \
	    --max-injection-pairs 1 \
	    --output benchmarks/agentdojo_live/results_haiku_smoke.json
	@echo ""
	@echo "Results written to benchmarks/agentdojo_live/results_haiku_smoke.json"

## Remove build artifacts and Python bytecode
clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
