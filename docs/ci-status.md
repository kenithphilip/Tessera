# CI workflow status

Last full audit: 2026-04-26. Refreshed when a workflow regresses.

| Workflow | Trigger(s) | Last 5 status | Notes |
| --- | --- | --- | --- |
| `ci.yml` | push (main), PR | 5/5 green | Python test suite + lint. |
| `wheels.yml` | push (main), tag | 5/5 green | Builds the PyO3 / maturin wheels. |
| `publish-scorecard.yml` | tag (`v*`) | 5/5 green | Last fired on `v1.0.2`. |
| `registry-mirror.yml` | schedule (every 6h), workflow_dispatch | 2/5 green | Earlier failures (2026-04-26 05:30-05:45) were the 7-layer cascade resolved in commits up to `3dccb97`. Two consecutive green runs after the fix; cron is healthy. |
| `spire-integration.yml` | push (main), workflow_dispatch | 4/5 green | Push trigger went live in `fe7ddee`. The single failure (`24968343126`) was the JWT bundle walker bug fixed in `3dccb97`; three consecutive workflow_dispatch greens followed, then the push from `fe7ddee` ran green automatically. |

## How to re-audit

```bash
for wf in ci wheels publish-scorecard registry-mirror spire-integration; do
  echo "=== $wf ==="
  gh run list --workflow=${wf}.yml --limit 5
done
```

Refresh this table when:

- Any workflow shows two consecutive failures (likely a real
  regression rather than a flaky retry).
- A workflow trigger changes (e.g. cron schedule, branch
  filter).
- A workflow is added or retired.

## Known flake patterns

None at present. All five workflows are deterministic against
their respective triggers. If a flake appears, document it here
with the run id and the suspected cause before adding a retry
loop or `if: failure()` workaround.
