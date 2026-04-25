# Tessera plugins for upstream agentgateway

In-tree home for three Rust plugins targeting the upstream
agentgateway project (https://github.com/solo-io/agentgateway). The
plugins live here until the upstream PRs land, then they move to
the upstream repo and Tessera depends on them via Cargo.

## Plugins

| Crate | What it does | Reuses |
| --- | --- | --- |
| `tessera-agentgateway-spiffe-svid-validator` | Parses + validates SPIFFE SVIDs against an operator-pinned trust domain | upstream `spiffe` crate (in PR), `x509-parser` |
| `tessera-agentgateway-audit-event-sink` | Hash-chained audit event sink (mirrors `tessera.compliance.ChainedAuditLog`) | `sha2` |
| `tessera-agentgateway-mcp-drift-scanner` | Behavioral drift detection (shape + latency p99) per upstream MCP server | none |

## Build + test

```bash
cd rust
cargo test -p tessera-agentgateway-spiffe-svid-validator
cargo test -p tessera-agentgateway-audit-event-sink
cargo test -p tessera-agentgateway-mcp-drift-scanner

# Build the entire workspace including the plugins.
cargo check --workspace
```

## Upstream PR targets

- spiffe-svid-validator: https://github.com/solo-io/agentgateway/pull/<TBD-3H-spiffe>
- audit-event-sink: https://github.com/solo-io/agentgateway/pull/<TBD-3H-audit>
- mcp-drift-scanner: https://github.com/solo-io/agentgateway/pull/<TBD-3H-drift>

Once each PR merges, the corresponding crate moves out of this
directory and Tessera (and downstream consumers) pick it up from
the upstream repo via a `[dependencies]` entry.

## License

Apache-2.0 (matches the Tessera library), to align with the
agentgateway project's expected inbound license.
