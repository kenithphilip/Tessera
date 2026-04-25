# 3H-1: SPIFFE SVID validator plugin

## Status

GATED on a discussion issue with the upstream maintainers about how
they want plugin crates to land. agentgateway/agentgateway has no
`plugins/` workspace directory today and no documented plugin trait.

## Target

- Repo: https://github.com/agentgateway/agentgateway
- Branch base: `main`
- License (upstream): Apache-2.0
- License (this contribution): Apache-2.0 (matches)

## Discussion issue (file first)

Title: `SPIFFE SVID validation plugin: how should external plugin crates land?`

Body:
> Tessera (https://github.com/kenithphilip/Tessera) has a
> Rust crate at
> https://github.com/kenithphilip/Tessera/tree/main/rust/agentgateway-plugins/spiffe-svid-validator
> that parses and validates SPIFFE SVIDs against an
> operator-pinned trust domain. We would like to upstream it.
>
> The repo's current `crates/` workspace doesn't include a
> `plugins/` directory and we couldn't find a documented plugin
> trait. Could you point us at the intended extension model? We
> see three options:
>
> 1. Land the crate as `crates/spiffe-svid-validator` and have
>    `agentgateway` depend on it under a feature flag.
> 2. Define a plugin trait in `core` and have us implement it.
> 3. Inline the validation logic into the existing `xds` or
>    `core` crates.
>
> Happy to do whichever fits your roadmap. The crate is 183 LOC,
> Apache-2.0 licensed, has unit tests, and depends only on
> `x509-parser` plus the in-development `spiffe` crate.

## PR title (after maintainer signal)

`feat: SPIFFE SVID validator plugin from Tessera`

## PR body

```markdown
## Summary

Adds a Rust plugin that parses and validates SPIFFE SVIDs against
an operator-pinned trust domain. Source attribution: ported from
Tessera v1.0 (https://github.com/kenithphilip/Tessera) which has
been validating SVIDs against a Workload API since v0.7.

## What it does

- Parses an x509 SVID URI SAN per RFC 9525 / SPIFFE ID spec.
- Verifies the trust domain matches the operator-pinned value.
- Returns a structured `SvidValidationError` enum on rejection
  (not a string), so downstream code can rate-limit / log per
  reason.

## Why agentgateway needs this

agentgateway is positioned as the LF-backed gateway for AI
agents and MCP servers. SPIFFE/SPIRE is the dominant workload
identity stack in cloud-native deployments, and gating MCP tool
calls on a verified SVID is a baseline security control. Today
operators have to bring their own validator.

## Test plan

- [x] Unit tests pass: `cargo test -p agentgateway-spiffe-svid-validator`
- [ ] Integration test against a SPIRE-attested workload
- [ ] Documentation example in `examples/`

## Dependencies

- `x509-parser` 0.16 (Apache-2.0 / MIT)
- `spiffe` (when published; currently a workspace path dep)

## License

Apache-2.0, matching the agentgateway project. DCO sign-off on
every commit per the Tessera contribution policy.

## Source attribution

Originally from `tessera/rust/agentgateway-plugins/spiffe-svid-validator/`.
That directory will be deleted from the Tessera repo once this
PR merges and Tessera will depend on the upstream crate.
```

## Submission checklist

- [ ] File the discussion issue listed above.
- [ ] Wait for maintainer response on plugin model.
- [ ] Fork agentgateway/agentgateway under your account.
- [ ] Branch: `feat/spiffe-svid-validator-from-tessera`.
- [ ] Copy `rust/agentgateway-plugins/spiffe-svid-validator/` into
      the location the maintainer specified.
- [ ] DCO sign-off every commit (`git commit -s`).
- [ ] Open PR with the body above.
- [ ] Link the PR back into the tracking issue in
      kenithphilip/Tessera.
