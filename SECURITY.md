# Security

`simplifi-mcp` is a security-hardened Rust rewrite of an unofficial Quicken Simplifi
MCP server. It talks to Simplifi's **internal, undocumented** web API with the user's
own account, so its threat model has two unusual axes: (1) the data it caches is the
user's complete financial ledger, and (2) sloppy automation can get the user's real
finance account flagged or locked by Quicken's anti-fraud systems. Both are treated
as security problems here.

This project was built against a full security audit of the upstream TypeScript
implementation performed as part of the port (2026-07-31). The finding IDs `SA-01` …
`SA-22` used below refer to that audit; its requirements checklist maps onto the
mitigations table in this file. (The audit itself covers the upstream project and is
not republished here; upstream findings that are architectural — cleartext storage,
fail-open OAuth defaults, login storms — are described generically below.)

## Threat model

**In scope**

- Theft of Simplifi credentials/tokens or the cached ledger from disk or logs
- A compromised or malicious MCP client silently corrupting financial records
- Automation patterns that trigger Quicken anti-fraud lockouts (login storms,
  device-identity churn, request floods)
- SSRF/token exfiltration via upstream-controlled URLs (`metaData.nextLink`)
- Exposure of the optional HTTP transport beyond the local machine
- Supply-chain risk in the dependency tree

**Out of scope (by design — single-user, local server)**

- Multi-user isolation and a downstream OAuth authorization server. Upstream shipped
  a fail-open OAuth AS (SA-02/04/06/07/16/19); this port deliberately does not
  reimplement it. The stdio transport inherits the local process boundary; the
  optional HTTP transport uses one static bearer token (below).
- Defense against a hostile local root/admin.

## Implemented mitigations

| Area | Mitigation | Audit ref |
|---|---|---|
| Secrets at rest | Token cache sealed with XChaCha20-Poly1305 (random 24-byte nonce, file-magic AAD); key from macOS Keychain, env, or 0600 key file; **no plaintext fallback**; wrong key / tampered file fails closed | SA-01 |
| File hygiene | Cache dir `0700`, cache/audit files `0600`, atomic tmp+rename writes, permissions re-verified at every open, refuse to run otherwise; default data dir outside the source tree | SA-01 |
| Credentials | Simplifi password never persisted; env-only sourcing (1Password `op run` pattern), held in `secrecy::SecretString`, zeroized on drop; refresh-token-only operation after one interactive `login` | SA-01 |
| Login storms | Single-flight token acquisition; exponential backoff on refresh failure; refresh failure **never** auto-escalates to a password login unless `SIMPLIFI_AUTO_PASSWORD_LOGIN=1`; hard rolling-24h credential-login budget (default 3, persisted) with quarantine; MFA surfaced interactively, never brute-looped | SA-03 |
| Device identity | ThreatMetrix session id generated **once**, persisted, and reused; stable browser-like UA and app headers | SA-03 |
| Upstream traffic | Global pacing floor between requests (default 250 ms); `429`/`503` `Retry-After` honored with capped retries; bounded pagination (max pages) with nextLink cycle detection | SA-03/SA-13 |
| SSRF | Every followed `nextLink` re-validated: https-only, exact-host allowlist, no userinfo, no port override; reqwest built with rustls, `https_only(true)`, redirects **disabled** | SA-05 |
| Write surface | MCP server **read-only by default**; `SIMPLIFI_MCP_ALLOW_WRITES=1` required for any mutation; HAR-unverified endpoints (create/bulk/delete) additionally behind `SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1`; bulk import requires `confirm:true` | SA-09 |
| Patch typing | `update_transaction` takes a typed, allowlisted patch (`deny_unknown_fields`); protected fields (`accountId`, `isDeleted`, `state`, …) are rejected at the schema boundary; no free-form deep merge, no JSON-string double-parse | SA-09/SA-14 |
| Audit trail | Append-only JSONL mutation journal (`data_dir/audit.jsonl`, 0600): `attempt` record with before-image **before** any upstream traffic, `result` record with after-image/ack after; if the journal cannot be opened the server forces read-only (fail closed) | SA-09 |
| Write quota | Rolling per-hour mutation cap (default 60; bulk rows count individually) | SA-09 |
| Sync amplification | Hard minimum interval between upstream syncs that `refresh:true` cannot bypass; sync execution is single-flight; post-write state comes from the mutation response, not a full resync | SA-13 |
| Error hygiene | Upstream response bodies are never interpolated into errors, logs, or persisted state — status + short truncated error code only; reqwest errors are URL-scrubbed; `status` CLI output is redacted | SA-11 |
| HTTP transport (optional feature) | Bearer token **required** at startup (≥ 32 chars), compared SHA-256 + constant-time; binds `127.0.0.1` by default and refuses non-loopback without an explicit acknowledgment env; stateless sessions (no unbounded session map); zero CORS headers; 401 = empty body + `WWW-Authenticate`; `no-store`/`nosniff`/`X-Frame-Options: DENY`/`no-referrer` on every response; rmcp DNS-rebinding (Host) validation left on | SA-06/SA-10/SA-12/SA-16/SA-21 |
| No bundled secrets | Quicken's web-client secret is **not** shipped in source, env samples, or docs — users must read it from their own browser session | SA-18 |
| Schema strictness | Every MCP tool input is `deny_unknown_fields` (`additionalProperties: false`); amounts are decimal strings end-to-end (no f64 arithmetic); dates validated as ISO | SA-14 |
| CSV safety | CSV exports sanitize formula-injection prefixes (`=`, `+`, `-`, `@`); imports are size-capped (1000 rows) with per-row error collection | — |

## Known gaps / deliberate deviations

- **No downstream multi-user OAuth AS** (see scope above). Use stdio, or the HTTP
  transport on loopback with its static bearer token.
- **The in-memory ledger mirror is not persisted** — nothing of the ledger touches
  disk except the encrypted token cache and (when writes are enabled) the audit
  journal, which intentionally stores before/after transaction images at the same
  0600/0700 permission class. Rotation/retention of the journal is the operator's
  responsibility.
- **`create`/`bulk`/`delete` wire shapes are inferred, not HAR-verified** — hence
  double-gated off by default.
- **No `undo_transaction_change` tool yet**; the audit journal's before-images make a
  manual restore possible via `update_transaction`.
- **Keychain bootstrap** briefly passes the new cache key through `security(1)` argv
  on first creation (visible in `ps` for that instant); avoid entirely by supplying
  `SIMPLIFI_MCP_TOKEN_KEY` via `op run`.
- **No tracing redaction layer**: log hygiene relies on the error taxonomy never
  carrying secrets/bodies (verified by tests) rather than a scrubbing formatter.
  Logs go to stderr only.
- Supply chain: `cargo audit` is clean at commit time (0 advisories, 265 crates);
  there is no CI in this repo yet, so re-run `cargo audit` and `cargo clippy` before
  releases. Recommended for publication: `cargo deny`, `--locked` builds, SBOM.

## Account-safety notes for users

- This is an **unofficial** integration. Quicken's Terms of Service plausibly prohibit
  automated access; use at your own risk, on your own account, single-user.
- Keep the SA-03 defaults. They are what stands between a transient auth failure and
  ~1,440 password logins/day against your real finance account (the upstream failure
  mode). Raising `SIMPLIFI_MAX_CREDENTIAL_LOGINS_PER_24H` or setting
  `SIMPLIFI_AUTO_PASSWORD_LOGIN=1` increases lockout risk.
- Prefer `simplifi-mcp login` once (interactive, MFA-aware), then refresh-token-only
  operation.

## Reporting a vulnerability

Open a GitHub security advisory (preferred) or an issue with the label `security`
on the project repository. Do not include real financial data, tokens, or your
ThreatMetrix session id in reports.
