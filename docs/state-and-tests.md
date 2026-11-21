# State at rest and tests

[Back to the README](../README.md)

## State at rest

`state_dir/oauth-clients.json` (DCR clients, client secret as SHA-256) and
`state_dir/oauth-tokens.json` (SHA-256 of access and refresh tokens), written
atomically with mode 600. Codes, login tickets, CIMD documents and assertion
`jti`s are in memory. Delete `oauth-tokens.json` and restart to log every
client out.

## Tests

`cargo test`: unit tests per module and end-to-end flows (`src/flow_tests.rs`:
DCR, CIMD public and `private_key_jwt`, allowlist and DCR grace, failure
counting, password check bound, a banned shared IP), the guard as another
crate uses it (`tests/public_api.rs`), with CIMD documents served from memory, and
the production HTTP fetcher against a local HTTPS server (`src/test_https.rs`,
test CA in `src/testdata/`, every `*.cimd.test` name resolved to it, nothing
leaves the machine): size cap, redirects, timeout, shared and bounded
fetches, and the Claude, Claude Code and ChatGPT flows end to end.
`cargo test --doc` compiles the [quickstart](quickstart.md#quickstart).
`cargo test --release -- --ignored cimd_fetch_memory --nocapture` prints the
memory and fetch counts of 60 concurrent authorize requests with CIMD URLs.
`cargo test -- --ignored live_vendor_documents` fetches the real Claude,
Claude Code and ChatGPT documents and ChatGPT's JWKS through the production
fetcher and checks that a public name resolving to loopback is refused.

`ci/run.sh` runs the whole CI locally (format, clippy with `-D warnings`,
tests, docs, gitleaks over the history, workflow lint); GitHub Actions calls
the same script.
