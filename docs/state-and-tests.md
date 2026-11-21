# State at rest and tests

[Back to the README](../README.md)

## State at rest

`state_dir/oauth-clients.json` (DCR clients, client secret as SHA-256),
`state_dir/oauth-tokens.json` (SHA-256 of access and refresh tokens, and
per family the user's address and generation) and
`state_dir/oauth-users.json` (see below), written atomically with mode
600. Codes, login tickets, CIMD documents and assertion `jti`s are in
memory. Delete `oauth-tokens.json` and restart to log every client out, or
`Users::revoke` one user.

`oauth-users.json` holds per address its generation, whether it is active,
dates, and the SHA-256 of the live enrolment code bound to the address;
never a code. It is written under an exclusive lock on
`state_dir/oauth-users.lock`. A token family is honoured only while its
address is active with the same generation, which every revocation
increments. See [Users and sign-in](sign-in.md).

## Tests

`cargo test`: unit tests per module and end-to-end flows (`src/flow_tests.rs`:
DCR, CIMD public and `private_key_jwt`, allowlist and DCR grace, failure
counting, a banned shared IP; `src/sign_in_tests.rs`:
allowlist, expired, reused and other people's codes, racing sign-ins,
revocation by another handle for bearer and refresh, the ban on code
failures, the subject in the grant, the adoption of 0.1 grants;
`src/users.rs`: the store and its admin API), the guard as another
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

