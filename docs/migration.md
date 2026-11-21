# Migration from 0.1

[Back to the README](../README.md)

Version 0.2 has one sign-in path: an allowlist of e-mail addresses and
single-use enrolment codes ([Users and sign-in](sign-in.md)). The owner
password is gone. A single-owner server becomes an allowlist of one address.

## API

| 0.1 | 0.2 |
|---|---|
| `Config::owner_password_hash` | removed; `Config` implements `Default` |
| `hash_password`, `DEFAULT_MAX_PASSWORD_CHECKS`, `OAuth::with_max_password_checks`, `OAuth::max_password_checks` | removed (no password, no argon2) |
| `Grant { client_id, scope }` | `Grant { client_id, scope, subject }`, `#[non_exhaustive]`: reading fields and `g.client_id` moves still compile; building or destructuring a `Grant` exhaustively does not |
| `REFRESH_TTL` 30 days | 180 days; `OAuth::with_refresh_ttl` |
| (none) | `Users` (`open`, `allow`, `enrol_code`, `revoke`, `list`), `User`, `ENROL_CODE_TTL`, `normalize_email`, `OAuth::users`, `OAuth::adopt_unowned_grants` |

## In the server's code

1. Drop `owner_password_hash` from the `Config` literal.
2. Replace the variable that turned OAuth on (`<PREFIX>_OWNER_PASSWORD_HASH`)
   with the owner's address, `<PREFIX>_OWNER_EMAIL`, and after `OAuth::new`:

   ```rust
   let o = mcp_oauth_server::OAuth::new(cfg)?;
   o.users().allow(&owner_email)?;          // idempotent
   o.adopt_unowned_grants(&owner_email)?;   // 0.1 grants keep working; 0 later
   ```

3. Replace the `hash-password` subcommand with `enrol <address>`:
   `Users::open(state_dir)`, `allow(address)`, print `enrol_code(address)`.
4. Remove `[profile.dev.package.argon2]` and `[profile.dev.package.blake2]`
   from `Cargo.toml` (cargo warns that they match no package), and any
   `argon2` dependency kept only to check the hash.
5. Tests that typed the password: post `email` and `code` instead of
   `password`, with a code from `Users::open(state_dir)` (`allow`, then
   `enrol_code`); a wrong-password check becomes a wrong-code check, whose
   page says "Unknown address, or wrong, expired or already used code."

A server that reads the hash from a configuration file rather than the
environment does the same with its key there (and drops its own argon2
check of the hash at load, if it had one).

## Operations

- Deploy with `<PREFIX>_OWNER_EMAIL` set. Thanks to `adopt_unowned_grants`,
  every connector already authorised keeps working: its token family is
  given to the owner's address (it was the owner's; nothing else could have
  issued it). The start log says how many families were adopted.
- Without that call, families of 0.1 are not honoured: every connector is
  answered 401 with `error="invalid_token"`, cannot refresh, and must be
  authorised once more (`enrol` prints the code to type).
- New connectors: run `enrol <address>`, type the address and the code on
  the sign-in page within 24 hours.
- Remove the password hash from the deployment's secrets.

## Measured on kidctl

A throwaway copy of kidctl at its pinned 0.1 commit, moved to 0.2:
`Cargo.toml`, `src/main.rs`, `src/serve.rs`, 72 lines added and 70 removed.
`cargo build`, `cargo clippy --all-targets -- -D warnings` and `cargo test`
(94 tests, the same count as before) pass. The changes are the five steps
above: an `owner_email` field on its `McpAuth` (allow and adopt after
`OAuth::new`), `Enrol { email, state_dir }` instead of `HashPassword`, and
its OAuth test helpers taking the state directory to enrol a code.
