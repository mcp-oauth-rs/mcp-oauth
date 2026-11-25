# Changelog

## 0.2.0 (unreleased)

One sign-in path: an allowlist of e-mail addresses and single-use enrolment
codes. The owner password is gone; a single-owner server is an allowlist of
one address. Upgrading: [Migration from 0.1](docs/migration.md).

### Breaking

- `Config::owner_password_hash`, `hash_password`,
  `DEFAULT_MAX_PASSWORD_CHECKS`, `OAuth::with_max_password_checks` and
  `OAuth::max_password_checks` are removed; argon2 is no longer a
  dependency.
- `Grant` gains `subject` (the user's address, normalised) and is
  `#[non_exhaustive]`.
- Token families of 0.1 carry no user and are not honoured, unless the
  server calls `OAuth::adopt_unowned_grants(owner_address)`.
- `REFRESH_TTL` is 180 days (was 30), renewed at every refresh.

### Added

- `Users`: the allowlist and its enrolment codes in
  `state_dir/oauth-users.json`, with an admin API for a command-line tool
  (`allow`, `enrol_code`, `revoke`, `list`) that may run in another process:
  changes are made under a file lock and the server rereads the file when it
  changes. `OAuth::users()` gives the server's handle.
- Enrolment codes: 80 random bits, `XXXX-XXXX-XXXX-XXXX` in Crockford
  base32, valid 24 hours (`ENROL_CODE_TTL`), single use, bound to their
  address, stored as SHA-256 only. Typed on the sign-in page, never sent as
  a link (mail scanners open links). Every refusal gets the same answer and
  counts as an authentication failure; a banned IP's code is not checked.
- `Users::revoke`: the user's access tokens are refused on the next request,
  their refresh tokens are refused and the grants removed; allowing the
  address again does not revive them (a generation per user).
- `OAuth::with_refresh_ttl` and `OAuth::refresh_ttl`.
- `Config` implements `Default`.
- The consent page says who signed in; the log names the user on each
  sign-in and authorization.

### Fixed

- CIMD: a `client_id` or `jwks_uri` URL whose host the HTTP client reads as
  an IPv4 address (`127.1`, `10.1`, `0x7f.0.0.1`, `0177.0.0.1`,
  `%31%32%37.0.0.1`, `169.254.169.254.`, full-width digits) passed the URL
  check, and the client connected to it directly, without the resolver that
  refuses special-purpose addresses. The URL check and the fetch now ask the
  HTTP client's own URL parser and fetch only a DNS name host.
- CIMD: beyond 8 fetches at once a request is refused at once instead of
  waiting up to 5 s for a slot, and one host gets at most 2 fetches at once.

- `fetches_shared_and_bounded` failed now and then with "9 connections at
  once": the local HTTPS test server counted a connection until it was
  closed, after the client had its response and released its fetch slot.
  It now counts requests in flight. The fetcher itself was correct.

### Documentation

- The README is split into parts under `docs/`; new parts:
  [Users and sign-in](docs/sign-in.md) with its threat model and what the
  server must do (HTTPS in front, a correct clock), and
  [Migration from 0.1](docs/migration.md).

## 0.1.0

First release: OAuth 2.1 authorization server, bearer layer and abuse guard
for single-owner MCP servers (owner password, argon2id).
