# Users and sign-in

[Back to the README](../README.md)

Every user is known by an e-mail address. An administrator allows
addresses and hands out single-use enrolment codes; users type their
address and code on the sign-in page; every grant carries the address as
`Grant::subject` (trimmed, lower case). There is no password. A
single-owner server is an allowlist of one address.

## Setup

`OAuth::new(config)`; set the [CIMD allowlist](cimd-allowlist.md). A
handler behind `bearer_layer()` reads `Extension(g): Extension<Grant>` and
`g.subject`. Refresh tokens live `REFRESH_TTL` (180 days, renewed at each
refresh; `with_refresh_ttl` changes it). Servers coming from version 0.1:
see [Migration from 0.1](migration.md).

## Admin API

`Users::open(state_dir)` (or `OAuth::users()` in the server) is for a
command-line tool; it is never exposed over HTTP or MCP.

| Call | Effect |
|---|---|
| `allow(email) -> Result<bool, String>` | puts the address on the allowlist, or back on it after a revocation; `false` if already active |
| `enrol_code(email) -> Result<String, String>` | a new code `XXXX-XXXX-XXXX-XXXX` (Crockford base32, 80 random bits), valid 24 h (`ENROL_CODE_TTL`), single use, for that address only; replaces an unused earlier code; only its digest is stored, so print it once. Refused for an address that is not active |
| `revoke(email) -> Result<bool, String>` | the address leaves the allowlist (kept as revoked), its code is dropped, and all its access and refresh tokens stop working at once, for good: allowing it again needs a new code and does not revive them |
| `list() -> Result<Vec<User>, String>` | every address: `active`, `added_at`, `revoked_at`, `code_expires_at` (live code), `last_sign_in_at`; never a code |

```rust
let users = mcp_oauth_server::Users::open("/state")?;
users.allow("ada@example.org")?;
println!("{}", users.enrol_code("ada@example.org")?);
```

The tool may be another process on the same `state_dir` (e.g. through
`kubectl exec` into the server's pod): every change is made under an
exclusive lock on `oauth-users.lock`, and the server rereads
`oauth-users.json` when it changed, so a revocation applies to the very next
request, without a restart.

## Signing in

1. The administrator runs `allow` and `enrol_code` and sends the code by
   hand. A code, not a link: mail scanners (Outlook's among them) open the
   links of incoming mail and would use up a single-use link.
2. The user adds the connector. The sign-in page asks for the e-mail address
   and the code (case, spaces and dashes do not matter; O, I and L read as
   0, 1, 1); the consent page shows "Signed in as ...".
3. The client keeps a refresh token. A new code is needed only after 180
   days without use, for a new client connection, or after a revocation.

Every refusal (address not allowed or revoked, wrong, expired or used code)
gets the same `401` page, "Unknown address, or wrong, expired or already
used code.", logs its reason on stderr and counts as an authentication
failure: 10 in 10 min ban the IP for 1 h, and a banned IP's sign-in is not
checked at all (its code is not used up), also in shared-IP mode.

## Threat model (sign-in)

| Threat | What stops it |
|---|---|
| Guessing a code | 80 random bits, 24 h, single use, bound to one address; the per-IP ban; no check at all for a banned IP |
| Listing the allowed addresses | one answer for every refusal |
| A code intercepted on its way | single use: the first sign-in consumes it; `list()` shows `last_sign_in_at`; `revoke` and a new code |
| Mail scanners opening links | there is no link to open; the code is typed |
| Two sign-ins racing with one code | the file lock: exactly one gets a ticket |
| A user leaving | `revoke`: access tokens refused on the next request (no 1 h wait), refresh refused and the grant removed; the code exchange of a sign-in in progress is refused too |
| A leaked `state_dir` | SHA-256 of tokens and of address-bound 80-bit codes; addresses in clear |
| A stolen refresh token | rotation with reuse detection; `revoke` for the user |

Out of scope, beyond the [general list](threat-model.md): a mailbox or
chat account read by someone else before the user types the code (they sign
in as the user; the sign-in is logged and `revoke` ends it), and proof that
a person owns an address: the administrator vouches for it by handing the
code to the right person. Long refresh tokens widen the window of a stolen
one; revocation is the answer, so keep the admin tool at hand.

## What the server must do

- Serve HTTPS only, behind a TLS front (tunnel or reverse proxy) that sets
  `CF-Connecting-IP` or `X-Forwarded-For`: codes and tokens travel in forms
  and headers.
- Keep the clock right (NTP): code and token expiry compare Unix time; a
  clock set back lengthens codes, set forward expires grants early.
- Keep `state_dir` on a persistent local filesystem (the lock is `flock`;
  not NFS), mode 700, and run the admin tool as the server's user on it.
- Treat backups and logs as personal data: they hold the addresses.
- Use `grant.subject` for anything per user; never an identity sent by the
  client. Consider `serve_authenticated_when_banned` behind a campus NAT.
