# Threat model

[Back to the README](../README.md)

Assumptions: one owner, one password, an HTTPS front (e.g. a tunnel or a
reverse proxy) that sets `CF-Connecting-IP` or `X-Forwarded-For`, and a host
you trust.

| Threat | What stops it |
|---|---|
| Password brute force | argon2id; 10 authentication failures per IP in 10 min ban that IP for 1 h; per-IP token bucket (120/min, burst 40); the password is never checked for a banned IP, also in shared-IP mode (see below) |
| Token guessing | opaque 32-byte random tokens; a bearer token never issued here counts as a failure |
| Stolen authorization code | PKCE S256 for every client; a wrong verifier for a live code burns the code and counts as a failure; a reused code revokes its grant |
| Refresh token theft | rotation on every use; replaying a rotated-out refresh token revokes the whole grant |
| Client assertion replay | `jti` required and single-use, `exp` within an hour, `aud` checked |
| Token leakage at rest | only SHA-256 digests of tokens and client secrets are stored, files mode 600, directory mode 700 |
| Open redirect / code interception | redirect URIs must match the configured patterns (https only, http only on loopback, no `..` or encoded separators) |
| SSRF through CIMD `client_id` URLs | https only, host names only (IP literals and userinfo refused), a resolver that drops RFC 6890 special-purpose addresses, no redirects, no proxy, 5 s timeout, 64 KiB cap; with an allowlist nothing outside it is ever fetched |
| Memory exhaustion | argon2 bounded to 2 concurrent checks with reused buffers (2 x 19 MiB); at most 8 outgoing fetches, one per URL shared by concurrent callers, no idle connections; bounded maps: 512 DCR clients, 1024 token families, 256 pending sign-ins and codes, 10 000 recent `jti`s, 256 cached documents; 1 MiB bodies, 32 requests at once, 120 s timeout |
| Banning real clients | unknown paths (unless `count_unknown_path` says so), harmless probes and discovery URLs (always), expired or reused codes, unknown `client_id`s and CIMD fetch failures never count as failures; failures while banned do not extend the ban |
| One client getting a shared IP banned for everyone behind it (NAT) | `serve_authenticated_when_banned`: a banned IP still gets the answers to valid credentials, and only those |

Out of scope: a compromised host or `state_dir` (whoever can write it can
replace the hash or the token store), a leaked owner password, a
compromised client (claude.ai, ChatGPT or the owner's machine holding a
valid token), volumetric DDoS (leave that to the front: the caps here only
bound what reaches the process), and multi-user servers (there is one owner
and one scope, `mcp`). Client IP headers are trusted as sent: spoofing them
only spreads an attacker over buckets they could get with more IPs, and the
global caps still hold.

## Shared IPs (`serve_authenticated_when_banned`)

A home or office network, a campus or a mobile carrier (CGNAT) puts many
clients behind one public address. The ban is per IP, so anything on that network that collects
ten failures (a misconfigured tool, a browser extension, a compromised
device, a scanner with `count_unknown_path` on) bans every legitimate client
there for an hour. With `serve_authenticated_when_banned: true` a ban stops
guessing but never cuts a client that proves valid credentials:

- a banned IP's requests still pay the per-IP token bucket (120/min, burst
  40), then run; the response goes back only if it carries the
  `Authenticated` extension, anything else becomes `429 banned` (fail closed:
  a route that does not authenticate, a 404, a 405 or an extractor rejection
  never reaches a banned IP);
- failures while banned are neither counted nor logged and do not extend the
  ban, so the ban ends on time even if the culprit keeps going;
- no oracle for the bearer-style secrets: access and refresh tokens, codes,
  client secrets and sign-in tickets are 256-bit random values and client
  assertions are signatures, so telling a banned IP "valid" (the normal
  answer) versus "429" (for anything else) helps no guess.

What a banned IP gets in this mode:

| Request from a banned IP | Answer |
|---|---|
| `/mcp` with a valid bearer token | served (marked by `bearer_layer`) |
| `/mcp` with an expired token issued here (refresh still possible) | `401 invalid_token`, so the client refreshes |
| `/mcp` with no token or an unknown token | 429 |
| Protected resource and authorization server metadata | served (public documents clients fetch again before refreshing) |
| `/oauth/token`: client authentication (none, secret or assertion) **and** grant (code + PKCE verifier, or refresh token) valid | served (marked) |
| `/oauth/token`: anything else (wrong secret, assertion, verifier, unknown code or refresh token, malformed) | 429, not counted |
| `/oauth/authorize` consent step with a live sign-in ticket (password typed before the ban) | served (marked) |
| `/oauth/authorize` login step (owner password), right or wrong | 429, the password is **not checked** |
| `/oauth/authorize` page, `/oauth/register` | 429, no side effect (no CIMD fetch, nothing registered) |
| `/oauth/revoke` of a token issued here / of anything else | 200 (marked) / 429 |
| The app's routes | what the app marks with `authenticated(..)`, 429 otherwise |
| Unknown paths, harmless probes | 429, not counted, not logged |
| `exempt_paths` (`/healthz`) | served, as always |

Why the owner password does not count, although a right password proves
the owner: the owner password is the one low-entropy secret here. If a banned
IP could submit passwords and tell the right one by its answer (consent page)
from the wrong ones (429), the ban would turn into a password oracle at the
token bucket rate, 120 guesses a minute instead of 10 an hour. So the login
step answers 429 to a banned IP before the password is looked at (no argon2
run, no password slot taken), whatever the password. The cost is that the
owner cannot sign a *new* client in from a banned IP until the ban ends;
clients already connected keep working (bearer tokens, refresh), and a
sign-in started before the ban can still be approved.

With the default (`false`), a banned IP gets `429 banned` before any handler
runs, valid credentials or not, as before.
