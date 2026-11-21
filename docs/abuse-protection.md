# Abuse protection (`protect`)

[Back to the README](../README.md)

- Per-IP token bucket on every request except `Limits::exempt_paths`
  (`/healthz`): 120/min sustained, burst 40; 429 with `retry-after: 30`.
- Ban (429) for 1 h after 10 authentication failures in 10 min. Failures are
  a bearer token never issued here (an expired one does not count), a
  refused enrolment code (unknown address, wrong, expired or used code), a
  wrong client secret, a rejected client assertion, a wrong PKCE verifier
  for a live authorization code of that client (the client that asked for
  the code holds its verifier, so this is a stolen code; the code is burnt
  too), and whatever the app
  reports through `AuthFailures` (or `Guard::auth_failed` on a clone of the
  guard), plus unknown paths if `Limits::count_unknown_path` says so.
  Failures while an IP is banned are not counted, not logged and do not
  extend the ban.
- A banned IP is rate-limited like any other (its requests pay the token
  bucket). In shared-IP mode (`serve_authenticated_when_banned`) its
  requests run and only responses marked `Authenticated` go back; see
  [Shared IPs](threat-model.md#shared-ips-serve_authenticated_when_banned). An app marks its
  own verified credentials with `mcp_oauth_server::authenticated(response)`.
- Not counted, because real clients hit them: an unknown, expired or already
  used authorization code (restarts, retries, races; a reused code still
  revokes its grant), a code presented by another client, an unknown
  `client_id`, and a CIMD `client_id` URL that is not on the allowlist, cannot
  be fetched (timeout, network error, 5xx) or has an invalid document: a
  Claude client whose metadata fetch timed out must not get its (often
  shared) IP banned. Those only cost the rate limit.
- Unknown paths (no route matched): the app's own fallback answers if it
  has one (`protect` keeps it), else axum's 404; rate-limited; logged on
  stderr as `debug: unknown path <METHOD> <path> from <ip>` (path without
  query; not for a banned IP). Not counted by default; with
  `count_unknown_path: Some(f)`, counted when `f(&method, path)` is true,
  except `harmless_probe`s (`GET`/`HEAD` on `/`, `/favicon.ico`,
  `/robots.txt`, anything under `/.well-known/`), which never count. For
  example, to count scanner paths: `count_unknown_path: Some(|_, _| true)`.
  An app whose fallback counts failures itself should leave the hook `None`
  (or both count).
- Body cap 1 MiB, request timeout 120 s (408), 32 concurrent requests.
- An enrolment code check is a SHA-256 and a small file update under a lock,
  run off the async workers; nothing in a sign-in costs memory in proportion
  to the attacker's effort. (Version 0.1 bounded its argon2 password checks
  to 2 at once for that reason; there is no password since 0.2.)
