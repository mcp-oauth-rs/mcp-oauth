# Abuse protection (`protect`)

[Back to the README](../README.md)

- Per-IP token bucket on every request except `Limits::exempt_paths`
  (`/healthz`): 120/min sustained, burst 40; 429 with `retry-after: 30`.
- Ban (429) for 1 h after 10 authentication failures in 10 min. Failures are
  a bearer token never issued here (an expired one does not count), a wrong
  owner password, a wrong client secret, a rejected client assertion, a wrong
  PKCE verifier for a live authorization code of that client (the client
  that asked for the code holds its verifier, so this is a stolen code; the
  code is burnt too), and whatever the app reports through `AuthFailures`
  (or `Guard::auth_failed` on a clone of the guard), plus unknown paths if
  `Limits::count_unknown_path` says so. Failures while an IP is banned are
  not counted, not logged and do not extend the ban.
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
- Owner password checks (argon2id, 19 MiB of memory each with
  `hash_password`): at most 2 at once (`OAuth::with_max_password_checks`).
  A sign-in that finds both busy gets the login page again at once with
  `503` and `Retry-After: 2`; its password is not checked and nothing is
  counted. Each slot keeps its argon2 buffer for the next check, so password
  checks never hold more than 2 x 19 MiB, however many requests come in. This
  lives in `OAuth`, not in `protect`, so it holds without the guard too.

Memory of a release binary on a glibc 2.41, 20-core server for N concurrent
wrong passwords from N distinct IPs (`VmHWM` peak, `VmRSS` 15 s after the
burst; base 13 MiB):

| N concurrent | before: peak | before: kept | after: peak | after: kept | after: answers |
|---|---|---|---|---|---|
| 1 | 31 MiB | 13 MiB | 32 MiB | 32 MiB | 1 x 401 |
| 8 | 164 MiB | 13 MiB | 51 MiB | 51 MiB | 2 x 401, 6 x 503 |
| 60 | 644 MiB | 643 MiB | 53 MiB | 53 MiB | 2 x 401, 58 x 503 |
| 60, 20 bursts | 1165 MiB | 1164 MiB | 61 MiB | 61 MiB | 40 x 401, 1160 x 503 |

The bound on concurrent checks is what removes both the peak and the
retention: unbounded, every concurrent check got its own 19 MiB in its own
malloc arena, and glibc keeps arena memory. Why the buffers are also kept:
a buffer freed after each check does not reliably go back to the system
either (glibc raises its mmap threshold to the size of the first freed
19 MiB chunk, later ones come from the arenas), and how much stays depends
on how many arenas glibc creates (up to 8 per core). Measured over 60 bursts
of 60 (3600 checks): fresh buffers kept 52-53 MiB over base, kept buffers
49-51 MiB, about the same here; but with kept buffers the argon2 share is
exactly 2 x 19 MiB whatever the allocator and the core count, at the price
of holding it from the first sign-in on (32 MiB RSS after one login instead
of 13 MiB). The rest of the growth over many bursts is per-IP guard state
and allocator overhead.
