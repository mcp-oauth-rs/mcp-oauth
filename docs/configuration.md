# Configuration

[Back to the README](../README.md)

## `Config`

| Field | Meaning |
|---|---|
| `issuer` | Public origin, e.g. `https://mcp.example.net`: https, no path, query or fragment (http only on `localhost` / `127.0.0.1`); one trailing slash is dropped. It is the issuer; the protected resource is `issuer + mcp_path` |
| `mcp_path` | Path of the bearer-protected MCP route, e.g. `/mcp`; must start with `/` |
| `owner_password_hash` | argon2id PHC string of the single owner's password (`hash_password`) |
| `state_dir` | Directory for `oauth-clients.json` and `oauth-tokens.json`; created mode 700 if missing |
| `redirect_patterns` | Redirect URIs a client may use, by DCR or in its metadata document; non-empty; `DEFAULT_REDIRECT_PATTERNS` covers Claude, Claude Code and ChatGPT (see [Protocol details](protocol.md#protocol-details)) |
| `resource_name` | Display name on the login and consent pages and `resource_name` of the resource metadata |
| `cimd_allowlist` | `None`: DCR open, any https `client_id` URL accepted as a metadata document. `Some(urls)`: only those `client_id` URLs (exact match), DCR off. See [CIMD allowlist](cimd-allowlist.md) |

`OAuth::new(Config) -> Result<OAuth, String>` validates all of it, creates
`state_dir` and loads the persisted clients and tokens.

## Builders

| Builder | Default | Meaning |
|---|---|---|
| `OAuth::with_dcr_grace(bool)` | `true` | Only with an allowlist: whether tokens already held by clients outside it keep working (see [CIMD allowlist](cimd-allowlist.md)) |
| `OAuth::with_max_password_checks(n)` | `DEFAULT_MAX_PASSWORD_CHECKS` = 2 (minimum 1) | Owner password checks running at once; beyond that the login page comes back with `503` and `Retry-After: 2` (see [Abuse protection](abuse-protection.md)) |

## `Limits` (for `Guard::new`)

| Field | `Limits::default()` |
|---|---|
| `per_ip_per_min` / `per_ip_burst` | 120 / 40 |
| `max_failures` within `fail_window`, then banned for `ban_for` | 10 in 600 s, ban 3600 s |
| `max_body_bytes` | 1 MiB |
| `request_timeout` | 120 s (answered with 408) |
| `max_concurrency` | 32 |
| `exempt_paths` | `["/healthz"]` (no rate limit, no ban) |
| `serve_authenticated_when_banned` | `false`: a banned IP gets 429 before any handler. `true`: shared-IP mode, see [Shared IPs](threat-model.md#shared-ips-serve_authenticated_when_banned) |
| `count_unknown_path` | `None`: requests that match no route never count as failures. `Some(f)`: those with `f(&method, path)` true count, except `harmless_probe`s |

Override with struct update syntax, e.g.
`Limits { max_body_bytes: 256 * 1024, ..Limits::default() }`.

## Environment conventions

The crate reads no environment variable itself. Servers that use it
configure it from a prefixed set of variables, or from a mode-600 TOML file
outside git with the same keys:

| Variable | Maps to |
|---|---|
| `<PREFIX>_OWNER_PASSWORD_HASH` | `owner_password_hash`; its presence turns OAuth on |
| `<PREFIX>_PUBLIC_URL` | `issuer` |
| `<PREFIX>_STATE_DIR` | `state_dir` |
| `<PREFIX>_REDIRECT_PATTERNS` | `redirect_patterns`, comma list; unset = `DEFAULT_REDIRECT_PATTERNS` |
| `<PREFIX>_CIMD_ALLOWLIST` | `cimd_allowlist`, comma list; unset = `None` |

A `hash-password` subcommand that reads the password from stdin (not argv,
so it stays out of shell history and the process list) and prints
`hash_password(..)` is the usual way to produce the hash.

## API at a glance

| Item | What it does |
|---|---|
| `OAuth::router()` | `/.well-known/oauth-protected-resource` (also `+ mcp_path`), `/.well-known/oauth-authorization-server`, `/oauth/authorize` (login + consent pages), `/oauth/token`, `/oauth/register`, `/oauth/revoke` |
| `OAuth::bearer_layer()` | tower layer for any route: a valid token puts a `Grant { client_id, scope }` in the request extensions, otherwise `401` with `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"` (`error="invalid_token"` when a token was sent) |
| `OAuth::validate(token)` | the same check by hand |
| `OAuth::resource()`, `resource_metadata_url()`, `dcr_enabled()` | the MCP URL, the metadata URL, whether DCR is open |
| `hash_password(pw)` | argon2id (m=19 MiB, t=2, p=1) PHC string |
| `protect(router, Guard)` | abuse protection around the whole app; keeps the app's fallback |
| `AuthFailures` | request extension set by `protect`; `record("what")` counts a failure for the client IP (use it for your own credentials, e.g. a URL path token or a device token); `ip()`; `banned()` (the IP was banned when the request was admitted, only seen in shared-IP mode). `AuthFailures::new(guard, ip)` builds one for your own middleware |
| `Guard::auth_failed(ip, what, now)`, `Guard::is_banned(ip, now)` | the same ban state from code holding a clone of the `Guard` |
| `authenticated(response)`, `Authenticated` | marks a response to a request whose credentials were verified (the extension `Authenticated`); in shared-IP mode only marked responses reach a banned IP |
| `harmless_probe(method, path)` | `GET`/`HEAD` on `/`, `/favicon.ico`, `/robots.txt`, and anything under `/.well-known/`: never counted as failures |
| `client_ip(headers)` | `CF-Connecting-IP`, else leftmost `X-Forwarded-For`, else `unknown` |
| `check_pattern(p)` | validates one redirect pattern |
| `ACCESS_TTL`, `REFRESH_TTL` | 3600 s, 30 days |

The login and consent pages say "Sign in to `resource_name`", "*client* asks
to connect", "Owner password"; nothing else is shown about the owner.
