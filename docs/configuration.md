# Configuration

[Back to the README](../README.md)

## `Config`

| Field | Meaning |
|---|---|
| `issuer` | Public origin, e.g. `https://mcp.example.net`: https, no path, query or fragment (http only on `localhost` / `127.0.0.1`); one trailing slash is dropped. It is the issuer; the protected resource is `issuer + mcp_path` |
| `mcp_path` | Path of the bearer-protected MCP route, e.g. `/mcp`; must start with `/` |
| `state_dir` | Directory for `oauth-clients.json`, `oauth-tokens.json` and `oauth-users.json` (the allowlist); created mode 700 if missing; must persist |
| `redirect_patterns` | Redirect URIs a client may use, by DCR or in its metadata document; non-empty; `DEFAULT_REDIRECT_PATTERNS` covers Claude, Claude Code and ChatGPT (see [Protocol details](protocol.md#protocol-details)) |
| `resource_name` | Display name on the login and consent pages and `resource_name` of the resource metadata |
| `cimd_allowlist` | `None`: DCR open, any https `client_id` URL accepted as a metadata document. `Some(urls)`: only those `client_id` URLs (exact match), DCR off. See [CIMD allowlist](cimd-allowlist.md) |

`OAuth::new(Config) -> Result<OAuth, String>` validates all of it, creates
`state_dir` and loads the persisted clients, tokens and users. `Config`
implements `Default`, so a literal may end with `..Default::default()` to
leave `cimd_allowlist` (and fields added later) at their defaults.

## Builders

| Builder | Default | Meaning |
|---|---|---|
| `OAuth::with_dcr_grace(bool)` | `true` | Only with an allowlist: whether tokens already held by clients outside it keep working (see [CIMD allowlist](cimd-allowlist.md)) |
| `OAuth::with_refresh_ttl(secs)` | `REFRESH_TTL` (180 days) | Refresh token lifetime of the grants issued from then on, renewed at each refresh (minimum `ACCESS_TTL`) |

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
| `<PREFIX>_OWNER_EMAIL` | an address allowed at start (and given the 0.1 grants, see [Migration](migration.md)); its presence turns OAuth on |
| `<PREFIX>_PUBLIC_URL` | `issuer` |
| `<PREFIX>_STATE_DIR` | `state_dir` |
| `<PREFIX>_REDIRECT_PATTERNS` | `redirect_patterns`, comma list; unset = `DEFAULT_REDIRECT_PATTERNS` |
| `<PREFIX>_CIMD_ALLOWLIST` | `cimd_allowlist`, comma list; unset = `None` |

An `enrol <address>` subcommand that calls `Users::allow` and prints
`Users::enrol_code` (and `revoke <address>`, `users` for `Users::list`) is
the usual admin tool; it runs as the server's user on the same `state_dir`.

## API at a glance

| Item | What it does |
|---|---|
| `OAuth::router()` | `/.well-known/oauth-protected-resource` (also `+ mcp_path`), `/.well-known/oauth-authorization-server`, `/oauth/authorize` (login + consent pages), `/oauth/token`, `/oauth/register`, `/oauth/revoke` |
| `OAuth::bearer_layer()` | tower layer for any route: a valid token puts a `Grant { client_id, scope, subject }` (`#[non_exhaustive]`; `subject`: the user's address) in the request extensions, otherwise `401` with `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"` (`error="invalid_token"` when a token was sent) |
| `OAuth::validate(token)` | the same check by hand |
| `OAuth::resource()`, `resource_metadata_url()`, `dcr_enabled()` | the MCP URL, the metadata URL, whether DCR is open |
| `protect(router, Guard)` | abuse protection around the whole app; keeps the app's fallback |
| `AuthFailures` | request extension set by `protect`; `record("what")` counts a failure for the client IP (use it for your own credentials, e.g. a URL path token or a device token); `ip()`; `banned()` (the IP was banned when the request was admitted, only seen in shared-IP mode). `AuthFailures::new(guard, ip)` builds one for your own middleware |
| `Guard::auth_failed(ip, what, now)`, `Guard::is_banned(ip, now)` | the same ban state from code holding a clone of the `Guard` |
| `authenticated(response)`, `Authenticated` | marks a response to a request whose credentials were verified (the extension `Authenticated`); in shared-IP mode only marked responses reach a banned IP |
| `harmless_probe(method, path)` | `GET`/`HEAD` on `/`, `/favicon.ico`, `/robots.txt`, and anything under `/.well-known/`: never counted as failures |
| `client_ip(headers)` | `CF-Connecting-IP`, else leftmost `X-Forwarded-For`, else `unknown` |
| `check_pattern(p)` | validates one redirect pattern |
| `ACCESS_TTL`, `REFRESH_TTL` | 3600 s, 180 days |
| `OAuth::users()`, `OAuth::adopt_unowned_grants(email)` | the server's `Users` store; the [0.1 migration](migration.md) |
| `Users::open(state_dir)`: `allow`, `enrol_code`, `revoke`, `list` | the [admin API](sign-in.md#admin-api) for a command-line tool |
| `ENROL_CODE_TTL`, `normalize_email` | 24 h, how addresses are compared |

The sign-in page says "Sign in to `resource_name`", "*client* asks to
connect" and asks for the e-mail address and the enrolment code; the consent
page says who signed in.

