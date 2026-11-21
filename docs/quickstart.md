# Features and quickstart

[Back to the README](../README.md)

## Features

| Feature | Standard |
|---|---|
| Protected Resource Metadata, `401` with `WWW-Authenticate: Bearer resource_metadata=...` | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) |
| Authorization Server Metadata | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) |
| Authorization code + PKCE S256 for every client | [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) |
| Resource indicators: tokens bound to the MCP URL | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) |
| `iss` in every authorization response | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) |
| Client ID Metadata Documents (public clients, or `private_key_jwt` with RS256 / PS256 / ES256) | [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), [MCP authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) |
| `private_key_jwt` client assertions, single-use `jti` | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), [OpenID Connect Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| Dynamic Client Registration (public, or `client_secret_post` / `client_secret_basic`) | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) |
| Refresh token rotation with reuse detection | [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) |
| Token revocation | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) |
| Loopback redirects matched port-agnostically | [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3) |
| Sign-in: e-mail allowlist, single-use enrolment codes (24 h, typed, never a link), the user's address in every grant, long refresh tokens revoked per user at once, admin API for a command-line tool | (this crate) |

## Quickstart

1. Mount the authorization server next to your MCP route and wrap the app
   in the guard. This is the crate's doc test (`cargo test --doc` compiles
   it):

   ```rust
   use axum::{Extension, Router, routing::any};
   use mcp_oauth_server::{Config, Grant, Guard, Limits, OAuth, protect};

   fn app() -> Result<Router, String> {
   let oauth = OAuth::new(Config {
       issuer: "https://mcp.example.net".into(),
       mcp_path: "/mcp".into(),
       state_dir: "/state".into(),
       redirect_patterns: mcp_oauth_server::DEFAULT_REDIRECT_PATTERNS.iter().map(|s| s.to_string()).collect(),
       resource_name: "my-server".into(),
       ..Default::default()
   })?;
   let mcp = any(|Extension(g): Extension<Grant>| async move {
       format!("hello {}", g.subject.unwrap_or_default())
   });
   let app = Router::new()
       .route("/mcp", mcp.layer(oauth.bearer_layer()))
       .merge(oauth.router());
   Ok(protect(app, Guard::new(Limits::default())))
   }
   ```

   A handler behind `bearer_layer()` reads who called it from
   `Extension<Grant>`: `client_id`, `scope` and `subject`, the user's
   address. `Grant` is `#[non_exhaustive]`: read its fields, do not build or
   destructure it exhaustively.

2. Give your binary an admin command that allows an address and prints an
   enrolment code (see [Users and sign-in](sign-in.md#admin-api)):

   ```rust
   let users = mcp_oauth_server::Users::open("/state")?;
   users.allow("ada@example.org")?;
   println!("{}", users.enrol_code("ada@example.org")?);
   ```

3. Serve it over HTTPS at the issuer origin, then add
   `https://mcp.example.net/mcp` as a custom connector in claude.ai or
   ChatGPT, or `claude mcp add --transport http my-server
   https://mcp.example.net/mcp` in Claude Code. No client ID or secret to
   type: the client discovers the metadata, identifies itself (CIMD or DCR)
   and sends the user to the sign-in page ("Sign in to `resource_name`",
   e-mail address and enrolment code, then "Allow").

4. In production, set the [CIMD allowlist](cimd-allowlist.md).
