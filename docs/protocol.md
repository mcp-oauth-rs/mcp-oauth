# Client compatibility and protocol details

[Back to the README](../README.md)

## Client compatibility notes

Learned on live connections and from the published metadata documents:

- **Discovery probes.** MCP clients (ChatGPT among them) probe URLs this
  server does not serve, such as `/.well-known/openid-configuration` and
  path-suffixed variants, before and after registering. They get 404, are
  rate-limited like everything else, and never count toward a ban, even with
  `count_unknown_path` (anything under `/.well-known/` is a `harmless_probe`):
  a chatty client behind a shared IP must not lock itself out.
- **ChatGPT** offers CIMD when the metadata says
  `client_id_metadata_document_supported: true`. Its document declares
  `token_endpoint_auth_method: private_key_jwt` and
  `token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]`
  (RS256, keys at `https://chatgpt.com/oauth/jwks.json`); it picks from the
  intersection with this server's `token_endpoint_auth_methods_supported`,
  preferring `private_key_jwt`. The plural field is read first for that
  reason. OpenAI's docs also describe a per-connection
  `https://chatgpt.com/oauth/{callback_id}/client.json` for servers without
  RFC 9207 issuer identification; that does not apply here.
- **Claude and Claude Code** documents declare
  `token_endpoint_auth_method: none` (public clients, PKCE only). Claude
  Code redirects to `http://localhost/callback` or
  `http://127.0.0.1/callback` on a random port, hence the `:*` patterns.
- **CIMD fetch failures** (timeout, 5xx) from a vendor's side cost the rate
  limit only, never a ban.

## Protocol details

- Client ID Metadata Documents
  (draft-ietf-oauth-client-id-metadata-document-02, MCP authorization
  2025-11-25), advertised with `client_id_metadata_document_supported: true`.
  A `client_id` that is an https URL (host name, path, no userinfo, fragment
  or dot segments) is fetched at `/oauth/authorize` and at the token
  endpoint: 5 s timeout, 64 KiB max, no redirects, no proxy, only public IP
  addresses (RFC 6890 special-purpose ranges are refused by the resolver, IP
  literals by the URL check), cached in memory 1 h (a copy up to 24 h old is
  used if a refetch hits a network error; errors and invalid documents are
  never cached). At most 8 fetches run at once (documents and `jwks_uri` key
  sets together; a request waits up to 5 s for a slot, then gets
  "unavailable"), concurrent requests for the same URL share one fetch and
  its result, and no idle connection is kept. With an allowlist, a
  `client_id` outside it is refused before anything is fetched, at
  `/oauth/authorize` and at the token endpoint. The document must contain
  `client_id` equal to the URL and `redirect_uris`; it must not contain a
  client secret. Its `redirect_uris` are filtered by the redirect patterns
  and the authorization request must use one of the rest (loopback port
  ignored). Token endpoint authentication: the plural
  `token_endpoint_auth_methods_supported` of the document if present
  (ChatGPT), else `token_endpoint_auth_method`, else `none`; accepted are
  `none` (PKCE only) and `private_key_jwt` (RFC 7523: `iss` = `sub` =
  client_id, `aud` the issuer or the token endpoint, `exp` within an hour, a
  `jti` (required, as in OpenID Connect Core section 9; without it an
  assertion could be replayed) that is single-use; RS256, PS256 or ES256
  against `jwks` or `jwks_uri`, refetched at most once a minute on an
  unknown `kid`). The consent page shows the document's name and the host of
  the `client_id`. CIMD clients are never written to disk.
- Dynamic Client Registration (RFC 7591): `none` (or omitted) gives a public
  client; `client_secret_post` / `client_secret_basic` a confidential one whose
  secret is returned once and stored as a SHA-256 digest (accepted in the form
  body or HTTP Basic at the token endpoint). `private_key_jwt` is not offered
  through DCR (only through CIMD).
- Authorization code + PKCE S256 for every client; `resource` (RFC 8707)
  checked when present, tokens bound to the MCP URL; `iss` in every
  authorization response (RFC 9207).
- Refresh tokens rotate on every use, 180 days (`OAuth::with_refresh_ttl`);
  access tokens are opaque 32 random bytes, 1 h. Replaying a used code or a
  rotated-out refresh token revokes the grant. Revocation (RFC 7009).
- Redirect patterns: scheme and host match exactly, `:*` any port, a trailing
  `*` any rest of the path (no `..` or encoded `.` `/` `\`); https only, http
  only on loopback. `DEFAULT_REDIRECT_PATTERNS`: Claude
  (`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/...`),
  Claude Code (`http://localhost:*/callback`, `http://127.0.0.1:*/callback`),
  ChatGPT (`https://chatgpt.com/connector_platform_oauth_redirect` and `/*`,
  `https://chatgpt.com/aip/*`, `https://chat.openai.com/...`).

