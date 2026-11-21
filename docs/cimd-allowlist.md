# CIMD allowlist (recommended)

[Back to the README](../README.md)

`cimd_allowlist: None` (default): Dynamic Client Registration stays open and
any https `client_id` URL is accepted as a metadata document.

`cimd_allowlist: Some(urls)`: only those `client_id` URLs (exact string match)
are accepted through CIMD, Dynamic Client Registration is off
(`/oauth/register` answers 403 and `registration_endpoint` disappears from the
metadata, as do the shared-secret auth methods). Every new authorization
needs an allowlisted `client_id`: a client registered by DCR earlier gets an
error page at `/oauth/authorize` ("Remove the connector and add it again") and
`invalid_client` for an authorization code.

Recommended allowlist, the published client_id URLs (checked 2026-10-18; each
document names itself and validates against the default redirect patterns):

| Client | client_id URL | Source |
|---|---|---|
| ChatGPT | `https://chatgpt.com/oauth/client.json` | OpenAI, [Authentication](https://developers.openai.com/plugins/build/auth) ("For authorization servers that meet the issuer identification requirements above, ChatGPT uses the stable `https://chatgpt.com/oauth/client.json`"; this server meets them) |
| Claude Code | `https://claude.ai/oauth/claude-code-client-metadata` | Anthropic, [Authentication for connectors](https://claude.com/docs/connectors/building/authentication) (linked as Claude Code's Client ID Metadata Document) |
| Claude (claude.ai, Desktop, mobile, Cowork) | `https://claude.ai/oauth/mcp-oauth-client-metadata` | Not named in Anthropic's docs. The document is served by claude.ai, names itself (`client_name` "Claude", redirect `https://claude.ai/api/mcp/auth_callback`), and is the URL reported in anthropics/claude-ai-mcp issues [#1148](https://github.com/anthropics/claude-ai-mcp/issues/1148), [#623](https://github.com/anthropics/claude-ai-mcp/issues/623), [#566](https://github.com/anthropics/claude-ai-mcp/issues/566). Confirm it in your server log on the first CIMD connection before relying on it. |

```rust
cimd_allowlist: Some(vec![
    "https://claude.ai/oauth/mcp-oauth-client-metadata".into(),   // Claude
    "https://claude.ai/oauth/claude-code-client-metadata".into(), // Claude Code
    "https://chatgpt.com/oauth/client.json".into(),               // ChatGPT
]),
```

`OAuth::with_dcr_grace(grace)` (only with an allowlist) decides what happens
to the tokens such clients (DCR, or a CIMD URL outside the list) already
hold:

- `true` (the default): their access tokens keep validating and a DCR
  client keeps rotating its refresh token (still authenticating with its
  secret if it has one), so existing connections do not break. The grace ends
  when a refresh token expires (`REFRESH_TTL`, 180 days without use) or is
  revoked; the client then has to connect again, through CIMD. A CIMD client
  outside the list cannot refresh (its document is refused), so its access
  token simply runs out (`ACCESS_TTL`).
- `false`: cut off at once. Their access tokens get `401 invalid_token` (not
  counted as an authentication failure) and refresh gets `invalid_client`.
  Nothing is deleted: setting it back to `true` restores them.

At start the server logs `oauth: dynamic client registration closed (N
allowlisted client_id URLs); M token families of other clients kept ...`, and
`with_dcr_grace(false)` logs how many families it cuts off.

