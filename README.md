# mcp-oauth-server

[![CI](https://github.com/mcp-oauth-rs/mcp-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-oauth-rs/mcp-oauth/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mcp-oauth-server.svg)](https://crates.io/crates/mcp-oauth-server)
[![docs.rs](https://img.shields.io/docsrs/mcp-oauth-server)](https://docs.rs/mcp-oauth-server)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

OAuth 2.1 for a **single-owner MCP server** written with axum: the server is
its own authorization server and its own protected resource, one owner
password guards the consent screen, and an abuse guard sits in front of the
whole app. Nothing here knows about the tools your server offers. Verified
live with the claude.ai and ChatGPT custom connectors (Client ID Metadata
Documents, ChatGPT through `private_key_jwt`); the Claude Code flow is
covered end to end by the local HTTPS tests against its published metadata
document. Rust 1.99, edition 2024, axum 0.8, tokio. MIT.

```toml
[dependencies]
mcp-oauth-server = "0.1"
# or the development version:
# mcp-oauth-server = { git = "https://github.com/mcp-oauth-rs/mcp-oauth" }
```

The library is `mcp_oauth_server`.

## Documentation

| Part | Sections |
|---|---|
| [Features and quickstart](docs/quickstart.md) | [Features](docs/quickstart.md#features), [Quickstart](docs/quickstart.md#quickstart) |
| [Configuration](docs/configuration.md) | [`Config`](docs/configuration.md#config), [Builders](docs/configuration.md#builders), [`Limits`](docs/configuration.md#limits-for-guardnew), [Environment conventions](docs/configuration.md#environment-conventions), [API at a glance](docs/configuration.md#api-at-a-glance) |
| [CIMD allowlist (recommended)](docs/cimd-allowlist.md) | recommended `client_id` URLs, `with_dcr_grace` |
| [Threat model](docs/threat-model.md) | threats and what stops them, [Shared IPs](docs/threat-model.md#shared-ips-serve_authenticated_when_banned) |
| [Client compatibility and protocol details](docs/protocol.md) | [Client compatibility notes](docs/protocol.md#client-compatibility-notes), [Protocol details](docs/protocol.md#protocol-details) |
| [Abuse protection (`protect`)](docs/abuse-protection.md) | rate limit, ban, what counts, password check bound, memory |
| [State at rest and tests](docs/state-and-tests.md) | [State at rest](docs/state-and-tests.md#state-at-rest), [Tests](docs/state-and-tests.md#tests) |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
