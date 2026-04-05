# Changes from Upstream (vault-gpg-plugin)

This project is a port of [vault-gpg-plugin](https://github.com/LeSuisse/vault-gpg-plugin) by Thomas Gerbet. This document summarizes all changes made during the port to [OpenBao](https://openbao.org).

## SDK Migration

- **Vault SDK** replaced with **OpenBao SDK v2** (`github.com/openbao/openbao/sdk/v2`)
- Plugin entrypoint changed from `plugin.Serve` to `plugin.ServeMultiplex` (matching OpenBao builtin plugin conventions, allows a single process to handle multiple mount points)

## Crypto Library

- Migrated from `golang.org/x/crypto/openpgp` (deprecated) to `github.com/ProtonMail/go-crypto/openpgp`
- The upstream project had already begun this migration; this port completes it

## New Endpoint: `/gpg/encrypt/:name`

The upstream plugin had no encrypt endpoint. This port adds:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/gpg/encrypt/:name` | Encrypt plaintext to a named key |

Parameters: `plaintext` (base64), `format` (`base64` or `ascii-armor`), `signer_key_name` (optional, for sign+encrypt).

## API Change: `signer_key` to `signer_key_name`

Both `/decrypt` and `/show-session-key` endpoints now use `signer_key_name` instead of the upstream's `signer_key` parameter.

| Upstream (`signer_key`) | This port (`signer_key_name`) |
|--------------------------|-------------------------------|
| Inline ASCII-armored public key in request body | Reference to a key stored in OpenBao by name |

**Rationale**: Keeps key material inside OpenBao rather than requiring clients to transmit public keys in API calls. Makes the API consistent across all endpoints.

**Limitation**: The signer's full key (including private key) must be stored in OpenBao. Public-key-only import is not currently supported.

## Streaming Endpoints (New)

Nine new endpoints for session-based streaming operations on large data:

| Operation | Start | Update | Finalize |
|-----------|-------|--------|----------|
| Sign | `POST /gpg/sign-stream/:name/start` | `POST /gpg/sign-stream/:name/update` | `POST /gpg/sign-stream/:name/finalize` |
| Encrypt | `POST /gpg/encrypt-stream/:name/start` | `POST /gpg/encrypt-stream/:name/update` | `POST /gpg/encrypt-stream/:name/finalize` |
| Decrypt | `POST /gpg/decrypt-stream/:name/start` | `POST /gpg/decrypt-stream/:name/update` | `POST /gpg/decrypt-stream/:name/finalize` |

Features:
- 128-bit session IDs with client token binding
- 64 max concurrent sessions, 5-minute idle timeout
- Binary PGP output (base64-encoded per chunk for JSON transport)

See [docs/dev/design-decisions.md](docs/dev/design-decisions.md) for detailed rationale on the streaming architecture.

## Summary Table

| Area | Upstream | This Port |
|------|----------|-----------|
| SDK | HashiCorp Vault SDK | OpenBao SDK v2 |
| Entrypoint | `plugin.Serve` | `plugin.ServeMultiplex` |
| `signer_key` param | Inline ASCII-armored public key | `signer_key_name` (stored key reference) |
| `/encrypt` endpoint | Not present | Added |
| Streaming endpoints | Not present | 9 new endpoints |
| Session management | Not present | Full session store with cleanup |
| Crypto library | `golang.org/x/crypto/openpgp` | `ProtonMail/go-crypto/openpgp` |
