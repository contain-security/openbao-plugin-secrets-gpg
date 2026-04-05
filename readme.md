# openbao-plugin-secrets-gpg

A GPG secrets engine plugin for [OpenBao](https://openbao.org). Provides GPG key management and cryptographic operations (sign, verify, encrypt, decrypt) backed by OpenBao storage.

> **Provenance:** This project is a port of [vault-gpg-plugin](https://github.com/LeSuisse/vault-gpg-plugin) by [Thomas Gerbet](https://github.com/LeSuisse), originally licensed under the MIT License, adapted for OpenBao. See [CHANGES-FROM-UPSTREAM.md](CHANGES-FROM-UPSTREAM.md) for what has been modified.

## Features

*   **Key management** -- generate RSA keys or import existing GPG private keys, with optional export control
*   **Sign & verify** -- detached GPG signatures (base64 or ASCII-armored)
*   **Encrypt & decrypt** -- PGP encryption to stored keys, with optional sign+encrypt
*   **Streaming operations** -- session-based streaming for large data (sign, encrypt, decrypt)
*   **Export** -- export public keys (and private keys when explicitly allowed)
*   **GnuPG interop** -- output is standard GPG-compatible; verified against `gpg` CLI

## Changes from Upstream

Key differences from vault-gpg-plugin:

| Area | Upstream | This Plugin |
| --- | --- | --- |
| Platform | HashiCorp Vault | OpenBao |
| `/encrypt` endpoint | Not present | Added |
| Streaming endpoints | Not present | 9 new endpoints |
| `signer_key` param | Inline ASCII-armored key | `signer_key_name` (stored key reference) |

See [CHANGES-FROM-UPSTREAM.md](CHANGES-FROM-UPSTREAM.md) for the full list.

## Quick Start

### Build

```
go build -o /path/to/plugins/openbao-plugin-secrets-gpg .
```

### Register and Mount

```
SHA=$(sha256sum /path/to/plugins/openbao-plugin-secrets-gpg | awk '{print $1}')
bao plugin register -sha256=$SHA secret openbao-plugin-secrets-gpg
bao secrets enable -path=gpg -plugin-name=openbao-plugin-secrets-gpg plugin
```

### Create a Key and Sign

```
# Generate a key
bao write gpg/keys/my-key real_name="My App" email="app@example.com"

# Sign data
echo -n "hello world" | base64 | \
  bao write -field=signature gpg/sign/my-key input=-

# Read the public key
bao read -field=public_key gpg/export/my-key
```

See [docs/quickstart.md](docs/quickstart.md) for the full getting started guide.

## API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/gpg/keys/:name` | Create or import a key |
| `GET` | `/gpg/keys/:name` | Read key metadata |
| `DELETE` | `/gpg/keys/:name` | Delete a key |
| `LIST` | `/gpg/keys` | List all keys |
| `POST` | `/gpg/keys/:name/config` | Update key configuration |
| `GET` | `/gpg/export/:name` | Export public (or private) key |
| `POST` | `/gpg/sign/:name` | Create detached signature |
| `POST` | `/gpg/verify/:name` | Verify detached signature |
| `POST` | `/gpg/encrypt/:name` | Encrypt plaintext |
| `POST` | `/gpg/decrypt/:name` | Decrypt ciphertext |
| `POST` | `/gpg/show-session-key/:name` | Reveal session key |

**Streaming endpoints** follow the pattern `/{operation}-stream/:name/{start,update,finalize}` for sign, encrypt, and decrypt.

See [docs/api.md](docs/api.md) for the full API reference.

## Building & Testing

```
# Unit tests
go test ./... -race -count=1

# Cross-compile
bash scripts/build.sh v0.1.0
```

See [docs/dev/architecture.md](docs/dev/architecture.md) for architecture details.

## Documentation

*   [API Reference](docs/api.md)
*   [Quick Start Guide](docs/quickstart.md)
*   [Architecture](docs/dev/architecture.md)
*   [Design Decisions](docs/dev/design-decisions.md)
*   [Changes from Upstream](CHANGES-FROM-UPSTREAM.md)

## License

MIT License. See [LICENSE](LICENSE).

This project includes code originally written by Thomas Gerbet for [vault-gpg-plugin](https://github.com/LeSuisse/vault-gpg-plugin), Copyright (c) 2017-2019. See [NOTICE](NOTICE) and [CONTRIBUTORS.md](CONTRIBUTORS.md) for full attribution.