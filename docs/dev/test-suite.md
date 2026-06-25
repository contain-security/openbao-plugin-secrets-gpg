# Test Suite

This document covers the test infrastructure for openbao-plugin-secrets-gpg: unit tests, shell-based integration tests, and GnuPG interop coverage.

## Unit Tests

Standard Go tests in the `gpg/` package. No external dependencies.

```bash
go test ./... -race -count=1
```

## Integration Test Suite (`tests/`)

Shell-based regression tests that exercise the plugin's HTTP API against a live OpenBao instance.

### Prerequisites

- OpenBao dev server running with the plugin registered and mounted at `gpg/`
- `bao` CLI available (via `BAO_BIN` env or `PATH`)
- Tools: `jq`, `gpg`, `curl`, `base64`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BAO_ADDR` | `http://127.0.0.1:8200` | OpenBao server address |
| `BAO_TOKEN` | `root` | Authentication token |
| `BAO_BIN` | (auto-detect from PATH) | Path to `bao` binary |

### Running

```bash
# Build, register, and mount the plugin in a running OpenBao server.
go build -o /path/to/plugins/openbao-plugin-secrets-gpg .
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root
bash scripts/register.sh /path/to/plugins/openbao-plugin-secrets-gpg

# Run all tests
bash tests/run-all.sh

# Run specific tests by number
bash tests/run-all.sh 01 03

# List available tests
bash tests/run-all.sh --list
```

### Test Files

| File | Description |
|------|-------------|
| `common.sh` | Shared framework: assertions, prerequisite checks, key helpers |
| `01-key-crud.sh` | Create, read, list, config, export, delete keys |
| `02-sign-verify.sh` | Sign/verify with multiple formats and hash algorithms, GnuPG interop |
| `03-encrypt-decrypt.sh` | Encrypt/decrypt with sign+encrypt, GnuPG interop both directions |
| `04-sign-stream.sh` | Streaming sign sessions, chunked files, format/algorithm variants |
| `05-encrypt-stream.sh` | Streaming encrypt with chunking, signer verification, GnuPG interop |
| `06-decrypt-stream.sh` | Streaming decrypt, full round-trips, signer verification, edge cases |

### Prerequisite Checks

All tests call `check_prerequisites` on startup, which verifies:

1. Required tools are installed (`jq`, `gpg`, `curl`, `base64`)
2. OpenBao server is reachable at `BAO_ADDR`
3. GPG plugin is mounted at `gpg/`

If any check fails, the test bails immediately with a clear error message.

## GnuPG Interop Coverage

GnuPG interoperability checks now live in the shell integration tests under
`tests/`. The sign, encrypt, and decrypt scripts exercise plugin-to-GnuPG and
GnuPG-to-plugin flows while creating temporary GNUPGHOME directories as needed,
so no checked-in test keyring is required.

### Quick Start

```bash
# Full cycle after an OpenBao server is running.
go build -o /path/to/plugins/openbao-plugin-secrets-gpg .
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root
bash scripts/register.sh /path/to/plugins/openbao-plugin-secrets-gpg
bash tests/run-all.sh
```
