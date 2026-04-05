# Test Suite

This document covers the test infrastructure for openbao-plugin-secrets-gpg: unit tests, shell-based integration tests, and GnuPG cross-checks.

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
# Start the dev server (builds plugin, registers, mounts)
bash test-bed/start-dev.sh

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

## GnuPG Cross-Check Suite (`test-bed/run-cross-checks.sh`)

Validates interoperability between the plugin and the GnuPG CLI. Tests that data signed/encrypted by one can be verified/decrypted by the other.

### Prerequisites

Same as the integration tests, plus:

- Test PGP key files in `test-bed/test-pgp-keys/`:
  - `alice-private.asc`, `alice-public.asc`
  - `bob-private.asc`, `bob-public.asc`

### Running

```bash
bash test-bed/run-cross-checks.sh
```

### GPG Keyring Setup

The cross-check script creates an **isolated temporary GNUPGHOME** for each run. It imports Alice and Bob test keys into this temp keyring, keeping the user's real GPG keyring untouched. The temp directory is cleaned up on exit.

### Tests

| Test | Description |
|------|-------------|
| 1. Key CRUD | Create, list, delete via plugin |
| 2. Plugin sign → gpg verify | Plugin creates signature, GnuPG verifies |
| 3. gpg sign → plugin verify | GnuPG signs with Alice's key, plugin verifies |
| 4. Plugin encrypt → gpg decrypt | Plugin encrypts, GnuPG decrypts |
| 5. gpg encrypt → plugin decrypt | GnuPG encrypts to plugin key, plugin decrypts |
| 6. Sign+encrypt round-trip | Plugin encrypt+sign, decrypt+verify, wrong-signer rejection |
| 7. Key import (gpg → plugin) | Import Bob's gpg key into plugin, sign, gpg verify |
| 8. Key export (plugin → gpg) | Export plugin key, sign in gpg, plugin verify |

## Test-Bed Structure

```
test-bed/
├── common.env              # Shared env: paths, build/register/start/stop helpers
├── start-dev.sh            # One-command: build → start server → register → mount
├── stop.sh                 # Stop the dev server
├── run-cross-checks.sh     # GnuPG interop test suite
├── openbao-instance/
│   ├── config.hcl          # Server config (file storage, for non-dev mode)
│   └── plugins/            # Plugin binary placed here by build
└── test-pgp-keys/
    ├── alice-private.asc   # Alice test key (RSA 2048)
    ├── alice-public.asc
    ├── bob-private.asc     # Bob test key (RSA 2048)
    └── bob-public.asc
```

### Quick Start

```bash
# Full cycle: build, start, test, stop
bash test-bed/start-dev.sh
bash tests/run-all.sh
bash test-bed/run-cross-checks.sh
bash test-bed/stop.sh
```
