# Test-bed

Live test environment for the `openbao-plugin-secrets-gpg` plugin. Provides scripts to start an OpenBao instance in either dev or production-like mode, and a cross-check test suite that validates GnuPG interop.

## Prerequisites

- OpenBao `bao` binary built at `../openbao/bin/bao` (or set `BAO_BIN`)
- Go toolchain (1.25.0+) for plugin compilation
- GnuPG (`gpg`) and `jq` installed

## Scripts

| Script | Purpose |
|--------|---------|
| `common.env` | Shared paths and helpers (build, register, wait, stop) — sourced by other scripts |
| `start-dev.sh` | Build plugin, start dev server (in-memory, token=`root`), register and mount |
| `start-prod.sh` | Build plugin, start with file storage, init/unseal, register and mount |
| `stop.sh` | Stop the running instance (either mode) |
| `run-cross-checks.sh` | 11 GnuPG interop tests — auto-detects token from `init.json` or falls back to `root` |

## Usage

### Dev mode

```bash
bash test-bed/start-dev.sh
bash test-bed/run-cross-checks.sh
bash test-bed/stop.sh
```

### Non-dev (production-like) mode

```bash
bash test-bed/start-prod.sh --fresh
bash test-bed/run-cross-checks.sh
bash test-bed/stop.sh
```

## Options

### `start-dev.sh`

| Flag | Effect |
|------|--------|
| `--no-build` | Skip plugin recompilation, use existing binary |

### `start-prod.sh`

| Flag | Effect |
|------|--------|
| `--no-build` | Skip plugin recompilation, use existing binary |
| `--fresh` | Wipe file storage and init state before starting (clean slate) |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BAO_BIN` | `../openbao/bin/bao` | Path to the `bao` binary |
| `BAO_ADDR` | `http://127.0.0.1:8200` | OpenBao server address |
| `BAO_TOKEN` | auto-detected | Root token; reads from `init.json` in prod mode, defaults to `root` in dev mode |

## Cross-check tests

The `run-cross-checks.sh` suite validates 11 scenarios:

1. Key CRUD (create, read, list, delete)
2. Sign via plugin, verify with gpg
3. Sign with gpg, verify via plugin
4. Encrypt via plugin, decrypt with gpg
5. Encrypt with gpg, decrypt via plugin
6. Encrypt+sign round-trip with signer verification
7. Wrong signer rejection
8. Key import from gpg into plugin
9. Key export from plugin, sign in gpg, verify via plugin

## Directory layout

```
test-bed/
├── common.env              # Shared environment and helper functions
├── start-dev.sh            # Start in dev mode
├── start-prod.sh           # Start in non-dev mode
├── stop.sh                 # Stop server
├── run-cross-checks.sh     # Test suite
├── readme.md               # This file
├── openbao-instance/
│   ├── config.hcl          # Server config (used by non-dev mode)
│   ├── plugins/            # Plugin binary (gitignored)
│   ├── data/               # File storage (gitignored)
│   ├── logs/               # Server logs (gitignored)
│   ├── server.pid          # PID file (gitignored)
│   └── init.json           # Init credentials (gitignored)
└── test-pgp-keys/
    ├── alice-private.asc   # Alice RSA-2048 test key
    ├── alice-public.asc
    ├── bob-private.asc     # Bob RSA-2048 test key
    └── bob-public.asc
```
