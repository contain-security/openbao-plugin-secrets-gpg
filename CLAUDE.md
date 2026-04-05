# openbao-plugin-secrets-gpg

## Project Overview

A GPG secrets engine plugin for [OpenBao](https://openbao.org), ported from [vault-gpg-plugin](https://github.com/LeSuisse/vault-gpg-plugin) by Thomas Gerbet (MIT license). Provides GPG key management and cryptographic operations (sign, verify, encrypt, decrypt) backed by OpenBao storage.

**Status:** Phases 1-4 complete. Unit tests pass (20 tests). Integration cross-checks pass (11/11) against a live OpenBao instance with GnuPG interop.

## Repository Layout

```
.
├── main.go                       # Entrypoint (plugin.ServeMultiplex)
├── go.mod                        # Module: openbao-plugin-secrets-gpg (local, no remote prefix)
├── gpg/                          # Backend + all path handlers + tests
│   ├── backend.go                # Factory, path registration, keyLocks
│   ├── path_keys.go              # CRUD: POST/GET/DELETE/LIST /gpg/keys/:name
│   ├── path_sign_verify.go       # POST /gpg/sign/:name, POST /gpg/verify/:name
│   ├── path_decrypt.go           # POST /gpg/decrypt/:name
│   ├── path_encrypt.go           # POST /gpg/encrypt/:name  (NEW - not in upstream)
│   ├── path_show_session_key.go  # POST /gpg/show-session-key/:name
│   ├── path_export.go            # GET /gpg/export/:name
│   ├── path_config.go            # POST /gpg/keys/:name/config
│   ├── public_key.go             # Helper: extractPublicKey
│   ├── *_test.go                 # Unit tests for each path
│   └── path_encrypt_test.go      # Tests for new encrypt endpoint
├── scripts/
│   ├── build.sh                  # Cross-compile linux/darwin amd64/arm64
│   └── register.sh               # Register + mount plugin in OpenBao
├── dist/                         # Build output (gitignored)
├── LICENSE                       # MIT (upstream attribution included)
├── test-bed/                     # Live test environment
│   ├── openbao-instance/         # Dev server config, plugins dir, data, logs
│   │   ├── config.hcl
│   │   └── plugins/              # Plugin binary goes here
│   ├── test-pgp-keys/            # Isolated GNUPGHOME with Alice + Bob keys
│   │   ├── alice-{private,public}.asc
│   │   └── bob-{private,public}.asc
│   └── run-cross-checks.sh       # 11-check GnuPG interop test suite
├── tests/                        # Shell-based integration tests
│   ├── 01-key-crud.sh
│   ├── 02-sign-verify.sh
│   ├── 03-encrypt-decrypt.sh
│   ├── 04-sign-stream.sh
│   ├── 05-encrypt-stream.sh
│   ├── 06-decrypt-stream.sh
│   ├── common.sh
│   └── run-all.sh
├── docs/                         # Project documentation
│   ├── api.md                    # HTTP API reference
│   ├── quickstart.md             # Getting started guide
│   ├── project-plan.md           # Original project plan
│   └── dev/                      # Developer documentation
│       ├── architecture.md
│       └── design-decisions.md
└── readme.md
```

## Key Technical Decisions

- **Module path:** `openbao-plugin-secrets-gpg` (no remote prefix; not on GitHub yet)
- **Go version:** 1.25.0 (required by OpenBao SDK v2)
- **SDK:** `github.com/openbao/openbao/sdk/v2` via local `replace` directives in go.mod
- **Crypto library:** `github.com/ProtonMail/go-crypto/openpgp` (upstream already migrated from `golang.org/x/crypto/openpgp`)
- **BackendType:** `logical.TypeLogical` (not `TypeLogicalWithInjectedToken` which doesn't exist)
- **Entrypoint:** `plugin.ServeMultiplex` (matching upstream and all OpenBao builtin plugins)

## API Changes from Upstream

### New endpoint: `/gpg/encrypt/:name`
Encrypts plaintext to a named key. Parameters: `plaintext` (base64), `format` (base64|ascii-armor), `signer_key_name` (optional, for sign+encrypt).

### Changed: `signer_key` -> `signer_key_name`
Both `/decrypt` and `/show-session-key` now use `signer_key_name` (a reference to a key stored in OpenBao) instead of `signer_key` (inline ASCII-armored public key). This makes the API consistent with `/encrypt` and keeps key material inside OpenBao.

**Implication:** To verify a signer, their key (with private key) must be stored in OpenBao. External public-only keys cannot currently be imported since key storage requires a private key.

## Building

```bash
go build -o /path/to/plugins/openbao-plugin-secrets-gpg .

# Cross-platform:
bash scripts/build.sh v0.1.0    # outputs to dist/
```

## Running Tests

```bash
# Unit tests (no external dependencies)
go test ./... -race -count=1

# Integration cross-checks (requires running OpenBao + gpg)
# 1. Start dev server:
bash test-bed/start-dev.sh

# 2. Register plugin:
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root
bash scripts/register.sh

# 3. Run cross-checks:
bash test-bed/run-cross-checks.sh

# 4. Run shell integration tests:
bash tests/run-all.sh
```

## Remaining Work

- **Phase 5:** Integration test suite as Go tests (`go test -tags=integration`)
- **Phase 6:** CI/CD workflow YAML files (GitHub Actions, goreleaser)
- **Future:** Ed25519 key type support, public-key-only import for signer verification

## Gotchas

- OpenBao requires Go 1.25.8 to build (`bao` binary). The plugin itself compiles with Go 1.25.0+.
- Keys generated by `gpg --quick-gen-key` with `default` usage lack encryption subkeys. The plugin's own `openpgp.NewEntity` creates proper encryption subkeys. If importing a gpg key for encryption, ensure it has an encryption-capable subkey.