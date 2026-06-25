# Porting `vault-gpg-plugin` to OpenBao
## Detailed Implementation & Test Plan

**Source:** `github.com/LeSuisse/vault-gpg-plugin`  
**Target:** `openbao-plugin-secrets-gpg` — OpenBao secrets engine plugin  
**Go version:** 1.22+  
**Target OpenBao SDK:** `github.com/openbao/openbao/sdk/v2`  
**PGP Library:** `github.com/ProtonMail/go-crypto/openpgp`

---

## Overview of Changes Required

The port touches four distinct layers:

1. **SDK swap** — replace all `github.com/hashicorp/vault/sdk` imports with `github.com/openbao/openbao/sdk/v2`
2. **Entrypoint rewrite** — replace `vault/sdk/plugin.Serve` with `openbao/sdk/v2/plugin.ServeMultiplex`
3. **Crypto library upgrade** — replace the deprecated `golang.org/x/crypto/openpgp` with `github.com/ProtonMail/go-crypto/openpgp`
4. **Encrypt support** — the original plugin explicitly does not support encryption; this plan includes implementing it to make the plugin symmetric with decrypt

The upstream plugin's HTTP API surface, storage schema, and PGP logic are otherwise retained as-is — this is a port, not a redesign.

---

## Repository Structure (Target)

```
openbao-plugin-secrets-gpg/
├── main.go                          # Plugin entrypoint
├── go.mod                           # Module: github.com/your-org/openbao-plugin-secrets-gpg
├── go.sum
├── gpg/
│   ├── backend.go                   # Backend factory, path registration
│   ├── path_keys.go                 # POST/GET/DELETE /gpg/keys/:name
│   ├── path_sign.go                 # POST /gpg/sign/:name
│   ├── path_verify.go               # POST /gpg/verify/:name
│   ├── path_decrypt.go              # POST /gpg/decrypt/:name
│   ├── path_show_session_key.go     # POST /gpg/show-session-key/:name
│   ├── path_encrypt.go              # NEW: POST /gpg/encrypt/:name
│   ├── key.go                       # PGP key storage model, serialization
│   └── backend_test.go              # Integration tests using OpenBao test framework
├── scripts/
│   ├── build.sh                     # Cross-compile for linux/amd64, linux/arm64
│   └── register.sh                  # Dev helper: register + mount plugin in a dev OpenBao
├── docs/
│   ├── http-api.md                  # Updated API reference
│   └── development.md               # How to build, test, register
├── .github/
│   └── workflows/
│       ├── ci.yml                   # go test + go vet + staticcheck on PR
│       └── release.yml              # goreleaser on tag push
└── README.md
```

---

## Phase 1 — Repository Bootstrap & Module Setup

### Goal
Create the new repository, establish module identity, and get the project compiling with stub implementations before any logic is ported.

### Steps

**1.1 — Create the repository and module**

```bash
mkdir openbao-plugin-secrets-gpg && cd openbao-plugin-secrets-gpg
git init
go mod init github.com/your-org/openbao-plugin-secrets-gpg
```

**1.2 — Add dependencies**

```bash
go get github.com/openbao/openbao/api/v2
go get github.com/openbao/openbao/sdk/v2
go get github.com/ProtonMail/go-crypto@latest
go get github.com/hashicorp/go-hclog
go get github.com/stretchr/testify
go mod tidy
```

Key dependency versions to pin in `go.mod`:
- `github.com/openbao/openbao/sdk/v2 v0.6.0` (minimum for `ServeMultiplex`)
- `github.com/ProtonMail/go-crypto v1.x` (replaces deprecated `golang.org/x/crypto/openpgp`)

**1.3 — Write the minimal entrypoint `main.go`**

```go
package main

import (
    "os"

    "github.com/hashicorp/go-hclog"
    "github.com/openbao/openbao/api/v2"
    "github.com/openbao/openbao/sdk/v2/plugin"
    gpg "github.com/your-org/openbao-plugin-secrets-gpg/gpg"
)

func main() {
    apiClientMeta := &api.PluginAPIClientMeta{}
    flags := apiClientMeta.FlagSet()
    flags.Parse(os.Args[1:])

    tlsConfig := apiClientMeta.GetTLSConfig()
    tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

    if err := plugin.ServeMultiplex(&plugin.ServeOpts{
        BackendFactoryFunc: gpg.Factory,
        TLSProviderFunc:    tlsProviderFunc,
    }); err != nil {
        logger := hclog.New(&hclog.LoggerOptions{})
        logger.Error("plugin shutting down", "error", err)
        os.Exit(1)
    }
}
```

**1.4 — Write the minimal `gpg/backend.go` stub**

```go
package gpg

import (
    "context"

    "github.com/openbao/openbao/sdk/v2/framework"
    "github.com/openbao/openbao/sdk/v2/logical"
)

const backendHelp = `
The GPG secrets backend provides GPG key management and cryptographic
operations (sign, verify, decrypt, encrypt) backed by OpenBao's storage.
`

type backend struct {
    *framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
    b := &backend{}
    b.Backend = &framework.Backend{
        BackendType: logical.TypeLogicalWithInjectedToken,
        Help:        backendHelp,
        Paths:       framework.PathAppend(
            pathKeys(b),
            pathSign(b),
            pathVerify(b),
            pathDecrypt(b),
            pathShowSessionKey(b),
            pathEncrypt(b),
        ),
    }
    if err := b.Setup(ctx, conf); err != nil {
        return nil, err
    }
    return b, nil
}
```

**1.5 — Add stub files for each path** (empty `pathXxx` functions returning `[]*framework.Path{}`), then verify the project compiles:

```bash
go build ./...
```

### Phase 1 Test Plan

| Test ID | Type | Description | Pass Criteria |
|---------|------|-------------|---------------|
| P1-T1 | Build | `go build ./...` succeeds with no errors | Zero build errors |
| P1-T2 | Vet | `go vet ./...` reports no issues | Zero vet warnings |
| P1-T3 | Module | `go mod tidy` produces no diff | `go.mod`/`go.sum` stable |
| P1-T4 | Binary | `go build -o /tmp/openbao-plugin-secrets-gpg .` produces a runnable binary | `file` shows ELF/Mach-O; `--help` exits cleanly |
| P1-T5 | Plugin handshake | Register binary in a dev OpenBao instance; `bao secrets enable -path=gpg ./openbao-plugin-secrets-gpg` succeeds | No `plugin not found` or handshake error |

**P1-T5 setup:**
```bash
# Start dev OpenBao
bao server -dev -dev-root-token-id=root &
export BAO_ADDR=http://127.0.0.1:8200
export BAO_TOKEN=root

# Register plugin (dev mode uses SHA256 of binary)
SHASUM=$(sha256sum /tmp/openbao-plugin-secrets-gpg | awk '{print $1}')
bao plugin register -sha256=$SHASUM secret openbao-plugin-secrets-gpg

# Mount it
bao secrets enable -path=gpg -plugin-name=openbao-plugin-secrets-gpg plugin

# Verify mount appears
bao secrets list | grep gpg
```

---

## Phase 2 — SDK Import Migration

### Goal
Port every file from `vault/sdk` imports to `openbao/sdk/v2`. This is purely mechanical but must be done file-by-file with verification at each step.

### Import Substitution Map

| Old import | New import |
|------------|------------|
| `github.com/hashicorp/vault/sdk/framework` | `github.com/openbao/openbao/sdk/v2/framework` |
| `github.com/hashicorp/vault/sdk/logical` | `github.com/openbao/openbao/sdk/v2/logical` |
| `github.com/hashicorp/vault/sdk/plugin` | `github.com/openbao/openbao/sdk/v2/plugin` |
| `github.com/hashicorp/vault/api` | `github.com/openbao/openbao/api/v2` |
| `github.com/hashicorp/go-hclog` | unchanged (shared transitive dep) |

### Steps

**2.1** — Copy each source file from `vault-gpg-plugin/gpg/` into `gpg/`

**2.2** — Run a bulk import replacement (do NOT use sed blindly on go.sum; only source files):
```bash
find gpg/ main.go -name "*.go" -exec sed -i \
  's|github.com/hashicorp/vault/sdk/framework|github.com/openbao/openbao/sdk/v2/framework|g;
   s|github.com/hashicorp/vault/sdk/logical|github.com/openbao/openbao/sdk/v2/logical|g;
   s|github.com/hashicorp/vault/sdk/plugin|github.com/openbao/openbao/sdk/v2/plugin|g;
   s|github.com/hashicorp/vault/api|github.com/openbao/openbao/api/v2|g' {} \;
```

**2.3** — Remove the old Vault SDK dependency:
```bash
go mod edit -droprequire github.com/hashicorp/vault/sdk
go mod edit -droprequire github.com/hashicorp/vault/api
go mod tidy
```

**2.4** — Verify compilation after each file port:
```bash
go build ./...
```

### API Compatibility Notes

The OpenBao SDK v2 is API-compatible with Vault SDK for the interfaces used in this plugin (`framework.Backend`, `framework.Path`, `logical.Request`, `logical.Response`, `logical.Storage`). There are no field renames or signature changes in the methods used by this plugin.

One exception: the `plugin.Serve` function is replaced by `plugin.ServeMultiplex` (already handled in Phase 1). If any test utilities use `vault/sdk/helper/testcluster`, those must be replaced with `github.com/openbao/openbao/sdk/v2/helper/testcluster`.

### Phase 2 Test Plan

| Test ID | Type | Description | Pass Criteria |
|---------|------|-------------|---------------|
| P2-T1 | Build | `go build ./...` after all import replacements | Zero errors |
| P2-T2 | Import audit | `grep -r "hashicorp/vault" . --include="*.go"` | Zero matches |
| P2-T3 | Module audit | `grep "hashicorp/vault" go.mod` | Zero matches |
| P2-T4 | Mount test | Re-run P1-T5; plugin mounts successfully | Plugin accessible at `gpg/` |
| P2-T5 | Vet | `go vet ./...` | Zero issues |
| P2-T6 | Staticcheck | `staticcheck ./...` | Zero issues |

---

## Phase 3 — Crypto Library Migration

### Goal
Replace the deprecated `golang.org/x/crypto/openpgp` with `github.com/ProtonMail/go-crypto/openpgp`. The ProtonMail library is a maintained fork that is API-compatible in most cases, with several additions for modern algorithms.

### Import Substitution Map

| Old import | New import |
|------------|------------|
| `golang.org/x/crypto/openpgp` | `github.com/ProtonMail/go-crypto/openpgp` |
| `golang.org/x/crypto/openpgp/armor` | `github.com/ProtonMail/go-crypto/openpgp/armor` |
| `golang.org/x/crypto/openpgp/packet` | `github.com/ProtonMail/go-crypto/openpgp/packet` |

### Steps

**3.1** — Add ProtonMail library:
```bash
go get github.com/ProtonMail/go-crypto@latest
go mod edit -droprequire golang.org/x/crypto
go mod tidy
```

**3.2** — Bulk replace in source files:
```bash
find gpg/ -name "*.go" -exec sed -i \
  's|golang.org/x/crypto/openpgp|github.com/ProtonMail/go-crypto/openpgp|g' {} \;
```

**3.3 — Audit for breaking API differences**

The ProtonMail fork introduces these differences that require code changes:

| Issue | Old code | New code |
|-------|----------|----------|
| Key generation config | `packet.Config{RSABits: 4096}` | Unchanged; same struct |
| `NewEntity` signature | `openpgp.NewEntity(name, comment, email, config)` | Unchanged |
| `ReadArmoredKeyRing` | Unchanged | Unchanged |
| `openpgp.Encrypt` | Unchanged | Unchanged |
| `packet.Config` — preferred hash | `crypto.SHA256` | Unchanged; ProtonMail adds `PreferredHash` field, keep existing value |
| AEAD config | Not present in upstream | Optionally add `AEADConfig` for modern encryption |

The ProtonMail library adds Ed25519/Cv25519 key type support. To generate Ed25519 keys, the `packet.Config` needs:
```go
cfg := &packet.Config{
    Algorithm: packet.PubKeyAlgoEdDSA,
    Curve:     packet.Curve25519,
}
```
This is an enhancement for Phase 5, not required for the port.

**3.4** — Verify compilation and run the existing upstream test suite.

### Phase 3 Test Plan

| Test ID | Type | Description | Pass Criteria |
|---------|------|-------------|---------------|
| P3-T1 | Build | `go build ./...` after library swap | Zero errors |
| P3-T2 | Import audit | `grep -r "golang.org/x/crypto/openpgp" . --include="*.go"` | Zero matches |
| P3-T3 | Key generation unit test | Generate RSA-2048 and RSA-4096 keys using new library | Keys serialize to valid PGP armored blocks (`-----BEGIN PGP PUBLIC KEY BLOCK-----`) |
| P3-T4 | Sign/verify round-trip | Sign a test payload with generated key; verify signature using new library | Verification succeeds |
| P3-T5 | Encrypt/decrypt round-trip | Encrypt plaintext to generated key; decrypt with private key | Plaintext recovered correctly |
| P3-T6 | GnuPG interop — sign | Sign a payload via plugin; export public key from plugin; verify signature with `gpg --verify` | `gpg --verify` exits 0 with `Good signature` |
| P3-T7 | GnuPG interop — decrypt | Encrypt a payload to plugin's exported public key using `gpg --encrypt`; decrypt via plugin API | Plaintext recovered correctly |

**P3-T6 shell script:**
```bash
# Export the public key from the plugin
PUBLIC_KEY=$(bao read -field=public_key gpg/keys/test-key)

# Import into a temp GPG homedir
export GNUPGHOME=$(mktemp -d)
echo "$PUBLIC_KEY" | gpg --import

# Sign via plugin API
PAYLOAD=$(echo -n "test payload" | base64)
SIGNATURE=$(bao write -field=signature gpg/sign/test-key \
  input=$PAYLOAD format=ascii-armor)

# Verify with gpg
echo "$SIGNATURE" > /tmp/sig.asc
echo -n "test payload" > /tmp/payload.txt
gpg --verify /tmp/sig.asc /tmp/payload.txt
# Expected: Good signature from ...
```

**P3-T7 shell script:**
```bash
export GNUPGHOME=$(mktemp -d)
echo "$PUBLIC_KEY" | gpg --import

# Encrypt with gpg to the plugin's key fingerprint
FINGERPRINT=$(gpg --list-keys --with-colons | grep fpr | head -1 | cut -d: -f10)
echo -n "secret message" | gpg --encrypt --armor \
  --recipient $FINGERPRINT > /tmp/encrypted.asc

# Decrypt via plugin
CIPHERTEXT=$(cat /tmp/encrypted.asc)
bao write gpg/decrypt/test-key \
  format=ascii-armor \
  ciphertext="$CIPHERTEXT"
# Expected: plaintext field = "secret message" (base64)
```

---

## Phase 4 — Port All Path Handlers

### Goal
Port all six route handlers from the original plugin into the new repository, replacing Vault SDK types with OpenBao SDK types and ensuring all HTTP API endpoints function correctly.

### 4.1 — `path_keys.go` — Key Management

**Endpoints:**
- `POST /gpg/keys/:name` — create (generate or import) a named key
- `GET /gpg/keys/:name` — read key metadata + public key
- `DELETE /gpg/keys/:name` — delete key
- `LIST /gpg/keys` — list all key names

**Key creation parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `generate` | bool | true | Generate key internally vs. import |
| `real_name` | string | "" | Identity real name (used if generate=true) |
| `email` | string | "" | Identity email |
| `comment` | string | "" | Identity comment |
| `key_bits` | int | 4096 | RSA key size (2048 or 4096) |
| `exportable` | bool | false | Whether private key can be exported |
| `key_type` | string | "rsa" | "rsa" or "ed25519" |
| `transparency_log_address` | string | "" | Rekor endpoint for sign transparency |

**Storage schema** (stored at `keys/<name>` in OpenBao's physical storage):
```json
{
  "serialized_key": "<binary PGP private key, base64-encoded>",
  "exportable": false,
  "key_bits": 4096,
  "transparency_log_address": ""
}
```

**Key generation code pattern (ProtonMail library):**
```go
import (
    "github.com/ProtonMail/go-crypto/openpgp"
    "github.com/ProtonMail/go-crypto/openpgp/packet"
)

cfg := &packet.Config{
    RSABits:     keyBits,
    DefaultHash: crypto.SHA256,
}
entity, err := openpgp.NewEntity(realName, comment, email, cfg)
```

### 4.2 — `path_sign.go` — Detached Signature

**Endpoint:** `POST /gpg/sign/:name`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input` | string | required | Base64-encoded message to sign |
| `hash` | string | "sha2-256" | Hash algorithm: sha2-256, sha2-384, sha2-512, sha2-224 |
| `format` | string | "base64" | Output format: "base64" or "ascii-armor" |

**Returns:** `{ "signature": "<base64 or ascii-armor detached signature>" }`

**Implementation pattern:**
```go
var buf bytes.Buffer
w, err := armor.Encode(&buf, "PGP SIGNATURE", nil) // if ascii-armor
err = openpgp.DetachSign(w, entity, bytes.NewReader(input), cfg)
w.Close()
```

### 4.3 — `path_verify.go` — Signature Verification

**Endpoint:** `POST /gpg/verify/:name`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input` | string | required | Base64-encoded original message |
| `signature` | string | required | Detached signature (base64 or ascii-armor) |
| `format` | string | "base64" | Format of the `signature` field |
| `signer_key` | string | "" | ASCII-armored public key of expected signer (optional additional check) |

**Returns:** `{ "verified": true }` or logical error response

### 4.4 — `path_decrypt.go` — PGP Message Decryption

**Endpoint:** `POST /gpg/decrypt/:name`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ciphertext` | string | required | PGP message (base64 or ascii-armor) |
| `format` | string | "base64" | Format of ciphertext |
| `signer_key` | string | "" | ASCII-armored public key; if set, ciphertext must be signed by this key |

**Returns:** `{ "plaintext": "<base64-encoded plaintext>" }`

### 4.5 — `path_show_session_key.go` — Session Key Export

**Endpoint:** `POST /gpg/show-session-key/:name`

Same parameters as `/decrypt`. Returns:
```json
{
  "session_key": "<session key algorithm ID>:<hex-encoded session key>"
}
```

This is equivalent to `gpg --show-session-key` and is useful for law-enforcement/audit scenarios.

### 4.6 — `path_encrypt.go` — NEW: PGP Message Encryption

**Endpoint:** `POST /gpg/encrypt/:name` or `POST /gpg/encrypt/:name/sign/:signer_name`

This endpoint did not exist in the upstream plugin and is being added in this port.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signer_name` | string | "" | Name of another GPG key in OpenBao to sign with; URL path parameter on the `/sign/:signer_name` variant |
| `plaintext` | string | required | Base64-encoded plaintext to encrypt |
| `format` | string | "base64" | Output format: "base64" or "ascii-armor" |

**Returns:** `{ "ciphertext": "<base64 or ascii-armor PGP message>" }`

**Implementation pattern:**
```go
var buf bytes.Buffer
var out io.Writer = &buf
if format == "ascii-armor" {
    w, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
    defer w.Close()
    out = w
}

var signerEntity *openpgp.Entity
if signerKeyName != "" {
    signerEntity = loadKeyFromStorage(ctx, req, signerKeyName)
}

plainWriter, err := openpgp.Encrypt(out,
    []*openpgp.Entity{recipientEntity},
    signerEntity,
    nil,
    &packet.Config{DefaultCipher: packet.CipherAES256},
)
io.Copy(plainWriter, bytes.NewReader(plaintext))
plainWriter.Close()
```

### Phase 4 Test Plan

For each endpoint, tests are written using the OpenBao SDK test harness (`sdk/v2/logical/testing` / `framework.Backend` with `logical.TestBackend`).

**Test harness setup:**
```go
func testBackend(t *testing.T) (logical.Backend, logical.Storage) {
    config := logical.TestBackendConfig()
    b, err := Factory(context.Background(), config)
    require.NoError(t, err)
    return b, config.StorageView
}
```

#### 4-A — Key Management Tests

| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| P4-T-KM1 | Generate RSA-4096 key | `generate=true, real_name=Test, email=test@example.com, key_bits=4096` | 200; `public_key` field contains `-----BEGIN PGP PUBLIC KEY BLOCK-----` |
| P4-T-KM2 | Generate RSA-2048 key | `generate=true, key_bits=2048` | 200; public key present |
| P4-T-KM3 | Read key metadata | Read `gpg/keys/test-key` after creation | `key_bits=4096`, `exportable=false`, `public_key` present; NO private key material in response |
| P4-T-KM4 | List keys | Create two keys; LIST `gpg/keys` | Both key names appear in list |
| P4-T-KM5 | Delete key | Delete `gpg/keys/test-key`; then read it | 404 on read after delete |
| P4-T-KM6 | Overwrite protection | POST to `gpg/keys/test-key` when key already exists | 400 error, key unchanged |
| P4-T-KM7 | Import external key | `generate=false, key=<base64 PGP private key>` | 200; key readable |
| P4-T-KM8 | Non-exportable key | `exportable=false`; attempt to read private key | Private key NOT in response |
| P4-T-KM9 | Exportable key | `exportable=true`; read key | `private_key` field present in response |
| P4-T-KM10 | Invalid key_bits | `key_bits=512` | 400 error |

#### 4-B — Sign/Verify Tests

| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| P4-T-SV1 | Sign + verify round-trip (base64) | Sign `aGVsbG8=`; verify with same key | `verified=true` |
| P4-T-SV2 | Sign + verify round-trip (ascii-armor) | `format=ascii-armor` | Signature block starts with `-----BEGIN PGP SIGNATURE-----` |
| P4-T-SV3 | Verify fails wrong input | Sign "hello"; verify against "world" | Error or `verified=false` |
| P4-T-SV4 | Verify fails wrong key | Sign with key-A; verify with key-B | Verification error |
| P4-T-SV5 | signer_key enforcement | Verify with `signer_key` set to key-A's public key; present signature from key-A | `verified=true` |
| P4-T-SV6 | signer_key mismatch | Verify with `signer_key` set to key-A; present signature from key-B | Error |
| P4-T-SV7 | Hash algorithm SHA-384 | `hash=sha2-384` | Signature created; verification succeeds |
| P4-T-SV8 | Hash algorithm SHA-512 | `hash=sha2-512` | Signature created; verification succeeds |
| P4-T-SV9 | GnuPG interop verify | Sign via plugin; verify with `gpg --verify` | `gpg` exit 0, "Good signature" |
| P4-T-SV10 | GnuPG interop sign | Sign with `gpg --detach-sign`; verify via plugin API | `verified=true` |

#### 4-C — Decrypt Tests

| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| P4-T-DC1 | Encrypt externally, decrypt via plugin (ascii-armor) | Encrypt with `gpg --encrypt --armor`; POST to decrypt | Plaintext matches original |
| P4-T-DC2 | Encrypt externally, decrypt via plugin (base64) | Same, ciphertext as base64 | Plaintext matches original |
| P4-T-DC3 | Signed-and-encrypted message with signer_key | `gpg --sign --encrypt`; POST with `signer_key=<signer's public key>` | Plaintext returned, signature verified |
| P4-T-DC4 | Signed-and-encrypted, wrong signer_key | Wrong signer_key provided | Error: signature verification failed |
| P4-T-DC5 | Ciphertext for wrong key | Ciphertext encrypted to a different key | Error: cannot decrypt |
| P4-T-DC6 | Malformed ciphertext | Garbage base64 | 400 error |
| P4-T-DC7 | Show session key | Same input as DC1 | `session_key` field: `9:<hex key>` or similar; key is non-empty |

#### 4-D — Encrypt Tests (New)

| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| P4-T-EN1 | Encrypt + decrypt round-trip (internal) | Encrypt via plugin; decrypt via plugin | Plaintext recovered |
| P4-T-EN2 | Encrypt via plugin, decrypt with gpg | Encrypt via plugin (ascii-armor); import key to gpg; `gpg --decrypt` | `gpg` recovers plaintext |
| P4-T-EN3 | Encrypt with signing | `POST /gpg/encrypt/:name/sign/signing-key`; decrypt without signer check | Plaintext recovered |
| P4-T-EN4 | Encrypt with signing, verify signer | Encrypt with sign; decrypt with `/sign/:signer_name` check | Plaintext + signature verified |
| P4-T-EN5 | Non-exportable key encrypt | Encrypt to a non-exportable key | Ciphertext returned (encrypt requires only public key, must work regardless of exportable flag) |
| P4-T-EN6 | base64 output format | `format=base64` | Ciphertext is valid base64 binary PGP |
| P4-T-EN7 | ascii-armor output | `format=ascii-armor` | Ciphertext starts with `-----BEGIN PGP MESSAGE-----` |

---

## Phase 5 — ACL Policy Verification

### Goal
Ensure OpenBao's ACL system correctly scopes access to each operation. This is critical for security — a build/deploy pipeline should be able to encrypt/sign without being able to delete keys or export private key material.

### Recommended Policy Separation

**Admin policy** (key lifecycle):
```hcl
path "gpg/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

**Signer policy** (CI/CD signing only):
```hcl
path "gpg/sign/*" {
  capabilities = ["update"]
}
path "gpg/keys/*" {
  capabilities = ["read"]
}
```

**Encryptor policy** (encrypt data):
```hcl
path "gpg/encrypt/*" {
  capabilities = ["update"]
}
```

**Decryptor policy** (decrypt data):
```hcl
path "gpg/decrypt/*" {
  capabilities = ["update"]
}
```

### Phase 5 Test Plan

| Test ID | Description | Token Policy | Action | Expected |
|---------|-------------|-------------|--------|----------|
| P5-T1 | Signer cannot delete key | signer policy | DELETE `gpg/keys/my-key` | 403 Forbidden |
| P5-T2 | Signer can sign | signer policy | POST `gpg/sign/my-key` | 200 OK |
| P5-T3 | Signer cannot decrypt | signer policy | POST `gpg/decrypt/my-key` | 403 Forbidden |
| P5-T4 | Decryptor cannot sign | decryptor policy | POST `gpg/sign/my-key` | 403 Forbidden |
| P5-T5 | Encryptor cannot read private key | encryptor policy | GET `gpg/keys/my-key` (on exportable key) | 403 Forbidden |
| P5-T6 | Admin can do everything | admin policy | All operations | All succeed |
| P5-T7 | No policy = no access | empty policy | Any operation | 403 Forbidden |

---

## Phase 6 — Build, Registration, and Deployment

### Build Script (`scripts/build.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:-dev}
BINARY=openbao-plugin-secrets-gpg

echo "Building version: $VERSION"

for GOOS in linux darwin; do
    for GOARCH in amd64 arm64; do
        OUT="${BINARY}_${VERSION}_${GOOS}_${GOARCH}"
        echo "  -> $OUT"
        GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build \
            -ldflags="-X main.version=${VERSION}" \
            -o "dist/${OUT}" .
        sha256sum "dist/${OUT}" > "dist/${OUT}.sha256"
    done
done

echo "Done."
```

### Plugin Registration (`scripts/register.sh`)

```bash
#!/usr/bin/env bash
# Usage: ./scripts/register.sh <path-to-binary> [mount-path]
set -euo pipefail

BINARY=${1:?Usage: register.sh <binary>}
MOUNT=${2:-gpg}
PLUGIN_NAME=openbao-plugin-secrets-gpg

# OpenBao requires the binary to be in the plugin_directory configured in server.hcl
PLUGIN_DIR=$(bao read -field=value sys/config/state/sanitized 2>/dev/null | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['plugin_directory'])" 2>/dev/null || echo "/etc/openbao/plugins")

cp "$BINARY" "$PLUGIN_DIR/$PLUGIN_NAME"
chmod 755 "$PLUGIN_DIR/$PLUGIN_NAME"

SHASUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | awk '{print $1}')

bao plugin register -sha256="$SHASUM" secret "$PLUGIN_NAME"
echo "Registered plugin: $PLUGIN_NAME (sha256=$SHASUM)"

bao secrets enable -path="$MOUNT" -plugin-name="$PLUGIN_NAME" plugin
echo "Mounted at: $MOUNT/"
```

### Phase 6 Test Plan

| Test ID | Type | Description | Pass Criteria |
|---------|------|-------------|---------------|
| P6-T1 | Build | `scripts/build.sh` produces binaries for all four targets | Four binaries + sha256 files in `dist/` |
| P6-T2 | Checksum | sha256 of built binary matches `.sha256` file | `sha256sum -c` exits 0 |
| P6-T3 | Registration | `scripts/register.sh` against a live dev OpenBao | Plugin appears in `bao plugin list` |
| P6-T4 | Mount | Plugin mounts at specified path | `bao secrets list` shows mount |
| P6-T5 | Reload | `bao plugin reload -plugin openbao-plugin-secrets-gpg` | No error; mount still accessible |
| P6-T6 | Version | `bao read sys/plugins/catalog/secret/openbao-plugin-secrets-gpg` | Version field populated correctly |
| P6-T7 | Cross-arch | linux/arm64 binary runs on ARM64 host or QEMU | Binary executes without SIGILL |

---

## Phase 7 — Integration Test Suite

### Goal
A single `go test ./gpg/... -tags=integration` run that spins up a real OpenBao container, registers the plugin, and exercises every API endpoint end-to-end with real GnuPG interop checks.

### Test Infrastructure

Use the OpenBao Docker test cluster helper:

```go
import (
    "github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
)

func setupTestCluster(t *testing.T) (*docker.TestDockerCluster, *api.Client) {
    t.Helper()
    opts := &docker.DockerClusterOptions{
        ImageRepo: "openbao/openbao",
        ImageTag:  "latest",
        PluginTestEnv: []string{
            "PLUGIN_BINARY=/plugins/openbao-plugin-secrets-gpg",
        },
    }
    cluster := docker.NewTestDockerCluster(t, opts)
    t.Cleanup(cluster.Cleanup)
    return cluster, cluster.Nodes()[0].APIClient()
}
```

### Integration Test Matrix

| Test ID | Category | Description |
|---------|----------|-------------|
| IT-01 | Lifecycle | Create key → read → list → delete → confirm absent |
| IT-02 | Sign/Verify | Sign 1KB payload → verify same payload → alter payload → confirm fail |
| IT-03 | Sign/Verify | Sign → export public key → verify with system `gpg` binary |
| IT-04 | Decrypt | Encrypt with system `gpg` → decrypt via API → confirm plaintext |
| IT-05 | Encrypt | Encrypt via API → decrypt with system `gpg` → confirm plaintext |
| IT-06 | Round-trip | Encrypt via API → decrypt via API for same key |
| IT-07 | Round-trip | Encrypt via API to key-A → decrypt via API with key-A |
| IT-08 | Signed encrypt | Encrypt+sign via API (key-A encrypts, key-B signs) → decrypt with signer_key check → confirm |
| IT-09 | ACL — signer | Create signer-policy token → sign succeeds → delete fails → decrypt fails |
| IT-10 | ACL — decryptor | Create decryptor-policy token → decrypt succeeds → sign fails |
| IT-11 | Transparency log | Create key with `transparency_log_address=https://rekor.sigstore.dev/`; sign payload | Rekor entry URL returned in response |
| IT-12 | Key import | Export RSA-4096 key from system `gpg`; import via `generate=false`; sign + verify | Operations succeed with imported key |
| IT-13 | Exportable flag | Create exportable key; read returns `private_key`; create non-exportable; private_key absent | Field presence matches exportable flag |
| IT-14 | Session key | Encrypt with system `gpg`; call `show-session-key`; format is `<algo_id>:<hex>` | Non-empty, parseable format |
| IT-15 | Concurrent access | 20 goroutines signing different payloads with same key concurrently | All operations succeed, no race conditions |

---

## Phase 8 — CI/CD Pipeline

### `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install GnuPG
        run: sudo apt-get install -y gnupg

      - name: go vet
        run: go vet ./...

      - name: staticcheck
        run: |
          go install honnef.co/go/tools/cmd/staticcheck@latest
          staticcheck ./...

      - name: Unit tests
        run: go test ./... -race -count=1 -timeout=120s

      - name: Build all targets
        run: bash scripts/build.sh ci

      - name: Verify checksums
        run: |
          cd dist
          for f in *.sha256; do sha256sum -c "$f"; done

  integration:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Pull OpenBao image
        run: docker pull openbao/openbao:latest
      - name: Build plugin binary
        run: go build -o /tmp/openbao-plugin-secrets-gpg .
      - name: Integration tests
        run: go test ./gpg/... -tags=integration -v -timeout=300s
```

---

## Summary: Phase Sequence & Checkpoints

| Phase | Description | Exit Criteria |
|-------|-------------|---------------|
| 1 | Repository bootstrap, stub entrypoint | Compiles; mounts in dev OpenBao |
| 2 | SDK import migration | Zero Vault SDK imports; all tests pass |
| 3 | Crypto library swap | ProtonMail library in use; GnuPG interop round-trips pass |
| 4 | Port all path handlers | All 6 endpoints functional; 40+ unit tests pass |
| 5 | ACL policy verification | Policy separation enforced correctly |
| 6 | Build + registration | Cross-platform builds; clean plugin registration |
| 7 | Integration test suite | All 15 integration tests pass against live OpenBao |
| 8 | CI/CD pipeline | Green pipeline on PR; goreleaser on tag |

---

## Known Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| ProtonMail API breaks vs. x/crypto | Low | Import paths change; API is ~95% compatible; audit with `go build` |
| OpenBao SDK adds breaking changes | Low | Pin SDK version; check release notes before upgrade |
| GnuPG version differences on CI | Medium | Pin GnuPG version in CI Dockerfile; test against GnuPG 2.2 and 2.4 |
| Rekor integration breaks with network-off CI | Medium | Mock Rekor endpoint in unit tests; guard integration tests with build tag |
| Private key storage format change | Low | Define serialization version field in storage schema from day one |
| Concurrent key write race | Low | Use `framework.Backend`'s built-in locking via `b.lock` mutex on write paths |
