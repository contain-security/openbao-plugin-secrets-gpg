# Architecture Overview

## Plugin Type and Registration

The GPG secrets plugin is an external **logical backend** for OpenBao. It registers as `logical.TypeLogical` and is served via `plugin.ServeMultiplex`, allowing OpenBao to manage its lifecycle. The plugin communicates with the OpenBao server over gRPC.

```
OpenBao Server
  └── Plugin Catalog
        └── openbao-plugin-secrets-gpg (gRPC)
              └── gpg/ mount path
```

## Module and Dependencies

- **Module**: `openbao-plugin-secrets-gpg` (local, no remote prefix)
- **Go version**: 1.25.0+ (OpenBao SDK requires 1.25.8 for building the server itself)
- **SDK**: `github.com/openbao/openbao/sdk/v2` via local `replace` directive
- **Crypto library**: `github.com/ProtonMail/go-crypto/openpgp` (v1.4.1)
  - Migrated from `golang.org/x/crypto/openpgp` (deprecated upstream)
  - Supports RFC 4880 and RFC 9580 (v6 keys)

## Backend Structure

```
backend struct
  ├── *framework.Backend        // OpenBao framework base
  ├── keyLocks                  // Per-key lock array (locksutil)
  ├── streamSessions            // Session store for streaming ops
  └── cleanupCancel             // Context cancel for cleanup goroutine
```

The `Factory` function initializes the backend, starts the session cleanup goroutine, and returns the configured backend to OpenBao. On shutdown, `Clean` cancels the cleanup context and terminates all active sessions.

## Path Registration

All endpoints are registered as `framework.Path` entries in `Backend()`:

| Category | Paths | Handler File |
|---|---|---|
| Key CRUD | `keys/{name}`, `keys/?$` | `path_keys.go` |
| Key Export | `export/{name}` | `path_export.go` |
| Key Config | `keys/{name}/config` | `path_config.go` |
| Sign/Verify | `sign/{name}`, `verify/{name}` | `path_sign_verify.go` |
| Encrypt | `encrypt/{name}` | `path_encrypt.go` |
| Decrypt | `decrypt/{name}` | `path_decrypt.go` |
| Show Session Key | `show-session-key/{name}` | `path_show_session_key.go` |
| Stream Sign | `sign-stream/{name}/start\|update\|finalize` | `path_sign_stream.go` |
| Stream Encrypt | `encrypt-stream/{name}/start`, `encrypt-stream/session/{id}/update\|finalize` | `path_encrypt_stream.go` |
| Stream Decrypt | `decrypt-stream/{name}/start`, `decrypt-stream/session/{id}/update\|finalize` | `path_decrypt_stream.go` |

## Key Storage

Keys are stored at `key/{name}` with **seal-wrap** enabled (configured via `PathsSpecial.SealWrapStorage`). This means key material is encrypted at rest by OpenBao's seal mechanism before being written to the storage backend.

```go
type keyEntry struct {
    SerializedKey []byte `json:"SerializedKey"`
    Exportable    bool   `json:"Exportable"`
}
```

`SerializedKey` contains the full OpenPGP keyring (primary key + subkeys + user IDs) in binary format. The `b.entity()` helper deserializes it into an `openpgp.Entity` on each request.

Keys are protected by per-key locks (`locksutil.CreateLocks()`) to prevent concurrent mutation of the same key.

## Cryptographic Operations

### Non-Streaming (Single Request)

All data fits within one HTTP request (max ~24MB after base64 overhead from OpenBao's 32MB request limit).

**Sign**: `openpgp.ArmoredDetachSign()` produces a standard PGP detached signature. The signature is either returned as ascii-armor or the binary signature bytes are base64-encoded.

**Verify**: `openpgp.CheckDetachedSignature()` / `CheckArmoredDetachedSignature()` returns the signer entity on success. The endpoint returns `valid: true/false` without raising an error on verification failure.

**Encrypt**: `openpgp.Encrypt()` produces a hybrid-encrypted PGP message (AES-256 session key, RSA-wrapped). The `io.WriteCloser` pattern writes plaintext, and encrypted output accumulates in a buffer.

**Decrypt**: `openpgp.ReadMessage()` parses the PKESK packet, decrypts the session key, and returns a `MessageDetails` with `UnverifiedBody` as an `io.Reader`. After fully reading the body, signature verification results are available.

### Streaming (Multi-Request Sessions)

For data exceeding the request size limit (firmware images up to 3GB, SBOMs at 200MB+). Three session-based streaming flows:

#### Streaming Sign — Incremental Hashing

The simplest streaming design. PGP detached signing internally hashes the data then signs the hash. We replicate go-crypto's unexported `createSignaturePacket` to construct a `*packet.Signature`, call `PrepareSign()` to get a `hash.Hash`, and feed chunks into the hash across update calls.

```
Start:  key validation → createSignaturePacket → PrepareSign → hash.Hash
Update: base64 decode → hash.Write(chunk)  [chunk discarded immediately]
Final:  sig.Sign(hash, privateKey) → sig.Serialize → encode
```

**Memory per session**: ~3-5KB (hash state + signature packet + key pointer). No goroutine.

#### Streaming Encrypt — Synchronous WriteCloser

`openpgp.Encrypt()` returns an `io.WriteCloser` that encrypts data synchronously when written to. Output goes to a `bytes.Buffer` wrapped in a `lockedWriter` (mutex-protected). No goroutine needed.

```
Start:  openpgp.Encrypt(lockedWriter, recipients, signer, config) → WriteCloser
        drain outputBuf → PKESK header bytes returned to client
Update: WriteCloser.Write(chunk) → encrypted bytes appear in outputBuf
        drain outputBuf → encrypted chunk returned to client
Final:  WriteCloser.Close() → MDC bytes appear in outputBuf
        drain outputBuf → final chunk returned to client
```

Client concatenates all response `data` chunks (base64-decoded) to form a valid PGP message.

**Memory per session**: ~1-2MB (one chunk buffered in outputBuf).

#### Streaming Decrypt — Goroutine + Buffered Pipe

The most complex design. `openpgp.ReadMessage()` blocks on an `io.Reader` until enough data arrives to parse the PKESK header. A background goroutine runs `ReadMessage` and copies decrypted data from `md.UnverifiedBody` to a `lockedWriter` → `bytes.Buffer`.

Ciphertext is fed via a `bufferedPipeWriter` — a non-blocking wrapper around `io.PipeWriter` that buffers data and drains it to the pipe via a background drain goroutine. This prevents deadlock: without buffering, writing to the pipe would block if the ReadMessage goroutine hasn't consumed previous data yet.

```
                HTTP Handler                    Goroutine
                ────────────                    ─────────
Start:  bufferedPipeWriter.Write(initial)  →  ReadMessage(pipeReader, keyring)
        wait readySignal (5s timeout)         → parses PKESK, returns md
        drain outputBuf → initial plaintext   → io.Copy(lockedWriter, md.UnverifiedBody)

Update: bpw.Write(chunk)                   →  pipe drains to ReadMessage reader
        drain outputBuf → plaintext chunk     → decrypted bytes appear in outputBuf

Final:  bpw.Close()                        →  EOF on pipe
        wait goroutineDone                    → goroutine finishes, checks signature
        drain outputBuf → remaining plaintext
        return signature_valid (if signer)
```

**Memory per session**: ~1-2MB (one chunk in buffered pipe + output buffer).

## Session Management

All streaming sessions are managed by `sessionStore` (in `stream_session.go`):

```
sessionStore
  ├── sessions     sync.Map          // session_id → *streamSession
  ├── sessionCount atomic.Int64       // atomic counter
  ├── maxSessions  int                // default 64
  └── timeout      time.Duration      // default 5 minutes
```

**Session lifecycle**: `create` → `get` (repeated) → `remove` (on finalize or timeout)

**Concurrency safety**:
- `sync.Map` for lock-free session lookup
- `atomic.Int64` with increment-then-check for max session enforcement (no TOCTOU race)
- `LoadAndDelete` in cleanup/remove to prevent double-decrement
- Per-session `sync.Mutex` for state protection

**Cleanup**: A background goroutine sweeps every 30 seconds, terminating sessions idle for more than 5 minutes. On plugin shutdown, `killAll` terminates all active sessions.

**Security**:
- Session IDs are 128-bit `crypto/rand` values (32 hex characters)
- Sessions are bound to the creating client's token via `SHA-256(clientToken)` — a different OpenBao token cannot access another's session
- Key name is validated on update/finalize (sign-stream) to prevent cross-key operations

## Data Flow

```
Client → HTTP → OpenBao Server → gRPC → Plugin
                                          ├── Storage (key/)  [seal-wrapped]
                                          ├── go-crypto/openpgp  [crypto ops]
                                          └── streamSessions  [in-memory]
```

No data transits external systems. Key material never leaves the plugin process except via the export endpoint (when `exportable=true`). Streaming session state is purely in-memory and lost on plugin restart.

## Differences from Upstream (vault-gpg-plugin)

| Area | Upstream | This Plugin |
|---|---|---|
| SDK | HashiCorp Vault SDK | OpenBao SDK v2 |
| Entrypoint | `plugin.Serve` | `plugin.ServeMultiplex` |
| `signer_key` param | Inline ASCII-armored public key | `signer_key_name` (reference to stored key) |
| `/encrypt` endpoint | Not present | Added |
| Streaming endpoints | Not present | 9 new endpoints (sign/encrypt/decrypt) |
| Session management | Not present | Full session store with cleanup |
| Crypto library | `golang.org/x/crypto/openpgp` | `ProtonMail/go-crypto/openpgp` |
