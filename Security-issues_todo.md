# Security Issues — Streaming PGP Encrypt/Decrypt (Status)

Assessment of the **streaming** interface (`gpg/path_decrypt_stream.go`,  
`gpg/path_encrypt_stream.go`, `gpg/path_sign_stream.go`, `gpg/stream_session.go`).  
All findings below concern the streaming start/update/finalize endpoints, not the  
single-shot `/encrypt` `/decrypt` `/sign` paths (except where noted for contrast).

Scope note: the interface is only reachable by an OpenBao-authenticated client.  
DoS by an authenticated user is explicitly **not** a primary concern at this time;  
per-client connection limits are considered an optional future add-on.

Ideal operational mode: stream-encrypt a ~1TB archive and stream-decrypt it back.

---

## Not a bug (by design) — Release of Unverified Plaintext (RUP)

Streaming authenticated decryption must hand plaintext to the consumer _before_  
the integrity tag (MDC/SEIPD) verifies at end-of-stream. Buffering the whole  
plaintext to verify-first would just convert this into a memory/storage DoS.  
This matches how GnuPG itself behaves (`gpg --decrypt` streams to stdout, signals  
tampering only via exit status afterward).

**Conclusion:** acceptable design **provided** the consumer contract is stated and  
enforced. The security therefore rests on the items below — not on the RUP property  
itself.

What already works correctly (keep): for a cooperative consumer that waits for  
`finalize` to succeed, integrity _is_ enforced server-side — a tampered SEIPD/MDC  
makes `io.Copy(limited, md.UnverifiedBody)` return an error at EOF  
(`path_decrypt_stream.go:351`), surfaced as `goroutineErr`, so `finalize` returns  
an error instead of `done:true`. `ReadMessage` is called with a `nil` config, so  
go-crypto rejects legacy non-integrity-protected packets by default.

---

## Implementation status

### [x] SEV: MEDIUM — Signature verdict bound to the requested signer

Original issue: `signature_valid` proved only that the message was signed by
some key in the verification keyring, not necessarily the caller-requested
`signer_name`.

Status: implemented for both decrypt paths. The verdict now requires the
verified signing key's primary key id to match the requested signer entity:

* single-shot decrypt: `gpg/path_decrypt.go`
* streaming decrypt: `gpg/path_decrypt_stream.go`

Regression coverage: `gpg/signature_binding_test.go` checks that a message
signed by the recipient does **not** satisfy a request to verify another signer,
and that the correct signer succeeds.

### [x] SEV: HIGH (functional/operational) — Stream caps are configurable

Original issue: hard-coded cumulative caps blocked large-archive streaming:

| Path | Cap | Built-in default |
| --- | --- | --- |
| decrypt-stream | total decrypted out | 32 MiB (`defaultMaxPlaintextSize`) |
| encrypt-stream | total input | 512 MiB (`defaultMaxStreamBytes`) |
| sign-stream | total input | 512 MiB (`defaultMaxStreamBytes`) |

Status: implemented as a mount runtime configuration endpoint at `gpg/config`
(`gpg/path_config_stream.go`). These are configured **after** the secrets engine
is mounted, not as `bao secrets enable` options.

Relevant settings:

* `max_stream_bytes`: total input bytes per encrypt/sign stream; `0` = unlimited
* `max_plaintext_size`: decrypted plaintext bytes per decrypt stream; `0` = unlimited
* `max_chunk_size`: decoded bytes per chunk/start payload
* `session_timeout_seconds`: idle timeout before a stalled session is reaped
* `max_sessions`, `max_sessions_per_client`: concurrent session limits

For 40-60 GiB archive streams, configure the mount before use, for example:

```sh
bao write gpg/config \
  max_stream_bytes=0 \
  max_plaintext_size=0 \
  session_timeout_seconds=3600
```

If retaining a decompression-bomb ceiling is preferred, set a finite
`max_plaintext_size` above the largest expected plaintext, for example 70 GiB:

```sh
bao write gpg/config max_plaintext_size=75161927680
```

Regression coverage: `gpg/path_config_stream_test.go` checks defaults,
validation, merge/delete behavior, finite cap enforcement, and unlimited mode.

### [x] SEV: LOW — Response field names unified across stream stages

Original issue: `start`/`update` used `signature_verified` while `finalize` used
`signature_valid`.

Status: implemented. Streaming decrypt now consistently uses:

* `signature_valid`: false until finalize, then the signer-bound verdict
* `signature_final`: false until finalize, then true

Docs now describe those fields for start/update/finalize in `docs/api.md`.
Regression coverage: `gpg/signature_binding_test.go` verifies the fields are
present with the expected terminal-gate semantics.

### [x] Session idle timeout vs. multi-hour transfers

Status: confirmed and made configurable. `lastAccess` is refreshed on every
`update`, so an actively streaming session is not reaped. A stall longer than
`session_timeout_seconds` will expire the session; the built-in default remains
5 minutes, and large-transfer deployments should raise it (for example to 3600
seconds) via `gpg/config`.

---

## Withdrawn after cross-check

### Resource/DoS asymmetry on streaming decrypt — NOT a streaming-specific issue

Earlier flagged: decrypt `update` has no cumulative input cap (unlike encrypt/sign),  
and idle sessions could pin memory. Cross-check confirms the OpenBao side holds only  
a working-set in cooperative operation: `update` is serialized per session  
(`sess.mu.Lock()`), the client can't send the next chunk until it reads the current  
response, and each `update` drains+`Reset()`s `outputBuf`. The only abuse paths are  
(a) a misbehaving authenticated client (accepted authenticated-user DoS) or  
(b) many concurrent sessions (the deferred per-client connection-limit add-on).  
The missing decrypt input cap is actually _correct_ for the 1TB goal. No action.
