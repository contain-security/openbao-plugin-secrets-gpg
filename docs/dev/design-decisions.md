# Design Decisions

This document records key design decisions, the alternatives considered, and the rationale for the choices made.

---

## 1. Streaming Model: Session-Based vs. Pre-Hashed vs. Key-Wrapping

**Decision**: Session-based streaming with start/update/finalize endpoints.

**Alternatives considered**:

- **Pre-hashed signing**: Client hashes the file locally, sends only the hash to OpenBao for signing. Simple and efficient (~32 bytes over the wire), but moves the hashing operation outside the trust boundary. Rejected because some keys are restricted to hardened CI/CD systems where all crypto must occur server-side.

- **Key-wrapping for encryption**: Plugin generates and PGP-wraps a symmetric session key; client does bulk AES encryption locally. Minimal data over the wire, but again moves crypto outside OpenBao. Also produces non-standard PGP messages that `gpg --decrypt` cannot process.

- **Chunked streaming (chosen)**: Client sends data in chunks across multiple HTTP requests. All crypto stays inside OpenBao. Output is standard GPG-compatible.

**Trade-off**: Higher network load and more complex implementation, but full GPG compatibility and all crypto within the trust boundary.

---

## 2. Streaming Sign: Incremental Hash vs. io.Pipe + Goroutine

**Decision**: Incremental hashing with no goroutine.

PGP detached signing is hash-then-sign internally. By replicating go-crypto's `createSignaturePacket` (unexported), we obtain a `hash.Hash` from `sig.PrepareSign()` and feed chunks directly. Only ~3-5KB of state per session.

**Why not a goroutine?** The hash operation is purely additive — no streaming output, no blocking I/O. A goroutine would add complexity (lifecycle management, error propagation) with zero benefit.

**Risk**: Coupling to go-crypto internals. The `createSignaturePacket` function is unexported and could change. Mitigated by:
- Citing the exact source (`go-crypto v1.4.1, openpgp/write.go:559`)
- Extracting to a named helper (`newDetachedSignaturePacket`) for isolated testing
- Unit tests that verify output against `openpgp.CheckArmoredDetachedSignature`

---

## 3. Streaming Encrypt: Synchronous vs. Goroutine

**Decision**: Synchronous operation via `openpgp.Encrypt`'s `io.WriteCloser`.

`openpgp.Encrypt()` returns a `WriteCloser` that encrypts data synchronously when written to. The encrypted output flows to a `lockedWriter` wrapping a `bytes.Buffer`. No goroutine needed.

**Why `lockedWriter` instead of direct buffer access?** The mutex protection is defensive — in the current flow, writes are synchronous from the HTTP handler. But if go-crypto's internal implementation ever uses goroutines for compression or MDC computation, the lock prevents data races. Cost is negligible (one uncontended lock per write).

---

## 4. Streaming Decrypt: bufferedPipeWriter Design

**Decision**: Custom `bufferedPipeWriter` with background drain goroutine.

**The problem**: `openpgp.ReadMessage()` blocks on an `io.Reader` and writes decrypted output to `md.UnverifiedBody` (also an `io.Reader`). Both sides need to be driven across HTTP request boundaries. A naive `io.Pipe` deadlocks: the HTTP handler writes ciphertext to one pipe, but the goroutine writes plaintext to another pipe that nobody reads until the HTTP handler's write completes.

**Alternatives considered**:

- **Double io.Pipe**: Deadlock risk. The goroutine produces output into a pipe while trying to consume from another pipe. If neither side reads, both block.

- **Buffered channels**: More idiomatic Go, but `openpgp.ReadMessage` expects an `io.Reader`, not a channel. Adapting would require an intermediate reader that blocks on channel receives.

- **bufferedPipeWriter (chosen)**: Non-blocking writes to an internal `bytes.Buffer`, with a background drain goroutine that feeds the actual `io.PipeWriter`. The buffer absorbs write bursts, and the drain goroutine feeds data to the pipe at the consumer's pace.

**Output side**: Uses `lockedWriter` → `bytes.Buffer` (same as encrypt). The goroutine writes decrypted data to the buffer, and the HTTP handler drains it on each response.

---

## 5. Session ID Generation and Security

**Decision**: 128-bit `crypto/rand` hex string + client token binding.

- **128 bits of entropy**: Sufficient to prevent guessing (2^128 possibilities). OpenBao already authenticates callers via tokens/policies, so the session ID only needs to prevent one authenticated user from accessing another's session.

- **Client token binding**: `SHA-256(req.ClientToken)` is stored on the session and verified on every update/finalize. This prevents a user from hijacking another user's session even if they somehow learn the session ID.

- **No HMAC signing**: The session ID is not signed because it's validated server-side on every request. A tampered ID simply won't be found in the session store.

---

## 6. Session Limits and Cleanup

**Decision**: 64 max sessions, 5-minute idle timeout, 30-second sweep interval.

- **64 sessions**: At ~2MB peak memory per session, this bounds total memory to ~128MB. Sufficient for CI/CD workloads where signing/encryption operations are serialized per pipeline.

- **5-minute timeout**: Allows for slow network transfers and brief client interruptions without losing session state. Short enough to reclaim resources from abandoned sessions.

- **Atomic increment-then-check for max sessions**: `sessionCount.Add(1)` first, then check. If over limit, roll back with `Add(-1)`. This avoids the TOCTOU race where two concurrent `create` calls both pass the limit check.

- **`LoadAndDelete` in cleanup**: Prevents double-decrement if `remove()` and `cleanup()` race on the same session.

---

## 7. No ASCII-Armor in Streaming Encrypt/Decrypt

**Decision**: Streaming encrypt/decrypt output binary PGP packets (base64-encoded per chunk for JSON transport).

ASCII-armor includes a CRC24 checksum computed over the entire message body. To produce valid armor, you must buffer all data to compute the checksum — defeating the purpose of streaming. The client can armor the reassembled binary output if needed.

Non-streaming endpoints continue to support both `base64` and `ascii-armor` formats.

---

## 8. Stored signer key reference vs. inline `signer_key` (Upstream Change)

**Decision**: Replace inline `signer_key` (ASCII-armored public key in the request) with a `/sign/:signer_name` URL segment that references a key stored in OpenBao.

**Rationale**:
- Consistent API: all endpoints reference keys by name, not inline material
- Keys stay inside OpenBao: no need to transmit public keys in API calls
- Enables sign+encrypt: the signer's private key must be accessible (not just the public key)

**Limitation**: To verify a signer during decrypt, the signer's full key (including private key) must be stored in OpenBao. Public-key-only import is not currently supported because key storage requires a private key for serialization.

---

## 9. Replicating Unexported go-crypto Functions

**Decision**: Replicate `createSignaturePacket` locally rather than using the public `DetachSign` API with `io.Pipe`.

**Alternative**: Use `openpgp.DetachSign(pipeWriter, entity, pipeReader, config)` with an `io.Pipe`, feeding chunks through the pipe across HTTP requests. This would use only public API.

**Why rejected**: The pipe approach requires a goroutine running `DetachSign`, with all the lifecycle management complexity (timeout cleanup, goroutine leaks, error propagation). The incremental hash approach is far simpler: ~15 lines of replicated code vs. ~100 lines of goroutine management. The hash approach also uses ~3KB of memory per session vs. ~8KB for a goroutine stack.

**Maintenance burden**: The replicated code is a single function (`newDetachedSignaturePacket`) with a doc comment citing the exact source. If go-crypto changes the signature packet format, the unit tests (which verify against `CheckArmoredDetachedSignature`) will catch the incompatibility.

---

## 10. Plugin Entrypoint: ServeMultiplex

**Decision**: Use `plugin.ServeMultiplex` instead of `plugin.Serve`.

All OpenBao builtin plugins use `ServeMultiplex`, which allows a single plugin process to handle multiple mount points. The upstream vault-gpg-plugin uses `Serve` (single-mount), but this was updated for OpenBao compatibility.
