# REST API Reference

All endpoints are relative to the mount path (default: `gpg/`).

## Key Management

### Create Key

Generates a new GPG key or imports an existing one.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/keys/:name` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Key name (path parameter) |
| `generate` | bool | `true` | Generate a new key (`true`) or import (`false`) |
| `key_bits` | int | `2048` | RSA key size. Minimum 2048. Only used when `generate=true` |
| `real_name` | string | | Identity real name. Must not contain `()<>\x00` |
| `email` | string | | Identity email |
| `comment` | string | | Identity comment |
| `key` | string | | ASCII-armored private key to import. Required when `generate=false` |
| `exportable` | bool | `false` | Allow private key export. Immutable after creation |

**Response**: `204 No Content` on success.

---

### Read Key

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/gpg/keys/:name` |

**Response**

| Field | Type | Description |
|---|---|---|
| `fingerprint` | string | 40-character hex fingerprint |
| `public_key` | string | ASCII-armored public key block |
| `exportable` | bool | Whether the key can be exported |

---

### List Keys

| | |
|---|---|
| **Method** | `LIST` |
| **Path** | `/gpg/keys` |

**Response**

| Field | Type | Description |
|---|---|---|
| `keys` | string[] | Array of key names |

---

### Delete Key

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/gpg/keys/:name` |

**Response**: `204 No Content`.

---

### Export Key

Returns the ASCII-armored private key. Requires `exportable=true`.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/gpg/export/:name` |

**Response**

| Field | Type | Description |
|---|---|---|
| `name` | string | Key name |
| `key` | string | ASCII-armored private key block |

---

## Sign and Verify

### Sign

Produces a PGP detached signature.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/sign/:name[/:urlalgorithm]` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Signing key name |
| `input` | string | required | Base64-encoded data to sign |
| `algorithm` | string | `sha2-256` | Hash: `sha2-224`, `sha2-256`, `sha2-384`, `sha2-512` |
| `urlalgorithm` | string | | Hash algorithm as URL path parameter (overrides `algorithm`) |
| `format` | string | `base64` | Output format: `base64` or `ascii-armor` |

**Response**

| Field | Type | Description |
|---|---|---|
| `signature` | string | Detached PGP signature in requested format |

---

### Verify

Verifies a PGP detached signature.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/verify/:name` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Key name to verify against |
| `input` | string | required | Base64-encoded original data |
| `signature` | string | required | Signature to verify |
| `format` | string | `base64` | Signature format: `base64` or `ascii-armor` |

**Response**

| Field | Type | Description |
|---|---|---|
| `valid` | bool | `true` if signature is valid |

---

## Encrypt and Decrypt

### Encrypt

Encrypts data to a named key. Produces a standard PGP message.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/encrypt/:name` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Recipient key name |
| `plaintext` | string | required | Base64-encoded plaintext |
| `format` | string | `base64` | Output format: `base64` or `ascii-armor` |
| `signer_key_name` | string | | Optional signing key for sign+encrypt |

**Response**

| Field | Type | Description |
|---|---|---|
| `ciphertext` | string | PGP encrypted message in requested format |

---

### Decrypt

Decrypts a PGP message using a named key.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/decrypt/:name` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Recipient key name (must have private key) |
| `ciphertext` | string | required | Encrypted message |
| `format` | string | `base64` | Ciphertext format: `base64` or `ascii-armor` |
| `signer_key_name` | string | | Key name to verify sender signature. If set, signature must be valid |

**Response**

| Field | Type | Description |
|---|---|---|
| `plaintext` | string | Base64-encoded decrypted data |

---

### Show Session Key

Extracts the symmetric session key from an encrypted message without decrypting the body.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/show-session-key/:name` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Recipient key name |
| `ciphertext` | string | required | Encrypted message |
| `format` | string | `base64` | Ciphertext format: `base64` or `ascii-armor` |
| `signer_key_name` | string | | Optional signer key for verification |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_key` | string | Format: `{cipher_id}:{hex_key}` |

---

## Streaming Sign

For signing data that exceeds the single-request size limit (~24MB). Uses incremental hashing — only ~3-5KB of memory per session.

### Start Sign Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/sign-stream/:name/start[/:urlalgorithm]` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Signing key name |
| `algorithm` | string | `sha2-256` | Hash algorithm |
| `urlalgorithm` | string | | Hash algorithm as URL parameter (overrides `algorithm`) |
| `format` | string | `base64` | Signature output format: `base64` or `ascii-armor` |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session identifier for subsequent calls |
| `algorithm` | string | Hash algorithm being used |
| `format` | string | Output format being used |

---

### Update Sign Session

Feed a data chunk to the signing session.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/sign-stream/:name/update` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Signing key name (must match session) |
| `session_id` | string | required | Session ID from start |
| `input` | string | required | Base64-encoded data chunk (max 4MB decoded) |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session ID |
| `bytes_received` | int | Bytes from this chunk |
| `total_bytes_received` | int | Cumulative bytes |

---

### Finalize Sign Session

Produce the final signature and destroy the session.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/sign-stream/:name/finalize` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Signing key name (must match session) |
| `session_id` | string | required | Session ID from start |

**Response**

| Field | Type | Description |
|---|---|---|
| `signature` | string | PGP detached signature in the format specified at start |

---

## Streaming Encrypt

For encrypting data that exceeds the single-request size limit. Output is binary PGP packets (base64-encoded per response). Concatenate all decoded `data` fields to form a valid PGP message.

### Start Encrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/encrypt-stream/:name/start` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Recipient key name |
| `signer_key_name` | string | | Optional signing key |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session identifier |
| `data` | string | Base64-encoded initial ciphertext (PKESK header) |
| `sequence` | int | `0` |
| `done` | bool | `false` |

---

### Update Encrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/encrypt-stream/session/:session_id/update` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `session_id` | string | required | Session ID (path parameter) |
| `data` | string | required | Base64-encoded plaintext chunk (max 4MB decoded) |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session ID |
| `data` | string | Base64-encoded encrypted chunk |
| `sequence` | int | Incrementing sequence number |
| `done` | bool | `false` |

---

### Finalize Encrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/encrypt-stream/session/:session_id/finalize` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `session_id` | string | required | Session ID (path parameter) |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session ID |
| `data` | string | Base64-encoded final ciphertext (MDC packet) |
| `sequence` | int | Final sequence number |
| `done` | bool | `true` |

**Reassembly**: `base64_decode(start.data) + base64_decode(update[0].data) + ... + base64_decode(finalize.data)` = complete `.gpg` file.

---

## Streaming Decrypt

For decrypting data that exceeds the single-request size limit. The start request must contain enough ciphertext to include the PGP PKESK header.

### Start Decrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/decrypt-stream/:name/start` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Recipient key name |
| `data` | string | required | Base64-encoded initial ciphertext (must contain PKESK header) |
| `signer_key_name` | string | | Optional signer key for verification |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session identifier |
| `data` | string | Base64-encoded initial plaintext (may be empty) |
| `sequence` | int | `0` |
| `done` | bool | `false` |

---

### Update Decrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/decrypt-stream/session/:session_id/update` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `session_id` | string | required | Session ID (path parameter) |
| `data` | string | required | Base64-encoded ciphertext chunk (max 4MB decoded) |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session ID |
| `data` | string | Base64-encoded plaintext chunk (may be empty if processing is delayed) |
| `sequence` | int | Incrementing sequence number |
| `done` | bool | `false` |

---

### Finalize Decrypt Session

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/gpg/decrypt-stream/session/:session_id/finalize` |

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `session_id` | string | required | Session ID (path parameter) |

**Response**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Session ID |
| `data` | string | Base64-encoded remaining plaintext |
| `sequence` | int | Final sequence number |
| `done` | bool | `true` |
| `signature_valid` | bool | Only present if `signer_key_name` was set. `true` if valid |
| `signature_error` | string | Only present if signature verification failed |

**Reassembly**: `base64_decode(start.data) + base64_decode(update[0].data) + ... + base64_decode(finalize.data)` = original plaintext.

---

## Streaming Session Constraints

| Constraint | Value |
|---|---|
| Max concurrent sessions | 64 |
| Session idle timeout | 5 minutes |
| Max chunk size (decoded) | 4 MB |
| Session ID format | 32-character hex string |
| Cleanup interval | 30 seconds |

**Important notes**:
- Chunks must be sent **sequentially** (not in parallel)
- Sessions are bound to the creating client's OpenBao token
- Sessions are in-memory only and lost on plugin restart
- The `bao` CLI requires `-force` flag when no key=value data is provided (e.g., finalize endpoints)
- For large data, use the `@file` syntax: `input=@/path/to/file.b64`

## Error Responses

| Scenario | HTTP Code | Error Message |
|---|---|---|
| Key not found | 400 | `key not found` |
| Key already exists | 400 | `key already exists` |
| Key not exportable | 400 | `key is not exportable` |
| Invalid base64 | 400 | `unable to decode ... as base64: ...` |
| Unsupported algorithm | 400 | `unsupported algorithm ...` |
| Unsupported format | 400 | `unsupported encoding format ...` |
| Session not found | 400 | `session not found or expired` |
| Session already finalized | 400 | `session already finalized` |
| Wrong client token | 400 | `session belongs to a different client` |
| Key name mismatch | 400 | `key name does not match session` |
| Max sessions exceeded | 400 | `too many active streaming sessions (max 64)` |
| Chunk too large | 400 | `chunk exceeds maximum size of 4194304 bytes` |
| Invalid signature (verify) | 200 | `valid: false` (not an error) |
| Invalid signature (decrypt) | 400 | `Signature is invalid or not present: ...` |
