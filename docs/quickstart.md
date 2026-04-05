# Quick Start Guide

## Prerequisites

- OpenBao server (v2.0+) running and unsealed
- `bao` CLI configured (`BAO_ADDR` and `BAO_TOKEN` set)
- Plugin binary built and placed in the plugin directory

## 1. Build the Plugin

```bash
cd openbao-plugin-secrets-gpg
go build -o /path/to/plugins/openbao-plugin-secrets-gpg .
```

## 2. Register and Mount

```bash
SHA=$(sha256sum /path/to/plugins/openbao-plugin-secrets-gpg | awk '{print $1}')
bao plugin register -sha256=$SHA secret openbao-plugin-secrets-gpg
bao secrets enable -path=gpg -plugin-name=openbao-plugin-secrets-gpg plugin
```

## 3. Create a Key

```bash
bao write gpg/keys/my-key \
    real_name="My Application" \
    email="app@example.com" \
    generate=true \
    key_bits=4096 \
    exportable=true
```

Verify the key was created:

```bash
bao read gpg/keys/my-key
```

## 4. Sign Data

```bash
# Encode the data
INPUT=$(echo -n "Hello, World!" | base64)

# Sign
bao write -field=signature gpg/sign/my-key \
    input="$INPUT" \
    format=ascii-armor
```

## 5. Verify a Signature

```bash
INPUT=$(echo -n "Hello, World!" | base64)
SIGNATURE="-----BEGIN PGP SIGNATURE----- ..."

bao write -field=valid gpg/verify/my-key \
    input="$INPUT" \
    signature="$SIGNATURE" \
    format=ascii-armor
```

## 6. Encrypt Data

```bash
PLAINTEXT=$(echo -n "Secret message" | base64)

bao write -field=ciphertext gpg/encrypt/my-key \
    plaintext="$PLAINTEXT" \
    format=ascii-armor
```

## 7. Decrypt Data

```bash
bao write -field=plaintext gpg/decrypt/my-key \
    ciphertext="$CIPHERTEXT" \
    format=ascii-armor
```

The plaintext is returned as base64. Decode with: `echo "$RESULT" | base64 -d`

## 8. Sign a Large File (Streaming)

For files exceeding 24MB, use the streaming endpoints:

```bash
# Start a signing session
SESSION=$(bao write -format=json gpg/sign-stream/my-key/start \
    algorithm=sha2-256 format=ascii-armor | jq -r '.data.session_id')

# Send the file in chunks (16MB each)
split -b 16M firmware.bin /tmp/chunk_
for chunk in /tmp/chunk_*; do
    base64 -w0 "$chunk" > /tmp/chunk.b64
    bao write gpg/sign-stream/my-key/update \
        session_id="$SESSION" input=@/tmp/chunk.b64
done

# Finalize and get the signature
bao write -field=signature gpg/sign-stream/my-key/finalize \
    session_id="$SESSION" > firmware.sig

# Verify with gpg
gpg --verify firmware.sig firmware.bin
```

## 9. Encrypt a Large File (Streaming)

```bash
# Start
START=$(bao write -force -format=json gpg/encrypt-stream/my-key/start)
SESSION=$(echo "$START" | jq -r '.data.session_id')
echo -n "$(echo "$START" | jq -r '.data.data')" | base64 -d > output.gpg

# Send chunks
split -b 4M largefile.bin /tmp/chunk_
for chunk in /tmp/chunk_*; do
    base64 -w0 "$chunk" > /tmp/chunk.b64
    RESP=$(bao write -format=json "gpg/encrypt-stream/session/$SESSION/update" \
        data=@/tmp/chunk.b64)
    echo -n "$(echo "$RESP" | jq -r '.data.data')" | base64 -d >> output.gpg
done

# Finalize
FIN=$(bao write -force -format=json "gpg/encrypt-stream/session/$SESSION/finalize")
echo -n "$(echo "$FIN" | jq -r '.data.data')" | base64 -d >> output.gpg

# Decrypt with gpg
gpg --decrypt output.gpg > recovered.bin
```

## 10. Import an Existing Key

```bash
bao write gpg/keys/imported-key \
    generate=false \
    key=@/path/to/private-key.asc \
    exportable=true
```

## GnuPG Interoperability

All signatures and encrypted messages produced by this plugin are standard PGP format and can be processed by GnuPG:

```bash
# Export the public key for GnuPG use
bao read -field=public_key gpg/keys/my-key | gpg --import

# Verify plugin signatures with gpg
gpg --verify signature.asc datafile

# Decrypt plugin-encrypted messages with gpg
gpg --decrypt message.gpg
```

Conversely, data signed or encrypted by GnuPG can be verified or decrypted by the plugin, provided the corresponding key is stored in OpenBao.
