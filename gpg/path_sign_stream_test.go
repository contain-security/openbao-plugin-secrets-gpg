package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_SignStreamRoundTrip(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create a key
	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// The data to sign (simulating a large file split into chunks)
	fullData := []byte(strings.Repeat("Hello, this is test data for streaming sign. ", 100))
	chunkSize := 500

	// Start session
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/start",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"algorithm": "sha2-256",
			"format":    "ascii-armor",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error().Error())
	}
	sessionID := resp.Data["session_id"].(string)
	if sessionID == "" {
		t.Fatal("expected non-empty session_id")
	}

	// Send chunks
	var totalSent int
	for i := 0; i < len(fullData); i += chunkSize {
		end := i + chunkSize
		if end > len(fullData) {
			end = len(fullData)
		}
		chunk := fullData[i:end]
		req = &logical.Request{
			Storage:     storage,
			Operation:   logical.UpdateOperation,
			Path:        "sign-stream/test/update",
			ClientToken: "test-token",
			Data: map[string]interface{}{
				"session_id": sessionID,
				"input":      base64.StdEncoding.EncodeToString(chunk),
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("unexpected error on update: %s", resp.Error().Error())
		}
		totalSent += len(chunk)
	}

	if totalRecv := resp.Data["total_bytes_received"].(int64); totalRecv != int64(len(fullData)) {
		t.Fatalf("expected total_bytes_received=%d, got %d", len(fullData), totalRecv)
	}

	// Finalize
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/finalize",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on finalize: %s", resp.Error().Error())
	}
	signature := resp.Data["signature"].(string)
	if !strings.HasPrefix(signature, "-----BEGIN PGP SIGNATURE-----") {
		t.Fatal("expected ascii-armored signature")
	}

	// Verify the signature using the existing verify endpoint
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "verify/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"input":     base64.StdEncoding.EncodeToString(fullData),
			"signature": signature,
			"format":    "ascii-armor",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on verify: %s", resp.Error().Error())
	}
	if !resp.Data["valid"].(bool) {
		t.Fatal("expected signature to be valid")
	}
}

func TestGPG_SignStreamBase64Format(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create a key
	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test data for base64 format")

	// Start session with base64 format
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/start",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"algorithm": "sha2-256",
			"format":    "base64",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	// Send data in one chunk
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      base64.StdEncoding.EncodeToString(data),
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Finalize
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/finalize",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	signature := resp.Data["signature"].(string)

	// Verify using existing verify endpoint
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "verify/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"input":     base64.StdEncoding.EncodeToString(data),
			"signature": signature,
			"format":    "base64",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Data["valid"].(bool) {
		t.Fatal("expected signature to be valid")
	}
}

func TestGPG_SignStreamVsNonStream(t *testing.T) {
	// Verify that streaming sign and non-streaming sign of the same data
	// both produce signatures that verify against the same data.
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("consistent data for both sign methods")
	inputB64 := base64.StdEncoding.EncodeToString(data)

	// Non-streaming sign
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"input":     inputB64,
			"format":    "ascii-armor",
			"algorithm": "sha2-256",
		},
	}
	respNonStream, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Streaming sign: start → update → finalize
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/start",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"algorithm": "sha2-256",
			"format":    "ascii-armor",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      inputB64,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/finalize",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	respStream, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Both signatures should verify against the same data
	for name, sig := range map[string]string{
		"non-stream": respNonStream.Data["signature"].(string),
		"stream":     respStream.Data["signature"].(string),
	} {
		req = &logical.Request{
			Storage:     storage,
			Operation:   logical.UpdateOperation,
			Path:        "verify/test",
			ClientToken: "test-token",
			Data: map[string]interface{}{
				"input":     inputB64,
				"signature": sig,
				"format":    "ascii-armor",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: verify error: %v", name, err)
		}
		if !resp.Data["valid"].(bool) {
			t.Fatalf("%s: expected signature to be valid", name)
		}
	}
}

func TestGPG_SignStreamVerifyWithGoOpenpgp(t *testing.T) {
	// Verify the streaming signature directly with go-crypto's CheckArmoredDetachedSignature.
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Get the public key for verification
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "keys/test",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyArmor := resp.Data["public_key"].(string)

	data := []byte("data to verify with go-openpgp directly")

	// Stream sign
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/start",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"algorithm": "sha2-512",
			"format":    "ascii-armor",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      base64.StdEncoding.EncodeToString(data),
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/finalize",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	signatureArmor := resp.Data["signature"].(string)

	// Verify with go-crypto directly
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKeyArmor))
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), strings.NewReader(signatureArmor), nil)
	if err != nil {
		t.Fatalf("go-crypto signature verification failed: %v", err)
	}
}

func TestGPG_SignStreamErrors(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create a key
	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Test: update with non-existent session
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"session_id": "nonexistent",
			"input":      base64.StdEncoding.EncodeToString([]byte("data")),
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent session")
	}

	// Test: start with non-existent key
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/nonexistent/start",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"algorithm": "sha2-256",
			"format":    "base64",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent key")
	}

	// Test: wrong client token
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/start",
		ClientToken: "token-a",
		Data: map[string]interface{}{
			"algorithm": "sha2-256",
			"format":    "base64",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	// Try to update with different token
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "token-b",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      base64.StdEncoding.EncodeToString([]byte("data")),
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for wrong client token")
	}

	// Test: wrong key name on update
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/wrongkey/update",
		ClientToken: "token-a",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      base64.StdEncoding.EncodeToString([]byte("data")),
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for wrong key name")
	}

	// Test: double finalize
	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/update",
		ClientToken: "token-a",
		Data: map[string]interface{}{
			"session_id": sessionID,
			"input":      base64.StdEncoding.EncodeToString([]byte("data")),
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "sign-stream/test/finalize",
		ClientToken: "token-a",
		Data: map[string]interface{}{
			"session_id": sessionID,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal("first finalize should succeed")
	}

	// Second finalize should fail (session removed)
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for double finalize")
	}
}

func TestGPG_SignStreamTamperedData(t *testing.T) {
	// Verify that a signature produced by streaming sign fails verification
	// when the data is modified.
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage:     storage,
		Operation:   logical.UpdateOperation,
		Path:        "keys/test",
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"real_name": "Test User",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("original data")

	// Sign
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{"algorithm": "sha2-256", "format": "ascii-armor"},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/update", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sessionID, "input": base64.StdEncoding.EncodeToString(data)},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sessionID},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	signature := resp.Data["signature"].(string)

	// Verify with tampered data — should fail
	tamperedData := []byte("tampered data")
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "verify/test", ClientToken: "test-token",
		Data: map[string]interface{}{
			"input":     base64.StdEncoding.EncodeToString(tamperedData),
			"signature": signature,
			"format":    "ascii-armor",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["valid"].(bool) {
		t.Fatal("expected signature to be INVALID for tampered data")
	}

	// Also verify directly with go-crypto
	keyReq := &logical.Request{Storage: storage, Operation: logical.ReadOperation, Path: "keys/test"}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyArmor := keyResp.Data["public_key"].(string)
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKeyArmor))
	if err != nil {
		t.Fatal(err)
	}

	// Good data should verify
	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), strings.NewReader(signature), nil)
	if err != nil {
		t.Fatalf("original data should verify: %v", err)
	}

	// Tampered data should NOT verify
	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(tamperedData), strings.NewReader(signature), nil)
	if err == nil {
		t.Fatal("tampered data should NOT verify")
	}
}

// TestGPG_SignStreamVerifyWithExistingEndpoint_Base64 verifies that the base64
// output from streaming sign matches what the verify endpoint expects.
func TestGPG_SignStreamVerifyWithExistingEndpoint_Base64(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/test", ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": "Test", "email": "t@t.com"},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("base64 round trip data")
	b64Data := base64.StdEncoding.EncodeToString(data)

	// Start
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{"algorithm": "sha2-256", "format": "base64"},
	}
	resp, _ := b.HandleRequest(context.Background(), req)
	sid := resp.Data["session_id"].(string)

	// Update
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/update", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid, "input": b64Data},
	}
	b.HandleRequest(context.Background(), req)

	// Finalize
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "sign-stream/test/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	sig := resp.Data["signature"].(string)

	// Verify via the plugin's verify endpoint
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "verify/test", ClientToken: "test-token",
		Data: map[string]interface{}{"input": b64Data, "signature": sig, "format": "base64"},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Data["valid"].(bool) {
		t.Fatal("base64 streaming signature should verify via verify endpoint")
	}

	// Also verify the raw signature bytes are valid by decoding and checking with go-crypto
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("failed to decode base64 signature: %v", err)
	}

	// Re-armor the raw bytes to verify with go-crypto's armored checker
	var armorBuf bytes.Buffer
	w, _ := armor.Encode(&armorBuf, "PGP SIGNATURE", nil)
	w.Write(sigBytes)
	w.Close()

	keyReq := &logical.Request{Storage: storage, Operation: logical.ReadOperation, Path: "keys/test"}
	keyResp, _ := b.HandleRequest(context.Background(), keyReq)
	keyring, _ := openpgp.ReadArmoredKeyRing(strings.NewReader(keyResp.Data["public_key"].(string)))

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), strings.NewReader(armorBuf.String()), nil)
	if err != nil {
		t.Fatalf("go-crypto verification of re-armored base64 signature failed: %v", err)
	}
}
