package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_EncryptStreamRoundTrip(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create a key
	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/test", ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": "Test User", "email": "test@example.com"},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(strings.Repeat("Streaming encrypt test data. ", 200))
	chunkSize := 500

	// Start encrypt session
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error().Error())
	}
	sessionID := resp.Data["session_id"].(string)

	// Collect encrypted chunks
	var encryptedParts [][]byte

	// Initial data from start
	initialData, err := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	encryptedParts = append(encryptedParts, initialData)

	// Send chunks
	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[i:end]
		req = &logical.Request{
			Storage: storage, Operation: logical.UpdateOperation,
			Path:        "encrypt-stream/session/" + sessionID + "/update",
			ClientToken: "test-token",
			Data: map[string]interface{}{
				"data": base64.StdEncoding.EncodeToString(chunk),
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("unexpected error on update: %s", resp.Error().Error())
		}
		encData, err := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
		if err != nil {
			t.Fatal(err)
		}
		encryptedParts = append(encryptedParts, encData)
	}

	// Finalize
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path:        "encrypt-stream/session/" + sessionID + "/finalize",
		ClientToken: "test-token",
		Data:        map[string]interface{}{},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on finalize: %s", resp.Error().Error())
	}
	if !resp.Data["done"].(bool) {
		t.Fatal("expected done=true on finalize")
	}
	finalData, err := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	encryptedParts = append(encryptedParts, finalData)

	// Concatenate all encrypted parts
	var ciphertext bytes.Buffer
	for _, part := range encryptedParts {
		ciphertext.Write(part)
	}

	// Decrypt using the existing decrypt endpoint
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt/test", ClientToken: "test-token",
		Data: map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext.Bytes()),
			"format":     "base64",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on decrypt: %s", resp.Error().Error())
	}
	decryptedB64 := resp.Data["plaintext"].(string)
	decrypted, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data does not match original: got %d bytes, expected %d bytes", len(decrypted), len(plaintext))
	}
}

func TestGPG_EncryptStreamDecryptWithGoCrypto(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/test", ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": "Test User", "email": "test@example.com"},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Data to encrypt and verify with go-crypto directly")

	// Stream encrypt
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	var encryptedParts [][]byte
	initialData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, initialData)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/update", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString(plaintext)},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	encData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, encData)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	finalData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, finalData)

	var ciphertext bytes.Buffer
	for _, part := range encryptedParts {
		ciphertext.Write(part)
	}

	// Decrypt with go-crypto directly
	// Need the private key entity
	keyEntry, err := b.key(context.Background(), storage, "test")
	if err != nil {
		t.Fatal(err)
	}
	entity, err := b.entity(keyEntry)
	if err != nil {
		t.Fatal(err)
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext.Bytes()), openpgp.EntityList{entity}, nil, nil)
	if err != nil {
		t.Fatalf("go-crypto ReadMessage failed: %v", err)
	}
	decrypted, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("failed to read decrypted body: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("go-crypto decrypted data does not match original")
	}
}

func TestGPG_EncryptStreamWithSigner(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create recipient and signer keys
	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/recipient", ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": "Recipient", "email": "recipient@example.com"},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/signer", ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": "Signer", "email": "signer@example.com"},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Signed and encrypted data")

	// Start with signer via URL path
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/recipient/sign/signer/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	var encryptedParts [][]byte
	initialData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, initialData)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/update", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString(plaintext)},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	encData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, encData)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	finalData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	encryptedParts = append(encryptedParts, finalData)

	var ciphertext bytes.Buffer
	for _, part := range encryptedParts {
		ciphertext.Write(part)
	}

	// Decrypt with signer verification via URL path
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt/recipient/sign/signer", ClientToken: "test-token",
		Data: map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext.Bytes()),
			"format":     "base64",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on decrypt with signer: %s", resp.Error().Error())
	}
	decrypted, _ := base64.StdEncoding.DecodeString(resp.Data["plaintext"].(string))
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted data does not match original")
	}
}

func TestGPG_EncryptStreamErrors(t *testing.T) {
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

	// Non-existent key
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/nokey/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent key")
	}

	// Non-existent session update
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/fakeid/update", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString([]byte("data"))},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent session")
	}

	// Wrong client token
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/test/start", ClientToken: "token-a",
		Data: map[string]interface{}{},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	sessionID := resp.Data["session_id"].(string)

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/update", ClientToken: "token-b",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString([]byte("data"))},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for wrong client token")
	}

	// Double finalize
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/finalize", ClientToken: "token-a",
		Data: map[string]interface{}{},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal("first finalize should succeed")
	}

	// Second finalize
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for double finalize")
	}
}
