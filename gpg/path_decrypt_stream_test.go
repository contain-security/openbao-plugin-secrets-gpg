package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// encryptWithPlugin is a helper that uses the non-streaming encrypt endpoint
// to produce a ciphertext for decrypt-stream testing.
func encryptWithPlugin(t *testing.T, b *backend, storage logical.Storage, keyName string, plaintext []byte, signerKeyName string) []byte {
	t.Helper()
	path := "encrypt/" + keyName
	if signerKeyName != "" {
		path = "encrypt/" + keyName + "/sign/" + signerKeyName
	}
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		"format":    "base64",
	}
	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: path, ClientToken: "test-token",
		Data: data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("encrypt error: %s", resp.Error().Error())
	}
	ciphertext, err := base64.StdEncoding.DecodeString(resp.Data["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

// streamEncryptWithPlugin uses the streaming encrypt to produce ciphertext.
func streamEncryptWithPlugin(t *testing.T, b *backend, storage logical.Storage, keyName string, plaintext []byte, chunkSize int) []byte {
	t.Helper()

	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/" + keyName + "/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	var parts [][]byte
	initialData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	parts = append(parts, initialData)

	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		req = &logical.Request{
			Storage: storage, Operation: logical.UpdateOperation,
			Path: "encrypt-stream/session/" + sessionID + "/update", ClientToken: "test-token",
			Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString(plaintext[i:end])},
		}
		resp, _ = b.HandleRequest(context.Background(), req)
		encData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
		parts = append(parts, encData)
	}

	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "encrypt-stream/session/" + sessionID + "/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, _ = b.HandleRequest(context.Background(), req)
	finalData, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	parts = append(parts, finalData)

	var result bytes.Buffer
	for _, p := range parts {
		result.Write(p)
	}
	return result.Bytes()
}

func TestGPG_DecryptStreamRoundTrip(t *testing.T) {
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

	plaintext := []byte(strings.Repeat("Decrypt stream test data. ", 100))

	// Encrypt with the non-streaming endpoint
	ciphertext := encryptWithPlugin(t, b, storage, "test", plaintext, "")

	// Stream decrypt
	chunkSize := 500
	var decryptedParts [][]byte

	// Start
	firstChunkEnd := chunkSize
	if firstChunkEnd > len(ciphertext) {
		firstChunkEnd = len(ciphertext)
	}
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(ciphertext[:firstChunkEnd]),
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error on start: %s", resp.Error().Error())
	}
	sessionID := resp.Data["session_id"].(string)
	initialPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(initialPlain) > 0 {
		decryptedParts = append(decryptedParts, initialPlain)
	}

	// Send remaining ciphertext in chunks
	for i := firstChunkEnd; i < len(ciphertext); i += chunkSize {
		end := i + chunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		req = &logical.Request{
			Storage: storage, Operation: logical.UpdateOperation,
			Path:        "decrypt-stream/session/" + sessionID + "/update",
			ClientToken: "test-token",
			Data: map[string]interface{}{
				"data": base64.StdEncoding.EncodeToString(ciphertext[i:end]),
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("unexpected error on update: %s", resp.Error().Error())
		}
		chunkPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
		if len(chunkPlain) > 0 {
			decryptedParts = append(decryptedParts, chunkPlain)
		}
	}

	// Finalize
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path:        "decrypt-stream/session/" + sessionID + "/finalize",
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
		t.Fatal("expected done=true")
	}
	finalPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(finalPlain) > 0 {
		decryptedParts = append(decryptedParts, finalPlain)
	}

	// Concatenate all decrypted parts
	var decrypted bytes.Buffer
	for _, part := range decryptedParts {
		decrypted.Write(part)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("decrypted data does not match original: got %d bytes, expected %d bytes", decrypted.Len(), len(plaintext))
	}
}

func TestGPG_DecryptStreamFromStreamEncrypt(t *testing.T) {
	// Encrypt with streaming, decrypt with streaming — full round trip.
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

	plaintext := []byte(strings.Repeat("Full streaming round trip! ", 150))

	// Stream encrypt
	ciphertext := streamEncryptWithPlugin(t, b, storage, "test", plaintext, 1000)

	// Stream decrypt - feed all ciphertext at start
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(ciphertext),
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	var decryptedParts [][]byte
	initialPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(initialPlain) > 0 {
		decryptedParts = append(decryptedParts, initialPlain)
	}

	// Finalize immediately (all data was sent in start)
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path:        "decrypt-stream/session/" + sessionID + "/finalize",
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
	finalPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(finalPlain) > 0 {
		decryptedParts = append(decryptedParts, finalPlain)
	}

	var decrypted bytes.Buffer
	for _, part := range decryptedParts {
		decrypted.Write(part)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("decrypted data does not match original: got %d bytes, expected %d bytes", decrypted.Len(), len(plaintext))
	}
}

func TestGPG_DecryptStreamWithSigner(t *testing.T) {
	b := Backend()
	b.streamSessions = newSessionStore()
	storage := &logical.InmemStorage{}

	// Create recipient and signer keys
	for _, key := range []struct{ name, email string }{
		{"recipient", "recipient@example.com"},
		{"signer", "signer@example.com"},
	} {
		req := &logical.Request{
			Storage: storage, Operation: logical.UpdateOperation,
			Path: "keys/" + key.name, ClientToken: "test-token",
			Data: map[string]interface{}{"real_name": key.name, "email": key.email},
		}
		_, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
	}

	plaintext := []byte("Signed and encrypted data for streaming decrypt")

	// Encrypt with signer using non-streaming endpoint
	ciphertext := encryptWithPlugin(t, b, storage, "recipient", plaintext, "signer")

	// Stream decrypt with signer verification via URL path
	req := &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/recipient/sign/signer/start", ClientToken: "test-token",
		Data: map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(ciphertext),
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := resp.Data["session_id"].(string)

	var decryptedParts [][]byte
	initialPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(initialPlain) > 0 {
		decryptedParts = append(decryptedParts, initialPlain)
	}

	// Finalize
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path:        "decrypt-stream/session/" + sessionID + "/finalize",
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
	finalPlain, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string))
	if len(finalPlain) > 0 {
		decryptedParts = append(decryptedParts, finalPlain)
	}

	var decrypted bytes.Buffer
	for _, part := range decryptedParts {
		decrypted.Write(part)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatal("decrypted data does not match original")
	}

	// Check signature_valid
	if valid, ok := resp.Data["signature_valid"].(bool); !ok || !valid {
		t.Fatal("expected signature_valid=true")
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, remaining: 10}

	// Write within limit
	n, err := lw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes written, got %d, err: %v", n, err)
	}

	// Write that exactly exhausts remaining
	n, err = lw.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes written, got %d, err: %v", n, err)
	}

	// Write past limit
	n, err = lw.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected error when exceeding limit")
	}
	if !lw.exceeded {
		t.Fatal("expected exceeded=true")
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes written past limit, got %d", n)
	}

	// Subsequent writes also fail
	n, err = lw.Write([]byte("more"))
	if err == nil || n != 0 {
		t.Fatal("expected continued failure after exceeded")
	}

	if buf.String() != "helloworld" {
		t.Fatalf("expected 'helloworld' in buffer, got '%s'", buf.String())
	}
}

func TestGPG_DecryptStreamErrors(t *testing.T) {
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

	// Missing initial data
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/test/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for missing initial data")
	}

	// Non-existent key
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/nokey/start", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString([]byte("junk"))},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent key")
	}

	// Non-existent session
	req = &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/session/fakeid/update", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString([]byte("data"))},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || !resp.IsError() {
		t.Fatal("expected error for non-existent session")
	}
}
