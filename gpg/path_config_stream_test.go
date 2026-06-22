// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// --- shared test helpers (used by the config and signature-binding tests) ---

func mustCreateKey(t *testing.T, b *backend, storage logical.Storage, name, email string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "keys/" + name, ClientToken: "test-token",
		Data: map[string]interface{}{"real_name": name, "email": email},
	})
	if err != nil {
		t.Fatalf("create key %q: %v", name, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("create key %q: %s", name, resp.Error())
	}
}

func writeStreamConfig(t *testing.T, b *backend, storage logical.Storage, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "config", ClientToken: "test-token", Data: data,
	})
}

func readStreamConfig(t *testing.T, b *backend, storage logical.Storage) map[string]interface{} {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.ReadOperation,
		Path: "config", ClientToken: "test-token",
	})
	if err != nil {
		t.Fatalf("config read: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("config read returned error: %v", resp)
	}
	return resp.Data
}

func concatBytes(parts [][]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}

// streamDecrypt drives a full decrypt-stream session (start -> updates ->
// finalize) and returns the assembled plaintext, the final response, and the
// first error encountered at any stage (nil on success). signerName may be "".
func streamDecrypt(t *testing.T, b *backend, storage logical.Storage, keyName, signerName string, ciphertext []byte, chunkSize int) ([]byte, *logical.Response, error) {
	t.Helper()
	ctx := context.Background()
	if chunkSize <= 0 {
		chunkSize = len(ciphertext)
	}

	startPath := "decrypt-stream/" + keyName + "/start"
	if signerName != "" {
		startPath = "decrypt-stream/" + keyName + "/sign/" + signerName + "/start"
	}

	first := chunkSize
	if first > len(ciphertext) {
		first = len(ciphertext)
	}

	var parts [][]byte
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: startPath, ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString(ciphertext[:first])},
	})
	if err != nil {
		return nil, resp, err
	}
	if resp.IsError() {
		return nil, resp, resp.Error()
	}
	sid := resp.Data["session_id"].(string)
	if d, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string)); len(d) > 0 {
		parts = append(parts, d)
	}

	for off := first; off < len(ciphertext); off += chunkSize {
		end := off + chunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Storage: storage, Operation: logical.UpdateOperation, Path: "decrypt-stream/" + keyName + "/update", ClientToken: "test-token",
			Data: map[string]interface{}{"session_id": sid, "data": base64.StdEncoding.EncodeToString(ciphertext[off:end])},
		})
		if err != nil {
			return concatBytes(parts), resp, err
		}
		if resp.IsError() {
			return concatBytes(parts), resp, resp.Error()
		}
		if d, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string)); len(d) > 0 {
			parts = append(parts, d)
		}
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: "decrypt-stream/" + keyName + "/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid},
	})
	if err != nil {
		return concatBytes(parts), resp, err
	}
	if resp.IsError() {
		return concatBytes(parts), resp, resp.Error()
	}
	if d, _ := base64.StdEncoding.DecodeString(resp.Data["data"].(string)); len(d) > 0 {
		parts = append(parts, d)
	}
	return concatBytes(parts), resp, nil
}

// --- config endpoint tests ---

func TestStreamConfig_ReadDefaults(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}

	cfg := readStreamConfig(t, b, storage)
	if got := cfg["max_stream_bytes"].(int64); got != int64(defaultMaxStreamBytes) {
		t.Errorf("max_stream_bytes default = %d, want %d", got, int64(defaultMaxStreamBytes))
	}
	if got := cfg["max_plaintext_size"].(int64); got != int64(defaultMaxPlaintextSize) {
		t.Errorf("max_plaintext_size default = %d, want %d", got, int64(defaultMaxPlaintextSize))
	}
	if got := cfg["max_chunk_size"].(int64); got != int64(defaultMaxChunkSize) {
		t.Errorf("max_chunk_size default = %d, want %d", got, int64(defaultMaxChunkSize))
	}
	if got := cfg["session_timeout_seconds"].(int64); got != 300 {
		t.Errorf("session_timeout_seconds default = %d, want 300", got)
	}
	if got := cfg["max_sessions"].(int); got != defaultMaxSessions {
		t.Errorf("max_sessions default = %d, want %d", got, defaultMaxSessions)
	}
	if got := cfg["max_sessions_per_client"].(int); got != defaultMaxSessionsPerClient {
		t.Errorf("max_sessions_per_client default = %d, want %d", got, defaultMaxSessionsPerClient)
	}
}

func TestStreamConfig_WriteMergeAndDelete(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}

	// Set only two fields; the rest must stay at defaults.
	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{
		"max_stream_bytes":   0, // unlimited
		"max_chunk_size":     1024,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := readStreamConfig(t, b, storage)
	if cfg["max_stream_bytes"].(int64) != 0 {
		t.Errorf("max_stream_bytes = %d, want 0 (unlimited)", cfg["max_stream_bytes"].(int64))
	}
	if cfg["max_chunk_size"].(int64) != 1024 {
		t.Errorf("max_chunk_size = %d, want 1024", cfg["max_chunk_size"].(int64))
	}
	if cfg["max_plaintext_size"].(int64) != int64(defaultMaxPlaintextSize) {
		t.Errorf("max_plaintext_size = %d, want default %d", cfg["max_plaintext_size"].(int64), int64(defaultMaxPlaintextSize))
	}

	// A second write merges: changing one field preserves the earlier ones.
	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{"max_plaintext_size": 0}); err != nil {
		t.Fatal(err)
	}
	cfg = readStreamConfig(t, b, storage)
	if cfg["max_chunk_size"].(int64) != 1024 {
		t.Errorf("after merge, max_chunk_size = %d, want 1024 preserved", cfg["max_chunk_size"].(int64))
	}
	if cfg["max_plaintext_size"].(int64) != 0 {
		t.Errorf("after merge, max_plaintext_size = %d, want 0", cfg["max_plaintext_size"].(int64))
	}

	// Delete restores all defaults.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.DeleteOperation, Path: "config", ClientToken: "test-token",
	}); err != nil {
		t.Fatal(err)
	}
	cfg = readStreamConfig(t, b, storage)
	if cfg["max_chunk_size"].(int64) != int64(defaultMaxChunkSize) {
		t.Errorf("after delete, max_chunk_size = %d, want default", cfg["max_chunk_size"].(int64))
	}
	if cfg["max_plaintext_size"].(int64) != int64(defaultMaxPlaintextSize) {
		t.Errorf("after delete, max_plaintext_size = %d, want default", cfg["max_plaintext_size"].(int64))
	}
}

func TestStreamConfig_Validation(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}

	cases := []struct {
		name  string
		field string
		value int
	}{
		{"negative byte cap", "max_stream_bytes", -1},
		{"zero chunk size", "max_chunk_size", 0},
		{"negative timeout", "session_timeout_seconds", -5},
		{"zero max sessions", "max_sessions", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := writeStreamConfig(t, b, storage, map[string]interface{}{tc.field: tc.value})
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatalf("expected validation error for %s=%d", tc.field, tc.value)
			}
		})
	}
}

func TestStreamConfig_ChunkCapEnforced(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "k", "k@example.com")

	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{"max_chunk_size": 8}); err != nil {
		t.Fatal(err)
	}

	start, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: "encrypt-stream/k/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	})
	if err != nil || start.IsError() {
		t.Fatalf("start: err=%v resp=%v", err, start)
	}
	sid := start.Data["session_id"].(string)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: "encrypt-stream/k/update", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid, "data": base64.StdEncoding.EncodeToString(make([]byte, 16))},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected chunk-size cap to reject a 16-byte chunk when max_chunk_size=8")
	}
}

func TestStreamConfig_StreamBytesCapEnforced(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "k", "k@example.com")

	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{"max_stream_bytes": 8}); err != nil {
		t.Fatal(err)
	}

	start, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: "encrypt-stream/k/start", ClientToken: "test-token",
		Data: map[string]interface{}{},
	})
	if err != nil || start.IsError() {
		t.Fatalf("start: err=%v resp=%v", err, start)
	}
	sid := start.Data["session_id"].(string)

	// 16 bytes is under the (default) chunk cap but over the 8-byte stream cap.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: "encrypt-stream/k/update", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid, "data": base64.StdEncoding.EncodeToString(make([]byte, 16))},
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected stream-bytes cap to reject 16 bytes when max_stream_bytes=8")
	}
}

func TestStreamConfig_PlaintextCapAndUnlimited(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "reckey", "rec@example.com")

	plaintext := bytes.Repeat([]byte("A"), 100)
	ciphertext := encryptWithPlugin(t, b, storage, "reckey", plaintext, "")

	// With a 10-byte plaintext ceiling, decrypting 100 bytes must fail.
	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{"max_plaintext_size": 10}); err != nil {
		t.Fatal(err)
	}
	_, _, capErr := streamDecrypt(t, b, storage, "reckey", "", ciphertext, len(ciphertext))
	if capErr == nil {
		t.Fatal("expected plaintext cap to be enforced (max_plaintext_size=10, plaintext=100)")
	}

	// With the ceiling disabled (0 = unlimited), the same data round-trips.
	if _, err := writeStreamConfig(t, b, storage, map[string]interface{}{"max_plaintext_size": 0}); err != nil {
		t.Fatal(err)
	}
	got, _, err := streamDecrypt(t, b, storage, "reckey", "", ciphertext, len(ciphertext))
	if err != nil {
		t.Fatalf("unlimited decrypt failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("unlimited decrypt did not recover the original plaintext")
	}
}
