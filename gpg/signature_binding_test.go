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

// singleShotDecrypt drives the non-streaming /decrypt endpoint.
func singleShotDecrypt(t *testing.T, b *backend, storage logical.Storage, keyName, signerName string, ciphertext []byte) (*logical.Response, error) {
	t.Helper()
	path := "decrypt/" + keyName
	if signerName != "" {
		path = "decrypt/" + keyName + "/sign/" + signerName
	}
	return b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation, Path: path, ClientToken: "test-token",
		Data: map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
			"format":     "base64",
		},
	})
}

// TestDecrypt_SignerBinding_SingleShot proves the single-shot decrypt verdict is
// bound to the requested signer: a message signed by the recipient's own key
// (which is also in the keyring) must NOT satisfy a request to verify a
// different signer.
func TestDecrypt_SignerBinding_SingleShot(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "reckey", "rec@example.com")
	mustCreateKey(t, b, storage, "otherkey", "other@example.com")

	plaintext := []byte("bind the verdict to the requested signer")

	// Signed by the recipient itself, but we ask to verify "otherkey".
	ctSelfSigned := encryptWithPlugin(t, b, storage, "reckey", plaintext, "reckey")
	resp, err := singleShotDecrypt(t, b, storage, "reckey", "otherkey", ctSelfSigned)
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected signature verification to FAIL: message was signed by reckey, not the requested otherkey")
	}

	// Positive control: signed by otherkey, verifying otherkey -> succeeds.
	ctProperlySigned := encryptWithPlugin(t, b, storage, "reckey", plaintext, "otherkey")
	resp, err = singleShotDecrypt(t, b, storage, "reckey", "otherkey", ctProperlySigned)
	if err != nil {
		t.Fatalf("unexpected error on valid signer: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("expected success for correctly-signed message, got: %s", resp.Error())
	}
	got, _ := base64.StdEncoding.DecodeString(resp.Data["plaintext"].(string))
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted plaintext mismatch on valid signer")
	}
}

// TestDecrypt_SignerBinding_Streaming is the streaming counterpart: the finalize
// verdict (signature_valid) must reflect the requested signer.
func TestDecrypt_SignerBinding_Streaming(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "reckey", "rec@example.com")
	mustCreateKey(t, b, storage, "otherkey", "other@example.com")

	plaintext := []byte("streaming verdict must be bound to the signer")

	// Signed by recipient, verifying otherkey -> signature_valid must be false.
	ctSelfSigned := encryptWithPlugin(t, b, storage, "reckey", plaintext, "reckey")
	got, finalResp, err := streamDecrypt(t, b, storage, "reckey", "otherkey", ctSelfSigned, len(ctSelfSigned))
	if err != nil {
		t.Fatalf("stream decrypt errored unexpectedly: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("stream decrypt did not recover plaintext")
	}
	if valid, ok := finalResp.Data["signature_valid"].(bool); !ok || valid {
		t.Fatalf("expected signature_valid=false for wrong signer, got %v (ok=%v)", finalResp.Data["signature_valid"], ok)
	}
	if final, ok := finalResp.Data["signature_final"].(bool); !ok || !final {
		t.Fatalf("expected signature_final=true at finalize, got %v", finalResp.Data["signature_final"])
	}

	// Positive control: signed by otherkey, verifying otherkey -> valid.
	ctProperlySigned := encryptWithPlugin(t, b, storage, "reckey", plaintext, "otherkey")
	_, finalResp, err = streamDecrypt(t, b, storage, "reckey", "otherkey", ctProperlySigned, len(ctProperlySigned))
	if err != nil {
		t.Fatalf("stream decrypt (valid signer) errored: %v", err)
	}
	if valid, ok := finalResp.Data["signature_valid"].(bool); !ok || !valid {
		t.Fatalf("expected signature_valid=true for correct signer, got %v", finalResp.Data["signature_valid"])
	}
}

// TestDecryptStream_SignatureFieldsPresent verifies the unified verdict fields
// appear on every stage with the right terminal-gate semantics.
func TestDecryptStream_SignatureFieldsPresent(t *testing.T) {
	b := Backend()
	storage := &logical.InmemStorage{}
	mustCreateKey(t, b, storage, "reckey", "rec@example.com")
	mustCreateKey(t, b, storage, "signer", "signer@example.com")

	plaintext := []byte("verdict field presence across stages")
	ciphertext := encryptWithPlugin(t, b, storage, "reckey", plaintext, "signer")

	// Start: both fields present and false (verdict not yet known).
	startResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/reckey/sign/signer/start", ClientToken: "test-token",
		Data: map[string]interface{}{"data": base64.StdEncoding.EncodeToString(ciphertext)},
	})
	if err != nil || startResp.IsError() {
		t.Fatalf("start: err=%v resp=%v", err, startResp)
	}
	if v, ok := startResp.Data["signature_valid"].(bool); !ok || v {
		t.Errorf("start signature_valid = %v (ok=%v), want false", startResp.Data["signature_valid"], ok)
	}
	if v, ok := startResp.Data["signature_final"].(bool); !ok || v {
		t.Errorf("start signature_final = %v (ok=%v), want false", startResp.Data["signature_final"], ok)
	}
	sid := startResp.Data["session_id"].(string)

	// Finalize: signature_final=true, signature_valid=true.
	finResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage: storage, Operation: logical.UpdateOperation,
		Path: "decrypt-stream/reckey/finalize", ClientToken: "test-token",
		Data: map[string]interface{}{"session_id": sid},
	})
	if err != nil || finResp.IsError() {
		t.Fatalf("finalize: err=%v resp=%v", err, finResp)
	}
	if v, ok := finResp.Data["signature_final"].(bool); !ok || !v {
		t.Errorf("finalize signature_final = %v, want true", finResp.Data["signature_final"])
	}
	if v, ok := finResp.Data["signature_valid"].(bool); !ok || !v {
		t.Errorf("finalize signature_valid = %v, want true", finResp.Data["signature_valid"])
	}
}
