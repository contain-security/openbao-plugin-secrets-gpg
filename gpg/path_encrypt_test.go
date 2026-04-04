package gpg

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_Encrypt(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a key for encryption
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Test Key",
			"email":     "test@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("encrypt base64 format", func(t *testing.T) {
		plaintext := base64.StdEncoding.EncodeToString([]byte("hello world"))
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "encrypt/test",
			Data: map[string]interface{}{
				"plaintext": plaintext,
				"format":    "base64",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("unexpected error: %#v", *resp)
		}

		ciphertext, ok := resp.Data["ciphertext"].(string)
		if !ok || ciphertext == "" {
			t.Fatal("expected non-empty ciphertext in response")
		}

		// Verify it's valid base64
		_, err = base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			t.Fatalf("ciphertext is not valid base64: %s", err)
		}
	})

	t.Run("encrypt ascii-armor format", func(t *testing.T) {
		plaintext := base64.StdEncoding.EncodeToString([]byte("hello world"))
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "encrypt/test",
			Data: map[string]interface{}{
				"plaintext": plaintext,
				"format":    "ascii-armor",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("unexpected error: %#v", *resp)
		}

		ciphertext := resp.Data["ciphertext"].(string)
		if !strings.HasPrefix(ciphertext, "-----BEGIN PGP MESSAGE-----") {
			t.Fatalf("expected ASCII-armored PGP message, got: %s", ciphertext[:50])
		}
	})
}

func TestGPG_EncryptDecryptRoundTrip(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a key
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/recipient",
		Data: map[string]interface{}{
			"real_name": "Recipient",
			"email":     "recipient@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	originalPlaintext := "secret message for round-trip test"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(originalPlaintext))

	for _, format := range []string{"base64", "ascii-armor"} {
		t.Run("round-trip "+format, func(t *testing.T) {
			// Encrypt
			encResp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "encrypt/recipient",
				Data: map[string]interface{}{
					"plaintext": plaintextB64,
					"format":    format,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if encResp.IsError() {
				t.Fatalf("encrypt error: %#v", *encResp)
			}

			ciphertext := encResp.Data["ciphertext"].(string)

			// Decrypt
			decResp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "decrypt/recipient",
				Data: map[string]interface{}{
					"ciphertext": ciphertext,
					"format":     format,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if decResp.IsError() {
				t.Fatalf("decrypt error: %#v", *decResp)
			}

			recovered := decResp.Data["plaintext"].(string)
			if recovered != plaintextB64 {
				t.Fatalf("expected %s, got %s", plaintextB64, recovered)
			}
		})
	}
}

func TestGPG_EncryptDecryptWithSigning(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate recipient key
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/recipient",
		Data: map[string]interface{}{
			"real_name": "Recipient",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Generate signer key
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/signer",
		Data: map[string]interface{}{
			"real_name": "Signer",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	originalPlaintext := "signed and encrypted message"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(originalPlaintext))

	// Encrypt with signing via URL path
	encResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "encrypt/recipient/sign/signer",
		Data: map[string]interface{}{
			"plaintext": plaintextB64,
			"format":    "ascii-armor",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if encResp.IsError() {
		t.Fatalf("encrypt error: %#v", *encResp)
	}

	ciphertext := encResp.Data["ciphertext"].(string)

	// Decrypt with signer verification via URL path
	decResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decrypt/recipient/sign/signer",
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
			"format":     "ascii-armor",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decResp.IsError() {
		t.Fatalf("decrypt error: %#v", *decResp)
	}

	recovered := decResp.Data["plaintext"].(string)
	if recovered != plaintextB64 {
		t.Fatalf("expected %s, got %s", plaintextB64, recovered)
	}

	// Decrypt with WRONG signer should fail
	decResp, err = b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decrypt/recipient/sign/recipient",
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
			"format":     "ascii-armor",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decResp.IsError() {
		t.Fatal("expected error when verifying with wrong signer key")
	}
}

func TestGPG_EncryptError(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	// Generate a key
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	encryptMustFail := func(keyName string, data map[string]interface{}) {
		t.Helper()
		resp, _ := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "encrypt/" + keyName,
			Data:      data,
		})
		if resp == nil || !resp.IsError() {
			t.Fatalf("expected error for key=%s data=%v", keyName, data)
		}
	}

	// Key does not exist
	encryptMustFail("nonexistent", map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})

	// Invalid plaintext (not base64)
	encryptMustFail("test", map[string]interface{}{
		"plaintext": "not valid base64!!!",
	})

	// Invalid format
	encryptMustFail("test", map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
		"format":    "invalid",
	})

	// Signer key does not exist — use the /sign/ URL path
	resp, _ := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "encrypt/test/sign/nonexistent",
		Data: map[string]interface{}{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
		},
	})
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for nonexistent signer key via URL path")
	}
}
