// Copyright (c) 2017-2019 Thomas Gerbet
// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_CreateNotGeneratedKeyWithoutKeyError(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Key should not be generated but was created without passing an existing key")
	}
}

func TestGPG_CreateErrorGeneratedKeyWithInvalidKey(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
			"key":      "Not properly ascii-armored key",
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Key was not a ASCII-armored key but has been created")
	}
}

func TestGPG_CreateErrorGeneratedDuplicateKey(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if response.IsError() {
		t.Fatal("Key was not created")
	}

	response, err = b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Duplicate key has been created")
	}
}

func TestGPG_ImportPublicKeyOnly(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	// Public-only key import should succeed
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/pubonly",
		Data: map[string]interface{}{
			"generate": false,
			"key":      gpgPublicKey,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response != nil && response.IsError() {
		t.Fatalf("public key import should succeed: %s", response.Error().Error())
	}

	// Read should show has_private_key=false
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "keys/pubonly",
	}
	response, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Data["has_private_key"].(bool) {
		t.Fatal("expected has_private_key=false for public-only import")
	}

	// Sign should fail with public-only key
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/pubonly",
		Data: map[string]interface{}{
			"input": "dGVzdA==",
		},
	}
	response, _ = b.HandleRequest(context.Background(), req)
	if response == nil || !response.IsError() {
		t.Fatal("sign with public-only key should fail")
	}

	// Decrypt should fail with public-only key
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decrypt/pubonly",
		Data: map[string]interface{}{
			"ciphertext": "dGVzdA==",
			"format":     "base64",
		},
	}
	response, _ = b.HandleRequest(context.Background(), req)
	if response == nil || !response.IsError() {
		t.Fatal("decrypt with public-only key should fail")
	}

	// Verify should succeed with public-only key:
	// 1. Create a key with private material to sign with
	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/fullkey",
		Data: map[string]interface{}{
			"real_name": "Full Key",
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Import the full key's public key as a separate public-only key
	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "keys/fullkey",
	})
	if err != nil {
		t.Fatal(err)
	}
	pubKey := readResp.Data["public_key"].(string)

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/fullkey-pub",
		Data: map[string]interface{}{
			"generate": false,
			"key":      pubKey,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Sign with the full key
	signResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/fullkey",
		Data: map[string]interface{}{
			"input": "dGVzdA==",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if signResp.IsError() {
		t.Fatalf("sign error: %s", signResp.Error().Error())
	}
	sig := signResp.Data["signature"].(string)

	// 4. Verify with the public-only copy
	verifyResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/fullkey-pub",
		Data: map[string]interface{}{
			"input":     "dGVzdA==",
			"signature": sig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifyResp.IsError() {
		t.Fatalf("verify error: %s", verifyResp.Error().Error())
	}
	if !verifyResp.Data["valid"].(bool) {
		t.Fatal("signature should be valid when verified with public-only key")
	}
}

func TestGPG_CreateErrorGeneratedKeyTooSmallKeyBits(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"key_bits": 1024,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Key creation has been accepted but should have denied due to too small key size")
	}
}

func TestGPG_CreateErrorGeneratedKeyTooLargeKeyBits(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"key_bits": 8192,
		},
	}
	response, err := b.HandleRequest(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if !response.IsError() {
		t.Fatal("Key creation has been accepted but should have denied due to too large key size")
	}
}

const gpgPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFmZfJIBCACx2NgAf4rLLx2QKo444ATs3ewJICdy/cYhETxcn5wewdrxQayJ
XWtHZmLujIi9n+/ELg1ruqQOu+u+l21JZKa2QLaaSfqsk6aYY+sppvp3x8V9LXyN
FdsT/mWmtCC5AxagNEFuiCWu/QjOR06+fdt9bIZOiA1qtx6nrsBEYJTKUspAp8wV
foAMnpsX2VoQybHEIkc4G0iKf80bLgdPmGfTHB50Q/tWvuHv8xuOBqmQhpHXBgRH
GlBzt6M6eaHVJYFI+V8kd5iJ+AvIUAnNH1m0Pm7seAqQyptmYwZKfS7rOd5ZxYva
z0ZRQWxuX7hEjc1Js1XqRQUiSobIyqRWuJ9ZABEBAAG0I1ZhdWx0IChDb21tZW50
KSA8dmF1bHRAZXhhbXBsZS5jb20+iQFOBBMBCgA4FiEE+7yad7tpbmeH7wtbL3tW
M7b0JScFAlmZfJICGwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AACgkQL3tWM7b0
JSc+ugf/RgOOcJb1TwqbOIqXEshvmJpS40Q8+ZZY4TagWvteU3yYFtHisEkWogt5
m8QLyDV7IOopEidPL8muithsmuoxNpAoLDdg6Z1fMSd7UZ85l8Pogyae9yqZdd/F
b3psKqCugIG2eTS0FWBB1Oysx5AGZgqgYn/YnpCXzat0rvCaZdHXbmiAOBKs/SNA
0kWb8NwNQZZ2TAS9UNe1kOTuadt8iUBjYr1viHNT4bLwYAXaB41VANO/EO4bLyHz
ve6wngRAn/OAKqQPfFsgAVnOYtkdrWLg+12231XcECrdk19yaSn09Ss0FbflmGwv
uEwMQkbZ6yzc8BrBw3lp2H1FlSroRbkBDQRZmXySAQgAsgxo11TBe7LxBvGbKha4
sdn5F8WeHnNLigbCMGXDve9XO2yIE/KyvM7RIfP3jxwMAQvZ+1+0S2iZodoyYhKE
RyFgE9NvHYiwDfkKXTQgV2EkLJN6iGukTIRcnWs1gAYJ9x1E3JUz8LOBTAPxZYLQ
HY07Mm1POuCMKvTSlkAnc0WfQ39kzMVT1T+m+jLAxsyt9JcTdtDQERzs9Po72EDT
lCGTL6p0LQgArLMSohXJyhJi3wOibGXH0BZUCvwOZJmg6BWGmcO7+lPVPQYUVqDk
4dtxQiluwq5WK8YVSCnL6CjkVtjmy5jtu6Tw7vyps0kXfkMrUegZdTLrXhRmC8XW
qwARAQABiQE2BBgBCgAgFiEE+7yad7tpbmeH7wtbL3tWM7b0JScFAlmZfJICGwwA
CgkQL3tWM7b0JSeiuAf/RVr6eW5h4TspiAwZlBhVOTlVKxHLVR6SLebZA6eK+rDH
usw+Qq4bXIi51+c1kN68Ep8mq3/vJJmBoy1R3VZve5kBl/vc2qBbqjR06RgLqMZY
Gp5RUCDTE6Xey7+woTBhQiQXFBsfdXG2pjaFSJPs4FCVEbpV1QGEQq349kWRXEA+
tX6O0Tg/Q8RIcya3wmIyv4yCRwEzNdmWlAs8H1SiIzd5Qdx84VXj9aXspij0lmiu
qKqjtePx5gnMoyVXnDqgwsbxPh6GdKGx+Rgt47o1bXm/o8PSpA5Qbb3xVKmAi34b
ZfOYAeX554UB1xwK6a/T3rHf3eZM4Oc64dsmbhRftQ==
=G71q
-----END PGP PUBLIC KEY BLOCK-----`
