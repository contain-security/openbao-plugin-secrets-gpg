package gpg

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_Decrypt(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
			"key":      privateDecryptKey,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	decrypt := func(keyName, ciphertext, format, signerKeyName, expected string) {
		path := "decrypt/" + keyName
		if signerKeyName != "" {
			path = "decrypt/" + keyName + "/sign/" + signerKeyName
		}
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      path,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
			},
		}

		resp, err := b.HandleRequest(context.Background(), reqDecrypt)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("not expected error response: %#v", *resp)
		}

		if resp == nil {
			t.Fatalf("no name key found in response data %#v", resp)
		}
		plaintext, ok := resp.Data["plaintext"]
		if !ok {
			t.Fatalf("no name key found in response data %#v", resp.Data)
		}
		if plaintext != expected {
			t.Fatalf("expected plaintext %s, got: %s", expected, plaintext)
		}
	}

	expected := "QWxwYWNhcwo="
	decrypt("test", encryptedMessageASCIIArmored, "ascii-armor", "", expected)
	decrypt("test", encryptedMessageBase64Encoded, "base64", "", expected)
}

func TestGPG_DecryptError(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/testGenerated",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"generate": false,
			"key":      privateDecryptKey,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	decryptMustFail := func(keyName, ciphertext, format, signerKeyName string) {
		path := "decrypt/" + keyName
		if signerKeyName != "" {
			path = "decrypt/" + keyName + "/sign/" + signerKeyName
		}
		reqDecrypt := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      path,
			Data: map[string]interface{}{
				"ciphertext": ciphertext,
				"format":     format,
			},
		}

		resp, _ := b.HandleRequest(context.Background(), reqDecrypt)
		if !resp.IsError() {
			t.Fatalf(
				"expected to fail, keyname: %s, format: %s, cipertext: %s, signer: %s",
				keyName, format, ciphertext, signerKeyName)
		}
	}

	decryptMustFail("doNotExist", encryptedMessageASCIIArmored, "ascii-armor", "")
	decryptMustFail("test", encryptedMessageASCIIArmored, "invalidFormat", "")

	// Wrong key for the message
	decryptMustFail("testGenerated", encryptedMessageASCIIArmored, "ascii-armor", "")

	// Wrongly encoded
	decryptMustFail("test", "Not ASCII armored", "ascii-armor", "")
	decryptMustFail("test", "Not base64 encoded", "base64", "")

	// Signer key does not exist
	decryptMustFail("test", encryptedMessageASCIIArmored, "ascii-armor", "nonExistentSignerKey")

	// Message is not signed but signer is set via URL
	decryptMustFail("test", encryptedMessageASCIIArmored, "ascii-armor", "testGenerated")
}

//nolint:gosec
const privateDecryptKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
2YDbdwbm17gtImItk0iYTmX7FdFf
=Loke
-----END PGP PRIVATE KEY BLOCK-----`

const encryptedMessageASCIIArmored = `-----BEGIN PGP MESSAGE-----

hQEMA923ECy/uCBhAQf8DLagsnoLuM4AyKiTyvZ7uSQTkmOkwXwn1WWsxoKJkzdI
v2XJ7knQ3UR5nnhI8xVbAnZVZjx8wYaBPUvV2VqhA2sTn36mGlGw43ngDOFB1cKW
1VM9JY0xqxuHaIR3mvYFjb/iuoT2BM7SmCuIEJYgxKEM+/R1o9rkCenj2pOj4+XK
ryXv+iHQAar6Ic2G3g9T7Mu7Uw6+n1xBWr/XzPnJRJf4WB4m7sqd/Wm7NkHnvgde
P9kawh1lHYj32WdLUqZpQB3zQRguDHFfQA8vRVEG4Gyz/o7um5PFc4kDES0JYzNc
p6p64MAF+vMpSOsFU2TaixSmraidaWHVPYcao/w2UNJDAQ43l9lh064yz9bCaH41
UyEQpNH+l1EpqnIbu+iIQb3a02GwBB8lfEW7cFku8121H8XapkgKZDsmXD/7v0eW
e8iwFg==
=+yfj
-----END PGP MESSAGE-----`

const encryptedMessageBase64Encoded = `hQEMA923ECy/uCBhAQf/XPUNCcaIUyTDDQ+rII/sj24VtnBUdXDNntOtBX4pxIHzMWr6oCWGgZZV
WTRzRP4nEclUUhWKHDlEd7/1bG/1z3Px3JWXdnSCHYl3AqdFkS4bW26wpO+gcCTbiixo+JE93QoG
84rb5k6gdNGsVEpioDFK1FLGL9pPvyR+kp4JRg8qD1FpDsvow+zhJqgAak87s4Ly/YnYiVYbGjPl
u0pqEkvJwHnIyKThFW5N6OCYjB2pFpVLER7x6RGjuX6tRRYZayzT4sVKGj0Efp6T32EEVPURiJSn
elpIPEd8+8i/7X0Co6iNFEyucgxhaxN+ujqSxx+6ZIFV4UKC0LFgR2iF99JDAQ6ofxvUtoxMGKON
WVtrVMjN8Db3KXQ5rt/tyKbTVGXQot6ocSZ2Ae+rnSTiq0boGrWDnuYZHawc16iJhbcP68ERgg==`

