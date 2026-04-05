// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathEncrypt(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
			"plaintext": {
				Type:        framework.TypeString,
				Description: "The base64-encoded plaintext to encrypt",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format for the ciphertext output. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptWrite,
			},
		},
		HelpSynopsis:    pathEncryptHelpSyn,
		HelpDescription: pathEncryptHelpDesc,
	}
}

func pathEncryptWithSigner(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("name") + "/sign/" + framework.GenericNameRegex("signer_name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
			"signer_name": {
				Type:        framework.TypeString,
				Description: "The GPG key to sign the message with (from URL path)",
			},
			"plaintext": {
				Type:        framework.TypeString,
				Description: "The base64-encoded plaintext to encrypt",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format for the ciphertext output. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptWrite,
			},
		},
		HelpSynopsis:    pathEncryptHelpSyn,
		HelpDescription: pathEncryptHelpDesc,
	}
}

func (b *backend) pathEncryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	plaintextB64 := data.Get("plaintext").(string)
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return logical.ErrorResponse("unable to decode plaintext: invalid base64 encoding"), logical.ErrInvalidRequest
	}
	if len(plaintext) > defaultMaxPlaintextSize {
		return logical.ErrorResponse("plaintext exceeds maximum size"), logical.ErrInvalidRequest
	}

	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse("unsupported encoding format; must be \"base64\" or \"ascii-armor\""), nil
	}

	// Load the recipient key
	keyEntry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	recipientEntity, err := b.entity(keyEntry)
	if err != nil {
		return nil, err
	}

	// Optionally load a signer key
	var signerEntity *openpgp.Entity
	signerKeyName := resolveSignerKeyName(data)
	if signerKeyName != "" {
		signerEntry, err := b.key(ctx, req.Storage, signerKeyName)
		if err != nil {
			return nil, err
		}
		if signerEntry == nil {
			return logical.ErrorResponse("signer key not found"), logical.ErrInvalidRequest
		}
		if !signerEntry.HasPrivateKey {
			return logical.ErrorResponse("signing requires a key with private key material"), logical.ErrInvalidRequest
		}
		signerEntity, err = b.entity(signerEntry)
		if err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	var out io.WriteCloser

	switch format {
	case "ascii-armor":
		out, err = armor.Encode(&buf, "PGP MESSAGE", nil)
		if err != nil {
			return nil, err
		}
	case "base64":
		out = &nopWriteCloser{Writer: &buf}
	}

	plainWriter, err := openpgp.Encrypt(out, []*openpgp.Entity{recipientEntity}, signerEntity, nil, &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA256,
	})
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(plainWriter, bytes.NewReader(plaintext)); err != nil {
		return nil, err
	}
	if err := plainWriter.Close(); err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}

	var ciphertext string
	switch format {
	case "ascii-armor":
		ciphertext = buf.String()
	case "base64":
		ciphertext = base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
		},
	}, nil
}

// nopWriteCloser wraps a Writer with a no-op Close method.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

const pathEncryptHelpSyn = "Encrypt plaintext using a named GPG key"

const pathEncryptHelpDesc = `
This path uses the named GPG key from the request path to encrypt a user
provided plaintext. The ciphertext is returned in the requested format.
`
