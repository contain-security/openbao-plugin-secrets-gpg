// Copyright (c) 2017-2019 Thomas Gerbet
// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathDecrypt(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "The ciphertext to decrypt",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the ciphertext uses. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptWrite,
			},
		},
		HelpSynopsis:    pathDecryptHelpSyn,
		HelpDescription: pathDecryptHelpDesc,
	}
}

func pathDecryptWithSigner(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("name") + "/sign/" + framework.GenericNameRegex("signer_name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use for decryption",
			},
			"signer_name": {
				Type:        framework.TypeString,
				Description: "The GPG key to verify the signature against (from URL path)",
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "The ciphertext to decrypt",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the ciphertext uses. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptWrite,
			},
		},
		HelpSynopsis:    pathDecryptHelpSyn,
		HelpDescription: pathDecryptHelpDesc,
	}
}

func (b *backend) pathDecryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse("unsupported encoding format; must be \"base64\" or \"ascii-armor\""), nil
	}

	keyEntry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	if !keyEntry.HasPrivateKey {
		return logical.ErrorResponse("decryption requires a key with private key material"), logical.ErrInvalidRequest
	}

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	signerKeyName := resolveSignerKeyName(data)
	var signerEntity *openpgp.Entity
	if signerKeyName != "" {
		signerEntry, err := b.key(ctx, req.Storage, signerKeyName)
		if err != nil {
			return nil, err
		}
		if signerEntry == nil {
			return logical.ErrorResponse("signer key not found"), logical.ErrInvalidRequest
		}
		signerEntity, err = b.entity(signerEntry)
		if err != nil {
			return nil, err
		}
		keyring = append(keyring, signerEntity)
	}

	ciphertextEncoded := strings.NewReader(data.Get("ciphertext").(string))
	var ciphertextDecoder io.Reader
	switch format {
	case "base64":
		ciphertextDecoder = base64.NewDecoder(base64.StdEncoding, ciphertextEncoded)
	case "ascii-armor":
		block, err := armor.Decode(ciphertextEncoded)
		if err != nil {
			return logical.ErrorResponse("unable to decode armored ciphertext"), logical.ErrInvalidRequest
		}
		ciphertextDecoder = block.Body
	}

	md, err := openpgp.ReadMessage(ciphertextDecoder, keyring, nil, nil)
	if err != nil {
		return logical.ErrorResponse("decryption failed"), logical.ErrInvalidRequest
	}

	var plaintext bytes.Buffer
	w := base64.NewEncoder(base64.StdEncoding, &plaintext)
	n, err := io.Copy(w, io.LimitReader(md.UnverifiedBody, defaultMaxPlaintextSize+1))
	if err != nil {
		return logical.ErrorResponse("decryption failed"), logical.ErrInvalidRequest
	}
	if n > defaultMaxPlaintextSize {
		return logical.ErrorResponse("decrypted plaintext exceeds maximum size"), logical.ErrInvalidRequest
	}
	if err = w.Close(); err != nil {
		return logical.ErrorResponse("decryption failed"), logical.ErrInvalidRequest
	}

	// Bind the signature verdict to the requested signer: a valid signature from
	// any other key in the keyring (including the recipient's own key) does NOT
	// satisfy the request.
	if signerKeyName != "" {
		sigOK := md.IsSigned && md.SignedBy != nil && md.SignatureError == nil &&
			md.SignedBy.Entity != nil &&
			md.SignedBy.Entity.PrimaryKey.KeyId == signerEntity.PrimaryKey.KeyId
		if !sigOK {
			return logical.ErrorResponse("signature verification failed"), nil
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": plaintext.String(),
		},
	}, nil
}

const pathDecryptHelpSyn = "Decrypt a ciphertext value using a named GPG key"

const pathDecryptHelpDesc = `
This path uses the named GPG key from the request path to decrypt a user
provided ciphertext. The plaintext is returned base64 encoded.
`
