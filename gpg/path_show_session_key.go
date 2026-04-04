package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathShowSessionKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "show-session-key/" + framework.GenericNameRegex("name"),
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
				Callback: b.pathShowSessionKeyWrite,
			},
		},
		HelpSynopsis:    pathDecryptSessionKeyHelpSyn,
		HelpDescription: pathDecryptSessionKeyHelpDesc,
	}
}

func pathShowSessionKeyWithSigner(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "show-session-key/" + framework.GenericNameRegex("name") + "/sign/" + framework.GenericNameRegex("signer_name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
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
				Callback: b.pathShowSessionKeyWrite,
			},
		},
		HelpSynopsis:    pathDecryptSessionKeyHelpSyn,
		HelpDescription: pathDecryptSessionKeyHelpDesc,
	}
}

func (b *backend) pathShowSessionKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"base64\" or \"ascii-armor\"", format)), nil
	}

	keyEntry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	signerKeyName := resolveSignerKeyName(data)
	if signerKeyName != "" {
		signerEntry, err := b.key(ctx, req.Storage, signerKeyName)
		if err != nil {
			return nil, err
		}
		if signerEntry == nil {
			return logical.ErrorResponse("signer key not found"), logical.ErrInvalidRequest
		}
		signerEntity, err := b.entity(signerEntry)
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
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		ciphertextDecoder = block.Body
	}

	var p packet.Packet
	var sessionKey string
	for {
		p, err = packet.Read(ciphertextDecoder)
		if err == io.EOF {
			return logical.ErrorResponse("Unable to decrypt session key"), nil
		}
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			encryptedKey := *p
			keys := keyring.KeysById(encryptedKey.KeyId)
			for _, key := range keys {
				encryptedKey.Decrypt(key.PrivateKey, nil)

				if len(encryptedKey.Key) > 0 {
					sessionKey = fmt.Sprintf("%d:%s", encryptedKey.CipherFunc, strings.ToUpper(hex.EncodeToString(encryptedKey.Key)))
					return &logical.Response{
						Data: map[string]interface{}{
							"session_key": sessionKey,
						},
					}, nil
				}
			}
		}
	}
}

const pathDecryptSessionKeyHelpSyn = "Decrypt a session key of a message using a named GPG key"

const pathDecryptSessionKeyHelpDesc = `
This path uses the named GPG key from the request path to decrypt the session key of a message. 
`
