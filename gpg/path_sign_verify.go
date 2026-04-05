package gpg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},
			"urlalgorithm": {
				Type:        framework.TypeString,
				Description: "Hash algorithm to use (POST URL parameter)",
			},
			"algorithm": {
				Type:    framework.TypeString,
				Default: "sha2-256",
				Description: `Hash algorithm to use (POST body parameter). Valid values are:

* sha2-224
* sha2-256
* sha2-384
* sha2-512

Defaults to "sha2-256".`,
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format to use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignWrite,
			},
		},
		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func pathVerify(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data to verify",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The signature",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the signature use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVerifyWrite,
			},
		},
		HelpSynopsis:    pathVerifyHelpSyn,
		HelpDescription: pathVerifyHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

	config := packet.Config{}

	algorithm := data.Get("urlalgorithm").(string)
	if algorithm == "" {
		algorithm = data.Get("algorithm").(string)
	}
	switch algorithm {
	case "sha2-224":
		config.DefaultHash = crypto.SHA224
	case "sha2-256":
		config.DefaultHash = crypto.SHA256
	case "sha2-384":
		config.DefaultHash = crypto.SHA384
	case "sha2-512":
		config.DefaultHash = crypto.SHA512
	default:
		return logical.ErrorResponse("unsupported algorithm; must be \"sha2-224\", \"sha2-256\", \"sha2-384\", or \"sha2-512\""), nil
	}

	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse("unsupported encoding format; must be \"base64\" or \"ascii-armor\""), nil
	}

	entry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	if !entry.HasPrivateKey {
		return logical.ErrorResponse("signing requires a key with private key material"), logical.ErrInvalidRequest
	}
	entity, err := b.entity(entry)
	if err != nil {
		return nil, err
	}

	message := bytes.NewReader(input)

	var outputSignature bytes.Buffer
	switch format {
	case "ascii-armor":
		err = openpgp.ArmoredDetachSign(&outputSignature, entity, message, &config)
		if err != nil {
			return nil, err
		}
	case "base64":
		var rawSig bytes.Buffer
		err = openpgp.DetachSign(&rawSig, entity, message, &config)
		if err != nil {
			return nil, err
		}
		encoder := base64.NewEncoder(base64.StdEncoding, &outputSignature)
		if _, err = encoder.Write(rawSig.Bytes()); err != nil {
			return nil, err
		}
		if err = encoder.Close(); err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": outputSignature.String(),
		},
	}, nil
}

func (b *backend) pathVerifyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

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

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	signature := strings.NewReader(data.Get("signature").(string))
	message := bytes.NewReader(input)
	switch format {
	case "base64":
		decoder := base64.NewDecoder(base64.StdEncoding, signature)
		_, err = openpgp.CheckDetachedSignature(keyring, message, decoder, nil)
	case "ascii-armor":
		_, err = openpgp.CheckArmoredDetachedSignature(keyring, message, signature, nil)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"valid": err == nil,
		},
	}

	return resp, nil
}

const pathSignHelpSyn = "Generate a signature for input data using the named GPG key"
const pathSignHelpDesc = "Generates a signature of the input data using the named GPG key."
const pathVerifyHelpSyn = "Verify a signature for input data created using the named GPG key"
const pathVerifyHelpDesc = "Verifies a signature of the input data using the named GPG key."
