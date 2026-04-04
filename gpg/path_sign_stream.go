package gpg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathSignStreamStart(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign-stream/" + framework.GenericNameRegex("name") + "/start" + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use for signing",
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
				Description: `Encoding format for the signature output. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignStreamStartWrite,
			},
		},
		HelpSynopsis:    pathSignStreamStartHelpSyn,
		HelpDescription: pathSignStreamStartHelpDesc,
	}
}

func pathSignStreamUpdate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign-stream/" + framework.GenericNameRegex("name") + "/update",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use for signing",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "Base64-encoded data chunk",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignStreamUpdateWrite,
			},
		},
		HelpSynopsis:    pathSignStreamUpdateHelpSyn,
		HelpDescription: pathSignStreamUpdateHelpDesc,
	}
}

func pathSignStreamFinalize(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign-stream/" + framework.GenericNameRegex("name") + "/finalize",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use for signing",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignStreamFinalizeWrite,
			},
		},
		HelpSynopsis:    pathSignStreamFinalizeHelpSyn,
		HelpDescription: pathSignStreamFinalizeHelpDesc,
	}
}

func (b *backend) pathSignStreamStartWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Resolve hash algorithm
	algorithm := data.Get("urlalgorithm").(string)
	if algorithm == "" {
		algorithm = data.Get("algorithm").(string)
	}

	config := &packet.Config{}
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

	// Load the signing key
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

	signingKey, ok := entity.SigningKeyById(config.Now(), config.SigningKey())
	if !ok {
		return logical.ErrorResponse("no valid signing keys"), logical.ErrInvalidRequest
	}
	if signingKey.PrivateKey == nil {
		return logical.ErrorResponse("signing key doesn't have a private key"), logical.ErrInvalidRequest
	}
	if signingKey.PrivateKey.Encrypted {
		return logical.ErrorResponse("signing key is encrypted"), logical.ErrInvalidRequest
	}

	sig := newDetachedSignaturePacket(signingKey.PublicKey, config)

	// PrepareSign returns a hash.Hash pre-seeded with salt (for v6 keys).
	// For SigTypeBinary, wrapHashForSignature is identity — no wrapping needed,
	// so we write data directly to h across update calls.
	h, err := sig.PrepareSign(config)
	if err != nil {
		return nil, err
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	sess := &streamSession{
		id:              sessionID,
		sessionType:     sessionTypeSign,
		keyName:         data.Get("name").(string),
		clientTokenHash: hashClientToken(req.ClientToken),
		createdAt:       now,
		lastAccess:      now,
		sign: &signSessionState{
			hash:       h,
			sig:        sig,
			signingKey: signingKey.PrivateKey,
			config:     config,
			format:     format,
		},
	}

	if err := b.streamSessions.create(sess); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"session_id": sessionID,
			"algorithm":  algorithm,
			"format":     format,
		},
	}, nil
}

func (b *backend) pathSignStreamUpdateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sessionID := data.Get("session_id").(string)
	sess, ok := b.streamSessions.get(sessionID)
	if !ok {
		return logical.ErrorResponse("session not found or expired"), logical.ErrInvalidRequest
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.done {
		return logical.ErrorResponse("session already finalized"), logical.ErrInvalidRequest
	}
	if sess.sessionType != sessionTypeSign {
		return logical.ErrorResponse("session is not a sign session"), logical.ErrInvalidRequest
	}
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}
	if len(input) > defaultMaxChunkSize {
		return logical.ErrorResponse(fmt.Sprintf("chunk exceeds maximum size of %d bytes", defaultMaxChunkSize)), logical.ErrInvalidRequest
	}

	n, err := sess.sign.hash.Write(input)
	if err != nil {
		return nil, err
	}
	sess.sign.bytesReceived += int64(n)
	sess.lastAccess = time.Now()
	sess.sequence++

	return &logical.Response{
		Data: map[string]interface{}{
			"session_id":          sessionID,
			"bytes_received":      n,
			"total_bytes_received": sess.sign.bytesReceived,
		},
	}, nil
}

func (b *backend) pathSignStreamFinalizeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sessionID := data.Get("session_id").(string)
	sess, ok := b.streamSessions.get(sessionID)
	if !ok {
		return logical.ErrorResponse("session not found or expired"), logical.ErrInvalidRequest
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.done {
		return logical.ErrorResponse("session already finalized"), logical.ErrInvalidRequest
	}
	if sess.sessionType != sessionTypeSign {
		return logical.ErrorResponse("session is not a sign session"), logical.ErrInvalidRequest
	}
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	// Sign the accumulated hash
	err := sess.sign.sig.Sign(sess.sign.hash, sess.sign.signingKey, sess.sign.config)
	if err != nil {
		return nil, err
	}

	// Serialize the signature
	var sigBuf bytes.Buffer
	err = sess.sign.sig.Serialize(&sigBuf)
	if err != nil {
		return nil, err
	}

	// Format the output
	var outputSignature string
	switch sess.sign.format {
	case "ascii-armor":
		var armorBuf bytes.Buffer
		w, err := armor.Encode(&armorBuf, "PGP SIGNATURE", nil)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(sigBuf.Bytes()); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		outputSignature = armorBuf.String()
	case "base64":
		outputSignature = base64.StdEncoding.EncodeToString(sigBuf.Bytes())
	}

	sess.done = true

	// Clean up the session
	b.streamSessions.remove(sessionID)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": outputSignature,
		},
	}, nil
}

// newDetachedSignaturePacket replicates the unexported createSignaturePacket
// from go-crypto v1.4.1 (openpgp/write.go:559). It constructs a Signature
// packet configured for binary detached signing with the given key and config.
func newDetachedSignaturePacket(pub *packet.PublicKey, config *packet.Config) *packet.Signature {
	sigLifetimeSecs := config.SigLifetime()
	return &packet.Signature{
		Version:           pub.Version,
		SigType:           packet.SigTypeBinary,
		PubKeyAlgo:        pub.PubKeyAlgo,
		Hash:              config.Hash(),
		CreationTime:      config.Now(),
		IssuerKeyId:       &pub.KeyId,
		IssuerFingerprint: pub.Fingerprint,
		Notations:         config.Notations(),
		SigLifetimeSecs:   &sigLifetimeSecs,
	}
}

const pathSignStreamStartHelpSyn = "Start a streaming sign session for large data"
const pathSignStreamStartHelpDesc = `
Starts a streaming signing session for the named GPG key. Returns a session_id
that must be passed to subsequent update and finalize calls. Use this for
signing data that exceeds the single-request size limit.
`
const pathSignStreamUpdateHelpSyn = "Feed a data chunk to a streaming sign session"
const pathSignStreamUpdateHelpDesc = `
Sends a base64-encoded chunk of data to an active signing session. The data is
hashed incrementally; no chunk data is retained in memory after processing.
Chunks must be sent sequentially (not in parallel).
`
const pathSignStreamFinalizeHelpSyn = "Finalize a streaming sign session and retrieve the signature"
const pathSignStreamFinalizeHelpDesc = `
Finalizes the streaming signing session, producing a standard PGP detached
signature over all data sent via update calls. The signature is compatible
with gpg --verify. The session is destroyed after finalization.
`
