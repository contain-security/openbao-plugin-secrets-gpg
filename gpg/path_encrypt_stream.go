package gpg

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathEncryptStreamStart(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt-stream/" + framework.GenericNameRegex("name") + "/start",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptStreamStartWrite,
			},
		},
		HelpSynopsis:    pathEncryptStreamStartHelpSyn,
		HelpDescription: pathEncryptStreamStartHelpDesc,
	}
}

func pathEncryptStreamStartWithSigner(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt-stream/" + framework.GenericNameRegex("name") + "/sign/" + framework.GenericNameRegex("signer_name") + "/start",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
			"signer_name": {
				Type:        framework.TypeString,
				Description: "The GPG key to sign the message with (from URL path)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptStreamStartWrite,
			},
		},
		HelpSynopsis:    pathEncryptStreamStartHelpSyn,
		HelpDescription: pathEncryptStreamStartHelpDesc,
	}
}

func pathEncryptStreamUpdate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt-stream/" + framework.GenericNameRegex("name") + "/update",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded plaintext chunk",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptStreamUpdateWrite,
			},
		},
		HelpSynopsis:    pathEncryptStreamUpdateHelpSyn,
		HelpDescription: pathEncryptStreamUpdateHelpDesc,
	}
}

func pathEncryptStreamFinalize(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt-stream/" + framework.GenericNameRegex("name") + "/finalize",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to encrypt to",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptStreamFinalizeWrite,
			},
		},
		HelpSynopsis:    pathEncryptStreamFinalizeHelpSyn,
		HelpDescription: pathEncryptStreamFinalizeHelpDesc,
	}
}

func (b *backend) pathEncryptStreamStartWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	encState := &encryptSessionState{
		goroutineDone: make(chan struct{}),
	}

	// The lockedWriter allows the goroutine to write encrypted output
	// to the buffer without blocking (bytes.Buffer never blocks on Write).
	lw := &lockedWriter{
		mu:  &encState.outputMu,
		buf: &encState.outputBuf,
	}

	// openpgp.Encrypt writes the PKESK header immediately, then returns
	// the plainWriter for streaming plaintext.
	plainWriter, err := openpgp.Encrypt(lw, []*openpgp.Entity{recipientEntity}, signerEntity, nil, &packet.Config{
		DefaultCipher: packet.CipherAES256,
	})
	if err != nil {
		return nil, err
	}
	encState.plainWriter = plainWriter

	// No goroutine needed for encrypt — openpgp.Encrypt's WriteCloser
	// does the encryption synchronously when we Write to it. The output
	// goes to our lockedWriter -> outputBuf. Close triggers MDC finalization.
	// We just mark the goroutineDone channel as immediately ready since
	// there's no background goroutine.
	close(encState.goroutineDone)

	now := time.Now()
	sess := &streamSession{
		id:              sessionID,
		sessionType:     sessionTypeEncrypt,
		keyName:         data.Get("name").(string),
		clientTokenHash: hashClientToken(req.ClientToken),
		createdAt:       now,
		lastAccess:      now,
		encrypt:         encState,
	}

	if err := b.streamSessions.create(sess); err != nil {
		// Clean up
		plainWriter.Close()
		return logical.ErrorResponse(err.Error()), nil
	}

	// Drain the initial output (PKESK header)
	encState.outputMu.Lock()
	initialData := make([]byte, encState.outputBuf.Len())
	copy(initialData, encState.outputBuf.Bytes())
	encState.outputBuf.Reset()
	encState.outputMu.Unlock()

	return &logical.Response{
		Data: map[string]interface{}{
			"session_id": sessionID,
			"data":       base64.StdEncoding.EncodeToString(initialData),
			"sequence":   int64(0),
			"done":       false,
		},
	}, nil
}

func (b *backend) pathEncryptStreamUpdateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if sess.sessionType != sessionTypeEncrypt {
		return logical.ErrorResponse("session is not an encrypt session"), logical.ErrInvalidRequest
	}
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	inputB64 := data.Get("data").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode data as base64: %s", err)), logical.ErrInvalidRequest
	}
	if len(input) > defaultMaxChunkSize {
		return logical.ErrorResponse(fmt.Sprintf("chunk exceeds maximum size of %d bytes", defaultMaxChunkSize)), logical.ErrInvalidRequest
	}

	// Write plaintext to the encrypt writer — this triggers encryption
	// and writes to the outputBuf via lockedWriter.
	if _, err := sess.encrypt.plainWriter.Write(input); err != nil {
		return nil, fmt.Errorf("encryption error: %w", err)
	}

	// Drain the encrypted output
	sess.encrypt.outputMu.Lock()
	encryptedData := make([]byte, sess.encrypt.outputBuf.Len())
	copy(encryptedData, sess.encrypt.outputBuf.Bytes())
	sess.encrypt.outputBuf.Reset()
	sess.encrypt.outputMu.Unlock()

	sess.sequence++
	sess.lastAccess = time.Now()

	return &logical.Response{
		Data: map[string]interface{}{
			"session_id": sessionID,
			"data":       base64.StdEncoding.EncodeToString(encryptedData),
			"sequence":   sess.sequence,
			"done":       false,
		},
	}, nil
}

func (b *backend) pathEncryptStreamFinalizeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if sess.sessionType != sessionTypeEncrypt {
		return logical.ErrorResponse("session is not an encrypt session"), logical.ErrInvalidRequest
	}
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	// Close the plainWriter — triggers MDC computation and final encrypted bytes
	if err := sess.encrypt.plainWriter.Close(); err != nil {
		return nil, fmt.Errorf("encryption finalization error: %w", err)
	}

	// Drain remaining encrypted output (MDC packet)
	sess.encrypt.outputMu.Lock()
	finalData := make([]byte, sess.encrypt.outputBuf.Len())
	copy(finalData, sess.encrypt.outputBuf.Bytes())
	sess.encrypt.outputBuf.Reset()
	sess.encrypt.outputMu.Unlock()

	sess.done = true
	sess.sequence++

	// Remove session
	b.streamSessions.remove(sessionID)

	return &logical.Response{
		Data: map[string]interface{}{
			"session_id": sessionID,
			"data":       base64.StdEncoding.EncodeToString(finalData),
			"sequence":   sess.sequence,
			"done":       true,
		},
	}, nil
}

// drainWriter is a helper that discards writes (used in cleanup paths).
type drainWriter struct{}

func (drainWriter) Write(p []byte) (int, error) { return len(p), nil }

var _ io.Writer = drainWriter{}

const pathEncryptStreamStartHelpSyn = "Start a streaming encrypt session for large data"
const pathEncryptStreamStartHelpDesc = `
Starts a streaming encryption session for the named GPG key. Returns a
session_id and the initial encrypted data (containing the PGP PKESK header).
The client must collect the data from each response (start, updates, finalize)
and concatenate them to form a complete PGP encrypted message.
`
const pathEncryptStreamUpdateHelpSyn = "Feed a plaintext chunk to a streaming encrypt session"
const pathEncryptStreamUpdateHelpDesc = `
Sends a base64-encoded plaintext chunk to an active encryption session.
Returns the corresponding encrypted data chunk. Chunks must be sent
sequentially (not in parallel).
`
const pathEncryptStreamFinalizeHelpSyn = "Finalize a streaming encrypt session"
const pathEncryptStreamFinalizeHelpDesc = `
Finalizes the streaming encryption session, returning the final encrypted
data chunk (containing the MDC/integrity check). The client must append this
to the previously received chunks to form a valid PGP message that can be
decrypted with gpg --decrypt.
`
