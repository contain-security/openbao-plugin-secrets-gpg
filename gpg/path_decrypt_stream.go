// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathDecryptStreamStart(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt-stream/" + framework.GenericNameRegex("name") + "/start",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to decrypt with",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded initial ciphertext (must contain the PGP PKESK header).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptStreamStartWrite,
			},
		},
		HelpSynopsis:    pathDecryptStreamStartHelpSyn,
		HelpDescription: pathDecryptStreamStartHelpDesc,
	}
}

func pathDecryptStreamStartWithSigner(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt-stream/" + framework.GenericNameRegex("name") + "/sign/" + framework.GenericNameRegex("signer_name") + "/start",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to decrypt with",
			},
			"signer_name": {
				Type:        framework.TypeString,
				Description: "The GPG key to verify the signature against (from URL path)",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded initial ciphertext (must contain the PGP PKESK header).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptStreamStartWrite,
			},
		},
		HelpSynopsis:    pathDecryptStreamStartHelpSyn,
		HelpDescription: pathDecryptStreamStartHelpDesc,
	}
}

func pathDecryptStreamUpdate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt-stream/" + framework.GenericNameRegex("name") + "/update",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to decrypt with",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded ciphertext chunk",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptStreamUpdateWrite,
			},
		},
		HelpSynopsis:    pathDecryptStreamUpdateHelpSyn,
		HelpDescription: pathDecryptStreamUpdateHelpDesc,
	}
}

func pathDecryptStreamFinalize(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt-stream/" + framework.GenericNameRegex("name") + "/finalize",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to decrypt with",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "Session ID returned from the start endpoint",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptStreamFinalizeWrite,
			},
		},
		HelpSynopsis:    pathDecryptStreamFinalizeHelpSyn,
		HelpDescription: pathDecryptStreamFinalizeHelpDesc,
	}
}

// limitedWriter wraps an io.Writer and stops accepting data once a byte cap
// is exceeded. Unlike io.LimitReader, this prevents any over-limit data from
// reaching the underlying writer.
type limitedWriter struct {
	w         io.Writer
	remaining int64
	exceeded  bool
}

var errPlaintextTooLarge = fmt.Errorf("decrypted plaintext exceeds maximum size")

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.exceeded {
		return 0, errPlaintextTooLarge
	}
	if int64(len(p)) > lw.remaining {
		lw.exceeded = true
		return 0, errPlaintextTooLarge
	}
	n, err := lw.w.Write(p)
	lw.remaining -= int64(n)
	return n, err
}

// bufferedPipeWriter is a non-blocking writer that buffers data and feeds it
// to an io.PipeWriter via a background goroutine. This prevents deadlocks
// when both the writer and reader sides of a pipe are driven from the same
// logical flow (across HTTP requests).
type bufferedPipeWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
	pw     *io.PipeWriter
	closed bool
	done   chan struct{} // closed when the drain goroutine exits
}

func newBufferedPipeWriter(pw *io.PipeWriter) *bufferedPipeWriter {
	bpw := &bufferedPipeWriter{
		notify: make(chan struct{}, 1),
		pw:     pw,
		done:   make(chan struct{}),
	}
	go bpw.drain()
	return bpw
}

// Write buffers data and notifies the drain goroutine.
func (bpw *bufferedPipeWriter) Write(p []byte) (int, error) {
	bpw.mu.Lock()
	if bpw.closed {
		bpw.mu.Unlock()
		return 0, fmt.Errorf("writer is closed")
	}
	n, err := bpw.buf.Write(p)
	bpw.mu.Unlock()
	// Non-blocking notify
	select {
	case bpw.notify <- struct{}{}:
	default:
	}
	return n, err
}

// Close signals no more data will be written, and waits for drain to finish.
func (bpw *bufferedPipeWriter) Close() error {
	bpw.mu.Lock()
	bpw.closed = true
	bpw.mu.Unlock()
	select {
	case bpw.notify <- struct{}{}:
	default:
	}
	<-bpw.done
	return nil
}

// drain runs in a goroutine, feeding buffered data to the PipeWriter.
func (bpw *bufferedPipeWriter) drain() {
	defer close(bpw.done)
	defer bpw.pw.Close()

	for {
		<-bpw.notify

		for {
			bpw.mu.Lock()
			if bpw.buf.Len() == 0 {
				closed := bpw.closed
				bpw.mu.Unlock()
				if closed {
					return
				}
				break // wait for next notify
			}
			// Take a copy of the buffered data
			data := make([]byte, bpw.buf.Len())
			copy(data, bpw.buf.Bytes())
			bpw.buf.Reset()
			bpw.mu.Unlock()

			// Write to the pipe (may block until reader consumes)
			if _, err := bpw.pw.Write(data); err != nil {
				return
			}
		}
	}
}

func (b *backend) pathDecryptStreamStartWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	hasSigner := signerKeyName != ""
	var signerKeyId uint64
	if hasSigner {
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
		signerKeyId = signerEntity.PrimaryKey.KeyId
	}

	initialB64 := data.Get("data").(string)
	if initialB64 == "" {
		return logical.ErrorResponse("initial ciphertext data is required (must contain at least the PGP PKESK header)"), logical.ErrInvalidRequest
	}
	initialData, err := base64.StdEncoding.DecodeString(initialB64)
	if err != nil {
		return logical.ErrorResponse("unable to decode data: invalid base64 encoding"), logical.ErrInvalidRequest
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	// Create the pipe for ciphertext input to ReadMessage.
	inputPipeR, inputPipeW := io.Pipe()

	// Use a bufferedPipeWriter so writes from HTTP handlers don't block.
	bpw := newBufferedPipeWriter(inputPipeW)

	decState := &decryptSessionState{
		inputPipeW:    inputPipeW,
		goroutineDone: make(chan struct{}),
		hasSigner:     hasSigner,
		signerKeyId:   signerKeyId,
	}

	// Store the bufferedPipeWriter in a field we can access
	// We'll use a closure to capture it for the goroutine.

	cfg, err := b.streamConfig(ctx, req.Storage)
	if err != nil {
		bpw.Close()
		inputPipeR.Close()
		return nil, err
	}
	maxPlaintextSize := cfg.maxPlaintextSize

	// Enforce the per-chunk cap on the initial ciphertext too, for consistency
	// with the update endpoint (the initial data is just the first chunk).
	if int64(len(initialData)) > cfg.maxChunkSize {
		bpw.Close()
		inputPipeR.Close()
		return logical.ErrorResponse(fmt.Sprintf("chunk exceeds maximum size of %d bytes", cfg.maxChunkSize)), logical.ErrInvalidRequest
	}

	now := time.Now()
	sess := &streamSession{
		id:              sessionID,
		sessionType:     sessionTypeDecrypt,
		keyName:         data.Get("name").(string),
		clientTokenHash: hashClientToken(req.ClientToken),
		createdAt:       now,
		lastAccess:      now,
		decrypt:         decState,
	}
	sess.applyLimits(cfg)

	// Set bpw before creating the session so concurrent requests see it.
	sess.decrypt.bpw = bpw

	if err := b.streamSessions.create(sess); err != nil {
		bpw.Close()
		inputPipeR.Close()
		return logical.ErrorResponse("unable to create streaming session"), nil
	}

	// Write initial ciphertext to the buffered pipe.
	if _, err := bpw.Write(initialData); err != nil {
		b.streamSessions.remove(sessionID)
		bpw.Close()
		inputPipeR.Close()
		return nil, fmt.Errorf("failed to write initial ciphertext: %w", err)
	}

	// Goroutine: ReadMessage reads from inputPipeR, decrypts, writes plaintext
	// to the decState.outputBuf via lockedWriter.
	// The goroutine is started only after successful session creation.
	lw := &lockedWriter{
		mu:  &decState.outputMu,
		buf: &decState.outputBuf,
	}

	// readySignal is closed once ReadMessage returns successfully and
	// the goroutine starts reading UnverifiedBody. This lets the start
	// handler know the session is ready.
	readySignal := make(chan struct{})
	readyOnce := sync.Once{}

	go func() {
		defer close(decState.goroutineDone)
		// Close the read side when the goroutine exits. If it aborts early
		// (e.g. the plaintext cap is exceeded) without draining the input pipe,
		// this unblocks the bufferedPipeWriter's drain (its pw.Write would
		// otherwise block forever with no reader), so a later finalize/Close
		// does not deadlock.
		defer inputPipeR.Close()

		md, err := openpgp.ReadMessage(inputPipeR, keyring, nil, nil)
		if err != nil {
			decState.outputMu.Lock()
			decState.goroutineErr = fmt.Errorf("decryption failed")
			decState.outputMu.Unlock()
			readyOnce.Do(func() { close(readySignal) })
			return
		}

		readyOnce.Do(func() { close(readySignal) })

		// Copy decrypted body to the output buffer. When a plaintext cap is
		// configured (> 0) it is enforced here as the decompression-bomb
		// ceiling: the limitedWriter refuses writes once the cap is hit, so no
		// data beyond the limit is buffered or returned to the client. A cap of
		// 0 means unlimited, for cooperative large-archive streaming where the
		// plaintext is drained chunk-by-chunk under client backpressure.
		var copyErr error
		if maxPlaintextSize > 0 {
			limited := &limitedWriter{w: lw, remaining: maxPlaintextSize}
			_, copyErr = io.Copy(limited, md.UnverifiedBody)
			if limited.exceeded {
				decState.outputMu.Lock()
				decState.goroutineErr = fmt.Errorf("decrypted plaintext exceeds maximum size")
				decState.outputMu.Unlock()
				return
			}
		} else {
			_, copyErr = io.Copy(lw, md.UnverifiedBody)
		}
		if copyErr != nil {
			decState.outputMu.Lock()
			decState.goroutineErr = fmt.Errorf("decryption failed")
			decState.outputMu.Unlock()
			return
		}

		// Check the signature after fully reading UnverifiedBody. The verdict is
		// bound to the requested signer: a valid signature from any other key in
		// the keyring (including the recipient's own key) does NOT satisfy it.
		if hasSigner {
			sigOK := md.IsSigned && md.SignedBy != nil && md.SignatureError == nil &&
				md.SignedBy.Entity != nil &&
				md.SignedBy.Entity.PrimaryKey.KeyId == decState.signerKeyId
			if !sigOK {
				decState.outputMu.Lock()
				decState.sigError = fmt.Errorf("signature verification failed")
				decState.outputMu.Unlock()
			}
		}
	}()

	// Wait for ReadMessage to process the PKESK header
	select {
	case <-readySignal:
	case <-time.After(5 * time.Second):
		// Timeout waiting for ReadMessage — likely not enough initial data
		b.streamSessions.remove(sessionID)
		bpw.Close()
		return logical.ErrorResponse("timeout waiting for ReadMessage to process initial ciphertext; ensure enough data is provided"), logical.ErrInvalidRequest
	}

	// Check for errors
	decState.outputMu.Lock()
	if decState.goroutineErr != nil {
		decState.outputMu.Unlock()
		b.streamSessions.remove(sessionID)
		return logical.ErrorResponse("decryption failed"), logical.ErrInvalidRequest
	}

	// Drain any initial plaintext
	initialPlaintext := make([]byte, decState.outputBuf.Len())
	copy(initialPlaintext, decState.outputBuf.Bytes())
	decState.outputBuf.Reset()
	decState.outputMu.Unlock()

	respData := map[string]interface{}{
		"session_id": sessionID,
		"data":       base64.StdEncoding.EncodeToString(initialPlaintext),
		"sequence":   int64(0),
		"done":       false,
	}
	if hasSigner {
		respData["signature_valid"] = false
		respData["signature_final"] = false
	}

	return &logical.Response{Data: respData}, nil
}

func (b *backend) pathDecryptStreamUpdateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if sess.sessionType != sessionTypeDecrypt {
		return logical.ErrorResponse("session is not a decrypt session"), logical.ErrInvalidRequest
	}
	if !clientTokenMatches(sess.clientTokenHash, req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	// Check for goroutine errors
	sess.decrypt.outputMu.Lock()
	if sess.decrypt.goroutineErr != nil {
		err := sess.decrypt.goroutineErr
		sess.decrypt.outputMu.Unlock()
		return nil, err
	}
	sess.decrypt.outputMu.Unlock()

	inputB64 := data.Get("data").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse("unable to decode data: invalid base64 encoding"), logical.ErrInvalidRequest
	}
	if int64(len(input)) > sess.maxChunkSize {
		return logical.ErrorResponse(fmt.Sprintf("chunk exceeds maximum size of %d bytes", sess.maxChunkSize)), logical.ErrInvalidRequest
	}

	// Write ciphertext to the buffered pipe (non-blocking).
	if _, err := sess.decrypt.bpw.Write(input); err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	// Drain available decrypted plaintext. The goroutine may not have
	// processed this chunk yet — that's fine, remaining plaintext will
	// be returned in subsequent update or finalize responses.
	sess.decrypt.outputMu.Lock()
	plaintext := make([]byte, sess.decrypt.outputBuf.Len())
	copy(plaintext, sess.decrypt.outputBuf.Bytes())
	sess.decrypt.outputBuf.Reset()
	sess.decrypt.outputMu.Unlock()

	sess.sequence++
	sess.lastAccess = time.Now()

	respData := map[string]interface{}{
		"session_id": sessionID,
		"data":       base64.StdEncoding.EncodeToString(plaintext),
		"sequence":   sess.sequence,
		"done":       false,
	}
	if sess.decrypt.hasSigner {
		respData["signature_valid"] = false
		respData["signature_final"] = false
	}

	return &logical.Response{Data: respData}, nil
}

func (b *backend) pathDecryptStreamFinalizeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if sess.sessionType != sessionTypeDecrypt {
		return logical.ErrorResponse("session is not a decrypt session"), logical.ErrInvalidRequest
	}
	if !clientTokenMatches(sess.clientTokenHash, req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
	}
	if sess.keyName != data.Get("name").(string) {
		return logical.ErrorResponse("key name does not match session"), logical.ErrInvalidRequest
	}

	// Close the buffered pipe writer — signals EOF to the goroutine
	sess.decrypt.bpw.Close()

	// Wait for the goroutine to finish processing all data
	<-sess.decrypt.goroutineDone

	sess.done = true
	sess.sequence++

	// Check for errors
	sess.decrypt.outputMu.Lock()
	goroutineErr := sess.decrypt.goroutineErr
	sigError := sess.decrypt.sigError
	// Drain all remaining plaintext
	remaining := make([]byte, sess.decrypt.outputBuf.Len())
	copy(remaining, sess.decrypt.outputBuf.Bytes())
	sess.decrypt.outputBuf.Reset()
	sess.decrypt.outputMu.Unlock()

	if goroutineErr != nil {
		b.streamSessions.remove(sessionID)
		return nil, goroutineErr
	}

	respData := map[string]interface{}{
		"session_id": sessionID,
		"data":       base64.StdEncoding.EncodeToString(remaining),
		"sequence":   sess.sequence,
		"done":       true,
	}

	if sess.decrypt.hasSigner {
		respData["signature_valid"] = sigError == nil
		respData["signature_final"] = true
		if sigError != nil {
			respData["signature_error"] = sigError.Error()
		}
	}

	b.streamSessions.remove(sessionID)

	return &logical.Response{
		Data: respData,
	}, nil
}

const pathDecryptStreamStartHelpSyn = "Start a streaming decrypt session for large data"
const pathDecryptStreamStartHelpDesc = `
Starts a streaming decryption session for the named GPG key. The initial
ciphertext data must contain at least the PGP PKESK header. Returns a
session_id and any initial decrypted plaintext.

IMPORTANT: When a signer key is specified, plaintext returned by start and
update responses is UNVERIFIED. The PGP signature is appended after the
message body, so it cannot be checked until all data is read. The client
MUST wait for the finalize response and check signature_valid before
trusting or processing any of the received plaintext. Start and update
responses include "signature_valid": false and "signature_final": false as a
reminder; the verdict is authoritative only once finalize returns
"signature_final": true.
`
const pathDecryptStreamUpdateHelpSyn = "Feed a ciphertext chunk to a streaming decrypt session"
const pathDecryptStreamUpdateHelpDesc = `
Sends a base64-encoded ciphertext chunk to an active decryption session.
Returns any decrypted plaintext available. Chunks must be sent sequentially.

When a signer key is specified, responses include "signature_valid": false and
"signature_final": false. Do not act on the plaintext until finalize returns
"signature_final": true and confirms signature_valid is true.
`
const pathDecryptStreamFinalizeHelpSyn = "Finalize a streaming decrypt session"
const pathDecryptStreamFinalizeHelpDesc = `
Finalizes the streaming decryption session. Returns any remaining decrypted
plaintext and, if a signer was specified, the signature verification result
(signature_valid field). Only after this response confirms
signature_valid: true should the client trust the decrypted data.
`
