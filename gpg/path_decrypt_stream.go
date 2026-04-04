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
		Pattern: "decrypt-stream/session/" + framework.GenericNameRegex("session_id") + "/update",
		Fields: map[string]*framework.FieldSchema{
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
		Pattern: "decrypt-stream/session/" + framework.GenericNameRegex("session_id") + "/finalize",
		Fields: map[string]*framework.FieldSchema{
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

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	signerKeyName := resolveSignerKeyName(data)
	hasSigner := signerKeyName != ""
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
	}

	initialB64 := data.Get("data").(string)
	if initialB64 == "" {
		return logical.ErrorResponse("initial ciphertext data is required (must contain at least the PGP PKESK header)"), logical.ErrInvalidRequest
	}
	initialData, err := base64.StdEncoding.DecodeString(initialB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode data as base64: %s", err)), logical.ErrInvalidRequest
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
	}

	// Store the bufferedPipeWriter in a field we can access
	// We'll use a closure to capture it for the goroutine.

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

	// Set bpw before creating the session so concurrent requests see it.
	sess.decrypt.bpw = bpw

	if err := b.streamSessions.create(sess); err != nil {
		bpw.Close()
		inputPipeR.Close()
		return logical.ErrorResponse(err.Error()), nil
	}

	// Write initial ciphertext to the buffered pipe.
	if _, err := bpw.Write(initialData); err != nil {
		b.streamSessions.remove(sessionID)
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

		md, err := openpgp.ReadMessage(inputPipeR, keyring, nil, nil)
		if err != nil {
			decState.outputMu.Lock()
			decState.goroutineErr = fmt.Errorf("ReadMessage error: %w", err)
			decState.outputMu.Unlock()
			readyOnce.Do(func() { close(readySignal) })
			return
		}

		readyOnce.Do(func() { close(readySignal) })

		// Copy decrypted body to the output buffer with size limit.
		// The limitedWriter wraps lw and refuses writes once the cap is hit,
		// so no data beyond the limit is buffered or returned to the client.
		limited := &limitedWriter{w: lw, remaining: defaultMaxPlaintextSize}
		_, err = io.Copy(limited, md.UnverifiedBody)
		if limited.exceeded {
			decState.outputMu.Lock()
			decState.goroutineErr = fmt.Errorf("decrypted plaintext exceeds maximum size")
			decState.outputMu.Unlock()
			return
		}
		if err != nil {
			decState.outputMu.Lock()
			decState.goroutineErr = fmt.Errorf("decryption error: %w", err)
			decState.outputMu.Unlock()
			return
		}

		// Check signature after fully reading UnverifiedBody
		if hasSigner {
			if !md.IsSigned || md.SignedBy == nil || md.SignatureError != nil {
				decState.outputMu.Lock()
				decState.sigError = fmt.Errorf("signature is invalid or not present: %v", md.SignatureError)
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
		err := decState.goroutineErr
		decState.outputMu.Unlock()
		b.streamSessions.remove(sessionID)
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
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
		respData["signature_verified"] = false
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
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
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
		return logical.ErrorResponse(fmt.Sprintf("unable to decode data as base64: %s", err)), logical.ErrInvalidRequest
	}
	if len(input) > defaultMaxChunkSize {
		return logical.ErrorResponse(fmt.Sprintf("chunk exceeds maximum size of %d bytes", defaultMaxChunkSize)), logical.ErrInvalidRequest
	}

	// Write ciphertext to the buffered pipe (non-blocking).
	if _, err := sess.decrypt.bpw.Write(input); err != nil {
		return nil, fmt.Errorf("error writing ciphertext: %w", err)
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
		respData["signature_verified"] = false
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
	if sess.clientTokenHash != hashClientToken(req.ClientToken) {
		return logical.ErrorResponse("session belongs to a different client"), logical.ErrInvalidRequest
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
responses include "signature_verified": false as a reminder.
`
const pathDecryptStreamUpdateHelpSyn = "Feed a ciphertext chunk to a streaming decrypt session"
const pathDecryptStreamUpdateHelpDesc = `
Sends a base64-encoded ciphertext chunk to an active decryption session.
Returns any decrypted plaintext available. Chunks must be sent sequentially.

When a signer key is specified, responses include "signature_verified": false.
Do not act on the plaintext until finalize confirms signature_valid is true.
`
const pathDecryptStreamFinalizeHelpSyn = "Finalize a streaming decrypt session"
const pathDecryptStreamFinalizeHelpDesc = `
Finalizes the streaming decryption session. Returns any remaining decrypted
plaintext and, if a signer was specified, the signature verification result
(signature_valid and signature_error fields). Only after this response
confirms signature_valid: true should the client trust the decrypted data.
`
