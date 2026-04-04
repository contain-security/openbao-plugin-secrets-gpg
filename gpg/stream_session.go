package gpg

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	defaultSessionTimeout    = 5 * time.Minute
	defaultMaxSessions       = 64
	defaultMaxChunkSize      = 4 * 1024 * 1024  // 4MB decoded
	defaultMaxPlaintextSize  = 32 * 1024 * 1024 // 32MB — limit on decrypted plaintext to prevent decompression bombs
	sessionCleanupInterval   = 30 * time.Second
)

type sessionType int

const (
	sessionTypeSign    sessionType = iota
	sessionTypeEncrypt
	sessionTypeDecrypt
)

// streamSession holds the state for one streaming crypto operation.
type streamSession struct {
	id              string
	sessionType     sessionType
	keyName         string
	clientTokenHash string
	createdAt       time.Time
	lastAccess      time.Time
	sequence        int64
	done            bool
	err             error
	mu              sync.Mutex

	// Sign-specific fields are in signSession (embedded when sessionType == sessionTypeSign)
	sign *signSessionState

	// Encrypt-specific fields
	encrypt *encryptSessionState

	// Decrypt-specific fields
	decrypt *decryptSessionState
}

// signSessionState holds the incremental hashing state for streaming sign.
// Concrete types are used in path_sign_stream.go; here we use hash.Hash
// which satisfies both io.Writer (for feeding data) and Sum (for finalizing).
type signSessionState struct {
	hash          hash.Hash   // from sig.PrepareSign(); write chunks here
	sig           *packet.Signature
	signingKey    *packet.PrivateKey
	config        *packet.Config
	format        string
	bytesReceived int64
}

// encryptSessionState holds the goroutine-bridged state for streaming encrypt.
type encryptSessionState struct {
	plainWriter   io.WriteCloser // the WriteCloser returned by openpgp.Encrypt
	outputMu      sync.Mutex
	outputBuf     bytes.Buffer
	goroutineDone chan struct{}
	goroutineErr  error
}

// decryptSessionState holds the goroutine-bridged state for streaming decrypt.
type decryptSessionState struct {
	inputPipeW    *io.PipeWriter
	bpw           *bufferedPipeWriter // wraps inputPipeW for non-blocking writes
	outputMu      sync.Mutex
	outputBuf     bytes.Buffer
	goroutineDone chan struct{}
	goroutineErr  error
	sigError      error  // set after finalize if signature check fails
	hasSigner     bool
}

// lockedWriter wraps a bytes.Buffer with a mutex for safe concurrent writes.
type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.buf.Write(p)
}

// sessionStore manages streaming sessions on the backend.
type sessionStore struct {
	sessions     sync.Map
	sessionCount atomic.Int64
	maxSessions  int
	timeout      time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		maxSessions: defaultMaxSessions,
		timeout:     defaultSessionTimeout,
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashClientToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *sessionStore) create(sess *streamSession) error {
	// Atomic increment-then-check avoids TOCTOU race under concurrent creates.
	newCount := s.sessionCount.Add(1)
	if int(newCount) > s.maxSessions {
		s.sessionCount.Add(-1)
		return fmt.Errorf("too many active streaming sessions (max %d)", s.maxSessions)
	}
	s.sessions.Store(sess.id, sess)
	return nil
}

func (s *sessionStore) get(id string) (*streamSession, bool) {
	val, ok := s.sessions.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*streamSession), true
}

func (s *sessionStore) remove(id string) {
	if _, loaded := s.sessions.LoadAndDelete(id); loaded {
		s.sessionCount.Add(-1)
	}
}

// cleanup removes expired sessions and terminates their resources.
func (s *sessionStore) cleanup() int {
	now := time.Now()
	removed := 0
	s.sessions.Range(func(key, value any) bool {
		sess := value.(*streamSession)
		sess.mu.Lock()
		expired := now.Sub(sess.lastAccess) > s.timeout
		sess.mu.Unlock()
		if expired {
			s.terminateSession(sess)
			if _, loaded := s.sessions.LoadAndDelete(key); loaded {
				s.sessionCount.Add(-1)
				removed++
			}
		}
		return true
	})
	return removed
}

// terminateSession cleans up resources for a session (closes pipes, etc).
func (s *sessionStore) terminateSession(sess *streamSession) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.done {
		return
	}
	sess.done = true
	sess.err = fmt.Errorf("session expired")

	switch sess.sessionType {
	case sessionTypeEncrypt:
		if sess.encrypt != nil && sess.encrypt.plainWriter != nil {
			sess.encrypt.plainWriter.Close()
		}
	case sessionTypeDecrypt:
		if sess.decrypt != nil && sess.decrypt.bpw != nil {
			sess.decrypt.bpw.Close()
		}
	}
}

// killAll terminates all sessions (used on shutdown).
func (s *sessionStore) killAll() {
	s.sessions.Range(func(key, value any) bool {
		sess := value.(*streamSession)
		s.terminateSession(sess)
		if _, loaded := s.sessions.LoadAndDelete(key); loaded {
			s.sessionCount.Add(-1)
		}
		return true
	})
}

// startCleanupLoop runs periodic session cleanup until ctx is cancelled.
func (s *sessionStore) startCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(sessionCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.cleanup()
			case <-ctx.Done():
				s.killAll()
				return
			}
		}
	}()
}
