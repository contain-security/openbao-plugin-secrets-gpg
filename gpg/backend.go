package gpg

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/helper/locksutil"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Factory gives a configured logical.Backend for the GPG plugin
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Start the session cleanup goroutine
	cleanupCtx, cancel := context.WithCancel(context.Background())
	b.cleanupCancel = cancel
	b.streamSessions.startCleanupLoop(cleanupCtx)

	return b, nil
}

// Backend returns an instance of the backend for the GPG plugin
func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,
		Paths: []*framework.Path{
			pathKeys(&b),
			pathListKeys(&b),
			pathExportKeys(&b),
			pathSign(&b),
			pathVerify(&b),
			pathDecrypt(&b),
			pathDecryptWithSigner(&b),
			pathShowSessionKey(&b),
			pathShowSessionKeyWithSigner(&b),
			pathEncrypt(&b),
			pathEncryptWithSigner(&b),
			pathConfig(&b),
			// Streaming sign
			pathSignStreamStart(&b),
			pathSignStreamUpdate(&b),
			pathSignStreamFinalize(&b),
			// Streaming encrypt
			pathEncryptStreamStart(&b),
			pathEncryptStreamStartWithSigner(&b),
			pathEncryptStreamUpdate(&b),
			pathEncryptStreamFinalize(&b),
			// Streaming decrypt
			pathDecryptStreamStart(&b),
			pathDecryptStreamStartWithSigner(&b),
			pathDecryptStreamUpdate(&b),
			pathDecryptStreamFinalize(&b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"key/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Clean:       b.cleanup,
	}
	b.keyLocks = locksutil.CreateLocks()
	b.streamSessions = newSessionStore()
	return &b
}

type backend struct {
	*framework.Backend
	keyLocks       []*locksutil.LockEntry
	streamSessions *sessionStore
	cleanupCancel  context.CancelFunc
}

func (b *backend) cleanup(_ context.Context) {
	if b.cleanupCancel != nil {
		b.cleanupCancel()
	}
	if b.streamSessions != nil {
		b.streamSessions.killAll()
	}
}

// resolveSignerKeyName returns the signer key name from the URL path parameter
// "signer_name". This is the only source — the signer key is always in the URL.
func resolveSignerKeyName(data *framework.FieldData) string {
	if v, ok := data.GetOk("signer_name"); ok {
		if s := v.(string); s != "" {
			return s
		}
	}
	return ""
}

const backendHelp = `
The GPG backend handles GPG operations on data in-transit.
Data sent to the backend are not stored.
`
