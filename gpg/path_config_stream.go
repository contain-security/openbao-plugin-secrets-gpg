// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// streamConfigStorageKey is the storage location of the mount-wide streaming
// configuration entry.
const streamConfigStorageKey = "config"

// streamConfigEntry is the persisted mount-level streaming configuration.
//
// Pointer fields distinguish "unset" (nil -> fall back to the built-in default)
// from an explicit value. For the byte caps (MaxStreamBytes, MaxPlaintextSize)
// an explicit 0 means "unlimited"; for the remaining tunables a value must be
// greater than 0 to take effect.
type streamConfigEntry struct {
	MaxStreamBytes        *int64 `json:"max_stream_bytes,omitempty"`
	MaxPlaintextSize      *int64 `json:"max_plaintext_size,omitempty"`
	MaxChunkSize          *int64 `json:"max_chunk_size,omitempty"`
	SessionTimeoutSeconds *int64 `json:"session_timeout_seconds,omitempty"`
	MaxSessions           *int64 `json:"max_sessions,omitempty"`
	MaxSessionsPerClient  *int64 `json:"max_sessions_per_client,omitempty"`
}

// resolvedStreamConfig holds the effective streaming limits with all defaults
// applied. A byte cap of 0 means "no limit"; the timeout and session counts are
// always greater than 0.
type resolvedStreamConfig struct {
	maxStreamBytes       int64
	maxPlaintextSize     int64
	maxChunkSize         int64
	timeout              time.Duration
	maxSessions          int
	maxSessionsPerClient int
}

func pathStreamConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"max_stream_bytes": {
				Type:        framework.TypeInt64,
				Description: "Maximum total input bytes accepted per streaming encrypt or sign session. 0 means unlimited. Unset leaves the default (512 MiB).",
			},
			"max_plaintext_size": {
				Type:        framework.TypeInt64,
				Description: "Maximum decrypted plaintext bytes produced per streaming decrypt session; this is the decompression-bomb ceiling. 0 means unlimited. Unset leaves the default (32 MiB).",
			},
			"max_chunk_size": {
				Type:        framework.TypeInt64,
				Description: "Maximum size in bytes of a single decoded chunk. Must be greater than 0. Unset leaves the default (4 MiB).",
			},
			"session_timeout_seconds": {
				Type:        framework.TypeInt64,
				Description: "Idle timeout for streaming sessions, in seconds. Must be greater than 0. Unset leaves the default (300).",
			},
			"max_sessions": {
				Type:        framework.TypeInt64,
				Description: "Maximum number of concurrent streaming sessions across the mount. Must be greater than 0. Unset leaves the default (64).",
			},
			"max_sessions_per_client": {
				Type:        framework.TypeInt64,
				Description: "Maximum number of concurrent streaming sessions per client token. Must be greater than 0. Unset leaves the default (4).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStreamConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStreamConfigRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStreamConfigDelete},
		},
		HelpSynopsis:    pathStreamConfigHelpSyn,
		HelpDescription: pathStreamConfigHelpDesc,
	}
}

// streamConfig reads the persisted mount configuration and returns the
// effective limits with defaults applied. It is safe to call on every session
// start: a missing entry yields the built-in defaults.
func (b *backend) streamConfig(ctx context.Context, s logical.Storage) (resolvedStreamConfig, error) {
	resolved := resolvedStreamConfig{
		maxStreamBytes:       defaultMaxStreamBytes,
		maxPlaintextSize:     defaultMaxPlaintextSize,
		maxChunkSize:         defaultMaxChunkSize,
		timeout:              defaultSessionTimeout,
		maxSessions:          defaultMaxSessions,
		maxSessionsPerClient: defaultMaxSessionsPerClient,
	}

	entry, err := s.Get(ctx, streamConfigStorageKey)
	if err != nil {
		return resolved, err
	}
	if entry == nil {
		return resolved, nil
	}

	var cfg streamConfigEntry
	if err := entry.DecodeJSON(&cfg); err != nil {
		return resolved, err
	}

	// Byte caps: a non-nil value (including 0 = unlimited) overrides.
	if cfg.MaxStreamBytes != nil {
		resolved.maxStreamBytes = *cfg.MaxStreamBytes
	}
	if cfg.MaxPlaintextSize != nil {
		resolved.maxPlaintextSize = *cfg.MaxPlaintextSize
	}
	// The remaining tunables only override when a positive value is stored.
	if cfg.MaxChunkSize != nil && *cfg.MaxChunkSize > 0 {
		resolved.maxChunkSize = *cfg.MaxChunkSize
	}
	if cfg.SessionTimeoutSeconds != nil && *cfg.SessionTimeoutSeconds > 0 {
		resolved.timeout = time.Duration(*cfg.SessionTimeoutSeconds) * time.Second
	}
	if cfg.MaxSessions != nil && *cfg.MaxSessions > 0 {
		resolved.maxSessions = int(*cfg.MaxSessions)
	}
	if cfg.MaxSessionsPerClient != nil && *cfg.MaxSessionsPerClient > 0 {
		resolved.maxSessionsPerClient = int(*cfg.MaxSessionsPerClient)
	}

	return resolved, nil
}

// applyLimits copies the resolved mount limits onto a session at start time.
// Enforcement then references the per-session values, so a session uses the
// configuration that was in force when it began.
func (sess *streamSession) applyLimits(cfg resolvedStreamConfig) {
	sess.maxStreamBytes = cfg.maxStreamBytes
	sess.maxPlaintextSize = cfg.maxPlaintextSize
	sess.maxChunkSize = cfg.maxChunkSize
	sess.timeout = cfg.timeout
	sess.maxSessions = cfg.maxSessions
	sess.maxSessionsPerClient = cfg.maxSessionsPerClient
}

func (b *backend) pathStreamConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Start from any existing config so fields not present in this request are
	// preserved (merge semantics).
	cfg := &streamConfigEntry{}
	entry, err := req.Storage.Get(ctx, streamConfigStorageKey)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(cfg); err != nil {
			return nil, err
		}
	}

	// setByteCap accepts >= 0 (0 means unlimited); setPositive requires > 0.
	setByteCap := func(field string, dst **int64) *logical.Response {
		if raw, ok := data.GetOk(field); ok {
			v := raw.(int64)
			if v < 0 {
				return logical.ErrorResponse(fmt.Sprintf("%s must be >= 0 (0 means unlimited)", field))
			}
			*dst = &v
		}
		return nil
	}
	setPositive := func(field string, dst **int64) *logical.Response {
		if raw, ok := data.GetOk(field); ok {
			v := raw.(int64)
			if v <= 0 {
				return logical.ErrorResponse(fmt.Sprintf("%s must be > 0", field))
			}
			*dst = &v
		}
		return nil
	}

	if resp := setByteCap("max_stream_bytes", &cfg.MaxStreamBytes); resp != nil {
		return resp, logical.ErrInvalidRequest
	}
	if resp := setByteCap("max_plaintext_size", &cfg.MaxPlaintextSize); resp != nil {
		return resp, logical.ErrInvalidRequest
	}
	if resp := setPositive("max_chunk_size", &cfg.MaxChunkSize); resp != nil {
		return resp, logical.ErrInvalidRequest
	}
	if resp := setPositive("session_timeout_seconds", &cfg.SessionTimeoutSeconds); resp != nil {
		return resp, logical.ErrInvalidRequest
	}
	if resp := setPositive("max_sessions", &cfg.MaxSessions); resp != nil {
		return resp, logical.ErrInvalidRequest
	}
	if resp := setPositive("max_sessions_per_client", &cfg.MaxSessionsPerClient); resp != nil {
		return resp, logical.ErrInvalidRequest
	}

	storageEntry, err := logical.StorageEntryJSON(streamConfigStorageKey, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, err
	}

	// Return the effective config so the caller sees what is now in force.
	return b.pathStreamConfigRead(ctx, req, data)
}

func (b *backend) pathStreamConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resolved, err := b.streamConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"max_stream_bytes":        resolved.maxStreamBytes,
			"max_plaintext_size":      resolved.maxPlaintextSize,
			"max_chunk_size":          resolved.maxChunkSize,
			"session_timeout_seconds": int64(resolved.timeout / time.Second),
			"max_sessions":            resolved.maxSessions,
			"max_sessions_per_client": resolved.maxSessionsPerClient,
		},
	}, nil
}

func (b *backend) pathStreamConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, streamConfigStorageKey); err != nil {
		return nil, err
	}
	return nil, nil
}

const pathStreamConfigHelpSyn = "Configure mount-wide limits for the streaming encrypt/decrypt/sign sessions."
const pathStreamConfigHelpDesc = `
This endpoint configures the resource limits applied to streaming sessions on
this mount. All fields are optional; a field that is not supplied keeps its
current value (or the built-in default if never set).

Size caps that block large-archive streaming:
  - max_stream_bytes   : total input bytes per encrypt/sign session (0 = unlimited)
  - max_plaintext_size : decrypted plaintext bytes per decrypt session, the
                         decompression-bomb ceiling (0 = unlimited)
  - max_chunk_size     : maximum size of a single decoded chunk (must be > 0)

Session lifecycle / concurrency limits:
  - session_timeout_seconds : idle timeout before an inactive session is reaped
  - max_sessions            : concurrent sessions across the mount
  - max_sessions_per_client : concurrent sessions per client token

Setting a byte cap to 0 disables that limit for cooperative large-data
streaming. The single-shot /encrypt and /decrypt endpoints are NOT affected by
these settings; they keep a fixed in-memory bound.

A read returns the effective limits currently in force; a delete restores all
defaults.
`
