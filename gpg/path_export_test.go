// Copyright (c) 2017-2019 Thomas Gerbet
// Copyright (c) 2026 OpenBao GPG Plugin Contributors
// SPDX-License-Identifier: MIT

package gpg

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestGPG_ExportNotExistingKeyReturnsError(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/test",
	}
	rsp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if rsp == nil || !rsp.IsError() {
		t.Fatal("expected error for non-existent key")
	}
}

func TestGPG_ExportNotExportableKeyReturnsError(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	reqExp := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/test",
	}
	resp, err := b.HandleRequest(context.Background(), reqExp)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Key not exportable but was exported")
	}
}

func TestGPG_ExportKey(t *testing.T) {
	storage := &logical.InmemStorage{}

	b := Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name":  "Vault GPG test",
			"exportable": true,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	reqExp := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/test",
	}
	resp, err := b.HandleRequest(context.Background(), reqExp)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("not expected error response: %#v", *resp)
	}
	name, ok := resp.Data["name"]
	if !ok {
		t.Fatalf("no name key found in response data %#v", resp.Data)
	}
	if name != "test" {
		t.Fatalf("not expected name, expected test got: %s", name)
	}
}
