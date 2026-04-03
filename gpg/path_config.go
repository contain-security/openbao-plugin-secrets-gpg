package gpg

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/config",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

// pathConfigWrite validates the key exists. This is a placeholder from
// upstream vault-gpg-plugin — no configuration fields are currently supported.
// Future: could allow toggling exportable flag or setting transparency_log_address.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	lock := locksutil.LockForKey(b.keyLocks, name)
	lock.Lock()
	defer lock.Unlock()

	entry, err := b.key(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse(fmt.Sprintf("no existing key named %s could be found", name)), logical.ErrInvalidRequest
	}

	return nil, nil
}

const pathConfigHelpSyn = "Configure a named GPG key"
const pathConfigHelpDesc = "This path is used to configure the named key."
