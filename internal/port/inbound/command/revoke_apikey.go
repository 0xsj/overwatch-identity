package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// RevokeAPIKey revokes an API key.
type RevokeAPIKey struct {
	APIKeyID types.ID
	UserID   types.ID // The user requesting the revocation (for authorization)
	Reason   string
}

func (c RevokeAPIKey) CommandName() string {
	return "identity.revoke_apikey"
}

// RevokeAPIKeyResult is empty on success.
type RevokeAPIKeyResult struct{}

// RevokeAPIKeyHandler handles the RevokeAPIKey command.
type RevokeAPIKeyHandler interface {
	Handle(ctx context.Context, cmd RevokeAPIKey) (RevokeAPIKeyResult, error)
}
