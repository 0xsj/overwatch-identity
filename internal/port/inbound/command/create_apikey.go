package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// CreateAPIKey creates a new API key for a user.
type CreateAPIKey struct {
	UserID    types.ID
	Name      string
	Scopes    []string
	TenantID  types.Optional[types.ID]
	ExpiresAt types.Optional[types.Timestamp]
}

func (c CreateAPIKey) CommandName() string {
	return "identity.create_apikey"
}

// CreateAPIKeyResult contains the created API key and the secret.
// The secret is only returned once at creation time.
type CreateAPIKeyResult struct {
	APIKey *model.APIKey
	Secret string
}

// CreateAPIKeyHandler handles the CreateAPIKey command.
type CreateAPIKeyHandler interface {
	Handle(ctx context.Context, cmd CreateAPIKey) (CreateAPIKeyResult, error)
}
