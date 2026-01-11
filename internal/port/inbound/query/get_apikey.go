package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// GetAPIKey retrieves an API key by ID.
type GetAPIKey struct {
	APIKeyID types.ID
	UserID   types.ID // For authorization - user can only see their own API keys
}

func (q GetAPIKey) QueryName() string {
	return "identity.get_apikey"
}

// GetAPIKeyResult contains the API key.
type GetAPIKeyResult struct {
	APIKey *model.APIKey
}

// GetAPIKeyHandler handles the GetAPIKey query.
type GetAPIKeyHandler interface {
	Handle(ctx context.Context, qry GetAPIKey) (GetAPIKeyResult, error)
}
