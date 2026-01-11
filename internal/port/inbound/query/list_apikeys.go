package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// ListAPIKeys retrieves API keys for a user.
type ListAPIKeys struct {
	UserID     types.ID
	TenantID   types.Optional[types.ID]
	ActiveOnly bool
	Limit      int
	Offset     int
}

func (q ListAPIKeys) QueryName() string {
	return "identity.list_apikeys"
}

// ListAPIKeysResult contains the API keys and pagination info.
type ListAPIKeysResult struct {
	APIKeys    []*model.APIKey
	TotalCount int64
}

// ListAPIKeysHandler handles the ListAPIKeys query.
type ListAPIKeysHandler interface {
	Handle(ctx context.Context, qry ListAPIKeys) (ListAPIKeysResult, error)
}
