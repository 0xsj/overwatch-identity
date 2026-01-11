package repository

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// APIKeyRepository defines the interface for API key persistence.
type APIKeyRepository interface {
	// Create persists a new API key.
	Create(ctx context.Context, apiKey *model.APIKey) error

	// Update persists changes to an existing API key.
	Update(ctx context.Context, apiKey *model.APIKey) error

	// FindByID retrieves an API key by its ID.
	FindByID(ctx context.Context, id types.ID) (*model.APIKey, error)

	// FindByKeyHash retrieves an API key by its hash.
	FindByKeyHash(ctx context.Context, hash string) (*model.APIKey, error)

	// FindByPrefix retrieves an API key by its prefix.
	// Used for displaying keys to users (they only see prefix).
	FindByPrefix(ctx context.Context, prefix string) (*model.APIKey, error)

	// FindActiveByUserID retrieves all active API keys for a user.
	FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.APIKey, error)

	// List retrieves API keys with pagination.
	List(ctx context.Context, params ListAPIKeysParams) ([]*model.APIKey, error)

	// Count returns the total number of API keys matching the filter.
	Count(ctx context.Context, params ListAPIKeysParams) (int64, error)

	// RevokeByID revokes an API key by ID.
	RevokeByID(ctx context.Context, id types.ID) error

	// RevokeAllByUserID revokes all API keys for a user.
	// Returns the number of API keys revoked.
	RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error)

	// Delete removes an API key by ID.
	Delete(ctx context.Context, id types.ID) error

	// DeleteExpired removes all expired API keys.
	// Returns the number of API keys deleted.
	DeleteExpired(ctx context.Context) (int, error)
}

// ListAPIKeysParams defines parameters for listing API keys.
type ListAPIKeysParams struct {
	// Pagination
	Limit  int
	Offset int

	// Filters
	UserID     *types.ID
	TenantID   *types.ID
	Status     *model.APIKeyStatus
	ActiveOnly bool

	// Sorting
	SortBy    APIKeySortField
	SortOrder SortOrder
}

// APIKeySortField defines fields that can be used for sorting API keys.
type APIKeySortField string

const (
	APIKeySortFieldCreatedAt  APIKeySortField = "created_at"
	APIKeySortFieldLastUsedAt APIKeySortField = "last_used_at"
	APIKeySortFieldName       APIKeySortField = "name"
	APIKeySortFieldExpiresAt  APIKeySortField = "expires_at"
)

// DefaultListAPIKeysParams returns default listing parameters.
func DefaultListAPIKeysParams() ListAPIKeysParams {
	return ListAPIKeysParams{
		Limit:      20,
		Offset:     0,
		UserID:     nil,
		TenantID:   nil,
		Status:     nil,
		ActiveOnly: true,
		SortBy:     APIKeySortFieldCreatedAt,
		SortOrder:  SortOrderDesc,
	}
}
