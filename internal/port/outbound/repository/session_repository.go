package repository

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// SessionRepository defines the interface for session persistence.
type SessionRepository interface {
	// Create persists a new session.
	Create(ctx context.Context, session *model.Session) error

	// Update persists changes to an existing session.
	Update(ctx context.Context, session *model.Session) error

	// FindByID retrieves a session by its ID.
	FindByID(ctx context.Context, id types.ID) (*model.Session, error)

	// FindByRefreshTokenHash retrieves a session by refresh token hash.
	FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error)

	// FindActiveByUserID retrieves all active sessions for a user.
	FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.Session, error)

	// List retrieves sessions with pagination.
	List(ctx context.Context, params ListSessionsParams) ([]*model.Session, error)

	// Count returns the total number of sessions matching the filter.
	Count(ctx context.Context, params ListSessionsParams) (int64, error)

	// RevokeByID revokes a session by ID.
	RevokeByID(ctx context.Context, id types.ID) error

	// RevokeAllByUserID revokes all sessions for a user.
	// Returns the number of sessions revoked.
	RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error)

	// DeleteExpired removes all expired sessions.
	// Returns the number of sessions deleted.
	DeleteExpired(ctx context.Context) (int, error)
}

// ListSessionsParams defines parameters for listing sessions.
type ListSessionsParams struct {
	// Pagination
	Limit  int
	Offset int

	// Filters
	UserID     *types.ID
	TenantID   *types.ID
	ActiveOnly bool

	// Sorting
	SortBy    SessionSortField
	SortOrder SortOrder
}

// SessionSortField defines fields that can be used for sorting sessions.
type SessionSortField string

const (
	SessionSortFieldCreatedAt SessionSortField = "created_at"
	SessionSortFieldExpiresAt SessionSortField = "expires_at"
)

// DefaultListSessionsParams returns default listing parameters.
func DefaultListSessionsParams() ListSessionsParams {
	return ListSessionsParams{
		Limit:      20,
		Offset:     0,
		UserID:     nil,
		TenantID:   nil,
		ActiveOnly: true,
		SortBy:     SessionSortFieldCreatedAt,
		SortOrder:  SortOrderDesc,
	}
}
