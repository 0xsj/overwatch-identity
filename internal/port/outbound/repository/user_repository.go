package repository

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// UserRepository defines the interface for user persistence.
type UserRepository interface {
	// Create persists a new user.
	Create(ctx context.Context, user *model.User) error

	// Update persists changes to an existing user.
	Update(ctx context.Context, user *model.User) error

	// FindByID retrieves a user by their ID.
	FindByID(ctx context.Context, id types.ID) (*model.User, error)

	// FindByDID retrieves a user by their DID.
	FindByDID(ctx context.Context, did string) (*model.User, error)

	// FindByEmail retrieves a user by their email.
	FindByEmail(ctx context.Context, email types.Email) (*model.User, error)

	// ExistsByDID checks if a user with the given DID exists.
	ExistsByDID(ctx context.Context, did string) (bool, error)

	// ExistsByEmail checks if a user with the given email exists.
	ExistsByEmail(ctx context.Context, email types.Email) (bool, error)

	// List retrieves users with pagination.
	List(ctx context.Context, params ListUsersParams) ([]*model.User, error)

	// Count returns the total number of users matching the filter.
	Count(ctx context.Context, params ListUsersParams) (int64, error)

	// Delete removes a user by ID.
	Delete(ctx context.Context, id types.ID) error
}

// ListUsersParams defines parameters for listing users.
type ListUsersParams struct {
	// Pagination
	Limit  int
	Offset int

	// Filters
	Status *model.UserStatus

	// Sorting
	SortBy    UserSortField
	SortOrder SortOrder
}

// UserSortField defines fields that can be used for sorting users.
type UserSortField string

const (
	UserSortFieldCreatedAt UserSortField = "created_at"
	UserSortFieldUpdatedAt UserSortField = "updated_at"
	UserSortFieldEmail     UserSortField = "email"
)

// SortOrder defines sort direction.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// DefaultListUsersParams returns default listing parameters.
func DefaultListUsersParams() ListUsersParams {
	return ListUsersParams{
		Limit:     20,
		Offset:    0,
		Status:    nil,
		SortBy:    UserSortFieldCreatedAt,
		SortOrder: SortOrderDesc,
	}
}
