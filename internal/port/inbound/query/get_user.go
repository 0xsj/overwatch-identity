package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// GetUser retrieves a user by ID.
type GetUser struct {
	UserID types.ID
}

func (q GetUser) QueryName() string {
	return "identity.get_user"
}

// GetUserResult contains the user.
type GetUserResult struct {
	User *model.User
}

// GetUserHandler handles the GetUser query.
type GetUserHandler interface {
	Handle(ctx context.Context, qry GetUser) (GetUserResult, error)
}
