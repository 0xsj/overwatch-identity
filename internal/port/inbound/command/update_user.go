package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// UpdateUser updates a user's profile.
type UpdateUser struct {
	UserID types.ID
	Email  types.Optional[types.Email]
	Name   types.Optional[string]
}

func (c UpdateUser) CommandName() string {
	return "identity.update_user"
}

// UpdateUserResult contains the updated user.
type UpdateUserResult struct {
	User          *model.User
	UpdatedFields []string
}

// UpdateUserHandler handles the UpdateUser command.
type UpdateUserHandler interface {
	Handle(ctx context.Context, cmd UpdateUser) (UpdateUserResult, error)
}
