package query

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// GetUserByDID retrieves a user by their DID.
type GetUserByDID struct {
	DID string
}

func (q GetUserByDID) QueryName() string {
	return "identity.get_user_by_did"
}

// GetUserByDIDResult contains the user.
type GetUserByDIDResult struct {
	User *model.User
}

// GetUserByDIDHandler handles the GetUserByDID query.
type GetUserByDIDHandler interface {
	Handle(ctx context.Context, qry GetUserByDID) (GetUserByDIDResult, error)
}
