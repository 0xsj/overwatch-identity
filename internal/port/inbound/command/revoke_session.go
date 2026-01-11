package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// RevokeSession revokes a specific session.
type RevokeSession struct {
	SessionID types.ID
	UserID    types.ID // The user requesting the revocation (for authorization)
	Reason    string
}

func (c RevokeSession) CommandName() string {
	return "identity.revoke_session"
}

// RevokeSessionResult is empty on success.
type RevokeSessionResult struct{}

// RevokeSessionHandler handles the RevokeSession command.
type RevokeSessionHandler interface {
	Handle(ctx context.Context, cmd RevokeSession) (RevokeSessionResult, error)
}
