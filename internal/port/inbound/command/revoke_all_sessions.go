package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// RevokeAllSessions revokes all sessions for a user.
type RevokeAllSessions struct {
	UserID types.ID
}

func (c RevokeAllSessions) CommandName() string {
	return "identity.revoke_all_sessions"
}

// RevokeAllSessionsResult contains the count of revoked sessions.
type RevokeAllSessionsResult struct {
	RevokedCount int
}

// RevokeAllSessionsHandler handles the RevokeAllSessions command.
type RevokeAllSessionsHandler interface {
	Handle(ctx context.Context, cmd RevokeAllSessions) (RevokeAllSessionsResult, error)
}
