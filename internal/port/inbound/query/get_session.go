package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// GetSession retrieves a session by ID.
type GetSession struct {
	SessionID types.ID
	UserID    types.ID // For authorization - user can only see their own sessions
}

func (q GetSession) QueryName() string {
	return "identity.get_session"
}

// GetSessionResult contains the session.
type GetSessionResult struct {
	Session *model.Session
}

// GetSessionHandler handles the GetSession query.
type GetSessionHandler interface {
	Handle(ctx context.Context, qry GetSession) (GetSessionResult, error)
}
