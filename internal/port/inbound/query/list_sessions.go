package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// ListSessions retrieves sessions for a user.
type ListSessions struct {
	UserID     types.ID
	ActiveOnly bool
	Limit      int
	Offset     int
}

func (q ListSessions) QueryName() string {
	return "identity.list_sessions"
}

// ListSessionsResult contains the sessions and pagination info.
type ListSessionsResult struct {
	Sessions   []*model.Session
	TotalCount int64
}

// ListSessionsHandler handles the ListSessions query.
type ListSessionsHandler interface {
	Handle(ctx context.Context, qry ListSessions) (ListSessionsResult, error)
}
