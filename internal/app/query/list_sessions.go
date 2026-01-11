package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// listSessionsHandler implements query.ListSessionsHandler.
type listSessionsHandler struct {
	sessionRepo repository.SessionRepository
}

// NewListSessionsHandler creates a new ListSessionsHandler.
func NewListSessionsHandler(
	sessionRepo repository.SessionRepository,
) query.ListSessionsHandler {
	return &listSessionsHandler{
		sessionRepo: sessionRepo,
	}
}

func (h *listSessionsHandler) Handle(ctx context.Context, qry query.ListSessions) (query.ListSessionsResult, error) {
	if qry.UserID.IsEmpty() {
		return query.ListSessionsResult{}, domainerror.ErrUserIDRequired
	}

	// Set defaults
	limit := qry.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := qry.Offset
	if offset < 0 {
		offset = 0
	}

	// Build params
	params := repository.ListSessionsParams{
		Limit:      limit,
		Offset:     offset,
		UserID:     &qry.UserID,
		ActiveOnly: qry.ActiveOnly,
		SortBy:     repository.SessionSortFieldCreatedAt,
		SortOrder:  repository.SortOrderDesc,
	}

	// Fetch sessions
	sessions, err := h.sessionRepo.List(ctx, params)
	if err != nil {
		return query.ListSessionsResult{}, err
	}

	// Fetch count
	totalCount, err := h.sessionRepo.Count(ctx, params)
	if err != nil {
		return query.ListSessionsResult{}, err
	}

	return query.ListSessionsResult{
		Sessions:   sessions,
		TotalCount: totalCount,
	}, nil
}
