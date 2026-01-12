package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// getSessionHandler implements query.GetSessionHandler.
type getSessionHandler struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCache
}

// NewGetSessionHandler creates a new GetSessionHandler.
func NewGetSessionHandler(
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCache,
) query.GetSessionHandler {
	return &getSessionHandler{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
	}
}

func (h *getSessionHandler) Handle(ctx context.Context, qry query.GetSession) (query.GetSessionResult, error) {
	if qry.SessionID.IsEmpty() {
		return query.GetSessionResult{}, domainerror.ErrSessionIDRequired
	}

	// Try cache first
	if h.sessionCache != nil {
		session, err := h.sessionCache.Get(ctx, qry.SessionID)
		if err == nil && session != nil {
			// Authorization: user can only see their own sessions
			if session.UserID() != qry.UserID {
				return query.GetSessionResult{}, domainerror.ErrSessionNotFound
			}
			return query.GetSessionResult{Session: session}, nil
		}
	}

	// Fallback to repository
	session, err := h.sessionRepo.FindByID(ctx, qry.SessionID)
	if err != nil {
		return query.GetSessionResult{}, domainerror.ErrSessionNotFound
	}

	// Authorization: user can only see their own sessions
	if session.UserID() != qry.UserID {
		return query.GetSessionResult{}, domainerror.ErrSessionNotFound
	}

	// Populate cache
	if h.sessionCache != nil {
		_ = h.sessionCache.Set(ctx, session, 0) // Use default TTL
	}

	return query.GetSessionResult{Session: session}, nil
}
