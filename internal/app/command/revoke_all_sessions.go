package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// revokeAllSessionsHandler implements command.RevokeAllSessionsHandler.
type revokeAllSessionsHandler struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCache
	publisher    messaging.EventPublisher
}

// NewRevokeAllSessionsHandler creates a new RevokeAllSessionsHandler.
func NewRevokeAllSessionsHandler(
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCache,
	publisher messaging.EventPublisher,
) command.RevokeAllSessionsHandler {
	return &revokeAllSessionsHandler{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		publisher:    publisher,
	}
}

func (h *revokeAllSessionsHandler) Handle(ctx context.Context, cmd command.RevokeAllSessions) (command.RevokeAllSessionsResult, error) {
	if cmd.UserID.IsEmpty() {
		return command.RevokeAllSessionsResult{}, domainerror.ErrUserIDRequired
	}

	// Revoke all sessions in the repository
	revokedCount, err := h.sessionRepo.RevokeAllByUserID(ctx, cmd.UserID)
	if err != nil {
		return command.RevokeAllSessionsResult{}, err
	}

	// Invalidate all cached sessions for this user
	_ = h.sessionCache.DeleteByUserID(ctx, cmd.UserID)

	// Publish event
	_ = h.publisher.Publish(ctx, event.NewAllSessionsRevoked(cmd.UserID, revokedCount))

	return command.RevokeAllSessionsResult{
		RevokedCount: revokedCount,
	}, nil
}
