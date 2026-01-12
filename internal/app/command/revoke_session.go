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

// revokeSessionHandler implements command.RevokeSessionHandler.
type revokeSessionHandler struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCache
	publisher    messaging.EventPublisher
}

// NewRevokeSessionHandler creates a new RevokeSessionHandler.
func NewRevokeSessionHandler(
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCache,
	publisher messaging.EventPublisher,
) command.RevokeSessionHandler {
	return &revokeSessionHandler{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		publisher:    publisher,
	}
}

func (h *revokeSessionHandler) Handle(ctx context.Context, cmd command.RevokeSession) (command.RevokeSessionResult, error) {
	if cmd.SessionID.IsEmpty() {
		return command.RevokeSessionResult{}, domainerror.ErrSessionIDRequired
	}

	// Find session
	session, err := h.sessionRepo.FindByID(ctx, cmd.SessionID)
	if err != nil {
		return command.RevokeSessionResult{}, domainerror.ErrSessionNotFound
	}

	// Authorization: user can only revoke their own sessions
	if session.UserID() != cmd.UserID {
		return command.RevokeSessionResult{}, domainerror.ErrSessionNotFound
	}

	// Check if already revoked
	if session.IsRevoked() {
		return command.RevokeSessionResult{}, domainerror.ErrSessionRevoked
	}

	// Revoke session
	if err := session.Revoke(); err != nil {
		return command.RevokeSessionResult{}, err
	}

	// Persist changes
	if err := h.sessionRepo.Update(ctx, session); err != nil {
		return command.RevokeSessionResult{}, err
	}

	// Invalidate cache
	_ = h.sessionCache.Delete(ctx, cmd.SessionID)

	// Publish event
	reason := cmd.Reason
	if reason == "" {
		reason = "user requested"
	}
	_ = h.publisher.Publish(ctx, event.NewSessionRevoked(session.ID(), session.UserID(), reason))

	return command.RevokeSessionResult{}, nil
}
