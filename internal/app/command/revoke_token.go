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

// TokenHasher provides refresh token hashing capability.
type TokenHasher interface {
	HashRefreshToken(token string) string
}

// revokeTokenHandler implements command.RevokeTokenHandler.
type revokeTokenHandler struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCache
	tokenHasher  TokenHasher
	publisher    messaging.EventPublisher
}

// NewRevokeTokenHandler creates a new RevokeTokenHandler.
func NewRevokeTokenHandler(
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCache,
	tokenHasher TokenHasher,
	publisher messaging.EventPublisher,
) command.RevokeTokenHandler {
	return &revokeTokenHandler{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		tokenHasher:  tokenHasher,
		publisher:    publisher,
	}
}

func (h *revokeTokenHandler) Handle(ctx context.Context, cmd command.RevokeToken) (command.RevokeTokenResult, error) {
	if cmd.RefreshToken == "" {
		return command.RevokeTokenResult{}, domainerror.ErrRefreshTokenRequired
	}

	// Hash the refresh token to look up the session
	tokenHash := h.tokenHasher.HashRefreshToken(cmd.RefreshToken)

	// Find session by refresh token hash
	session, err := h.sessionRepo.FindByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		if err == repository.ErrNotFound {
			return command.RevokeTokenResult{}, domainerror.ErrSessionNotFound
		}
		return command.RevokeTokenResult{}, err
	}

	// Check if already revoked
	if session.IsRevoked() {
		// Already revoked, return success (idempotent)
		return command.RevokeTokenResult{SessionID: session.ID().String()}, nil
	}

	// Revoke session
	if err := session.Revoke(); err != nil {
		return command.RevokeTokenResult{}, err
	}

	// Persist changes
	if err := h.sessionRepo.Update(ctx, session); err != nil {
		return command.RevokeTokenResult{}, err
	}

	// Invalidate cache
	_ = h.sessionCache.Delete(ctx, session.ID())

	// Publish event
	_ = h.publisher.Publish(ctx, event.NewSessionRevoked(session.ID(), session.UserID(), "logout"))

	return command.RevokeTokenResult{SessionID: session.ID().String()}, nil
}
