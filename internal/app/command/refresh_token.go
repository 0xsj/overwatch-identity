package command

import (
	"context"
	"time"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

// refreshTokenHandler implements command.RefreshTokenHandler.
type refreshTokenHandler struct {
	userRepo        repository.UserRepository
	sessionRepo     repository.SessionRepository
	tokenService    service.TokenService
	publisher       messaging.EventPublisher
	sessionDuration time.Duration
}

// NewRefreshTokenHandler creates a new RefreshTokenHandler.
func NewRefreshTokenHandler(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	tokenService service.TokenService,
	publisher messaging.EventPublisher,
	sessionConfig model.SessionConfig,
) command.RefreshTokenHandler {
	return &refreshTokenHandler{
		userRepo:        userRepo,
		sessionRepo:     sessionRepo,
		tokenService:    tokenService,
		publisher:       publisher,
		sessionDuration: sessionConfig.SessionDuration,
	}
}

func (h *refreshTokenHandler) Handle(ctx context.Context, cmd command.RefreshToken) (command.RefreshTokenResult, error) {
	if cmd.RefreshToken == "" {
		return command.RefreshTokenResult{}, domainerror.ErrRefreshTokenInvalid
	}

	// Hash the provided refresh token
	tokenHash := h.tokenService.HashRefreshToken(cmd.RefreshToken)

	// Find session by refresh token hash
	session, err := h.sessionRepo.FindByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		return command.RefreshTokenResult{}, domainerror.ErrRefreshTokenInvalid
	}

	// Validate session
	if err := session.Validate(); err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Find user
	user, err := h.userRepo.FindByID(ctx, session.UserID())
	if err != nil {
		return command.RefreshTokenResult{}, domainerror.ErrUserNotFound
	}

	// Check if user can authenticate
	if err := user.CanAuthenticate(); err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Generate new refresh token
	newRefreshToken, newRefreshTokenHash, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Update session with new refresh token hash
	if err := session.Refresh(newRefreshTokenHash, h.sessionDuration); err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Persist updated session
	if err := h.sessionRepo.Update(ctx, session); err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Generate new access token
	accessToken, accessTokenExpiresAt, err := h.tokenService.GenerateAccessToken(user, session)
	if err != nil {
		return command.RefreshTokenResult{}, err
	}

	// Publish event
	_ = h.publisher.Publish(ctx, event.NewTokenRefreshed(session.ID(), user.ID()))

	return command.RefreshTokenResult{
		AccessToken:          accessToken,
		RefreshToken:         newRefreshToken,
		AccessTokenExpiresAt: accessTokenExpiresAt,
	}, nil
}
