package command

import (
	"context"
	"encoding/base64"

	"github.com/0xsj/overwatch-pkg/security"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

// verifyAuthenticationHandler implements command.VerifyAuthenticationHandler.
type verifyAuthenticationHandler struct {
	userRepo      repository.UserRepository
	sessionRepo   repository.SessionRepository
	challengeRepo repository.ChallengeRepository
	tokenService  service.TokenService
	publisher     messaging.EventPublisher
	domain        string
	sessionConfig model.SessionConfig
}

// NewVerifyAuthenticationHandler creates a new VerifyAuthenticationHandler.
func NewVerifyAuthenticationHandler(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	challengeRepo repository.ChallengeRepository,
	tokenService service.TokenService,
	publisher messaging.EventPublisher,
	domain string,
	sessionConfig model.SessionConfig,
) command.VerifyAuthenticationHandler {
	return &verifyAuthenticationHandler{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		challengeRepo: challengeRepo,
		tokenService:  tokenService,
		publisher:     publisher,
		domain:        domain,
		sessionConfig: sessionConfig,
	}
}

func (h *verifyAuthenticationHandler) Handle(ctx context.Context, cmd command.VerifyAuthentication) (command.VerifyAuthenticationResult, error) {
	// Parse DID
	did, err := security.ParseDID(cmd.DID)
	if err != nil {
		return command.VerifyAuthenticationResult{}, domainerror.ErrUserDIDRequired
	}

	// Get challenge
	challenge, err := h.challengeRepo.FindByID(ctx, cmd.ChallengeID)
	if err != nil {
		// Publish failed auth event
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "challenge not found"))
		return command.VerifyAuthenticationResult{}, domainerror.ErrChallengeNotFound
	}

	// Validate challenge
	if err := challenge.ValidateFor(did); err != nil {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "challenge validation failed"))
		return command.VerifyAuthenticationResult{}, err
	}

	// Verify it's an authentication challenge
	if !challenge.IsForAuthentication() {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "invalid challenge purpose"))
		return command.VerifyAuthenticationResult{}, domainerror.ErrChallengeInvalid
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "invalid signature encoding"))
		return command.VerifyAuthenticationResult{}, domainerror.ErrSignatureInvalid
	}

	// Verify signature
	if err := challenge.VerifySignature(h.domain, signature); err != nil {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "signature verification failed"))
		return command.VerifyAuthenticationResult{}, err
	}

	// Delete challenge (prevent replay)
	_ = h.challengeRepo.Delete(ctx, cmd.ChallengeID)

	// Find user
	user, err := h.userRepo.FindByDID(ctx, did.String())
	if err != nil {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "user not found"))
		return command.VerifyAuthenticationResult{}, domainerror.ErrUserNotFound
	}

	// Check if user can authenticate
	if err := user.CanAuthenticate(); err != nil {
		_ = h.publisher.Publish(ctx, event.NewAuthenticationFailed(cmd.DID, "user suspended"))
		return command.VerifyAuthenticationResult{}, err
	}

	// Generate refresh token
	refreshToken, refreshTokenHash, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		return command.VerifyAuthenticationResult{}, err
	}

	// Create session
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		cmd.TenantID,
		refreshTokenHash,
		h.sessionConfig,
	)
	if err != nil {
		return command.VerifyAuthenticationResult{}, err
	}

	// Persist session
	if err := h.sessionRepo.Create(ctx, session); err != nil {
		return command.VerifyAuthenticationResult{}, err
	}

	// Generate access token
	accessToken, accessTokenExpiresAt, err := h.tokenService.GenerateAccessToken(user, session)
	if err != nil {
		return command.VerifyAuthenticationResult{}, err
	}

	// Publish events
	events := []event.Event{
		event.NewSessionCreated(
			session.ID(),
			user.ID(),
			user.DID().String(),
			cmd.TenantID,
		),
		event.NewAuthenticationSucceeded(
			user.ID(),
			user.DID().String(),
			session.ID(),
			event.AuthMethodDIDChallenge,
		),
	}
	_ = h.publisher.PublishAll(ctx, events)

	return command.VerifyAuthenticationResult{
		User:                 user,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: accessTokenExpiresAt,
	}, nil
}
