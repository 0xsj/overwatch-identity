package command

import (
	"context"
	"encoding/base64"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

// verifyRegistrationHandler implements command.VerifyRegistrationHandler.
type verifyRegistrationHandler struct {
	userRepo      repository.UserRepository
	sessionRepo   repository.SessionRepository
	challengeRepo repository.ChallengeRepository
	tokenService  service.TokenService
	publisher     messaging.EventPublisher
	domain        string
	sessionConfig model.SessionConfig
}

// NewVerifyRegistrationHandler creates a new VerifyRegistrationHandler.
func NewVerifyRegistrationHandler(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	challengeRepo repository.ChallengeRepository,
	tokenService service.TokenService,
	publisher messaging.EventPublisher,
	domain string,
	sessionConfig model.SessionConfig,
) command.VerifyRegistrationHandler {
	return &verifyRegistrationHandler{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		challengeRepo: challengeRepo,
		tokenService:  tokenService,
		publisher:     publisher,
		domain:        domain,
		sessionConfig: sessionConfig,
	}
}

func (h *verifyRegistrationHandler) Handle(ctx context.Context, cmd command.VerifyRegistration) (command.VerifyRegistrationResult, error) {
	// Parse DID
	did, err := security.ParseDID(cmd.DID)
	if err != nil {
		return command.VerifyRegistrationResult{}, domainerror.ErrUserDIDRequired
	}

	// Get challenge
	challenge, err := h.challengeRepo.FindByID(ctx, cmd.ChallengeID)
	if err != nil {
		return command.VerifyRegistrationResult{}, domainerror.ErrChallengeNotFound
	}

	// Validate challenge
	if err := challenge.ValidateFor(did); err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Verify it's a registration challenge
	if !challenge.IsForRegistration() {
		return command.VerifyRegistrationResult{}, domainerror.ErrChallengeInvalid
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return command.VerifyRegistrationResult{}, domainerror.ErrSignatureInvalid
	}

	// Verify signature
	if err := challenge.VerifySignature(h.domain, signature); err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Delete challenge (prevent replay)
	_ = h.challengeRepo.Delete(ctx, cmd.ChallengeID)

	// Check if user already exists (race condition check)
	exists, err := h.userRepo.ExistsByDID(ctx, did.String())
	if err != nil {
		return command.VerifyRegistrationResult{}, err
	}
	if exists {
		return command.VerifyRegistrationResult{}, domainerror.ErrUserAlreadyExists
	}

	// Create user
	user, err := model.NewUser(did)
	if err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Persist user
	if err := h.userRepo.Create(ctx, user); err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Generate refresh token
	refreshToken, refreshTokenHash, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Create session
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](), // No tenant for registration
		refreshTokenHash,
		h.sessionConfig,
	)
	if err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Persist session
	if err := h.sessionRepo.Create(ctx, session); err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Generate access token
	accessToken, accessTokenExpiresAt, err := h.tokenService.GenerateAccessToken(user, session)
	if err != nil {
		return command.VerifyRegistrationResult{}, err
	}

	// Publish events
	events := []event.Event{
		event.NewUserRegistered(
			user.ID(),
			user.DID().String(),
			types.None[string](),
			types.None[string](),
		),
		event.NewSessionCreated(
			session.ID(),
			user.ID(),
			user.DID().String(),
			types.None[types.ID](),
		),
		event.NewAuthenticationSucceeded(
			user.ID(),
			user.DID().String(),
			session.ID(),
			event.AuthMethodDIDChallenge,
		),
	}
	_ = h.publisher.PublishAll(ctx, events)

	return command.VerifyRegistrationResult{
		User:                 user,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: accessTokenExpiresAt,
	}, nil
}
