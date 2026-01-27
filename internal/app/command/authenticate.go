package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/security"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// authenticateHandler implements command.AuthenticateHandler.
type authenticateHandler struct {
	userRepo      repository.UserRepository
	challengeRepo repository.ChallengeRepository
	config        model.ChallengeConfig
}

// NewAuthenticateHandler creates a new AuthenticateHandler.
func NewAuthenticateHandler(
	userRepo repository.UserRepository,
	challengeRepo repository.ChallengeRepository,
	config model.ChallengeConfig,
) command.AuthenticateHandler {
	return &authenticateHandler{
		userRepo:      userRepo,
		challengeRepo: challengeRepo,
		config:        config,
	}
}

func (h *authenticateHandler) Handle(ctx context.Context, cmd command.Authenticate) (command.AuthenticateResult, error) {
	if err := security.ValidateDID(cmd.DID); err != nil {
		return command.AuthenticateResult{}, domainerror.ErrUserDIDRequired
	}
	// Parse and validate DID
	did, err := security.ParseDID(cmd.DID)
	if err != nil {
		return command.AuthenticateResult{}, domainerror.ErrUserDIDRequired
	}

	// Find user by DID
	user, err := h.userRepo.FindByDID(ctx, did.String())
	if err != nil {
		return command.AuthenticateResult{}, domainerror.ErrUserNotFound
	}

	// Check if user can authenticate
	if err := user.CanAuthenticate(); err != nil {
		return command.AuthenticateResult{}, err
	}

	// Clean up any existing challenges for this DID
	_ = h.challengeRepo.DeleteByDID(ctx, did.String())

	// Create challenge
	challenge, err := model.NewChallenge(did, model.ChallengePurposeAuthenticate, h.config)
	if err != nil {
		return command.AuthenticateResult{}, err
	}

	// Store challenge
	if err := h.challengeRepo.Create(ctx, challenge); err != nil {
		return command.AuthenticateResult{}, err
	}

	return command.AuthenticateResult{
		ChallengeID: challenge.ID(),
		Nonce:       challenge.Nonce(),
		Message:     challenge.Message(h.config.Domain),
		ExpiresAt:   challenge.ExpiresAt(),
	}, nil
}
