package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/security"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// registerUserHandler implements command.RegisterUserHandler.
type registerUserHandler struct {
	userRepo      repository.UserRepository
	challengeRepo repository.ChallengeRepository
	config        model.ChallengeConfig
}

// NewRegisterUserHandler creates a new RegisterUserHandler.
func NewRegisterUserHandler(
	userRepo repository.UserRepository,
	challengeRepo repository.ChallengeRepository,
	config model.ChallengeConfig,
) command.RegisterUserHandler {
	return &registerUserHandler{
		userRepo:      userRepo,
		challengeRepo: challengeRepo,
		config:        config,
	}
}

func (h *registerUserHandler) Handle(ctx context.Context, cmd command.RegisterUser) (command.RegisterUserResult, error) {
	// Parse and validate DID
	did, err := security.ParseDID(cmd.DID)
	if err != nil {
		return command.RegisterUserResult{}, domainerror.ErrUserDIDRequired
	}

	// Check if user already exists
	exists, err := h.userRepo.ExistsByDID(ctx, did.String())
	if err != nil {
		return command.RegisterUserResult{}, err
	}
	if exists {
		return command.RegisterUserResult{}, domainerror.ErrUserAlreadyExists
	}

	// Clean up any existing challenges for this DID
	_ = h.challengeRepo.DeleteByDID(ctx, did.String())

	// Create challenge
	challenge, err := model.NewChallenge(did, model.ChallengePurposeRegister, h.config)
	if err != nil {
		return command.RegisterUserResult{}, err
	}

	// Store challenge
	if err := h.challengeRepo.Create(ctx, challenge); err != nil {
		return command.RegisterUserResult{}, err
	}

	return command.RegisterUserResult{
		ChallengeID: challenge.ID(),
		Nonce:       challenge.Nonce(),
		ExpiresAt:   challenge.ExpiresAt(),
	}, nil
}
