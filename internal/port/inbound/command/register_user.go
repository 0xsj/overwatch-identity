package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// RegisterUser initiates user registration with a DID.
// Returns a challenge that must be signed to complete registration.
type RegisterUser struct {
	DID   string
	Email types.Optional[string]
	Name  types.Optional[string]
}

func (c RegisterUser) CommandName() string {
	return "identity.register_user"
}

// RegisterUserResult contains the challenge for the user to sign.
type RegisterUserResult struct {
	ChallengeID types.ID
	Nonce       string
	Message     string
	ExpiresAt   types.Timestamp
}

// RegisterUserHandler handles the RegisterUser command.
type RegisterUserHandler interface {
	Handle(ctx context.Context, cmd RegisterUser) (RegisterUserResult, error)
}
