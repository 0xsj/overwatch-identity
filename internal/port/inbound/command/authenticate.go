package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// Authenticate initiates authentication for an existing user.
// Returns a challenge that must be signed to complete authentication.
type Authenticate struct {
	DID string
}

func (c Authenticate) CommandName() string {
	return "identity.authenticate"
}

// AuthenticateResult contains the challenge for the user to sign.
type AuthenticateResult struct {
	ChallengeID types.ID
	Nonce       string
	Message     string
	ExpiresAt   types.Timestamp
}

// AuthenticateHandler handles the Authenticate command.
type AuthenticateHandler interface {
	Handle(ctx context.Context, cmd Authenticate) (AuthenticateResult, error)
}
