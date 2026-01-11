package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// VerifyRegistration completes user registration by verifying the signed challenge.
type VerifyRegistration struct {
	ChallengeID types.ID
	DID         string
	Signature   string // Base64 encoded
}

func (c VerifyRegistration) CommandName() string {
	return "identity.verify_registration"
}

// VerifyRegistrationResult contains the new user and session tokens.
type VerifyRegistrationResult struct {
	User                 *model.User
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt types.Timestamp
}

// VerifyRegistrationHandler handles the VerifyRegistration command.
type VerifyRegistrationHandler interface {
	Handle(ctx context.Context, cmd VerifyRegistration) (VerifyRegistrationResult, error)
}
