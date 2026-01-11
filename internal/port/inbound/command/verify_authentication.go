package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// VerifyAuthentication completes authentication by verifying the signed challenge.
type VerifyAuthentication struct {
	ChallengeID types.ID
	DID         string
	Signature   string // Base64 encoded
	TenantID    types.Optional[types.ID]
}

func (c VerifyAuthentication) CommandName() string {
	return "identity.verify_authentication"
}

// VerifyAuthenticationResult contains the user and session tokens.
type VerifyAuthenticationResult struct {
	User                 *model.User
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt types.Timestamp
}

// VerifyAuthenticationHandler handles the VerifyAuthentication command.
type VerifyAuthenticationHandler interface {
	Handle(ctx context.Context, cmd VerifyAuthentication) (VerifyAuthenticationResult, error)
}
