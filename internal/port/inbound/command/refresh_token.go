package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"
)

// RefreshToken exchanges a refresh token for new access and refresh tokens.
type RefreshToken struct {
	RefreshToken string
}

func (c RefreshToken) CommandName() string {
	return "identity.refresh_token"
}

// RefreshTokenResult contains the new tokens.
type RefreshTokenResult struct {
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt types.Timestamp
}

// RefreshTokenHandler handles the RefreshToken command.
type RefreshTokenHandler interface {
	Handle(ctx context.Context, cmd RefreshToken) (RefreshTokenResult, error)
}
