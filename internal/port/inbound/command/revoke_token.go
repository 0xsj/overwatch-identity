package command

import (
	"context"
)

// RevokeToken is the command to revoke a session by refresh token.
// This is used during logout to invalidate the user's session.
type RevokeToken struct {
	// RefreshToken is the raw refresh token (not hashed).
	RefreshToken string
}

// RevokeTokenResult is the result of revoking a token.
type RevokeTokenResult struct {
	// SessionID is the ID of the revoked session.
	SessionID string
}

// RevokeTokenHandler handles RevokeToken commands.
type RevokeTokenHandler interface {
	Handle(ctx context.Context, cmd RevokeToken) (RevokeTokenResult, error)
}
