package event

import (
	"github.com/0xsj/overwatch-pkg/types"
)

// OAuth event types
const (
	EventTypeOAuthLinked   = "oauth.linked"
	EventTypeOAuthUnlinked = "oauth.unlinked"
)

// OAuth auth method
const (
	AuthMethodOAuthGoogle AuthMethod = "oauth_google"
)

// Aggregate type for OAuth identity
const (
	AggregateTypeOAuthIdentity = "oauth_identity"
)

// OAuthLinked is emitted when an OAuth provider is linked to a user.
type OAuthLinked struct {
	BaseEvent
	UserID         types.ID
	Provider       string
	ProviderUserID string
	Email          string
}

// NewOAuthLinked creates a new OAuthLinked event.
func NewOAuthLinked(
	userID types.ID,
	provider string,
	providerUserID string,
	email string,
) OAuthLinked {
	return OAuthLinked{
		BaseEvent:      NewBaseEvent(EventTypeOAuthLinked, userID, AggregateTypeUser),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          email,
	}
}

// OAuthUnlinked is emitted when an OAuth provider is unlinked from a user.
type OAuthUnlinked struct {
	BaseEvent
	UserID   types.ID
	Provider string
}

// NewOAuthUnlinked creates a new OAuthUnlinked event.
func NewOAuthUnlinked(userID types.ID, provider string) OAuthUnlinked {
	return OAuthUnlinked{
		BaseEvent: NewBaseEvent(EventTypeOAuthUnlinked, userID, AggregateTypeUser),
		UserID:    userID,
		Provider:  provider,
	}
}
