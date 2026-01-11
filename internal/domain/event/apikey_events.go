package event

import (
	"github.com/0xsj/overwatch-pkg/types"
)

// APIKeyCreated is emitted when a new API key is created.
type APIKeyCreated struct {
	BaseEvent
	APIKeyID  types.ID
	UserID    types.ID
	Name      string
	Scopes    []string
	TenantID  types.Optional[types.ID]
	ExpiresAt types.Optional[types.Timestamp]
}

// NewAPIKeyCreated creates a new APIKeyCreated event.
func NewAPIKeyCreated(
	apiKeyID types.ID,
	userID types.ID,
	name string,
	scopes []string,
	tenantID types.Optional[types.ID],
	expiresAt types.Optional[types.Timestamp],
) APIKeyCreated {
	return APIKeyCreated{
		BaseEvent: NewBaseEvent(EventTypeAPIKeyCreated, apiKeyID, AggregateTypeAPIKey),
		APIKeyID:  apiKeyID,
		UserID:    userID,
		Name:      name,
		Scopes:    scopes,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	}
}

// APIKeyRevoked is emitted when an API key is revoked.
type APIKeyRevoked struct {
	BaseEvent
	APIKeyID types.ID
	UserID   types.ID
	Reason   string
}

// NewAPIKeyRevoked creates a new APIKeyRevoked event.
func NewAPIKeyRevoked(apiKeyID types.ID, userID types.ID, reason string) APIKeyRevoked {
	return APIKeyRevoked{
		BaseEvent: NewBaseEvent(EventTypeAPIKeyRevoked, apiKeyID, AggregateTypeAPIKey),
		APIKeyID:  apiKeyID,
		UserID:    userID,
		Reason:    reason,
	}
}

// APIKeyUsed is emitted when an API key is used for authentication.
type APIKeyUsed struct {
	BaseEvent
	APIKeyID types.ID
	UserID   types.ID
	Endpoint string
}

// NewAPIKeyUsed creates a new APIKeyUsed event.
func NewAPIKeyUsed(apiKeyID types.ID, userID types.ID, endpoint string) APIKeyUsed {
	return APIKeyUsed{
		BaseEvent: NewBaseEvent(EventTypeAPIKeyUsed, apiKeyID, AggregateTypeAPIKey),
		APIKeyID:  apiKeyID,
		UserID:    userID,
		Endpoint:  endpoint,
	}
}
