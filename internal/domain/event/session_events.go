package event

import (
	"github.com/0xsj/overwatch-pkg/types"
)

// SessionCreated is emitted when a new session is created.
type SessionCreated struct {
	BaseEvent
	SessionID types.ID
	UserID    types.ID
	DID       string
	TenantID  types.Optional[types.ID]
}

// NewSessionCreated creates a new SessionCreated event.
func NewSessionCreated(
	sessionID types.ID,
	userID types.ID,
	did string,
	tenantID types.Optional[types.ID],
) SessionCreated {
	return SessionCreated{
		BaseEvent: NewBaseEvent(EventTypeSessionCreated, sessionID, AggregateTypeSession),
		SessionID: sessionID,
		UserID:    userID,
		DID:       did,
		TenantID:  tenantID,
	}
}

// SessionRevoked is emitted when a session is revoked.
type SessionRevoked struct {
	BaseEvent
	SessionID types.ID
	UserID    types.ID
	Reason    string
}

// NewSessionRevoked creates a new SessionRevoked event.
func NewSessionRevoked(sessionID types.ID, userID types.ID, reason string) SessionRevoked {
	return SessionRevoked{
		BaseEvent: NewBaseEvent(EventTypeSessionRevoked, sessionID, AggregateTypeSession),
		SessionID: sessionID,
		UserID:    userID,
		Reason:    reason,
	}
}

// AllSessionsRevoked is emitted when all sessions for a user are revoked.
type AllSessionsRevoked struct {
	BaseEvent
	UserID       types.ID
	RevokedCount int
}

// NewAllSessionsRevoked creates a new AllSessionsRevoked event.
func NewAllSessionsRevoked(userID types.ID, revokedCount int) AllSessionsRevoked {
	return AllSessionsRevoked{
		BaseEvent:    NewBaseEvent(EventTypeSessionsRevokedAll, userID, AggregateTypeUser),
		UserID:       userID,
		RevokedCount: revokedCount,
	}
}

// TokenRefreshed is emitted when an access token is refreshed.
type TokenRefreshed struct {
	BaseEvent
	SessionID types.ID
	UserID    types.ID
}

// NewTokenRefreshed creates a new TokenRefreshed event.
func NewTokenRefreshed(sessionID types.ID, userID types.ID) TokenRefreshed {
	return TokenRefreshed{
		BaseEvent: NewBaseEvent(EventTypeTokenRefreshed, sessionID, AggregateTypeSession),
		SessionID: sessionID,
		UserID:    userID,
	}
}
