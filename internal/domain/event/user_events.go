package event

import (
	"github.com/0xsj/overwatch-pkg/types"
)

// UserRegistered is emitted when a new user registers.
type UserRegistered struct {
	BaseEvent
	UserID types.ID
	DID    string
	Email  types.Optional[string]
	Name   types.Optional[string]
}

// NewUserRegistered creates a new UserRegistered event.
func NewUserRegistered(
	userID types.ID,
	did string,
	email types.Optional[string],
	name types.Optional[string],
) UserRegistered {
	return UserRegistered{
		BaseEvent: NewBaseEvent(EventTypeUserRegistered, userID, AggregateTypeUser),
		UserID:    userID,
		DID:       did,
		Email:     email,
		Name:      name,
	}
}

// UserUpdated is emitted when a user's profile is updated.
type UserUpdated struct {
	BaseEvent
	UserID        types.ID
	UpdatedFields []string
}

// NewUserUpdated creates a new UserUpdated event.
func NewUserUpdated(userID types.ID, updatedFields []string) UserUpdated {
	return UserUpdated{
		BaseEvent:     NewBaseEvent(EventTypeUserUpdated, userID, AggregateTypeUser),
		UserID:        userID,
		UpdatedFields: updatedFields,
	}
}

// UserSuspended is emitted when a user account is suspended.
type UserSuspended struct {
	BaseEvent
	UserID types.ID
	Reason string
}

// NewUserSuspended creates a new UserSuspended event.
func NewUserSuspended(userID types.ID, reason string) UserSuspended {
	return UserSuspended{
		BaseEvent: NewBaseEvent(EventTypeUserSuspended, userID, AggregateTypeUser),
		UserID:    userID,
		Reason:    reason,
	}
}

// UserActivated is emitted when a suspended user account is reactivated.
type UserActivated struct {
	BaseEvent
	UserID types.ID
}

// NewUserActivated creates a new UserActivated event.
func NewUserActivated(userID types.ID) UserActivated {
	return UserActivated{
		BaseEvent: NewBaseEvent(EventTypeUserActivated, userID, AggregateTypeUser),
		UserID:    userID,
	}
}

// AuthenticationSucceeded is emitted when a user successfully authenticates.
type AuthenticationSucceeded struct {
	BaseEvent
	UserID    types.ID
	DID       string
	SessionID types.ID
	Method    AuthMethod
}

// AuthMethod represents how the user authenticated.
type AuthMethod string

const (
	AuthMethodDIDChallenge AuthMethod = "did_challenge"
	AuthMethodAPIKey       AuthMethod = "api_key"
	AuthMethodRefreshToken AuthMethod = "refresh_token"
)

// NewAuthenticationSucceeded creates a new AuthenticationSucceeded event.
func NewAuthenticationSucceeded(
	userID types.ID,
	did string,
	sessionID types.ID,
	method AuthMethod,
) AuthenticationSucceeded {
	return AuthenticationSucceeded{
		BaseEvent: NewBaseEvent(EventTypeAuthenticationSucceeded, userID, AggregateTypeUser),
		UserID:    userID,
		DID:       did,
		SessionID: sessionID,
		Method:    method,
	}
}

// AuthenticationFailed is emitted when an authentication attempt fails.
type AuthenticationFailed struct {
	BaseEvent
	DID    string
	Reason string
}

// NewAuthenticationFailed creates a new AuthenticationFailed event.
func NewAuthenticationFailed(did string, reason string) AuthenticationFailed {
	// Use a zero ID since there's no user aggregate for failed auth
	return AuthenticationFailed{
		BaseEvent: NewBaseEvent(EventTypeAuthenticationFailed, types.ID(""), AggregateTypeUser),
		DID:       did,
		Reason:    reason,
	}
}
