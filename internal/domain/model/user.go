package model

import (
	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

// UserStatus represents the status of a user account.
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
)

func (s UserStatus) String() string {
	return string(s)
}

func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusActive, UserStatusSuspended:
		return true
	default:
		return false
	}
}

// User is the root aggregate for identity.
type User struct {
	id        types.ID
	did       *security.DID
	email     types.Optional[types.Email]
	name      types.Optional[string]
	status    UserStatus
	createdAt types.Timestamp
	updatedAt types.Timestamp
}

// NewUser creates a new User aggregate.
func NewUser(did *security.DID) (*User, error) {
	if did == nil {
		return nil, domainerror.ErrUserDIDRequired
	}

	now := types.Now()

	return &User{
		id:        types.NewID(),
		did:       did,
		email:     types.None[types.Email](),
		name:      types.None[string](),
		status:    UserStatusActive,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// ReconstructUser creates a User from persisted data (bypasses validation).
// Used by repository when loading from database.
func ReconstructUser(
	id types.ID,
	did *security.DID,
	email types.Optional[types.Email],
	name types.Optional[string],
	status UserStatus,
	createdAt types.Timestamp,
	updatedAt types.Timestamp,
) *User {
	return &User{
		id:        id,
		did:       did,
		email:     email,
		name:      name,
		status:    status,
		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

// Getters

func (u *User) ID() types.ID                       { return u.id }
func (u *User) DID() *security.DID                 { return u.did }
func (u *User) Email() types.Optional[types.Email] { return u.email }
func (u *User) Name() types.Optional[string]       { return u.name }
func (u *User) Status() UserStatus                 { return u.status }
func (u *User) CreatedAt() types.Timestamp         { return u.createdAt }
func (u *User) UpdatedAt() types.Timestamp         { return u.updatedAt }

// Commands

func (u *User) SetEmail(email types.Email) {
	u.email = types.Some(email)
	u.updatedAt = types.Now()
}

func (u *User) ClearEmail() {
	u.email = types.None[types.Email]()
	u.updatedAt = types.Now()
}

func (u *User) SetName(name string) {
	u.name = types.Some(name)
	u.updatedAt = types.Now()
}

func (u *User) ClearName() {
	u.name = types.None[string]()
	u.updatedAt = types.Now()
}

func (u *User) Suspend() error {
	if u.status == UserStatusSuspended {
		return domainerror.ErrUserAlreadySuspended
	}
	u.status = UserStatusSuspended
	u.updatedAt = types.Now()
	return nil
}

func (u *User) Activate() error {
	if u.status == UserStatusActive {
		return domainerror.ErrUserAlreadyActive
	}
	u.status = UserStatusActive
	u.updatedAt = types.Now()
	return nil
}

// Queries

func (u *User) IsActive() bool {
	return u.status == UserStatusActive
}

func (u *User) IsSuspended() bool {
	return u.status == UserStatusSuspended
}

func (u *User) CanAuthenticate() error {
	if u.status == UserStatusSuspended {
		return domainerror.ErrUserSuspended
	}
	return nil
}
