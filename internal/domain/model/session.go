package model

import (
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

// Session represents an authenticated user session.
// Created after successful DID challenge verification.
type Session struct {
	id               types.ID
	userID           types.ID
	userDID          *security.DID
	tenantID         types.Optional[types.ID]
	refreshTokenHash string
	expiresAt        types.Timestamp
	createdAt        types.Timestamp
	revokedAt        types.Optional[types.Timestamp]
}

// SessionConfig holds configuration for session creation.
type SessionConfig struct {
	SessionDuration time.Duration
}

// DefaultSessionConfig returns default session configuration.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		SessionDuration: 7 * 24 * time.Hour, // 7 days
	}
}

// NewSession creates a new Session.
func NewSession(
	userID types.ID,
	userDID *security.DID,
	tenantID types.Optional[types.ID],
	refreshTokenHash string,
	config SessionConfig,
) (*Session, error) {
	if userID.IsEmpty() {
		return nil, domainerror.ErrUserIDRequired
	}
	if userDID == nil {
		return nil, domainerror.ErrUserDIDRequired
	}
	if refreshTokenHash == "" {
		return nil, domainerror.ErrRefreshTokenInvalid
	}

	now := types.Now()

	return &Session{
		id:               types.NewID(),
		userID:           userID,
		userDID:          userDID,
		tenantID:         tenantID,
		refreshTokenHash: refreshTokenHash,
		expiresAt:        now.Add(config.SessionDuration),
		createdAt:        now,
		revokedAt:        types.None[types.Timestamp](),
	}, nil
}

// ReconstructSession creates a Session from persisted data.
func ReconstructSession(
	id types.ID,
	userID types.ID,
	userDID *security.DID,
	tenantID types.Optional[types.ID],
	refreshTokenHash string,
	expiresAt types.Timestamp,
	createdAt types.Timestamp,
	revokedAt types.Optional[types.Timestamp],
) *Session {
	return &Session{
		id:               id,
		userID:           userID,
		userDID:          userDID,
		tenantID:         tenantID,
		refreshTokenHash: refreshTokenHash,
		expiresAt:        expiresAt,
		createdAt:        createdAt,
		revokedAt:        revokedAt,
	}
}

// Getters

func (s *Session) ID() types.ID                               { return s.id }
func (s *Session) UserID() types.ID                           { return s.userID }
func (s *Session) UserDID() *security.DID                     { return s.userDID }
func (s *Session) TenantID() types.Optional[types.ID]         { return s.tenantID }
func (s *Session) RefreshTokenHash() string                   { return s.refreshTokenHash }
func (s *Session) ExpiresAt() types.Timestamp                 { return s.expiresAt }
func (s *Session) CreatedAt() types.Timestamp                 { return s.createdAt }
func (s *Session) RevokedAt() types.Optional[types.Timestamp] { return s.revokedAt }

// Commands

func (s *Session) Revoke() error {
	if s.IsRevoked() {
		return domainerror.ErrSessionRevoked
	}
	s.revokedAt = types.Some(types.Now())
	return nil
}

func (s *Session) Refresh(newRefreshTokenHash string, duration time.Duration) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if newRefreshTokenHash == "" {
		return domainerror.ErrRefreshTokenInvalid
	}

	now := types.Now()
	s.refreshTokenHash = newRefreshTokenHash
	s.expiresAt = now.Add(duration)
	return nil
}

// Queries

func (s *Session) IsExpired() bool {
	return types.Now().After(s.expiresAt)
}

func (s *Session) IsRevoked() bool {
	return s.revokedAt.IsPresent()
}

func (s *Session) IsValid() bool {
	return !s.IsExpired() && !s.IsRevoked()
}

func (s *Session) Validate() error {
	if s.IsRevoked() {
		return domainerror.ErrSessionRevoked
	}
	if s.IsExpired() {
		return domainerror.ErrSessionExpired
	}
	return nil
}

func (s *Session) ValidateRefreshToken(hash string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.refreshTokenHash != hash {
		return domainerror.ErrRefreshTokenInvalid
	}
	return nil
}

func (s *Session) TimeUntilExpiry() time.Duration {
	return s.expiresAt.Time().Sub(types.Now().Time())
}

func (s *Session) HasTenant() bool {
	return s.tenantID.IsPresent()
}
