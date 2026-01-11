package model

import (
	"strings"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

// APIKeyStatus represents the status of an API key.
type APIKeyStatus string

const (
	APIKeyStatusActive  APIKeyStatus = "active"
	APIKeyStatusRevoked APIKeyStatus = "revoked"
)

func (s APIKeyStatus) String() string {
	return string(s)
}

func (s APIKeyStatus) IsValid() bool {
	switch s {
	case APIKeyStatusActive, APIKeyStatusRevoked:
		return true
	default:
		return false
	}
}

// APIKey represents a non-interactive authentication credential.
// Uses security.APIKey for key generation and validation.
type APIKey struct {
	id         types.ID
	userID     types.ID
	name       string
	keyPrefix  string // First 8 chars for identification (from security.APIKey.Redacted)
	keyHash    string // SHA256 hash of full key
	scopes     []string
	status     APIKeyStatus
	tenantID   types.Optional[types.ID]
	expiresAt  types.Optional[types.Timestamp]
	lastUsedAt types.Optional[types.Timestamp]
	createdAt  types.Timestamp
	revokedAt  types.Optional[types.Timestamp]
}

// APIKeyWithSecret holds an APIKey and its plaintext secret (only at creation).
type APIKeyWithSecret struct {
	APIKey *APIKey
	Secret string // Full key, only available at creation
}

// NewAPIKey creates a new API key using security.APIKeyGenerator.
// Returns APIKeyWithSecret so the plaintext key can be returned to the user once.
func NewAPIKey(
	userID types.ID,
	name string,
	scopes []string,
	tenantID types.Optional[types.ID],
	expiresAt types.Optional[types.Timestamp],
) (*APIKeyWithSecret, error) {
	if userID.IsEmpty() {
		return nil, domainerror.ErrUserIDRequired
	}
	if strings.TrimSpace(name) == "" {
		return nil, domainerror.ErrAPIKeyNameRequired
	}

	// Generate key using security package
	generated, err := security.GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	now := types.Now()

	// Normalize scopes
	normalizedScopes := normalizeScopes(scopes)

	// Extract prefix (first 8 chars including "ow_")
	keyPrefix := generated.Key
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}

	apiKey := &APIKey{
		id:         types.NewID(),
		userID:     userID,
		name:       strings.TrimSpace(name),
		keyPrefix:  keyPrefix,
		keyHash:    generated.Hash,
		scopes:     normalizedScopes,
		status:     APIKeyStatusActive,
		tenantID:   tenantID,
		expiresAt:  expiresAt,
		lastUsedAt: types.None[types.Timestamp](),
		createdAt:  now,
		revokedAt:  types.None[types.Timestamp](),
	}

	return &APIKeyWithSecret{
		APIKey: apiKey,
		Secret: generated.Key,
	}, nil
}

// ReconstructAPIKey creates an APIKey from persisted data.
func ReconstructAPIKey(
	id types.ID,
	userID types.ID,
	name string,
	keyPrefix string,
	keyHash string,
	scopes []string,
	status APIKeyStatus,
	tenantID types.Optional[types.ID],
	expiresAt types.Optional[types.Timestamp],
	lastUsedAt types.Optional[types.Timestamp],
	createdAt types.Timestamp,
	revokedAt types.Optional[types.Timestamp],
) *APIKey {
	return &APIKey{
		id:         id,
		userID:     userID,
		name:       name,
		keyPrefix:  keyPrefix,
		keyHash:    keyHash,
		scopes:     scopes,
		status:     status,
		tenantID:   tenantID,
		expiresAt:  expiresAt,
		lastUsedAt: lastUsedAt,
		createdAt:  createdAt,
		revokedAt:  revokedAt,
	}
}

// Getters

func (k *APIKey) ID() types.ID                                { return k.id }
func (k *APIKey) UserID() types.ID                            { return k.userID }
func (k *APIKey) Name() string                                { return k.name }
func (k *APIKey) KeyPrefix() string                           { return k.keyPrefix }
func (k *APIKey) KeyHash() string                             { return k.keyHash }
func (k *APIKey) Scopes() []string                            { return k.scopes }
func (k *APIKey) Status() APIKeyStatus                        { return k.status }
func (k *APIKey) TenantID() types.Optional[types.ID]          { return k.tenantID }
func (k *APIKey) ExpiresAt() types.Optional[types.Timestamp]  { return k.expiresAt }
func (k *APIKey) LastUsedAt() types.Optional[types.Timestamp] { return k.lastUsedAt }
func (k *APIKey) CreatedAt() types.Timestamp                  { return k.createdAt }
func (k *APIKey) RevokedAt() types.Optional[types.Timestamp]  { return k.revokedAt }

// Commands

func (k *APIKey) Revoke() error {
	if k.IsRevoked() {
		return domainerror.ErrAPIKeyRevoked
	}
	k.status = APIKeyStatusRevoked
	k.revokedAt = types.Some(types.Now())
	return nil
}

func (k *APIKey) RecordUsage() {
	k.lastUsedAt = types.Some(types.Now())
}

// Queries

func (k *APIKey) IsActive() bool {
	return k.status == APIKeyStatusActive
}

func (k *APIKey) IsRevoked() bool {
	return k.status == APIKeyStatusRevoked
}

func (k *APIKey) IsExpired() bool {
	if k.expiresAt.IsEmpty() {
		return false
	}
	return types.Now().After(k.expiresAt.MustGet())
}

func (k *APIKey) IsValid() bool {
	return k.IsActive() && !k.IsExpired()
}

func (k *APIKey) Validate() error {
	if k.IsRevoked() {
		return domainerror.ErrAPIKeyRevoked
	}
	if k.IsExpired() {
		return domainerror.ErrAPIKeyExpired
	}
	return nil
}

// VerifyKey verifies the provided plaintext key against the stored hash.
func (k *APIKey) VerifyKey(plaintextKey string) error {
	if err := k.Validate(); err != nil {
		return err
	}
	if err := security.VerifyAPIKey(plaintextKey, k.keyHash); err != nil {
		return domainerror.ErrAPIKeyInvalid
	}
	return nil
}

func (k *APIKey) HasScope(scope string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	for _, s := range k.scopes {
		if s == scope {
			return true
		}
		// Wildcard support: "read:*" matches "read:sources"
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(scope, prefix) {
				return true
			}
		}
		// Full wildcard
		if s == "*" {
			return true
		}
	}
	return false
}

func (k *APIKey) HasAllScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !k.HasScope(scope) {
			return false
		}
	}
	return true
}

func (k *APIKey) HasAnyScope(scopes []string) bool {
	for _, scope := range scopes {
		if k.HasScope(scope) {
			return true
		}
	}
	return len(scopes) == 0
}

func (k *APIKey) HasTenant() bool {
	return k.tenantID.IsPresent()
}

// Helpers

func normalizeScopes(scopes []string) []string {
	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]bool)

	for _, scope := range scopes {
		s := strings.TrimSpace(strings.ToLower(scope))
		if s != "" && !seen[s] {
			normalized = append(normalized, s)
			seen[s] = true
		}
	}
	return normalized
}
