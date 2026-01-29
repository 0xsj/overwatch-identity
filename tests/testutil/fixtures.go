package testutil

import (
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// Fixtures provides builders for domain models in tests.
var Fixtures = &fixtures{}

type fixtures struct{}

// --- DID / KeyPair ---

// KeyPair generates a new Ed25519 keypair.
func (f *fixtures) KeyPair() security.KeyPair {
	kp, err := security.GenerateEd25519()
	if err != nil {
		panic("fixtures: failed to generate keypair: " + err.Error())
	}
	return kp
}

// DID generates a valid DID from a new keypair.
func (f *fixtures) DID() *security.DID {
	kp := f.KeyPair()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		panic("fixtures: failed to create DID: " + err.Error())
	}
	return did
}

// DIDWithKeyPair generates a DID and returns both the DID and keypair.
// Useful when you need to sign challenges.
func (f *fixtures) DIDWithKeyPair() (*security.DID, security.KeyPair) {
	kp := f.KeyPair()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		panic("fixtures: failed to create DID: " + err.Error())
	}
	return did, kp
}

// --- User ---

// User creates a new User with default values.
func (f *fixtures) User() *model.User {
	user, err := model.NewUser(f.DID())
	if err != nil {
		panic("fixtures: failed to create user: " + err.Error())
	}
	return user
}

// UserBuilder returns a builder for customizing User creation.
func (f *fixtures) UserBuilder() *UserBuilder {
	return &UserBuilder{
		did: f.DID(),
	}
}

type UserBuilder struct {
	did       *security.DID
	email     types.Optional[types.Email]
	name      types.Optional[string]
	status    model.UserStatus
	createdAt types.Timestamp
	updatedAt types.Timestamp

	// For reconstruction
	id          types.ID
	reconstruct bool
}

func (b *UserBuilder) WithDID(did *security.DID) *UserBuilder {
	b.did = did
	return b
}

func (b *UserBuilder) WithEmail(email string) *UserBuilder {
	e, err := types.NewEmail(email)
	if err != nil {
		panic("fixtures: invalid email: " + err.Error())
	}
	b.email = types.Some(e)
	return b
}

func (b *UserBuilder) WithName(name string) *UserBuilder {
	b.name = types.Some(name)
	return b
}

func (b *UserBuilder) WithStatus(status model.UserStatus) *UserBuilder {
	b.status = status
	b.reconstruct = true
	return b
}

func (b *UserBuilder) Suspended() *UserBuilder {
	return b.WithStatus(model.UserStatusSuspended)
}

func (b *UserBuilder) WithID(id types.ID) *UserBuilder {
	b.id = id
	b.reconstruct = true
	return b
}

func (b *UserBuilder) WithCreatedAt(t time.Time) *UserBuilder {
	b.createdAt = types.FromTime(t)
	b.reconstruct = true
	return b
}

func (b *UserBuilder) Build() *model.User {
	if b.reconstruct {
		id := b.id
		if id.IsEmpty() {
			id = types.NewID()
		}
		status := b.status
		if status == "" {
			status = model.UserStatusActive
		}
		createdAt := b.createdAt
		if createdAt.IsZero() {
			createdAt = types.Now()
		}
		updatedAt := b.updatedAt
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}

		return model.ReconstructUser(
			id,
			b.did,
			b.email,
			b.name,
			status,
			createdAt,
			updatedAt,
		)
	}

	user, err := model.NewUser(b.did)
	if err != nil {
		panic("fixtures: failed to create user: " + err.Error())
	}

	if b.email.IsPresent() {
		user.SetEmail(b.email.MustGet())
	}
	if b.name.IsPresent() {
		user.SetName(b.name.MustGet())
	}

	return user
}

// --- Session ---

// Session creates a new Session with default values.
func (f *fixtures) Session(userID types.ID, userDID *security.DID) *model.Session {
	hash := Fake.Hex(32)
	session, err := model.NewSession(
		userID,
		userDID,
		types.None[types.ID](),
		hash,
		model.DefaultSessionConfig(),
	)
	if err != nil {
		panic("fixtures: failed to create session: " + err.Error())
	}
	return session
}

// SessionBuilder returns a builder for customizing Session creation.
func (f *fixtures) SessionBuilder(userID types.ID, userDID *security.DID) *SessionBuilder {
	return &SessionBuilder{
		userID:           userID,
		userDID:          userDID,
		tenantID:         types.None[types.ID](),
		refreshTokenHash: Fake.Hex(32),
		config:           model.DefaultSessionConfig(),
	}
}

type SessionBuilder struct {
	userID           types.ID
	userDID          *security.DID
	tenantID         types.Optional[types.ID]
	refreshTokenHash string
	config           model.SessionConfig

	// For reconstruction
	id          types.ID
	expiresAt   types.Timestamp
	createdAt   types.Timestamp
	revokedAt   types.Optional[types.Timestamp]
	reconstruct bool
}

func (b *SessionBuilder) WithTenantID(tenantID types.ID) *SessionBuilder {
	b.tenantID = types.Some(tenantID)
	return b
}

func (b *SessionBuilder) WithRefreshTokenHash(hash string) *SessionBuilder {
	b.refreshTokenHash = hash
	return b
}

func (b *SessionBuilder) WithDuration(d time.Duration) *SessionBuilder {
	b.config.SessionDuration = d
	return b
}

func (b *SessionBuilder) WithID(id types.ID) *SessionBuilder {
	b.id = id
	b.reconstruct = true
	return b
}

func (b *SessionBuilder) Expired() *SessionBuilder {
	b.expiresAt = types.FromTime(time.Now().Add(-time.Hour))
	b.reconstruct = true
	return b
}

func (b *SessionBuilder) Revoked() *SessionBuilder {
	b.revokedAt = types.Some(types.Now())
	b.reconstruct = true
	return b
}

func (b *SessionBuilder) Build() *model.Session {
	if b.reconstruct {
		id := b.id
		if id.IsEmpty() {
			id = types.NewID()
		}
		createdAt := b.createdAt
		if createdAt.IsZero() {
			createdAt = types.Now()
		}
		expiresAt := b.expiresAt
		if expiresAt.IsZero() {
			expiresAt = createdAt.Add(b.config.SessionDuration)
		}

		return model.ReconstructSession(
			id,
			b.userID,
			b.userDID,
			b.tenantID,
			b.refreshTokenHash,
			expiresAt,
			createdAt,
			b.revokedAt,
		)
	}

	session, err := model.NewSession(
		b.userID,
		b.userDID,
		b.tenantID,
		b.refreshTokenHash,
		b.config,
	)
	if err != nil {
		panic("fixtures: failed to create session: " + err.Error())
	}
	return session
}

// --- APIKey ---

// APIKey creates a new APIKey with default values.
// Returns APIKeyWithSecret so tests can access the plaintext key.
func (f *fixtures) APIKey(userID types.ID) *model.APIKeyWithSecret {
	apiKey, err := model.NewAPIKey(
		userID,
		Fake.String("test-key"),
		Fake.Scopes(),
		types.None[types.ID](),
		types.None[types.Timestamp](),
	)
	if err != nil {
		panic("fixtures: failed to create apikey: " + err.Error())
	}
	return apiKey
}

// APIKeyBuilder returns a builder for customizing APIKey creation.
func (f *fixtures) APIKeyBuilder(userID types.ID) *APIKeyBuilder {
	return &APIKeyBuilder{
		userID:    userID,
		name:      Fake.String("test-key"),
		scopes:    []string{"read:users"},
		tenantID:  types.None[types.ID](),
		expiresAt: types.None[types.Timestamp](),
	}
}

type APIKeyBuilder struct {
	userID    types.ID
	name      string
	scopes    []string
	tenantID  types.Optional[types.ID]
	expiresAt types.Optional[types.Timestamp]

	// For reconstruction
	id          types.ID
	keyPrefix   string
	keyHash     string
	status      model.APIKeyStatus
	lastUsedAt  types.Optional[types.Timestamp]
	createdAt   types.Timestamp
	revokedAt   types.Optional[types.Timestamp]
	reconstruct bool
}

func (b *APIKeyBuilder) WithName(name string) *APIKeyBuilder {
	b.name = name
	return b
}

func (b *APIKeyBuilder) WithScopes(scopes ...string) *APIKeyBuilder {
	b.scopes = scopes
	return b
}

func (b *APIKeyBuilder) WithTenantID(tenantID types.ID) *APIKeyBuilder {
	b.tenantID = types.Some(tenantID)
	return b
}

func (b *APIKeyBuilder) WithExpiry(t time.Time) *APIKeyBuilder {
	b.expiresAt = types.Some(types.FromTime(t))
	return b
}

func (b *APIKeyBuilder) ExpiresIn(d time.Duration) *APIKeyBuilder {
	b.expiresAt = types.Some(types.FromTime(time.Now().Add(d)))
	return b
}

func (b *APIKeyBuilder) Expired() *APIKeyBuilder {
	b.expiresAt = types.Some(types.FromTime(time.Now().Add(-time.Hour)))
	b.reconstruct = true
	return b
}

func (b *APIKeyBuilder) Revoked() *APIKeyBuilder {
	b.status = model.APIKeyStatusRevoked
	b.revokedAt = types.Some(types.Now())
	b.reconstruct = true
	return b
}

func (b *APIKeyBuilder) WithID(id types.ID) *APIKeyBuilder {
	b.id = id
	b.reconstruct = true
	return b
}

func (b *APIKeyBuilder) Build() *model.APIKeyWithSecret {
	if b.reconstruct {
		id := b.id
		if id.IsEmpty() {
			id = types.NewID()
		}
		status := b.status
		if status == "" {
			status = model.APIKeyStatusActive
		}
		createdAt := b.createdAt
		if createdAt.IsZero() {
			createdAt = types.Now()
		}
		keyPrefix := b.keyPrefix
		if keyPrefix == "" {
			keyPrefix = "ow_test_"
		}
		keyHash := b.keyHash
		if keyHash == "" {
			keyHash = Fake.Hex(32)
		}

		apiKey := model.ReconstructAPIKey(
			id,
			b.userID,
			b.name,
			keyPrefix,
			keyHash,
			b.scopes,
			status,
			b.tenantID,
			b.expiresAt,
			b.lastUsedAt,
			createdAt,
			b.revokedAt,
		)

		return &model.APIKeyWithSecret{
			APIKey: apiKey,
			Secret: "", // Not available for reconstructed keys
		}
	}

	apiKey, err := model.NewAPIKey(
		b.userID,
		b.name,
		b.scopes,
		b.tenantID,
		b.expiresAt,
	)
	if err != nil {
		panic("fixtures: failed to create apikey: " + err.Error())
	}
	return apiKey
}

// --- Challenge ---

// Challenge creates a new Challenge with default values.
func (f *fixtures) Challenge(purpose model.ChallengePurpose) *model.Challenge {
	challenge, err := model.NewChallenge(
		f.DID(),
		purpose,
		model.DefaultChallengeConfig(),
	)
	if err != nil {
		panic("fixtures: failed to create challenge: " + err.Error())
	}
	return challenge
}

// ChallengeBuilder returns a builder for customizing Challenge creation.
func (f *fixtures) ChallengeBuilder() *ChallengeBuilder {
	return &ChallengeBuilder{
		did:     f.DID(),
		purpose: model.ChallengePurposeAuthenticate,
		config:  model.DefaultChallengeConfig(),
	}
}

type ChallengeBuilder struct {
	did     *security.DID
	purpose model.ChallengePurpose
	config  model.ChallengeConfig

	// For reconstruction
	id          types.ID
	nonce       string
	expiresAt   types.Timestamp
	createdAt   types.Timestamp
	reconstruct bool
}

func (b *ChallengeBuilder) WithDID(did *security.DID) *ChallengeBuilder {
	b.did = did
	return b
}

func (b *ChallengeBuilder) ForRegistration() *ChallengeBuilder {
	b.purpose = model.ChallengePurposeRegister
	return b
}

func (b *ChallengeBuilder) ForAuthentication() *ChallengeBuilder {
	b.purpose = model.ChallengePurposeAuthenticate
	return b
}

func (b *ChallengeBuilder) WithDuration(d time.Duration) *ChallengeBuilder {
	b.config.ChallengeDuration = d
	return b
}

func (b *ChallengeBuilder) WithDomain(domain string) *ChallengeBuilder {
	b.config.Domain = domain
	return b
}

func (b *ChallengeBuilder) WithID(id types.ID) *ChallengeBuilder {
	b.id = id
	b.reconstruct = true
	return b
}

func (b *ChallengeBuilder) Expired() *ChallengeBuilder {
	b.expiresAt = types.FromTime(time.Now().Add(-time.Hour))
	b.reconstruct = true
	return b
}

func (b *ChallengeBuilder) Build() *model.Challenge {
	if b.reconstruct {
		id := b.id
		if id.IsEmpty() {
			id = types.NewID()
		}
		nonce := b.nonce
		if nonce == "" {
			nonce = Fake.Nonce(32)
		}
		createdAt := b.createdAt
		if createdAt.IsZero() {
			createdAt = types.Now()
		}
		expiresAt := b.expiresAt
		if expiresAt.IsZero() {
			expiresAt = createdAt.Add(b.config.ChallengeDuration)
		}

		return model.ReconstructChallenge(
			id,
			b.did,
			nonce,
			b.purpose,
			expiresAt,
			createdAt,
		)
	}

	challenge, err := model.NewChallenge(b.did, b.purpose, b.config)
	if err != nil {
		panic("fixtures: failed to create challenge: " + err.Error())
	}
	return challenge
}
