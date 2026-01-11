package model

import (
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

// ChallengePurpose represents why the challenge was created.
type ChallengePurpose string

const (
	ChallengePurposeRegister     ChallengePurpose = "register"
	ChallengePurposeAuthenticate ChallengePurpose = "authenticate"
)

func (p ChallengePurpose) String() string {
	return string(p)
}

func (p ChallengePurpose) IsValid() bool {
	switch p {
	case ChallengePurposeRegister, ChallengePurposeAuthenticate:
		return true
	default:
		return false
	}
}

// Challenge represents an ephemeral authentication challenge.
// Used for DID-based authentication flow.
type Challenge struct {
	id        types.ID
	did       *security.DID
	nonce     string
	purpose   ChallengePurpose
	expiresAt types.Timestamp
	createdAt types.Timestamp
}

// ChallengeConfig holds configuration for challenge creation.
type ChallengeConfig struct {
	ChallengeDuration time.Duration
	NonceLength       int
}

// DefaultChallengeConfig returns default challenge configuration.
func DefaultChallengeConfig() ChallengeConfig {
	return ChallengeConfig{
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
}

// NewChallenge creates a new authentication challenge.
func NewChallenge(
	did *security.DID,
	purpose ChallengePurpose,
	config ChallengeConfig,
) (*Challenge, error) {
	if did == nil {
		return nil, domainerror.ErrUserDIDRequired
	}
	if !purpose.IsValid() {
		return nil, domainerror.ErrChallengeInvalid
	}

	// Generate cryptographic nonce
	nonce, err := security.RandomHex(config.NonceLength)
	if err != nil {
		return nil, err
	}

	now := types.Now()

	return &Challenge{
		id:        types.NewID(),
		did:       did,
		nonce:     nonce,
		purpose:   purpose,
		expiresAt: now.Add(config.ChallengeDuration),
		createdAt: now,
	}, nil
}

// ReconstructChallenge creates a Challenge from persisted data.
func ReconstructChallenge(
	id types.ID,
	did *security.DID,
	nonce string,
	purpose ChallengePurpose,
	expiresAt types.Timestamp,
	createdAt types.Timestamp,
) *Challenge {
	return &Challenge{
		id:        id,
		did:       did,
		nonce:     nonce,
		purpose:   purpose,
		expiresAt: expiresAt,
		createdAt: createdAt,
	}
}

// Getters

func (c *Challenge) ID() types.ID               { return c.id }
func (c *Challenge) DID() *security.DID         { return c.did }
func (c *Challenge) Nonce() string              { return c.nonce }
func (c *Challenge) Purpose() ChallengePurpose  { return c.purpose }
func (c *Challenge) ExpiresAt() types.Timestamp { return c.expiresAt }
func (c *Challenge) CreatedAt() types.Timestamp { return c.createdAt }

// Queries

func (c *Challenge) IsExpired() bool {
	return types.Now().After(c.expiresAt)
}

func (c *Challenge) IsValid() bool {
	return !c.IsExpired()
}

func (c *Challenge) Validate() error {
	if c.IsExpired() {
		return domainerror.ErrChallengeExpired
	}
	return nil
}

func (c *Challenge) ValidateFor(did *security.DID) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if did == nil || !c.did.Equals(did) {
		return domainerror.ErrChallengeDIDMismatch
	}
	return nil
}

func (c *Challenge) IsForRegistration() bool {
	return c.purpose == ChallengePurposeRegister
}

func (c *Challenge) IsForAuthentication() bool {
	return c.purpose == ChallengePurposeAuthenticate
}

func (c *Challenge) TimeUntilExpiry() time.Duration {
	return c.expiresAt.Time().Sub(types.Now().Time())
}

// Message returns the challenge message to be signed by the client.
// Format follows Sign-In with Ethereum (SIWE) style for familiarity.
func (c *Challenge) Message(domain string) string {
	return domain + " wants you to sign in with your DID:\n" +
		c.did.String() + "\n\n" +
		"Nonce: " + c.nonce + "\n" +
		"Issued At: " + c.createdAt.String() + "\n" +
		"Expiration Time: " + c.expiresAt.String()
}

// MessageBytes returns the challenge message as bytes for signing.
func (c *Challenge) MessageBytes(domain string) []byte {
	return []byte(c.Message(domain))
}

// VerifySignature verifies the signature against the challenge message.
// Extracts the public key from the DID and uses the appropriate KeyPair for verification.
func (c *Challenge) VerifySignature(domain string, signature []byte) error {
	if err := c.Validate(); err != nil {
		return err
	}

	if len(signature) == 0 {
		return domainerror.ErrSignatureRequired
	}

	// Only did:key supports direct signature verification
	if !c.did.IsKeyDID() {
		return domainerror.ErrSignatureInvalid
	}

	// Extract public key and algorithm from DID
	pubKeyBytes, alg, err := c.did.ExtractPublicKey()
	if err != nil {
		return domainerror.ErrSignatureInvalid
	}

	// Create appropriate KeyPair for verification
	var kp security.KeyPair
	switch alg {
	case security.AlgorithmEdDSA:
		kp, err = security.NewEd25519PublicKey(pubKeyBytes)
	case security.AlgorithmES256K:
		kp, err = security.NewSecp256k1FromPublicKey(pubKeyBytes)
	default:
		return domainerror.ErrSignatureInvalid
	}

	if err != nil {
		return domainerror.ErrSignatureInvalid
	}

	// Verify signature
	message := c.MessageBytes(domain)
	if err := kp.Verify(message, signature); err != nil {
		return domainerror.ErrSignatureInvalid
	}

	return nil
}
