//go:build contract

package contract_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/0xsj/overwatch-pkg/security"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

var (
	client   identityv1.IdentityServiceClient
	natsConn *nats.Conn
)

func TestMain(m *testing.M) {
	grpcAddr := os.Getenv("IDENTITY_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = "localhost:50051"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4230"
	}

	// Connect to gRPC
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic("failed to connect to identity service: " + err.Error())
	}
	defer conn.Close()

	client = identityv1.NewIdentityServiceClient(conn)

	// Connect to NATS
	natsConn, err = nats.Connect(natsURL)
	if err != nil {
		panic("failed to connect to NATS: " + err.Error())
	}
	defer natsConn.Close()

	os.Exit(m.Run())
}

// ============================================================================
// Event Envelope Schema (Signed)
// ============================================================================

// SignedEnvelope matches the structure published by Identity service
type SignedEnvelope struct {
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"`
	OccurredAt time.Time       `json:"occurred_at"`
	SignedAt   time.Time       `json:"signed_at"`
	SignerDID  string          `json:"signer_did"`
	SignerType string          `json:"signer_type"`
	SignerID   string          `json:"signer_id,omitempty"`
	Payload    json.RawMessage `json:"payload"`
	Signature  string          `json:"signature"`
}

// UserRegisteredPayload is the expected payload for user.registered events
type UserRegisteredPayload struct {
	UserID string `json:"UserID"`
	DID    string `json:"DID"`
}

// SessionCreatedPayload is the expected payload for session.created events
type SessionCreatedPayload struct {
	SessionID string `json:"SessionID"`
	UserID    string `json:"UserID"`
	DID       string `json:"DID"`
}

// APIKeyCreatedPayload is the expected payload for apikey.created events
type APIKeyCreatedPayload struct {
	APIKeyID string   `json:"APIKeyID"`
	UserID   string   `json:"UserID"`
	Name     string   `json:"Name"`
	Scopes   []string `json:"Scopes"`
}

// SessionRevokedPayload is the expected payload for session.revoked events
type SessionRevokedPayload struct {
	SessionID string `json:"SessionID"`
	UserID    string `json:"UserID"`
	Reason    string `json:"Reason"`
}

// APIKeyRevokedPayload is the expected payload for apikey.revoked events
type APIKeyRevokedPayload struct {
	APIKeyID string `json:"APIKeyID"`
	UserID   string `json:"UserID"`
	Reason   string `json:"Reason"`
}

// ============================================================================
// Contract Tests
// ============================================================================

func TestUserRegisteredEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Subscribe to user events before triggering
	sub, err := natsConn.SubscribeSync("overwatch.identity.user")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Drain any existing messages
	drainSubscription(sub)

	// Trigger: Register a new user
	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(registerResp.Message))
	verifyResp, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("VerifyRegistration failed: %v", err)
	}

	userID := verifyResp.User.Id

	// Wait for event
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("did not receive event: %v", err)
	}

	// Parse envelope
	var envelope SignedEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	// Verify envelope fields
	if envelope.EventType != "user.registered" {
		t.Errorf("EventType = %s, want user.registered", envelope.EventType)
	}
	if envelope.EventID == "" {
		t.Error("EventID should not be empty")
	}
	if envelope.OccurredAt.IsZero() {
		t.Error("OccurredAt should not be zero")
	}
	if envelope.SignedAt.IsZero() {
		t.Error("SignedAt should not be zero")
	}
	if envelope.SignerDID == "" {
		t.Error("SignerDID should not be empty")
	}
	if envelope.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Parse payload
	var payload UserRegisteredPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload.UserID != userID {
		t.Errorf("Payload.UserID = %s, want %s", payload.UserID, userID)
	}
	if payload.DID != did.String() {
		t.Errorf("Payload.DID = %s, want %s", payload.DID, did.String())
	}

	t.Logf("✓ user.registered event received: %s (signed by %s)", envelope.EventID, envelope.SignerDID)
}

func TestSessionCreatedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First register a user
	keyPair, did := mustRegisterUser(t, ctx)

	// Subscribe to session events
	sub, err := natsConn.SubscribeSync("overwatch.identity.session")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Drain any existing messages
	drainSubscription(sub)

	// Trigger: Authenticate (creates a session)
	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(authResp.Message))
	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	userID := verifyResp.User.Id

	// Wait for event
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("did not receive event: %v", err)
	}

	// Parse envelope
	var envelope SignedEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	// Verify envelope
	if envelope.EventType != "session.created" {
		t.Errorf("EventType = %s, want session.created", envelope.EventType)
	}
	if envelope.SignerDID == "" {
		t.Error("SignerDID should not be empty")
	}
	if envelope.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Parse payload
	var payload SessionCreatedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload.UserID != userID {
		t.Errorf("Payload.UserID = %s, want %s", payload.UserID, userID)
	}
	if payload.DID != did.String() {
		t.Errorf("Payload.DID = %s, want %s", payload.DID, did.String())
	}
	if payload.SessionID == "" {
		t.Error("Payload.SessionID should not be empty")
	}

	t.Logf("✓ session.created event received: %s (signed by %s)", envelope.EventID, envelope.SignerDID)
}

func TestAPIKeyCreatedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)

	// Subscribe to apikey events
	sub, err := natsConn.SubscribeSync("overwatch.identity.apikey")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Drain any existing messages
	drainSubscription(sub)

	// Trigger: Create API key
	authCtx := withAuthToken(ctx, accessToken)
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:   "contract-test-key",
		Scopes: []string{"read:entities", "write:entities"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	apiKeyID := createResp.ApiKey.Id

	// Wait for event
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("did not receive event: %v", err)
	}

	// Parse envelope
	var envelope SignedEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	// Verify envelope
	if envelope.EventType != "apikey.created" {
		t.Errorf("EventType = %s, want apikey.created", envelope.EventType)
	}
	if envelope.SignerDID == "" {
		t.Error("SignerDID should not be empty")
	}
	if envelope.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Parse payload
	var payload APIKeyCreatedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload.APIKeyID != apiKeyID {
		t.Errorf("Payload.APIKeyID = %s, want %s", payload.APIKeyID, apiKeyID)
	}
	if payload.Name != "contract-test-key" {
		t.Errorf("Payload.Name = %s, want contract-test-key", payload.Name)
	}
	if len(payload.Scopes) != 2 {
		t.Errorf("Payload.Scopes length = %d, want 2", len(payload.Scopes))
	}

	t.Logf("✓ apikey.created event received: %s (signed by %s)", envelope.EventID, envelope.SignerDID)
}

func TestSessionRevokedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and create multiple sessions
	keyPair, did := mustRegisterUser(t, ctx)

	// Create first session
	authResp1, _ := client.Authenticate(ctx, &identityv1.AuthenticateRequest{Did: did.String()})
	sig1, _ := keyPair.Sign([]byte(authResp1.Message))
	verifyResp1, _ := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp1.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(sig1),
	})
	token1 := verifyResp1.AccessToken

	// Create second session
	authResp2, _ := client.Authenticate(ctx, &identityv1.AuthenticateRequest{Did: did.String()})
	sig2, _ := keyPair.Sign([]byte(authResp2.Message))
	verifyResp2, _ := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp2.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(sig2),
	})
	token2 := verifyResp2.AccessToken

	// Get session ID to revoke
	authCtx := withAuthToken(ctx, token2)
	listResp, _ := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if len(listResp.Sessions) < 2 {
		t.Fatal("expected at least 2 sessions")
	}

	// Find the session for token1 (oldest)
	sessionToRevoke := listResp.Sessions[len(listResp.Sessions)-1].Id

	// Subscribe to session events
	sub, err := natsConn.SubscribeSync("overwatch.identity.session")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Drain any existing messages
	drainSubscription(sub)

	// Trigger: Revoke session
	_, err = client.RevokeSession(withAuthToken(ctx, token1), &identityv1.RevokeSessionRequest{
		SessionId: sessionToRevoke,
	})
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	// Wait for event
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("did not receive event: %v", err)
	}

	// Parse envelope
	var envelope SignedEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	// Verify envelope
	if envelope.EventType != "session.revoked" {
		t.Errorf("EventType = %s, want session.revoked", envelope.EventType)
	}
	if envelope.SignerDID == "" {
		t.Error("SignerDID should not be empty")
	}
	if envelope.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Parse payload
	var payload SessionRevokedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload.SessionID != sessionToRevoke {
		t.Errorf("Payload.SessionID = %s, want %s", payload.SessionID, sessionToRevoke)
	}

	t.Logf("✓ session.revoked event received: %s (signed by %s)", envelope.EventID, envelope.SignerDID)
}

func TestAPIKeyRevokedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create API key
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:   "revoke-test-key",
		Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}
	apiKeyID := createResp.ApiKey.Id

	// Subscribe to apikey events
	sub, err := natsConn.SubscribeSync("overwatch.identity.apikey")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Drain any existing messages (including the create event)
	drainSubscription(sub)

	// Trigger: Revoke API key
	_, err = client.RevokeAPIKey(authCtx, &identityv1.RevokeAPIKeyRequest{
		Id: apiKeyID,
	})
	if err != nil {
		t.Fatalf("RevokeAPIKey failed: %v", err)
	}

	// Wait for event
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("did not receive event: %v", err)
	}

	// Parse envelope
	var envelope SignedEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	// Verify envelope
	if envelope.EventType != "apikey.revoked" {
		t.Errorf("EventType = %s, want apikey.revoked", envelope.EventType)
	}
	if envelope.SignerDID == "" {
		t.Error("SignerDID should not be empty")
	}
	if envelope.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Parse payload
	var payload APIKeyRevokedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload.APIKeyID != apiKeyID {
		t.Errorf("Payload.APIKeyID = %s, want %s", payload.APIKeyID, apiKeyID)
	}

	t.Logf("✓ apikey.revoked event received: %s (signed by %s)", envelope.EventID, envelope.SignerDID)
}

// ============================================================================
// Helpers
// ============================================================================

func drainSubscription(sub *nats.Subscription) {
	for {
		_, err := sub.NextMsg(100 * time.Millisecond)
		if err != nil {
			break
		}
	}
}

func mustRegisterUser(t *testing.T, ctx context.Context) (security.KeyPair, *security.DID) {
	t.Helper()

	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(registerResp.Message))
	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("VerifyRegistration failed: %v", err)
	}

	return keyPair, did
}

func mustRegisterAndAuthenticate(t *testing.T, ctx context.Context) (security.KeyPair, *security.DID, string) {
	t.Helper()

	keyPair, did := mustRegisterUser(t, ctx)

	authResp, _ := client.Authenticate(ctx, &identityv1.AuthenticateRequest{Did: did.String()})
	sig, _ := keyPair.Sign([]byte(authResp.Message))
	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	return keyPair, did, verifyResp.AccessToken
}

func withAuthToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}