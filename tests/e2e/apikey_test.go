//go:build e2e

package e2e_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

func toTimestamppb(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}

func TestCreateAPIKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create API key
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:   "test-api-key",
		Scopes: []string{"read:sources", "write:sources"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	if createResp.ApiKey == nil {
		t.Fatal("expected non-nil api_key")
	}
	if createResp.Key == "" {
		t.Fatal("expected non-empty key (secret)")
	}
	if createResp.ApiKey.Id == "" {
		t.Fatal("expected non-empty api_key.id")
	}
	if createResp.ApiKey.Name != "test-api-key" {
		t.Errorf("name mismatch: got %s, want test-api-key", createResp.ApiKey.Name)
	}
	if createResp.ApiKey.KeyPrefix == "" {
		t.Fatal("expected non-empty key_prefix")
	}
	if len(createResp.ApiKey.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(createResp.ApiKey.Scopes))
	}

	t.Logf("Created API key: %s (prefix: %s)", createResp.ApiKey.Id, createResp.ApiKey.KeyPrefix)
	t.Logf("Secret key: %s...", createResp.Key[:20])
}

func TestCreateAPIKeyUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.CreateAPIKey(ctx, &identityv1.CreateAPIKeyRequest{
		Name:   "test-api-key",
		Scopes: []string{"read:sources"},
	})

	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Unauthenticated request correctly rejected: %s", st.Message())
}

func TestListAPIKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create a few API keys
	for i := 0; i < 3; i++ {
		_, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
			Name:   "test-key-" + string(rune('a'+i)),
			Scopes: []string{"read"},
		})
		if err != nil {
			t.Fatalf("CreateAPIKey %d failed: %v", i, err)
		}
	}

	// List API keys
	listResp, err := client.ListAPIKeys(authCtx, &identityv1.ListAPIKeysRequest{})
	if err != nil {
		t.Fatalf("ListAPIKeys failed: %v", err)
	}

	if len(listResp.ApiKeys) < 3 {
		t.Errorf("expected at least 3 API keys, got %d", len(listResp.ApiKeys))
	}

	t.Logf("Found %d API keys", len(listResp.ApiKeys))

	for _, key := range listResp.ApiKeys {
		t.Logf("  - %s: %s (prefix: %s)", key.Id, key.Name, key.KeyPrefix)
	}
}

func TestGetAPIKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create API key
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:   "get-test-key",
		Scopes: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	apiKeyID := createResp.ApiKey.Id

	// Get API key by ID
	getResp, err := client.GetAPIKey(authCtx, &identityv1.GetAPIKeyRequest{
		Id: apiKeyID,
	})
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}

	if getResp.ApiKey == nil {
		t.Fatal("expected non-nil api_key")
	}
	if getResp.ApiKey.Id != apiKeyID {
		t.Errorf("ID mismatch: got %s, want %s", getResp.ApiKey.Id, apiKeyID)
	}
	if getResp.ApiKey.Name != "get-test-key" {
		t.Errorf("name mismatch: got %s, want get-test-key", getResp.ApiKey.Name)
	}

	t.Logf("Retrieved API key: %s", getResp.ApiKey.Name)
}

func TestGetAPIKeyNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Try to get non-existent API key (valid ULID format but doesn't exist)
	_, err := client.GetAPIKey(authCtx, &identityv1.GetAPIKeyRequest{
		Id: "01H0000000000000000000000", // Valid ULID format
	})

	if err == nil {
		t.Fatal("expected error for non-existent API key")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	// Could be NotFound or InvalidArgument depending on validation order
	if st.Code() != codes.NotFound && st.Code() != codes.InvalidArgument {
		t.Errorf("expected NotFound or InvalidArgument, got: %s", st.Code())
	}

	t.Logf("Non-existent API key correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestRevokeAPIKey(t *testing.T) {
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
	apiKeySecret := createResp.Key

	// Verify API key works before revocation
	verifyResp, err := client.VerifyAPIKey(ctx, &identityv1.VerifyAPIKeyRequest{
		Key: apiKeySecret,
	})
	if err != nil {
		t.Fatalf("VerifyAPIKey should work before revocation: %v", err)
	}
	if verifyResp.ApiKey == nil {
		t.Fatal("expected non-nil api_key from verify")
	}

	t.Log("API key verified successfully before revocation")

	// Revoke API key
	_, err = client.RevokeAPIKey(authCtx, &identityv1.RevokeAPIKeyRequest{
		Id: apiKeyID,
	})
	if err != nil {
		t.Fatalf("RevokeAPIKey failed: %v", err)
	}

	t.Logf("Revoked API key: %s", apiKeyID)

	// Verify API key should fail after revocation
	_, err = client.VerifyAPIKey(ctx, &identityv1.VerifyAPIKeyRequest{
		Key: apiKeySecret,
	})
	if err == nil {
		t.Fatal("VerifyAPIKey should fail after revocation")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("Revoked API key correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestVerifyAPIKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create API key
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:   "verify-test-key",
		Scopes: []string{"read:entities", "write:entities"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	apiKeySecret := createResp.Key

	// Verify API key (this is a public endpoint)
	verifyResp, err := client.VerifyAPIKey(ctx, &identityv1.VerifyAPIKeyRequest{
		Key: apiKeySecret,
	})
	if err != nil {
		t.Fatalf("VerifyAPIKey failed: %v", err)
	}

	if verifyResp.ApiKey == nil {
		t.Fatal("expected non-nil api_key")
	}
	if verifyResp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if verifyResp.ApiKey.Name != "verify-test-key" {
		t.Errorf("name mismatch: got %s, want verify-test-key", verifyResp.ApiKey.Name)
	}

	t.Logf("Verified API key: %s (user: %s)", verifyResp.ApiKey.Name, verifyResp.User.Id)
}

func TestVerifyAPIKeyInvalid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.VerifyAPIKey(ctx, &identityv1.VerifyAPIKeyRequest{
		Key: "invalid-api-key",
	})

	if err == nil {
		t.Fatal("expected error for invalid API key")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound && st.Code() != codes.Unauthenticated {
		t.Errorf("expected NotFound or Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Invalid API key correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestAPIKeyWithExpiration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Create API key with expiration
	expiresAt := time.Now().Add(24 * time.Hour)
	createResp, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
		Name:      "expiring-key",
		Scopes:    []string{"read"},
		ExpiresAt: toTimestamppb(expiresAt),
	})
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	if createResp.ApiKey.ExpiresAt == nil {
		t.Fatal("expected non-nil expires_at")
	}

	t.Logf("Created API key with expiration: %s (expires: %s)",
		createResp.ApiKey.Id,
		createResp.ApiKey.ExpiresAt.AsTime().Format(time.RFC3339))
}
