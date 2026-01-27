//go:build e2e

package e2e_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-pkg/security"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

func TestGetCurrentUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, did, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Get current user
	resp, err := client.GetCurrentUser(authCtx, &identityv1.GetCurrentUserRequest{})
	if err != nil {
		t.Fatalf("GetCurrentUser failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if resp.User.Id == "" {
		t.Fatal("expected non-empty user ID")
	}
	if resp.User.Did != did.String() {
		t.Errorf("DID mismatch: got %s, want %s", resp.User.Did, did.String())
	}
	if resp.User.Status != identityv1.UserStatus_USER_STATUS_ACTIVE {
		t.Errorf("expected active status, got %s", resp.User.Status)
	}

	t.Logf("Got current user: %s (DID: %s)", resp.User.Id, resp.User.Did)
}

func TestGetCurrentUserUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.GetCurrentUser(ctx, &identityv1.GetCurrentUserRequest{})
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

func TestGetUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate to get user ID
	_, did, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Get current user to get the ID
	currentResp, err := client.GetCurrentUser(authCtx, &identityv1.GetCurrentUserRequest{})
	if err != nil {
		t.Fatalf("GetCurrentUser failed: %v", err)
	}
	userID := currentResp.User.Id

	// GetUser is public - no auth needed
	resp, err := client.GetUser(ctx, &identityv1.GetUserRequest{
		Id: userID,
	})
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if resp.User.Id != userID {
		t.Errorf("ID mismatch: got %s, want %s", resp.User.Id, userID)
	}
	if resp.User.Did != did.String() {
		t.Errorf("DID mismatch: got %s, want %s", resp.User.Did, did.String())
	}

	t.Logf("Got user: %s", resp.User.Id)
}

func TestGetUserNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to get non-existent user (valid ULID format)
	_, err := client.GetUser(ctx, &identityv1.GetUserRequest{
		Id: "01H0000000000000000000000",
	})

	if err == nil {
		t.Fatal("expected error for non-existent user")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound && st.Code() != codes.InvalidArgument {
		t.Errorf("expected NotFound or InvalidArgument, got: %s", st.Code())
	}

	t.Logf("Non-existent user correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestGetUserByDID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register a user
	_, did := mustRegisterNewUser(t, ctx)

	// GetUserByDID is public - no auth needed
	resp, err := client.GetUserByDID(ctx, &identityv1.GetUserByDIDRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("GetUserByDID failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if resp.User.Did != did.String() {
		t.Errorf("DID mismatch: got %s, want %s", resp.User.Did, did.String())
	}

	t.Logf("Got user by DID: %s (ID: %s)", resp.User.Did, resp.User.Id)
}

func TestGetUserByDIDNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate a DID that was never registered
	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	_, err := client.GetUserByDID(ctx, &identityv1.GetUserByDIDRequest{
		Did: did.String(),
	})

	if err == nil {
		t.Fatal("expected error for non-existent DID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got: %s", st.Code())
	}

	t.Logf("Non-existent DID correctly rejected: %s", st.Message())
}

func TestUpdateUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Update user with unique email and name
	email := fmt.Sprintf("test-%d@example.com", time.Now().UnixNano())
	name := "Test User"
	resp, err := client.UpdateUser(authCtx, &identityv1.UpdateUserRequest{
		Email: &email,
		Name:  &name,
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if resp.User.Email == nil || *resp.User.Email != email {
		t.Errorf("email mismatch: got %v, want %s", resp.User.Email, email)
	}
	if resp.User.Name == nil || *resp.User.Name != name {
		t.Errorf("name mismatch: got %v, want %s", resp.User.Name, name)
	}

	t.Logf("Updated user: email=%s, name=%s", *resp.User.Email, *resp.User.Name)
}

func TestUpdateUserEmailOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Update only email with unique value
	email := fmt.Sprintf("emailonly-%d@example.com", time.Now().UnixNano())
	resp, err := client.UpdateUser(authCtx, &identityv1.UpdateUserRequest{
		Email: &email,
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if resp.User.Email == nil || *resp.User.Email != email {
		t.Errorf("email mismatch: got %v, want %s", resp.User.Email, email)
	}

	t.Logf("Updated user email: %s", *resp.User.Email)
}

func TestUpdateUserNameOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Update only name
	name := "Name Only User"
	resp, err := client.UpdateUser(authCtx, &identityv1.UpdateUserRequest{
		Name: &name,
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if resp.User.Name == nil || *resp.User.Name != name {
		t.Errorf("name mismatch: got %v, want %s", resp.User.Name, name)
	}

	t.Logf("Updated user name: %s", *resp.User.Name)
}

func TestUpdateUserUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := "test@example.com"
	_, err := client.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		Email: &email,
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

func TestUpdateUserPersistence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	// Update user with unique values
	email := fmt.Sprintf("persist-%d@example.com", time.Now().UnixNano())
	name := "Persistent User"
	_, err := client.UpdateUser(authCtx, &identityv1.UpdateUserRequest{
		Email: &email,
		Name:  &name,
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	// Verify changes persisted by fetching current user
	resp, err := client.GetCurrentUser(authCtx, &identityv1.GetCurrentUserRequest{})
	if err != nil {
		t.Fatalf("GetCurrentUser failed: %v", err)
	}

	if resp.User.Email == nil || *resp.User.Email != email {
		t.Errorf("email not persisted: got %v, want %s", resp.User.Email, email)
	}
	if resp.User.Name == nil || *resp.User.Name != name {
		t.Errorf("name not persisted: got %v, want %s", resp.User.Name, name)
	}

	t.Log("User updates persisted correctly")
}
