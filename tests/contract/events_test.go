package contract

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	natsadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/nats"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
)

// --- User Events ---

func TestEventPublisher_UserRegistered(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	evt := event.NewUserRegistered(
		userID,
		"did:key:z6MkTest123",
		types.Some("test@example.com"),
		types.Some("Alice"),
	)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	// Verify subject
	if msg.Subject != "overwatch.identity.user" {
		t.Errorf("Subject = %v, want overwatch.identity.user", msg.Subject)
	}

	// Verify envelope structure
	var envelope legacyEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		t.Fatalf("failed to unmarshal envelope: %v", err)
	}

	if envelope.EventType != event.EventTypeUserRegistered {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeUserRegistered)
	}
	if envelope.AggregateType != event.AggregateTypeUser {
		t.Errorf("AggregateType = %v, want %v", envelope.AggregateType, event.AggregateTypeUser)
	}
	if envelope.AggregateID != userID.String() {
		t.Errorf("AggregateID = %v, want %v", envelope.AggregateID, userID.String())
	}
	if envelope.EventID == "" {
		t.Error("EventID should not be empty")
	}
	if envelope.OccurredAt == 0 {
		t.Error("OccurredAt should not be zero")
	}

	// Verify payload
	payload, ok := envelope.Payload.(map[string]any)
	if !ok {
		t.Fatalf("Payload is not a map: %T", envelope.Payload)
	}
	if payload["DID"] != "did:key:z6MkTest123" {
		t.Errorf("Payload DID = %v, want did:key:z6MkTest123", payload["DID"])
	}
}

func TestEventPublisher_UserSuspended(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	evt := event.NewUserSuspended(userID, "policy violation")

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeUserSuspended {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeUserSuspended)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Reason"] != "policy violation" {
		t.Errorf("Payload Reason = %v, want policy violation", payload["Reason"])
	}
}

func TestEventPublisher_UserActivated(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	evt := event.NewUserActivated(userID)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeUserActivated {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeUserActivated)
	}
}

// --- Session Events ---

func TestEventPublisher_SessionCreated(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.session")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	sessionID := types.NewID()
	userID := types.NewID()
	evt := event.NewSessionCreated(
		sessionID,
		userID,
		"did:key:z6MkTest456",
		types.Some(types.NewID()),
	)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	if msg.Subject != "overwatch.identity.session" {
		t.Errorf("Subject = %v, want overwatch.identity.session", msg.Subject)
	}

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeSessionCreated {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeSessionCreated)
	}
	if envelope.AggregateType != event.AggregateTypeSession {
		t.Errorf("AggregateType = %v, want %v", envelope.AggregateType, event.AggregateTypeSession)
	}
}

func TestEventPublisher_SessionRevoked(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.session")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	sessionID := types.NewID()
	userID := types.NewID()
	evt := event.NewSessionRevoked(sessionID, userID, "user requested")

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeSessionRevoked {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeSessionRevoked)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Reason"] != "user requested" {
		t.Errorf("Payload Reason = %v, want user requested", payload["Reason"])
	}
}

func TestEventPublisher_AllSessionsRevoked(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	evt := event.NewAllSessionsRevoked(userID, 5)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	// AllSessionsRevoked goes to user topic (aggregate type is user)
	if msg.Subject != "overwatch.identity.user" {
		t.Errorf("Subject = %v, want overwatch.identity.user", msg.Subject)
	}

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeSessionsRevokedAll {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeSessionsRevokedAll)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if int(payload["RevokedCount"].(float64)) != 5 {
		t.Errorf("Payload RevokedCount = %v, want 5", payload["RevokedCount"])
	}
}

func TestEventPublisher_TokenRefreshed(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.session")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	sessionID := types.NewID()
	userID := types.NewID()
	evt := event.NewTokenRefreshed(sessionID, userID)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeTokenRefreshed {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeTokenRefreshed)
	}
}

// --- Auth Events ---

func TestEventPublisher_AuthenticationSucceeded(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.auth")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	sessionID := types.NewID()
	evt := event.NewAuthenticationSucceeded(
		userID,
		"did:key:z6MkTest789",
		sessionID,
		event.AuthMethodDIDChallenge,
	)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	if msg.Subject != "overwatch.identity.auth" {
		t.Errorf("Subject = %v, want overwatch.identity.auth", msg.Subject)
	}

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeAuthenticationSucceeded {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeAuthenticationSucceeded)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Method"] != string(event.AuthMethodDIDChallenge) {
		t.Errorf("Payload Method = %v, want %v", payload["Method"], event.AuthMethodDIDChallenge)
	}
}

func TestEventPublisher_AuthenticationFailed(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.auth")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	evt := event.NewAuthenticationFailed("did:key:z6MkTest000", "invalid signature")

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeAuthenticationFailed {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeAuthenticationFailed)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Reason"] != "invalid signature" {
		t.Errorf("Payload Reason = %v, want invalid signature", payload["Reason"])
	}
}

// --- API Key Events ---

func TestEventPublisher_APIKeyCreated(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.apikey")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	apiKeyID := types.NewID()
	userID := types.NewID()
	evt := event.NewAPIKeyCreated(
		apiKeyID,
		userID,
		"Production Key",
		[]string{"read:users", "write:users"},
		types.None[types.ID](),
		types.None[types.Timestamp](),
	)

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	if msg.Subject != "overwatch.identity.apikey" {
		t.Errorf("Subject = %v, want overwatch.identity.apikey", msg.Subject)
	}

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeAPIKeyCreated {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeAPIKeyCreated)
	}
	if envelope.AggregateType != event.AggregateTypeAPIKey {
		t.Errorf("AggregateType = %v, want %v", envelope.AggregateType, event.AggregateTypeAPIKey)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Name"] != "Production Key" {
		t.Errorf("Payload Name = %v, want Production Key", payload["Name"])
	}
}

func TestEventPublisher_APIKeyRevoked(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.apikey")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	apiKeyID := types.NewID()
	userID := types.NewID()
	evt := event.NewAPIKeyRevoked(apiKeyID, userID, "compromised")

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeAPIKeyRevoked {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeAPIKeyRevoked)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Reason"] != "compromised" {
		t.Errorf("Payload Reason = %v, want compromised", payload["Reason"])
	}
}

func TestEventPublisher_APIKeyUsed(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.apikey")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	apiKeyID := types.NewID()
	userID := types.NewID()
	evt := event.NewAPIKeyUsed(apiKeyID, userID, "/api/v1/users")

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	var envelope legacyEnvelope
	json.Unmarshal(msg.Data, &envelope)

	if envelope.EventType != event.EventTypeAPIKeyUsed {
		t.Errorf("EventType = %v, want %v", envelope.EventType, event.EventTypeAPIKeyUsed)
	}

	payload, _ := envelope.Payload.(map[string]any)
	if payload["Endpoint"] != "/api/v1/users" {
		t.Errorf("Payload Endpoint = %v, want /api/v1/users", payload["Endpoint"])
	}
}

// --- PublishAll ---

func TestEventPublisher_PublishAll(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.>")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	userID := types.NewID()
	sessionID := types.NewID()

	events := []event.Event{
		event.NewUserRegistered(userID, "did:key:z6MkBatch1", types.None[string](), types.None[string]()),
		event.NewSessionCreated(sessionID, userID, "did:key:z6MkBatch1", types.None[types.ID]()),
		event.NewAuthenticationSucceeded(userID, "did:key:z6MkBatch1", sessionID, event.AuthMethodDIDChallenge),
	}

	err := publisher.PublishAll(getContext(), events)

	if err != nil {
		t.Fatalf("PublishAll() error = %v", err)
	}

	messages := waitForMessageCount(t, msgChan, 3, 5*time.Second)

	if len(messages) != 3 {
		t.Errorf("Received %d messages, want 3", len(messages))
	}

	// Verify all different event types
	eventTypes := make(map[string]bool)
	for _, msg := range messages {
		var envelope legacyEnvelope
		json.Unmarshal(msg.Data, &envelope)
		eventTypes[envelope.EventType] = true
	}

	if !eventTypes[event.EventTypeUserRegistered] {
		t.Error("Missing user.registered event")
	}
	if !eventTypes[event.EventTypeSessionCreated] {
		t.Error("Missing session.created event")
	}
	if !eventTypes[event.EventTypeAuthenticationSucceeded] {
		t.Error("Missing auth.succeeded event")
	}
}

// --- Topic Routing ---

func TestEventPublisher_TopicRouting(t *testing.T) {
	tests := []struct {
		name          string
		event         event.Event
		expectedTopic string
	}{
		{
			name:          "user registered goes to user topic",
			event:         event.NewUserRegistered(types.NewID(), "did:key:test", types.None[string](), types.None[string]()),
			expectedTopic: "overwatch.identity.user",
		},
		{
			name:          "session created goes to session topic",
			event:         event.NewSessionCreated(types.NewID(), types.NewID(), "did:key:test", types.None[types.ID]()),
			expectedTopic: "overwatch.identity.session",
		},
		{
			name:          "auth succeeded goes to auth topic",
			event:         event.NewAuthenticationSucceeded(types.NewID(), "did:key:test", types.NewID(), event.AuthMethodDIDChallenge),
			expectedTopic: "overwatch.identity.auth",
		},
		{
			name:          "auth failed goes to auth topic",
			event:         event.NewAuthenticationFailed("did:key:test", "reason"),
			expectedTopic: "overwatch.identity.auth",
		},
		{
			name:          "apikey created goes to apikey topic",
			event:         event.NewAPIKeyCreated(types.NewID(), types.NewID(), "key", []string{}, types.None[types.ID](), types.None[types.Timestamp]()),
			expectedTopic: "overwatch.identity.apikey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgChan, cleanup := subscribeAndCollect(t, tt.expectedTopic)
			defer cleanup()

			publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

			err := publisher.Publish(getContext(), tt.event)
			if err != nil {
				t.Fatalf("Publish() error = %v", err)
			}

			msg := waitForMessage(t, msgChan, 2*time.Second)

			if msg.Subject != tt.expectedTopic {
				t.Errorf("Subject = %v, want %v", msg.Subject, tt.expectedTopic)
			}
		})
	}
}

// --- Custom Subject Prefix ---

func TestEventPublisher_CustomSubjectPrefix(t *testing.T) {
	msgChan, cleanup := subscribeAndCollect(t, "custom.identity.user")
	defer cleanup()

	publisher := natsadapter.NewEventPublisher(getConn(), "custom")

	evt := event.NewUserRegistered(types.NewID(), "did:key:test", types.None[string](), types.None[string]())

	err := publisher.Publish(getContext(), evt)

	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	msg := waitForMessage(t, msgChan, 2*time.Second)

	if msg.Subject != "custom.identity.user" {
		t.Errorf("Subject = %v, want custom.identity.user", msg.Subject)
	}
}

// --- Envelope structure for unmarshaling ---

type legacyEnvelope struct {
	EventID       string `json:"event_id"`
	EventType     string `json:"event_type"`
	AggregateID   string `json:"aggregate_id"`
	AggregateType string `json:"aggregate_type"`
	OccurredAt    int64  `json:"occurred_at"`
	Payload       any    `json:"payload"`
}
