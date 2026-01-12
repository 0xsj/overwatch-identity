package event

import (
	"github.com/0xsj/overwatch-pkg/types"
)

// Event is the base interface for all domain events.
type Event interface {
	// EventID returns the unique identifier for this event instance.
	EventID() types.ID

	// EventType returns the type name of the event (e.g., "user.registered").
	EventType() string

	// OccurredAt returns when the event occurred.
	OccurredAt() types.Timestamp

	// AggregateID returns the ID of the aggregate that produced this event.
	AggregateID() types.ID

	// AggregateType returns the type of aggregate (e.g., "user", "session").
	AggregateType() string
}

// BaseEvent provides common fields for all domain events.
type BaseEvent struct {
	eventID       types.ID
	eventType     string
	occurredAt    types.Timestamp
	aggregateID   types.ID
	aggregateType string
}

// NewBaseEvent creates a new BaseEvent.
func NewBaseEvent(eventType string, aggregateID types.ID, aggregateType string) BaseEvent {
	return BaseEvent{
		eventID:       types.NewID(),
		eventType:     eventType,
		occurredAt:    types.Now(),
		aggregateID:   aggregateID,
		aggregateType: aggregateType,
	}
}

// ReconstructBaseEvent creates a BaseEvent from persisted data.
func ReconstructBaseEvent(
	eventID types.ID,
	eventType string,
	occurredAt types.Timestamp,
	aggregateID types.ID,
	aggregateType string,
) BaseEvent {
	return BaseEvent{
		eventID:       eventID,
		eventType:     eventType,
		occurredAt:    occurredAt,
		aggregateID:   aggregateID,
		aggregateType: aggregateType,
	}
}

func (e BaseEvent) EventID() types.ID           { return e.eventID }
func (e BaseEvent) EventType() string           { return e.eventType }
func (e BaseEvent) OccurredAt() types.Timestamp { return e.occurredAt }
func (e BaseEvent) AggregateID() types.ID       { return e.aggregateID }
func (e BaseEvent) AggregateType() string       { return e.aggregateType }

// Aggregate types
const (
	AggregateTypeUser    = "user"
	AggregateTypeSession = "session"
	AggregateTypeAPIKey  = "apikey"
)

// Event types
const (
	// User events
	EventTypeUserRegistered = "user.registered"
	EventTypeUserUpdated    = "user.updated"
	EventTypeUserSuspended  = "user.suspended"
	EventTypeUserActivated  = "user.activated"

	// Session events
	EventTypeSessionCreated     = "session.created"
	EventTypeSessionRevoked     = "session.revoked"
	EventTypeSessionsRevokedAll = "session.revoked_all"
	EventTypeTokenRefreshed     = "token.refreshed"

	// Authentication events
	EventTypeAuthenticationSucceeded = "auth.succeeded"
	EventTypeAuthenticationFailed    = "auth.failed"

	// API Key events
	EventTypeAPIKeyCreated = "apikey.created"
	EventTypeAPIKeyRevoked = "apikey.revoked"
	EventTypeAPIKeyUsed    = "apikey.used"
)
