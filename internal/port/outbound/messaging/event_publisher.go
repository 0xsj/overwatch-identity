package messaging

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/domain/event"
)

// EventPublisher defines the interface for publishing domain events.
type EventPublisher interface {
	// Publish publishes a single event.
	Publish(ctx context.Context, evt event.Event) error

	// PublishAll publishes multiple events.
	PublishAll(ctx context.Context, events []event.Event) error
}

// Topic names for identity events.
const (
	TopicUserEvents    = "identity.user"
	TopicSessionEvents = "identity.session"
	TopicAPIKeyEvents  = "identity.apikey"
	TopicAuthEvents    = "identity.auth"
)

// TopicForEvent returns the appropriate topic for an event type.
func TopicForEvent(evt event.Event) string {
	switch evt.AggregateType() {
	case event.AggregateTypeUser:
		// Auth events go to a separate topic
		if evt.EventType() == event.EventTypeAuthenticationSucceeded ||
			evt.EventType() == event.EventTypeAuthenticationFailed {
			return TopicAuthEvents
		}
		return TopicUserEvents
	case event.AggregateTypeSession:
		return TopicSessionEvents
	case event.AggregateTypeAPIKey:
		return TopicAPIKeyEvents
	default:
		return TopicUserEvents
	}
}
