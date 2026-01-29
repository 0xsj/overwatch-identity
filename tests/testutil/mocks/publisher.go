package mocks

import (
	"context"
	"sync"

	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
)

// EventPublisher is a mock implementation of messaging.EventPublisher.
type EventPublisher struct {
	mu sync.RWMutex

	// Published events
	events []event.Event

	// Events by type for easier querying
	byType map[string][]event.Event

	// Events by topic
	byTopic map[string][]event.Event

	// Call tracking
	Calls struct {
		Publish    int
		PublishAll int
	}

	// Error injection
	Errors struct {
		Publish    error
		PublishAll error
	}
}

// NewEventPublisher creates a new mock EventPublisher.
func NewEventPublisher() *EventPublisher {
	return &EventPublisher{
		events:  make([]event.Event, 0),
		byType:  make(map[string][]event.Event),
		byTopic: make(map[string][]event.Event),
	}
}

func (m *EventPublisher) Publish(ctx context.Context, evt event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Publish++

	if m.Errors.Publish != nil {
		return m.Errors.Publish
	}

	m.recordEvent(evt)
	return nil
}

func (m *EventPublisher) PublishAll(ctx context.Context, events []event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.PublishAll++

	if m.Errors.PublishAll != nil {
		return m.Errors.PublishAll
	}

	for _, evt := range events {
		m.recordEvent(evt)
	}
	return nil
}

// recordEvent stores the event in all indexes (must hold lock).
func (m *EventPublisher) recordEvent(evt event.Event) {
	m.events = append(m.events, evt)
	m.byType[evt.EventType()] = append(m.byType[evt.EventType()], evt)

	topic := messaging.TopicForEvent(evt)
	m.byTopic[topic] = append(m.byTopic[topic], evt)
}

// --- Query Methods ---

// Events returns all published events.
func (m *EventPublisher) Events() []event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]event.Event, len(m.events))
	copy(result, m.events)
	return result
}

// EventCount returns the total number of published events.
func (m *EventPublisher) EventCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}

// EventsByType returns all events of a specific type.
func (m *EventPublisher) EventsByType(eventType string) []event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[eventType]
	result := make([]event.Event, len(events))
	copy(result, events)
	return result
}

// EventsByTopic returns all events published to a specific topic.
func (m *EventPublisher) EventsByTopic(topic string) []event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byTopic[topic]
	result := make([]event.Event, len(events))
	copy(result, events)
	return result
}

// LastEvent returns the most recently published event, or nil if none.
func (m *EventPublisher) LastEvent() event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.events) == 0 {
		return nil
	}
	return m.events[len(m.events)-1]
}

// LastEventOfType returns the most recent event of a specific type, or nil if none.
func (m *EventPublisher) LastEventOfType(eventType string) event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[eventType]
	if len(events) == 0 {
		return nil
	}
	return events[len(events)-1]
}

// HasEvent checks if any event of the given type was published.
func (m *EventPublisher) HasEvent(eventType string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.byType[eventType]) > 0
}

// HasEventCount checks if exactly n events of the given type were published.
func (m *EventPublisher) HasEventCount(eventType string, n int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.byType[eventType]) == n
}

// --- Typed Getters ---

// UserRegisteredEvents returns all UserRegistered events.
func (m *EventPublisher) UserRegisteredEvents() []event.UserRegistered {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeUserRegistered]
	result := make([]event.UserRegistered, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.UserRegistered); ok {
			result = append(result, typed)
		}
	}
	return result
}

// UserSuspendedEvents returns all UserSuspended events.
func (m *EventPublisher) UserSuspendedEvents() []event.UserSuspended {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeUserSuspended]
	result := make([]event.UserSuspended, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.UserSuspended); ok {
			result = append(result, typed)
		}
	}
	return result
}

// UserActivatedEvents returns all UserActivated events.
func (m *EventPublisher) UserActivatedEvents() []event.UserActivated {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeUserActivated]
	result := make([]event.UserActivated, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.UserActivated); ok {
			result = append(result, typed)
		}
	}
	return result
}

// SessionCreatedEvents returns all SessionCreated events.
func (m *EventPublisher) SessionCreatedEvents() []event.SessionCreated {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeSessionCreated]
	result := make([]event.SessionCreated, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.SessionCreated); ok {
			result = append(result, typed)
		}
	}
	return result
}

// SessionRevokedEvents returns all SessionRevoked events.
func (m *EventPublisher) SessionRevokedEvents() []event.SessionRevoked {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeSessionRevoked]
	result := make([]event.SessionRevoked, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.SessionRevoked); ok {
			result = append(result, typed)
		}
	}
	return result
}

// AllSessionsRevokedEvents returns all AllSessionsRevoked events.
func (m *EventPublisher) AllSessionsRevokedEvents() []event.AllSessionsRevoked {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeSessionsRevokedAll]
	result := make([]event.AllSessionsRevoked, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.AllSessionsRevoked); ok {
			result = append(result, typed)
		}
	}
	return result
}

// TokenRefreshedEvents returns all TokenRefreshed events.
func (m *EventPublisher) TokenRefreshedEvents() []event.TokenRefreshed {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeTokenRefreshed]
	result := make([]event.TokenRefreshed, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.TokenRefreshed); ok {
			result = append(result, typed)
		}
	}
	return result
}

// AuthenticationSucceededEvents returns all AuthenticationSucceeded events.
func (m *EventPublisher) AuthenticationSucceededEvents() []event.AuthenticationSucceeded {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeAuthenticationSucceeded]
	result := make([]event.AuthenticationSucceeded, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.AuthenticationSucceeded); ok {
			result = append(result, typed)
		}
	}
	return result
}

// AuthenticationFailedEvents returns all AuthenticationFailed events.
func (m *EventPublisher) AuthenticationFailedEvents() []event.AuthenticationFailed {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeAuthenticationFailed]
	result := make([]event.AuthenticationFailed, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.AuthenticationFailed); ok {
			result = append(result, typed)
		}
	}
	return result
}

// APIKeyCreatedEvents returns all APIKeyCreated events.
func (m *EventPublisher) APIKeyCreatedEvents() []event.APIKeyCreated {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeAPIKeyCreated]
	result := make([]event.APIKeyCreated, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.APIKeyCreated); ok {
			result = append(result, typed)
		}
	}
	return result
}

// APIKeyRevokedEvents returns all APIKeyRevoked events.
func (m *EventPublisher) APIKeyRevokedEvents() []event.APIKeyRevoked {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeAPIKeyRevoked]
	result := make([]event.APIKeyRevoked, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.APIKeyRevoked); ok {
			result = append(result, typed)
		}
	}
	return result
}

// APIKeyUsedEvents returns all APIKeyUsed events.
func (m *EventPublisher) APIKeyUsedEvents() []event.APIKeyUsed {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := m.byType[event.EventTypeAPIKeyUsed]
	result := make([]event.APIKeyUsed, 0, len(events))
	for _, evt := range events {
		if typed, ok := evt.(event.APIKeyUsed); ok {
			result = append(result, typed)
		}
	}
	return result
}

// --- Reset ---

// Reset clears all events and call counts.
func (m *EventPublisher) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = make([]event.Event, 0)
	m.byType = make(map[string][]event.Event)
	m.byTopic = make(map[string][]event.Event)
	m.Calls = struct {
		Publish    int
		PublishAll int
	}{}
	m.Errors = struct {
		Publish    error
		PublishAll error
	}{}
}
