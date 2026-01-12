package nats

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
)

// eventPublisher implements messaging.EventPublisher.
type eventPublisher struct {
	conn          *nats.Conn
	subjectPrefix string
}

// NewEventPublisher creates a new EventPublisher.
func NewEventPublisher(conn *nats.Conn, subjectPrefix string) messaging.EventPublisher {
	if subjectPrefix == "" {
		subjectPrefix = "overwatch"
	}
	return &eventPublisher{
		conn:          conn,
		subjectPrefix: subjectPrefix,
	}
}

func (p *eventPublisher) Publish(ctx context.Context, evt event.Event) error {
	subject := p.subjectForEvent(evt)

	envelope := eventEnvelope{
		EventID:       evt.EventID().String(),
		EventType:     evt.EventType(),
		AggregateID:   evt.AggregateID().String(),
		AggregateType: evt.AggregateType(),
		OccurredAt:    evt.OccurredAt().Time().Unix(),
		Payload:       evt,
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := p.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}

func (p *eventPublisher) PublishAll(ctx context.Context, events []event.Event) error {
	for _, evt := range events {
		if err := p.Publish(ctx, evt); err != nil {
			return err
		}
	}
	return nil
}

func (p *eventPublisher) subjectForEvent(evt event.Event) string {
	topic := messaging.TopicForEvent(evt)
	return fmt.Sprintf("%s.%s", p.subjectPrefix, topic)
}

// eventEnvelope wraps an event with metadata for transport.
type eventEnvelope struct {
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	AggregateID   string      `json:"aggregate_id"`
	AggregateType string      `json:"aggregate_type"`
	OccurredAt    int64       `json:"occurred_at"`
	Payload       interface{} `json:"payload"`
}
