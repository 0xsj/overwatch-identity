package nats

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/0xsj/overwatch-pkg/provenance"
	"github.com/0xsj/overwatch-pkg/provenance/middleware"

	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
)

// eventPublisher implements messaging.EventPublisher with provenance signing.
type eventPublisher struct {
	conn          *nats.Conn
	subjectPrefix string
	publisher     *middleware.Publisher
}

// NewEventPublisher creates a new EventPublisher without signing (legacy).
func NewEventPublisher(conn *nats.Conn, subjectPrefix string) messaging.EventPublisher {
	if subjectPrefix == "" {
		subjectPrefix = "overwatch"
	}
	return &eventPublisher{
		conn:          conn,
		subjectPrefix: subjectPrefix,
		publisher:     nil,
	}
}

// NewSignedEventPublisher creates a new EventPublisher with provenance signing.
func NewSignedEventPublisher(conn *nats.Conn, subjectPrefix string, identity provenance.Identity) (messaging.EventPublisher, error) {
	if subjectPrefix == "" {
		subjectPrefix = "overwatch"
	}

	publisher, err := middleware.NewPublisher(conn, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed publisher: %w", err)
	}

	return &eventPublisher{
		conn:          conn,
		subjectPrefix: subjectPrefix,
		publisher:     publisher,
	}, nil
}

func (p *eventPublisher) Publish(ctx context.Context, evt event.Event) error {
	subject := p.subjectForEvent(evt)

	if p.publisher != nil {
		return p.publishSigned(ctx, subject, evt)
	}
	return p.publishLegacy(ctx, subject, evt)
}

func (p *eventPublisher) PublishAll(ctx context.Context, events []event.Event) error {
	for _, evt := range events {
		if err := p.Publish(ctx, evt); err != nil {
			return err
		}
	}
	return nil
}

// publishSigned publishes an event as a signed envelope.
func (p *eventPublisher) publishSigned(ctx context.Context, subject string, evt event.Event) error {
	// Pass event directly - envelope builder handles metadata
	if err := p.publisher.Publish(subject, evt.EventType(), evt); err != nil {
		return fmt.Errorf("failed to publish signed event: %w", err)
	}
	return nil
}

// publishLegacy publishes an event in the old unsigned format.
func (p *eventPublisher) publishLegacy(ctx context.Context, subject string, evt event.Event) error {
	envelope := legacyEnvelope{
		EventID:       evt.EventID().String(),
		EventType:     evt.EventType(),
		AggregateID:   evt.AggregateID().String(),
		AggregateType: evt.AggregateType(),
		OccurredAt:    evt.OccurredAt().Time().Unix(),
		Payload:       evt,
	}

	data, err := provenance.BuildPayload(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := p.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}

func (p *eventPublisher) subjectForEvent(evt event.Event) string {
	topic := messaging.TopicForEvent(evt)
	return fmt.Sprintf("%s.%s", p.subjectPrefix, topic)
}

// legacyEnvelope wraps an event with metadata for transport (unsigned).
type legacyEnvelope struct {
	EventID       string `json:"event_id"`
	EventType     string `json:"event_type"`
	AggregateID   string `json:"aggregate_id"`
	AggregateType string `json:"aggregate_type"`
	OccurredAt    int64  `json:"occurred_at"`
	Payload       any    `json:"payload"`
}
