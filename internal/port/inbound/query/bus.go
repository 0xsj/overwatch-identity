package query

import (
	"context"
)

// Query is a marker interface for all queries.
type Query interface {
	// QueryName returns the name of the query for logging/tracing.
	QueryName() string
}

// Handler handles a specific query type.
type Handler[Q Query, R any] interface {
	Handle(ctx context.Context, qry Q) (R, error)
}

// Bus dispatches queries to their handlers.
// This is optional - you can also call handlers directly.
type Bus interface {
	// Dispatch sends a query to its handler and returns the result.
	Dispatch(ctx context.Context, qry Query) (any, error)

	// Register registers a handler for a query type.
	Register(qryName string, handler any)
}
