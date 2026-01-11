package command

import (
	"context"
)

// Command is a marker interface for all commands.
type Command interface {
	// CommandName returns the name of the command for logging/tracing.
	CommandName() string
}

// Handler handles a specific command type.
type Handler[C Command, R any] interface {
	Handle(ctx context.Context, cmd C) (R, error)
}

// Bus dispatches commands to their handlers.
// This is optional - you can also call handlers directly.
type Bus interface {
	// Dispatch sends a command to its handler and returns the result.
	Dispatch(ctx context.Context, cmd Command) (any, error)

	// Register registers a handler for a command type.
	Register(cmdName string, handler any)
}
