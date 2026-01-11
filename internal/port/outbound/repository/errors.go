package repository

import "errors"

var (
	// ErrNotFound is returned when a requested entity is not found.
	ErrNotFound = errors.New("entity not found")
)
