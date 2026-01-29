// Package testutil provides testing utilities for the identity service.
package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Fake provides generators for fake test data.
var Fake = &fakeGenerator{}

type fakeGenerator struct {
	counter int64
}

// String generates a random string with the given prefix.
func (f *fakeGenerator) String(prefix string) string {
	f.counter++
	return fmt.Sprintf("%s_%d_%s", prefix, f.counter, f.randomHex(4))
}

// Email generates a fake email address.
func (f *fakeGenerator) Email() string {
	f.counter++
	return fmt.Sprintf("user%d_%s@example.com", f.counter, f.randomHex(4))
}

// Name generates a fake name.
func (f *fakeGenerator) Name() string {
	firstNames := []string{"Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"}
	return fmt.Sprintf("%s %s", f.randomChoice(firstNames), f.randomChoice(lastNames))
}

// DIDKey generates a fake did:key string.
// Note: This is not a valid DID - use Fixtures.DID() for valid DIDs.
func (f *fakeGenerator) DIDKey() string {
	return fmt.Sprintf("did:key:z6Mk%s", f.randomHex(32))
}

// Hex generates a random hex string of the given byte length.
func (f *fakeGenerator) Hex(byteLength int) string {
	return f.randomHex(byteLength)
}

// ID generates a fake ULID-like string.
func (f *fakeGenerator) ID() string {
	return strings.ToUpper(f.randomHex(13))
}

// Nonce generates a cryptographic nonce.
func (f *fakeGenerator) Nonce(length int) string {
	return f.randomHex(length)
}

// Scopes generates a slice of fake API scopes.
func (f *fakeGenerator) Scopes() []string {
	allScopes := []string{
		"read:users",
		"write:users",
		"read:sources",
		"write:sources",
		"read:entities",
		"write:entities",
		"read:events",
		"write:events",
		"admin",
	}

	// Return 1-3 random scopes
	count := f.randomInt(1, 4)
	scopes := make([]string, 0, count)
	used := make(map[int]bool)

	for len(scopes) < count {
		idx := f.randomInt(0, len(allScopes))
		if !used[idx] {
			scopes = append(scopes, allScopes[idx])
			used[idx] = true
		}
	}

	return scopes
}

// Duration generates a random duration between min and max.
func (f *fakeGenerator) Duration(min, max time.Duration) time.Duration {
	minNanos := min.Nanoseconds()
	maxNanos := max.Nanoseconds()
	deltaNanos := f.randomInt64(0, maxNanos-minNanos)
	return time.Duration(minNanos + deltaNanos)
}

// FutureTime generates a time in the future.
func (f *fakeGenerator) FutureTime(maxOffset time.Duration) time.Time {
	offset := f.Duration(time.Minute, maxOffset)
	return time.Now().Add(offset)
}

// PastTime generates a time in the past.
func (f *fakeGenerator) PastTime(maxOffset time.Duration) time.Time {
	offset := f.Duration(time.Minute, maxOffset)
	return time.Now().Add(-offset)
}

// Helpers

func (f *fakeGenerator) randomHex(byteLength int) string {
	bytes := make([]byte, byteLength)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (f *fakeGenerator) randomChoice(choices []string) string {
	idx := f.randomInt(0, len(choices))
	return choices[idx]
}

func (f *fakeGenerator) randomInt(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

func (f *fakeGenerator) randomInt64(min, max int64) int64 {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min))
	return min + n.Int64()
}
