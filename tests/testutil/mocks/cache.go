package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// --- SessionCache Mock ---

// SessionCache is a mock implementation of cache.SessionCache.
type SessionCache struct {
	mu sync.RWMutex

	// Storage
	sessions map[string]*model.Session // by session ID
	byUserID map[string][]string       // userID -> []sessionID

	// Call tracking
	Calls struct {
		Get            int
		Set            int
		Delete         int
		DeleteByUserID int
		Exists         int
	}

	// Error injection
	Errors struct {
		Get            error
		Set            error
		Delete         error
		DeleteByUserID error
		Exists         error
	}
}

// NewSessionCache creates a new mock SessionCache.
func NewSessionCache() *SessionCache {
	return &SessionCache{
		sessions: make(map[string]*model.Session),
		byUserID: make(map[string][]string),
	}
}

func (m *SessionCache) Get(ctx context.Context, sessionID types.ID) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Get++

	if m.Errors.Get != nil {
		return nil, m.Errors.Get
	}

	session, ok := m.sessions[sessionID.String()]
	if !ok {
		return nil, nil // Cache miss
	}
	return session, nil
}

func (m *SessionCache) Set(ctx context.Context, session *model.Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Set++

	if m.Errors.Set != nil {
		return m.Errors.Set
	}

	sessionID := session.ID().String()
	userID := session.UserID().String()

	m.sessions[sessionID] = session
	m.byUserID[userID] = append(m.byUserID[userID], sessionID)

	return nil
}

func (m *SessionCache) Delete(ctx context.Context, sessionID types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Delete++

	if m.Errors.Delete != nil {
		return m.Errors.Delete
	}

	delete(m.sessions, sessionID.String())
	return nil
}

func (m *SessionCache) DeleteByUserID(ctx context.Context, userID types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteByUserID++

	if m.Errors.DeleteByUserID != nil {
		return m.Errors.DeleteByUserID
	}

	sessionIDs := m.byUserID[userID.String()]
	for _, sid := range sessionIDs {
		delete(m.sessions, sid)
	}
	delete(m.byUserID, userID.String())

	return nil
}

func (m *SessionCache) Exists(ctx context.Context, sessionID types.ID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Exists++

	if m.Errors.Exists != nil {
		return false, m.Errors.Exists
	}

	_, ok := m.sessions[sessionID.String()]
	return ok, nil
}

// Reset clears all data and call counts.
func (m *SessionCache) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions = make(map[string]*model.Session)
	m.byUserID = make(map[string][]string)
	m.Calls = struct {
		Get            int
		Set            int
		Delete         int
		DeleteByUserID int
		Exists         int
	}{}
	m.Errors = struct {
		Get            error
		Set            error
		Delete         error
		DeleteByUserID error
		Exists         error
	}{}
}

// Seed adds a session directly to the mock cache.
func (m *SessionCache) Seed(session *model.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionID := session.ID().String()
	userID := session.UserID().String()

	m.sessions[sessionID] = session
	m.byUserID[userID] = append(m.byUserID[userID], sessionID)
}

// --- UserCache Mock ---

// UserCache is a mock implementation of cache.UserCache.
type UserCache struct {
	mu sync.RWMutex

	// Storage
	users map[string]*model.User // by user ID
	byDID map[string]string      // DID -> userID

	// Call tracking
	Calls struct {
		Get         int
		GetByDID    int
		Set         int
		Delete      int
		DeleteByDID int
	}

	// Error injection
	Errors struct {
		Get         error
		GetByDID    error
		Set         error
		Delete      error
		DeleteByDID error
	}
}

// NewUserCache creates a new mock UserCache.
func NewUserCache() *UserCache {
	return &UserCache{
		users: make(map[string]*model.User),
		byDID: make(map[string]string),
	}
}

func (m *UserCache) Get(ctx context.Context, userID types.ID) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Get++

	if m.Errors.Get != nil {
		return nil, m.Errors.Get
	}

	user, ok := m.users[userID.String()]
	if !ok {
		return nil, nil // Cache miss
	}
	return user, nil
}

func (m *UserCache) GetByDID(ctx context.Context, did string) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.GetByDID++

	if m.Errors.GetByDID != nil {
		return nil, m.Errors.GetByDID
	}

	userID, ok := m.byDID[did]
	if !ok {
		return nil, nil // Cache miss
	}
	return m.users[userID], nil
}

func (m *UserCache) Set(ctx context.Context, user *model.User, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Set++

	if m.Errors.Set != nil {
		return m.Errors.Set
	}

	userID := user.ID().String()
	did := user.DID().String()

	m.users[userID] = user
	m.byDID[did] = userID

	return nil
}

func (m *UserCache) Delete(ctx context.Context, userID types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Delete++

	if m.Errors.Delete != nil {
		return m.Errors.Delete
	}

	user, ok := m.users[userID.String()]
	if ok {
		delete(m.byDID, user.DID().String())
		delete(m.users, userID.String())
	}

	return nil
}

func (m *UserCache) DeleteByDID(ctx context.Context, did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteByDID++

	if m.Errors.DeleteByDID != nil {
		return m.Errors.DeleteByDID
	}

	userID, ok := m.byDID[did]
	if ok {
		delete(m.users, userID)
		delete(m.byDID, did)
	}

	return nil
}

// Reset clears all data and call counts.
func (m *UserCache) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users = make(map[string]*model.User)
	m.byDID = make(map[string]string)
	m.Calls = struct {
		Get         int
		GetByDID    int
		Set         int
		Delete      int
		DeleteByDID int
	}{}
	m.Errors = struct {
		Get         error
		GetByDID    error
		Set         error
		Delete      error
		DeleteByDID error
	}{}
}

// Seed adds a user directly to the mock cache.
func (m *UserCache) Seed(user *model.User) {
	m.mu.Lock()
	defer m.mu.Unlock()

	userID := user.ID().String()
	did := user.DID().String()

	m.users[userID] = user
	m.byDID[did] = userID
}

// --- TokenBlacklist Mock ---

// TokenBlacklist is a mock implementation of cache.TokenBlacklist.
type TokenBlacklist struct {
	mu sync.RWMutex

	// Storage
	blacklisted map[string]time.Time // tokenID -> expiry time

	// Call tracking
	Calls struct {
		Add           int
		IsBlacklisted int
		Remove        int
	}

	// Error injection
	Errors struct {
		Add           error
		IsBlacklisted error
		Remove        error
	}
}

// NewTokenBlacklist creates a new mock TokenBlacklist.
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		blacklisted: make(map[string]time.Time),
	}
}

func (m *TokenBlacklist) Add(ctx context.Context, tokenID string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Add++

	if m.Errors.Add != nil {
		return m.Errors.Add
	}

	if tokenID == "" {
		return nil
	}

	m.blacklisted[tokenID] = time.Now().Add(ttl)
	return nil
}

func (m *TokenBlacklist) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.IsBlacklisted++

	if m.Errors.IsBlacklisted != nil {
		return false, m.Errors.IsBlacklisted
	}

	if tokenID == "" {
		return false, nil
	}

	expiry, ok := m.blacklisted[tokenID]
	if !ok {
		return false, nil
	}

	// Check if expired
	if time.Now().After(expiry) {
		return false, nil
	}

	return true, nil
}

func (m *TokenBlacklist) Remove(ctx context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Remove++

	if m.Errors.Remove != nil {
		return m.Errors.Remove
	}

	delete(m.blacklisted, tokenID)
	return nil
}

// Reset clears all data and call counts.
func (m *TokenBlacklist) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blacklisted = make(map[string]time.Time)
	m.Calls = struct {
		Add           int
		IsBlacklisted int
		Remove        int
	}{}
	m.Errors = struct {
		Add           error
		IsBlacklisted error
		Remove        error
	}{}
}

// Seed adds a token directly to the blacklist.
func (m *TokenBlacklist) Seed(tokenID string, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blacklisted[tokenID] = time.Now().Add(ttl)
}

// Count returns the number of blacklisted tokens.
func (m *TokenBlacklist) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.blacklisted)
}
