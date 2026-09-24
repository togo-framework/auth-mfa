package mfa

import (
	"sync"
	"time"
)

// TOTPSecret is a user's enrolled authenticator secret.
type TOTPSecret struct {
	UserID    string
	Secret    string // base32
	Activated bool
	CreatedAt time.Time
}

// RecoveryCode is a single-use backup code (stored hashed).
type RecoveryCode struct {
	UserID string
	Hash   string
	Used   bool
}

// OTPCode is a time-limited email OTP.
type OTPCode struct {
	UserID  string
	Code    string
	Expires time.Time
}

// Lockout tracks failed-login state for a user.
type Lockout struct {
	Failures    int
	LastFailure time.Time
	LockedUntil time.Time
}

// Store is the MFA persistence seam (swap the in-memory default for a DB one).
type Store interface {
	SetTOTP(TOTPSecret)
	GetTOTP(userID string) (TOTPSecret, bool)
	DeleteTOTP(userID string)

	AddRecoveryCodes(userID string, hashes []string)
	ConsumeRecovery(userID, hash string) bool // returns true if a matching unused code was consumed

	SetOTP(OTPCode)
	GetOTP(userID string) (OTPCode, bool)
	DeleteOTP(userID string)
	OTPSendsSince(userID string, since time.Time) int
	RecordOTPSend(userID string, at time.Time)

	GetLockout(userID string) Lockout
	SetLockout(userID string, l Lockout)

	// ConsumeNonce records a single-use token id; it returns false if the
	// nonce was already used. until is when the nonce can be forgotten.
	ConsumeNonce(nonce string, until time.Time) bool
}

// ---- in-memory store (default) ----

type memStore struct {
	mu       sync.Mutex
	totp     map[string]TOTPSecret
	recovery map[string][]RecoveryCode
	otp      map[string]OTPCode
	otpSends map[string][]time.Time
	lockout  map[string]Lockout
	nonces   map[string]time.Time
}

func newMemStore() *memStore {
	return &memStore{
		totp:     map[string]TOTPSecret{},
		recovery: map[string][]RecoveryCode{},
		otp:      map[string]OTPCode{},
		otpSends: map[string][]time.Time{},
		lockout:  map[string]Lockout{},
		nonces:   map[string]time.Time{},
	}
}

func (m *memStore) SetTOTP(t TOTPSecret) {
	m.mu.Lock()
	m.totp[t.UserID] = t
	m.mu.Unlock()
}

func (m *memStore) GetTOTP(userID string) (TOTPSecret, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.totp[userID]
	return t, ok
}

func (m *memStore) DeleteTOTP(userID string) {
	m.mu.Lock()
	delete(m.totp, userID)
	m.mu.Unlock()
}

func (m *memStore) AddRecoveryCodes(userID string, hashes []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var codes []RecoveryCode
	for _, h := range hashes {
		codes = append(codes, RecoveryCode{UserID: userID, Hash: h})
	}
	m.recovery[userID] = codes
}

func (m *memStore) ConsumeRecovery(userID, hash string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.recovery[userID] {
		if !c.Used && c.Hash == hash {
			m.recovery[userID][i].Used = true
			return true
		}
	}
	return false
}

func (m *memStore) SetOTP(o OTPCode) {
	m.mu.Lock()
	m.otp[o.UserID] = o
	m.mu.Unlock()
}

func (m *memStore) GetOTP(userID string) (OTPCode, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.otp[userID]
	return o, ok
}

func (m *memStore) DeleteOTP(userID string) {
	m.mu.Lock()
	delete(m.otp, userID)
	m.mu.Unlock()
}

func (m *memStore) OTPSendsSince(userID string, since time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.otpSends[userID] {
		if t.After(since) {
			n++
		}
	}
	return n
}

func (m *memStore) RecordOTPSend(userID string, at time.Time) {
	m.mu.Lock()
	m.otpSends[userID] = append(m.otpSends[userID], at)
	m.mu.Unlock()
}

func (m *memStore) GetLockout(userID string) Lockout {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lockout[userID]
}

func (m *memStore) SetLockout(userID string, l Lockout) {
	m.mu.Lock()
	m.lockout[userID] = l
	m.mu.Unlock()
}

func (m *memStore) ConsumeNonce(nonce string, until time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for n, exp := range m.nonces {
		if exp.Before(now) {
			delete(m.nonces, n)
		}
	}
	if _, used := m.nonces[nonce]; used {
		return false
	}
	m.nonces[nonce] = until
	return true
}
