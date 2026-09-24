// Package mfa adds multi-factor auth + account protection to the togo auth
// family: a challenge state-machine (login → challenge token → factor → session),
// TOTP 2FA with recovery codes, email OTP, magic-link login, account lockout,
// and password policy.
//
//	m, _ := mfa.FromKernel(k)
//	if m.Required(userID) { // issue a challenge instead of a session
//	    tok, _ := m.IssueChallenge(userID)
//	}
package mfa

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	authpkg "github.com/togo-framework/auth"
	"github.com/togo-framework/togo"
)

// Config is read from env on boot.
type Config struct {
	ChallengeSecret  []byte
	ChallengeTTL     time.Duration
	OTPTTL           time.Duration
	OTPRatePer10Min  int
	LockoutThreshold int
	LockoutMinutes   int
	PwMinLen         int
	// MagicLinkEnabled gates magic-link sign-in (MFA_MAGIC_LINK=true). Off by
	// default: it is a password replacement and should be a deliberate choice.
	MagicLinkEnabled bool
}

func configFromEnv() Config {
	c := Config{
		// v0.1.0 fell back to the public string "dev-mfa-secret-change-me", so
		// challenges and magic links could be forged wherever it was unset.
		// Now: required in production, random per process in development.
		// When the auth plugin is present its own challenge (AUTH_SECRET) is
		// used instead and this secret only signs magic links.
		ChallengeSecret:  challengeSecret(),
		ChallengeTTL:     5 * time.Minute,
		OTPTTL:           dur("MFA_OTP_TTL", 5*time.Minute),
		OTPRatePer10Min:  3,
		LockoutThreshold: atoi("MFA_LOCKOUT_THRESHOLD", 5),
		LockoutMinutes:   atoi("MFA_LOCKOUT_MINUTES", 15),
		PwMinLen:         atoi("MFA_PW_MIN_LEN", 12),
		MagicLinkEnabled: env("MFA_MAGIC_LINK", "") == "true",
	}
	return c
}

// Service is the MFA runtime stored on the kernel (k.Get("mfa")).
type Service struct {
	k     *togo.Kernel
	cfg   Config
	mu    sync.Mutex
	store Store
}

func init() {
	togo.RegisterProviderFunc("auth-mfa", togo.PriorityLate+10, func(k *togo.Kernel) error {
		if production() && os.Getenv("MFA_CHALLENGE_SECRET") == "" {
			return fmt.Errorf("auth-mfa: MFA_CHALLENGE_SECRET is required in production (>= 32 bytes)")
		}
		s := &Service{k: k, cfg: configFromEnv(), store: newMemStore()}
		// Persist factors in the kernel database. v0.1.0 kept them in memory,
		// so every enrolment and recovery code vanished on restart.
		if db, err := k.SQL(context.Background()); err == nil {
			store, err := newSQLStore(context.Background(), db, k.Dialect().Placeholder)
			if err != nil {
				return err
			}
			s.store = store
		}
		// Make auth's own login enforce this plugin's TOTP.
		authpkg.RegisterSecondFactor(func(_ context.Context, userID string) bool { return s.Required(userID) })
		k.Set("mfa", s)
		if k.Router != nil {
			s.mountRoutes(k.Router)
		}
		return nil
	})
}

// FromKernel returns the MFA Service.
func FromKernel(k *togo.Kernel) (*Service, bool) {
	v, ok := k.Get("mfa")
	if !ok {
		return nil, false
	}
	s, ok := v.(*Service)
	return s, ok
}

// WithStore swaps the backing store (e.g. a DB-backed one).
func (s *Service) WithStore(store Store) *Service {
	s.store = store
	return s
}

// Config returns the active configuration.
func (s *Service) Cfg() Config { return s.cfg }

// Required reports whether the user has any active factor (TOTP enrolled).
func (s *Service) Required(userID string) bool {
	t, ok := s.store.GetTOTP(userID)
	return ok && t.Activated
}

// ---- challenge tokens (HMAC-signed, purpose=mfa) ----

type challenge struct {
	UserID  string `json:"uid"`
	Purpose string `json:"p"`
	Nonce   string `json:"n,omitempty"`
	Exp     int64  `json:"exp"`
}

// IssueChallenge mints a short-lived signed challenge token (NOT a session).
func (s *Service) IssueChallenge(userID string) (string, error) {
	c := challenge{UserID: userID, Purpose: "mfa", Exp: time.Now().Add(s.cfg.ChallengeTTL).Unix()}
	body, _ := json.Marshal(c)
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + s.sign(b), nil
}

// VerifyChallenge validates a challenge token and returns its user id.
func (s *Service) VerifyChallenge(token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		return "", fmt.Errorf("mfa: invalid challenge token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("mfa: malformed challenge token")
	}
	var c challenge
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", err
	}
	if c.Purpose != "mfa" {
		return "", fmt.Errorf("mfa: not an mfa challenge")
	}
	if time.Now().Unix() > c.Exp {
		return "", fmt.Errorf("mfa: challenge expired")
	}
	return c.UserID, nil
}

func (s *Service) sign(msg string) string {
	mac := hmac.New(sha256.New, s.cfg.ChallengeSecret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ---- account lockout ----

// RecordFailure increments a user's failure counter; locks after the threshold.
func (s *Service) RecordFailure(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.store.GetLockout(userID)
	l.Failures++
	l.LastFailure = time.Now()
	if l.Failures >= s.cfg.LockoutThreshold {
		l.LockedUntil = time.Now().Add(time.Duration(s.cfg.LockoutMinutes) * time.Minute)
	}
	s.store.SetLockout(userID, l)
}

// Reset clears a user's failure/lock state (call on a successful login).
func (s *Service) Reset(userID string) { s.store.SetLockout(userID, Lockout{}) }

// IsLocked reports whether a user is currently locked, and until when.
func (s *Service) IsLocked(userID string) (bool, time.Time) {
	l := s.store.GetLockout(userID)
	if l.LockedUntil.After(time.Now()) {
		return true, l.LockedUntil
	}
	return false, time.Time{}
}

// ---- password policy ----

// ValidatePassword checks a password against the configured policy.
func (s *Service) ValidatePassword(pw string) error {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?/~`", r):
			hasSymbol = true
		}
	}
	var missing []string
	if len(pw) < s.cfg.PwMinLen {
		missing = append(missing, fmt.Sprintf("at least %d characters", s.cfg.PwMinLen))
	}
	if !hasUpper {
		missing = append(missing, "an uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "a lowercase letter")
	}
	if !hasDigit {
		missing = append(missing, "a digit")
	}
	if !hasSymbol {
		missing = append(missing, "a symbol")
	}
	if len(missing) > 0 {
		return fmt.Errorf("password must contain %s", strings.Join(missing, ", "))
	}
	return nil
}

func challengeSecret() []byte {
	if v := os.Getenv("MFA_CHALLENGE_SECRET"); v != "" {
		return []byte(v)
	}
	b := make([]byte, 32)
	_, _ = cryptorand.Read(b)
	return b
}

func production() bool {
	e := strings.ToLower(os.Getenv("APP_ENV"))
	return e == "production" || e == "prod"
}

// ---- env helpers ----

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func atoi(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func dur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
