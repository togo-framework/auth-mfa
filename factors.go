package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ---- TOTP 2FA ----

// EnrollTOTP generates a new (inactive) TOTP secret for a user and returns the
// otpauth:// provisioning URI (render it as a QR code client-side).
func (s *Service) EnrollTOTP(userID, issuer string) (secret, uri string, err error) {
	// Never overwrite an active secret: that silently switched 2FA off.
	if s.Required(userID) {
		return "", "", fmt.Errorf("mfa: 2fa already enabled")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: orDefault(issuer, "togo"), AccountName: userID})
	if err != nil {
		return "", "", err
	}
	s.store.SetTOTP(TOTPSecret{UserID: userID, Secret: key.Secret(), Activated: false, CreatedAt: time.Now()})
	return key.Secret(), key.URL(), nil
}

// VerifyTOTP checks a code against an ACTIVE secret. A pending enrolment is
// never accepted as a login factor; it only becomes one through ActivateTOTP.
func (s *Service) VerifyTOTP(userID, code string) bool {
	t, ok := s.store.GetTOTP(userID)
	if !ok || !t.Activated {
		return false
	}
	return totp.Validate(strings.TrimSpace(code), t.Secret)
}

// ActivateTOTP confirms a pending enrolment with the first code from the app.
func (s *Service) ActivateTOTP(userID, code string) bool {
	t, ok := s.store.GetTOTP(userID)
	if !ok || t.Activated || !totp.Validate(strings.TrimSpace(code), t.Secret) {
		return false
	}
	t.Activated = true
	s.store.SetTOTP(t)
	return true
}

// ValidateTOTPAt verifies a code at a specific time (used by tests).
func (s *Service) ValidateTOTPAt(secret, code string, at time.Time) (bool, error) {
	return totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
}

// DisableTOTP removes a user's TOTP enrollment.
func (s *Service) DisableTOTP(userID string) { s.store.DeleteTOTP(userID) }

// ---- recovery codes ----

// GenerateRecoveryCodes creates n single-use codes, stores their hashes, and
// returns the plaintext codes (shown to the user ONCE).
func (s *Service) GenerateRecoveryCodes(userID string, n int) []string {
	if n <= 0 {
		n = 8
	}
	codes := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		c := randCode(10)
		codes = append(codes, c)
		hashes = append(hashes, hashCode(c))
	}
	s.store.AddRecoveryCodes(userID, hashes)
	return codes
}

// VerifyRecoveryCode consumes a single-use recovery code.
func (s *Service) VerifyRecoveryCode(userID, code string) bool {
	return s.store.ConsumeRecovery(userID, hashCode(strings.TrimSpace(code)))
}

// ---- email OTP ----

// SendOTP generates a 6-digit code for the user (rate-limited). The caller is
// responsible for delivery (email/SMS); the code is returned for the caller to
// send (and logged in dev). Returns the code + an error if rate-limited.
func (s *Service) SendOTP(userID string) (string, error) {
	window := time.Now().Add(-10 * time.Minute)
	if s.store.OTPSendsSince(userID, window) >= s.cfg.OTPRatePer10Min {
		return "", fmt.Errorf("mfa: too many OTP requests, try again later")
	}
	code := randDigits(6)
	// Stored hashed; the plaintext only leaves via the delivery event.
	s.store.SetOTP(OTPCode{UserID: userID, Code: hashCode(code), Expires: time.Now().Add(s.cfg.OTPTTL)})
	s.store.RecordOTPSend(userID, time.Now())
	return code, nil
}

// VerifyOTP checks an email OTP (single-use, expiring).
func (s *Service) VerifyOTP(userID, code string) bool {
	o, ok := s.store.GetOTP(userID)
	if !ok || time.Now().After(o.Expires) ||
		subtle.ConstantTimeCompare([]byte(o.Code), []byte(hashCode(strings.TrimSpace(code)))) != 1 {
		return false
	}
	s.store.DeleteOTP(userID)
	return true
}

// ---- magic-link ----

// MagicLinkToken mints a signed login token for a user (reuses the challenge
// signing with a distinct purpose).
func (s *Service) MagicLinkToken(userID string) string {
	c := challenge{UserID: userID, Purpose: "magic", Nonce: randCode(16), Exp: time.Now().Add(15 * time.Minute).Unix()}
	body, _ := jsonMarshal(c)
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + s.sign(b)
}

// VerifyMagicLink validates a magic-link token, returning the user id.
func (s *Service) VerifyMagicLink(token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		return "", fmt.Errorf("mfa: invalid magic link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	var c challenge
	if err := jsonUnmarshal(raw, &c); err != nil {
		return "", err
	}
	if c.Purpose != "magic" || time.Now().Unix() > c.Exp || c.Nonce == "" {
		return "", fmt.Errorf("mfa: magic link invalid or expired")
	}
	// Single-use: a forwarded or leaked link works at most once.
	if !s.store.ConsumeNonce("magic:"+c.Nonce, time.Unix(c.Exp, 0)) {
		return "", fmt.Errorf("mfa: magic link already used")
	}
	return c.UserID, nil
}

// ---- helpers ----

func hashCode(c string) string {
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randCode(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
		b.WriteByte(codeAlphabet[idx.Int64()])
		if i == n/2-1 {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func randDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteString(d.String())
	}
	return b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
