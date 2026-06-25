package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func newTestService() *Service {
	return &Service{cfg: configFromEnv(), store: newMemStore()}
}

func TestPasswordPolicy(t *testing.T) {
	s := newTestService()
	if err := s.ValidatePassword("short"); err == nil {
		t.Error("short password should fail")
	}
	if err := s.ValidatePassword("alllowercase123!"); err == nil {
		t.Error("missing uppercase should fail")
	}
	if err := s.ValidatePassword("NoSymbolsHere123"); err == nil {
		t.Error("missing symbol should fail")
	}
	if err := s.ValidatePassword("Str0ng&Passw0rd!"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
}

func TestChallengeTokenRoundTripAndReject(t *testing.T) {
	s := newTestService()
	tok, err := s.IssueChallenge("user-1")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := s.VerifyChallenge(tok)
	if err != nil || uid != "user-1" {
		t.Fatalf("verify = %q, %v", uid, err)
	}
	// Tampered token is rejected.
	if _, err := s.VerifyChallenge(tok + "x"); err == nil {
		t.Error("tampered challenge should be rejected")
	}
	// A magic-link token must NOT verify as an mfa challenge (purpose mismatch).
	magic := s.MagicLinkToken("user-1")
	if _, err := s.VerifyChallenge(magic); err == nil {
		t.Error("magic token must not pass as an mfa challenge")
	}
}

func TestTOTPEnrollVerifyDisable(t *testing.T) {
	s := newTestService()
	secret, uri, err := s.EnrollTOTP("user-1", "togo")
	if err != nil || secret == "" || uri == "" {
		t.Fatalf("enroll = %q,%q,%v", secret, uri, err)
	}
	if s.Required("user-1") {
		t.Error("not activated until first verify")
	}
	// Generate a valid code for the current time-step.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyTOTP("user-1", code) {
		t.Fatal("valid TOTP code rejected")
	}
	if !s.Required("user-1") {
		t.Error("should be activated after verify")
	}
	if s.VerifyTOTP("user-1", "000000") {
		t.Error("wrong code should fail")
	}
	s.DisableTOTP("user-1")
	if s.Required("user-1") {
		t.Error("disable should clear TOTP")
	}
}

func TestRecoveryCodesSingleUse(t *testing.T) {
	s := newTestService()
	codes := s.GenerateRecoveryCodes("user-1", 8)
	if len(codes) != 8 {
		t.Fatalf("got %d codes", len(codes))
	}
	if !s.VerifyRecoveryCode("user-1", codes[0]) {
		t.Fatal("first use should succeed")
	}
	if s.VerifyRecoveryCode("user-1", codes[0]) {
		t.Error("second use of the same code should fail")
	}
	if s.VerifyRecoveryCode("user-1", "BOGUS-CODE") {
		t.Error("unknown code should fail")
	}
}

func TestOTPSendVerifyExpiryRateLimit(t *testing.T) {
	s := newTestService()
	code, err := s.SendOTP("user-1")
	if err != nil || len(code) != 6 {
		t.Fatalf("send = %q,%v", code, err)
	}
	if s.VerifyOTP("user-1", "999999") && code != "999999" {
		t.Error("wrong otp should fail")
	}
	if !s.VerifyOTP("user-1", code) {
		t.Fatal("correct otp should verify")
	}
	if s.VerifyOTP("user-1", code) {
		t.Error("otp is single-use")
	}
	// Rate limit: threshold is 3 per 10 min; we already sent once.
	_, _ = s.SendOTP("user-1")
	_, _ = s.SendOTP("user-1")
	if _, err := s.SendOTP("user-1"); err == nil {
		t.Error("4th send in the window should be rate-limited")
	}
}

func TestOTPExpiry(t *testing.T) {
	s := newTestService()
	s.store.SetOTP(OTPCode{UserID: "u", Code: "123456", Expires: time.Now().Add(-time.Minute)})
	if s.VerifyOTP("u", "123456") {
		t.Error("expired otp should fail")
	}
}

func TestLockout(t *testing.T) {
	s := newTestService() // threshold 5, 15 min
	for i := 0; i < 4; i++ {
		s.RecordFailure("user-1")
	}
	if locked, _ := s.IsLocked("user-1"); locked {
		t.Error("4 failures should not lock (threshold 5)")
	}
	s.RecordFailure("user-1")
	locked, until := s.IsLocked("user-1")
	if !locked || !until.After(time.Now()) {
		t.Fatalf("5 failures should lock: %v %v", locked, until)
	}
	s.Reset("user-1")
	if locked, _ := s.IsLocked("user-1"); locked {
		t.Error("reset should clear lockout")
	}
}

func TestMagicLink(t *testing.T) {
	s := newTestService()
	tok := s.MagicLinkToken("user-9")
	uid, err := s.VerifyMagicLink(tok)
	if err != nil || uid != "user-9" {
		t.Fatalf("verify = %q,%v", uid, err)
	}
	if _, err := s.VerifyMagicLink(tok + "x"); err == nil {
		t.Error("tampered magic link should fail")
	}
}
