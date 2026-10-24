package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/togo-framework/togo"

	authpkg "github.com/togo-framework/auth"
)

// jsonMarshal/jsonUnmarshal are small indirections so factors.go can stay
// import-light; they just proxy encoding/json.
func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// Events fired for delivery. The code or link is never returned over HTTP; a
// mail/SMS/notifications listener sends it.
const (
	EventOTPRequested       = "mfa.otp_requested"        // {user_id, code}
	EventMagicLinkRequested = "mfa.magic_link_requested" // {user_id, email, token}
)

// Routes, v0.2.0. Before this version every route took the user from a
// user_id in the query, a header or the body, with no session and no
// challenge: anyone could enrol their own authenticator on another account and
// sign in as it, mint and redeem its recovery codes, or switch its 2FA off.
//
//   - Management routes (enrol, disable, recovery codes) act on the signed-in
//     session's user and require the auth plugin.
//   - Factor routes (verify a TOTP, OTP or recovery code) act on the user named
//     by a login challenge — the one /api/auth/login returns — never on a
//     caller-supplied id.
//   - Completion issues the session through auth, with roles and permissions.
func (s *Service) mountRoutes(r chi.Router) {
	r.Route("/api/auth/mfa", func(r chi.Router) {
		// Management: signed-in user only.
		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Post("/totp/enroll", s.handleEnroll)
			r.Post("/totp/activate", s.handleActivate)
			r.Post("/totp/disable", s.handleTOTPDisable)
			r.Post("/recovery/generate", s.handleRecoveryGenerate)
		})
		// Factors: a login challenge names the user.
		r.Post("/totp/verify", s.handleTOTPVerify)
		r.Post("/recovery/verify", s.handleRecoveryVerify)
		r.Post("/otp/send", s.handleOTPSend)
		r.Post("/otp/verify", s.handleOTPVerify)
		// Magic link: off unless MFA_MAGIC_LINK=true.
		r.Post("/magic-link/send", s.handleMagicSend)
		r.Get("/magic-link/verify", s.handleMagicVerify)
	})
}

func (s *Service) auth() (*authpkg.Service, bool) {
	if s.k == nil {
		return nil, false
	}
	return authpkg.FromKernel(s.k)
}

// requireSession runs auth's session middleware; without the auth plugin there
// is no way to know who is asking, so management is unavailable.
func (s *Service) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.auth()
		if !ok {
			writeErr(w, http.StatusNotImplemented, "mfa management needs the auth plugin")
			return
		}
		a.Middleware(next).ServeHTTP(w, r)
	})
}

func sessionUser(r *http.Request) (authpkg.Identity, bool) {
	id, ok := authpkg.IdentityFrom(r.Context())
	if !ok || id == nil || id.ID == "" {
		return authpkg.Identity{}, false
	}
	return *id, true
}

// challengeUser resolves the user from a login challenge. It prefers auth's
// challenge (issued by /api/auth/login) and falls back to this plugin's own
// signed challenge only when auth is absent.
func (s *Service) challengeUser(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	if a, ok := s.auth(); ok {
		uid, err := a.VerifyLoginChallenge(token)
		return uid, err == nil
	}
	uid, err := s.VerifyChallenge(token)
	return uid, err == nil
}

type factorBody struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// verifyFactor is the shared shape of every factor route: resolve the user from
// the challenge, refuse while locked out, check the code, count failures.
func (s *Service) verifyFactor(w http.ResponseWriter, r *http.Request, check func(uid, code string) bool) {
	var body factorBody
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Code == "" {
		writeErr(w, http.StatusBadRequest, "challenge and code required")
		return
	}
	uid, ok := s.challengeUser(body.Challenge)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "challenge invalid or expired; sign in again")
		return
	}
	if locked, _ := s.IsLocked(uid); locked {
		writeErr(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	if !check(uid, strings.TrimSpace(body.Code)) {
		s.RecordFailure(uid)
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.completeChallenge(w, r.Context(), uid)
}

func (s *Service) handleEnroll(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionUser(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "sign in first")
		return
	}
	if s.Required(id.ID) {
		writeErr(w, http.StatusConflict, "2fa already enabled; disable it with a valid code first")
		return
	}
	issuer := env("MFA_ISSUER", "togo")
	secret, uri, err := s.EnrollTOTP(id.ID, issuer)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "enroll failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": uri})
}

// handleActivate confirms enrolment with the first code from the new app.
func (s *Service) handleActivate(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionUser(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "sign in first")
		return
	}
	var body factorBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.ActivateTOTP(id.ID, body.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes": s.GenerateRecoveryCodes(id.ID, 8)})
}

// handleTOTPDisable needs a valid TOTP or recovery code: a stolen session alone
// must not be able to remove the second factor.
func (s *Service) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionUser(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "sign in first")
		return
	}
	var body factorBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	code := strings.TrimSpace(body.Code)
	if !s.VerifyTOTP(id.ID, code) && !s.VerifyRecoveryCode(id.ID, code) {
		s.RecordFailure(id.ID)
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.DisableTOTP(id.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": true})
}

func (s *Service) handleRecoveryGenerate(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionUser(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "sign in first")
		return
	}
	// Regenerating replaces the old codes, so it needs the current factor.
	var body factorBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	if s.Required(id.ID) && !s.VerifyTOTP(id.ID, body.Code) {
		writeErr(w, http.StatusUnauthorized, "a current 2fa code is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"codes": s.GenerateRecoveryCodes(id.ID, 8)})
}

func (s *Service) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	s.verifyFactor(w, r, s.VerifyTOTP)
}

func (s *Service) handleRecoveryVerify(w http.ResponseWriter, r *http.Request) {
	s.verifyFactor(w, r, s.VerifyRecoveryCode)
}

func (s *Service) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	s.verifyFactor(w, r, s.VerifyOTP)
}

func (s *Service) handleOTPSend(w http.ResponseWriter, r *http.Request) {
	var body factorBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	uid, ok := s.challengeUser(body.Challenge)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "challenge invalid or expired; sign in again")
		return
	}
	code, err := s.SendOTP(uid)
	if err != nil {
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return
	}
	// Before v0.2.0 the code was generated and never sent anywhere.
	s.fire(r.Context(), EventOTPRequested, map[string]string{"user_id": uid, "code": code})
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Service) handleMagicSend(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.MagicLinkEnabled {
		writeErr(w, http.StatusNotFound, "magic links are disabled")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	email := strings.TrimSpace(body.Email)
	if email == "" {
		writeErr(w, http.StatusBadRequest, "email required")
		return
	}
	// Same answer whether or not the account exists; only real accounts get a
	// link, and it is delivered, never returned. v0.1.0 returned a working
	// sign-in link to whoever asked, for any address, and created the account.
	defer writeJSON(w, http.StatusAccepted, map[string]string{"status": "if that account exists, a sign-in link has been sent"})
	a, ok := s.auth()
	if !ok {
		return
	}
	id, err := a.FindByEmail(r.Context(), email)
	if err != nil || id == nil {
		return
	}
	// Throttled silently: a different answer would tell the caller the
	// account exists.
	token, err := s.RequestMagicLink(id.ID)
	if err != nil {
		return
	}
	s.fire(r.Context(), EventMagicLinkRequested, map[string]string{
		"user_id": id.ID, "email": id.Email, "token": token,
	})
}

func (s *Service) handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.MagicLinkEnabled {
		writeErr(w, http.StatusNotFound, "magic links are disabled")
		return
	}
	uid, err := s.VerifyMagicLink(r.URL.Query().Get("token"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "link invalid, used or expired")
		return
	}
	// A magic link replaces the password, not the second factor.
	if a, ok := s.auth(); ok && a.SecondFactorRequired(r.Context(), uid) {
		challenge, err := a.IssueLoginChallenge(uid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "sign-in failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "challenge": challenge})
		return
	}
	s.completeChallenge(w, r.Context(), uid)
}

// completeChallenge issues the session after every factor has passed.
func (s *Service) completeChallenge(w http.ResponseWriter, ctx context.Context, userID string) {
	s.Reset(userID) // clear lockout on success
	a, ok := s.auth()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"verified": true, "user_id": userID, "note": "auth plugin not present; no session issued"})
		return
	}
	// Through auth, so the session carries the account's roles and permissions
	// (v0.1.0 issued a bare {ID} identity with none).
	a.CompleteLogin(w, ctx, userID)
}

func (s *Service) fire(ctx context.Context, event string, payload any) {
	if s.k != nil && s.k.Hooks != nil {
		_ = s.k.Hooks.Fire(ctx, event, payload)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var _ = togo.PriorityLate
