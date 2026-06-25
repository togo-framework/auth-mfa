package mfa

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/togo-framework/togo"

	authpkg "github.com/togo-framework/auth"
)

// jsonMarshal/jsonUnmarshal are small indirections so factors.go can stay
// import-light; they just proxy encoding/json.
func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func (s *Service) mountRoutes(r chi.Router) {
	r.Route("/api/auth/mfa", func(r chi.Router) {
		// TOTP
		r.Post("/totp/enroll", s.handleEnroll)
		r.Post("/totp/verify", s.handleTOTPVerify)
		r.Post("/totp/disable", s.handleTOTPDisable)
		// recovery
		r.Post("/recovery/generate", s.handleRecoveryGenerate)
		r.Post("/recovery/verify", s.handleRecoveryVerify)
		// email OTP
		r.Post("/otp/send", s.handleOTPSend)
		r.Post("/otp/verify", s.handleOTPVerify)
		// magic-link
		r.Post("/magic-link/send", s.handleMagicSend)
		r.Get("/magic-link/verify", s.handleMagicVerify)
		// challenge status
		r.Get("/challenge/status", s.handleChallengeStatus)
	})
}

func subject(r *http.Request) string {
	if v := r.URL.Query().Get("user_id"); v != "" {
		return v
	}
	if v := r.Header.Get("X-User-Id"); v != "" {
		return v
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return body.UserID
}

func (s *Service) handleEnroll(w http.ResponseWriter, r *http.Request) {
	uid := subject(r)
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	secret, uri, err := s.EnrollTOTP(uid, "togo")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"secret": secret, "otpauth_url": uri})
}

func (s *Service) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserID, Code, Challenge string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	uid := body.UserID
	if body.Challenge != "" {
		if u, err := s.VerifyChallenge(body.Challenge); err == nil {
			uid = u
		}
	}
	if uid == "" || !s.VerifyTOTP(uid, body.Code) {
		writeErr(w, 401, "invalid code")
		return
	}
	s.completeChallenge(w, uid)
}

func (s *Service) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	s.DisableTOTP(subject(r))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Service) handleRecoveryGenerate(w http.ResponseWriter, r *http.Request) {
	uid := subject(r)
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	writeJSON(w, 200, map[string]any{"codes": s.GenerateRecoveryCodes(uid, 8)})
}

func (s *Service) handleRecoveryVerify(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserID, Code, Challenge string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	uid := body.UserID
	if body.Challenge != "" {
		if u, err := s.VerifyChallenge(body.Challenge); err == nil {
			uid = u
		}
	}
	if uid == "" || !s.VerifyRecoveryCode(uid, body.Code) {
		writeErr(w, 401, "invalid recovery code")
		return
	}
	s.completeChallenge(w, uid)
}

func (s *Service) handleOTPSend(w http.ResponseWriter, r *http.Request) {
	uid := subject(r)
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	code, err := s.SendOTP(uid)
	if err != nil {
		writeErr(w, 429, err.Error())
		return
	}
	// Deliver via the mail/notifications plugin in production; log in dev.
	slog.Info("auth-mfa: OTP issued", "user", uid, "code_len", len(code))
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

func (s *Service) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserID, Code, Challenge string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	uid := body.UserID
	if body.Challenge != "" {
		if u, err := s.VerifyChallenge(body.Challenge); err == nil {
			uid = u
		}
	}
	if uid == "" || !s.VerifyOTP(uid, body.Code) {
		writeErr(w, 401, "invalid or expired code")
		return
	}
	s.completeChallenge(w, uid)
}

func (s *Service) handleMagicSend(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Email == "" {
		writeErr(w, 400, "email required")
		return
	}
	uid := body.Email
	if a, ok := authpkg.FromKernel(s.k); ok {
		if id, err := a.FindOrCreateByEmail(context.Background(), body.Email); err == nil {
			uid = id.ID
		}
	}
	tok := s.MagicLinkToken(uid)
	slog.Info("auth-mfa: magic link issued", "email", body.Email)
	// In production email the link; in dev return it.
	writeJSON(w, 200, map[string]string{"status": "sent", "link": "/api/auth/mfa/magic-link/verify?token=" + tok})
}

func (s *Service) handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	uid, err := s.VerifyMagicLink(r.URL.Query().Get("token"))
	if err != nil {
		writeErr(w, 401, err.Error())
		return
	}
	s.completeChallenge(w, uid)
}

func (s *Service) handleChallengeStatus(w http.ResponseWriter, r *http.Request) {
	uid, err := s.VerifyChallenge(r.URL.Query().Get("challenge"))
	if err != nil {
		writeErr(w, 401, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"user_id": uid, "totp": s.Required(uid)})
}

// completeChallenge issues the real auth session after a factor succeeds.
func (s *Service) completeChallenge(w http.ResponseWriter, userID string) {
	s.Reset(userID) // clear lockout on a successful MFA completion
	a, ok := authpkg.FromKernel(s.k)
	if !ok {
		writeJSON(w, 200, map[string]any{"verified": true, "user_id": userID, "note": "auth plugin not present; no session issued"})
		return
	}
	id := authpkg.Identity{ID: userID}
	tok, err := a.IssueSession(w, id)
	if err != nil {
		// fall back to a bearer token
		if t2, err2 := a.IssueToken(id); err2 == nil {
			writeJSON(w, 200, map[string]any{"verified": true, "user_id": userID, "token": t2})
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"verified": true, "user_id": userID, "session": tok})
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
