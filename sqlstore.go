package mfa

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"
)

// sqlStore persists MFA state in the kernel database, so enrolments, recovery
// codes and lockouts survive a restart (v0.1.0 kept them in memory). Columns
// are TEXT for cross-driver portability, like togo's auth tables; placeholders
// come from the kernel dialect.
type sqlStore struct {
	db *sql.DB
	ph func(int) string
}

func newSQLStore(ctx context.Context, db *sql.DB, ph func(int) string) (*sqlStore, error) {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS mfa_totp (user_id text PRIMARY KEY, secret text NOT NULL, activated text NOT NULL DEFAULT '', created_at text NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mfa_recovery (user_id text NOT NULL, hash text NOT NULL, used text NOT NULL DEFAULT '', PRIMARY KEY (user_id, hash))`,
		`CREATE TABLE IF NOT EXISTS mfa_otp (user_id text PRIMARY KEY, code_hash text NOT NULL, expires_at text NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mfa_otp_sends (user_id text NOT NULL, sent_at text NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mfa_lockout (user_id text PRIMARY KEY, failures text NOT NULL, last_failure text NOT NULL, locked_until text NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mfa_nonces (nonce text PRIMARY KEY, expires_at text NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, err
		}
	}
	return &sqlStore{db: db, ph: ph}, nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// q substitutes ?-style markers with the dialect's placeholders ($1… on Postgres).
func (s *sqlStore) q(query string) string {
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString(s.ph(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *sqlStore) exec(query string, args ...any) {
	_, _ = s.db.ExecContext(context.Background(), s.q(query), args...)
}

func (s *sqlStore) SetTOTP(t TOTPSecret) {
	activated := ""
	if t.Activated {
		activated = "true"
	}
	s.exec(`INSERT INTO mfa_totp (user_id, secret, activated, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, activated = excluded.activated, created_at = excluded.created_at`,
		t.UserID, t.Secret, activated, ts(t.CreatedAt))
}

func (s *sqlStore) GetTOTP(userID string) (TOTPSecret, bool) {
	var secret, activated, created string
	err := s.db.QueryRowContext(context.Background(),
		s.q(`SELECT secret, activated, created_at FROM mfa_totp WHERE user_id = ?`), userID).Scan(&secret, &activated, &created)
	if err != nil {
		return TOTPSecret{}, false
	}
	return TOTPSecret{UserID: userID, Secret: secret, Activated: activated == "true", CreatedAt: parseTS(created)}, true
}

func (s *sqlStore) DeleteTOTP(userID string) {
	s.exec(`DELETE FROM mfa_totp WHERE user_id = ?`, userID)
	s.exec(`DELETE FROM mfa_recovery WHERE user_id = ?`, userID)
}

func (s *sqlStore) AddRecoveryCodes(userID string, hashes []string) {
	// New codes replace the old set.
	s.exec(`DELETE FROM mfa_recovery WHERE user_id = ?`, userID)
	for _, h := range hashes {
		s.exec(`INSERT INTO mfa_recovery (user_id, hash, used) VALUES (?, ?, '')`, userID, h)
	}
}

func (s *sqlStore) ConsumeRecovery(userID, hash string) bool {
	res, err := s.db.ExecContext(context.Background(),
		s.q(`UPDATE mfa_recovery SET used = 'true' WHERE user_id = ? AND hash = ? AND used = ''`), userID, hash)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (s *sqlStore) SetOTP(o OTPCode) {
	s.exec(`INSERT INTO mfa_otp (user_id, code_hash, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at`,
		o.UserID, o.Code, ts(o.Expires))
}

func (s *sqlStore) GetOTP(userID string) (OTPCode, bool) {
	var code, expires string
	if s.db.QueryRowContext(context.Background(),
		s.q(`SELECT code_hash, expires_at FROM mfa_otp WHERE user_id = ?`), userID).Scan(&code, &expires) != nil {
		return OTPCode{}, false
	}
	return OTPCode{UserID: userID, Code: code, Expires: parseTS(expires)}, true
}

func (s *sqlStore) DeleteOTP(userID string) { s.exec(`DELETE FROM mfa_otp WHERE user_id = ?`, userID) }

func (s *sqlStore) OTPSendsSince(userID string, since time.Time) int {
	var n int
	_ = s.db.QueryRowContext(context.Background(),
		s.q(`SELECT COUNT(*) FROM mfa_otp_sends WHERE user_id = ? AND sent_at > ?`), userID, ts(since)).Scan(&n)
	return n
}

func (s *sqlStore) RecordOTPSend(userID string, at time.Time) {
	s.exec(`INSERT INTO mfa_otp_sends (user_id, sent_at) VALUES (?, ?)`, userID, ts(at))
	s.exec(`DELETE FROM mfa_otp_sends WHERE sent_at < ?`, ts(at.Add(-24*time.Hour)))
}

func (s *sqlStore) GetLockout(userID string) Lockout {
	var failures, last, until string
	if s.db.QueryRowContext(context.Background(),
		s.q(`SELECT failures, last_failure, locked_until FROM mfa_lockout WHERE user_id = ?`), userID).Scan(&failures, &last, &until) != nil {
		return Lockout{}
	}
	n, _ := strconv.Atoi(failures)
	return Lockout{Failures: n, LastFailure: parseTS(last), LockedUntil: parseTS(until)}
}

func (s *sqlStore) SetLockout(userID string, l Lockout) {
	s.exec(`INSERT INTO mfa_lockout (user_id, failures, last_failure, locked_until) VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET failures = excluded.failures, last_failure = excluded.last_failure, locked_until = excluded.locked_until`,
		userID, strconv.Itoa(l.Failures), ts(l.LastFailure), ts(l.LockedUntil))
}

func (s *sqlStore) ConsumeNonce(nonce string, until time.Time) bool {
	now := ts(time.Now())
	s.exec(`DELETE FROM mfa_nonces WHERE expires_at < ?`, now)
	res, err := s.db.ExecContext(context.Background(),
		s.q(`INSERT INTO mfa_nonces (nonce, expires_at) VALUES (?, ?) ON CONFLICT (nonce) DO NOTHING`), nonce, ts(until))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}
