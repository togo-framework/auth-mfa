# auth-mfa — usage

## Challenge flow
After primary login, if the user has a factor enrolled, issue a challenge token
instead of a session:
```go
m, _ := mfa.FromKernel(k)
if m.Required(userID) {
    tok, _ := m.IssueChallenge(userID)   // 5-min HMAC token, purpose=mfa
    // return {mfa_required:true, challenge: tok}
}
```
The client then POSTs a factor with the `challenge` field; on success the plugin
calls `auth.IssueSession` and returns the real session.

## TOTP 2FA
```go
secret, otpauthURL, _ := m.EnrollTOTP(userID, "MyApp")  // render otpauthURL as a QR
m.VerifyTOTP(userID, code)                               // activates on first valid code
m.DisableTOTP(userID)
```
Endpoints: `POST /api/auth/mfa/totp/{enroll,verify,disable}`.

## Recovery codes
```go
codes := m.GenerateRecoveryCodes(userID, 8)  // show ONCE
m.VerifyRecoveryCode(userID, code)           // single-use
```

## Email OTP
```go
code, err := m.SendOTP(userID)   // rate-limited 3/10min; deliver via mail plugin
m.VerifyOTP(userID, code)        // single-use, 5-min expiry
```

## Magic-link
```go
tok := m.MagicLinkToken(userID)          // email /api/auth/mfa/magic-link/verify?token=<tok>
uid, _ := m.VerifyMagicLink(tok)         // → issue a session
```

## Account lockout + password policy
```go
m.RecordFailure(userID); m.Reset(userID)
locked, until := m.IsLocked(userID)      // N failures (5) → locked M min (15)
m.ValidatePassword(pw)                   // min len + upper/lower/digit/symbol
```

## Persistence
Default store is in-memory; implement the `Store` interface + `m.WithStore(...)` for DB-backed TOTP secrets / recovery codes / lockout counters.
