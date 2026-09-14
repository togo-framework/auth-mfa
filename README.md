<div align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/togo-mark-dark.svg" /><img src=".github/assets/togo-mark.svg" alt="ToGO" height="64" /></picture>
  <h1>togo-framework/auth-mfa</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1F8A99" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/auth-mfa"><img src="https://pkg.go.dev/badge/github.com/togo-framework/auth-mfa.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>Multi-factor auth &amp; account protection for the <a href="https://to-go.dev">togo</a> auth family.</strong></p>
</div>

## Install

```bash
togo install togo-framework/auth-mfa
```

Adds the security layer Fort-grade auth needs, on top of the togo `auth` plugin:
**TOTP 2FA + recovery codes**, **email OTP**, **magic-link login**, **account lockout**, **password policy**, and an **MFA challenge state-machine** that gates a full session behind a second factor.

## The challenge flow

```
primary login ──► if mfa.Required(user): IssueChallenge() ──► challenge token (5 min, NOT a session)
                                                                    │
        client completes a factor (TOTP / recovery / OTP) ─────────┘
                                                                    ▼
                          on success: auth.IssueSession()  ──►  real session
```

Challenge tokens are HMAC-signed with `purpose=mfa` and are **rejected as sessions**.

## Endpoints (`/api/auth/mfa`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/totp/enroll` | generate a TOTP secret + `otpauth://` URI (QR) |
| POST | `/totp/verify` | verify a code (activates; pass `challenge` to complete login) |
| POST | `/totp/disable` | remove 2FA |
| POST | `/recovery/generate` | 8 single-use recovery codes (shown once) |
| POST | `/recovery/verify` | consume a recovery code |
| POST | `/otp/send` | email a 6-digit OTP (rate-limited 3/10min) |
| POST | `/otp/verify` | verify the OTP |
| POST | `/magic-link/send` | email a signed login link |
| GET | `/magic-link/verify?token=` | log in via the link |
| GET | `/challenge/status?challenge=` | inspect a pending challenge |

## Go API

```go
m, _ := mfa.FromKernel(k)

if m.Required(userID) {
    tok, _ := m.IssueChallenge(userID)   // hand the client a challenge token instead of a session
}

secret, uri, _ := m.EnrollTOTP(userID, "MyApp")   // show the QR
m.VerifyTOTP(userID, "123456")                    // activates on first success
codes := m.GenerateRecoveryCodes(userID, 8)

m.RecordFailure(userID); locked, until := m.IsLocked(userID)   // lockout
m.ValidatePassword(pw)                                          // policy
```

## Configuration

| Env | Default | |
|---|---|---|
| `MFA_CHALLENGE_SECRET` | dev secret | HMAC key for challenge / magic-link tokens — **set in prod** |
| `MFA_OTP_TTL` | `5m` | email-OTP lifetime |
| `MFA_LOCKOUT_THRESHOLD` | `5` | failures before lock |
| `MFA_LOCKOUT_MINUTES` | `15` | lock duration |
| `MFA_PW_MIN_LEN` | `12` | password minimum length |

OTP/magic-link delivery: wire the togo `mail`/`notifications` plugin (the code is logged in dev). State is in a bounded in-memory store with a pluggable `Store` (`WithStore`) for DB persistence.

---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
