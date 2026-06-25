---
name: auth-mfa
description: Add multi-factor auth to a togo app with the auth-mfa plugin — TOTP 2FA, recovery codes, email OTP, magic-link, account lockout, and password policy, gated behind an MFA challenge flow.
---

# togo auth-mfa

Use this skill to add MFA + account protection to a togo app (on top of the `auth` plugin).

## Gate login behind a factor
```go
m, _ := mfa.FromKernel(k)
if m.Required(userID) {            // user has TOTP enrolled
    tok, _ := m.IssueChallenge(userID)   // return a challenge token, NOT a session
}
```
The client completes a factor (TOTP / recovery / OTP), then the plugin issues the real session via `auth.IssueSession`.

## Endpoints
`/api/auth/mfa/totp/{enroll,verify,disable}`, `/recovery/{generate,verify}`, `/otp/{send,verify}`, `/magic-link/{send,verify}`, `/challenge/status`.

## Notes
- Set `MFA_CHALLENGE_SECRET` in production (HMAC key for challenge + magic-link tokens).
- Wire `mail`/`notifications` to deliver OTP codes + magic links (logged in dev).
- Enforce `ValidatePassword` on signup/reset; call `RecordFailure`/`IsLocked` around login to lock out brute force.
- Swap the in-memory store for a DB-backed `Store` (`WithStore`) in production.
