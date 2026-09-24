package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/togo-framework/togo"
	_ "modernc.org/sqlite"

	authpkg "github.com/togo-framework/auth"
)

// These tests boot a real kernel with auth + auth-mfa and replay each attack
// that worked against v0.1.0, asserting it no longer does.

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	k   *togo.Kernel
}

func boot(t *testing.T, extra map[string]string) *testEnv {
	t.Helper()
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DATABASE_URL", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	t.Setenv("AUTH_SECRET", "a-sufficiently-long-test-secret-for-mfa-tests!!")
	t.Setenv("APP_ENV", "development")
	for k, v := range extra {
		t.Setenv(k, v)
	}
	k := togo.New()
	t.Cleanup(func() { k.Close() })
	srv := httptest.NewServer(k.Handler())
	t.Cleanup(srv.Close)
	return &testEnv{t: t, srv: srv, k: k}
}

type cl struct {
	e      *testEnv
	h      *http.Client
	csrf   string
	bearer string
}

func (e *testEnv) client() *cl {
	jar, _ := cookiejar.New(nil)
	c := &cl{e: e, h: &http.Client{Jar: jar}}
	var body map[string]string
	c.call(http.MethodGet, "/api/auth/csrf", nil, &body)
	c.csrf = body["csrf_token"]
	return c
}

func (c *cl) as(token string) *cl { return &cl{e: c.e, h: c.h, csrf: c.csrf, bearer: token} }

func (c *cl) call(method, path string, in, out any) int {
	c.e.t.Helper()
	var buf bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&buf).Encode(in)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	res, err := c.h.Do(req)
	if err != nil {
		c.e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

const password = "correct-horse-battery-staple"

// account registers a user and returns its id and a session token.
func (c *cl) account(email string) (id, token string) {
	c.e.t.Helper()
	if code := c.call(http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": password}, nil); code != http.StatusCreated {
		c.e.t.Fatalf("register %s: %d", email, code)
	}
	var login map[string]any
	c.call(http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": password}, &login)
	token, _ = login["token"].(string)
	user, _ := login["user"].(map[string]any)
	id, _ = user["id"].(string)
	return id, token
}

// enable turns TOTP on through the session routes and returns the secret.
func (c *cl) enable(token string) string {
	c.e.t.Helper()
	var enrol map[string]string
	if code := c.as(token).call(http.MethodPost, "/api/auth/mfa/totp/enroll", nil, &enrol); code != http.StatusOK {
		c.e.t.Fatalf("enroll: %d", code)
	}
	code, _ := totp.GenerateCode(enrol["secret"], time.Now())
	if st := c.as(token).call(http.MethodPost, "/api/auth/mfa/totp/activate", map[string]string{"code": code}, nil); st != http.StatusOK {
		c.e.t.Fatalf("activate: %d", st)
	}
	return enrol["secret"]
}

// Attack 1 (v0.1.0): enrol an attacker-controlled authenticator on the victim
// by passing their user_id, then sign in with it.
func TestAttackEnrollOnSomeoneElse(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	victim, _ := c.account("victim@example.com")
	attacker := e.client() // a separate browser: no victim session

	var out map[string]string
	code := attacker.call(http.MethodPost, "/api/auth/mfa/totp/enroll?user_id="+victim, map[string]string{"user_id": victim}, &out)
	if code != http.StatusUnauthorized || out["secret"] != "" {
		t.Fatalf("SECURITY: enrolment without a session must be refused, got %d %v", code, out)
	}
	// And a raw user_id is no longer a way to verify a factor.
	var sess map[string]any
	code = attacker.call(http.MethodPost, "/api/auth/mfa/totp/verify", map[string]string{"user_id": victim, "code": "123456"}, &sess)
	if code == http.StatusOK || sess["token"] != nil {
		t.Fatalf("SECURITY: factor verify without a challenge must fail, got %d %v", code, sess)
	}
}

// Attack 2 (v0.1.0): mint the victim's recovery codes and redeem one.
func TestAttackMintRecoveryCodes(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	victim, _ := c.account("victim2@example.com")
	attacker := e.client()

	var out map[string]any
	code := attacker.call(http.MethodPost, "/api/auth/mfa/recovery/generate", map[string]string{"user_id": victim}, &out)
	if code != http.StatusUnauthorized || out["codes"] != nil {
		t.Fatalf("SECURITY: recovery codes must not be minted without a session, got %d %v", code, out)
	}
}

// Attack 3 (v0.1.0): switch off someone's 2FA by user_id.
func TestAttackDisableSomeoneElses2FA(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	victim, token := c.account("victim3@example.com")
	c.enable(token)

	e.client().call(http.MethodPost, "/api/auth/mfa/totp/disable", map[string]string{"user_id": victim}, nil)
	svc, _ := FromKernel(e.k)
	if !svc.Required(victim) {
		t.Fatal("SECURITY: 2fa was disabled without a session")
	}
	// Even with the victim's session, disabling needs a valid code.
	if code := c.as(token).call(http.MethodPost, "/api/auth/mfa/totp/disable", map[string]string{"code": "000000"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong code should be 401, got %d", code)
	}
	if !svc.Required(victim) {
		t.Fatal("2fa must survive a wrong-code disable")
	}
}

// Attack 4 (v0.1.0): magic link returned a working sign-in link to anyone,
// for any address, and created the account.
func TestAttackMagicLinkTakeover(t *testing.T) {
	e := boot(t, map[string]string{"MFA_MAGIC_LINK": "true"})
	c := e.client()
	c.account("admin@example.com")

	var captured map[string]string
	e.k.Hooks.On(EventMagicLinkRequested, 50, func(_ context.Context, p any) error {
		captured = p.(map[string]string)
		return nil
	})

	var out map[string]string
	c.call(http.MethodPost, "/api/auth/mfa/magic-link/send", map[string]string{"email": "admin@example.com"}, &out)
	if out["link"] != "" || strings.Contains(out["status"], "token=") {
		t.Fatalf("SECURITY: the magic link must never be in the response: %v", out)
	}
	if captured == nil || captured["token"] == "" {
		t.Fatal("the link should be delivered through the event")
	}

	// Unknown address: same answer, no link, no account created.
	captured = nil
	var unknown map[string]string
	c.call(http.MethodPost, "/api/auth/mfa/magic-link/send", map[string]string{"email": "stranger@example.com"}, &unknown)
	if unknown["status"] != out["status"] || captured != nil {
		t.Fatalf("unknown email must be indistinguishable and get nothing: %v %v", unknown, captured)
	}
	a, _ := authpkg.FromKernel(e.k)
	if id, _ := a.FindByEmail(context.Background(), "stranger@example.com"); id != nil {
		t.Fatal("SECURITY: requesting a magic link must not create an account")
	}
}

func TestMagicLinkIsSingleUseAndRespects2FA(t *testing.T) {
	e := boot(t, map[string]string{"MFA_MAGIC_LINK": "true"})
	c := e.client()
	_, token := c.account("magic@example.com")

	var captured map[string]string
	e.k.Hooks.On(EventMagicLinkRequested, 50, func(_ context.Context, p any) error {
		captured = p.(map[string]string)
		return nil
	})
	c.call(http.MethodPost, "/api/auth/mfa/magic-link/send", map[string]string{"email": "magic@example.com"}, nil)
	link := "/api/auth/mfa/magic-link/verify?token=" + captured["token"]

	var first map[string]any
	if code := c.call(http.MethodGet, link, nil, &first); code != http.StatusOK || first["token"] == nil {
		t.Fatalf("first use should sign in: %d %v", code, first)
	}
	if code := c.call(http.MethodGet, link, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("a used magic link must not work again, got %d", code)
	}

	// With 2FA on, a magic link replaces the password, not the second factor.
	c.enable(token)
	c.call(http.MethodPost, "/api/auth/mfa/magic-link/send", map[string]string{"email": "magic@example.com"}, nil)
	var held map[string]any
	c.call(http.MethodGet, "/api/auth/mfa/magic-link/verify?token="+captured["token"], nil, &held)
	if held["token"] != nil || held["mfa_required"] != true {
		t.Fatalf("SECURITY: a magic link must not bypass 2fa: %v", held)
	}
}

func TestMagicLinkOffByDefault(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	if code := c.call(http.MethodPost, "/api/auth/mfa/magic-link/send", map[string]string{"email": "a@example.com"}, nil); code != http.StatusNotFound {
		t.Fatalf("magic links should be off unless MFA_MAGIC_LINK=true, got %d", code)
	}
}

// The legitimate path: password → challenge → TOTP → session with roles.
func TestTwoFactorLoginEndToEnd(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	_, token := c.account("real@example.com")
	secret := c.enable(token)

	var login map[string]any
	c.call(http.MethodPost, "/api/auth/login", map[string]string{"email": "real@example.com", "password": password}, &login)
	if login["token"] != nil || login["mfa_required"] != true {
		t.Fatalf("auth login must hold for auth-mfa's TOTP: %v", login)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	var done map[string]any
	if st := c.call(http.MethodPost, "/api/auth/mfa/totp/verify", map[string]string{"challenge": login["challenge"].(string), "code": code}, &done); st != http.StatusOK {
		t.Fatalf("verify with challenge: %d %v", st, done)
	}
	a, _ := authpkg.FromKernel(e.k)
	id, err := a.Verify(done["token"].(string))
	if err != nil || id.Email != "real@example.com" {
		t.Fatalf("session must carry the full identity: %v %+v", err, id)
	}
}

func TestLockoutAfterRepeatedWrongCodes(t *testing.T) {
	e := boot(t, map[string]string{"MFA_LOCKOUT_THRESHOLD": "3"})
	c := e.client()
	_, token := c.account("locked@example.com")
	secret := c.enable(token)

	var login map[string]any
	c.call(http.MethodPost, "/api/auth/login", map[string]string{"email": "locked@example.com", "password": password}, &login)
	ch := login["challenge"].(string)
	for i := 0; i < 3; i++ {
		c.call(http.MethodPost, "/api/auth/mfa/totp/verify", map[string]string{"challenge": ch, "code": "111111"}, nil)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if st := c.call(http.MethodPost, "/api/auth/mfa/totp/verify", map[string]string{"challenge": ch, "code": code}, nil); st != http.StatusTooManyRequests {
		t.Fatalf("after the threshold even a right code should be locked out, got %d", st)
	}
}

func TestFactorsSurviveRestart(t *testing.T) {
	e := boot(t, nil)
	c := e.client()
	uid, token := c.account("durable@example.com")
	c.enable(token)

	svc, _ := FromKernel(e.k)
	db, _ := e.k.SQL(context.Background())
	fresh, err := newSQLStore(context.Background(), db, e.k.Dialect().Placeholder)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := fresh.GetTOTP(uid); !ok || !got.Activated {
		t.Fatal("an activated TOTP must be persisted, not held in memory")
	}
	_ = svc
}
