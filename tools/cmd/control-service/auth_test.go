package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"faf-main/tools/oidcmock"
)

func TestSignInPublicClientNameFromUserinfo(t *testing.T) {
	e := newEnv(t, nil, envOpts{store: testStore(t)})
	c := e.browser(uidPlayerA)
	code, me := e.do(c, http.MethodGet, "/api/v1/me", nil, nil)
	user := me["user"].(map[string]any)
	if code != 200 || user["name"] != "PlayerA" || user["via"] != "session" {
		t.Fatalf("me: %d %v", code, me)
	}
	if roles := me["roles"].([]any); len(roles) != 1 || roles[0] != "player" {
		t.Fatalf("a listed player's roles: %v", roles)
	}
	if ts := me["tournaments"].([]any); len(ts) != 1 || ts[0].(map[string]any)["players"] != nil {
		t.Fatalf("a player sees the cup without its lists: %v", ts)
	}
}

func TestSignInConfidentialClientNameInIDToken(t *testing.T) {
	e := newEnv(t, nil, envOpts{store: testStore(t), secret: "s3cret-of-the-client", nameInIDToken: true})
	c := e.browser(uidTO)
	_, me := e.do(c, http.MethodGet, "/api/v1/me", nil, nil)
	if me["user"].(map[string]any)["name"] != "CupTO" {
		t.Fatalf("me: %v", me)
	}
	roles := me["roles"].([]any)
	if len(roles) != 2 || roles[0] != "organiser" || roles[1] != "player" {
		t.Fatalf("a tournament organiser's roles: %v", roles)
	}
	_, me = e.do(e.browser(uidAdmin), http.MethodGet, "/api/v1/me", nil, nil)
	if r := me["roles"].([]any); len(r) != 3 || r[0] != "admin" {
		t.Fatalf("admin's roles: %v", r)
	}
}

// startLogin runs /auth/login and the provider's authorize step without following the last redirect, returning the
// callback URL the provider sends the browser to.
func startLogin(t *testing.T, e *env, uid int) *url.URL {
	t.Helper()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(e.ts.URL + "/auth/login")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %v %v", resp, err)
	}
	resp.Body.Close()
	auth, _ := url.Parse(resp.Header.Get("Location"))
	q := auth.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("client_id") != "faf-control" {
		t.Fatalf("authorize URL lacks PKCE, nonce or state: %s", auth)
	}
	q.Set("login_as", strconv.Itoa(uid))
	auth.RawQuery = q.Encode()
	resp, err = noFollow.Get(auth.String())
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %v %v", resp, err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	return cb
}

func TestSignInStateIsUsedOnce(t *testing.T) {
	e := newEnv(t, nil, envOpts{store: testStore(t)})
	cb := startLogin(t, e, uidPlayerA)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(cb.String())
	if err != nil || resp.StatusCode != http.StatusFound || len(resp.Cookies()) != 1 {
		t.Fatalf("first callback: %v %v", resp, err)
	}
	ck := resp.Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Name != sessionCookie {
		t.Fatalf("session cookie: %+v", ck)
	}
	resp, _ = noFollow.Get(cb.String())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second use of the state: %d", resp.StatusCode)
	}
}

func TestSignInRefusesWrongVerifierAndNonce(t *testing.T) {
	for _, field := range []string{"verifier", "nonce"} {
		t.Run(field, func(t *testing.T) {
			e := newEnv(t, nil, envOpts{store: testStore(t)})
			cb := startLogin(t, e, uidPlayerA)
			key := "login:" + cb.Query().Get("state")
			v, ok, _ := e.store.Get(t.Context(), key)
			if !ok {
				t.Fatal("no login state stored")
			}
			var ls loginState
			_ = json.Unmarshal([]byte(v), &ls)
			if field == "verifier" {
				ls.Verifier = randomToken(48) // the provider's PKCE check must refuse it
			} else {
				ls.Nonce = "another" // the ID token's nonce won't match
			}
			b, _ := json.Marshal(ls)
			_ = e.store.Set(t.Context(), key, string(b), time.Minute)
			resp, err := http.Get(cb.String())
			if err != nil || resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("callback with a wrong %s: %v %v", field, resp, err)
			}
		})
	}
}

func TestSafeReturn(t *testing.T) {
	cfg := &Config{PublicURL: "https://control.example.org", CORSOrigin: "http://localhost:5173"}
	for ret, want := range map[string]bool{"/lobbies": true, "//evil.example/": false, `/\evil.example`: false,
		"https://evil.example/": false, "http://localhost:5173/lobby/1": true, "https://control.example.org/x": true,
		"https://user@control.example.org/": false, "": false} {
		if got := safeReturn(cfg, ret); got != want {
			t.Errorf("safeReturn(%q) = %v", ret, got)
		}
	}
}

func TestAccessTokens(t *testing.T) {
	e := newEnv(t, nil, envOpts{store: testStore(t)})
	user := oidcmock.User{ID: uidOrganiser, Name: "Org"}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	iss := e.idp.Issuer + "/"
	cases := map[string]struct {
		token string
		want  int
	}{
		"good":          {e.idp.AccessToken(user, []string{"openid", "lobby"}, time.Hour), 200},
		"no scope":      {e.idp.AccessToken(user, []string{"openid"}, time.Hour), 401},
		"expired":       {e.idp.AccessToken(user, []string{"lobby"}, -time.Hour), 401},
		"other key":     {oidcmock.SignWith(other, e.idp.KID, map[string]any{"iss": iss, "sub": "2", "exp": now.Add(time.Hour).Unix(), "scp": []string{"lobby"}}), 401},
		"other issuer":  {e.idp.Sign(map[string]any{"iss": "https://evil.example/", "sub": "2", "exp": now.Add(time.Hour).Unix(), "scp": []string{"lobby"}}), 401},
		"sub not an id": {e.idp.Sign(map[string]any{"iss": iss, "sub": "abc", "exp": now.Add(time.Hour).Unix(), "scp": []string{"lobby"}}), 401},
		"alg none":      {"eyJhbGciOiJub25lIn0.eyJzdWIiOiIyIn0.", 401},
		"garbage":       {"x", 401},
	}
	for name, c := range cases {
		code, out := e.do(nil, http.MethodGet, "/api/v1/me", nil, map[string]string{"Authorization": "Bearer " + c.token})
		if code != c.want {
			t.Errorf("%s: %d %v", name, code, out)
		}
		if code == 200 {
			if u := out["user"].(map[string]any); u["uid"] != float64(uidOrganiser) || u["via"] != "access_token" {
				t.Errorf("%s: %v", name, out)
			}
		}
	}
	code, out := e.do(nil, http.MethodGet, "/api/v1/me", nil, e.adminHdr())
	if code != 200 || out["roles"].([]any)[0] != "admin" {
		t.Fatalf("admin token: %d %v", code, out)
	}
}

func TestSessionRules(t *testing.T) {
	e := newEnv(t, nil, envOpts{store: testStore(t)})
	if code, _ := e.do(nil, http.MethodGet, "/api/v1/lobbies", nil, nil); code != 401 {
		t.Fatalf("no credentials: %d", code)
	}
	c := e.browser(uidOrganiser)
	// A change from a page on another origin is refused even with the cookie.
	code, out := e.do(c, http.MethodPost, "/api/v1/lobbies", map[string]any{}, map[string]string{"Origin": "https://evil.example"})
	if code != http.StatusForbidden || !strings.Contains(out["error"].(string), "origin") {
		t.Fatalf("cross-origin change: %d %v", code, out)
	}
	if code, _ := e.do(c, http.MethodPost, "/auth/logout", nil, nil); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := e.do(c, http.MethodGet, "/api/v1/me", nil, nil); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
	// CORS for the web UI's origin, with credentials.
	req, _ := http.NewRequest(http.MethodOptions, e.ts.URL+"/api/v1/lobbies", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("preflight: %v %v", resp.Header, err)
	}
}
