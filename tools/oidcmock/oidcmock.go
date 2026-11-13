// Package oidcmock is a small OpenID Connect provider for tests: discovery, a JWKS with one RSA key, an authorize
// endpoint that signs the configured user in at once, a token endpoint for the authorization-code grant with PKCE
// (S256) and a userinfo endpoint. Tokens are RS256 JWTs shaped like FAF's (Hydra's): `sub` is the FAF user id as a
// string, access tokens carry their scopes in `scp`.
//
// It is a stand-in for FAF's provider in tests of tools/cmd/control-service and is not a real identity provider: it
// asks for no password.
package oidcmock

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// User is a FAF account as the provider knows it.
type User struct {
	ID   int
	Name string
}

// Provider is the mock. Set Issuer to the URL it is served at (no trailing slash needed) before the first request.
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string   // "" for a public client (PKCE only)
	RedirectURIs []string // the redirect URIs the client registered
	Users        []User   // the first is signed in unless authorize gets ?login_as=<id>
	// NameInIDToken puts preferred_username into the ID token; without it the name is only in userinfo.
	NameInIDToken bool
	TokenTTL      time.Duration // default 1 hour

	Key *rsa.PrivateKey
	KID string

	mu    sync.Mutex
	codes map[string]grant
	// Counters for tests.
	Authorizations, TokenRequests int
}

type grant struct {
	user               User
	clientID, redirect string
	challenge, nonce   string
	scope              string
	expires            time.Time
	used               bool
}

// New makes a provider with a fresh 2048-bit key.
func New(issuer, clientID, clientSecret string, redirectURIs []string, users ...User) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Provider{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: redirectURIs,
		Users: users, Key: key, KID: "mock-" + randomHex(4)}, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *Provider) issuer() string { return strings.TrimRight(p.Issuer, "/") }

// Sign makes an RS256 JWT with the provider's key (exported so tests can make tokens directly, also bad ones).
func (p *Provider) Sign(claims map[string]any) string {
	return SignWith(p.Key, p.KID, claims)
}

// SignWith makes an RS256 JWT with any key.
func SignWith(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

// AccessToken makes an access token for a user as FAF's provider shapes them.
func (p *Provider) AccessToken(u User, scopes []string, ttl time.Duration) string {
	now := time.Now()
	return p.Sign(map[string]any{"iss": p.issuer() + "/", "sub": strconv.Itoa(u.ID), "aud": []string{p.ClientID},
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "scp": scopes, "client_id": p.ClientID,
		"jti": randomHex(8)})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code int, kind, text string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": text})
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		iss := p.issuer()
		writeJSON(w, http.StatusOK, map[string]any{
			// Hydra's issuer ends with a slash; the service must accept either spelling.
			"issuer": iss + "/", "authorization_endpoint": iss + "/oauth2/auth", "token_endpoint": iss + "/oauth2/token",
			"userinfo_endpoint": iss + "/userinfo", "jwks_uri": iss + "/.well-known/jwks.json",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		})
	case "/.well-known/jwks.json":
		pub := p.Key.PublicKey
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.KID,
			"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	case "/oauth2/auth":
		p.authorize(w, r)
	case "/oauth2/token":
		p.token(w, r)
	case "/userinfo":
		p.userinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != p.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_type code and the registered client_id")
		return
	}
	redirect := q.Get("redirect_uri")
	known := false
	for _, u := range p.RedirectURIs {
		known = known || u == redirect
	}
	if !known {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri isn't registered")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE with S256 is required")
		return
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "openid is required")
		return
	}
	if len(p.Users) == 0 {
		oauthError(w, http.StatusBadRequest, "access_denied", "no user")
		return
	}
	user := p.Users[0]
	if as := q.Get("login_as"); as != "" {
		found := false
		for _, u := range p.Users {
			if strconv.Itoa(u.ID) == as {
				user, found = u, true
			}
		}
		if !found {
			oauthError(w, http.StatusBadRequest, "access_denied", "no such user")
			return
		}
	}
	code := randomHex(16)
	p.mu.Lock()
	if p.codes == nil {
		p.codes = map[string]grant{}
	}
	p.codes[code] = grant{user: user, clientID: p.ClientID, redirect: redirect, challenge: q.Get("code_challenge"),
		nonce: q.Get("nonce"), scope: q.Get("scope"), expires: time.Now().Add(2 * time.Minute)}
	p.Authorizations++
	p.mu.Unlock()
	target, _ := url.Parse(redirect)
	v := target.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	target.RawQuery = v.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	p.mu.Lock()
	p.TokenRequests++
	p.mu.Unlock()
	// Client authentication: basic, or client_id (+ client_secret) in the form.
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || (p.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(p.ClientSecret)) != 1) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code only")
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, ok := p.codes[code]
	if ok {
		delete(p.codes, code) // one use
	}
	p.mu.Unlock()
	if !ok || time.Now().After(g.expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}
	if r.PostForm.Get("redirect_uri") != g.redirect {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri differs from the authorization request's")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64(sum[:]) != g.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier doesn't match the challenge")
		return
	}
	ttl := p.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	now := time.Now()
	idClaims := map[string]any{"iss": p.issuer() + "/", "sub": strconv.Itoa(g.user.ID), "aud": []string{p.ClientID},
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "auth_time": now.Unix(), "nonce": g.nonce, "jti": randomHex(8)}
	if p.NameInIDToken {
		idClaims["preferred_username"] = g.user.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": p.AccessToken(g.user, strings.Fields(g.scope), ttl), "token_type": "bearer",
		"expires_in": int(ttl.Seconds()), "scope": g.scope, "id_token": p.Sign(idClaims),
	})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
		return
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "not a JWT")
		return
	}
	sig, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err1 != nil || err2 != nil || rsa.VerifyPKCS1v15(&p.Key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "bad signature")
		return
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &c) != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "bad claims")
		return
	}
	for _, u := range p.Users {
		if strconv.Itoa(u.ID) == c.Sub {
			writeJSON(w, http.StatusOK, map[string]any{"sub": c.Sub, "preferred_username": u.Name})
			return
		}
	}
	oauthError(w, http.StatusUnauthorized, "invalid_token", errors.New("unknown user").Error())
}
