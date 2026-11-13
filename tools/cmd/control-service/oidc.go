package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// oidcClient signs users in with the authorization-code flow and PKCE (S256) against an OpenID provider (FAF's is
// Hydra), and checks its tokens: RS256 signatures against the provider's JWKS, issuer, audience, expiry, nonce.
type oidcClient struct {
	issuer   string // as configured, without a trailing slash
	clientID string
	secret   string // "" for a public client
	redirect string
	scopes   []string
	http     *http.Client

	mu        sync.Mutex
	discovery *discoveryDoc
	keys      map[string]*rsa.PublicKey
	keysAt    time.Time
	lastFetch time.Time
}

type discoveryDoc struct {
	Issuer   string `json:"issuer"`
	Auth     string `json:"authorization_endpoint"`
	Token    string `json:"token_endpoint"`
	UserInfo string `json:"userinfo_endpoint"`
	JWKS     string `json:"jwks_uri"`
}

const clockSkew = 60 * time.Second

func sameIssuer(a, b string) bool { return strings.TrimRight(a, "/") == strings.TrimRight(b, "/") }

func (o *oidcClient) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// discover reads the provider's /.well-known/openid-configuration once (again after a failure).
func (o *oidcClient) discover(ctx context.Context) (*discoveryDoc, error) {
	o.mu.Lock()
	d := o.discovery
	o.mu.Unlock()
	if d != nil {
		return d, nil
	}
	var doc discoveryDoc
	if err := o.getJSON(ctx, o.issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("OpenID discovery: %w", err)
	}
	if !sameIssuer(doc.Issuer, o.issuer) || doc.Auth == "" || doc.Token == "" || doc.JWKS == "" {
		return nil, fmt.Errorf("OpenID discovery: issuer %q or endpoints don't fit %q", doc.Issuer, o.issuer)
	}
	o.mu.Lock()
	o.discovery = &doc
	o.mu.Unlock()
	return &doc, nil
}

// key finds the signing key by kid; an unknown kid fetches the JWKS again (keys rotate), at most every 10 s.
func (o *oidcClient) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	o.mu.Lock()
	k, ok := o.keys[kid]
	stale := time.Since(o.keysAt) > 10*time.Minute
	recent := time.Since(o.lastFetch) < 10*time.Second
	o.mu.Unlock()
	if ok && !stale {
		return k, nil
	}
	if recent && !ok {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	d, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.lastFetch = time.Now()
	o.mu.Unlock()
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, Use, Alg string
		} `json:"keys"`
	}
	if err := o.getJSON(ctx, d.JWKS, &set); err != nil {
		if ok {
			return k, nil // keep using a known key while the provider is unreachable
		}
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(j.N)
		e, err2 := base64.RawURLEncoding.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pk.N.BitLen() < 2048 {
			continue
		}
		keys[j.Kid] = pk
	}
	o.mu.Lock()
	o.keys, o.keysAt = keys, time.Now()
	o.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

// tokenClaims are the claims the service reads.
type tokenClaims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"` // a string or a list
	Exp               float64         `json:"exp"`
	Nbf               float64         `json:"nbf"`
	Iat               float64         `json:"iat"`
	Nonce             string          `json:"nonce"`
	Scp               []string        `json:"scp"`
	PreferredUsername string          `json:"preferred_username"`
	Name              string          `json:"name"`
	Nickname          string          `json:"nickname"`
}

func (c tokenClaims) audience() []string {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(c.Aud, &many)
	return many
}

func (c tokenClaims) displayName() string {
	for _, n := range []string{c.PreferredUsername, c.Nickname, c.Name} {
		if strings.TrimSpace(n) != "" {
			return strings.TrimSpace(n)
		}
	}
	return ""
}

// verify checks a JWT's signature (RS256 only), issuer and times, and returns its claims; the caller checks audience,
// nonce and scopes.
func (o *oidcClient) verify(ctx context.Context, token string) (tokenClaims, error) {
	var c tokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("not a JWT")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, errors.New("JWT header isn't base64url")
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil {
		return c, errors.New("JWT header isn't JSON")
	}
	if h.Alg != "RS256" {
		return c, fmt.Errorf("JWT algorithm %q (only RS256 is accepted)", h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, errors.New("JWT signature isn't base64url")
	}
	key, err := o.key(ctx, h.Kid)
	if err != nil {
		return c, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return c, errors.New("JWT signature is wrong")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &c) != nil {
		return c, errors.New("JWT claims aren't JSON")
	}
	if !sameIssuer(c.Iss, o.issuer) {
		return c, fmt.Errorf("JWT issuer %q isn't %q", c.Iss, o.issuer)
	}
	now := time.Now()
	if c.Exp == 0 || now.After(time.Unix(int64(c.Exp), 0).Add(clockSkew)) {
		return c, errors.New("JWT has expired")
	}
	if c.Nbf != 0 && now.Add(clockSkew).Before(time.Unix(int64(c.Nbf), 0)) {
		return c, errors.New("JWT isn't valid yet")
	}
	if _, err := strconv.Atoi(c.Sub); err != nil {
		return c, fmt.Errorf("JWT subject %q isn't a FAF user id", c.Sub)
	}
	return c, nil
}

// verifyAccessToken checks a FAF access token sent as a bearer token, as FAF's lobby server does (signature, issuer,
// expiry; no audience), plus a required scope when one is configured.
func (o *oidcClient) verifyAccessToken(ctx context.Context, token, scope string) (int, error) {
	c, err := o.verify(ctx, token)
	if err != nil {
		return 0, err
	}
	if scope != "" && !slices.Contains(c.Scp, scope) {
		return 0, fmt.Errorf("token lacks the %q scope", scope)
	}
	uid, _ := strconv.Atoi(c.Sub)
	return uid, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// loginState is kept in the store between /auth/login and /auth/callback (10 minutes, used once).
type loginState struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Return   string `json:"return"`
}

// authURL starts a sign-in: a state, a nonce and a PKCE verifier, and the provider's URL to send the browser to.
func (o *oidcClient) authURL(ctx context.Context) (url string, state string, ls loginState, err error) {
	d, err := o.discover(ctx)
	if err != nil {
		return "", "", ls, err
	}
	state = randomToken(24)
	ls = loginState{Verifier: randomToken(48), Nonce: randomToken(24)}
	sum := sha256.Sum256([]byte(ls.Verifier))
	q := neturlValues(map[string]string{
		"response_type": "code", "client_id": o.clientID, "redirect_uri": o.redirect, "scope": strings.Join(o.scopes, " "),
		"state": state, "nonce": ls.Nonce, "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]),
		"code_challenge_method": "S256",
	})
	sep := "?"
	if strings.Contains(d.Auth, "?") {
		sep = "&"
	}
	return d.Auth + sep + q, state, ls, nil
}

func neturlValues(m map[string]string) string {
	v := url.Values{}
	for k, x := range m {
		v.Set(k, x)
	}
	return v.Encode()
}

// exchange trades the code for tokens, checks the ID token and returns the FAF user id and name.
func (o *oidcClient) exchange(ctx context.Context, code string, ls loginState) (int, string, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return 0, "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {o.redirect},
		"code_verifier": {ls.Verifier}}
	if o.secret == "" {
		form.Set("client_id", o.clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if o.secret != "" {
		req.SetBasicAuth(url.QueryEscape(o.clientID), url.QueryEscape(o.secret))
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return 0, "", fmt.Errorf("token endpoint answered %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK || tr.IDToken == "" {
		return 0, "", fmt.Errorf("token endpoint: %s %s %s", resp.Status, tr.Error, tr.Description)
	}
	c, err := o.verify(ctx, tr.IDToken)
	if err != nil {
		return 0, "", fmt.Errorf("ID token: %w", err)
	}
	if !slices.Contains(c.audience(), o.clientID) {
		return 0, "", errors.New("ID token isn't for this client")
	}
	if c.Nonce != ls.Nonce {
		return 0, "", errors.New("ID token's nonce doesn't match the sign-in's")
	}
	uid, _ := strconv.Atoi(c.Sub)
	name := c.displayName()
	if name == "" && d.UserInfo != "" && tr.AccessToken != "" {
		name = o.userInfoName(ctx, d.UserInfo, tr.AccessToken)
	}
	if name == "" {
		name = "FAF user " + c.Sub
	}
	return uid, name, nil
}

// userInfoName asks the provider's userinfo endpoint for the user's name ("" when it has none).
func (o *oidcClient) userInfoName(ctx context.Context, endpoint, access string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := o.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var c tokenClaims
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&c) != nil {
		return ""
	}
	return c.displayName()
}

// session is a signed-in browser, kept in the store under the hash of its cookie.
type session struct {
	UID     int    `json:"uid"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

const sessionCookie = "faf_control_session"

func sessionKey(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return "session:" + hex.EncodeToString(sum[:])
}
