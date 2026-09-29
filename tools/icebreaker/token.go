package icebreaker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Claims is the part of the FAF access token faf-icebreaker cares about.
type Claims struct {
	Sub string `json:"sub"`
	Ext struct {
		GameID uint64   `json:"gameId"`
		Roles  []string `json:"roles,omitempty"`
		HMAC   string   `json:"hmac,omitempty"`
	} `json:"ext"`
	Scp []string `json:"scp,omitempty"`
	Exp int64    `json:"exp,omitempty"`
}

var b64 = base64.RawURLEncoding

// MintAccessToken builds an unsigned access token for a local test user. The
// ICE adapter only decodes the payload (for the optional X-HMAC header), so on
// a loopback-only server "alg": "none" is enough.
func MintAccessToken(uid uint, gameID uint64) string {
	return MintSignedAccessToken(uid, gameID, "")
}

// MintSignedAccessToken builds an HS256 access token signed with secret (an
// unsigned one when secret is empty). A server started with the same secret
// accepts it; anything else is refused, which keeps a server reachable from
// the internet from being used by strangers.
func MintSignedAccessToken(uid uint, gameID uint64, secret string) string {
	alg := "none"
	if secret != "" {
		alg = "HS256"
	}
	header := b64.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
	var c Claims
	c.Sub = strconv.FormatUint(uint64(uid), 10)
	c.Ext.GameID = gameID
	c.Ext.Roles = []string{"USER"}
	c.Scp = []string{"lobby"}
	c.Exp = 4102444800 // 2100-01-01
	payload, _ := json.Marshal(c)
	signingInput := header + "." + b64.EncodeToString(payload)
	if secret == "" {
		return signingInput + ".mpemu"
	}
	return signingInput + "." + b64.EncodeToString(sign(signingInput, secret))
}

func sign(input, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

// VerifyAccessToken parses a token and, when secret is set, requires a valid
// HS256 signature made with it.
func VerifyAccessToken(token, secret string) (uint, Claims, error) {
	uid, claims, err := ParseAccessToken(token)
	if err != nil || secret == "" {
		return uid, claims, err
	}
	parts := strings.Split(token, ".")
	header, err := b64.DecodeString(parts[0])
	if err != nil || !strings.Contains(string(header), `"HS256"`) {
		return 0, claims, errors.New("access token must be HS256-signed")
	}
	got, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, sign(parts[0]+"."+parts[1], secret)) {
		return 0, claims, errors.New("access token signature does not match this server's secret")
	}
	return uid, claims, nil
}

// ParseAccessToken decodes a JWT payload without verifying it. Tokens from the
// real FAF test set (faf-pioneer/TEST_TOKEN.md) parse the same way.
func ParseAccessToken(token string) (uid uint, claims Claims, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, claims, errors.New("access token is not a JWT")
	}
	raw, err := b64.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return 0, claims, err
	}
	if err = json.Unmarshal(raw, &claims); err != nil {
		return 0, claims, err
	}
	id, err := strconv.ParseUint(claims.Sub, 10, 32)
	if err != nil || id == 0 {
		return 0, claims, errors.New("access token has no numeric sub claim")
	}
	return uint(id), claims, nil
}
