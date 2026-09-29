package icebreaker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"faf-main/tools/journal"
)

func sessionToken(t *testing.T, base string, uid uint) string {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/session/token", strings.NewReader(`{"gameId":100}`))
	req.Header.Set("Authorization", "Bearer "+MintAccessToken(uid, 100))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("token: %s", resp.Status)
	}
	var out struct{ Jwt string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Jwt
}

// sse opens an event stream and returns its data lines.
func sse(t *testing.T, ctx context.Context, base, token string) <-chan map[string]any {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/session/game/100/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan map[string]any, 16)
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(line[6:]), &ev) == nil {
				out <- ev
			}
		}
	}()
	return out
}

func next(t *testing.T, ch <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	return nil
}

func TestSignallingFlow(t *testing.T) {
	j, _ := journal.New("", nil)
	srv := New(Options{}, j)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t1 := sessionToken(t, ts.URL, 1)
	t2 := sessionToken(t, ts.URL, 2)

	// Session info in the shape faf-pioneer's SessionGameResponse expects.
	req, _ := http.NewRequest("GET", ts.URL+"/session/game/100", nil)
	req.Header.Set("Authorization", "Bearer "+t1)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sess struct {
		ID         string
		ForceRelay bool
		Servers    []any
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess.ID != "100" || sess.Servers == nil {
		t.Fatalf("session %+v", sess)
	}

	s1 := sse(t, ctx, ts.URL, t1)
	time.Sleep(50 * time.Millisecond)
	s2 := sse(t, ctx, ts.URL, t2)

	// 2 subscribing tells 1 it is there.
	if ev := next(t, s1); ev["eventType"] != "connected" || ev["senderId"] != float64(2) {
		t.Fatalf("user 1 got %v", ev)
	}
	// 1 subscribed first, before 2 had a stream; its "connected" was queued.
	if ev := next(t, s2); ev["eventType"] != "connected" || ev["senderId"] != float64(1) {
		t.Fatalf("user 2 got %v", ev)
	}

	// Targeted candidates; a forged senderId is rewritten to the session user.
	body := `{"eventType":"candidates","gameId":100,"senderId":9,"recipientId":2,"session":{"type":"offer","sdp":"x"},"candidates":[{"typ":"host"}]}`
	req, _ = http.NewRequest("POST", ts.URL+"/session/game/100/events", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+t1)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("post event: %v %v", err, resp)
	}
	resp.Body.Close()
	ev := next(t, s2)
	if ev["eventType"] != "candidates" || ev["senderId"] != float64(1) {
		t.Fatalf("user 2 got %v", ev)
	}
	if ev["session"].(map[string]any)["sdp"] != "x" {
		t.Fatalf("payload not forwarded intact: %v", ev)
	}

	// Wrong game id in the path is refused.
	req, _ = http.NewRequest("GET", ts.URL+"/session/game/101", nil)
	req.Header.Set("Authorization", "Bearer "+t1)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-game access: %s", resp.Status)
	}
	resp.Body.Close()
}

func TestSignedTokens(t *testing.T) {
	tok := MintSignedAccessToken(3, 100, "s3cret")
	if uid, _, err := VerifyAccessToken(tok, "s3cret"); err != nil || uid != 3 {
		t.Fatalf("valid token refused: uid=%d err=%v", uid, err)
	}
	if _, _, err := VerifyAccessToken(tok, "other"); err == nil {
		t.Fatal("token signed with another secret accepted")
	}
	if _, _, err := VerifyAccessToken(MintAccessToken(3, 100), "s3cret"); err == nil {
		t.Fatal("unsigned token accepted by a server with a secret")
	}
	if uid, _, err := VerifyAccessToken(MintAccessToken(3, 100), ""); err != nil || uid != 3 {
		t.Fatalf("loopback server refused an unsigned token: %v", err)
	}
}

func TestParseRealTestToken(t *testing.T) {
	// faf-pioneer/TEST_TOKEN.md user 2 (RS256, signature not checked here).
	tok := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyIiwiZXh0Ijp7InJvbGVzIjpbIlVTRVIiXSwiZ2FtZUlkIjoxMDB9LCJzY3AiOlsibG9iYnkiXSwiaXNzIjoiaHR0cHM6Ly9pY2UuZmFmb3JldmVyLmNvbSIsImF1ZCI6Imh0dHBzOi8vaWNlLmZhZm9yZXZlci5jb20iLCJleHAiOjIwMDAwMDAwMDAsImlhdCI6MTc0MTAwMDAwMCwianRpIjoiZmNkOTkwZjYtNWU3Mi00MjA4LTg1MzktNmQ1NDU3NDkyOTY4In0.sig"
	uid, claims, err := ParseAccessToken(tok)
	if err != nil || uid != 2 || claims.Ext.GameID != 100 {
		t.Fatalf("uid=%d claims=%+v err=%v", uid, claims, err)
	}
}
