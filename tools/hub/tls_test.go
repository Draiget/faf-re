package hub

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tlsHub(t *testing.T, secret string, h http.Handler) *httptest.Server {
	t.Helper()
	cfg, err := ServerTLS(secret)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestDerivedTLSAcceptsOnlyTheSecretsKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hub/info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"publicHost":"hub.test"}`)
	})
	srv := tlsHub(t, "right secret", mux)
	ctx := context.Background()

	info, err := NewClient(srv.URL, "right secret").Info(ctx)
	if err != nil || info.PublicHost != "hub.test" {
		t.Fatalf("same secret: info %+v, err %v", info, err)
	}
	if _, err = NewClient(srv.URL, "wrong secret").Info(ctx); err == nil ||
		!strings.Contains(err.Error(), "neither derived from the shared secret nor trusted") {
		t.Fatalf("other secret must be refused, got %v", err)
	}
}

func TestGatewayRelaysOnlyTheIcebreakerAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /session/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"jwt":"`+r.Header.Get("Authorization")+`"}`)
	})
	mux.HandleFunc("GET /session/game/7/events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond) // the first event must arrive before the stream ends
		_, _ = io.WriteString(w, "data: second\n\n")
	})
	mux.HandleFunc("GET /hub/info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "control route")
	})
	srv := tlsHub(t, "s", mux)
	c := NewClient(srv.URL, "s")
	defer c.Close()
	root, err := c.Gateway()
	if err != nil || !strings.HasPrefix(root, "http://127.0.0.1:") {
		t.Fatalf("gateway %q, err %v", root, err)
	}

	req, _ := http.NewRequest(http.MethodPost, root+"/session/token", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"jwt":"Bearer tok"}` {
		t.Fatalf("token through gateway: %s", body)
	}

	resp, err = http.Get(root + "/session/game/7/events")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	resp.Body.Close()
	if line != "data: first\n" || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("event stream buffered: %q after %s", line, time.Since(start))
	}

	resp, err = http.Get(root + "/hub/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("control route exposed through the gateway: %s", resp.Status)
	}
}
