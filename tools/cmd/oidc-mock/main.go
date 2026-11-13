// Command oidc-mock serves tools/oidcmock's mock OpenID provider, for trying tools/cmd/control-service's sign-in
// without FAF's provider. It signs the first --user in at once (another with ?login_as=<id> on the authorize URL);
// it asks for no password, so never expose it.
//
//	oidc-mock --listen 127.0.0.1:27199 --client-id faf-control --redirect http://127.0.0.1:27190/auth/callback \
//	  --user 1001:Ann --user 1002:Bo
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"faf-main/tools/oidcmock"
)

type users []oidcmock.User

func (u *users) String() string { return fmt.Sprint(*u) }
func (u *users) Set(v string) error {
	id, name, ok := strings.Cut(v, ":")
	n, err := strconv.Atoi(id)
	if !ok || err != nil || n < 1 || name == "" {
		return errors.New("--user takes <FAF id>:<name>")
	}
	*u = append(*u, oidcmock.User{ID: n, Name: name})
	return nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:27199", "address to serve on")
	issuer := flag.String("issuer", "", "the issuer URL (default http://<listen>)")
	clientID := flag.String("client-id", "faf-control", "the client id the service uses")
	secretFile := flag.String("client-secret-file", "", "file with the client secret (default: a public client)")
	var redirects []string
	flag.Func("redirect", "a registered redirect URI (repeat for several)", func(v string) error {
		redirects = append(redirects, v)
		return nil
	})
	var us users
	flag.Var(&us, "user", "<FAF id>:<name> (repeat; the first signs in by default)")
	nameInID := flag.Bool("name-in-id-token", false, "put preferred_username into the ID token (else only userinfo has it)")
	flag.Parse()
	if len(redirects) == 0 || len(us) == 0 {
		fmt.Fprintln(os.Stderr, "oidc-mock needs at least one --redirect and one --user")
		os.Exit(2)
	}
	secret := ""
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			log.Fatal(err)
		}
		secret = strings.TrimSpace(string(b))
	}
	if *issuer == "" {
		*issuer = "http://" + *listen
	}
	p, err := oidcmock.New(*issuer, *clientID, secret, redirects, us...)
	if err != nil {
		log.Fatal(err)
	}
	p.NameInIDToken = *nameInID
	log.Printf("oidc-mock: issuer %s, client %s, users %v", *issuer, *clientID, us)
	srv := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
