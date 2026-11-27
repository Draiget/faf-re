package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// apiBase is GitHub's API for this repository's releases; tests point it at a local server.
var apiBase = "https://api.github.com/repos/Draiget/scfa-re"

const sumsName = "SHA256SUMS.txt"

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type release struct {
	Tag    string  `json:"tag_name"`
	Assets []asset `json:"assets"`
}

// pkgSource is the package to install: a release asset to download, or a file already here.
type pkgSource struct {
	tag    string
	name   string // the package's file name, e.g. faf-engine-2026.11.015-x64.zip
	url    string // empty for a local file
	file   string // local file, for --package
	size   int64
	sha256 string // expected hex digest; empty when none could be had (local package without sums)
}

// httpClient has no overall timeout, as a download takes as long as it takes; small requests set
// their own deadline (getSmall).
var httpClient = &http.Client{}

func resolvePackage(s *system, o options) (*pkgSource, error) {
	if o.pkg != "" {
		return localPackage(s, o.pkg)
	}
	what := "latest release"
	endpoint := apiBase + "/releases/latest"
	if o.tag != "" {
		what = "release " + o.tag
		endpoint = apiBase + "/releases/tags/" + o.tag
	}
	fmt.Printf("\nLooking up the %s on GitHub...\n", what)
	var rel release
	if err := getJSON(endpoint, &rel); err != nil {
		return nil, fmt.Errorf("can't read the %s: %w", what, err)
	}
	name := "faf-engine-" + rel.Tag + s.assetSuffix
	pkg, sums := findAsset(rel.Assets, name), findAsset(rel.Assets, sumsName)
	if pkg == nil {
		return nil, fmt.Errorf("release %s has no %s", rel.Tag, name)
	}
	if sums == nil {
		return nil, fmt.Errorf("release %s has no %s to check the download against", rel.Tag, sumsName)
	}
	text, err := getText(sums.URL)
	if err != nil {
		return nil, fmt.Errorf("can't read %s: %w", sumsName, err)
	}
	digest, ok := parseSums(text)[name]
	if !ok {
		return nil, fmt.Errorf("%s of release %s doesn't list %s", sumsName, rel.Tag, name)
	}
	fmt.Printf("Found %s (%d MB).\n", rel.Tag, pkg.Size>>20)
	return &pkgSource{tag: rel.Tag, name: name, url: pkg.URL, size: pkg.Size, sha256: digest}, nil
}

// localPackage takes a package file given with --package, and the SHA256SUMS.txt next to it if any.
func localPackage(s *system, path string) (*pkgSource, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	tag, ok := tagFromName(name, s.assetSuffix)
	if !ok {
		return nil, fmt.Errorf("%s isn't a package for this system (expected faf-engine-<version>%s)", name, s.assetSuffix)
	}
	p := &pkgSource{tag: tag, name: name, file: path, size: st.Size()}
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(path), sumsName)); err == nil {
		digest, ok := parseSums(string(data))[name]
		if !ok {
			return nil, fmt.Errorf("%s next to the package doesn't list %s", sumsName, name)
		}
		p.sha256 = digest
	} else {
		fmt.Printf("\nNo %s next to %s: the package can't be checked against the release's checksums.\n", sumsName, name)
	}
	return p, nil
}

// tagFromName takes the release tag out of a package name: faf-engine-<tag><suffix>.
func tagFromName(name, suffix string) (string, bool) {
	if !strings.HasPrefix(name, "faf-engine-") || !strings.HasSuffix(name, suffix) {
		return "", false
	}
	tag := strings.TrimSuffix(strings.TrimPrefix(name, "faf-engine-"), suffix)
	return tag, tag != ""
}

func findAsset(assets []asset, name string) *asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

// parseSums reads sha256sum output: "<hex>  <name>" (or "<hex> *<name>") per line.
func parseSums(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || len(fields[0]) != 64 {
			continue
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			continue
		}
		out[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return out
}

// fetchPackage puts the package into a file in dir and checks its SHA-256. It returns the file and
// whether that file is a temporary download the caller removes.
func fetchPackage(p *pkgSource, dir string) (path string, temp bool, err error) {
	if p.url == "" {
		if p.sha256 != "" {
			got, err := fileSHA256(p.file)
			if err != nil {
				return "", false, err
			}
			if got != p.sha256 {
				return "", false, fmt.Errorf("%s doesn't match its checksum (got %s, expected %s)", p.name, got, p.sha256)
			}
			fmt.Println("Checksum matches.")
		}
		return p.file, false, nil
	}
	f, err := os.CreateTemp(dir, ".faf-re-setup-download-*")
	if err != nil {
		return "", false, err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	resp, err := get(p.url)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	fmt.Printf("Downloading %s\n", p.name)
	n, err := io.Copy(io.MultiWriter(f, h), &progressReader{r: resp.Body, total: p.size})
	fmt.Println()
	if err != nil {
		return "", false, fmt.Errorf("download failed: %w", err)
	}
	if p.size > 0 && n != p.size {
		return "", false, fmt.Errorf("download stopped at %d of %d bytes", n, p.size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.sha256 {
		return "", false, fmt.Errorf("the download doesn't match the release's checksum (got %s, expected %s)", got, p.sha256)
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}
	fmt.Println("Checksum matches.")
	return f.Name(), true, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func get(url string) (*http.Response, error) {
	return getContext(context.Background(), url)
}

func getContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "faf-re-setup/"+version)
	if strings.HasPrefix(url, apiBase) {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, errors.New("not found (404)")
		}
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	}
	return resp, nil
}

// getSmall fetches a small document (at most 4 MB) within 60 seconds.
func getSmall(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := getContext(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func getJSON(url string, v any) error {
	data, err := getSmall(url)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func getText(url string) (string, error) {
	data, err := getSmall(url)
	return string(data), err
}

// progressReader prints how much of a download has arrived, at most once per percent.
type progressReader struct {
	r     io.Reader
	total int64
	done  int64
	shown int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.total > 0 {
		if pct := p.done * 100 / p.total; pct != p.shown || err == io.EOF {
			p.shown = pct
			fmt.Printf("\r  %3d %%  %d of %d MB", pct, p.done>>20, p.total>>20)
		}
	}
	return n, err
}
