package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestName  = "faf-re-setup.json"
	stageName     = ".faf-re-setup-new"
	backupName    = ".faf-re-setup-old"
	originalsName = ".faf-re-setup-originals"
)

// manifest records what setup installed, so a later run can update or remove exactly that.
type manifest struct {
	Version   string    `json:"version"`
	Installed time.Time `json:"installed"`
	Files     []string  `json:"files"` // relative to the install folder, with forward slashes
	// Originals are files that were in the folder before setup first wrote over them (a hand install,
	// or FAF's bin for --x86). They are kept in originalsName and put back by --uninstall.
	Originals []string `json:"originals,omitempty"`
	Shortcuts []string `json:"shortcuts,omitempty"`
}

func readManifest(dir string) (*manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestName, err)
	}
	return &m, nil
}

func writeManifest(dir string, m *manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestName), append(data, '\n'), 0o644)
}

func install(s *system, o options, p *pkgSource) error {
	if err := os.MkdirAll(s.installDir, 0o755); err != nil {
		return err
	}
	file, temp, err := fetchPackage(p, s.installDir)
	if err != nil {
		return err
	}
	if temp {
		defer os.Remove(file)
	}

	stage := filepath.Join(s.installDir, stageName)
	backup := filepath.Join(s.installDir, backupName)
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	defer os.RemoveAll(backup)

	fmt.Println("Unpacking...")
	var files []string
	if strings.HasSuffix(p.name, ".zip") {
		files, err = extractZip(file, stage)
	} else {
		files, err = extractTarGz(file, stage)
	}
	if err != nil {
		return fmt.Errorf("can't unpack %s: %w", p.name, err)
	}
	if !contains(files, s.exeName) {
		return fmt.Errorf("%s has no %s", p.name, s.exeName)
	}

	// The game could have been started since the checks ran.
	if running, _ := engineRunning(filepath.Join(s.installDir, s.exeName)); running {
		return errors.New("the engine is running; close the game and run setup again")
	}
	old, _ := readManifest(s.installDir)
	if old == nil {
		old = &manifest{}
	}
	replaced, err := swapIn(s.installDir, stage, backup, files)
	if err != nil {
		return err
	}

	m := &manifest{Version: p.tag, Installed: time.Now().UTC().Truncate(time.Second), Files: files,
		Originals: old.Originals, Shortcuts: old.Shortcuts}
	// A replaced file setup didn't put there is someone else's: keep it for --uninstall.
	originals := filepath.Join(s.installDir, originalsName)
	for _, rel := range replaced {
		if contains(old.Files, rel) || contains(m.Originals, rel) {
			continue
		}
		dst := filepath.Join(originals, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err == nil && os.Rename(filepath.Join(backup, filepath.FromSlash(rel)), dst) == nil {
			m.Originals = append(m.Originals, rel)
		}
	}
	sort.Strings(m.Originals)
	// Files an earlier install put here that this package no longer has.
	for _, f := range old.Files {
		if !contains(files, f) {
			os.Remove(filepath.Join(s.installDir, filepath.FromSlash(f)))
		}
	}
	removeEmptyDirs(s.installDir, old.Files)
	if !o.noShortcut {
		links, err := createShortcuts(s)
		if err != nil {
			fmt.Printf("  The shortcut could not be made: %v\n", err)
		} else {
			m.Shortcuts = links
			for _, l := range links {
				fmt.Printf("  Shortcut: %s\n", l)
			}
		}
	}
	if err := writeManifest(s.installDir, m); err != nil {
		return err
	}
	fmt.Printf("\n%s is installed in %s.\n", p.tag, s.installDir)
	afterInstall(s)
	return nil
}

// swapIn moves every staged file into dir. A file it replaces goes to backup first; if any move
// fails, the files moved so far are taken out again and the replaced ones put back. It returns the
// files that replaced one already there.
func swapIn(dir, stage, backup string, files []string) ([]string, error) {
	type moved struct {
		dst      string
		replaced bool
		saved    string
	}
	var done []moved
	undo := func() {
		for i := len(done) - 1; i >= 0; i-- {
			os.Remove(done[i].dst)
			if done[i].replaced {
				os.Rename(done[i].saved, done[i].dst)
			}
		}
	}
	var replaced []string
	for _, rel := range files {
		native := filepath.FromSlash(rel)
		src, dst := filepath.Join(stage, native), filepath.Join(dir, native)
		mv := moved{dst: dst}
		if _, err := os.Lstat(dst); err == nil {
			mv.saved = filepath.Join(backup, native)
			if err := os.MkdirAll(filepath.Dir(mv.saved), 0o755); err != nil {
				undo()
				return nil, err
			}
			if err := os.Rename(dst, mv.saved); err != nil {
				undo()
				return nil, fmt.Errorf("can't replace %s: %w", dst, err)
			}
			mv.replaced = true
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			if mv.replaced {
				os.Rename(mv.saved, dst)
			}
			undo()
			return nil, err
		}
		if err := os.Rename(src, dst); err != nil {
			if mv.replaced {
				os.Rename(mv.saved, dst)
			}
			undo()
			return nil, fmt.Errorf("can't put %s in place: %w", dst, err)
		}
		done = append(done, mv)
		if mv.replaced {
			replaced = append(replaced, rel)
		}
	}
	return replaced, nil
}

// cleanEntry turns an archive entry name into a safe relative path with forward slashes, or ""
// for the archive's root. Names that would leave the folder are refused.
func cleanEntry(name string) (string, error) {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || (len(n) >= 2 && n[1] == ':') {
		return "", fmt.Errorf("entry %q has an absolute path", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("entry %q leaves the folder", name)
		}
	}
	n = path.Clean(n)
	if n == "." {
		return "", nil
	}
	return n, nil
}

func extractZip(file, dest string) ([]string, error) {
	r, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var files []string
	for _, f := range r.File {
		rel, err := cleanEntry(f.Name)
		if err != nil {
			return nil, err
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if strings.HasSuffix(f.Name, "/") || f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("entry %q is a link", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		err = writeFile(target, rc, 0o644)
		rc.Close()
		if err != nil {
			return nil, err
		}
		files = append(files, rel)
	}
	sort.Strings(files)
	return files, nil
}

func extractTarGz(file, dest string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var files []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rel, err := cleanEntry(h.Name)
		if err != nil {
			return nil, err
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := writeFile(target, tr, mode); err != nil {
				return nil, err
			}
			files = append(files, rel)
		default:
			return nil, fmt.Errorf("entry %q is not a file or folder", h.Name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func writeFile(target string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(target, mode) // the umask may have taken bits off
}

func uninstall(s *system, o options) error {
	m, err := readManifest(s.installDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("setup has installed nothing in %s (no %s there)", s.installDir, manifestName)
		}
		return err
	}
	if running, _ := engineRunning(filepath.Join(s.installDir, s.exeName)); running {
		return errors.New("the engine is running; close the game first")
	}
	if !o.yes && !ask(fmt.Sprintf("Remove %s (%d files) from %s, and its shortcuts?", m.Version, len(m.Files), s.installDir), false) {
		return nil
	}
	for _, f := range m.Files {
		p := filepath.Join(s.installDir, filepath.FromSlash(f))
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Put back what was there before setup wrote over it.
	originals := filepath.Join(s.installDir, originalsName)
	for _, f := range m.Originals {
		native := filepath.FromSlash(f)
		dst := filepath.Join(s.installDir, native)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(originals, native), dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("can't put back %s: %w", dst, err)
		}
	}
	if len(m.Originals) > 0 {
		removeEmptyDirs(originals, m.Originals)
		os.Remove(originals)
		fmt.Printf("Put back %d file(s) that were there before setup.\n", len(m.Originals))
	}
	removeEmptyDirs(s.installDir, m.Files)
	for _, l := range m.Shortcuts {
		os.Remove(l)
	}
	if err := os.Remove(filepath.Join(s.installDir, manifestName)); err != nil {
		return err
	}
	os.Remove(s.installDir) // only if empty
	fmt.Printf("Removed %s from %s.\n", m.Version, s.installDir)
	return nil
}

// removeEmptyDirs removes the folders the files lived in, deepest first, while they are empty.
func removeEmptyDirs(root string, files []string) {
	dirs := map[string]bool{}
	for _, f := range files {
		for d := path.Dir(f); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	list := make([]string, 0, len(dirs))
	for d := range dirs {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return strings.Count(list[i], "/") > strings.Count(list[j], "/") })
	for _, d := range list {
		os.Remove(filepath.Join(root, filepath.FromSlash(d))) // fails, harmlessly, when not empty
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
