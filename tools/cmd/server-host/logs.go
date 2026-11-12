package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Logs: the host's own log lines (kept in memory, the last hostLogLines) and each lobby's server.log, as a tail and as
// a live stream of new lines (Server-Sent Events).

const (
	hostLogLines = 5000
	maxLogLine   = 4096
	maxTailBytes = 4 << 20
)

// logRing keeps the host's last log lines and hands new ones to the streams that follow it. It is the log package's
// output (with stderr).
type logRing struct {
	mu      sync.Mutex
	lines   []string
	partial []byte
	subs    map[chan string]struct{}
}

func (r *logRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.partial = append(r.partial, p...)
	for {
		i := bytes.IndexByte(r.partial, '\n')
		if i < 0 {
			break
		}
		line := clipLine(string(bytes.TrimRight(r.partial[:i], "\r")))
		r.partial = r.partial[i+1:]
		r.lines = append(r.lines, line)
		if len(r.lines) > hostLogLines {
			r.lines = append(r.lines[:0:0], r.lines[len(r.lines)-hostLogLines:]...)
		}
		for ch := range r.subs {
			select {
			case ch <- line:
			default: // a stream that doesn't keep up loses lines rather than holding the log up
			}
		}
	}
	return len(p), nil
}

func (r *logRing) tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > len(r.lines) {
		n = len(r.lines)
	}
	return append([]string{}, r.lines[len(r.lines)-n:]...)
}

func (r *logRing) subscribe() (chan string, func()) {
	ch := make(chan string, 256)
	r.mu.Lock()
	if r.subs == nil {
		r.subs = map[chan string]struct{}{}
	}
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		delete(r.subs, ch)
		r.mu.Unlock()
	}
}

func clipLine(s string) string {
	if len(s) > maxLogLine {
		return s[:maxLogLine] + "…"
	}
	return s
}

// splitLines splits text into lines without their ends.
func splitLines(text []byte) []string {
	var out []string
	for _, l := range strings.Split(string(text), "\n") {
		out = append(out, clipLine(strings.TrimRight(l, "\r")))
	}
	return out
}

// tailFile is a file's last n lines (read from at most its last maxTailBytes) and its size.
func tailFile(path string, n int) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	from := size - maxTailBytes
	if from < 0 {
		from = 0
	}
	buf := make([]byte, size-from)
	if _, err := f.ReadAt(buf, from); err != nil && err != io.EOF {
		return nil, 0, err
	}
	buf = bytes.TrimRight(buf, "\n")
	if len(buf) == 0 {
		return []string{}, size, nil
	}
	lines := splitLines(buf)
	if from > 0 && len(lines) > 0 {
		lines = lines[1:] // cut in the middle
	}
	if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	return lines, size, nil
}

// linesParam reads ?lines= (default 500, at most 5000).
func linesParam(r *http.Request) int {
	n := 500
	if v := r.URL.Query().Get("lines"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
			n = 500
		}
	}
	if n > hostLogLines {
		n = hostLogLines
	}
	return n
}

// sseStart answers with an event stream; false if the connection can't stream.
func sseStart(w http.ResponseWriter) (http.Flusher, bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, fmt.Errorf("streaming isn't supported here"))
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": stream open\n\n")
	fl.Flush()
	return fl, true
}

// streamRing sends the host's new log lines as they come, one "data:" event each.
func streamRing(w http.ResponseWriter, r *http.Request, ring *logRing) {
	fl, ok := sseStart(w)
	if !ok {
		return
	}
	ch, done := ring.subscribe()
	defer done()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", line)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// streamFile follows a lobby's log from its current end: each new complete line as a "data:" event; once the lobby
// has ended and the file is read to its end, an "end" event, and the stream closes.
func streamFile(w http.ResponseWriter, r *http.Request, path string, live func() bool) {
	f, err := os.Open(path)
	if err != nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no log yet: %v", err))
		return
	}
	defer f.Close()
	fl, ok := sseStart(w)
	if !ok {
		return
	}
	var off int64
	if st, err := f.Stat(); err == nil {
		off = st.Size()
	}
	var partial []byte
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	quiet := 0
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
		alive := live()
		st, err := f.Stat()
		if err != nil {
			return
		}
		if st.Size() < off { // the file was cut: start over
			off, partial = 0, nil
		}
		sent := false
		for off < st.Size() {
			n, err := f.ReadAt(buf, off)
			if n > 0 {
				off += int64(n)
				partial = append(partial, buf[:n]...)
				for {
					i := bytes.IndexByte(partial, '\n')
					if i < 0 {
						break
					}
					fmt.Fprintf(w, "data: %s\n\n", clipLine(string(bytes.TrimRight(partial[:i], "\r"))))
					partial = partial[i+1:]
					sent = true
				}
				if len(partial) > maxLogLine {
					fmt.Fprintf(w, "data: %s\n\n", clipLine(string(partial)))
					partial, sent = nil, true
				}
			}
			if err != nil {
				break
			}
		}
		if sent {
			fl.Flush()
			quiet = 0
		} else if quiet++; quiet%30 == 0 {
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
		if !alive && !sent {
			if len(partial) > 0 {
				fmt.Fprintf(w, "data: %s\n\n", clipLine(string(partial)))
			}
			fmt.Fprint(w, "event: end\ndata: {}\n\n")
			fl.Flush()
			return
		}
	}
}
