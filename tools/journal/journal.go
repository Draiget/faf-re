// Package journal is mpemu's internal database: an append-only, queryable log
// of everything that happened in a run (GPGNet traffic in both directions,
// signalling events, TURN allocations, relay statistics, process lifecycle,
// scenario steps). It is mirrored to a JSONL file so a run can be inspected or
// diffed after the fact, and scenario steps block on it to wait for a state.
package journal

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Record kinds. GPGNet traffic is recorded from the launcher's point of view:
// "gpgnet.in" came from the game, "gpgnet.out" was sent to it.
const (
	GpgIn        = "gpgnet.in"
	GpgOut       = "gpgnet.out"
	GpgConnect   = "gpgnet.connect"
	GpgClose     = "gpgnet.close"
	ProcStart    = "proc.start"
	ProcExit     = "proc.exit"
	ProcExternal = "proc.external" // the game is to be started by hand (debugger)
	IceSession   = "ice.session"
	IceEvent     = "ice.event"
	IceSub       = "ice.subscribe"
	IceUnsub     = "ice.unsubscribe"
	IceLogs      = "ice.logs"
	TurnAlloc    = "turn.allocation"
	TurnDealloc  = "turn.deallocation"
	TurnPerm     = "turn.permission"
	TurnChannel  = "turn.channel"
	TurnAuthErr  = "turn.auth_failed"
	RelayStats   = "relay.stats"
	RelayLink    = "relay.link"
	Step         = "step"
	Note         = "note"
	Warn         = "warn"
	Verdict      = "verdict"
)

// Record is one journal row.
type Record struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"t"`
	Kind    string    `json:"kind"`
	Game    uint64    `json:"game,omitempty"` // signalling / TURN records: the game session
	UID     int       `json:"uid,omitempty"`
	Peer    int       `json:"peer,omitempty"`
	Command string    `json:"cmd,omitempty"`
	Args    []any     `json:"args,omitempty"`
	Text    string    `json:"text,omitempty"`
	Data    any       `json:"data,omitempty"`
}

// Journal is safe for concurrent use.
type Journal struct {
	mu      sync.Mutex
	records []Record
	file    *os.File
	enc     *json.Encoder
	changed chan struct{} // closed and replaced on every append
	echo    func(Record)
}

// New creates a journal, mirrored to path when it is non-empty. echo, when
// set, is called for every record (console output).
func New(path string, echo func(Record)) (*Journal, error) {
	j := &Journal{changed: make(chan struct{}), echo: echo}
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		j.file = f
		j.enc = json.NewEncoder(f)
	}
	return j, nil
}

// Add appends one record and returns it with its sequence number and time set.
func (j *Journal) Add(r Record) Record {
	j.mu.Lock()
	r.Seq = int64(len(j.records)) + 1
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	j.records = append(j.records, r)
	if j.enc != nil {
		_ = j.enc.Encode(r)
	}
	close(j.changed)
	j.changed = make(chan struct{})
	echo := j.echo
	j.mu.Unlock()
	if echo != nil {
		echo(r)
	}
	return r
}

// Note records a free-form note.
func (j *Journal) Note(kind string, uid int, text string, data any) Record {
	return j.Add(Record{Kind: kind, UID: uid, Text: text, Data: data})
}

// Last is the sequence number of the newest record.
func (j *Journal) Last() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return int64(len(j.records))
}

// Query returns every record matching pred, oldest first.
func (j *Journal) Query(pred func(Record) bool) []Record {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []Record
	for _, r := range j.records {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

// Tail returns the newest n records.
func (j *Journal) Tail(n int) []Record {
	j.mu.Lock()
	defer j.mu.Unlock()
	if n > len(j.records) {
		n = len(j.records)
	}
	return append([]Record(nil), j.records[len(j.records)-n:]...)
}

// WaitFor blocks until a record with Seq > after matches pred, and returns it.
func (j *Journal) WaitFor(ctx context.Context, after int64, pred func(Record) bool) (Record, error) {
	next := after
	for {
		j.mu.Lock()
		for ; next < int64(len(j.records)); next++ {
			if r := j.records[next]; pred(r) {
				j.mu.Unlock()
				return r, nil
			}
		}
		changed := j.changed
		j.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return Record{}, ctx.Err()
		}
	}
}

// Close flushes the mirror file.
func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file != nil {
		_ = j.file.Close()
		j.file = nil
		j.enc = nil
	}
}
