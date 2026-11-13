package main

// Plan WPR.16: placement by the players' ping. Each host answers RTT probes on a UDP echo (server-host --rtt-echo,
// format in tools/rttprobe); a signed-in player measures every host (tools/cmd/rtt-probe, later the launcher) and
// reports the medians here. A lobby or request made with "placement": "ping" then goes to the host whose worst
// player ping is lowest among those that can take it, near-ties broken by load.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	rttTTL      = 30 * time.Minute // a report counts this long
	rttMaxMs    = 2000.0
	rttMarginMs = 10.0            // worst pings this close are a tie, broken by load
	rttMinGap   = 2 * time.Second // between two reports of one user
)

// rttEntry is one user's ping to one host.
type rttEntry struct {
	Ms      float64 `json:"ms"`
	LossPct float64 `json:"loss_pct"`
	At      string  `json:"at"`
}

// rttRecord is what a user reported, per host; kept rttTTL after the last report, each entry rttTTL after its own.
type rttRecord struct {
	UID     int                 `json:"uid"`
	Name    string              `json:"name"`
	Updated string              `json:"updated"`
	Hosts   map[string]rttEntry `json:"hosts"`
}

func rttKey(uid int) string { return "rtt:" + strconv.Itoa(uid) }

// reached says whether a reported entry is a ping (some probe came back) rather than a host nothing came back from.
func (e rttEntry) reached() bool { return e.LossPct < 100 }

// rttOf reads a user's report without its entries older than rttTTL; nil when there is none.
func (s *server) rttOf(ctx context.Context, uid int, now time.Time) (*rttRecord, error) {
	if uid == 0 {
		return nil, nil
	}
	v, ok, err := s.store.Get(ctx, rttKey(uid))
	if err != nil || !ok {
		return nil, err
	}
	var rec rttRecord
	if json.Unmarshal([]byte(v), &rec) != nil {
		return nil, nil
	}
	for h, e := range rec.Hosts {
		at, err := time.Parse(time.RFC3339, e.At)
		if err != nil || now.Sub(at) > rttTTL {
			delete(rec.Hosts, h)
		}
	}
	if len(rec.Hosts) == 0 {
		return nil, nil
	}
	return &rec, nil
}

// GET /api/v1/rtt/hosts: where every signed-in user probes each host.
func (s *server) rttHosts(w http.ResponseWriter) {
	out := []map[string]any{}
	for _, p := range s.reg.all() {
		h, _ := p.state()
		out = append(out, map[string]any{"name": h.Name, "region": h.Region, "rtt_echo": h.RTTEcho, "reachable": h.Reachable})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hosts": out, "max_age_minutes": rttTTL.Minutes(),
		"probe": map[string]any{"format": "rttprobe/1", "count": 10, "interval_ms": 50, "timeout_ms": 1000}})
}

type rttReport struct {
	RTTs []struct {
		Host    string   `json:"host"`
		Ms      *float64 `json:"ms"`
		LossPct float64  `json:"loss_pct"`
	} `json:"rtts"`
}

// /api/v1/rtt: GET the signed-in user's own report; POST a report, merged into the one kept.
func (s *server) rttRoute(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) {
	if who.UID == 0 {
		fail(w, http.StatusForbidden, errors.New("a ping is a FAF user's: sign in with FAF"))
		return
	}
	now := time.Now().UTC()
	rec, err := s.rttOf(r.Context(), who.UID, now)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	if r.Method == http.MethodGet {
		if rec == nil {
			rec = &rttRecord{UID: who.UID, Name: who.Name, Hosts: map[string]rttEntry{}}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rtt": rec})
		return
	}
	var body rttReport
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
		return
	}
	if len(body.RTTs) == 0 || len(body.RTTs) > max(len(cfg.Hosts), 1) {
		fail(w, http.StatusBadRequest, fmt.Errorf("rtts lists 1 to %d hosts", max(len(cfg.Hosts), 1)))
		return
	}
	fresh := map[string]rttEntry{}
	stamp := now.Format(time.RFC3339)
	for i, e := range body.RTTs {
		if cfg.host(e.Host) == nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("rtts[%d]: no host %q", i, e.Host))
			return
		}
		if _, twice := fresh[e.Host]; twice {
			fail(w, http.StatusBadRequest, fmt.Errorf("rtts[%d]: %s twice", i, e.Host))
			return
		}
		if math.IsNaN(e.LossPct) || e.LossPct < 0 || e.LossPct > 100 {
			fail(w, http.StatusBadRequest, fmt.Errorf("rtts[%d]: loss_pct is 0..100", i))
			return
		}
		entry := rttEntry{LossPct: math.Round(e.LossPct*10) / 10, At: stamp}
		if e.LossPct < 100 {
			if e.Ms == nil || math.IsNaN(*e.Ms) || *e.Ms < 0 || *e.Ms > rttMaxMs {
				fail(w, http.StatusBadRequest, fmt.Errorf("rtts[%d]: ms is 0..%v (or loss_pct 100: nothing came back)", i, rttMaxMs))
				return
			}
			entry.Ms = math.Round(*e.Ms*10) / 10
		}
		fresh[e.Host] = entry
	}
	// A well-formed report, but too soon after the last one: refused, so that one user can't keep the store busy.
	if rec != nil {
		if at, err := time.Parse(time.RFC3339Nano, rec.Updated); err == nil && now.Sub(at) < rttMinGap {
			fail(w, http.StatusTooManyRequests, fmt.Errorf("one report every %v", rttMinGap))
			return
		}
	} else {
		rec = &rttRecord{UID: who.UID, Hosts: map[string]rttEntry{}}
	}
	for h, e := range fresh {
		rec.Hosts[h] = e
	}
	rec.Name, rec.Updated = who.Name, now.Format(time.RFC3339Nano)
	b, _ := json.Marshal(rec)
	if err := s.store.Set(r.Context(), rttKey(who.UID), string(b), rttTTL); err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rtt": rec})
}

// placementPlayer is a human seat without a usable ping.
type placementPlayer struct {
	Seat int    `json:"seat"`
	UID  int    `json:"uid,omitempty"`
	Name string `json:"name"`
	Why  string `json:"why"` // open seat, or no report
}

// hostPlacement is one host's row of the placement table.
type hostPlacement struct {
	Host           string   `json:"host"`
	Region         string   `json:"region,omitempty"`
	WorstMs        *float64 `json:"worst_ms"` // null: no measured player reported this host
	WorstPlayer    string   `json:"worst_player,omitempty"`
	Measured       int      `json:"measured"`                  // players with a ping to it
	Unmeasured     []string `json:"unmeasured,omitempty"`      // players who reported others but not this one
	UnreachableFor []string `json:"unreachable_for,omitempty"` // players none of whose probes came back
	Load           float64  `json:"load"`
	Candidate      bool     `json:"candidate"` // reachable, has the map and room (or takes players' games)
	Reason         string   `json:"reason,omitempty"`
	Rank           int      `json:"rank,omitempty"` // the order it is tried in, 1 first
}

// placement says how the host was chosen; the answer carries it with "placement": "ping".
type placement struct {
	Mode     string            `json:"mode"`
	MarginMs float64           `json:"margin_ms"`
	Players  int               `json:"players"` // human seats
	Measured int               `json:"measured"`
	Missing  []placementPlayer `json:"missing"`
	Basis    string            `json:"basis"`
	Hosts    []hostPlacement   `json:"hosts"`
	Picked   string            `json:"picked,omitempty"`
}

// rankByPing orders candidate hosts by their worst player ping: first those every measured player reached, then those
// fewest measured players lack, then the lowest worst ping, where pings within rttMarginMs of the best left are a tie
// that tieLess (the usual order) breaks. Players without a report don't block a placement; they are listed as missing.
// It answers the order (indices into rows) and fills rows' ping fields and ranks.
func (s *server) rankByPing(ctx context.Context, seats []seatIn, rows []hostPlacement, tieLess func(i, j int) bool) ([]int, *placement, error) {
	now := time.Now().UTC()
	pl := &placement{Mode: "ping", MarginMs: rttMarginMs, Missing: []placementPlayer{}}
	type measured struct {
		name string
		rec  *rttRecord
	}
	players := []measured{}
	for i, seat := range seats {
		if seat.Kind != "human" {
			continue
		}
		pl.Players++
		name := seat.Name
		if name == "" {
			name = fmt.Sprintf("seat %d", i+1)
		}
		if seat.UID == 0 {
			pl.Missing = append(pl.Missing, placementPlayer{Seat: i + 1, Name: name, Why: "open seat"})
			continue
		}
		rec, err := s.rttOf(ctx, seat.UID, now)
		if err != nil {
			return nil, nil, err
		}
		if rec == nil {
			pl.Missing = append(pl.Missing, placementPlayer{Seat: i + 1, UID: seat.UID, Name: name,
				Why: fmt.Sprintf("no ping reported in the last %d minutes", int(rttTTL.Minutes()))})
			continue
		}
		players = append(players, measured{name, rec})
	}
	pl.Measured = len(players)
	for i := range rows {
		row := &rows[i]
		for _, p := range players {
			e, ok := p.rec.Hosts[row.Host]
			switch {
			case !ok:
				row.Unmeasured = append(row.Unmeasured, p.name)
			case !e.reached():
				row.UnreachableFor = append(row.UnreachableFor, p.name)
			default:
				row.Measured++
				if row.WorstMs == nil || e.Ms > *row.WorstMs {
					ms := e.Ms
					row.WorstMs, row.WorstPlayer = &ms, p.name
				}
			}
		}
	}
	cand := []int{}
	for i := range rows {
		if rows[i].Candidate {
			cand = append(cand, i)
		}
	}
	// Groups by (unreachable, unmeasured), each ordered by worst ping with near-ties by tieLess.
	sort.SliceStable(cand, func(a, b int) bool {
		ra, rb := rows[cand[a]], rows[cand[b]]
		if len(ra.UnreachableFor) != len(rb.UnreachableFor) {
			return len(ra.UnreachableFor) < len(rb.UnreachableFor)
		}
		return len(ra.Unmeasured) < len(rb.Unmeasured)
	})
	order := []int{}
	for start := 0; start < len(cand); {
		end := start
		for end < len(cand) && len(rows[cand[end]].UnreachableFor) == len(rows[cand[start]].UnreachableFor) &&
			len(rows[cand[end]].Unmeasured) == len(rows[cand[start]].Unmeasured) {
			end++
		}
		left := slices.Clone(cand[start:end])
		for len(left) > 0 {
			best := -1
			for _, i := range left {
				if rows[i].WorstMs != nil && (best < 0 || *rows[i].WorstMs < *rows[best].WorstMs) {
					best = i
				}
			}
			tied := left
			if best >= 0 {
				tied = []int{}
				for _, i := range left {
					if rows[i].WorstMs != nil && *rows[i].WorstMs <= *rows[best].WorstMs+rttMarginMs {
						tied = append(tied, i)
					}
				}
			}
			pick := tied[0]
			for _, i := range tied[1:] {
				if tieLess(i, pick) {
					pick = i
				}
			}
			order = append(order, pick)
			left = slices.DeleteFunc(left, func(i int) bool { return i == pick })
		}
		start = end
	}
	for rank, i := range order {
		rows[i].Rank = rank + 1
	}
	pl.Hosts = rows
	switch {
	case pl.Players == 0:
		pl.Basis = "no human seats: the usual order"
	case pl.Measured == 0:
		pl.Basis = fmt.Sprintf("no player has reported a ping in the last %d minutes: the usual order", int(rttTTL.Minutes()))
	default:
		pl.Basis = fmt.Sprintf("the worst ping of %d of %d players; within %v ms of the best, the usual order", pl.Measured,
			pl.Players, rttMarginMs)
		if len(pl.Missing) > 0 {
			names := []string{}
			for _, m := range pl.Missing {
				names = append(names, m.Name)
			}
			pl.Basis += "; without " + strings.Join(names, ", ")
		}
	}
	return order, pl, nil
}

// previewPlacement is POST /api/v1/placement: a lobby's fields, answered with where it would go now; nothing is made.
func (s *server) previewPlacement(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) {
	b, ok := s.decodeCreate(w, r, cfg, who)
	if !ok {
		return
	}
	if b.Placement != "ping" {
		fail(w, http.StatusBadRequest, errors.New(`a preview is for "placement": "ping"`))
		return
	}
	cands, reasons, pl, err := s.pickHosts(r.Context(), b)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	if len(cands) > 0 && cands[0].p != nil {
		pl.Picked = cands[0].p.h.cfg.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "placement": pl, "reasons": reasons})
}
