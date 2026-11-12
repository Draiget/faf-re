package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"faf-main/tools/journal"
	"faf-main/tools/seat"
)

// ServerTokenCheck is the result of CheckServerTokens.
type ServerTokenCheck struct {
	Fails []string // a token where it must not be, or a player's own missing
	Notes []string // what was looked at, per player
}

// CheckServerTokens proves plan WP2.9 for a ModeServer run: every player's game
// was handed its own connection string and no other player's token reached it.
// It reads what each game was sent (the journal's GpgOut records to it), its
// command line files and its log in the run folder; the journal itself must hold
// tags only (seat.TokenTag), never a token. Players on other machines are
// checked by their journal records alone.
func (l *Launcher) CheckServerTokens() ServerTokenCheck {
	var out ServerTokenCheck
	if l.cfg.Mode != ModeServer {
		out.Fails = append(out.Fails, "not a mode server run")
		return out
	}
	tokens := map[int]string{}
	for _, uid := range l.order {
		tokens[uid] = l.players[uid].Cfg.ServerToken
	}
	others := func(uid int) map[int]string {
		m := map[int]string{}
		for other, t := range tokens {
			if other != uid {
				m[other] = t
			}
		}
		return m
	}

	// The journal holds no token at all.
	for _, rec := range l.j.Query(func(journal.Record) bool { return true }) {
		text := recordText(rec)
		for uid, t := range tokens {
			if strings.Contains(text, t) {
				out.Fails = append(out.Fails, fmt.Sprintf("journal record #%d (%s) holds player %d's token", rec.Seq, rec.Kind, uid))
			}
		}
	}

	for _, uid := range l.order {
		p := l.players[uid]
		own := tokens[uid]
		delivery := p.Cfg.ServerDelivery

		// What this game was sent.
		joins := 0
		for _, rec := range l.j.Query(func(r journal.Record) bool { return r.Kind == journal.GpgOut && r.UID == uid }) {
			text := recordText(rec)
			for other, t := range others(uid) {
				if strings.Contains(text, seat.TokenTag(t)) {
					out.Fails = append(out.Fails, fmt.Sprintf("player %d was sent player %d's token (%s)", uid, other, rec.Command))
				}
			}
			if rec.Command == "JoinServer" {
				joins++
				if !strings.Contains(text, seat.TokenTag(own)) {
					out.Fails = append(out.Fails, fmt.Sprintf("player %d's JoinServer doesn't carry its own token", uid))
				}
			}
		}
		if delivery == seat.DeliverGpgNet && joins == 0 {
			out.Fails = append(out.Fails, fmt.Sprintf("player %d was never sent JoinServer", uid))
		}
		if delivery == seat.DeliverArgs && joins != 0 {
			out.Fails = append(out.Fails, fmt.Sprintf("player %d (args) was sent JoinServer too", uid))
		}

		if p.Cfg.Agent != "" || l.cfg.RunDir == "" {
			out.Notes = append(out.Notes, fmt.Sprintf("player %d (%s): %d JoinServer, sent messages only", uid, delivery, joins))
			continue
		}
		// Its command line and its own log.
		seen := []string{}
		for _, name := range []string{
			fmt.Sprintf("debug-args-%d.txt", uid), fmt.Sprintf("start-game-%d.cmd", uid), fmt.Sprintf("game-%d.log", uid),
		} {
			raw, err := os.ReadFile(filepath.Join(l.cfg.RunDir, name))
			if err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("player %d: %s not read: %v", uid, name, err))
				continue
			}
			text := string(raw)
			for other, t := range others(uid) {
				if strings.Contains(text, t) {
					out.Fails = append(out.Fails, fmt.Sprintf("player %d's %s holds player %d's token", uid, name, other))
				}
			}
			mark := "no token"
			if strings.Contains(text, own) {
				mark = "own token"
			}
			seen = append(seen, name+": "+mark)
			if delivery == seat.DeliverArgs && strings.HasPrefix(name, "debug-args") && !strings.Contains(text, own) {
				out.Fails = append(out.Fails, fmt.Sprintf("player %d (args) has no /servertoken of its own", uid))
			}
		}
		out.Notes = append(out.Notes, fmt.Sprintf("player %d (%s): %d JoinServer; %s", uid, delivery, joins, strings.Join(seen, ", ")))
	}
	return out
}

func recordText(rec journal.Record) string {
	return fmt.Sprint(rec.Command, " ", rec.Text, " ", rec.Args, " ", rec.Data)
}
