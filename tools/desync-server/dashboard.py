"""Web dashboard for the desync test server: the records the collector stored and the dumps the receiver keeps.

usage: dashboard.py [--host 127.0.0.1] [--port 4320] [--otel DIR] [--dumps DIR] [--read-token R]

Reads, never writes: the collector's file exporter output (<otel>/received*.jsonl, OTLP JSON, one
export per line, rotated files included) and the receiver's folders (<dumps>/<game id>/ with the
.tar.gz dumps and report.txt). Pages:

  /                     counts, desyncs per build, the latest records (filters: kind, build, search)
  /games                every game seen in a record or a dump folder
  /game/<id>            the game's records with all attributes, the switches that differ between
                        its players, its dumps and the comparison report
  /files/<id>/<file>    a dump or report.txt; <file>/ lists a dump's entries, <file>/<entry> shows one
  /api/records          the records as JSON

With --read-token set (default FAF_READ_TOKEN), every page except /healthz needs the token:
"Authorization: Bearer <token>", ?token=<token> once (kept in a cookie), or the login form.
Attributes whose name contains "authorization" or "token" are shown as <hidden>.
Python 3, standard library only.
"""

import argparse
import datetime
import glob
import hmac
import html
import http.server
import json
import os
import re
import tarfile
import threading
import urllib.parse

DUMP = re.compile(r"^desync_([A-Za-z0-9_.-]+?)_(beat\d+|at\d+)_army(-?\d+)\.tar\.gz$")
GAME = re.compile(r"^[A-Za-z0-9_.-]+$")
COOKIE = "faf_read"
SHOW_BYTES = 1024 * 1024
RECENT_ROWS = 300

STYLE = """
:root { --bg: #f7f7f5; --panel: #ffffff; --text: #1d1d1b; --muted: #6b6b66; --line: #e2e2dc;
  --accent: #2f5fb3; --warn: #b4441c; --ok: #2d7a3e; --code: #f0f0ec; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --bg: #161615; --panel: #1f1f1d;
  --text: #e8e8e3; --muted: #9a9a93; --line: #34342f; --accent: #7aa2e8; --warn: #e9845c; --ok: #6fc282;
  --code: #262623; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 system-ui, sans-serif; }
header { display: flex; flex-wrap: wrap; gap: 4px 18px; align-items: baseline; padding: 12px 16px;
  border-bottom: 1px solid var(--line); background: var(--panel); }
header b { font-size: 16px; } header a { color: var(--accent); text-decoration: none; }
main { padding: 16px; max-width: 1500px; }
h1 { font-size: 20px; margin: 0 0 12px; } h2 { font-size: 16px; margin: 22px 0 8px; }
a { color: var(--accent); }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; }
.card .n { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; }
.card .l { color: var(--muted); font-size: 12px; }
.wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 6px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 5px 9px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 12px; white-space: nowrap; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: 0; }
.muted { color: var(--muted); } .warn { color: var(--warn); } .ok { color: var(--ok); }
.mono, pre, code { font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; }
pre { background: var(--code); padding: 10px; border-radius: 6px; overflow-x: auto; white-space: pre; }
form.filters { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
input, select, button { font: inherit; padding: 4px 8px; background: var(--panel); color: var(--text);
  border: 1px solid var(--line); border-radius: 4px; }
details { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; margin: 8px 0; }
details summary { padding: 8px 10px; cursor: pointer; }
details > div { padding: 0 10px 10px; }
.tag { display: inline-block; padding: 0 6px; border-radius: 4px; font-size: 12px; border: 1px solid var(--line); }
.tag.desync { color: var(--warn); border-color: var(--warn); } .tag.end { color: var(--ok); border-color: var(--ok); }
"""


def otlp_value(value):
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "boolValue" in value:
        return value["boolValue"]
    if "doubleValue" in value:
        return value["doubleValue"]
    if "arrayValue" in value:
        return [otlp_value(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return {kv["key"]: otlp_value(kv.get("value", {})) for kv in value["kvlistValue"].get("values", [])}
    return None


def masked(attributes):
    return {k: ("<hidden>" if "authorization" in k.lower() or "token" in k.lower() else v)
            for k, v in attributes.items()}


class Records:
    """The collector's files, parsed once per change of size or time."""

    def __init__(self, folder):
        self.folder = folder
        self.lock = threading.Lock()
        self.files = {}

    def parse(self, path):
        records = []
        with open(path, encoding="utf-8", errors="replace") as lines:
            for number, line in enumerate(lines):
                try:
                    export = json.loads(line)
                except ValueError:
                    continue
                for resource_logs in export.get("resourceLogs", []):
                    resource = masked({a["key"]: otlp_value(a.get("value", {}))
                                       for a in resource_logs.get("resource", {}).get("attributes", [])})
                    for scope_logs in resource_logs.get("scopeLogs", []):
                        scope = scope_logs.get("scope", {}).get("name", "")
                        for index, record in enumerate(scope_logs.get("logRecords", [])):
                            attributes = masked({a["key"]: otlp_value(a.get("value", {}))
                                                 for a in record.get("attributes", [])})
                            records.append({
                                "id": "%s.%d.%d" % (os.path.basename(path), number, index),
                                "time": int(record.get("timeUnixNano") or record.get("observedTimeUnixNano") or 0),
                                "kind": attributes.get("event.name") or scope or otlp_value(record.get("body", {})),
                                "severity": record.get("severityText", ""),
                                "resource": resource,
                                "attributes": attributes,
                            })
        return records

    def all(self):
        paths = glob.glob(os.path.join(self.folder, "received*.jsonl"))
        with self.lock:
            for path in paths:
                try:
                    stamp = (os.path.getsize(path), os.path.getmtime(path))
                except OSError:
                    continue
                cached = self.files.get(path)
                if not cached or cached[0] != stamp:
                    self.files[path] = (stamp, self.parse(path))
            for gone in set(self.files) - set(paths):
                del self.files[gone]
            records = [r for _, parsed in self.files.values() for r in parsed]
        return sorted(records, key=lambda r: r["time"], reverse=True)


def when(nanoseconds):
    if not nanoseconds:
        return "-"
    stamp = datetime.datetime.fromtimestamp(nanoseconds / 1e9, datetime.timezone.utc)
    return stamp.strftime("%Y-%m-%d %H:%M:%S")


def build_of(record):
    resource = record["resource"]
    version = str(resource.get("faf.engine.version") or str(resource.get("service.version", ""))[:9] or "?")
    return version + ("-dirty" if resource.get("faf.engine.dirty") and not version.endswith("-dirty") else "")


def switch_map(text):
    pairs = {}
    for item in str(text or "").split(";"):
        if "=" in item:
            key, value = item.split("=", 1)
            pairs[key.strip()] = value
    return pairs


def e(value):
    return html.escape(str(value))


def size_text(count):
    for unit in ("B", "KB", "MB", "GB"):
        if count < 1024 or unit == "GB":
            return ("%d %s" if unit == "B" else "%.1f %s") % (count, unit)
        count /= 1024.0


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path == "/healthz":
            return self.reply(200, "ok")
        token = (query.get("token") or [""])[0]
        if token and self.token_ok(token):
            rest = urllib.parse.urlencode([(k, v) for k, vs in query.items() if k != "token" for v in vs])
            return self.redirect(url.path + ("?" + rest if rest else ""), token)
        if not self.authorized():
            return self.login_page()
        if url.path == "/logout":
            return self.redirect("/", "", expire=True)
        parts = [urllib.parse.unquote(p) for p in url.path.split("/") if p]
        if not parts:
            return self.overview(query)
        if parts == ["games"]:
            return self.games()
        if parts == ["api", "records"]:
            return self.reply(200, json.dumps(self.server.records.all(), indent=1), "application/json")
        if parts[0] == "game" and len(parts) == 2:
            return self.game(parts[1])
        if parts[0] == "files" and len(parts) >= 3:
            return self.file(parts[1], parts[2], "/".join(parts[3:]), url.path.endswith("/"), "raw" in query)
        return self.reply(404, "not found")

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/login":
            return self.reply(404, "not found")
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = (form.get("token") or [""])[0]
        if not self.token_ok(token):
            return self.login_page("Wrong token.")
        self.redirect("/", token)

    # ---- access

    def token_ok(self, token):
        expected = self.server.options.read_token
        return not expected or hmac.compare_digest(token.encode(), expected.encode())

    def authorized(self):
        if not self.server.options.read_token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and self.token_ok(auth[7:]):
            return True
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and self.token_ok(urllib.parse.unquote(value)):
                return True
        return False

    def redirect(self, where, token, expire=False):
        self.send_response(303)
        self.send_header("Location", where)
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        if token or expire:
            self.send_header("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (
                COOKIE, urllib.parse.quote(token), 0 if expire else 30 * 86400, secure))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def login_page(self, note=""):
        body = ('<h1>Read token</h1><p class="muted">The dumps hold player names and game logs; '
                'this dashboard needs the server\'s read token.</p>'
                '<form method="post" action="/login" class="filters"><input type="password" name="token" '
                'autofocus size="40" aria-label="read token"><button>Open</button></form>%s') % (
                    '<p class="warn">%s</p>' % e(note) if note else "")
        self.page("Desync server", body, code=401, nav=False)

    # ---- pages

    def dump_folders(self):
        folder = self.server.options.dumps
        if not os.path.isdir(folder):
            return {}
        games = {}
        for game in os.listdir(folder):
            path = os.path.join(folder, game)
            if GAME.match(game) and os.path.isdir(path):
                games[game] = sorted(f for f in os.listdir(path) if DUMP.match(f) or f == "report.txt")
        return games

    def overview(self, query):
        records = self.server.records.all()
        dumps = self.dump_folders()
        kind = (query.get("kind") or [""])[0]
        build = (query.get("build") or [""])[0]
        search = (query.get("q") or [""])[0].strip().lower()

        desyncs = [r for r in records if r["kind"] == "faf.desync"]
        ends = [r for r in records if r["kind"] == "faf.game.end"]
        games_desynced = {r["attributes"].get("faf.game.id") for r in desyncs}
        cards = [
            (len(desyncs), "desync records"),
            (len(games_desynced - {None}), "games with a desync"),
            (len(ends), "game-end records"),
            (sum(len([f for f in files if DUMP.match(f)]) for files in dumps.values()), "dumps stored"),
            (len({build_of(r) for r in records}), "builds seen"),
            (when(records[0]["time"]) if records else "-", "last record (UTC)"),
        ]
        out = ['<h1>Desync records</h1><div class="cards">']
        out += ['<div class="card"><div class="n">%s</div><div class="l">%s</div></div>' % (e(n), e(l))
                for n, l in cards]
        out.append("</div>")

        per_build = {}
        for r in records:
            key = (build_of(r), r["resource"].get("faf.arch", "?"), r["resource"].get("os.type", "?"))
            row = per_build.setdefault(key, {"desync": 0, "end": 0, "games": set(), "ended": set(),
                                             "last": 0})
            game_id = r["attributes"].get("faf.game.id")
            if r["kind"] == "faf.desync":
                row["desync"] += 1
                row["games"].add(game_id)
            elif r["kind"] == "faf.game.end":
                row["end"] += 1
                row["ended"].add(game_id)
            row["last"] = max(row["last"], r["time"])
        out.append('<h2>Per build</h2><div class="wrap"><table><tr><th>build</th><th>arch</th><th>os</th>'
                   '<th>desync records</th><th>games with a desync</th><th>game ends</th>'
                   '<th>games desynced / ended</th><th>last record</th></tr>')
        for (name, arch, os_type), row in sorted(per_build.items(), key=lambda kv: -kv[1]["last"]):
            ended = len(row["ended"])
            share = "%d / %d" % (len(row["games"] & row["ended"]), ended) if ended else "-"
            out.append('<tr><td class="mono"><a href="/?build=%s">%s</a></td><td>%s</td><td>%s</td>'
                       '<td class="num">%d</td><td class="num">%d</td><td class="num">%d</td>'
                       '<td class="num">%s</td><td class="mono">%s</td></tr>' % (
                           urllib.parse.quote(name), e(name), e(arch), e(os_type), row["desync"],
                           len(row["games"]), row["end"], share, when(row["last"])))
        out.append("</table></div>")

        shown = [r for r in records if (not kind or r["kind"] == kind) and (not build or build_of(r) == build)]
        if search:
            shown = [r for r in shown if search in json.dumps(r["attributes"]).lower()
                     or search in json.dumps(r["resource"]).lower()]
        kinds = sorted({r["kind"] for r in records})
        out.append('<h2>Records</h2><form class="filters" method="get"><select name="kind" aria-label="kind">'
                   '<option value="">all kinds</option>%s</select>'
                   '<input name="build" placeholder="build" value="%s" aria-label="build">'
                   '<input name="q" placeholder="search: game id, map, switch..." value="%s" size="28" '
                   'aria-label="search"><button>Filter</button> <a href="/">clear</a></form>' % (
                       "".join('<option%s>%s</option>' % (" selected" if k == kind else "", e(k)) for k in kinds),
                       e(build), e(search)))
        out.append(self.record_table(shown[:RECENT_ROWS], dumps))
        if len(shown) > RECENT_ROWS:
            out.append('<p class="muted">%d more; narrow the filter or use /api/records.</p>' % (
                len(shown) - RECENT_ROWS))
        self.page("Desync server", "".join(out))

    def record_table(self, records, dumps, link_game=True):
        if not records:
            return '<p class="muted">No records.</p>'
        out = ['<div class="wrap"><table><tr><th>time (UTC)</th><th>kind</th><th>game</th><th>build</th>'
               '<th>arch</th><th>map</th><th>army</th><th>beat</th><th>disagree / reported</th>'
               '<th>switches changed</th><th>dump</th></tr>']
        for r in records:
            a = r["attributes"]
            game_id = a.get("faf.game.id")
            is_desync = r["kind"] == "faf.desync"
            tag = '<span class="tag %s">%s</span>' % ("desync" if is_desync else "end" if r["kind"] == "faf.game.end"
                                                       else "", e(r["kind"].replace("faf.", "")))
            game = ('<a href="/game/%s">%s</a>' % (urllib.parse.quote(str(game_id)), e(game_id))
                    if game_id is not None and link_game else e(game_id if game_id is not None else "-"))
            beat = a.get("faf.desync.beat", a.get("faf.game.beats", ""))
            votes = ("%s / %s" % (a.get("faf.desync.players_disagreeing", "?"), a.get("faf.desync.players_reported", "?"))
                     if is_desync else "")
            dump = a.get("faf.dump.file", "")
            stored_name = str(dump).replace(".zip", ".tar.gz")
            if dump and stored_name in dumps.get(str(game_id), []):
                dump_cell = '<a href="/files/%s/%s/">%s</a>' % (
                    urllib.parse.quote(str(game_id)), urllib.parse.quote(stored_name), e(stored_name))
            else:
                dump_cell = '<span class="muted">%s</span>' % e(dump) if dump else ""
            changed = str(a.get("faf.switches.changed", ""))
            out.append('<tr><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td>'
                       '<td>%s</td><td>%s</td><td class="num">%s</td><td class="num">%s</td><td class="num">%s</td>'
                       '<td class="mono" title="%s">%s</td><td class="mono">%s</td></tr>' % (
                           when(r["time"]), tag, game, e(build_of(r)), e(r["resource"].get("faf.arch", "")),
                           e(os.path.basename(str(a.get("faf.map", "")))), e(a.get("faf.army.local", "")),
                           e(beat), votes, e(changed), e(changed if len(changed) < 70 else changed[:67] + "..."),
                           dump_cell))
        out.append("</table></div>")
        return "".join(out)

    def games(self):
        records = self.server.records.all()
        dumps = self.dump_folders()
        games = {}
        for r in records:
            game_id = r["attributes"].get("faf.game.id")
            if game_id is None:
                continue
            row = games.setdefault(str(game_id), {"desync": 0, "end": 0, "last": 0, "map": ""})
            row["desync" if r["kind"] == "faf.desync" else "end"] += 1
            row["last"] = max(row["last"], r["time"])
            row["map"] = row["map"] or os.path.basename(str(r["attributes"].get("faf.map", "")))
        for game_id in dumps:
            games.setdefault(game_id, {"desync": 0, "end": 0, "last": 0, "map": ""})
        out = ['<h1>Games</h1><div class="wrap"><table><tr><th>game</th><th>map</th><th>desync records</th>'
               '<th>game ends</th><th>dumps</th><th>report</th><th>last record (UTC)</th></tr>']
        for game_id, row in sorted(games.items(), key=lambda kv: (-kv[1]["last"], kv[0])):
            files = dumps.get(game_id, [])
            out.append('<tr><td class="mono"><a href="/game/%s">%s</a></td><td>%s</td><td class="num">%d</td>'
                       '<td class="num">%d</td><td class="num">%d</td><td>%s</td><td class="mono">%s</td></tr>' % (
                           urllib.parse.quote(game_id), e(game_id), e(row["map"]), row["desync"], row["end"],
                           len([f for f in files if DUMP.match(f)]), "yes" if "report.txt" in files else "",
                           when(row["last"])))
        out.append("</table></div>")
        self.page("Games", "".join(out))

    def game(self, game_id):
        if not GAME.match(game_id):
            return self.reply(404, "not found")
        records = [r for r in self.server.records.all() if str(r["attributes"].get("faf.game.id")) == game_id]
        files = self.dump_folders().get(game_id, [])
        if not records and not files:
            return self.reply(404, "no records or dumps for game %s" % game_id)
        out = ["<h1>Game %s</h1>" % e(game_id), "<h2>Records</h2>",
               self.record_table(records, {game_id: files}, link_game=False)]

        # faf.switches lists every reported switch; older builds send only faf.switches.changed (the
        # ones off their default), where a missing switch means "default".
        players = {}
        for r in records:
            listed = r["attributes"].get("faf.switches") or r["attributes"].get("faf.switches.changed")
            if listed is not None:
                players.setdefault(r["attributes"].get("faf.army.local", "?"), switch_map(listed))
        if len(players) > 1:
            keys = sorted({k for m in players.values() for k in m})
            differ = [k for k in keys if len({m.get(k, "default") for m in players.values()}) > 1]
            out.append("<h2>Switches that differ between players</h2>")
            if differ:
                armies = sorted(players, key=str)
                out.append('<div class="wrap"><table><tr><th>switch</th>%s</tr>%s</table></div>' % (
                    "".join("<th>army %s</th>" % e(a) for a in armies),
                    "".join('<tr><td class="mono">%s</td>%s</tr>' % (
                        e(k), "".join('<td class="mono">%s</td>' % e(players[a].get(k, "default")) for a in armies))
                        for k in differ)))
            else:
                out.append('<p class="ok">None: all %d players report the same %d switches.</p>' % (
                    len(players), len(keys)))

        out.append("<h2>Dumps</h2>")
        if files:
            folder = os.path.join(self.server.options.dumps, game_id)
            out.append('<div class="wrap"><table><tr><th>file</th><th>size</th><th></th></tr>')
            for name in files:
                link = "/files/%s/%s" % (urllib.parse.quote(game_id), urllib.parse.quote(name))
                out.append('<tr><td class="mono">%s</td><td class="num">%s</td><td>%s</td></tr>' % (
                    e(name), size_text(os.path.getsize(os.path.join(folder, name))),
                    ('<a href="%s/">entries</a> · <a href="%s">download</a>' % (link, link)) if DUMP.match(name)
                    else '<a href="%s">open</a>' % link))
            out.append("</table></div>")
            if "report.txt" in files:
                with open(os.path.join(folder, "report.txt"), encoding="utf-8", errors="replace") as report:
                    out.append("<h2>Comparison report</h2><pre>%s</pre>" % e(report.read(SHOW_BYTES)))
        else:
            out.append('<p class="muted">No dumps uploaded for this game.</p>')

        out.append("<h2>All attributes</h2>")
        for r in records:
            rows = "".join('<tr><td class="mono">%s</td><td class="mono">%s</td></tr>' % (
                e(k), e(v)) for k, v in sorted(r["attributes"].items()) if k != "faf.switches")
            res = "".join('<tr><td class="mono">%s</td><td class="mono">%s</td></tr>' % (
                e(k), e(v)) for k, v in sorted(r["resource"].items()))
            switches = "".join('<tr><td class="mono">%s</td><td class="mono">%s</td></tr>' % (e(k), e(v))
                               for k, v in sorted(switch_map(r["attributes"].get("faf.switches")).items()))
            out.append('<details><summary>%s · %s · army %s · <span class="mono">%s</span></summary><div>'
                       '<div class="wrap"><table><tr><th>record</th><th></th></tr>%s</table></div>'
                       '<h2>Resource</h2><div class="wrap"><table>%s</table></div>%s</div></details>' % (
                           when(r["time"]), e(r["kind"]), e(r["attributes"].get("faf.army.local", "?")),
                           e(r["id"]), rows, res,
                           '<h2>Switches</h2><div class="wrap"><table>%s</table></div>' % switches if switches else ""))
        self.page("Game %s" % game_id, "".join(out))

    def file(self, game_id, name, entry, listing, raw):
        folder = os.path.join(self.server.options.dumps, game_id)
        path = os.path.join(folder, name)
        if not GAME.match(game_id) or not (DUMP.match(name) or name == "report.txt") or not os.path.isfile(path):
            return self.reply(404, "not found")
        if name == "report.txt" or (not entry and not listing):
            with open(path, "rb") as data:
                body = data.read()
            if name == "report.txt":
                return self.send_body(200, body, "text/plain; charset=utf-8")
            return self.send_body(200, body, "application/gzip", attachment=name)
        try:
            with tarfile.open(path, mode="r:gz") as tar:
                if not entry:
                    back = "/game/%s" % urllib.parse.quote(game_id)
                    rows = "".join('<tr><td class="mono"><a href="%s">%s</a></td><td class="num">%s</td></tr>' % (
                        urllib.parse.quote(m.name), e(m.name), size_text(m.size))
                        for m in tar.getmembers() if m.isfile())
                    return self.page(name, '<h1 class="mono">%s</h1><p><a href="%s">game %s</a> · '
                                     '<a href="/files/%s/%s">download .tar.gz</a></p>'
                                     '<div class="wrap"><table><tr><th>entry</th><th>size</th></tr>%s</table></div>' % (
                                         e(name), back, e(game_id), urllib.parse.quote(game_id),
                                         urllib.parse.quote(name), rows))
                try:
                    member = tar.getmember(entry)
                except KeyError:
                    return self.reply(404, "no entry %s" % entry)
                if not member.isfile():
                    return self.reply(404, "no entry %s" % entry)
                data = tar.extractfile(member).read()
        except (tarfile.TarError, OSError, EOFError) as error:
            return self.reply(500, "can't read %s: %s" % (name, error))
        if raw:
            return self.send_body(200, data, "text/plain; charset=utf-8")
        text = data[:SHOW_BYTES].decode("utf-8", "replace")
        more = ('<p class="muted">Showing %s of %s. <a href="?raw=1">Whole entry as text</a>.</p>' % (
            size_text(SHOW_BYTES), size_text(len(data)))) if len(data) > SHOW_BYTES else ""
        self.page(entry, '<h1 class="mono">%s</h1><p><a href="/files/%s/%s/">%s</a> · <a href="?raw=1">raw</a></p>'
                  '%s<pre>%s</pre>' % (e(entry), urllib.parse.quote(game_id), urllib.parse.quote(name), e(name),
                                       more, e(text)))

    # ---- output

    def page(self, title, content, code=200, nav=True):
        links = ('<a href="/">records</a><a href="/games">games</a><a href="/api/records">json</a>'
                 '<a href="/logout">log out</a>') if nav and self.server.options.read_token else (
                 '<a href="/">records</a><a href="/games">games</a><a href="/api/records">json</a>' if nav else "")
        self.reply(code, '<!doctype html><html lang="en"><meta charset="utf-8">'
                   '<meta name="viewport" content="width=device-width, initial-scale=1">'
                   '<title>%s</title><style>%s</style><header><b>faf-re desyncs</b>%s</header><main>%s</main>' % (
                       e(title), STYLE, links, content), "text/html; charset=utf-8")

    def send_body(self, code, body, kind, attachment=None):
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        if attachment:
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % attachment)
        self.end_headers()
        self.wfile.write(body)

    def reply(self, code, text, kind="text/plain; charset=utf-8"):
        self.send_body(code, text.encode("utf-8"), kind)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4320)
    parser.add_argument("--otel", default="data/otel", help="the collector's file exporter folder")
    parser.add_argument("--dumps", default="data/dumps", help="the dump receiver's --out folder")
    parser.add_argument("--read-token", default=os.environ.get("FAF_READ_TOKEN", ""))
    options = parser.parse_args()
    server = http.server.ThreadingHTTPServer((options.host, options.port), Handler)
    server.options = options
    server.records = Records(options.otel)
    print("dashboard on http://%s:%d, records from %s, dumps from %s" % (
        options.host, options.port, os.path.abspath(options.otel), os.path.abspath(options.dumps)), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
