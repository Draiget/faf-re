"""Receives the desync dumps the engine uploads (telemetry_DumpEndpoint), keeps them per game and serves them back.

usage: receive.py [--host 127.0.0.1] [--port 4319] [--prefix /dumps] [--out DIR] [--token T] [--read-token R]
                  [--max-mb 64]

Each upload is one POST whose body is a .tar.gz and whose X-FAF-Dump header names it
(desync_<game id>_<beat tag>_army<A>.tar.gz). It is checked as a dump (header.json in the
archive), stored as <out>/<game id>/<name>, and answered 201. Once a game has dumps from two
armies, desync_diff.py compares them and the report goes to <out>/<game id>/report.txt.

Reading: GET <prefix>/ lists the games, <prefix>/<game id>/ a game's files, and
<prefix>/<game id>/<file> downloads one (a dump or report.txt). With --read-token set, a read
needs "Authorization: Bearer <read token>" or "?token=<read token>"; the upload token (which
ships with the game) never reads. GET /healthz answers "ok" without a token.

--token and --read-token default to the FAF_UPLOAD_TOKEN and FAF_READ_TOKEN environment
variables. Plain HTTP: put TLS in front (tools/desync-server). Python 3, standard library only.
"""

import argparse
import html
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import urllib.parse

NAME = re.compile(r"^desync_([A-Za-z0-9_.-]+?)_(beat\d+|at\d+)_army(-?\d+)\.tar\.gz$")
GAME = re.compile(r"^[A-Za-z0-9_.-]+$")
HERE = os.path.dirname(os.path.abspath(__file__))
COMPARE_LOCK = threading.Lock()


def check_dump(data):
    """The archive's header.json, or raises ValueError when the body is not a dump."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            member = tar.getmember("header.json")
            header = json.loads(tar.extractfile(member).read())
    except (tarfile.TarError, KeyError, EOFError, OSError, ValueError) as error:
        raise ValueError("not a desync dump: %s" % error)
    if header.get("format") != 1:
        raise ValueError("unknown dump format %r" % header.get("format"))
    return header


def compare(folder):
    dumps = sorted(os.path.join(folder, n) for n in os.listdir(folder) if NAME.match(n))
    if len({NAME.match(os.path.basename(d)).group(3) for d in dumps}) < 2:
        return None
    result = subprocess.run([sys.executable, os.path.join(HERE, "desync_diff.py")] + dumps,
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    report = os.path.join(folder, "report.txt")
    with open(report + ".tmp", "w", encoding="utf-8") as out:
        out.write(result.stdout)
        out.write(result.stderr)
    os.replace(report + ".tmp", report)
    return report, result.returncode


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        options = self.server.options
        if options.token and self.headers.get("Authorization") != "Bearer " + options.token:
            return self.reply(401, "bad token")
        name = self.headers.get("X-FAF-Dump", "")
        match = NAME.match(name)
        if not match:
            return self.reply(400, "X-FAF-Dump is not a dump name: %r" % name)
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > options.max_mb * 1024 * 1024:
            return self.reply(413, "body of %d bytes" % length)
        data = self.rfile.read(length)
        try:
            header = check_dump(data)
        except ValueError as error:
            return self.reply(400, str(error))
        folder = os.path.join(options.out, match.group(1))
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name)
        with open(path + ".tmp", "wb") as out:
            out.write(data)
        os.replace(path + ".tmp", path)
        print("stored %s (%d bytes, build %s, local army %s)" % (
            path, len(data), header.get("build", {}).get("commit"), header.get("local_army")), flush=True)
        with COMPARE_LOCK:
            compared = compare(folder)
        if compared:
            print("compared %s: desync_diff exit %d" % (compared[0], compared[1]), flush=True)
        self.reply(201, json.dumps({"stored": name, "url": "%s/%s/%s" % (options.prefix, match.group(1), name)}),
                   "application/json")

    def do_GET(self):
        options = self.server.options
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/healthz":
            return self.reply(200, "ok")
        query = urllib.parse.parse_qs(url.query)
        token = (query.get("token") or [""])[0]
        if options.read_token and self.headers.get("Authorization") != "Bearer " + options.read_token \
                and token != options.read_token:
            return self.reply(401, "bad read token")
        prefix = options.prefix.rstrip("/")
        if not (url.path == prefix or url.path.startswith(prefix + "/")):
            return self.reply(404, "not found")
        parts = [p for p in url.path[len(prefix):].split("/") if p]
        suffix = "?token=" + urllib.parse.quote(token) if token else ""
        if not parts:
            games = sorted((g for g in os.listdir(options.out) if GAME.match(g)), reverse=True) \
                if os.path.isdir(options.out) else []
            rows = []
            for game in games:
                files = os.listdir(os.path.join(options.out, game))
                dumps = sum(1 for f in files if NAME.match(f))
                report = "report.txt" in files
                rows.append('<li><a href="%s/%s/%s">%s</a>: %d dump(s)%s</li>' % (
                    prefix, game, suffix, html.escape(game), dumps,
                    ', <a href="%s/%s/report.txt%s">report</a>' % (prefix, game, suffix) if report else ""))
            return self.page("Desync dumps", "<ul>%s</ul>" % "".join(rows) if rows else "<p>No dumps yet.</p>")
        game = parts[0]
        folder = os.path.join(options.out, game)
        if not GAME.match(game) or not os.path.isdir(folder) or len(parts) > 2:
            return self.reply(404, "not found")
        if len(parts) == 1:
            files = sorted(f for f in os.listdir(folder) if NAME.match(f) or f == "report.txt")
            rows = "".join('<li><a href="%s/%s/%s%s">%s</a> (%d bytes)</li>' % (
                prefix, game, f, suffix, html.escape(f), os.path.getsize(os.path.join(folder, f))) for f in files)
            return self.page("Game %s" % game, "<ul>%s</ul>" % rows)
        name = parts[1]
        if not (NAME.match(name) or name == "report.txt") or not os.path.isfile(os.path.join(folder, name)):
            return self.reply(404, "not found")
        with open(os.path.join(folder, name), "rb") as data:
            body = data.read()
        kind = "text/plain; charset=utf-8" if name == "report.txt" else "application/gzip"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        if name != "report.txt":
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
        self.end_headers()
        self.wfile.write(body)

    def page(self, title, content):
        self.reply(200, "<!doctype html><meta charset=utf-8><title>%s</title><h1>%s</h1>%s" % (
            html.escape(title), html.escape(title), content), "text/html; charset=utf-8")

    def reply(self, code, text, kind="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if code >= 400:
            print("refused %d: %s" % (code, text), flush=True)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4319)
    parser.add_argument("--prefix", default="/dumps", help="path the dumps are read under (default /dumps)")
    parser.add_argument("--out", default="received-dumps")
    parser.add_argument("--token", default=os.environ.get("FAF_UPLOAD_TOKEN", ""))
    parser.add_argument("--read-token", default=os.environ.get("FAF_READ_TOKEN", ""))
    parser.add_argument("--max-mb", type=int, default=64)
    options = parser.parse_args()
    options.prefix = "/" + options.prefix.strip("/")
    server = http.server.ThreadingHTTPServer((options.host, options.port), Handler)
    server.options = options
    print("receiving dumps on http://%s:%d%s, storing under %s" % (
        options.host, options.port, options.prefix, os.path.abspath(options.out)), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
