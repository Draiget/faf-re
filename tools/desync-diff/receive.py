"""Receives the desync dumps the engine uploads (telemetry_DumpEndpoint) and keeps them per game.

usage: receive.py [--host 127.0.0.1] [--port 4319] [--out DIR] [--token T] [--max-mb 64]

Each upload is one POST whose body is a .tar.gz and whose X-FAF-Dump header names it
(desync_<game id>_<beat tag>_army<A>.tar.gz). It is checked as a dump (header.json in the
archive), stored as <out>/<game id>/<name>, and answered 201. Once a game has dumps from two
armies, desync_diff.py compares them and the report goes to <out>/<game id>/report.txt.
A reference and test server: one thread, no TLS. Python 3 with the standard library only.
"""

import argparse
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tarfile

NAME = re.compile(r"^desync_([A-Za-z0-9_.-]+?)_(beat\d+|at\d+)_army(-?\d+)\.tar\.gz$")
HERE = os.path.dirname(os.path.abspath(__file__))


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
    with open(report, "w", encoding="utf-8") as out:
        out.write(result.stdout)
        out.write(result.stderr)
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
        with open(os.path.join(folder, name), "wb") as out:
            out.write(data)
        print("stored %s (%d bytes, build %s, local army %s)" % (
            os.path.join(folder, name), len(data), header.get("build", {}).get("commit"), header.get("local_army")),
            flush=True)
        compared = compare(folder)
        if compared:
            print("compared %s: desync_diff exit %d" % (compared[0], compared[1]), flush=True)
        self.reply(201, json.dumps({"stored": name}))

    def reply(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if code == 201 else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if code != 201:
            print("refused %d: %s" % (code, text), flush=True)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4319)
    parser.add_argument("--out", default="received-dumps")
    parser.add_argument("--token", default="")
    parser.add_argument("--max-mb", type=int, default=64)
    options = parser.parse_args()
    server = http.server.HTTPServer((options.host, options.port), Handler)
    server.options = options
    print("receiving dumps on http://%s:%d, storing under %s" % (options.host, options.port, os.path.abspath(options.out)),
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
