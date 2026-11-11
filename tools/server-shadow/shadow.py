#!/usr/bin/env python3
"""Shadow verifier (plan WP13.3): re-simulates a dedicated server's game live and checks its checksums as they come.

The server runs with `--checksum-events` (each checksummed beat's MD5 as a `checksum` event), `--observe` and a
referee token in its match file's `MatchReferees` (a referee watches with no delay), and `--rest` or a host's lobby
API. This script starts headless as that referee (`--replay gpgnet://<server>:<port>/<token>`), which plays the game
as it arrives and writes its own per-beat checksums, reads the server's from the event stream, and compares every beat
both have. Run it on a trusted machine of another platform (Windows) to catch a sim that differs on the server.

    python tools/server-shadow/shadow.py --api http://<server>:<rest port> --token-file admin.token \
        --watch "gpgnet://<server>:<observe port>/<referee token>" --headless <headless exe> --init <init_replay.lua>

With server-host, --api is the lobby's API through the host: http://<host>:27180/api/v1/lobbies/<id> and the host's token.

It reports to the server with the `verifier` op: `mismatch` at the first differing beat (the server prints
"VERIFIER ...: MISMATCH" and sends a `verifier` event, the admin's alert), `ok` every --report-every matched checksums,
and `stopped` if headless ends before the game does. Exit code: 0 no difference, 1 a mismatch, 2 stopped or nothing
compared.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


class Server:
    def __init__(self, api, token):
        self.api = api.rstrip("/")
        self.token = token
        self.checksums = {}  # beat -> md5, from `checksum` events
        self.ended = False
        self.lock = threading.Lock()
        self.connected = threading.Event()
        self.error = ""

    def request(self, method, path, body=None):
        req = urllib.request.Request(self.api + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as answer:
            return json.loads(answer.read() or b"{}")

    def report(self, name, verdict, beat, reason):
        with self.lock:
            if self.ended:
                return  # the game ended: nobody to report to
        try:
            self.request("POST", "/api/v1/ops/verifier", {"name": name, "results": verdict, "count": beat, "reason": reason})
            print(f"shadow: reported {verdict} at beat {beat}: {reason}", flush=True)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"shadow: couldn't report {verdict} to the server: {e}", flush=True)

    def follow(self):
        """Reads the event stream (Server-Sent Events) until the game ends or the stream closes."""
        req = urllib.request.Request(self.api + "/api/v1/events", headers={"Authorization": "Bearer " + self.token})
        try:
            with urllib.request.urlopen(req, timeout=60) as stream:
                self.connected.set()
                name = ""
                for raw in stream:
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if line.startswith("event:"):
                        name = line[6:].strip()
                    elif line.startswith("data:") and name in ("checksum", "game_ended"):
                        data = json.loads(line[5:])
                        with self.lock:
                            if name == "checksum":
                                self.checksums[int(data["beat"])] = data["md5"]
                            else:
                                self.ended = True
                    elif not line:
                        name = ""
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.error = str(e)
        finally:
            self.connected.set()
            with self.lock:
                self.ended = True


def read_new(path, offset, into):
    """`beat md5` lines appended to headless's --digests file since offset; returns the new offset (whole lines only)."""
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read()
    except OSError:
        return offset
    end = data.rfind(b"\n") + 1
    for line in data[:end].decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].lstrip("-").isdigit():
            into[int(parts[0])] = parts[1]
    return offset + end


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", required=True, help="the server's REST API (http://host:port), or a host lobby's (.../api/v1/lobbies/<id>)")
    parser.add_argument("--token-file", required=True, help="the API's admin token")
    parser.add_argument("--watch", required=True, help="gpgnet://<server>:<observe port>/<referee token> (a '/replay ' in front is dropped)")
    parser.add_argument("--headless", required=True, help="the headless build to re-simulate with")
    parser.add_argument("--init", required=True, help="init file for headless (/init)")
    parser.add_argument("--name", default=socket.gethostname(),
                        help="this verifier's name in the server's log and events")
    parser.add_argument("--work", default="shadow", help="folder for headless's digests and log (default ./shadow)")
    parser.add_argument("--report-every", type=int, default=20, help="report ok after this many matched checksums (default 20)")
    parser.add_argument("--args", default="", help="more headless arguments, one string")
    options = parser.parse_args()

    with open(options.token_file, encoding="utf-8") as handle:
        token = handle.read().strip()
    watch = options.watch.split(" ", 1)[1] if options.watch.startswith("/replay ") else options.watch
    os.makedirs(options.work, exist_ok=True)
    digests = os.path.join(options.work, "shadow-digests.txt")
    log = os.path.join(options.work, "headless.log")
    if os.path.exists(digests):
        os.remove(digests)

    server = Server(options.api, token)
    threading.Thread(target=server.follow, daemon=True).start()
    server.connected.wait(15)
    if server.error:
        print(f"shadow: the server's event stream: {server.error}", flush=True)
        return 2

    command = [options.headless, "--label", "shadow", "--replay", watch, "--digests", digests, "/init", options.init,
               "/nobugreport", "/nosound"] + options.args.split()
    with open(log, "w") as out:
        headless = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT)
    print(f"shadow: {options.name} re-simulating {watch.rsplit('/', 1)[0]}/... with {options.headless}", flush=True)

    mine, offset, compared, since_report, last_beat = {}, 0, set(), 0, 0
    mismatch = None
    while True:
        running = headless.poll() is None
        offset = read_new(digests, offset, mine)
        with server.lock:
            theirs = dict(server.checksums)
            ended = server.ended
        for beat in sorted(set(mine) & set(theirs) - compared):
            compared.add(beat)
            last_beat = beat
            if mine[beat] != theirs[beat] and mismatch is None:
                mismatch = beat
                reason = f"server {theirs[beat]}, here {mine[beat]}"
                print(f"shadow: MISMATCH at beat {beat}: {reason}", flush=True)
                server.report(options.name, "mismatch", beat, reason)
            elif mine[beat] == theirs[beat]:
                since_report += 1
                if since_report >= options.report_every and mismatch is None:
                    since_report = 0
                    server.report(options.name, "ok", beat, f"{len(compared)} checksums equal")
        if not running:
            offset = read_new(digests, offset, mine)
            break
        time.sleep(0.5)

    time.sleep(2)  # the last checksum events
    with server.lock:
        theirs = dict(server.checksums)
    for beat in sorted(set(mine) & set(theirs) - compared):
        compared.add(beat)
        last_beat = beat
        if mine[beat] != theirs[beat] and mismatch is None:
            mismatch = beat
            server.report(options.name, "mismatch", beat, f"server {theirs[beat]}, here {mine[beat]}")
    differ = sum(1 for b in compared if mine[b] != theirs[b])
    print(f"shadow: headless exit {headless.returncode}; {len(compared)} checksums compared, {differ} differ"
          f"{f', first at beat {mismatch}' if mismatch is not None else ''}; server sent {len(theirs)}, headless wrote {len(mine)}", flush=True)
    if mismatch is not None:
        return 1
    with server.lock:
        server_gone = server.ended  # the game ended (or its server did): nobody to report to
    if headless.returncode != 0 or not compared:
        if not server_gone:
            server.report(options.name, "stopped", last_beat, f"headless exit {headless.returncode}, {len(compared)} checksums compared")
        return 2
    if not server_gone:
        server.report(options.name, "ok", last_beat, f"{len(compared)} checksums equal, the whole game")
    return 0


if __name__ == "__main__":
    sys.exit(main())
