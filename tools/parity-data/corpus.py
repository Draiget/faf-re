"""The replay corpus of a game version, from the FAF API: which vault replays CI plays.

usage: corpus.py <command> [options]    (see README.md next to this file)

  login                      sign in to the FAF API (device code: prints a link and a code to
                             confirm in any browser); tokens go to --token (default
                             tmp/claude/faf_api_token.json, outside git)
  export --first ID --last ID --out DIR
                             every faf-mod game in the id range with a replay and at least 5
                             minutes of game: DIR/games.jsonl, DIR/maps.json (map versions)
  build --export DIR --retail-maps DIR --top-maps N --out FILE
                             the corpus file (corpus/<version>.tsv.gz): 2+ player games on a
                             map that can be had (generated maps cannot), the core and
                             extended sets, and whether each map is retail, cached (one of
                             the N most played vault maps) or downloaded when played

The API needs a signed-in user. It is asked one page (100 games) at a time, a second apart.
Login, client id and scopes are the FAF client's (downlords-faf-client: application-prod.yml,
api/TokenRetriever.java), as the API has no client of its own for this project.
"""
import argparse
import collections
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from common import CORE_SET, CORPUS_COLUMNS, EXTENDED_SET, USER_AGENT

CLIENT_ID = "2e8808cf-5889-469b-b2c3-01f0cc58c4af"
SCOPES = "openid offline public_profile"
HYDRA = "https://hydra.faforever.com"
API = "https://api.faforever.com/data/"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_TOKEN = os.path.join(REPO, "tmp", "claude", "faf_api_token.json")
MIN_TICKS = 3000  # 5 minutes of game at 10 beats per second


def hydra_post(path, fields):
    req = urllib.request.Request(HYDRA + path, data=urllib.parse.urlencode(fields).encode(),
                                 headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, {"error": body[:200].decode("utf-8", "replace")}


def save_tokens(path, tokens):
    tokens["expires_at"] = int(time.time()) + int(tokens.get("expires_in", 0))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tokens, f)


def cmd_login(args):
    status, device = hydra_post("/oauth2/device/auth", {"client_id": CLIENT_ID, "scope": SCOPES})
    if status != 200:
        sys.exit("device authorization failed: %s %s" % (status, device))
    print("Open this link, sign in and confirm the code:\n  %s\ncode: %s\n(waiting up to %d s)"
          % (device.get("verification_uri_complete") or device["verification_uri"], device["user_code"],
             device["expires_in"]), flush=True)
    interval = int(device.get("interval", 5))
    deadline = time.time() + int(device["expires_in"])
    fields = {"device_code": device["device_code"], "client_id": CLIENT_ID,
              "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}
    while time.time() < deadline:
        time.sleep(interval)
        status, tokens = hydra_post("/oauth2/token", fields)
        if status == 200:
            save_tokens(args.token, tokens)
            print("tokens written to %s" % args.token)
            return 0
        error = tokens.get("error")
        if error == "slow_down":
            interval += 5
        elif error != "authorization_pending":
            sys.exit("sign-in failed: %s" % error)
    sys.exit("the code expired before it was confirmed")


class Api:
    def __init__(self, token_path):
        self.token_path = token_path
        self.requests = 0

    def refresh(self):
        with open(self.token_path, encoding="utf-8") as f:
            tokens = json.load(f)
        status, fresh = hydra_post("/oauth2/token", {"grant_type": "refresh_token", "client_id": CLIENT_ID,
                                                     "refresh_token": tokens["refresh_token"]})
        if status != 200:
            sys.exit("token refresh failed: %s; run `corpus.py login` again" % fresh.get("error"))
        save_tokens(self.token_path, fresh)

    def get(self, path, params):
        url = API + path + "?" + urllib.parse.urlencode(params, safe="=;,()*")
        for attempt in range(2):
            with open(self.token_path, encoding="utf-8") as f:
                token = json.load(f)["access_token"]
            req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "User-Agent": USER_AGENT,
                                                       "Accept": "application/vnd.api+json"})
            try:
                self.requests += 1
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = json.load(r)
                time.sleep(1.0)
                return data
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self.refresh()
                    continue
                sys.exit("%s -> HTTP %d %s" % (url, exc.code, exc.read()[:300]))


def cmd_export(args):
    api = Api(args.token)
    os.makedirs(args.out, exist_ok=True)
    games = []
    number = 1
    while True:
        data = api.get("game", {
            "filter": "id=ge=%d;id=le=%d;featuredMod.technicalName==faf;replayAvailable==true;replayTicks=ge=%d"
                      % (args.first, args.last, MIN_TICKS),
            "fields[game]": "replayTicks,validity,mapVersion,playerStats",
            "sort": "id", "page[size]": 100, "page[number]": number, "page[totals]": "",
        })
        for g in data["data"]:
            rel = g.get("relationships", {})
            mv = (rel.get("mapVersion") or {}).get("data")
            games.append({"id": int(g["id"]), "ticks": g["attributes"]["replayTicks"],
                          "validity": g["attributes"]["validity"],
                          "players": len((rel.get("playerStats") or {}).get("data") or []),
                          "mapVersion": int(mv["id"]) if mv else None})
        pages = data["meta"]["page"]["totalPages"]
        if number % 50 == 0 or number >= pages:
            print("games page %d/%d (%d games)" % (number, pages, len(games)), flush=True)
        if number >= pages:
            break
        number += 1
    with open(os.path.join(args.out, "games.jsonl"), "w", encoding="utf-8") as f:
        for g in games:
            f.write(json.dumps(g) + "\n")

    ids = sorted({g["mapVersion"] for g in games if g["mapVersion"] is not None})
    maps = {}
    for i in range(0, len(ids), 100):  # the API's page limit
        batch = ids[i:i + 100]
        data = api.get("mapVersion", {"filter": "id=in=(%s)" % ",".join(map(str, batch)),
                                      "fields[mapVersion]": "folderName,downloadUrl", "page[size]": len(batch)})
        for mv in data["data"]:
            maps[mv["id"]] = mv["attributes"]
    with open(os.path.join(args.out, "maps.json"), "w", encoding="utf-8") as f:
        json.dump(maps, f, indent=1)
    print("%d games, %d map versions, %d requests" % (len(games), len(maps), api.requests))
    return 0


def cmd_build(args):
    with open(os.path.join(args.export, "games.jsonl"), encoding="utf-8") as f:
        games = [json.loads(line) for line in f]
    with open(os.path.join(args.export, "maps.json"), encoding="utf-8") as f:
        maps = json.load(f)
    retail = {n.lower() for n in os.listdir(args.retail_maps)}
    named = set(CORE_SET) | set(EXTENDED_SET)

    def folder(g):
        mv = maps.get(str(g["mapVersion"])) if g["mapVersion"] is not None else None
        return mv["folderName"].lower() if mv else None

    rows = []
    for g in games:
        f = folder(g)
        if f is None or f.startswith("neroxis_map_generator"):
            continue  # generated maps are not on the content server
        if g["players"] >= 2 or g["id"] in named:
            rows.append((g, f))
    plays = collections.Counter(f for g, f in rows if f not in retail)
    top = {f for f, _ in plays.most_common(args.top_maps)}
    kinds = collections.Counter()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with gzip.open(args.out, "wt", encoding="utf-8", newline="\n") as out:
        out.write("# %s\n" % "\t".join(CORPUS_COLUMNS))
        for g, f in sorted(rows, key=lambda r: r[0]["id"]):
            kind = "retail" if f in retail else "cached" if f in top else "download"
            kinds[kind] += 1
            out.write("%d\t%d\t%d\t%s\t%s\n" % (g["id"], g["ticks"], g["players"], f, kind))
    missing = sorted(named - {g["id"] for g, _ in rows})
    print("%d replays: %s; %d cached maps; core/extended not in the export: %s"
          % (len(rows), dict(kinds), len(top), missing or "none"))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("login")
    p.add_argument("--token", default=DEFAULT_TOKEN)
    p = sub.add_parser("export")
    p.add_argument("--token", default=DEFAULT_TOKEN)
    p.add_argument("--first", type=int, required=True, help="first vault id of the game version")
    p.add_argument("--last", type=int, required=True, help="last vault id of the game version")
    p.add_argument("--out", required=True)
    p = sub.add_parser("build")
    p.add_argument("--export", required=True, help="folder `export` wrote")
    p.add_argument("--retail-maps", required=True, help="the game's maps folder (the pack's fa/maps)")
    p.add_argument("--top-maps", type=int, default=500)
    p.add_argument("--out", required=True)
    args = parser.parse_args()
    return {"login": cmd_login, "export": cmd_export, "build": cmd_build}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
