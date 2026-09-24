"""Find big FAF team games recorded on a given game version, reading only replay headers.

usage: vault_scan.py <version> <lo_id> <hi_id> <out.jsonl>
Phase 1 bisects the id range down to where <version> was current; phase 2 samples that range.
"""
import json
import sys
import time
import urllib.request

UA = {"User-Agent": "faf-perf-research/1.0", "Range": "bytes=0-4095"}


def header(game_id):
    req = urllib.request.Request("https://replay.faforever.com/%d" % game_id, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            blob = resp.read()
            total = resp.headers.get("Content-Range", "").rsplit("/", 1)[-1]
    except Exception as exc:  # 404 for missing ids, timeouts
        return None
    try:
        line = blob[:blob.index(b"\n")]
        hdr = json.loads(line)
    except Exception:
        return None
    versions = [v for v in (hdr.get("featured_mod_versions") or {}).values() if isinstance(v, int)]
    return {
        "id": game_id,
        "size": int(total) if total.isdigit() else None,
        "version": max(versions) if versions else None,
        "mod": hdr.get("featured_mod"),
        "players": hdr.get("num_players"),
        "map": hdr.get("mapname"),
        "minutes": round(((hdr.get("game_end") or 0) - (hdr.get("launched_at") or 0)) / 60.0, 1),
        "title": (hdr.get("title") or "")[:40],
    }


def probe(game_id, spread=40):
    """First readable faf header at or after game_id."""
    for k in range(spread):
        h = header(game_id + k)
        time.sleep(0.15)
        if h and h["mod"] == "faf" and h["version"]:
            return h
    return None


def main():
    version = int(sys.argv[1])
    lo, hi = int(sys.argv[2]), int(sys.argv[3])
    out = open(sys.argv[4], "a")
    # phase 1: coarse samples to find where `version` is the current one
    samples = []
    steps = 24
    for i in range(steps + 1):
        gid = lo + (hi - lo) * i // steps
        h = probe(gid)
        if h:
            samples.append(h)
            out.write(json.dumps({"phase": 1, **h}) + "\n")
            out.flush()
    ids = [s["id"] for s in samples if s["version"] == version]
    if not ids:
        print("no ids at version", version, flush=True)
        return
    a, b = min(ids), max(ids)
    print("version %d seen from %d to %d" % (version, a, b), flush=True)
    # phase 2: sample the range for big team games
    count = 0
    stride = max(1, (b - a) // 400)
    gid = a
    while gid <= b and count < 400:
        h = header(gid)
        time.sleep(0.12)
        gid += stride
        if not h:
            continue
        count += 1
        if h["mod"] == "faf" and h["version"] == version and (h["players"] or 0) >= 8 and h["minutes"] >= 30:
            out.write(json.dumps({"phase": 2, **h}) + "\n")
            out.flush()
    print("done, sampled", count, flush=True)


if __name__ == "__main__":
    main()
