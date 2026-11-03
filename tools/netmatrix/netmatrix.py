#!/usr/bin/env python3
"""Compatibility matrix for the network layers (issue #242).

Every pair of player kinds plays an autolobby game under each profile, through
mpemu. Writes one scenario per cell, runs them one after another, and prints a
Markdown table: verdict, the beat both games reached, the longest wait the
games reported, and any disconnect.

Kinds (both players of a cell take one each):
  native   our build, /nativenet: no adapter, the game links itself (#274)
  inengine our build behind faf-netbridge, /inenginelinks (#233)
  bridge   our build behind faf-netbridge, which relays its datagrams (#230)
  retail   the retail game behind faf-netbridge
  jar      the retail game behind FAF's faf-ice-adapter.jar (--jar-dir); with
           --bind, mpemu stands between the two (tools/seat/jarbridge.go), as
           the jar always sends to 127.0.0.1, which a host that drops loopback
           UDP to sockets bound to every interface cannot deliver

Profiles:
  direct   no impairment, host candidates
  relay    relayed candidates only, through mpemu's TURN server, 25 ms each way
  worst    relayed only, 150 ms each way + up to 50 ms jitter, 5 % loss, and
           one 2 s partition
Impairments are applied where every link sends (contract `shaping: links`,
FAF_NETLINK_TEST_SHAPING in src/netlink/Link.cpp), so they hold on whichever
path ICE picks. Shaping them in mpemu's TURN server instead missed some cells:
with both players on one machine, ICE may settle on a host-to-host path that
never reaches the TURN server, even with relayed candidates only.

Example (from tools/, after `go build -o mpemu.exe ./cmd/mpemu`):
  python netmatrix/netmatrix.py --mpemu mpemu.exe --out ../tmp/matrix \\
      --ours %ProgramData%/FAForever/bin_x64/main_x64.exe \\
      --retail %ProgramData%/FAForever/bin/ForgedAlliance.exe \\
      --bridge path/to/faf-netbridge.exe --bind 192.168.42.77
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

KINDS = ["native", "inengine", "bridge", "retail", "jar"]
PROFILES = {
    "direct": {"forceRelay": False, "play": "7m", "steps": []},
    "relay": {"forceRelay": True, "play": "7m", "steps": ["  - link: { from: 1, to: 2, latency: 25ms }"]},
    "worst": {
        "forceRelay": True,
        "play": "8m",  # the game runs at about 0.7x here; the 90 s step below adds to it
        "steps": [
            "  - link: { from: 1, to: 2, latency: 150ms, jitter: 50ms, loss: 0.05 }",
            "  - wait: 90s",
            "  - link: { from: 1, to: 2, blocked: true }",
            "  - note: 2 s partition",
            "  - wait: 2s",
            "  - link: { from: 1, to: 2, latency: 150ms, jitter: 50ms, loss: 0.05 }",
        ],
    },
}
DISCONNECT = re.compile(r"LOBBY: (lost connection to|host disconnected|we've been ejected)")
GAME_TIME = re.compile(r"Game time: (\d+):(\d+):(\d+)")


def yaml_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def player(uid: int, name: str, kind: str, args: argparse.Namespace) -> str:
    exe = args.retail if kind in ("retail", "jar") else args.ours
    adapter = {"native": "native", "jar": "jar"}.get(kind, args.bridge)
    extra = ["/inenginelinks"] if kind == "inengine" else []
    fields = [f"uid: {uid}", f"name: {name}", f"exe: {yaml_str(exe)}", f"adapter: {yaml_str(adapter)}"]
    if extra:
        fields.append("args: [" + ", ".join(yaml_str(a) for a in extra) + "]")
    return "  - { " + ", ".join(fields) + " }"


def scenario(a: str, b: str, profile: str, args: argparse.Namespace) -> str:
    p = PROFILES[profile]
    bind = args.bind
    exe_args = f"[--bind-address, {yaml_str(bind)}, --game-address, {yaml_str(bind)}]" if bind else "[]"
    lines = [
        f"name: matrix-{a}-{b}-{profile}",
        "description: >",
        f"  Issue #242 matrix cell: {a} against {b}, profile {profile}.",
        f"timeout: {args.timeout}",
        "",
        "mode: contract",
        "lobby: auto",
        "map: SCMP_009",
        "",
        "contract:",
        f"  exeArgs: {exe_args}",
        f"  forceRelay: {'true' if p['forceRelay'] else 'false'}",
        "  shaping: links",
    ]
    if bind:
        lines.append(f"  nativeBind: {yaml_str(bind)}")
        lines.append(f"  jarBind: {yaml_str(bind)}")
    if args.jar_dir:
        lines.append(f"  nativeDir: {yaml_str(args.jar_dir)}")
    lines += [
        "",
        "game:",
        f"  exe: {yaml_str(args.ours)}",
        "  nosound: true",
        "  tile: true",
        "",
        "players:",
        player(1, "Alpha", a, args),
        player(2, "Bravo", b, args),
        "",
        "steps:",
        "  - start: all",
        "  - host: 1",
        "  - join: others",
        "  - waitState: { uids: all, state: Launching, timeout: 5m }",
        *p["steps"],
        f"  - wait: {args.play or p['play']}",
        "",
        "expect:",
        "  allLaunched: true",
        "  noDesync: true",
        "  noCrash: true",
        "",
    ]
    return "\n".join(lines)


def last_beat(log: Path) -> int:
    beat = 0
    try:
        for m in GAME_TIME.finditer(log.read_text(encoding="utf-8", errors="replace")):
            h, mi, s = (int(x) for x in m.groups())
            beat = (h * 3600 + mi * 60 + s) * 10
    except OSError:
        pass
    return beat


def run_cell(a: str, b: str, profile: str, args: argparse.Namespace) -> dict:
    name = f"matrix-{a}-{b}-{profile}"
    scen = args.out / "scen" / f"{name}.yaml"
    scen.parent.mkdir(parents=True, exist_ok=True)
    scen.write_text(scenario(a, b, profile, args), encoding="utf-8", newline="\n")
    cmd = [str(args.mpemu), "run", str(scen), *args.mpemu_args]
    if args.slot:
        cmd = [sys.executable, args.slot, "slot", "run", "--cores", "6", "--label", f"netmatrix {name}", "--", *cmd]
    started = time.time()
    proc = subprocess.run(cmd, cwd=args.out, capture_output=True, text=True, errors="replace")
    out = proc.stdout + proc.stderr
    (args.out / f"{name}.log").write_text(out, encoding="utf-8")
    m = re.search(r"journal: (.+journal\.jsonl)", out)
    run_dir = Path(m.group(1)).parent if m else None
    beats, disconnects, waits = [], 0, 0.0
    if run_dir:
        for uid in (1, 2):
            log = run_dir / f"game-{uid}.log"
            beats.append(last_beat(log))
            try:
                disconnects += len(DISCONNECT.findall(log.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass
        try:
            for line in (run_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines():
                rec = json.loads(line)
                if rec.get("cmd") == "Bottleneck" and len(rec.get("args", [])) >= 4:
                    waits = max(waits, float(rec["args"][3]) / 1000.0)
        except (OSError, ValueError):
            pass
    verdict = "PASS" if "PASS in" in out else "FAIL"
    beat = min(beats) if beats else 0
    return {
        "a": a, "b": b, "profile": profile, "verdict": verdict, "beat": beat,
        "disconnects": disconnects, "maxWaitS": round(waits, 1), "minutes": round((time.time() - started) / 60, 1),
        "ok": verdict == "PASS" and beat >= args.beats and disconnects == 0, "runDir": str(run_dir) if run_dir else "",
    }


def table(results: list[dict], beats: int) -> str:
    rows = [
        "| Players | Profile | mpemu | Beat reached | Longest reported wait | Disconnects | Cell |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        wait = f"{r['maxWaitS']} s" if r["maxWaitS"] else "none over 5 s"
        cell = "ok" if r["ok"] else f"**fails** (needs beat {beats})" if r["beat"] < beats else "**fails**"
        rows.append(f"| {r['a']} / {r['b']} | {r['profile']} | {r['verdict']} | {r['beat']} | {wait} | {r['disconnects']} | {cell} |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mpemu", required=True, type=Path)
    ap.add_argument("--ours", required=True, help="our game exe")
    ap.add_argument("--retail", required=True, help="the retail game exe")
    ap.add_argument("--bridge", required=True, help="faf-netbridge.exe")
    ap.add_argument("--jar-dir", default="", help="a folder with a copy of faf-ice-adapter.jar, for kind jar")
    ap.add_argument("--bind", default="", help="this machine's LAN address, for hosts that drop loopback UDP")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--kinds", default=",".join(KINDS))
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--play", default="", help="play time after launch, for every profile (default: the profile's own)")
    ap.add_argument("--timeout", default="20m")
    ap.add_argument("--beats", type=int, default=3000, help="a cell passes once both games reach this beat")
    ap.add_argument("--slot", default="", help="path to harness.py: run each cell inside `harness slot run`")
    ap.add_argument("--mpemu-args", nargs=argparse.REMAINDER, default=[], help="passed to `mpemu run` (e.g. -advertise A -turn-ip A)")
    args = ap.parse_args()
    args.ours = os.path.expandvars(args.ours)
    args.retail = os.path.expandvars(args.retail)
    args.out.mkdir(parents=True, exist_ok=True)
    args.out = args.out.resolve()
    args.mpemu = args.mpemu.resolve()
    if args.slot:
        args.slot = str(Path(args.slot).resolve())

    kinds = [k for k in args.kinds.split(",") if k]
    profiles = [p for p in args.profiles.split(",") if p]
    results = []
    for profile in profiles:
        for a, b in itertools.combinations_with_replacement(kinds, 2):
            r = run_cell(a, b, profile, args)
            results.append(r)
            print(json.dumps(r), flush=True)
            (args.out / "results.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    md = table(results, args.beats)
    (args.out / "results.md").write_text(md + "\n", encoding="utf-8")
    print(md)
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
