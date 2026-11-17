#!/usr/bin/env python3
"""Runs faf_netbench over network profiles and engine configurations; appends one JSON line per run.

Example (from the repository root, after building faf_netbench):
  python tools/netbench/run.py --bench build/clang-x64-release/tests/faf_netbench.exe --out tmp/netbench/before.jsonl \
      --configs retail,lane --seeds 3 --jobs 4

A run already in the output file (same profile, configuration and seed) is skipped, so an interrupted batch resumes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path

# Network profiles. Latency is one way (round trip = 2 x latency); jitter is +- uniform per datagram; loss is the long-run
# share of datagrams lost, in runs of `burst` datagrams on average; bandwidth is the uplink in kbit/s (0 = unlimited);
# partition is "<start s>:<length s>" with no datagram getting through either way.
PROFILES: dict[str, dict] = {
    "lan": {"latency": 1, "jitter": 0.5},
    "good": {"latency": 20, "jitter": 3, "loss": 0.001},
    "typical": {"latency": 40, "jitter": 10, "loss": 0.005},
    "wifi": {"latency": 30, "jitter": 25, "loss": 0.02, "burst": 3},
    "bad": {"latency": 80, "jitter": 30, "loss": 0.03, "burst": 2},
    "worst": {"latency": 150, "jitter": 50, "loss": 0.05},
    "order-burst": {"latency": 40, "jitter": 10, "loss": 0.005, "burstat": 20, "burstbytes": 44891},
    "slow-uplink": {"latency": 40, "jitter": 10, "loss": 0.005, "bandwidth": 256, "burstat": 20, "burstbytes": 44891},
    "outage": {"latency": 40, "jitter": 10, "loss": 0.005, "partition": "30:3"},
}

# Engine configurations: the carrier and the console variables each one sets.
# The shipped game's values, set explicitly: the engine's defaults are the tuned ones now.
SHIPPED = {"net_FastRetransmit": 0, "net_MaxSendRate": 2048, "net_MaxBacklog": 2048}
FAST = {"net_FastRetransmit": 1}
RATE = {"net_MaxSendRate": 65536, "net_MaxBacklog": 65536}
CONFIGS: dict[str, dict] = {
    # As shipped: the Java adapter and every retail peer.
    "retail": {"carrier": "plain", **SHIPPED},
    # Native links between our builds before this work (#240): the redundant lane around the same game datagrams.
    "lane": {"carrier": "lane", "redundancy": 2, **SHIPPED},
    # One change at a time on the retail carrier.
    "flush": {"carrier": "plain", "flush": 1, **SHIPPED},
    "fast-resend": {"carrier": "plain", **SHIPPED, **FAST},
    "rate": {"carrier": "plain", **SHIPPED, **RATE},
    # All three together (the new defaults), on each carrier.
    "tuned": {"carrier": "plain", "flush": 1, **FAST, **RATE},
    "lane-tuned": {"carrier": "lane", "redundancy": 2, "flush": 1, **FAST, **RATE},
    # The game channel (net_GameChannel) between our builds, with the beat flush.
    "channel": {"carrier": "channel", "flush": 1, **FAST, **RATE},
    # The game channel's repeats (net_GameChannelRepeats, net_GameChannelRepeatMs): none, 2, and 5 at a 60 ms first gap.
    "channel-r0": {"carrier": "channel", "flush": 1, "net_GameChannelRepeats": 0},
    "channel-r2": {"carrier": "channel", "flush": 1, "net_GameChannelRepeats": 2},
    "channel-r5-60": {"carrier": "channel", "flush": 1, "net_GameChannelRepeats": 5, "net_GameChannelRepeatMs": 60},
    # Repeats only for 10 s after each loss (net_GameChannelRepeatHoldMs), against the default's always.
    "channel-hold": {"carrier": "channel", "flush": 1, "net_GameChannelRepeatHoldMs": 10000},
}


def args_for(profile: str, config: str, seed: int, seconds: float, players: int) -> list[str]:
    a = [f"seconds={seconds}", f"players={players}", f"seed={seed}"]
    for k, v in PROFILES[profile].items():
        a.append(f"{k}={v}")
    for k, v in CONFIGS[config].items():
        a.append(f"{k}={v}")
    return a


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bench", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--players", type=int, default=2)
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()

    done = set()
    if a.out.exists():
        for line in a.out.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done.add((r.get("profile"), r.get("config"), r.get("seed"), r.get("players")))
            except ValueError:
                pass
    a.out.parent.mkdir(parents=True, exist_ok=True)

    cells = [
        (p, c, s)
        for p in a.profiles.split(",")
        for c in a.configs.split(",")
        for s in range(1, a.seeds + 1)
        if (p, c, s, a.players) not in done
    ]
    print(f"{len(cells)} runs, {len(done)} already in {a.out}", flush=True)

    def run(cell):
        p, c, s = cell
        cmd = [str(a.bench.resolve()), *args_for(p, c, s, a.seconds, a.players)]
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        try:
            r = json.loads(line)
        except ValueError:
            return cell, None, (proc.stderr or proc.stdout)[-300:]
        r["profile"], r["config"] = p, c
        return cell, r, ""

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool, a.out.open("a", encoding="utf-8") as f:
        for cell, r, err in pool.map(run, cells):
            if r is None:
                failed += 1
                print(f"FAIL {cell}: {err}", flush=True)
                continue
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
            f.flush()
            print(f"ok {cell}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
