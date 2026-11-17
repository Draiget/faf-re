#!/usr/bin/env python3
"""Tables and charts for docs/NETWORK_MEASUREMENTS.md from faf_netbench runs (tools/netbench/run.py).

  python tools/netbench/report.py tmp/netbench/before.jsonl [more.jsonl ...] --charts docs/images/net-measurements \
      --tables tmp/netbench/tables.md

How a beat's delivery time becomes a pause the player sees (the game's issue pacing, CSimDriver::ThreadRun): a client
issues beat k net_Lag ms before it is due, i.e. when beat k - m has executed, m = ceil(lag / 100), plus 100 m - lag ms.
Beat k executes once every player's beat k has arrived and 100 ms after beat k - 1. The bench sent beat k at
S_k = 100 k and the slowest link delivered it d_k later, at S_k + d_k. A beat a stalled game issues later than S_k
still can't get through before the network let it (it queues behind the same burst, waits for the same outage), nor
sooner than the link's quickest delivery d_min after it was issued:

    I_k = E_(k-m) + 100 m - lag                         (I_k = 100 k before beat m)
    A_k = max(S_k + d_k, I_k + d_min)
    E_k = max(E_(k-1) + 100, A_k)

Everything E_k lags behind 100 k + lag is time the game stood still. A beat that never arrived counts as a 10 s pause.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import svgchart  # noqa: E402

BEAT_MS = 100.0
LAGS = list(range(50, 1525, 25))
PAUSE_MS = 150.0  # a beat shown this much later than its turn reads as a pause (net_AdaptiveLagMax uses the same)
MISSING_MS = 10000.0


def slowest_per_beat(run: dict) -> list[float]:
    beats = run["beats"]
    worst = [0.0] * beats
    for link in run["links"]:
        for k, d in enumerate(link["delay"]):
            worst[k] = max(worst[k], MISSING_MS if d < 0 else d)
    return worst


def pace(delays: list[float], lag: float) -> tuple[float, int, list[float]]:
    """Total stall (ms), pauses of PAUSE_MS or more, and the per-beat stall."""
    m = max(1, math.ceil(lag / BEAT_MS))
    d_min = min(delays) if delays else 0.0
    e: list[float] = []
    stalls = []
    for k, d in enumerate(delays):
        issue = k * BEAT_MS if k < m else e[k - m] + BEAT_MS * m - lag
        arrival = max(k * BEAT_MS + d, issue + d_min)
        due = (e[k - 1] + BEAT_MS) if k else lag
        ek = max(due, arrival)
        stalls.append(ek - due)
        e.append(ek)
    return sum(stalls), sum(1 for s in stalls if s >= PAUSE_MS), stalls


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    if not s:
        return float("nan")
    i = min(len(s) - 1, max(0, math.ceil(q / 100.0 * len(s)) - 1))
    return s[i]


def load(paths: list[Path]) -> list[dict]:
    runs = []
    for p in paths:
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                runs.append(json.loads(line))
    return runs


def summarize(runs: list[dict]) -> dict:
    """(profile, config) -> aggregated numbers over seeds."""
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for r in runs:
        cells[(r["profile"], r["config"])].append(r)
    out = {}
    for key, rs in cells.items():
        all_delays = []
        worst = []
        minutes = 0.0
        stall_by_lag = {lag: 0.0 for lag in LAGS}
        pauses_by_lag = {lag: 0 for lag in LAGS}
        wire_bytes = payload_bytes = datagrams = 0
        missing = 0
        burst_ms = []
        for r in rs:
            minutes += r["beats"] * BEAT_MS / 60000.0
            w = slowest_per_beat(r)
            worst.extend(w)
            for lag in LAGS:
                s, p, _ = pace(w, lag)
                stall_by_lag[lag] += s
                pauses_by_lag[lag] += p
            for link in r["links"]:
                all_delays.extend(d for d in link["delay"] if d >= 0)
                missing += sum(1 for d in link["delay"] if d < 0)
                wire_bytes += link["bytes"]
                datagrams += link["datagrams"]
                if link.get("burstMs", -1) >= 0:
                    burst_ms.append(link["burstMs"])
            # Each player's beats go to every other player.
            payload_bytes += sum(r["payloadBytes"]) * (r["players"] - 1)
        links = sum(len(r["links"]) for r in rs)
        seconds = sum(r["beats"] * BEAT_MS / 1000.0 for r in rs)
        out[key] = {
            "runs": len(rs),
            "minutes": minutes,
            "p50": pct(all_delays, 50),
            "p99": pct(all_delays, 99),
            "p999": pct(all_delays, 99.9),
            "max": max(all_delays) if all_delays else float("nan"),
            "missing": missing,
            "stallPerMin": {lag: stall_by_lag[lag] / minutes for lag in LAGS},
            "pausesPer10Min": {lag: pauses_by_lag[lag] * 10.0 / minutes for lag in LAGS},
            "wireBytesPerLinkSecond": wire_bytes / links / (seconds / len(rs)),
            "datagramsPerLinkSecond": datagrams / links / (seconds / len(rs)),
            "overhead": wire_bytes / payload_bytes if payload_bytes else float("nan"),
            "burstMs": statistics.median(burst_ms) if burst_ms else None,
            "worst": worst,
            "delays": all_delays,
        }
    return out


def lag_needed(cell: dict, budget_ms_per_min: float = 60.0) -> int | None:
    """The smallest lag whose stall stays within the budget (60 ms a minute = 0.1 % of play) with no pause over
    PAUSE_MS more than once in 10 minutes."""
    for lag in LAGS:
        if cell["stallPerMin"][lag] <= budget_ms_per_min and cell["pausesPer10Min"][lag] <= 1.0:
            return lag
    return None


def fmt(v, digits=0):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    return f"{v:,.{digits}f}"


def tables(summary: dict, profiles: list[str], configs: list[str]) -> str:
    lines = []
    lines.append("| Profile | Configuration | Beat delivery p50 / p99 / p99.9 / max (ms) | Stall at lag 500 (ms/min) | "
                 "Pauses >= 150 ms at lag 500 (per 10 min) | Lag needed (ms) | Wire bytes/s per link | Datagrams/s per link | "
                 "Wire / payload |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for p in profiles:
        for c in configs:
            cell = summary.get((p, c))
            if not cell:
                continue
            lines.append(
                f"| {p} | {c} | {fmt(cell['p50'])} / {fmt(cell['p99'])} / {fmt(cell['p999'])} / {fmt(cell['max'])} | "
                f"{fmt(cell['stallPerMin'][500])} | {fmt(cell['pausesPer10Min'][500], 1)} | {fmt(lag_needed(cell))} | "
                f"{fmt(cell['wireBytesPerLinkSecond'])} | {fmt(cell['datagramsPerLinkSecond'], 1)} | "
                f"{fmt(cell['overhead'], 2)} |"
            )
    return "\n".join(lines)


def charts(summary: dict, profiles: list[str], configs: list[str], out: Path, runs: list[dict]) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    made = []

    # 1. Lag needed per profile.
    cats = [p for p in profiles if any((p, c) in summary for c in configs)]
    # The slow uplink and the outage stall every configuration once, whatever the delay: no delay "needed" there.
    lag_cats = [p for p in cats if p not in ("slow-uplink", "outage")]
    series = [(c, [lag_needed(summary[(p, c)]) if (p, c) in summary else None for p in lag_cats]) for c in configs]
    svgchart.bar_chart(out / "lag_needed.svg", "Order delay each network needs",
                       lag_cats, series, ylabel="lag (ms)",
                       subtitle="smallest net_Lag with under 0.1 % of play paused; the shipped game always uses 500",
                       refs=[("shipped net_Lag 500 ms", 500)], width=900)
    made.append("lag_needed.svg")

    # 2. Stall against lag, one chart per profile worth showing.
    for p in [p for p in ("typical", "wifi", "bad", "worst") if p in cats]:
        series = []
        for c in configs:
            cell = summary.get((p, c))
            if cell:
                series.append((c, [(lag, cell["stallPerMin"][lag]) for lag in LAGS if lag <= 1000]))
        if series:
            svgchart.line_chart(out / f"stall_vs_lag_{p}.svg", f"Time the game stands still, network '{p}'", series,
                                xlabel="net_Lag (ms)", ylabel="stall (ms per minute)",
                                subtitle="from measured beat delivery, through the game's issue pacing")
            made.append(f"stall_vs_lag_{p}.svg")

    # 3. Delivery distribution (share of beats delivered later than x).
    for p in [p for p in ("typical", "bad") if p in cats]:
        series = []
        for c in configs:
            cell = summary.get((p, c))
            if not cell:
                continue
            d = sorted(cell["delays"])
            pts = []
            for x in range(0, 1001, 10):
                late = (len(d) - _count_le(d, x)) / len(d) * 100.0
                pts.append((x, late))
            series.append((c, pts))
        if series:
            svgchart.line_chart(out / f"delivery_tail_{p}.svg", f"Beats still on the way, network '{p}'", series,
                                xlabel="time since the beat was sent (ms)", ylabel="% of beats not yet delivered",
                                subtitle="every link, every seed; lower and further left is better", ymax=20)
            made.append(f"delivery_tail_{p}.svg")

    # 4. Bytes on the wire.
    series = [(c, [summary[(p, c)]["wireBytesPerLinkSecond"] if (p, c) in summary else None for p in cats])
              for c in configs]
    svgchart.bar_chart(out / "wire_bytes.svg", "Bytes on the wire per link", cats, series, ylabel="bytes per second",
                       subtitle="IP and UDP headers included; the same orders in every column", width=900)
    made.append("wire_bytes.svg")

    # 5. Per-beat stall around the order burst and the outage, seed 1, lag 500.
    for p, title in (("order-burst", "A 44,891-byte order at 20 s"), ("slow-uplink", "The same order on a 256 kbit/s uplink"),
                     ("outage", "3 s with no connection at 30 s")):
        series = []
        for c in configs:
            r = next((r for r in runs if r["profile"] == p and r["config"] == c and r["seed"] == 1), None)
            if not r:
                continue
            _, _, stalls = pace(slowest_per_beat(r), 500)
            acc = 0.0
            pts = []
            for k, s in enumerate(stalls):
                acc += s
                pts.append((k * BEAT_MS / 1000.0, acc / 1000.0))
            series.append((c, pts))
        if series:
            svgchart.line_chart(out / f"timeline_{p}.svg", title, series, xlabel="game time (s)",
                                ylabel="time stood still so far (s)", subtitle="lag 500 ms, seed 1")
            made.append(f"timeline_{p}.svg")
    # 6. The game channel's repeats: order delay needed and bytes, per setting.
    sweep = [c for c in ("channel-r0", "channel-r2", "channel", "channel-r5-60", "channel-hold")
             if any((p, c) in summary for p in cats)]
    if sweep:
        lossy = [p for p in ("typical", "wifi", "bad", "worst") if p in cats]
        names = {"channel-r0": "no repeats", "channel-r2": "2 repeats", "channel": "5 repeats from 30 ms",
                 "channel-r5-60": "5 repeats from 60 ms", "channel-hold": "5 from 30 ms, only after a loss"}
        series = [(names[c], [lag_needed(summary[(p, c)]) if (p, c) in summary else None for p in lossy]) for c in sweep]
        svgchart.bar_chart(out / "repeats_lag.svg", "Game channel repeats: order delay needed", lossy, series,
                           ylabel="lag (ms)", subtitle="smallest net_Lag with under 0.1 % of play paused", width=900)
        series = [(names[c], [summary[(p, c)]["wireBytesPerLinkSecond"] if (p, c) in summary else None for p in lossy])
                  for c in sweep]
        svgchart.bar_chart(out / "repeats_bytes.svg", "Game channel repeats: bytes on the wire", lossy, series,
                           ylabel="bytes per second per link", subtitle="IP and UDP headers included", width=900)
        made += ["repeats_lag.svg", "repeats_bytes.svg"]
    return made


def _count_le(sorted_values: list[float], x: float) -> int:
    lo, hi = 0, len(sorted_values)
    while lo < hi:
        mid = (lo + hi) // 2
        if sorted_values[mid] <= x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("--charts", type=Path)
    ap.add_argument("--tables", type=Path)
    ap.add_argument("--configs", help="order of configurations (default: as found)")
    a = ap.parse_args()
    runs = load(a.inputs)
    profiles = list(dict.fromkeys(r["profile"] for r in runs))
    configs = a.configs.split(",") if a.configs else list(dict.fromkeys(r["config"] for r in runs))
    summary = summarize(runs)
    text = tables(summary, profiles, configs)
    if a.tables:
        a.tables.write_text(text + "\n", encoding="utf-8")
    print(text)
    if a.charts:
        for name in charts(summary, profiles, configs, a.charts, runs):
            print(f"chart {a.charts / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
