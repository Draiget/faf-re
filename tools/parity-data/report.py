"""Merges the shards' results into one report and judges the run.

usage: report.py --plan plan.json --results DIR [--expected FILE] --out DIR

DIR holds the shards' results (any depth: every results.jsonl under it). Writes OUT/report.json
(every replay) and OUT/report.md (the summary: counts, every replay that did not pass with its
beat and notes, replays where a live client desynced, every passing replay with its replay time,
wall time and speedup, the time model fitted to this run), and
appends report.md to the GitHub job summary. --after DIR merges an earlier run's results
under this run's (a run that finishes what the earlier one had no time for). --expected lists known failures
({"<id>": {"verdict": "desync", "note": "..."}}); exit code 1 when a replay desynced, crashed,
stopped early, ran out of time, could not be got ready or got no result from its shard, and is
not listed there with that verdict.
"""
import argparse
import glob
import json
import os
import sys

from common import clock

# error: the replay could not be got ready (download, map, M28AI) or its shard's job died; a
# replay the run meant to play and did not is a failure of the run, not a pass.
FAILURES = ("desync", "crash", "incomplete", "timeout", "error")
# Passing replays listed in report.md (GitHub caps a job summary at 1 MiB); report.json has all.
PASS_ROWS = 500
ORDER = ("pass", "desync", "crash", "incomplete", "timeout", "error", "unsupported", "not-run", "not-scheduled")


def fit_time_model(results):
    """Least squares of wall_s = a + ticks * (b + c * players) over passing replays without
    M28AI, to replace common.estimate_seconds' numbers."""
    rows = [(1.0, r["length"], r["length"] * r["players"], r["wall_s"]) for r in results
            if r["verdict"] == "pass" and not r.get("m28") and r.get("length") and r.get("wall_s")]
    if len(rows) < 10:
        return None
    # Normal equations for three unknowns, solved by Cramer's rule.
    s = [[sum(x[i] * x[j] for x in rows) for j in range(3)] for i in range(3)]
    t = [sum(x[i] * x[3] for x in rows) for i in range(3)]

    def det(m):
        return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
                + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))

    d = det(s)
    if abs(d) < 1e-9:
        return None
    coef = []
    for k in range(3):
        m = [row[:] for row in s]
        for i in range(3):
            m[i][k] = t[i]
        coef.append(det(m) / d)
    return {"a_s": round(coef[0], 2), "per_tick": round(coef[1], 6), "per_tick_player": round(coef[2], 6),
            "replays": len(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--expected")
    parser.add_argument("--after", help="the earlier run's results (plan.py --after): merged under this run's")
    parser.add_argument("--out", required=True)
    parser.add_argument("--title", default="Replay parity")
    args = parser.parse_args()

    with open(args.plan, encoding="utf-8") as f:
        plan = json.load(f)
    expected = {}
    if args.expected and os.path.isfile(args.expected):
        with open(args.expected, encoding="utf-8") as f:
            expected = {int(k): v for k, v in json.load(f).items()}

    results = {}
    for folder in filter(None, (args.after, args.results)):  # this run's results replace the earlier's
        for path in glob.glob(os.path.join(folder, "**", "results.jsonl"), recursive=True):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        results[r["id"]] = r
    for u in plan["unsupported"]:
        results.setdefault(u["id"], {"id": u["id"], "verdict": "unsupported", "why": u["reason"]})
    for n in plan["not_scheduled"]:
        results.setdefault(n["id"], {"id": n["id"], "verdict": "not-scheduled", "why": n["why"]})
    for shard in plan["shards"]:  # a shard whose job died wrote nothing
        for item in shard["replays"]:
            results.setdefault(item["id"], {"id": item["id"], "verdict": "error",
                                            "why": "no result from shard %d" % shard["shard"]})

    regressions, known, fixed = [], [], []
    for r in results.values():
        exp = expected.get(r["id"])
        if r["verdict"] in FAILURES:
            (known if exp and exp.get("verdict") == r["verdict"] else regressions).append(r)
        elif r["verdict"] == "pass" and exp:
            fixed.append(r)

    counts = {}
    for r in results.values():
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    model = fit_time_model(list(results.values()))

    def row(r):
        beat = r.get("first_beat", "")
        detail = "; ".join(r.get("notes") or []) or r.get("why", "")
        return "| %d | %s | %s | %s/%s | %s | %s | %s |" % (
            r["id"], r["verdict"], beat, r.get("last_beat", ""), r.get("length", ""), r.get("players", ""),
            r.get("map", ""), detail.replace("|", "/")[:160])

    lines = ["# %s" % args.title, "",
             "Set `%s`, %d replays: %s." % (plan["settings"]["which"], len(results),
                                            ", ".join("%d %s" % (counts[v], v) for v in ORDER if v in counts)), ""]
    if regressions:
        lines += ["## New failures (%d)" % len(regressions), "",
                  "| Replay | Verdict | First mismatch | Last beat / length | Players | Map | Notes |",
                  "|---|---|---|---|---|---|---|"] + [row(r) for r in sorted(regressions, key=lambda r: r["id"])] + [""]
    else:
        lines += ["**No new failures.**", ""]
    if known:
        lines += ["## Known failures (%d)" % len(known), "",
                  "| Replay | Verdict | First mismatch | Last beat / length | Players | Map | Notes |",
                  "|---|---|---|---|---|---|---|"] + [row(r) for r in sorted(known, key=lambda r: r["id"])] + [""]
    if fixed:
        lines += ["## Listed as failing, now passing (%d)" % len(fixed), "",
                  ", ".join(str(r["id"]) for r in sorted(fixed, key=lambda r: r["id"])), ""]
    live = [r for r in results.values() if r.get("live_desyncs")]
    if live:
        lines += ["## Desynced in the live game, ignored (%d)" % len(live), "",
                  "A live client disagreed with the others and the sim sided with the majority.", ""]
        lines += ["- %d: %s" % (r["id"], ", ".join("%s at beat %d" % (d["client"], d["beat"]) for d in r["live_desyncs"]))
                  for r in sorted(live, key=lambda r: r["id"])] + [""]
    passed = sorted((r for r in results.values() if r["verdict"] == "pass" and r.get("wall_s")), key=lambda r: r["id"])
    if passed:
        for r in passed:  # results written before game_s existed
            r.setdefault("game_s", max(0, r.get("last_beat") or 0) / 10.0)
        game_total = sum(r["game_s"] for r in passed)
        wall_total = sum(r["wall_s"] for r in passed)
        lines += ["## Passed (%d)" % len(passed), "",
                  "Replay time is the game time played (10 beats a second); wall time runs from starting headless "
                  "to its exit, loading included; speedup is replay time over wall time. A runner plays %s at once."
                  % plan["settings"].get("slots", "several"), "",
                  "In all: %s of replay time in %s of wall time, x%.1f." % (clock(game_total), clock(wall_total),
                                                                            game_total / wall_total if wall_total else 0), "",
                  "| Replay | Replay time | Wall time | Speedup | Players | Map |", "|---|---|---|---|---|---|"]
        shown = passed[:PASS_ROWS]
        lines += ["| %d | %s | %s | x%.1f | %s | %s |" % (r["id"], clock(r["game_s"]), clock(r["wall_s"]),
                                                          r["game_s"] / r["wall_s"], r.get("players", ""), r.get("map", ""))
                  for r in shown]
        if len(passed) > len(shown):
            lines += ["", "%d more in report.json." % (len(passed) - len(shown))]
        lines += [""]
    other = [r for r in results.values() if r["verdict"] in ("not-run", "not-scheduled", "unsupported")]
    if other:
        why = {}
        for r in other:
            key = "%s: %s" % (r["verdict"], (r.get("why") or "").split(":")[0])
            why[key] = why.get(key, 0) + 1
        lines += ["## Not played (%d)" % len(other), ""] + ["- %s: %d" % (k, n) for k, n in sorted(why.items())] + [""]
    if model:
        lines += ["## Time model", "",
                  "Fitted to %d passing replays without M28AI: wall seconds = %.1f + ticks x (%.6f + %.6f x players)."
                  % (model["replays"], model["a_s"], model["per_tick"], model["per_tick_player"]), ""]

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump({"settings": plan["settings"], "counts": counts, "time_model": model,
                   "regressions": sorted(r["id"] for r in regressions),
                   "replays": sorted(results.values(), key=lambda r: r["id"])}, f, indent=1)
    text = "\n".join(lines) + "\n"
    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    print(text)
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
