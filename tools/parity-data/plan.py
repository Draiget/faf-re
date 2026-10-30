"""Splits a parity run into shards, one GitHub job each, packed to the job's time budget.

usage: plan.py --corpus FILE --index DIR --set core|extended|sample|all [options] --out plan.json

Every shard holds replays of one id bucket (so its job restores one replay cache; the core and
extended sets share shards, bucket -1, and their jobs fetch the replays) whose
estimated times fill `slots` parallel players for `budget-minutes` (first fit, longest first).
A set that fills fewer than --jobs shards (the jobs GitHub runs at once) is split further, down
to `slots` replays a shard, so it ends as soon as the jobs running at once allow.
The core set comes first, then the extended set, then the rest in a seeded random order; when
the shards would pass --max-shards, the replays at the end of that order are left out (listed in
the plan as not scheduled). Replays the prewarm found unplayable (a sim mod, another version)
are listed as unsupported; replays it has not seen yet are scheduled and checked by the job.

Writes the plan and, for GitHub Actions, `matrix` (the shards) and `shards` to GITHUB_OUTPUT.
"""
import argparse
import collections
import glob
import json
import os
import random
import sys

from common import CORE_SET, EXTENDED_SET, bucket_of, estimate_seconds, read_corpus
from prewarm import read_index


def select(corpus, which, sample, seed):
    named = [i for i in CORE_SET if i in corpus]
    if which in ("extended", "sample", "all"):
        named += [i for i in EXTENDED_SET if i in corpus]
    if which in ("core", "extended"):
        return named
    rest = sorted(set(corpus) - set(named))
    random.Random(seed).shuffle(rest)
    if which == "sample":
        rest = rest[:max(0, sample - len(named))]
    return named + rest


def pack(items, capacity):
    """First fit decreasing: lists of items whose `est` sums stay within capacity."""
    bins = []
    for item in sorted(items, key=lambda r: -r["est"]):
        for b in bins:
            if b["load"] + item["est"] <= capacity:
                b["items"].append(item)
                b["load"] += item["est"]
                break
        else:
            bins.append({"items": [item], "load": item["est"]})
    return bins


def spread(shards, want, slots):
    """Splits the most loaded shard in two (longest first, each to the lighter half) until there
    are `want` shards or none holds more than `slots` replays: a set too small to fill a job's
    budget still plays on as many jobs as run at once, `slots` replays to each."""
    while len(shards) < want:
        splittable = [s for s in shards if len(s[1]["items"]) > slots]
        if not splittable:
            break
        bucket, big = max(splittable, key=lambda s: s[1]["load"])
        halves = [{"items": [], "load": 0}, {"items": [], "load": 0}]
        for item in sorted(big["items"], key=lambda r: -r["est"]):
            half = min(halves, key=lambda h: h["load"])
            half["items"].append(item)
            half["load"] += item["est"]
        i = next(n for n, s in enumerate(shards) if s[1] is big)
        shards[i:i + 1] = [(bucket, h) for h in halves]
    return shards


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--index", required=True, help="folder holding the buckets' index.jsonl files")
    parser.add_argument("--set", dest="which", choices=("core", "extended", "sample", "all"), default="core")
    parser.add_argument("--sample", type=int, default=1000, help="replays for --set sample")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--slots", type=int, default=4, help="replays a job plays at once")
    parser.add_argument("--budget-minutes", type=float, default=300, help="time a job spends playing")
    parser.add_argument("--fill", type=float, default=0.85, help="share of slots x budget a shard is packed to")
    parser.add_argument("--max-shards", type=int, default=256)
    parser.add_argument("--jobs", type=int, default=20,
                        help="jobs GitHub runs at once (20 on Free): a small set is spread over this many")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    corpus = read_corpus(args.corpus)
    index = {}
    for path in glob.glob(os.path.join(args.index, "**", "index.jsonl"), recursive=True):
        index.update(read_index(path))

    unsupported = []
    chosen = []
    for replay_id in select(corpus, args.which, args.sample, args.seed):
        row = corpus[replay_id]
        e = index.get(replay_id)
        if e and e["state"] != "ready":
            unsupported.append({"id": replay_id, "reason": e["reason"]})
            continue
        m28 = (e or {}).get("m28")
        chosen.append({"id": replay_id, "ticks": row["ticks"], "players": row["players"], "map": row["map"],
                       "map_kind": row["map_kind"], "m28": m28, "indexed": e is not None,
                       "est": round(estimate_seconds(row["ticks"], row["players"], bool(m28)))})

    capacity = args.slots * args.budget_minutes * 60 * args.fill
    longest = args.budget_minutes * 60 * 0.9  # one replay plays in one slot
    too_long = [r for r in chosen if r["est"] > longest]
    chosen = [r for r in chosen if r["est"] <= longest]

    # The core and extended sets are a few replays across many buckets: one shard per bucket
    # would leave most of each job idle, so they share shards (bucket -1), and those jobs fetch
    # their replays instead of restoring a bucket's cache.
    mixed = args.which in ("core", "extended")

    def shards_for(items):
        by_bucket = collections.defaultdict(list)
        for r in items:
            by_bucket[-1 if mixed else bucket_of(r["id"])].append(r)
        return [(b, x) for b in sorted(by_bucket) for x in pack(by_bucket[b], capacity)]

    dropped = []
    shards = shards_for(chosen)
    while len(shards) > args.max_shards:
        cut = max(1, len(chosen) // 50)  # the end of the priority order goes first
        dropped = chosen[-cut:] + dropped
        chosen = chosen[:-cut]
        shards = shards_for(chosen)
    shards = spread(shards, min(args.jobs, args.max_shards), args.slots)

    plan = {
        "settings": {k: getattr(args, k) for k in ("which", "sample", "seed", "slots", "budget_minutes", "fill")},
        "shards": [{"shard": n, "bucket": b, "load_s": round(x["load"]),
                    "replays": sorted(x["items"], key=lambda r: -r["est"])} for n, (b, x) in enumerate(shards)],
        "unsupported": unsupported,
        "not_scheduled": [{"id": r["id"], "why": "too long for one job"} for r in too_long]
                         + [{"id": r["id"], "why": "past --max-shards"} for r in dropped],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=1)

    scheduled = sum(len(s["replays"]) for s in plan["shards"])
    print("set %s: %d replays in %d shards (%.0f%% full on average), %d unsupported, %d not scheduled"
          % (args.which, scheduled, len(shards),
             100.0 * sum(s["load_s"] for s in plan["shards"]) / max(1, len(shards) * capacity / args.fill),
             len(unsupported), len(plan["not_scheduled"])))
    matrix = {"include": [{"shard": s["shard"], "bucket": s["bucket"]} for s in plan["shards"]]}
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write("matrix=%s\n" % json.dumps(matrix, separators=(",", ":")))
            f.write("shards=%d\n" % len(shards))
    return 0


if __name__ == "__main__":
    sys.exit(main())
