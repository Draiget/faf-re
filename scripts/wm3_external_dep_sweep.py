"""Sweep FA function exports for `Wm3::*`-namespace symbols and emit a
worklist suitable for `recovered_progress.py bulk-mark --status external_dependency`.

This is the mangled-name pass of the WildMagic3p8 dependency-marking workflow.
It identifies functions in the FA binary whose owning namespace is `Wm3::`
(i.e. they live in WildMagic library code, not in moho/gpg code that merely
consumes Wm3 types in signatures), classifies them by current recovery status,
and produces:

  1. A summary report with counts by current status.
  2. A `tmp/wm3_sweep_candidates.txt` file containing one FUN_token per line
     for the candidates that should be flipped to `external_dependency`.
  3. A `tmp/wm3_sweep_recovered.txt` file containing tokens already in
     `recovered/accepted/done` (these become wrappers in a later step, NOT
     external_dependency).
  4. A `tmp/wm3_sweep_skipped.txt` file containing tokens we leave alone
     (already `in_progress` by another worker, or `skip`).

Run it dry by default; pass `--print-samples N` to see N example names per
bucket. Use the produced `tmp/wm3_sweep_candidates.txt` with:

    python skills/fa-recovery-iteration/scripts/recovered_progress.py \
        bulk-mark --namespace fa_full_2026_03_26 \
        --functions-file tmp/wm3_sweep_candidates.txt \
        --status external_dependency \
        --note "WildMagic3p8 mangled-name sweep" \
        --skip-recovered

Mangled-name match heuristic: a function is "Wm3-owned" if its best-available
demangled name (preferring `demangled_name`, then `listing_name`, then
`function_name`) starts with `Wm3::`. This excludes Moho/gpg code that takes
`Wm3::Vector3` etc as parameters — those still need normal recovery.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NAMESPACE = "fa_full_2026_03_26"
DEFAULT_INDEX = REPO_ROOT / "decomp" / "recovery" / "disasm" / DEFAULT_NAMESPACE / "_callgraph_index.sqlite"
DEFAULT_PROGRESS = REPO_ROOT / "decomp" / "recovery" / "recovered_progress.json"
TMP_DIR = REPO_ROOT / "tmp"


def best_demangled(function_name: str | None, demangled_name: str | None, listing_name: str | None) -> str:
    """Return the most demangled-looking of the three name fields, or empty string."""
    for n in (demangled_name, listing_name, function_name):
        if n and not n.startswith("?"):
            if " [" in n:
                n = n.split(" [", 1)[0]
            return n
    return function_name or ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=f"Recovery namespace key (default: {DEFAULT_NAMESPACE}).",
    )
    parser.add_argument(
        "--index",
        type=Path,
        default=DEFAULT_INDEX,
        help="Path to the callgraph index sqlite (default: derived from --namespace).",
    )
    parser.add_argument(
        "--progress",
        type=Path,
        default=DEFAULT_PROGRESS,
        help=f"Path to recovered_progress.json (default: {DEFAULT_PROGRESS}).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=TMP_DIR,
        help=f"Output directory for the worklist files (default: {TMP_DIR}).",
    )
    parser.add_argument(
        "--print-samples",
        type=int,
        default=0,
        help="Print N example function names per bucket (default: 0).",
    )
    args = parser.parse_args()

    if args.index != DEFAULT_INDEX and "--namespace" not in sys.argv:
        # If user passed --index but not --namespace, fall back to derive ns from index
        pass
    elif args.namespace != DEFAULT_NAMESPACE:
        args.index = REPO_ROOT / "decomp" / "recovery" / "disasm" / args.namespace / "_callgraph_index.sqlite"

    if not args.index.exists():
        print(f"callgraph index not found: {args.index}", file=sys.stderr)
        return 2
    if not args.progress.exists():
        print(f"progress DB not found: {args.progress}", file=sys.stderr)
        return 2

    progress = json.loads(args.progress.read_text(encoding="utf-8"))
    ns = progress.get("namespaces", {}).get(args.namespace)
    if ns is None:
        print(
            f"namespace {args.namespace!r} not found in {args.progress}; "
            f"available: {list(progress.get('namespaces', {}).keys())}",
            file=sys.stderr,
        )
        return 2

    recovered_db: dict = ns.get("recovered", {})

    con = sqlite3.connect(args.index)
    rows = con.execute(
        "SELECT token, function_name, demangled_name, listing_name FROM functions"
    ).fetchall()
    con.close()

    # Buckets keyed by current recovery status (or "<not in progress>")
    buckets: dict[str, list[tuple[str, str]]] = {}
    for token, fn, dm, ln in rows:
        name = best_demangled(fn, dm, ln)
        if not name.startswith("Wm3::"):
            continue
        cur = recovered_db.get(token, {}).get("status", "<not in progress>")
        buckets.setdefault(cur, []).append((token, name))

    # Decide which buckets become external_dependency candidates
    flip_to_external = {"blocked", "needs_evidence", "<not in progress>"}
    leave_alone = {"in_progress", "skip", "external_dependency"}
    keep_as_recovered = {"recovered", "accepted", "done", "wip"}

    candidates: list[tuple[str, str]] = []
    recovered_list: list[tuple[str, str]] = []
    skipped_list: list[tuple[str, str]] = []
    unknown_list: list[tuple[str, str]] = []

    for status, items in buckets.items():
        if status in flip_to_external:
            candidates.extend(items)
        elif status in keep_as_recovered:
            recovered_list.extend(items)
        elif status in leave_alone:
            skipped_list.extend(items)
        else:
            unknown_list.extend(items)

    # Print summary
    total = sum(len(v) for v in buckets.values())
    print(f"Wm3-owned functions in {args.namespace}: {total}")
    print()
    print("By current recovery status:")
    for status in sorted(buckets.keys(), key=lambda s: -len(buckets[s])):
        items = buckets[status]
        marker = ""
        if status in flip_to_external:
            marker = "  -> mark external_dependency"
        elif status in keep_as_recovered:
            marker = "  -> keep, will become wrapper"
        elif status in leave_alone:
            marker = "  -> skip (don't touch)"
        else:
            marker = "  -> UNKNOWN status, skipped"
        print(f"  {status:<24}  {len(items):>4}{marker}")
        if args.print_samples > 0:
            for tok, name in items[: args.print_samples]:
                print(f"      {tok}  {name}")

    # Write worklists. The candidates file is the one that gets fed to
    # `recovered_progress.py bulk-mark`, whose token parser does NOT accept
    # inline `#` comments — it calls normalize_fun_token directly on the line.
    # So the candidates file is bare-token-per-line; the review files
    # (.recovered / .skipped) keep names as comments for human inspection.
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cand_path = args.out_dir / "wm3_sweep_candidates.txt"
    cand_review_path = args.out_dir / "wm3_sweep_candidates_review.txt"
    rec_path = args.out_dir / "wm3_sweep_recovered.txt"
    skip_path = args.out_dir / "wm3_sweep_skipped.txt"

    def write_review_list(path: Path, items: list[tuple[str, str]]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for tok, name in sorted(items):
                f.write(f"{tok}  # {name}\n")

    def write_bare_list(path: Path, items: list[tuple[str, str]]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for tok, _name in sorted(items):
                f.write(f"{tok}\n")

    write_bare_list(cand_path, candidates)
    write_review_list(cand_review_path, candidates)
    write_review_list(rec_path, recovered_list)
    write_review_list(skip_path, skipped_list)

    print()
    print(f"Wrote {cand_path}: {len(candidates)} external_dependency candidates (bare tokens)")
    print(f"Wrote {cand_review_path}: same set with name comments for review")
    print(f"Wrote {rec_path}: {len(recovered_list)} already recovered (will become wrappers)")
    print(f"Wrote {skip_path}: {len(skipped_list)} skipped (in_progress / skip)")
    if unknown_list:
        print(f"WARNING: {len(unknown_list)} functions had unknown status, not written")

    print()
    print("To apply the candidates, run:")
    print(
        "  python skills/fa-recovery-iteration/scripts/recovered_progress.py "
        f"bulk-mark --namespace {args.namespace} "
        f"--functions-file {cand_path.relative_to(REPO_ROOT)} "
        '--status external_dependency '
        '--note "WildMagic3p8 mangled-name sweep" '
        "--skip-recovered"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
