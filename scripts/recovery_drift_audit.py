#!/usr/bin/env python3
"""
Recovery drift audit: find progress-DB tokens marked as completed that have
NO matching `Address: 0x...` annotation in src/sdk.

These "phantom recoveries" are entries where the JSON bookkeeping claims a
function is done but no actual recovered source body references its binary
address. They happen when:

  1. A token was bulk-marked without writing a body.
  2. A recovered function was inlined into a helper and nobody added the
     `Address:` annotation.
  3. One `.cpp` implements several binary tokens but only the "primary" one
     got documented.

Run:
  python scripts/recovery_drift_audit.py --namespace fa_full_2026_03_26

Outputs a summary and optionally a token queue for bulk re-classification.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

# Canonical recovery annotation is `Address: 0x...`, but the project also
# uses `Scalar-deleting wrapper: 0x...`, `Mangled deleting-dtor thunk: 0x...`,
# `Address family:` blocks, `(FUN_xxxxxxxx)` cross-refs, etc. Accept any
# 0xXXXXXXXX that lives in source as evidence the binary address is
# referenced — this matches how `recovery_coverage.py`'s scoped metric sees
# it.
ADDR_RE = re.compile(r"0x([0-9A-Fa-f]{8})\b")
FUN_REF_RE = re.compile(r"FUN_([0-9A-Fa-f]{8})\b")
FUN_RE = re.compile(r"^FUN_([0-9A-Fa-f]{6,16})$")

COMPLETED_STATUSES = {"recovered", "accepted", "done"}
EXTERNAL_STATUS = "external_dependency"
SOURCE_EXTENSIONS = {".h", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--src-root",
        type=Path,
        default=REPO_ROOT / "src" / "sdk",
        help="Source root to scan for Address: 0x... annotations.",
    )
    parser.add_argument(
        "--recovered-progress",
        type=Path,
        default=REPO_ROOT / "decomp" / "recovery" / "recovered_progress.json",
        help="Path to recovered_progress.json",
    )
    parser.add_argument(
        "--namespace",
        default="fa_full_2026_03_26",
        help="Namespace key inside recovered_progress.json",
    )
    parser.add_argument(
        "--queue-out",
        type=Path,
        help="Write phantom FUN_ tokens to this path (one per line).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Max sample tokens printed per category (default 30).",
    )
    parser.add_argument(
        "--bare-queue",
        type=Path,
        help="Write phantom tokens with no source path to this file (cleanup target).",
    )
    parser.add_argument(
        "--real-src-queue",
        type=Path,
        help="Write phantom tokens with an actual src/ path (real drift) to this file.",
    )
    return parser.parse_args()


def collect_annotated_addresses(src_root: Path) -> Set[int]:
    addrs: Set[int] = set()
    for path in src_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in ADDR_RE.finditer(text):
            addrs.add(int(match.group(1), 16))
        for match in FUN_REF_RE.finditer(text):
            addrs.add(int(match.group(1), 16))
    return addrs


def load_progress(recovered_path: Path, namespace: str) -> Dict[str, Dict]:
    if not recovered_path.exists():
        print(f"error: {recovered_path} does not exist", file=sys.stderr)
        sys.exit(1)
    payload = json.loads(recovered_path.read_text(encoding="utf-8"))
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    if not isinstance(recovered, dict):
        print(f"error: namespace {namespace!r} has no recovered map", file=sys.stderr)
        sys.exit(1)
    return recovered


def token_to_address(token: str) -> int | None:
    match = FUN_RE.match(token.strip())
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def classify(
    progress: Dict[str, Dict], annotated: Set[int]
) -> Tuple[List[Tuple[str, Dict]], List[Tuple[str, Dict]], Counter]:
    phantom: List[Tuple[str, Dict]] = []
    matched: List[Tuple[str, Dict]] = []
    status_counts: Counter = Counter()

    for token, info in progress.items():
        if not isinstance(info, dict):
            continue
        status = str(info.get("status", "")).strip().lower()
        status_counts[status] += 1
        if status not in COMPLETED_STATUSES:
            continue
        addr = token_to_address(token)
        if addr is None:
            continue
        if addr in annotated:
            matched.append((token, info))
        else:
            phantom.append((token, info))
    return phantom, matched, status_counts


def print_sample(label: str, items: List[Tuple[str, Dict]], limit: int) -> None:
    print(f"\n{label} (showing up to {limit}):")
    for token, info in items[:limit]:
        source = info.get("source") or info.get("sources") or ""
        if isinstance(source, list):
            source = ", ".join(source)
        note = info.get("note", "")
        line = f"  {token}  status={info.get('status', '')}"
        if source:
            line += f"  src={source}"
        if note:
            line += f'  note="{note[:80]}"'
        print(line)


def main() -> int:
    args = parse_args()
    annotated = collect_annotated_addresses(args.src_root)
    progress = load_progress(args.recovered_progress, args.namespace)

    phantom, matched, status_counts = classify(progress, annotated)

    total_progress_entries = len(progress)
    total_completed = sum(
        status_counts[s] for s in COMPLETED_STATUSES
    )
    total_external = status_counts.get(EXTERNAL_STATUS, 0)
    total_completed_non_external = total_completed - total_external

    print("Recovery Drift Audit")
    print("====================")
    print(f"Source root:        {args.src_root}")
    print(f"Progress DB:        {args.recovered_progress}")
    print(f"Namespace:          {args.namespace}")
    print()
    print(f"Annotated addresses in source (Address: 0x...):  {len(annotated):>8,}")
    print(f"Progress-DB entries total:                       {total_progress_entries:>8,}")
    print(f"  status in {{recovered, accepted, done}}:        {total_completed:>8,}")
    print(f"    of which external_dependency:                {total_external:>8,}")
    print(f"  non-external completed:                        {total_completed_non_external:>8,}")
    print()
    print(f"Matched (annotated AND completed):               {len(matched):>8,}")
    print(f"Phantom (completed but NOT annotated):           {len(phantom):>8,}")
    drift_pct = (len(phantom) / total_completed_non_external * 100) if total_completed_non_external else 0.0
    print(f"Drift ratio (phantom / non-ext completed):       {drift_pct:>7.2f}%")

    # Break phantom by status for more insight.
    phantom_by_status = Counter(info.get("status", "") for _, info in phantom)
    print()
    print("Phantom breakdown by status:")
    for status, count in phantom_by_status.most_common():
        print(f"  {status:>12}: {count:>6,}")

    # Break phantom by token-owner prefix (who "owns" these ghosts?)
    source_counter: Counter = Counter()
    noted_phantom: List[Tuple[str, Dict]] = []
    bare_phantom: List[Tuple[str, Dict]] = []
    for token, info in phantom:
        source = info.get("source") or info.get("sources") or ""
        if isinstance(source, list):
            source = ", ".join(source)
        if source:
            source_counter[Path(str(source)).parts[0] if str(source) else "?"] += 1
            noted_phantom.append((token, info))
        else:
            bare_phantom.append((token, info))

    print()
    print(f"Phantom with recorded source path:   {len(noted_phantom):>8,}")
    print(f"Phantom with no source path at all:  {len(bare_phantom):>8,}")

    if source_counter:
        print()
        print("Top source prefixes among phantoms:")
        for prefix, count in source_counter.most_common(15):
            print(f"  {prefix:>12}: {count:>6,}")

    if args.limit > 0:
        print_sample("Sample phantoms with recorded source", noted_phantom, args.limit)
        print_sample("Sample phantoms with NO source", bare_phantom, args.limit)

    def write_queue(path: Path, items: List[Tuple[str, Dict]], label: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(token for token, _ in items) + "\n",
            encoding="utf-8",
        )
        print(f"\nWrote {len(items):,} {label} tokens to {path}")

    if args.queue_out:
        write_queue(args.queue_out, phantom, "phantom")

    if args.bare_queue:
        write_queue(args.bare_queue, bare_phantom, "bare-path phantom")

    if args.real_src_queue:
        real_src_phantom = [
            (token, info)
            for token, info in noted_phantom
            if str((info.get("source") or info.get("sources") or "")).startswith("src")
        ]
        write_queue(args.real_src_queue, real_src_phantom, "real-src phantom")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
