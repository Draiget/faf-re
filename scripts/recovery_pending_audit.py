#!/usr/bin/env python3
"""
Audit partially reconstructed source markers against recovered_progress status.

Goal:
- If source code under src/sdk still says a function is pending reconstruction,
  make sure that function is not marked as completed in recovered_progress.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ADDRESS_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{8,16})")
PENDING_RECOVERY_RE = re.compile(
    r"(pending\s+(?:reconstruction|recovery|lift|source[- ]?lift)"
    r"|not\s+fully\s+reconstructed"
    r"|partially\s+(?:lifted|reconstructed)"
    r"|not\s+yet\s+source[- ]?lifted)",
    re.IGNORECASE,
)
SOURCE_FILE_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cpp", ".cc", ".cxx", ".inl", ".ipp"}

COMPLETED_STATUSES = {"recovered", "accepted", "done", "skip", "skipped", "external_dependency"}
TRACKED_PENDING_STATUSES = {"blocked", "needs_evidence", "in_progress", "wip"}


def normalize_fun_token(token: str | None) -> str | None:
    if not token:
        return None
    raw = token.strip()
    if not raw:
        return None
    raw = re.sub(r"^FUN_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^sub_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^0x", "", raw, flags=re.IGNORECASE)
    if not re.fullmatch(r"[0-9A-Fa-f]{6,16}", raw):
        return None
    value = int(raw, 16)
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def addr_to_token(addr_hex: str) -> str:
    value = int(addr_hex, 16)
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit pending-reconstruction markers against recovered_progress.")
    parser.add_argument("--src-root", default="src/sdk", help="Source root to scan (default: src/sdk).")
    parser.add_argument(
        "--recovered-progress",
        default="decomp/recovery/recovered_progress.json",
        help="Path to recovered_progress.json.",
    )
    parser.add_argument(
        "--namespace",
        default="fa_full_2026_03_26",
        help="Namespace key inside recovered_progress.json.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    parser.add_argument(
        "--queue-out",
        default="",
        help="Optional output path to write mismatched tokens (one FUN_ token per line).",
    )
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Treat pending markers with no progress status as mismatches too (recommended for CI).",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always return exit code 0 (for report-only mode).",
    )
    return parser.parse_args()


def iter_source_files(src_root: Path) -> list[Path]:
    return sorted(
        path
        for path in src_root.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_FILE_EXTENSIONS
    )


def load_progress_status_map(progress_path: Path, namespace: str) -> dict[str, str]:
    if not progress_path.exists():
        return {}
    payload = json.loads(progress_path.read_text(encoding="utf-8"))
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    if not isinstance(recovered, dict):
        return {}

    status_map: dict[str, str] = {}
    for token, info in recovered.items():
        if not isinstance(info, dict):
            continue
        status = str(info.get("status", "")).strip().lower()
        if not status:
            continue
        norm = normalize_fun_token(token)
        if not norm:
            continue
        status_map[norm] = status
    return status_map


def find_pending_marked_functions(src_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    files = iter_source_files(src_root)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        if not lines:
            continue

        address_hits = []
        for idx, line in enumerate(lines):
            match = ADDRESS_RE.search(line)
            if not match:
                continue
            address_hits.append((idx, match.group(1)))
        if not address_hits:
            continue

        for i, (start_idx, addr_hex) in enumerate(address_hits):
            next_idx = address_hits[i + 1][0] if i + 1 < len(address_hits) else len(lines)
            end_idx = min(next_idx, start_idx + 260)

            marker_line = None
            marker_text = ""
            for line_idx in range(start_idx, end_idx):
                line_text = lines[line_idx]
                if PENDING_RECOVERY_RE.search(line_text):
                    marker_line = line_idx + 1
                    marker_text = line_text.strip()
                    break

            if marker_line is None:
                continue

            findings.append(
                {
                    "file": str(path),
                    "address": f"0x{int(addr_hex, 16):08X}",
                    "token": addr_to_token(addr_hex),
                    "address_line": start_idx + 1,
                    "marker_line": marker_line,
                    "marker_text": marker_text,
                }
            )

    return findings


def build_report(
    *,
    src_root: Path,
    namespace: str,
    recovered_progress_path: Path,
    include_untracked: bool,
) -> dict[str, Any]:
    findings = find_pending_marked_functions(src_root)
    status_map = load_progress_status_map(recovered_progress_path, namespace)

    tracked_ok: list[dict[str, Any]] = []
    mismatched_completed: list[dict[str, Any]] = []
    mismatched_untracked: list[dict[str, Any]] = []
    other_status: list[dict[str, Any]] = []

    for row in findings:
        status = (status_map.get(row["token"]) or "").strip().lower()
        entry = dict(row)
        entry["status"] = status

        if status in TRACKED_PENDING_STATUSES:
            tracked_ok.append(entry)
        elif status in COMPLETED_STATUSES:
            mismatched_completed.append(entry)
        elif not status:
            if include_untracked:
                mismatched_untracked.append(entry)
            else:
                other_status.append(entry)
        else:
            other_status.append(entry)

    mismatched = mismatched_completed + mismatched_untracked

    report = {
        "source_root": str(src_root),
        "recovered_progress": str(recovered_progress_path),
        "namespace": namespace,
        "pending_marked_count": len(findings),
        "tracked_pending_count": len(tracked_ok),
        "mismatch_completed_count": len(mismatched_completed),
        "mismatch_untracked_count": len(mismatched_untracked),
        "other_status_count": len(other_status),
        "mismatched_count": len(mismatched),
        "tracked_pending": tracked_ok,
        "mismatched_completed": mismatched_completed,
        "mismatched_untracked": mismatched_untracked,
        "other_status": other_status,
        "mismatched_tokens": sorted({item["token"] for item in mismatched}),
    }
    return report


def print_text_report(report: dict[str, Any]) -> None:
    print("Recovery Pending Audit")
    print("======================")
    print(f"Source root: {report['source_root']}")
    print(f"Recovered progress: {report['recovered_progress']}")
    print(f"Namespace: {report['namespace']}")
    print()
    print(f"Pending-marked functions: {report['pending_marked_count']}")
    print(f"Tracked as pending (blocked/needs_evidence/in_progress/wip): {report['tracked_pending_count']}")
    print(f"Mismatched completed statuses: {report['mismatch_completed_count']}")
    print(f"Mismatched untracked statuses: {report['mismatch_untracked_count']}")
    print(f"Other statuses: {report['other_status_count']}")
    print()
    if report["mismatched_count"] == 0:
        print("No mismatches found.")
        return

    print("Mismatches")
    print("----------")
    for row in report["mismatched_completed"]:
        print(
            f"- {row['token']} status={row['status']} "
            f"{row['file']}:{row['marker_line']} "
            f"marker=\"{row['marker_text']}\""
        )
    for row in report["mismatched_untracked"]:
        print(
            f"- {row['token']} status=<missing> "
            f"{row['file']}:{row['marker_line']} "
            f"marker=\"{row['marker_text']}\""
        )


def maybe_write_queue(report: dict[str, Any], queue_out: Path | None) -> None:
    if not queue_out:
        return
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    tokens = report.get("mismatched_tokens", [])
    queue_out.write_text("\n".join(tokens) + ("\n" if tokens else ""), encoding="utf-8")


def main() -> int:
    args = parse_args()
    src_root = Path(args.src_root).resolve()
    recovered_progress_path = Path(args.recovered_progress).resolve()
    queue_out = Path(args.queue_out).resolve() if args.queue_out else None

    if not src_root.exists():
        print(f"error: source root not found: {src_root}", file=sys.stderr)
        return 2
    if not recovered_progress_path.exists():
        print(f"error: recovered_progress not found: {recovered_progress_path}", file=sys.stderr)
        return 2

    report = build_report(
        src_root=src_root,
        namespace=args.namespace,
        recovered_progress_path=recovered_progress_path,
        include_untracked=bool(args.include_untracked),
    )

    maybe_write_queue(report, queue_out)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report)

    if args.no_fail:
        return 0
    return 1 if report.get("mismatched_count", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
