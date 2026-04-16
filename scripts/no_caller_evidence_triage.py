#!/usr/bin/env python3
"""
Triage no-caller recovered functions using callgraph/xref evidence.

Goal:
- Start from tokens with callers_count == 0.
- Filter to annotated/completed recovered functions (optional).
- Classify each token into buckets useful for recovery/runtime-probe planning:
  - potential_direct_or_indirect_callsite
  - indirect_dispatch_candidate
  - registration_callback_lane
  - root_or_entry_lane
  - no_evidence_orphan
  - other_no_caller

This does not prove runtime reachability. It provides static evidence signals and
queues for focused follow-up (including runtime instrumentation).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


COMPLETED_STATUSES = {"recovered", "accepted", "done"}


class ProgressPrinter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def update(self, label: str, cur: int, total: int) -> None:
        if not self.enabled:
            return
        pct = 100.0 if total <= 0 else (cur * 100.0 / total)
        print(f"\r[{label}] processed {cur}/{total} ({pct:5.1f}%)", end="", flush=True)

    def done(self) -> None:
        if self.enabled:
            print()


@dataclass
class TokenRow:
    token: str
    status: str
    callers_count: int
    callees_count: int
    incoming_xrefs_count: int
    incoming_xrefs_code_count: int
    incoming_xrefs_data_count: int
    data_refs_count: int
    string_refs_count: int
    xref_total: int
    xref_code_total: int
    xref_data_total: int
    xref_code_call_instr: int
    xref_code_offset: int
    xref_code_mov_offset: int
    xref_code_push_offset: int
    xref_owner_distinct: int
    xref_owner_reflection_like: int
    dataref_to_total: int
    dataref_to_owner_distinct: int
    dataref_to_rodata_like: int
    bucket: str
    reason: str
    severity: str
    first_source_hit: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def normalize_status(s: str | None) -> str:
    return str(s or "").strip().lower()


def load_progress_status_map(progress_path: Path, namespace: str) -> dict[str, str]:
    if not progress_path.exists():
        return {}
    try:
        payload = load_json(progress_path)
    except Exception:
        return {}
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    out: dict[str, str] = {}
    if not isinstance(recovered, dict):
        return out
    for token, meta in recovered.items():
        status = ""
        if isinstance(meta, dict):
            status = normalize_status(meta.get("status"))
        out[str(token)] = status
    return out


def load_audit_token_map(audit_json_path: Path) -> dict[str, dict[str, Any]]:
    if not audit_json_path.exists():
        return {}
    try:
        payload = load_json(audit_json_path)
    except Exception:
        return {}
    tokens = payload.get("tokens", {})
    if not isinstance(tokens, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for token, entry in tokens.items():
        if isinstance(entry, dict):
            out[str(token)] = entry
    return out


def resolve_out_path(repo_root: Path, raw: str, default_abs: Path) -> Path:
    if not raw:
        return default_abs
    p = Path(raw)
    if p.is_absolute():
        return p.resolve()
    return (repo_root / p).resolve()


def create_temp_token_table(conn: sqlite3.Connection, tokens: list[str]) -> None:
    conn.execute("DROP TABLE IF EXISTS _triage_tokens")
    conn.execute("CREATE TEMP TABLE _triage_tokens(token TEXT PRIMARY KEY)")
    conn.executemany("INSERT INTO _triage_tokens(token) VALUES (?)", ((t,) for t in tokens))


def classify_bucket(
    *,
    callers_count: int,
    callees_count: int,
    incoming_xrefs_count: int,
    incoming_xrefs_code_count: int,
    incoming_xrefs_data_count: int,
    data_refs_count: int,
    string_refs_count: int,
    xref_code_call_instr: int,
    xref_code_offset: int,
    xref_owner_reflection_like: int,
    dataref_to_total: int,
) -> tuple[str, str, str]:
    # High-confidence likely orphan: no incoming/static evidence and no outgoing calls.
    if (
        incoming_xrefs_count == 0
        and data_refs_count == 0
        and string_refs_count == 0
        and dataref_to_total == 0
        and callees_count == 0
    ):
        return (
            "no_evidence_orphan",
            "No callers, no incoming xrefs, no data/string refs, no outgoing calls in index.",
            "high",
        )

    # Explicit call-like code xrefs, but missing caller edges in callgraph.
    if xref_code_call_instr > 0:
        return (
            "potential_direct_or_indirect_callsite",
            "Code xref lines contain call-like instructions while callers_count is zero.",
            "high",
        )

    # Function pointer registration / callback slots via offset stores or data xrefs.
    if xref_code_offset > 0 or incoming_xrefs_data_count > 0 or dataref_to_total > 0:
        reflection_weighted = xref_owner_reflection_like > 0 and xref_owner_reflection_like * 2 >= max(1, xref_code_offset)
        if reflection_weighted and incoming_xrefs_code_count <= 2:
            return (
                "registration_callback_lane",
                "Mostly typeinfo/serializer/registration style owners storing function pointers.",
                "medium",
            )
        return (
            "indirect_dispatch_candidate",
            "Pointer/offset or data-ref evidence suggests indirect dispatch or callback usage.",
            "medium",
        )

    # No callers but does call out to others: likely root/bootstrap/entry-like.
    if callees_count > 0:
        return (
            "root_or_entry_lane",
            "No incoming callers but has outgoing calls; likely root/entry/init lane.",
            "low",
        )

    # Remaining no-caller with some weak evidence.
    return (
        "other_no_caller",
        "No-caller token with partial evidence that does not fit stronger buckets.",
        "low",
    )


def build_markdown(
    *,
    generated_utc: str,
    callgraph_db: Path,
    recovered_progress: Path,
    namespace: str,
    audit_json: Path | None,
    summary: dict[str, Any],
    bucket_counts: Counter[str],
    severity_counts: Counter[str],
    top_rows: list[TokenRow],
    top_limit: int,
) -> str:
    lines: list[str] = []
    lines.append("# No-Caller Evidence Triage")
    lines.append("")
    lines.append(f"- Generated (UTC): `{generated_utc}`")
    lines.append(f"- Callgraph DB: `{callgraph_db}`")
    lines.append(f"- Recovered progress: `{recovered_progress}` (namespace: `{namespace}`)")
    if audit_json is not None:
        lines.append(f"- Audit JSON: `{audit_json}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for k in (
        "db_no_caller_tokens",
        "candidate_tokens_after_filters",
        "filtered_out_non_annotated",
        "filtered_out_non_completed",
    ):
        lines.append(f"- {k}: `{summary.get(k, 0)}`")
    lines.append("")
    lines.append("## Buckets")
    lines.append("")
    for k, v in bucket_counts.most_common():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("## Severity")
    lines.append("")
    for k, v in severity_counts.most_common():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append(f"## Top Priorities (up to {top_limit})")
    lines.append("")
    lines.append("| Token | Bucket | Severity | Status | in_xrefs(code/data) | callees | code_call | code_offset | data_to | first_source_hit |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---|")
    for row in top_rows[:top_limit]:
        lines.append(
            f"| `{row.token}` | `{row.bucket}` | `{row.severity}` | `{row.status}` | "
            f"`{row.incoming_xrefs_count} ({row.incoming_xrefs_code_count}/{row.incoming_xrefs_data_count})` | "
            f"`{row.callees_count}` | `{row.xref_code_call_instr}` | `{row.xref_code_offset}` | `{row.dataref_to_total}` | "
            f"`{row.first_source_hit}` |"
        )
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- `potential_direct_or_indirect_callsite`: strongest static signal that call edges may be missing from current index extraction.")
    lines.append("- `indirect_dispatch_candidate` / `registration_callback_lane`: usually function-pointer, vtable, serializer, or callback lanes.")
    lines.append("- `no_evidence_orphan`: best candidates for deep validation (source annotation mistakes, external-only lanes, or dead/unreached code).")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify no-caller recovered functions using callgraph/xref evidence.")
    parser.add_argument("--repo-root", default=".", help="Repository root (default: current directory).")
    parser.add_argument(
        "--callgraph-db",
        default="decomp/recovery/disasm/fa_full_2026_03_26/_callgraph_index.sqlite",
        help="Path to namespace callgraph sqlite.",
    )
    parser.add_argument(
        "--recovered-progress",
        default="decomp/recovery/recovered_progress.json",
        help="Path to recovered_progress.json.",
    )
    parser.add_argument("--namespace", default="fa_full_2026_03_26", help="Namespace key for recovered_progress.")
    parser.add_argument(
        "--audit-json",
        default="decomp/recovery/disasm/fa_full_2026_03_26/_recovered_address_usage_audit.json",
        help="Optional address-annotation audit JSON from recovered_address_usage_audit.py.",
    )
    parser.add_argument(
        "--only-annotated",
        action="store_true",
        help="Restrict to tokens present in --audit-json source-annotated set.",
    )
    parser.add_argument(
        "--only-completed",
        action="store_true",
        help="Restrict to completed progress statuses (recovered,accepted,done by default).",
    )
    parser.add_argument(
        "--completed-statuses",
        default="recovered,accepted,done",
        help="Comma-separated statuses considered completed when --only-completed is set.",
    )
    parser.add_argument("--token-limit", type=int, default=0, help="Optional cap on processed tokens (0 = all).")
    parser.add_argument(
        "--json-out",
        default="",
        help="JSON report path (default: next to callgraph DB).",
    )
    parser.add_argument(
        "--markdown-out",
        default="",
        help="Markdown report path (default: next to callgraph DB).",
    )
    parser.add_argument(
        "--queue-prefix",
        default="",
        help="Queue file prefix path without suffix (default: next to callgraph DB).",
    )
    parser.add_argument("--markdown-top", type=int, default=250, help="Max top rows in markdown table.")
    parser.add_argument("--no-progress", action="store_true", help="Disable carriage-return progress output.")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    callgraph_db = resolve_out_path(repo_root, args.callgraph_db, Path(args.callgraph_db).resolve())
    recovered_progress = resolve_out_path(repo_root, args.recovered_progress, Path(args.recovered_progress).resolve())
    audit_json = resolve_out_path(repo_root, args.audit_json, Path(args.audit_json).resolve()) if args.audit_json else None

    if not callgraph_db.exists():
        print(f"error: callgraph db not found: {callgraph_db}", file=sys.stderr)
        return 2

    default_json_out = callgraph_db.parent / "_no_caller_evidence_triage.json"
    default_md_out = callgraph_db.parent / "_no_caller_evidence_triage.md"
    default_queue_prefix = callgraph_db.parent / "_no_caller_evidence"

    json_out = resolve_out_path(repo_root, args.json_out, default_json_out)
    markdown_out = resolve_out_path(repo_root, args.markdown_out, default_md_out)
    queue_prefix = resolve_out_path(repo_root, args.queue_prefix, default_queue_prefix)

    progress_enabled = not args.no_progress
    completed_statuses = {
        normalize_status(s)
        for s in str(args.completed_statuses).split(",")
        if normalize_status(s)
    }
    if not completed_statuses:
        completed_statuses = set(COMPLETED_STATUSES)

    progress_status_map = load_progress_status_map(recovered_progress, args.namespace)
    audit_token_map = load_audit_token_map(audit_json) if audit_json is not None else {}

    conn = sqlite3.connect(str(callgraph_db))
    conn.row_factory = sqlite3.Row

    db_no_callers = [str(r["token"]) for r in conn.execute("SELECT token FROM functions WHERE callers_count = 0 ORDER BY token")]
    db_no_callers_set = set(db_no_callers)

    candidate_tokens = db_no_callers
    filtered_non_annotated = 0
    filtered_non_completed = 0

    if args.only_annotated:
        if not audit_token_map:
            print("error: --only-annotated requested but audit-json missing/unreadable.", file=sys.stderr)
            return 3
        annotated_set = set(audit_token_map.keys())
        candidate_tokens = [t for t in candidate_tokens if t in annotated_set]
        filtered_non_annotated = len(db_no_callers) - len(candidate_tokens)

    if args.only_completed:
        pre = len(candidate_tokens)
        filtered: list[str] = []
        for token in candidate_tokens:
            status = normalize_status(progress_status_map.get(token))
            if not status and token in audit_token_map:
                status = normalize_status(audit_token_map[token].get("progress_status"))
            if status in completed_statuses:
                filtered.append(token)
        candidate_tokens = filtered
        filtered_non_completed = pre - len(candidate_tokens)

    if args.token_limit and args.token_limit > 0:
        candidate_tokens = candidate_tokens[: args.token_limit]

    if not candidate_tokens:
        print("No candidate no-caller tokens after filters.")
        return 0

    create_temp_token_table(conn, candidate_tokens)

    metrics_map: dict[str, dict[str, int]] = {}
    for row in conn.execute(
        """
        SELECT
            t.token AS token,
            COALESCE(f.callers_count, 0) AS callers_count,
            COALESCE(f.callees_count, 0) AS callees_count,
            COALESCE(f.incoming_xrefs_count, 0) AS incoming_xrefs_count,
            COALESCE(f.incoming_xrefs_code_count, 0) AS incoming_xrefs_code_count,
            COALESCE(f.incoming_xrefs_data_count, 0) AS incoming_xrefs_data_count,
            COALESCE(f.data_refs_count, 0) AS data_refs_count,
            COALESCE(f.string_refs_count, 0) AS string_refs_count
        FROM _triage_tokens t
        LEFT JOIN functions f ON f.token = t.token
        """
    ):
        token = str(row["token"])
        metrics_map[token] = {
            "callers_count": int(row["callers_count"] or 0),
            "callees_count": int(row["callees_count"] or 0),
            "incoming_xrefs_count": int(row["incoming_xrefs_count"] or 0),
            "incoming_xrefs_code_count": int(row["incoming_xrefs_code_count"] or 0),
            "incoming_xrefs_data_count": int(row["incoming_xrefs_data_count"] or 0),
            "data_refs_count": int(row["data_refs_count"] or 0),
            "string_refs_count": int(row["string_refs_count"] or 0),
        }

    xref_agg: dict[str, dict[str, int]] = {}
    for row in conn.execute(
        """
        SELECT
            x.target_token AS token,
            COUNT(*) AS xref_total,
            SUM(CASE WHEN x.kind = 'code' THEN 1 ELSE 0 END) AS xref_code_total,
            SUM(CASE WHEN x.kind = 'data' THEN 1 ELSE 0 END) AS xref_data_total,
            SUM(
                CASE
                    WHEN x.kind = 'code' AND lower(trim(COALESCE(x.line, ''))) LIKE 'call %'
                    THEN 1
                    ELSE 0
                END
            ) AS xref_code_call_instr,
            SUM(CASE WHEN x.kind = 'code' AND lower(COALESCE(x.line, '')) LIKE '%offset%' THEN 1 ELSE 0 END) AS xref_code_offset,
            SUM(CASE WHEN x.kind = 'code' AND lower(COALESCE(x.line, '')) LIKE 'mov %' AND lower(COALESCE(x.line, '')) LIKE '%offset%' THEN 1 ELSE 0 END) AS xref_code_mov_offset,
            SUM(CASE WHEN x.kind = 'code' AND lower(COALESCE(x.line, '')) LIKE 'push %' AND lower(COALESCE(x.line, '')) LIKE '%offset%' THEN 1 ELSE 0 END) AS xref_code_push_offset,
            COUNT(DISTINCT CASE WHEN x.owner_token IS NOT NULL AND x.owner_token != '' THEN x.owner_token END) AS xref_owner_distinct,
            SUM(
                CASE
                    WHEN lower(COALESCE(x.owner_name, '')) LIKE '%typeinfo%'
                      OR lower(COALESCE(x.owner_name, '')) LIKE '%serializer%'
                      OR lower(COALESCE(x.owner_name, '')) LIKE '%rtti%'
                    THEN 1
                    ELSE 0
                END
            ) AS xref_owner_reflection_like
        FROM incoming_xrefs x
        JOIN _triage_tokens t ON t.token = x.target_token
        GROUP BY x.target_token
        """
    ):
        token = str(row["token"])
        xref_agg[token] = {
            "xref_total": int(row["xref_total"] or 0),
            "xref_code_total": int(row["xref_code_total"] or 0),
            "xref_data_total": int(row["xref_data_total"] or 0),
            "xref_code_call_instr": int(row["xref_code_call_instr"] or 0),
            "xref_code_offset": int(row["xref_code_offset"] or 0),
            "xref_code_mov_offset": int(row["xref_code_mov_offset"] or 0),
            "xref_code_push_offset": int(row["xref_code_push_offset"] or 0),
            "xref_owner_distinct": int(row["xref_owner_distinct"] or 0),
            "xref_owner_reflection_like": int(row["xref_owner_reflection_like"] or 0),
        }

    data_to_agg: dict[str, dict[str, int]] = {}
    for row in conn.execute(
        """
        SELECT
            d.to_token AS token,
            COUNT(*) AS dataref_to_total,
            COUNT(DISTINCT d.owner_token) AS dataref_to_owner_distinct,
            SUM(
                CASE
                    WHEN lower(COALESCE(d.to_segment, '')) LIKE '%rdata%'
                      OR lower(COALESCE(d.to_segment, '')) LIKE '%data%'
                    THEN 1
                    ELSE 0
                END
            ) AS dataref_to_rodata_like
        FROM data_refs d
        JOIN _triage_tokens t ON t.token = d.to_token
        GROUP BY d.to_token
        """
    ):
        token = str(row["token"])
        data_to_agg[token] = {
            "dataref_to_total": int(row["dataref_to_total"] or 0),
            "dataref_to_owner_distinct": int(row["dataref_to_owner_distinct"] or 0),
            "dataref_to_rodata_like": int(row["dataref_to_rodata_like"] or 0),
        }

    token_rows: list[TokenRow] = []
    bucket_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    progress = ProgressPrinter(progress_enabled)
    total = len(candidate_tokens)

    for idx, token in enumerate(candidate_tokens, start=1):
        progress.update("triage", idx, total)
        m = metrics_map.get(token, {})
        x = xref_agg.get(token, {})
        d = data_to_agg.get(token, {})
        status = normalize_status(progress_status_map.get(token))
        if not status and token in audit_token_map:
            status = normalize_status(audit_token_map[token].get("progress_status"))

        callers_count = int(m.get("callers_count", 0))
        callees_count = int(m.get("callees_count", 0))
        incoming_xrefs_count = int(m.get("incoming_xrefs_count", 0))
        incoming_xrefs_code_count = int(m.get("incoming_xrefs_code_count", 0))
        incoming_xrefs_data_count = int(m.get("incoming_xrefs_data_count", 0))
        data_refs_count = int(m.get("data_refs_count", 0))
        string_refs_count = int(m.get("string_refs_count", 0))
        xref_total = int(x.get("xref_total", 0))
        xref_code_total = int(x.get("xref_code_total", 0))
        xref_data_total = int(x.get("xref_data_total", 0))
        xref_code_call_instr = int(x.get("xref_code_call_instr", 0))
        xref_code_offset = int(x.get("xref_code_offset", 0))
        xref_code_mov_offset = int(x.get("xref_code_mov_offset", 0))
        xref_code_push_offset = int(x.get("xref_code_push_offset", 0))
        xref_owner_distinct = int(x.get("xref_owner_distinct", 0))
        xref_owner_reflection_like = int(x.get("xref_owner_reflection_like", 0))
        dataref_to_total = int(d.get("dataref_to_total", 0))
        dataref_to_owner_distinct = int(d.get("dataref_to_owner_distinct", 0))
        dataref_to_rodata_like = int(d.get("dataref_to_rodata_like", 0))

        bucket, reason, severity = classify_bucket(
            callers_count=callers_count,
            callees_count=callees_count,
            incoming_xrefs_count=incoming_xrefs_count,
            incoming_xrefs_code_count=incoming_xrefs_code_count,
            incoming_xrefs_data_count=incoming_xrefs_data_count,
            data_refs_count=data_refs_count,
            string_refs_count=string_refs_count,
            xref_code_call_instr=xref_code_call_instr,
            xref_code_offset=xref_code_offset,
            xref_owner_reflection_like=xref_owner_reflection_like,
            dataref_to_total=dataref_to_total,
        )

        first_source_hit = ""
        if token in audit_token_map:
            hits = audit_token_map[token].get("source_hits", [])
            if isinstance(hits, list) and hits:
                hit = hits[0]
                if isinstance(hit, dict):
                    rel = str(hit.get("file_rel", ""))
                    line = int(hit.get("line", 0) or 0)
                    first_source_hit = f"{rel}:{line}" if rel else ""

        token_row = TokenRow(
            token=token,
            status=status,
            callers_count=callers_count,
            callees_count=callees_count,
            incoming_xrefs_count=incoming_xrefs_count,
            incoming_xrefs_code_count=incoming_xrefs_code_count,
            incoming_xrefs_data_count=incoming_xrefs_data_count,
            data_refs_count=data_refs_count,
            string_refs_count=string_refs_count,
            xref_total=xref_total,
            xref_code_total=xref_code_total,
            xref_data_total=xref_data_total,
            xref_code_call_instr=xref_code_call_instr,
            xref_code_offset=xref_code_offset,
            xref_code_mov_offset=xref_code_mov_offset,
            xref_code_push_offset=xref_code_push_offset,
            xref_owner_distinct=xref_owner_distinct,
            xref_owner_reflection_like=xref_owner_reflection_like,
            dataref_to_total=dataref_to_total,
            dataref_to_owner_distinct=dataref_to_owner_distinct,
            dataref_to_rodata_like=dataref_to_rodata_like,
            bucket=bucket,
            reason=reason,
            severity=severity,
            first_source_hit=first_source_hit,
        )
        token_rows.append(token_row)
        bucket_counts[bucket] += 1
        severity_counts[severity] += 1

    progress.done()

    # Priority order for follow-up and runtime probing.
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    bucket_rank = {
        "potential_direct_or_indirect_callsite": 0,
        "no_evidence_orphan": 1,
        "indirect_dispatch_candidate": 2,
        "registration_callback_lane": 3,
        "root_or_entry_lane": 4,
        "other_no_caller": 5,
    }
    token_rows.sort(
        key=lambda r: (
            severity_rank.get(r.severity, 99),
            bucket_rank.get(r.bucket, 99),
            -r.xref_code_call_instr,
            -r.incoming_xrefs_count,
            r.token,
        )
    )

    # Bucket-specific queues.
    by_bucket: dict[str, list[str]] = {}
    for row in token_rows:
        by_bucket.setdefault(row.bucket, []).append(row.token)

    priority_queue = [r.token for r in token_rows if r.bucket in {
        "potential_direct_or_indirect_callsite",
        "no_evidence_orphan",
        "indirect_dispatch_candidate",
        "registration_callback_lane",
    }]

    summary = {
        "db_no_caller_tokens": len(db_no_callers),
        "candidate_tokens_after_filters": len(candidate_tokens),
        "filtered_out_non_annotated": filtered_non_annotated,
        "filtered_out_non_completed": filtered_non_completed,
    }

    report = {
        "generated_utc": utc_now_iso(),
        "callgraph_db": str(callgraph_db),
        "recovered_progress": str(recovered_progress),
        "namespace": args.namespace,
        "audit_json": str(audit_json) if audit_json is not None else None,
        "filters": {
            "only_annotated": bool(args.only_annotated),
            "only_completed": bool(args.only_completed),
            "completed_statuses": sorted(completed_statuses),
            "token_limit": int(args.token_limit),
        },
        "summary": summary,
        "bucket_counts": dict(bucket_counts),
        "severity_counts": dict(severity_counts),
        "priority_queue_size": len(priority_queue),
        "tokens": [
            {
                "token": r.token,
                "status": r.status,
                "bucket": r.bucket,
                "severity": r.severity,
                "reason": r.reason,
                "callers_count": r.callers_count,
                "callees_count": r.callees_count,
                "incoming_xrefs_count": r.incoming_xrefs_count,
                "incoming_xrefs_code_count": r.incoming_xrefs_code_count,
                "incoming_xrefs_data_count": r.incoming_xrefs_data_count,
                "data_refs_count": r.data_refs_count,
                "string_refs_count": r.string_refs_count,
                "xref_total": r.xref_total,
                "xref_code_total": r.xref_code_total,
                "xref_data_total": r.xref_data_total,
                "xref_code_call_instr": r.xref_code_call_instr,
                "xref_code_offset": r.xref_code_offset,
                "xref_code_mov_offset": r.xref_code_mov_offset,
                "xref_code_push_offset": r.xref_code_push_offset,
                "xref_owner_distinct": r.xref_owner_distinct,
                "xref_owner_reflection_like": r.xref_owner_reflection_like,
                "dataref_to_total": r.dataref_to_total,
                "dataref_to_owner_distinct": r.dataref_to_owner_distinct,
                "dataref_to_rodata_like": r.dataref_to_rodata_like,
                "first_source_hit": r.first_source_hit,
            }
            for r in token_rows
        ],
    }

    md = build_markdown(
        generated_utc=report["generated_utc"],
        callgraph_db=callgraph_db,
        recovered_progress=recovered_progress,
        namespace=args.namespace,
        audit_json=audit_json if audit_json and audit_json.exists() else None,
        summary=summary,
        bucket_counts=bucket_counts,
        severity_counts=severity_counts,
        top_rows=token_rows,
        top_limit=max(0, int(args.markdown_top)),
    )

    ensure_parent(json_out)
    ensure_parent(markdown_out)
    ensure_parent(queue_prefix)

    json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_out.write_text(md, encoding="utf-8")

    # Queue outputs (always rewrite full known set to avoid stale files from old runs).
    bucket_order = [
        "potential_direct_or_indirect_callsite",
        "indirect_dispatch_candidate",
        "registration_callback_lane",
        "root_or_entry_lane",
        "no_evidence_orphan",
        "other_no_caller",
    ]
    for bucket in bucket_order:
        tokens = by_bucket.get(bucket, [])
        out = queue_prefix.parent / f"{queue_prefix.name}_{bucket}.txt"
        out.write_text("\n".join(tokens) + ("\n" if tokens else ""), encoding="utf-8")
    priority_out = queue_prefix.parent / f"{queue_prefix.name}_priority.txt"
    priority_out.write_text("\n".join(priority_queue) + ("\n" if priority_queue else ""), encoding="utf-8")

    print(f"DB no-caller tokens: {len(db_no_callers)}")
    print(f"Candidates after filters: {len(candidate_tokens)}")
    print(f"Priority queue size: {len(priority_queue)}")
    print(f"JSON report: {json_out}")
    print(f"Markdown report: {markdown_out}")
    print(f"Queue prefix: {queue_prefix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
