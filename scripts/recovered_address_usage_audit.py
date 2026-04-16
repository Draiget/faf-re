#!/usr/bin/env python3
"""
Audit recovered Address-annotated SDK functions against FA callgraph evidence.

What this script checks:
1) Scans src/sdk C/C++ files for Doxygen blocks with `Address: 0x...` (and FUN_ tokens).
2) Resolves those annotations to FUN_XXXXXXXX tokens.
3) Queries _callgraph_index.sqlite for call/xref evidence.
4) Classifies each token for connectivity/usage sanity.
5) Writes detailed JSON + Markdown reports and a suspicious-token queue.

The default output paths are placed next to the callgraph DB, so reports stay
close to the namespace evidence they were computed from.
"""

from __future__ import annotations

import argparse
import bisect
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any


DOXYGEN_BLOCK_RE = re.compile(r"/\*\*.*?\*/", re.S)
ADDRESS_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{6,16})(?:\s*\(([^)]*)\))?")
FUN_TOKEN_RE = re.compile(r"\bFUN_([0-9A-Fa-f]{6,16})\b")
SOURCE_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".inl", ".ipp"}
COMPLETED_STATUSES = {"recovered", "accepted", "done"}


@dataclass(frozen=True)
class AnnotationHit:
    file_abs: str
    file_rel: str
    line: int


@dataclass
class TokenUsage:
    token: str
    exists_in_db: bool
    callers_all: int
    callees_all: int
    callers_internal: int
    callees_internal: int
    incoming_xrefs: int
    incoming_xrefs_code: int
    incoming_xrefs_data: int
    data_refs: int
    string_refs: int
    component_size: int
    reason: str
    severity: str
    progress_status: str | None


class ProgressPrinter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._last_len = 0

    def update(self, label: str, current: int, total: int) -> None:
        if not self.enabled:
            return
        pct = 100.0 if total <= 0 else (current * 100.0 / total)
        msg = f"\r[{label}] processed {current}/{total} ({pct:5.1f}%)"
        self._last_len = max(self._last_len, len(msg))
        print(msg, end="", flush=True)

    def done(self) -> None:
        if self.enabled:
            print()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_fun_token(raw: str | None) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    text = re.sub(r"^FUN_", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^sub_", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^0x", "", text, flags=re.IGNORECASE)
    if not re.fullmatch(r"[0-9A-Fa-f]{6,16}", text):
        return None
    value = int(text, 16)
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def build_line_starts(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def offset_to_line(line_starts: list[int], offset: int) -> int:
    return bisect.bisect_right(line_starts, offset)


def iter_source_files(src_root: Path) -> list[Path]:
    files: list[Path] = []
    for p in src_root.rglob("*"):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS:
            files.append(p)
    files.sort()
    return files


def extract_tokens_from_doxygen(block: str) -> set[str]:
    out: set[str] = set()
    for match in ADDRESS_RE.finditer(block):
        token = normalize_fun_token(match.group(1))
        if token:
            out.add(token)
        payload = (match.group(2) or "").strip()
        if payload:
            maybe = normalize_fun_token(payload.split(",")[0].strip())
            if maybe:
                out.add(maybe)
    for match in FUN_TOKEN_RE.finditer(block):
        token = normalize_fun_token(match.group(1))
        if token:
            out.add(token)
    return out


def scan_source_annotations(repo_root: Path, src_root: Path, show_progress: bool) -> dict[str, list[AnnotationHit]]:
    hits_by_token: dict[str, list[AnnotationHit]] = defaultdict(list)
    files = iter_source_files(src_root)
    progress = ProgressPrinter(show_progress)
    total = len(files)

    for idx, path in enumerate(files, start=1):
        progress.update("scan", idx, total)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        line_starts = build_line_starts(text)
        rel = path
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            pass
        rel_str = rel.as_posix()
        abs_str = str(path.resolve())
        for block_match in DOXYGEN_BLOCK_RE.finditer(text):
            tokens = extract_tokens_from_doxygen(block_match.group(0))
            if not tokens:
                continue
            line = offset_to_line(line_starts, block_match.start())
            for token in tokens:
                hits_by_token[token].append(
                    AnnotationHit(
                        file_abs=abs_str,
                        file_rel=rel_str,
                        line=line,
                    )
                )

    progress.done()
    return hits_by_token


def load_progress_status_map(progress_path: Path, namespace: str) -> dict[str, str]:
    if not progress_path.exists():
        return {}
    try:
        payload = json.loads(progress_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    out: dict[str, str] = {}
    if not isinstance(recovered, dict):
        return out
    for raw_token, meta in recovered.items():
        token = normalize_fun_token(raw_token)
        if not token:
            continue
        status = ""
        if isinstance(meta, dict):
            status = str(meta.get("status", "")).strip().lower()
        out[token] = status
    return out


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def create_temp_token_table(conn: sqlite3.Connection, tokens: list[str]) -> None:
    conn.execute("DROP TABLE IF EXISTS _audit_tokens")
    conn.execute("CREATE TEMP TABLE _audit_tokens(token TEXT PRIMARY KEY)")
    conn.executemany("INSERT INTO _audit_tokens(token) VALUES (?)", ((t,) for t in tokens))


def load_callgraph_maps(conn: sqlite3.Connection) -> tuple[dict[str, dict[str, int | None]], dict[str, int], dict[str, int], dict[str, int], dict[str, int], set[tuple[str, str]]]:
    metrics: dict[str, dict[str, int | None]] = {}
    callers_all: dict[str, int] = {}
    callees_all: dict[str, int] = {}
    callers_internal: dict[str, int] = {}
    callees_internal: dict[str, int] = {}
    internal_edges: set[tuple[str, str]] = set()

    for row in conn.execute(
        """
        SELECT
            t.token AS token,
            f.ea AS ea,
            COALESCE(f.callers_count, 0) AS callers_count,
            COALESCE(f.callees_count, 0) AS callees_count,
            COALESCE(f.incoming_xrefs_count, 0) AS incoming_xrefs_count,
            COALESCE(f.incoming_xrefs_code_count, 0) AS incoming_xrefs_code_count,
            COALESCE(f.incoming_xrefs_data_count, 0) AS incoming_xrefs_data_count,
            COALESCE(f.data_refs_count, 0) AS data_refs_count,
            COALESCE(f.string_refs_count, 0) AS string_refs_count
        FROM _audit_tokens t
        LEFT JOIN functions f ON f.token = t.token
        """
    ):
        token = str(row["token"])
        metrics[token] = {
            "ea": int(row["ea"]) if row["ea"] is not None else None,
            "callers_count": int(row["callers_count"] or 0),
            "callees_count": int(row["callees_count"] or 0),
            "incoming_xrefs_count": int(row["incoming_xrefs_count"] or 0),
            "incoming_xrefs_code_count": int(row["incoming_xrefs_code_count"] or 0),
            "incoming_xrefs_data_count": int(row["incoming_xrefs_data_count"] or 0),
            "data_refs_count": int(row["data_refs_count"] or 0),
            "string_refs_count": int(row["string_refs_count"] or 0),
        }

    for row in conn.execute(
        """
        SELECT e.src_token AS token, COUNT(DISTINCT e.dst_token) AS c
        FROM call_edges e
        JOIN _audit_tokens t ON t.token = e.src_token
        GROUP BY e.src_token
        """
    ):
        callees_all[str(row["token"])] = int(row["c"] or 0)

    for row in conn.execute(
        """
        SELECT e.dst_token AS token, COUNT(DISTINCT e.src_token) AS c
        FROM call_edges e
        JOIN _audit_tokens t ON t.token = e.dst_token
        GROUP BY e.dst_token
        """
    ):
        callers_all[str(row["token"])] = int(row["c"] or 0)

    for row in conn.execute(
        """
        SELECT e.src_token AS token, COUNT(DISTINCT e.dst_token) AS c
        FROM call_edges e
        JOIN _audit_tokens src_t ON src_t.token = e.src_token
        JOIN _audit_tokens dst_t ON dst_t.token = e.dst_token
        GROUP BY e.src_token
        """
    ):
        callees_internal[str(row["token"])] = int(row["c"] or 0)

    for row in conn.execute(
        """
        SELECT e.dst_token AS token, COUNT(DISTINCT e.src_token) AS c
        FROM call_edges e
        JOIN _audit_tokens src_t ON src_t.token = e.src_token
        JOIN _audit_tokens dst_t ON dst_t.token = e.dst_token
        GROUP BY e.dst_token
        """
    ):
        callers_internal[str(row["token"])] = int(row["c"] or 0)

    for row in conn.execute(
        """
        SELECT DISTINCT e.src_token AS src_token, e.dst_token AS dst_token
        FROM call_edges e
        JOIN _audit_tokens src_t ON src_t.token = e.src_token
        JOIN _audit_tokens dst_t ON dst_t.token = e.dst_token
        """
    ):
        internal_edges.add((str(row["src_token"]), str(row["dst_token"])))

    return metrics, callers_all, callees_all, callers_internal, callees_internal, internal_edges


def compute_internal_components(tokens: list[str], internal_edges: set[tuple[str, str]]) -> tuple[dict[str, int], dict[int, int]]:
    adj: dict[str, set[str]] = {t: set() for t in tokens}
    for src, dst in internal_edges:
        if src == dst:
            adj[src].add(dst)
            continue
        adj[src].add(dst)
        adj[dst].add(src)

    component_of: dict[str, int] = {}
    component_sizes: dict[int, int] = {}
    next_id = 1

    for token in tokens:
        if token in component_of:
            continue
        stack = [token]
        component_nodes: list[str] = []
        component_of[token] = next_id
        while stack:
            cur = stack.pop()
            component_nodes.append(cur)
            for nb in adj.get(cur, ()):
                if nb not in component_of:
                    component_of[nb] = next_id
                    stack.append(nb)
        component_sizes[next_id] = len(component_nodes)
        next_id += 1

    return component_of, component_sizes


def classify_token(
    token: str,
    metric_row: dict[str, int | None] | None,
    callers_all: int,
    callees_all: int,
    callers_internal: int,
    callees_internal: int,
    component_size: int,
    progress_status: str | None,
) -> TokenUsage:
    if metric_row is None:
        metric_row = {
            "ea": None,
            "incoming_xrefs_count": 0,
            "incoming_xrefs_code_count": 0,
            "incoming_xrefs_data_count": 0,
            "data_refs_count": 0,
            "string_refs_count": 0,
        }

    exists_in_db = metric_row.get("ea") is not None
    incoming_xrefs = int(metric_row.get("incoming_xrefs_count") or 0)
    incoming_xrefs_code = int(metric_row.get("incoming_xrefs_code_count") or 0)
    incoming_xrefs_data = int(metric_row.get("incoming_xrefs_data_count") or 0)
    data_refs = int(metric_row.get("data_refs_count") or 0)
    string_refs = int(metric_row.get("string_refs_count") or 0)

    call_links_all = callers_all + callees_all
    call_links_internal = callers_internal + callees_internal
    non_call_evidence = incoming_xrefs + data_refs + string_refs

    reason = "connected_within_annotated"
    severity = "ok"

    if not exists_in_db:
        reason = "missing_callgraph_entry"
        severity = "high"
    elif call_links_all == 0 and non_call_evidence == 0:
        reason = "no_binary_evidence"
        severity = "high"
    elif call_links_all == 0 and non_call_evidence > 0:
        reason = "xref_or_data_only_no_calls"
        severity = "medium"
    elif call_links_internal == 0 and call_links_all > 0:
        reason = "connected_only_to_unannotated"
        severity = "medium"
    elif component_size == 1 and call_links_internal > 0 and callers_internal == 0 and callees_internal == 1:
        reason = "tiny_internal_leaf_like"
        severity = "low"
    elif callers_all == 0 and callees_all > 0:
        reason = "binary_root_candidate"
        severity = "ok"
    elif callees_all == 0 and callers_all > 0:
        reason = "binary_leaf_candidate"
        severity = "ok"

    return TokenUsage(
        token=token,
        exists_in_db=exists_in_db,
        callers_all=callers_all,
        callees_all=callees_all,
        callers_internal=callers_internal,
        callees_internal=callees_internal,
        incoming_xrefs=incoming_xrefs,
        incoming_xrefs_code=incoming_xrefs_code,
        incoming_xrefs_data=incoming_xrefs_data,
        data_refs=data_refs,
        string_refs=string_refs,
        component_size=component_size,
        reason=reason,
        severity=severity,
        progress_status=progress_status,
    )


def fetch_neighbor_samples(conn: sqlite3.Connection, token: str, limit: int) -> dict[str, list[dict[str, Any]]]:
    out_neighbors: list[dict[str, Any]] = []
    in_neighbors: list[dict[str, Any]] = []
    in_xrefs: list[dict[str, Any]] = []

    for row in conn.execute(
        """
        SELECT e.dst_token AS token, COUNT(*) AS callsites
        FROM call_edges e
        WHERE e.src_token = ?
        GROUP BY e.dst_token
        ORDER BY callsites DESC, token
        LIMIT ?
        """,
        (token, limit),
    ):
        out_neighbors.append({"token": str(row["token"]), "callsites": int(row["callsites"] or 0)})

    for row in conn.execute(
        """
        SELECT e.src_token AS token, COUNT(*) AS callsites
        FROM call_edges e
        WHERE e.dst_token = ?
        GROUP BY e.src_token
        ORDER BY callsites DESC, token
        LIMIT ?
        """,
        (token, limit),
    ):
        in_neighbors.append({"token": str(row["token"]), "callsites": int(row["callsites"] or 0)})

    for row in conn.execute(
        """
        SELECT x.owner_token AS token, COUNT(*) AS refs
        FROM incoming_xrefs x
        WHERE x.target_token = ?
        GROUP BY x.owner_token
        ORDER BY refs DESC, token
        LIMIT ?
        """,
        (token, limit),
    ):
        in_xrefs.append({"token": str(row["token"]), "refs": int(row["refs"] or 0)})

    return {
        "incoming_callers_sample": in_neighbors,
        "outgoing_callees_sample": out_neighbors,
        "incoming_xrefs_owner_sample": in_xrefs,
    }


def resolve_output_path(repo_root: Path, arg_value: str, default_abs: Path) -> Path:
    if not arg_value:
        return default_abs
    raw = Path(arg_value)
    if raw.is_absolute():
        return raw.resolve()
    return (repo_root / raw).resolve()


def build_markdown_report(
    *,
    generated_utc: str,
    repo_root: Path,
    src_root: Path,
    callgraph_db: Path,
    recovered_progress: Path,
    namespace: str,
    summary: dict[str, Any],
    reason_counts: Counter[str],
    severity_counts: Counter[str],
    suspicious_rows: list[dict[str, Any]],
    limit: int,
) -> str:
    lines: list[str] = []
    lines.append("# Recovered Address Usage Audit")
    lines.append("")
    lines.append(f"- Generated (UTC): `{generated_utc}`")
    lines.append(f"- Repo root: `{repo_root}`")
    lines.append(f"- Source root: `{src_root}`")
    lines.append(f"- Callgraph DB: `{callgraph_db}`")
    lines.append(f"- Recovered progress: `{recovered_progress}` (namespace: `{namespace}`)")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Annotated tokens in source: `{summary['source_annotated_tokens']}`")
    lines.append(f"- Annotation hits (header+cpp occurrences): `{summary['source_annotation_hits']}`")
    lines.append(f"- DB matched tokens: `{summary['db_matched_tokens']}`")
    lines.append(f"- Missing DB entries: `{summary['missing_db_tokens']}`")
    lines.append(f"- Completed progress tokens: `{summary['progress_completed_tokens']}`")
    lines.append(f"- Annotated + completed overlap: `{summary['annotated_completed_overlap']}`")
    lines.append(f"- Completed but not annotated in source: `{summary['completed_missing_annotation']}`")
    lines.append(f"- Annotated but not completed in progress: `{summary['annotated_not_completed']}`")
    lines.append("")
    lines.append("## Reason Buckets")
    lines.append("")
    for reason, count in reason_counts.most_common():
        lines.append(f"- {reason}: `{count}`")
    lines.append("")
    lines.append("## Severity Buckets")
    lines.append("")
    for sev, count in severity_counts.most_common():
        lines.append(f"- {sev}: `{count}`")
    lines.append("")
    lines.append(f"## Suspicious Tokens (top {limit})")
    lines.append("")
    lines.append("| Token | Severity | Reason | in/out(all) | in/out(internal) | xrefs | data | strings | Progress | First source hit |")
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---|---|")
    for row in suspicious_rows[:limit]:
        first_hit = row.get("first_hit") or {}
        first_loc = f"{first_hit.get('file_rel', '?')}:{first_hit.get('line', '?')}"
        lines.append(
            f"| `{row['token']}` | `{row['severity']}` | `{row['reason']}` | "
            f"`{row['callers_all']}/{row['callees_all']}` | "
            f"`{row['callers_internal']}/{row['callees_internal']}` | "
            f"`{row['incoming_xrefs']}` | `{row['data_refs']}` | `{row['string_refs']}` | "
            f"`{row.get('progress_status') or ''}` | `{first_loc}` |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- `connected_only_to_unannotated` means binary links exist, but links to other annotated recovered functions were not found.")
    lines.append("- `no_binary_evidence` is the strongest hanging signal (no calls, no xrefs, no data/string refs in the indexed evidence).")
    lines.append("- `xref_or_data_only_no_calls` can still be valid for callback/data-driven lanes; review with owner context.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Address-annotated recovered functions against callgraph evidence.")
    parser.add_argument("--repo-root", default=".", help="Repository root (default: current directory).")
    parser.add_argument("--src-root", default="src/sdk", help="Source root to scan for Address annotations.")
    parser.add_argument(
        "--callgraph-db",
        default="decomp/recovery/disasm/fa_full_2026_03_26/_callgraph_index.sqlite",
        help="Path to _callgraph_index.sqlite.",
    )
    parser.add_argument(
        "--recovered-progress",
        default="decomp/recovery/recovered_progress.json",
        help="Path to recovered_progress.json.",
    )
    parser.add_argument(
        "--namespace",
        default="fa_full_2026_03_26",
        help="Namespace key in recovered_progress.json.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Output JSON path. Default: next to callgraph DB.",
    )
    parser.add_argument(
        "--markdown-out",
        default="",
        help="Output Markdown path. Default: next to callgraph DB.",
    )
    parser.add_argument(
        "--queue-out",
        default="",
        help="Output queue (.txt) for suspicious tokens. Default: next to callgraph DB.",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=12,
        help="Per-token neighbor/xref sample limit for suspicious entries.",
    )
    parser.add_argument(
        "--sample-token-cap",
        type=int,
        default=400,
        help="Max suspicious tokens to enrich with neighbor/xref samples.",
    )
    parser.add_argument(
        "--markdown-top",
        type=int,
        default=250,
        help="Max suspicious rows to show in markdown table.",
    )
    parser.add_argument(
        "--token-limit",
        type=int,
        default=0,
        help="Optional cap on sorted tokens processed (0 = all).",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable carriage-return progress output.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    src_root = (repo_root / args.src_root).resolve() if not Path(args.src_root).is_absolute() else Path(args.src_root).resolve()
    callgraph_db = (repo_root / args.callgraph_db).resolve() if not Path(args.callgraph_db).is_absolute() else Path(args.callgraph_db).resolve()
    recovered_progress = (
        (repo_root / args.recovered_progress).resolve()
        if not Path(args.recovered_progress).is_absolute()
        else Path(args.recovered_progress).resolve()
    )

    if not src_root.exists():
        print(f"error: source root not found: {src_root}", file=sys.stderr)
        return 2
    if not callgraph_db.exists():
        print(f"error: callgraph db not found: {callgraph_db}", file=sys.stderr)
        return 2

    default_json_out = callgraph_db.parent / "_recovered_address_usage_audit.json"
    default_md_out = callgraph_db.parent / "_recovered_address_usage_audit.md"
    default_queue_out = callgraph_db.parent / "_recovered_address_usage_suspicious.txt"

    json_out = resolve_output_path(repo_root, args.json_out, default_json_out)
    markdown_out = resolve_output_path(repo_root, args.markdown_out, default_md_out)
    queue_out = resolve_output_path(repo_root, args.queue_out, default_queue_out)

    show_progress = not args.no_progress
    generated_utc = utc_now_iso()

    hits_by_token = scan_source_annotations(repo_root, src_root, show_progress=show_progress)
    tokens = sorted(hits_by_token.keys())
    if args.token_limit > 0:
        tokens = tokens[: args.token_limit]

    if not tokens:
        print("error: no Address/FUN annotations found in source scope.", file=sys.stderr)
        return 3

    progress_status_map = load_progress_status_map(recovered_progress, args.namespace)
    completed_tokens = {t for t, s in progress_status_map.items() if s in COMPLETED_STATUSES}
    source_tokens_set = set(tokens)
    annotated_completed_overlap = len(source_tokens_set & completed_tokens)
    completed_missing_annotation = len(completed_tokens - source_tokens_set)
    annotated_not_completed = len(source_tokens_set - completed_tokens) if completed_tokens else len(source_tokens_set)

    conn = sqlite3.connect(str(callgraph_db))
    conn.row_factory = sqlite3.Row
    create_temp_token_table(conn, tokens)

    (
        metrics_map,
        callers_all_map,
        callees_all_map,
        callers_internal_map,
        callees_internal_map,
        internal_edges,
    ) = load_callgraph_maps(conn)

    component_of, component_sizes = compute_internal_components(tokens, internal_edges)

    usages: dict[str, TokenUsage] = {}
    reason_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()

    progress = ProgressPrinter(show_progress)
    total = len(tokens)
    for idx, token in enumerate(tokens, start=1):
        progress.update("audit", idx, total)
        usage = classify_token(
            token=token,
            metric_row=metrics_map.get(token),
            callers_all=int(callers_all_map.get(token, 0)),
            callees_all=int(callees_all_map.get(token, 0)),
            callers_internal=int(callers_internal_map.get(token, 0)),
            callees_internal=int(callees_internal_map.get(token, 0)),
            component_size=int(component_sizes.get(component_of.get(token, 0), 1)),
            progress_status=progress_status_map.get(token),
        )
        usages[token] = usage
        reason_counts[usage.reason] += 1
        severity_counts[usage.severity] += 1
    progress.done()

    suspicious_order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    suspicious_tokens = [
        t
        for t in tokens
        if usages[t].severity in {"high", "medium"}
    ]
    suspicious_tokens.sort(
        key=lambda t: (
            suspicious_order.get(usages[t].severity, 99),
            usages[t].reason,
            t,
        )
    )

    enrich_limit = max(0, args.sample_token_cap)
    enriched_tokens = suspicious_tokens[:enrich_limit]
    enriched_samples: dict[str, dict[str, list[dict[str, Any]]]] = {}
    if enriched_tokens:
        sample_prog = ProgressPrinter(show_progress)
        total_samples = len(enriched_tokens)
        for idx, token in enumerate(enriched_tokens, start=1):
            sample_prog.update("sample", idx, total_samples)
            enriched_samples[token] = fetch_neighbor_samples(conn, token, max(0, args.sample_limit))
        sample_prog.done()

    db_matched_tokens = sum(1 for t in tokens if usages[t].exists_in_db)
    missing_db_tokens = len(tokens) - db_matched_tokens
    annotation_hits_total = sum(len(v) for v in hits_by_token.values())

    summary: dict[str, Any] = {
        "source_annotated_tokens": len(tokens),
        "source_annotation_hits": annotation_hits_total,
        "db_matched_tokens": db_matched_tokens,
        "missing_db_tokens": missing_db_tokens,
        "progress_completed_tokens": len(completed_tokens),
        "annotated_completed_overlap": annotated_completed_overlap,
        "completed_missing_annotation": completed_missing_annotation,
        "annotated_not_completed": annotated_not_completed,
    }

    tokens_json: dict[str, Any] = {}
    for token in tokens:
        usage = usages[token]
        hits = hits_by_token.get(token, [])
        payload = {
            "token": token,
            "severity": usage.severity,
            "reason": usage.reason,
            "exists_in_callgraph_db": usage.exists_in_db,
            "callers_all": usage.callers_all,
            "callees_all": usage.callees_all,
            "callers_internal": usage.callers_internal,
            "callees_internal": usage.callees_internal,
            "incoming_xrefs": usage.incoming_xrefs,
            "incoming_xrefs_code": usage.incoming_xrefs_code,
            "incoming_xrefs_data": usage.incoming_xrefs_data,
            "data_refs": usage.data_refs,
            "string_refs": usage.string_refs,
            "component_size": usage.component_size,
            "progress_status": usage.progress_status,
            "source_hits": [
                {
                    "file_abs": h.file_abs,
                    "file_rel": h.file_rel,
                    "line": h.line,
                }
                for h in hits
            ],
        }
        if token in enriched_samples:
            payload["samples"] = enriched_samples[token]
        tokens_json[token] = payload

    suspicious_rows: list[dict[str, Any]] = []
    for token in suspicious_tokens:
        usage = usages[token]
        first_hit = hits_by_token.get(token, [None])[0]
        suspicious_rows.append(
            {
                "token": token,
                "severity": usage.severity,
                "reason": usage.reason,
                "callers_all": usage.callers_all,
                "callees_all": usage.callees_all,
                "callers_internal": usage.callers_internal,
                "callees_internal": usage.callees_internal,
                "incoming_xrefs": usage.incoming_xrefs,
                "data_refs": usage.data_refs,
                "string_refs": usage.string_refs,
                "progress_status": usage.progress_status,
                "first_hit": {
                    "file_abs": first_hit.file_abs,
                    "file_rel": first_hit.file_rel,
                    "line": first_hit.line,
                }
                if first_hit
                else None,
            }
        )

    report: dict[str, Any] = {
        "generated_utc": generated_utc,
        "repo_root": str(repo_root),
        "src_root": str(src_root),
        "callgraph_db": str(callgraph_db),
        "recovered_progress": str(recovered_progress),
        "namespace": args.namespace,
        "summary": summary,
        "reason_counts": dict(reason_counts),
        "severity_counts": dict(severity_counts),
        "suspicious_tokens": suspicious_tokens,
        "tokens": tokens_json,
    }

    md = build_markdown_report(
        generated_utc=generated_utc,
        repo_root=repo_root,
        src_root=src_root,
        callgraph_db=callgraph_db,
        recovered_progress=recovered_progress,
        namespace=args.namespace,
        summary=summary,
        reason_counts=reason_counts,
        severity_counts=severity_counts,
        suspicious_rows=suspicious_rows,
        limit=max(0, args.markdown_top),
    )

    ensure_parent(json_out)
    ensure_parent(markdown_out)
    ensure_parent(queue_out)
    json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_out.write_text(md, encoding="utf-8")
    queue_out.write_text("\n".join(suspicious_tokens) + ("\n" if suspicious_tokens else ""), encoding="utf-8")

    print(f"Annotated tokens: {len(tokens)}")
    print(f"Suspicious tokens (high+medium): {len(suspicious_tokens)}")
    print(f"JSON report: {json_out}")
    print(f"Markdown report: {markdown_out}")
    print(f"Queue: {queue_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
