#!/usr/bin/env python3
"""
Generate wxWidgets external dependency mapping for FAF and emit a token queue for progress marking.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sqlite3
from pathlib import Path
from typing import Any


NS_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)::")
MSVC_SCOPE_RE = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)@@")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate wx external dependency mapping/report + token queue.")
    parser.add_argument("--recovery-dir", default="decomp/recovery", help="Recovery root (default: decomp/recovery)")
    parser.add_argument(
        "--names-json",
        default="",
        help="Optional explicit fa_function_names_*.json path (default: latest under recovery dir)",
    )
    parser.add_argument(
        "--namespace",
        default="fa_full_2026_03_26",
        help="recovered_progress namespace to inspect/update (default: fa_full_2026_03_26)",
    )
    parser.add_argument(
        "--recovered-progress",
        default="decomp/recovery/recovered_progress.json",
        help="Path to recovered_progress.json",
    )
    parser.add_argument(
        "--callgraph-db",
        default="decomp/recovery/disasm/fa_full_2026_03_26/_callgraph_index.sqlite",
        help="Optional callgraph DB for function hashes/metrics",
    )
    parser.add_argument(
        "--report-out",
        default="decomp/recovery/reports/wxwidgets_external_dependency_matches_2026-04-08.md",
        help="Output markdown report path",
    )
    parser.add_argument(
        "--queue-out",
        default="decomp/recovery/queues/wxwidgets_external_dependency_tokens_2026-04-08.json",
        help="Output token queue path (.json)",
    )
    parser.add_argument(
        "--csv-out",
        default="decomp/recovery/reports/wxwidgets_external_dependency_matches_2026-04-08.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--include-no-body",
        action="store_true",
        help="Include functions without decomp body evidence in report/queue.",
    )
    return parser.parse_args()


def normalize_token(token: str) -> str:
    token = token.strip()
    token = token.removeprefix("FUN_").removeprefix("sub_").removeprefix("0x").removeprefix("0X")
    value = int(token, 16) if re.fullmatch(r"[0-9A-Fa-f]{6,16}", token) else int(token, 10)
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def token_sort_key(token: str) -> tuple[int, str]:
    try:
        norm = normalize_token(token)
        return (int(norm[4:], 16), norm)
    except Exception:
        return (2**63 - 1, token)


def to_addr_int(address: str) -> int:
    address = address.strip()
    if address.lower().startswith("0x"):
        return int(address, 16)
    return int(address, 16)


def find_latest_names_json(recovery_dir: Path) -> Path:
    candidates = sorted(recovery_dir.glob("fa_function_names_*.json"))
    if not candidates:
        raise FileNotFoundError(f"No fa_function_names_*.json in {recovery_dir}")
    return candidates[-1]


def extract_root_token(raw_name: str, demangled: str) -> str | None:
    if demangled:
        match = NS_RE.search(demangled)
        if match:
            return match.group(1).strip()

    if raw_name:
        match = NS_RE.search(raw_name)
        if match:
            return match.group(1).strip()

    if raw_name:
        for match in MSVC_SCOPE_RE.finditer(raw_name):
            token = match.group(1).strip()
            if token:
                return token

    return None


def classify_external_dependency(token: str | None, raw_name: str, demangled: str) -> str | None:
    token_lower = (token or "").lower()
    if token_lower.startswith("wx") or "wx" in token_lower:
        return "wxWidgets"

    hay = f"{raw_name.lower()}\n{demangled.lower()}"
    if "wxwidgets" in hay:
        return "wxWidgets"

    return None


def load_body_addresses(recovery_dir: Path) -> set[int]:
    csv_path = recovery_dir / "function-context.csv"
    if not csv_path.exists():
        return set()

    out: set[int] = set()
    with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            addr = (row.get("Address") or "").strip()
            if not addr:
                continue
            try:
                hits = int((row.get("DecompHits") or "0").strip())
            except ValueError:
                hits = 0
            if hits <= 0:
                continue
            try:
                out.add(to_addr_int(addr))
            except ValueError:
                continue
    return out


def load_recovered_statuses(progress_path: Path, namespace: str) -> dict[str, str]:
    if not progress_path.exists():
        return {}
    payload = json.loads(progress_path.read_text(encoding="utf-8"))
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    out: dict[str, str] = {}
    if not isinstance(recovered, dict):
        return out
    for token, info in recovered.items():
        if not isinstance(info, dict):
            continue
        status = str(info.get("status", "")).strip().lower()
        if status:
            out[token] = status
    return out


def load_callgraph_hashes(db_path: Path, tokens: list[str]) -> dict[str, dict[str, Any]]:
    if not db_path.exists() or not tokens:
        return {}
    out: dict[str, dict[str, Any]] = {}
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        chunk_size = 900
        for start in range(0, len(tokens), chunk_size):
            part = tokens[start : start + chunk_size]
            placeholders = ",".join("?" for _ in part)
            rows = conn.execute(
                (
                    "SELECT token, function_sha256, function_code_bytes, instruction_count, "
                    "function_name, demangled_name FROM functions WHERE token IN (" + placeholders + ")"
                ),
                part,
            ).fetchall()
            for row in rows:
                out[str(row["token"])] = {
                    "function_sha256": str(row["function_sha256"] or ""),
                    "function_code_bytes": int(row["function_code_bytes"] or 0),
                    "instruction_count": int(row["instruction_count"] or 0),
                    "function_name": str(row["function_name"] or ""),
                    "demangled_name": str(row["demangled_name"] or ""),
                }
    return out


def main() -> int:
    args = parse_args()
    recovery_dir = Path(args.recovery_dir).resolve()
    names_json_path = Path(args.names_json).resolve() if args.names_json else find_latest_names_json(recovery_dir)
    recovered_progress_path = Path(args.recovered_progress).resolve()
    callgraph_db_path = Path(args.callgraph_db).resolve()
    report_out = Path(args.report_out).resolve()
    queue_out = Path(args.queue_out).resolve()
    csv_out = Path(args.csv_out).resolve()

    body_addresses = load_body_addresses(recovery_dir)
    recovered_statuses = load_recovered_statuses(recovered_progress_path, args.namespace)

    payload = json.loads(names_json_path.read_text(encoding="utf-8"))
    rows = payload.get("functions", [])
    if not isinstance(rows, list):
        raise ValueError(f"Unexpected functions payload shape in: {names_json_path}")

    matches: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address", "") or "")
        if not address:
            continue
        try:
            addr_int = to_addr_int(address)
        except ValueError:
            continue
        raw_name = str(item.get("raw_name", "") or "")
        demangled = str(item.get("demangled", "") or "")
        token = extract_root_token(raw_name, demangled)
        dependency = classify_external_dependency(token, raw_name, demangled)
        if dependency != "wxWidgets":
            continue

        fun_token = f"FUN_{addr_int:08X}" if addr_int <= 0xFFFFFFFF else f"FUN_{addr_int:016X}"
        has_body = addr_int in body_addresses
        current_status = recovered_statuses.get(fun_token, "")
        target_symbol = demangled if demangled else raw_name
        matches.append(
            {
                "token": fun_token,
                "address": f"0x{addr_int:08X}",
                "address_int": addr_int,
                "raw_name": raw_name,
                "demangled": demangled,
                "target_symbol": target_symbol,
                "has_body": has_body,
                "current_status": current_status,
            }
        )

    matches.sort(key=lambda row: row["address_int"])
    tokens = [row["token"] for row in matches]
    hash_map = load_callgraph_hashes(callgraph_db_path, tokens)

    mark_candidates: list[str] = []
    for row in matches:
        token = row["token"]
        info = hash_map.get(token, {})
        row["fa_sha256"] = str(info.get("function_sha256", ""))
        row["fa_code_bytes"] = int(info.get("function_code_bytes", 0))
        row["fa_instructions"] = int(info.get("instruction_count", 0))

        should_consider = row["has_body"] or args.include_no_body
        current = row["current_status"]
        if should_consider and current not in {"recovered", "accepted", "done", "external_dependency"}:
            row["action"] = "mark_external_dependency"
            mark_candidates.append(token)
        else:
            row["action"] = "keep"

    mark_candidates = sorted(set(mark_candidates), key=token_sort_key)
    matched_considered = [row for row in matches if row["has_body"] or args.include_no_body]

    report_out.parent.mkdir(parents=True, exist_ok=True)
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    csv_out.parent.mkdir(parents=True, exist_ok=True)

    queue_payload = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "namespace": args.namespace,
        "status": "external_dependency",
        "count": len(mark_candidates),
        "functions": mark_candidates,
    }
    queue_out.write_text(json.dumps(queue_payload, indent=2) + "\n", encoding="utf-8")

    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "token",
                "address",
                "target_symbol",
                "raw_name",
                "demangled",
                "has_body",
                "current_status",
                "action",
                "fa_sha256",
                "fa_code_bytes",
                "fa_instructions",
            ],
        )
        writer.writeheader()
        for row in matched_considered:
            writer.writerow(
                {
                    "token": row["token"],
                    "address": row["address"],
                    "target_symbol": row["target_symbol"],
                    "raw_name": row["raw_name"],
                    "demangled": row["demangled"],
                    "has_body": 1 if row["has_body"] else 0,
                    "current_status": row["current_status"],
                    "action": row["action"],
                    "fa_sha256": row["fa_sha256"],
                    "fa_code_bytes": row["fa_code_bytes"],
                    "fa_instructions": row["fa_instructions"],
                }
            )

    summary_lines = [
        f"# wxWidgets External Dependency Mapping ({dt.date.today().isoformat()})",
        "",
        "## Inputs",
        "",
        f"- Names index: `{names_json_path}`",
        f"- Recovery DB: `{recovered_progress_path}` (namespace: `{args.namespace}`)",
        f"- Callgraph DB: `{callgraph_db_path}`",
        f"- Include no-body entries: `{args.include_no_body}`",
        "",
        "## Match Basis",
        "",
        "- Symbol identity: FAF function symbol resolves to `wx*` namespace/class token.",
        "- Optional body evidence: address present in `decomp/recovery/function-context.csv` with `DecompHits > 0`.",
        "- FAF byte hash comes from callgraph metadata (`function_sha256`) for traceability.",
        "",
        "## Summary",
        "",
        f"- wx symbol matches found: `{len(matches)}`",
        f"- Entries considered (has_body or include_no_body): `{len(matched_considered)}`",
        f"- To mark as `external_dependency`: `{len(mark_candidates)}`",
        f"- Queue JSON: `{queue_out}`",
        f"- CSV: `{csv_out}`",
        "",
        "## Function List",
        "",
        "| FAF Token | Address | wx Target Symbol | Current Status | Action | SHA256 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in matched_considered:
        symbol = row["target_symbol"].replace("|", "\\|")
        summary_lines.append(
            f"| {row['token']} | {row['address']} | `{symbol}` | `{row['current_status']}` | `{row['action']}` | `{row['fa_sha256']}` |"
        )

    report_out.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"[wx-report] report={report_out}")
    print(f"[wx-report] queue={queue_out} count={len(mark_candidates)}")
    print(f"[wx-report] csv={csv_out} rows={len(matched_considered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

