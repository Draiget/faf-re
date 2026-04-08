#!/usr/bin/env python3
"""
Verify README-scope wxWidgets functions against built wx library symbols.

README-scope parity:
- Uses the same wx classification basis as scripts/recovery_coverage.py.
- Includes only functions with decomp body evidence (DecompHits > 0).
- Excludes link-only entries from that body scope.

Outputs:
- CSV with verification result per README-scope wx function.
- Markdown summary report.
- Queue JSON for verified tokens that are not yet marked external_dependency.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


NS_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)::")
MSVC_SCOPE_RE = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)@@")
XACT_TOKEN_RE = re.compile(r"(?:^|[^a-z])xact(?:[^a-z]|$)", re.IGNORECASE)
SYMBOL_LINE_RE = re.compile(r"^\s*[0-9A-Fa-f]+\s+(\S+)$")
ARGS_RE = re.compile(r"\s*\(.*\)\s*$")
ALIAS_SUFFIX_RE = re.compile(r"^(?P<prefix>.*::)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)_(?P<index>\d+)$")

DEFAULT_NAMESPACE = "fa_full_2026_03_26"
DEFAULT_RECOVERY_DIR = Path("decomp/recovery")
DEFAULT_RECOVERED_PROGRESS = Path("decomp/recovery/recovered_progress.json")
DEFAULT_WX_LIB = Path("dependencies/wxWindows-2.4.2/lib/wxmsw.lib")
DEFAULT_SYMBOL_DUMP = Path("decomp/recovery/reports/wxmsw_lib_symbols.txt")
DEFAULT_CSV_OUT = Path("decomp/recovery/reports/wxwidgets_readme_scope_verification.csv")
DEFAULT_MD_OUT = Path("decomp/recovery/reports/wxwidgets_readme_scope_verification.md")
DEFAULT_QUEUE_OUT = Path("decomp/recovery/queues/wxwidgets_readme_scope_verified_to_external.json")
DEFAULT_VCVARS = Path(
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify README-scope wx symbols against wxmsw.lib.")
    parser.add_argument("--recovery-dir", default=str(DEFAULT_RECOVERY_DIR), help="Recovery root directory.")
    parser.add_argument("--names-json", default="", help="Optional explicit fa_function_names_*.json path.")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE, help="recovered_progress namespace key.")
    parser.add_argument(
        "--recovered-progress",
        default=str(DEFAULT_RECOVERED_PROGRESS),
        help="Path to recovered_progress.json.",
    )
    parser.add_argument(
        "--wx-lib",
        default=str(DEFAULT_WX_LIB),
        help="Path to built wx static library (default: dependencies/wxWindows-2.4.2/lib/wxmsw.lib).",
    )
    parser.add_argument(
        "--symbol-dump",
        default=str(DEFAULT_SYMBOL_DUMP),
        help="Path to dumpbin /linkermember:2 text output.",
    )
    parser.add_argument(
        "--refresh-symbol-dump",
        action="store_true",
        help="Regenerate --symbol-dump via dumpbin before verification.",
    )
    parser.add_argument(
        "--vcvars-bat",
        default=str(DEFAULT_VCVARS),
        help="Path to vcvarsamd64_x86.bat used for dumpbin command setup.",
    )
    parser.add_argument("--csv-out", default=str(DEFAULT_CSV_OUT), help="Verification CSV output path.")
    parser.add_argument("--report-out", default=str(DEFAULT_MD_OUT), help="Verification markdown output path.")
    parser.add_argument("--queue-out", default=str(DEFAULT_QUEUE_OUT), help="Queue JSON output path.")
    return parser.parse_args()


def normalize_token(token: str | None) -> str | None:
    if not token:
        return None
    raw = token.strip()
    if not raw:
        return None
    raw = raw.split(",")[0].strip()
    raw = re.sub(r"^FUN_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^sub_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^0x", "", raw, flags=re.IGNORECASE)
    if re.fullmatch(r"[0-9A-Fa-f]{6,16}", raw):
        value = int(raw, 16)
    elif re.fullmatch(r"\d+", raw):
        value = int(raw, 10)
    else:
        return None
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def token_sort_key(token: str) -> tuple[int, str]:
    norm = normalize_token(token) or token
    try:
        return (int(norm[4:], 16), norm)
    except Exception:
        return (2**63 - 1, norm)


def to_addr_int(address: str) -> int:
    text = address.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 16)


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
    raw_lower = raw_name.lower()
    dem_lower = demangled.lower()
    hay = f"{raw_lower}\n{dem_lower}"

    if token_lower.startswith("wx") or "wx" in token_lower:
        return "wxWidgets"
    if token_lower in {"std"}:
        return "MSVC STL/CRT"
    if token_lower == "boost":
        return "Boost"
    if token_lower in {"luaplus", "lua", "luaobject", "luastate"}:
        return "LuaPlus/Lua"
    if token_lower.startswith("wm3"):
        return "WildMagic"
    if token_lower.startswith("sofdec") or "adx" in token_lower or token_lower.startswith("cri"):
        return "CRI Middleware"
    if "bugsplat" in hay:
        return "BugSplat"
    if "direct3d" in hay or "ixact" in hay:
        return "DirectX/XACT"
    if token_lower.startswith("idirect3d") or token_lower.startswith("ixact"):
        return "DirectX/XACT"
    if XACT_TOKEN_RE.search(hay):
        return "DirectX/XACT"
    return None


def is_external_link_only(raw_name: str, demangled: str, dependency: str | None, token: str | None) -> bool:
    raw = raw_name.strip()
    dem = demangled.strip()
    raw_lower = raw.lower()
    token_lower = (token or "").lower()

    if raw_lower.startswith("__imp_") or raw_lower.startswith("j_"):
        return True

    if dependency == "DirectX/XACT":
        if raw_lower.startswith("direct3dcreate"):
            return True
        if token_lower.startswith("ixact") or token_lower.startswith("idirect3d"):
            return True
        if raw.startswith("IXACT") or raw.startswith("IDirect3D"):
            return True
        if dem.startswith("IXACT") or dem.startswith("IDirect3D"):
            return True
    return False


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
            except Exception:
                continue
    return out


def load_status_map(progress_path: Path, namespace: str) -> dict[str, str]:
    if not progress_path.exists():
        return {}
    payload = json.loads(progress_path.read_text(encoding="utf-8"))
    ns = payload.get("namespaces", {}).get(namespace, {})
    recovered = ns.get("recovered", {})
    if not isinstance(recovered, dict):
        return {}
    out: dict[str, str] = {}
    for token, info in recovered.items():
        if not isinstance(info, dict):
            continue
        status = str(info.get("status", "")).strip().lower()
        if status:
            norm = normalize_token(token)
            if norm:
                out[norm] = status
    return out


def refresh_symbol_dump(symbol_dump: Path, wx_lib: Path, vcvars_bat: Path) -> None:
    symbol_dump.parent.mkdir(parents=True, exist_ok=True)
    refresh_cmd = symbol_dump.with_suffix(".refresh.cmd")
    refresh_cmd.write_text(
        "\r\n".join(
            [
                "@echo off",
                f"call \"{vcvars_bat}\" >nul",
                f"dumpbin /linkermember:2 \"{wx_lib}\" > \"{symbol_dump}\"",
            ]
        )
        + "\r\n",
        encoding="ascii",
        errors="ignore",
    )
    try:
        subprocess.run(["cmd.exe", "/c", str(refresh_cmd)], check=True)
    finally:
        try:
            refresh_cmd.unlink()
        except OSError:
            pass


def load_decorated_symbols(symbol_dump: Path) -> set[str]:
    if not symbol_dump.exists():
        raise FileNotFoundError(f"Symbol dump not found: {symbol_dump}")
    decorated: set[str] = set()
    in_public = False
    for line in symbol_dump.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "public symbols" in line:
            in_public = True
            continue
        if in_public and line.startswith("Archive member name at"):
            break
        if not in_public:
            continue
        match = SYMBOL_LINE_RE.match(line)
        if not match:
            continue
        sym = match.group(1).strip()
        if sym:
            decorated.add(sym)
    return decorated


def load_name_only_symbols(decorated_symbols: set[str]) -> set[str]:
    undec = ctypes.windll.dbghelp.UnDecorateSymbolName
    undec.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
    undec.restype = ctypes.c_uint

    UNDNAME_NAME_ONLY = 0x1000
    UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080
    UNDNAME_NO_MS_KEYWORDS = 0x0002
    UNDNAME_NO_FUNCTION_RETURNS = 0x0004
    flags = (
        UNDNAME_NAME_ONLY
        | UNDNAME_NO_ACCESS_SPECIFIERS
        | UNDNAME_NO_MS_KEYWORDS
        | UNDNAME_NO_FUNCTION_RETURNS
    )

    out: set[str] = set()
    for symbol in decorated_symbols:
        if not symbol.startswith("?"):
            continue
        src = symbol.encode("utf-8", errors="ignore")
        buf = ctypes.create_string_buffer(4096)
        size = undec(src, buf, ctypes.c_uint(len(buf)), ctypes.c_uint(flags))
        if size:
            dem = buf.value.decode("utf-8", errors="ignore").strip()
            if dem:
                out.add(dem)
                out.add(dem + "(void)")
    return out


def normalize_name_for_name_only(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if text.startswith("j_"):
        text = text[2:]
    dtr = re.match(r"^(?P<cls>[A-Za-z_][A-Za-z0-9_:]*)::dtr$", text)
    if dtr:
        cls = dtr.group("cls")
        cls_leaf = cls.split("::")[-1]
        return f"{cls}::~{cls_leaf}"
    text = ARGS_RE.sub("", text)
    return text


def generate_name_only_candidates(value: str) -> list[str]:
    base = normalize_name_for_name_only(value)
    if not base:
        return []
    candidates = [base]
    alias = ALIAS_SUFFIX_RE.match(base)
    if alias:
        prefix = alias.group("prefix") or ""
        name = alias.group("name")
        candidates.append(prefix + name)
    return candidates


def verify_row(
    raw_name: str,
    demangled: str,
    decorated_symbols: set[str],
    name_only_symbols: set[str],
) -> tuple[bool, str]:
    raw = (raw_name or "").strip()
    dem = (demangled or "").strip()

    decorated_candidate = raw[2:] if raw.startswith("j_") else raw
    if decorated_candidate and decorated_candidate in decorated_symbols:
        return True, f"decorated:{decorated_candidate}"

    for candidate in (raw, dem):
        for norm in generate_name_only_candidates(candidate):
            if norm in name_only_symbols:
                return True, f"name_only:{norm}"

    return False, ""


def main() -> int:
    args = parse_args()

    recovery_dir = Path(args.recovery_dir).resolve()
    names_json_path = Path(args.names_json).resolve() if args.names_json else find_latest_names_json(recovery_dir)
    recovered_progress_path = Path(args.recovered_progress).resolve()
    wx_lib = Path(args.wx_lib).resolve()
    symbol_dump = Path(args.symbol_dump).resolve()
    vcvars_bat = Path(args.vcvars_bat).resolve()
    csv_out = Path(args.csv_out).resolve()
    report_out = Path(args.report_out).resolve()
    queue_out = Path(args.queue_out).resolve()

    if args.refresh_symbol_dump:
        refresh_symbol_dump(symbol_dump=symbol_dump, wx_lib=wx_lib, vcvars_bat=vcvars_bat)

    decorated_symbols = load_decorated_symbols(symbol_dump)
    name_only_symbols = load_name_only_symbols(decorated_symbols)
    body_addresses = load_body_addresses(recovery_dir)
    status_map = load_status_map(recovered_progress_path, args.namespace)

    payload = json.loads(names_json_path.read_text(encoding="utf-8"))
    functions = payload.get("functions", [])
    if not isinstance(functions, list):
        raise ValueError(f"Unexpected names payload: {names_json_path}")

    rows: list[dict[str, str]] = []
    for fn in functions:
        if not isinstance(fn, dict):
            continue
        address = str(fn.get("address", "") or "")
        if not address:
            continue
        try:
            addr_int = to_addr_int(address)
        except Exception:
            continue

        raw_name = str(fn.get("raw_name", "") or "")
        demangled = str(fn.get("demangled", "") or "")
        token = extract_root_token(raw_name, demangled)
        dependency = classify_external_dependency(token, raw_name, demangled)
        if dependency != "wxWidgets":
            continue

        link_only = is_external_link_only(raw_name, demangled, dependency, token)
        has_body = (addr_int in body_addresses) and (not link_only)
        if not has_body:
            continue

        fun_token = f"FUN_{addr_int:08X}" if addr_int <= 0xFFFFFFFF else f"FUN_{addr_int:016X}"
        verified, match = verify_row(
            raw_name=raw_name,
            demangled=demangled,
            decorated_symbols=decorated_symbols,
            name_only_symbols=name_only_symbols,
        )
        status = status_map.get(fun_token, "")
        rows.append(
            {
                "token": fun_token,
                "address": f"0x{addr_int:08X}",
                "raw_name": raw_name,
                "demangled": demangled,
                "verified_in_wx_lib": "1" if verified else "0",
                "verification_match": match,
                "current_status": status,
            }
        )

    rows.sort(key=lambda row: int(row["address"], 16))
    verified_rows = [row for row in rows if row["verified_in_wx_lib"] == "1"]
    unverified_rows = [row for row in rows if row["verified_in_wx_lib"] != "1"]

    status_counts = Counter(row["current_status"] for row in rows)
    verified_status_counts = Counter(row["current_status"] for row in verified_rows)

    to_mark = sorted(
        {
            row["token"]
            for row in verified_rows
            if row["current_status"] != "external_dependency"
        },
        key=token_sort_key,
    )

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.parent.mkdir(parents=True, exist_ok=True)
    queue_out.parent.mkdir(parents=True, exist_ok=True)

    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "token",
                "address",
                "raw_name",
                "demangled",
                "verified_in_wx_lib",
                "verification_match",
                "current_status",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    queue_payload = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "namespace": args.namespace,
        "status": "external_dependency",
        "count": len(to_mark),
        "functions": to_mark,
    }
    queue_out.write_text(json.dumps(queue_payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# wxWidgets README-Scope Verification",
        "",
        "## Inputs",
        "",
        f"- Names index: `{names_json_path}`",
        f"- Recovery DB: `{recovered_progress_path}` (namespace: `{args.namespace}`)",
        f"- wx library: `{wx_lib}`",
        f"- Symbol dump: `{symbol_dump}`",
        "",
        "## Scope",
        "",
        "- Matches README `wxWidgets` denominator from `scripts/recovery_coverage.py`.",
        "- Includes only `has_body` entries and excludes link-only entries.",
        "",
        "## Summary",
        "",
        f"- README-scope wx total: `{len(rows)}`",
        f"- Verified in built wx library: `{len(verified_rows)}`",
        f"- Unverified: `{len(unverified_rows)}`",
        f"- Verified and already `external_dependency`: `{verified_status_counts.get('external_dependency', 0)}`",
        f"- Verified and still non-external: `{len(to_mark)}`",
        f"- CSV: `{csv_out}`",
        f"- Queue: `{queue_out}`",
        "",
        "## Current Status Split (README scope)",
        "",
        f"- external_dependency: `{status_counts.get('external_dependency', 0)}`",
        f"- recovered: `{status_counts.get('recovered', 0)}`",
        "",
    ]

    if unverified_rows:
        lines.extend(
            [
                "## First Unverified Samples",
                "",
                "| Token | Address | Raw | Demangled |",
                "| --- | --- | --- | --- |",
            ]
        )
        for row in unverified_rows[:30]:
            raw = row["raw_name"].replace("|", "\\|")
            dem = row["demangled"].replace("|", "\\|")
            lines.append(f"| {row['token']} | {row['address']} | `{raw}` | `{dem}` |")

    report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[wx-verify] csv={csv_out}")
    print(f"[wx-verify] report={report_out}")
    print(f"[wx-verify] queue={queue_out} count={len(to_mark)}")
    print(
        "[wx-verify] summary "
        f"readme_scope_total={len(rows)} verified={len(verified_rows)} unverified={len(unverified_rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
