#!/usr/bin/env python3
"""
Compute FAF reconstruction coverage from source annotations and IDA exports.

Inputs:
- decomp/recovery/fa_function_names_*.json (function universe + names)
- src/sdk/** Address: 0xXXXXXXXX annotations (recovered function evidence)

Outputs:
- Human-readable summary (default)
- JSON payload (--format json)
- Optional CSV dump of excluded external functions (--dump-excluded-external-csv)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple


ADDR_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{8})")
NS_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)::")
MSVC_SCOPE_RE = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)@@")
XACT_TOKEN_RE = re.compile(r"(?:^|[^a-z])xact(?:[^a-z]|$)", re.IGNORECASE)
ZLIB_RAW_NAMES = {
    "inflate",
    "inflatereset",
    "inflateinit2_",
    "inflateinit_",
    "inflateend",
    "deflate",
    "deflateend",
    "deflate_stored",
    "deflate_fast",
    "deflate_slow",
    "deflatereset",
    "deflateparams",
    "deflateinit2_",
    "adler32",
    "crc32",
}
FILE_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cpp", ".cc", ".cxx", ".inl", ".ipp"}
DEFAULT_EXCLUDED_EXTERNAL_DEPENDENCIES = {"Boost", "zlib"}


@dataclass(frozen=True)
class FunctionOwner:
    family: str  # moho | gpg | external | unknown
    dependency: Optional[str] = None
    token: Optional[str] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute FAF reconstruction coverage")
    parser.add_argument(
        "--src-root",
        default="src/sdk",
        help="Source root scanned for Address: 0x... annotations (default: src/sdk)",
    )
    parser.add_argument(
        "--recovery-dir",
        default="decomp/recovery",
        help="Directory containing fa_function_names_*.json (default: decomp/recovery)",
    )
    parser.add_argument(
        "--names-json",
        default="",
        help="Explicit fa_function_names JSON file path (optional)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--exclude-external-dependency",
        action="append",
        default=sorted(DEFAULT_EXCLUDED_EXTERNAL_DEPENDENCIES),
        help=(
            "External dependency to exclude from scoped reconstruction denominator "
            "(repeatable, default: Boost, zlib)"
        ),
    )
    parser.add_argument(
        "--dump-excluded-external-csv",
        default="",
        help=(
            "Optional CSV output path for address inventory of excluded external dependencies "
            "(for example Boost)."
        ),
    )
    return parser.parse_args()


def find_latest_names_json(recovery_dir: Path) -> Path:
    candidates = sorted(recovery_dir.glob("fa_function_names_*.json"))
    if not candidates:
        raise FileNotFoundError(f"No fa_function_names_*.json in {recovery_dir}")
    return candidates[-1]


def normalize_token(token: str) -> str:
    token = token.strip()
    while token.startswith("j_"):
        token = token[2:]
    return token


def extract_root_token(raw_name: str, demangled: str) -> Optional[str]:
    # Prefer demangled namespace when present.
    if demangled:
        match = NS_RE.search(demangled)
        if match:
            return normalize_token(match.group(1))

    # Then try raw name namespace.
    if raw_name:
        match = NS_RE.search(raw_name)
        if match:
            return normalize_token(match.group(1))

    # Finally, try MSVC mangled owner scope token.
    if raw_name:
        for match in MSVC_SCOPE_RE.finditer(raw_name):
            token = normalize_token(match.group(1))
            if token:
                return token

    return None


def classify_external_dependency(token: Optional[str], raw_name: str, demangled: str) -> Optional[str]:
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

    # DirectX/XACT: avoid false positives like "wxActivateEvent".
    if "direct3d" in hay or "ixact" in hay:
        return "DirectX/XACT"
    if token_lower.startswith("idirect3d") or token_lower.startswith("ixact"):
        return "DirectX/XACT"
    if XACT_TOKEN_RE.search(hay):
        return "DirectX/XACT"
    raw_no_imp = raw_lower[6:] if raw_lower.startswith("__imp_") else raw_lower
    if raw_no_imp in ZLIB_RAW_NAMES or raw_no_imp.startswith("gz"):
        return "zlib"

    return None


def classify_owner(raw_name: str, demangled: str) -> FunctionOwner:
    token = extract_root_token(raw_name, demangled)
    token_lower = (token or "").lower()

    if token_lower == "moho":
        return FunctionOwner("moho", token=token)
    if token_lower == "gpg":
        return FunctionOwner("gpg", token=token)

    # Handle decorated cases where root token cannot be extracted cleanly.
    combined = f"{raw_name}\n{demangled}"
    if "@Moho@@" in combined or "Moho::" in combined:
        return FunctionOwner("moho", token="Moho")
    if "@gpg@@" in combined or "gpg::" in combined:
        return FunctionOwner("gpg", token="gpg")

    dependency = classify_external_dependency(token, raw_name, demangled)
    if dependency:
        return FunctionOwner("external", dependency=dependency, token=token)

    return FunctionOwner("unknown", token=token)


def to_addr_int(address: str) -> int:
    address = address.strip()
    if address.lower().startswith("0x"):
        return int(address, 16)
    return int(address, 16)


def iter_source_files(src_root: Path) -> Iterable[Path]:
    for path in src_root.rglob("*"):
        if path.is_file() and path.suffix.lower() in FILE_EXTENSIONS:
            yield path


def collect_annotated_addresses(src_root: Path) -> Counter:
    counts: Counter = Counter()
    for path in iter_source_files(src_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in ADDR_RE.finditer(text):
            addr = int(match.group(1), 16)
            counts[addr] += 1
    return counts


def is_external_link_only(owner: FunctionOwner, raw_name: str, demangled: str) -> bool:
    """
    Heuristic for external link-only entries (import/thunk/interface API surface)
    that should not be treated as reconstructable in-binary bodies.
    """
    raw = raw_name.strip()
    dem = demangled.strip()
    raw_lower = raw.lower()
    dem_lower = dem.lower()
    token_lower = (owner.token or "").lower()

    if raw_lower.startswith("__imp_") or raw_lower.startswith("j_"):
        return True

    if owner.dependency == "DirectX/XACT":
        if raw_lower.startswith("direct3dcreate"):
            return True
        if token_lower.startswith("ixact") or token_lower.startswith("idirect3d"):
            return True
        if raw.startswith("IXACT") or raw.startswith("IDirect3D"):
            return True
        if dem.startswith("IXACT") or dem.startswith("IDirect3D"):
            return True

    return False


def load_decomp_body_addresses(recovery_dir: Path) -> set[int]:
    """
    Best-effort load of addresses known to have decompilation body context.
    Uses function-context.csv when available.
    """
    csv_path = recovery_dir / "function-context.csv"
    if not csv_path.exists():
        return set()

    body_addresses: set[int] = set()
    try:
        import csv

        with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = (row.get("Address") or "").strip()
                decomp_hits_str = (row.get("DecompHits") or "0").strip()
                if not addr:
                    continue
                try:
                    decomp_hits = int(decomp_hits_str)
                except ValueError:
                    decomp_hits = 0
                if decomp_hits > 0:
                    body_addresses.add(to_addr_int(addr))
    except OSError:
        return set()

    return body_addresses


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return (numerator / denominator) * 100.0


def format_ratio(numerator: int, denominator: int) -> str:
    return f"{numerator:,}/{denominator:,} ({pct(numerator, denominator):.2f}%)"


def build_report(
    names_json_path: Path,
    src_root: Path,
    excluded_external_dependencies: Optional[set[str]] = None,
    include_excluded_external_entries: bool = False,
) -> Dict:
    excluded_external_dependencies = {dep for dep in (excluded_external_dependencies or set()) if dep}
    obj = json.loads(names_json_path.read_text(encoding="utf-8"))
    functions = obj.get("functions", [])
    function_count = int(obj.get("function_count", len(functions)))

    owner_by_addr: Dict[int, FunctionOwner] = {}
    raw_name_by_addr: Dict[int, str] = {}
    demangled_by_addr: Dict[int, str] = {}
    fa_addresses = set()
    for fn in functions:
        addr_str = fn.get("address", "")
        if not addr_str:
            continue
        addr = to_addr_int(addr_str)
        raw_name = fn.get("raw_name", "") or ""
        demangled = fn.get("demangled", "") or ""
        owner = classify_owner(raw_name, demangled)
        owner_by_addr[addr] = owner
        raw_name_by_addr[addr] = raw_name
        demangled_by_addr[addr] = demangled
        fa_addresses.add(addr)

    recovery_dir = names_json_path.parent
    body_addresses = load_decomp_body_addresses(recovery_dir)

    annotated_counts = collect_annotated_addresses(src_root)
    annotated_addresses = set(annotated_counts.keys())

    recovered_fa_addresses = annotated_addresses & fa_addresses
    non_fa_annotated = annotated_addresses - fa_addresses

    family_total = Counter()
    family_recovered = Counter()
    dependency_total = Counter()
    dependency_recovered = Counter()
    token_total = Counter()
    external_excluded_dependency_total = Counter()
    external_excluded_dependency_recovered = Counter()
    external_excluded_no_body_total = Counter()
    external_excluded_no_body_recovered = Counter()
    excluded_external_entries = []

    include_external_by_addr: Dict[int, bool] = {}

    for addr, owner in owner_by_addr.items():
        token = owner.token or "<none>"
        token_total[token] += 1
        if owner.family in {"moho", "gpg", "external"}:
            if owner.family == "external":
                dep = owner.dependency or "OtherExternal"
                raw_name = raw_name_by_addr.get(addr, "")
                demangled = demangled_by_addr.get(addr, "")
                is_link_only = is_external_link_only(
                    owner=owner,
                    raw_name=raw_name,
                    demangled=demangled,
                )
                has_body = (addr in body_addresses) and not is_link_only

                if dep in excluded_external_dependencies:
                    external_excluded_dependency_total[dep] += 1
                    if include_excluded_external_entries:
                        excluded_external_entries.append(
                            {
                                "dependency": dep,
                                "address": f"0x{addr:08X}",
                                "has_body": has_body,
                                "is_link_only": is_link_only,
                                "raw_name": raw_name,
                                "demangled": demangled,
                            }
                        )
                    continue
                include_external_by_addr[addr] = has_body
                if not has_body:
                    external_excluded_no_body_total[dep] += 1
                    continue

            family_total[owner.family] += 1
            if owner.family == "external":
                dependency_total[owner.dependency or "OtherExternal"] += 1

    for addr in recovered_fa_addresses:
        owner = owner_by_addr.get(addr)
        if not owner:
            continue
        if owner.family in {"moho", "gpg", "external"}:
            if owner.family == "external":
                dep = owner.dependency or "OtherExternal"
                if dep in excluded_external_dependencies:
                    external_excluded_dependency_recovered[dep] += 1
                    continue
                if not include_external_by_addr.get(addr, False):
                    external_excluded_no_body_recovered[dep] += 1
                    continue
            family_recovered[owner.family] += 1
            if owner.family == "external":
                dependency_recovered[owner.dependency or "OtherExternal"] += 1

    scoped_total = sum(family_total[f] for f in ("moho", "gpg", "external"))
    scoped_recovered = sum(family_recovered[f] for f in ("moho", "gpg", "external"))

    report = {
        "names_json": str(names_json_path),
        "source_root": str(src_root),
        "function_count_total": function_count,
        "function_rows": len(functions),
        "annotated_addresses_total": len(annotated_addresses),
        "annotated_addresses_fa": len(recovered_fa_addresses),
        "annotated_addresses_non_fa": len(non_fa_annotated),
        "coverage_total": {
            "recovered": len(recovered_fa_addresses),
            "max": function_count,
            "percent": pct(len(recovered_fa_addresses), function_count),
        },
        "coverage_scoped": {
            "recovered": scoped_recovered,
            "max": scoped_total,
            "percent": pct(scoped_recovered, scoped_total),
        },
        "family": {
            family: {
                "recovered": int(family_recovered[family]),
                "max": int(family_total[family]),
                "percent": pct(int(family_recovered[family]), int(family_total[family])),
            }
            for family in ("moho", "gpg", "external")
        },
        "external_dependencies": {
            dep: {
                "recovered": int(dependency_recovered[dep]),
                "max": int(dependency_total[dep]),
                "percent": pct(int(dependency_recovered[dep]), int(dependency_total[dep])),
            }
            for dep in sorted(dependency_total.keys())
        },
        "external_excluded_dependency": {
            dep: {
                "recovered": int(external_excluded_dependency_recovered[dep]),
                "max": int(external_excluded_dependency_total[dep]),
                "percent": pct(
                    int(external_excluded_dependency_recovered[dep]),
                    int(external_excluded_dependency_total[dep]),
                ),
            }
            for dep in sorted(external_excluded_dependency_total.keys())
        },
        "external_excluded_no_body": {
            dep: {
                "recovered": int(external_excluded_no_body_recovered[dep]),
                "max": int(external_excluded_no_body_total[dep]),
                "percent": pct(
                    int(external_excluded_no_body_recovered[dep]),
                    int(external_excluded_no_body_total[dep]),
                ),
            }
            for dep in sorted(external_excluded_no_body_total.keys())
        },
    }

    if include_excluded_external_entries:
        report["external_excluded_entries"] = sorted(
            excluded_external_entries,
            key=lambda item: (item["dependency"], item["address"]),
        )

    return report


def dump_excluded_external_csv(output_path: Path, entries: list[Dict]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ("dependency", "address", "has_body", "is_link_only", "raw_name", "demangled")
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "dependency": entry.get("dependency", ""),
                    "address": entry.get("address", ""),
                    "has_body": 1 if entry.get("has_body", False) else 0,
                    "is_link_only": 1 if entry.get("is_link_only", False) else 0,
                    "raw_name": entry.get("raw_name", ""),
                    "demangled": entry.get("demangled", ""),
                }
            )


def print_text(report: Dict) -> None:
    print("FAF Reconstruction Coverage")
    print("===========================")
    print(f"Names index: {report['names_json']}")
    print(f"Source root: {report['source_root']}")
    print()
    print(f"Total FAF functions: {report['function_count_total']:,}")
    print(
        "Recovered FAF functions in source annotations: "
        f"{format_ratio(report['coverage_total']['recovered'], report['coverage_total']['max'])}"
    )
    print(
        "Scoped coverage (moho+gpg+external): "
        f"{format_ratio(report['coverage_scoped']['recovered'], report['coverage_scoped']['max'])}"
    )
    print()
    print(
        "Annotated addresses under src root: "
        f"{report['annotated_addresses_total']:,} "
        f"(FA: {report['annotated_addresses_fa']:,}, non-FA: {report['annotated_addresses_non_fa']:,})"
    )
    print()
    print("External dependencies excluded from scoped metrics")
    print("-------------------------------------------------")
    if not report["external_excluded_dependency"]:
        print("- (none)")
    else:
        for dep, block in sorted(
            report["external_excluded_dependency"].items(),
            key=lambda item: item[1]["max"],
            reverse=True,
        ):
            print(f"- {dep}: {format_ratio(block['recovered'], block['max'])}")
    print()
    print("External entries excluded (no body evidence)")
    print("-------------------------------------------")
    if not report["external_excluded_no_body"]:
        print("- (none)")
    else:
        for dep, block in sorted(
            report["external_excluded_no_body"].items(),
            key=lambda item: item[1]["max"],
            reverse=True,
        ):
            print(f"- {dep}: {format_ratio(block['recovered'], block['max'])}")
    print()
    print("Namespace families")
    print("------------------")
    for family in ("moho", "gpg", "external"):
        block = report["family"][family]
        print(f"- {family}: {format_ratio(block['recovered'], block['max'])}")
    print()
    print("External dependency split")
    print("-------------------------")
    if not report["external_dependencies"]:
        print("- (none detected)")
        return
    for dep, block in sorted(
        report["external_dependencies"].items(),
        key=lambda item: item[1]["max"],
        reverse=True,
    ):
        print(f"- {dep}: {format_ratio(block['recovered'], block['max'])}")


def main() -> int:
    args = parse_args()
    src_root = Path(args.src_root).resolve()
    recovery_dir = Path(args.recovery_dir).resolve()
    names_json_path = Path(args.names_json).resolve() if args.names_json else find_latest_names_json(recovery_dir)

    if not src_root.exists():
        print(f"error: src root not found: {src_root}", file=sys.stderr)
        return 2
    if not names_json_path.exists():
        print(f"error: names json not found: {names_json_path}", file=sys.stderr)
        return 2

    excluded_external_dependencies = {
        dep.strip() for dep in args.exclude_external_dependency if dep and dep.strip()
    }
    dump_excluded_external_csv_path = Path(args.dump_excluded_external_csv).resolve() if args.dump_excluded_external_csv else None
    report = build_report(
        names_json_path=names_json_path,
        src_root=src_root,
        excluded_external_dependencies=excluded_external_dependencies,
        include_excluded_external_entries=bool(dump_excluded_external_csv_path),
    )

    if dump_excluded_external_csv_path:
        dump_excluded_external_csv(
            output_path=dump_excluded_external_csv_path,
            entries=report.get("external_excluded_entries", []),
        )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
