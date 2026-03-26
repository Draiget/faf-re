#!/usr/bin/env python3
"""Detect Boost 1.34.0 vs 1.34.1 signature from FA decompiled code.

This script focuses on the only runtime-relevant Windows changes between
Boost 1.34.0 and 1.34.1 used by FAF:
  - libs/thread/src/tss.cpp
  - libs/thread/src/mutex.inl

In practice, the strongest discriminators are in tss.cpp:
  1) TlsSetValue(tss_data_native_key, 0) inside cleanup path
  2) tss_data_native_key reset to TLS_OUT_OF_INDEXES (-1) after TlsFree

If both signatures are present for the same TLS key variable in decompiled
FA code, we classify as Boost 1.34.1 patch behavior.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path

import pefile

def collect_targeted_changes(boost_1340: Path, boost_1341: Path) -> list[str]:
    patterns = [
        "boost/function*",
        "boost/shared_ptr*",
        "boost/weak_ptr*",
        "boost/enable_shared_from_this*",
        "boost/thread*",
        "boost/mutex*",
        "boost/recursive_mutex*",
        "boost/condition*",
        "boost/xtime*",
        "boost/detail/sp_*",
        "boost/detail/atomic_count*",
        "boost/detail/lightweight_*",
        "boost/detail/thread*",
        "libs/thread/src/*",
        "libs/function/src/*",
        "libs/smart_ptr/src/*",
    ]

    def collect(root: Path) -> set[str]:
        out: set[str] = set()
        for pat in patterns:
            for p in root.glob(pat):
                if p.is_file():
                    out.add(p.relative_to(root).as_posix())
        return out

    files0 = collect(boost_1340)
    files1 = collect(boost_1341)
    changed: list[str] = []

    for rel in sorted(files0 | files1):
        p0 = boost_1340 / rel
        p1 = boost_1341 / rel
        if not p0.exists() or not p1.exists():
            changed.append(rel)
            continue
        if p0.read_bytes() != p1.read_bytes():
            changed.append(rel)
    return changed


def _all_indices(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return out
        out.append(idx)
        start = idx + 1


def _u32(b: bytes) -> int:
    return struct.unpack("<I", b)[0]


def _is_reg_push(op: int) -> bool:
    return 0x50 <= op <= 0x57


def _read_import_iat(binary_path: Path) -> dict[str, int]:
    pe = pefile.PE(str(binary_path), fast_load=False)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    out: dict[str, int] = {}
    for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for entry in imp.imports:
            if not entry.name:
                continue
            name = entry.name.decode(errors="ignore")
            if name in {"TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue"}:
                out[name] = int(entry.address)
    return out


def _scan_free_reset_vars(data: bytes, tlsfree_iat_va: int) -> tuple[set[int], list[dict[str, int]]]:
    call_pat = b"\xff\x15" + struct.pack("<I", tlsfree_iat_va)
    vars_found: set[int] = set()
    hits: list[dict[str, int]] = []

    for call_off in _all_indices(data, call_pat):
        after = call_off + len(call_pat)
        end = min(len(data), after + 48)
        i = after
        while i + 10 <= end:
            # c7 05 <var32> ff ff ff ff
            if (
                data[i : i + 2] == b"\xc7\x05"
                and data[i + 6 : i + 10] == b"\xff\xff\xff\xff"
            ):
                var_va = _u32(data[i + 2 : i + 6])
                vars_found.add(var_va)
                hits.append(
                    {
                        "call_off": call_off,
                        "reset_off": i,
                        "var_va": var_va,
                    }
                )
                break
            i += 1
    return vars_found, hits


def _scan_set_zero_vars(data: bytes, tlsset_iat_va: int) -> tuple[set[int], list[dict[str, int]]]:
    call_pat = b"\xff\x15" + struct.pack("<I", tlsset_iat_va)
    vars_found: set[int] = set()
    hits: list[dict[str, int]] = []

    for call_off in _all_indices(data, call_pat):
        ws = max(0, call_off - 32)
        we = call_off
        win = data[ws:we]
        matched = False

        # A1 <var> 6A 00 5?
        for i in range(0, max(0, len(win) - 8) + 1):
            if win[i] == 0xA1:
                var_va = _u32(win[i + 1 : i + 5])
                if (
                    win[i + 5 : i + 7] == b"\x6a\x00"
                    and _is_reg_push(win[i + 7])
                    and (we - (ws + i + 8)) <= 2
                ):
                    vars_found.add(var_va)
                    hits.append(
                        {
                            "call_off": call_off,
                            "load_off": ws + i,
                            "var_va": var_va,
                        }
                    )
                    matched = True
                    break
        if matched:
            continue

        # 8B 05/0D/15/1D/35/3D <var> 6A 00 5?
        for i in range(0, max(0, len(win) - 9) + 1):
            if win[i : i + 1] == b"\x8b" and win[i + 1] in {0x05, 0x0D, 0x15, 0x1D, 0x35, 0x3D}:
                var_va = _u32(win[i + 2 : i + 6])
                if (
                    win[i + 6 : i + 8] == b"\x6a\x00"
                    and _is_reg_push(win[i + 8])
                    and (we - (ws + i + 9)) <= 2
                ):
                    vars_found.add(var_va)
                    hits.append(
                        {
                            "call_off": call_off,
                            "load_off": ws + i,
                            "var_va": var_va,
                        }
                    )
                    break
    return vars_found, hits


def _scan_alloc_guard_vars(data: bytes, tlsalloc_iat_va: int) -> tuple[set[int], list[dict[str, int]]]:
    call_pat = b"\xff\x15" + struct.pack("<I", tlsalloc_iat_va)
    vars_found: set[int] = set()
    hits: list[dict[str, int]] = []

    for call_off in _all_indices(data, call_pat):
        # Look for store of returned EAX into global TLS-key var:
        #   A3 <var>                mov [var], eax
        # or
        #   89 05 <var>             mov [var], eax
        after = call_off + len(call_pat)
        end = min(len(data), after + 40)
        i = after
        while i + 5 <= end:
            if data[i] == 0xA3:
                var_va = _u32(data[i + 1 : i + 5])
                vars_found.add(var_va)
                hits.append(
                    {
                        "call_off": call_off,
                        "store_off": i,
                        "var_va": var_va,
                    }
                )
                break
            if data[i : i + 2] == b"\x89\x05":
                var_va = _u32(data[i + 2 : i + 6])
                vars_found.add(var_va)
                hits.append(
                    {
                        "call_off": call_off,
                        "store_off": i,
                        "var_va": var_va,
                    }
                )
                break
            i += 1
    return vars_found, hits


def detect_from_binary(binary_path: Path) -> dict[str, object]:
    data = binary_path.read_bytes()
    imports = _read_import_iat(binary_path)
    missing = [n for n in ("TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue") if n not in imports]
    if missing:
        raise SystemExit(f"Missing required imports in binary: {', '.join(missing)}")

    free_reset_vars, free_reset_hits = _scan_free_reset_vars(data, imports["TlsFree"])
    set_zero_vars, set_zero_hits = _scan_set_zero_vars(data, imports["TlsSetValue"])
    alloc_guard_vars, alloc_hits = _scan_alloc_guard_vars(data, imports["TlsAlloc"])

    shared = sorted(free_reset_vars & set_zero_vars)
    strong = sorted((free_reset_vars & set_zero_vars) & alloc_guard_vars)

    if strong:
        verdict = "boost_1_34_1_signature_detected"
    elif shared:
        verdict = "boost_1_34_1_likely"
    else:
        verdict = "inconclusive_or_1_34_0"

    return {
        "binary_file": str(binary_path),
        "import_iat_va": {k: int(v) for k, v in imports.items()},
        "signature_analysis": {
            "verdict": verdict,
            "tls_set_zero_vars": [f"0x{v:08X}" for v in sorted(set_zero_vars)],
            "tls_free_reset_vars": [f"0x{v:08X}" for v in sorted(free_reset_vars)],
            "tls_alloc_guard_vars": [f"0x{v:08X}" for v in sorted(alloc_guard_vars)],
            "shared_signature_vars": [f"0x{v:08X}" for v in shared],
            "strong_signature_vars": [f"0x{v:08X}" for v in strong],
            "hit_counts": {
                "free_reset_hits": len(free_reset_hits),
                "set_zero_hits": len(set_zero_hits),
                "alloc_guard_hits": len(alloc_hits),
            },
        },
        "notes": [
            "Binary-mode check uses instruction signatures around TlsFree/TlsSetValue/TlsAlloc call sites.",
            "Strong match requires the same global TLS-key variable to satisfy all three signatures.",
        ],
    }


def find_tls_signature_vars(text: str) -> dict[str, list[str] | str]:
    set_zero_vars = set(
        re.findall(
            r"TlsSetValue\((DAT_[0-9A-Fa-f]+)\s*,\s*\(LPVOID\)0x0\)",
            text,
        )
    )
    free_reset_vars = set(
        re.findall(
            r"TlsFree\((DAT_[0-9A-Fa-f]+)\);\s*\1\s*=\s*0xffffffff;",
            text,
            flags=re.DOTALL,
        )
    )

    alloc_guard_vars: set[str] = set()
    for var in set_zero_vars | free_reset_vars:
        alloc_guard = re.search(
            rf"if\s*\(\s*{re.escape(var)}\s*==\s*0xffffffff\s*\)\s*\{{\s*{re.escape(var)}\s*=\s*TlsAlloc\(\);",
            text,
            flags=re.DOTALL,
        )
        if alloc_guard:
            alloc_guard_vars.add(var)

    shared_vars = sorted(set_zero_vars & free_reset_vars)
    strong_vars = sorted(set(shared_vars) & alloc_guard_vars)

    if strong_vars:
        verdict = "boost_1_34_1_signature_detected"
    elif shared_vars:
        verdict = "boost_1_34_1_likely"
    else:
        verdict = "inconclusive_or_1_34_0"

    return {
        "verdict": verdict,
        "tls_set_zero_vars": sorted(set_zero_vars),
        "tls_free_reset_vars": sorted(free_reset_vars),
        "tls_alloc_guard_vars": sorted(alloc_guard_vars),
        "shared_signature_vars": shared_vars,
        "strong_signature_vars": strong_vars,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--decomp-file",
        default="decomp/faf_code_p4.c",
        help="Decompiler C file to inspect (default: decomp/faf_code_p4.c)",
    )
    parser.add_argument(
        "--binary-file",
        default=None,
        help="Binary to inspect directly (e.g. bin/external/ForgedAlliance.exe)",
    )
    parser.add_argument(
        "--mode",
        choices=("decomp", "binary"),
        default="decomp",
        help="Detection mode (default: decomp)",
    )
    parser.add_argument(
        "--boost-1340",
        default=r"G:\lib\boost_1_34_0",
        help=r"Path to Boost 1.34.0 root (default: G:\lib\boost_1_34_0)",
    )
    parser.add_argument(
        "--boost-1341",
        default=r"G:\lib\boost_1_34_1",
        help=r"Path to Boost 1.34.1 root (default: G:\lib\boost_1_34_1)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output",
    )
    args = parser.parse_args()

    boost_1340 = Path(args.boost_1340)
    boost_1341 = Path(args.boost_1341)

    if not boost_1340.exists():
        raise SystemExit(f"Boost 1.34.0 path not found: {boost_1340}")
    if not boost_1341.exists():
        raise SystemExit(f"Boost 1.34.1 path not found: {boost_1341}")

    changed_files = collect_targeted_changes(boost_1340, boost_1341)
    result: dict[str, object]
    sig: dict[str, object]
    if args.mode == "binary":
        if not args.binary_file:
            raise SystemExit("--binary-file is required when --mode=binary")
        binary_path = Path(args.binary_file)
        if not binary_path.exists():
            raise SystemExit(f"Binary file not found: {binary_path}")
        result = detect_from_binary(binary_path)
        sig = result["signature_analysis"]  # type: ignore[assignment]
    else:
        decomp_path = Path(args.decomp_file)
        if not decomp_path.exists():
            raise SystemExit(f"Decompiler file not found: {decomp_path}")
        text = decomp_path.read_text(encoding="utf-8", errors="ignore")
        sig = find_tls_signature_vars(text)
        result = {
            "decomp_file": str(decomp_path),
            "signature_analysis": sig,
            "notes": [
                "Only libs/thread/src/tss.cpp contributes the decisive runtime fingerprint on Win32.",
                "function.hpp and atomic_count_gcc.hpp changes are compiler/platform specific and not useful for MSVC8/x86 FA runtime.",
            ],
        }

    result["targeted_changed_files_1340_vs_1341"] = changed_files
    result["runtime_relevant_changed_files"] = [
        p for p in changed_files if p.startswith("libs/thread/src/")
    ]

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    if args.mode == "binary":
        print(f"Binary file: {result['binary_file']}")
        print("Import IAT VAs:")
        for name, va in result["import_iat_va"].items():  # type: ignore[index]
            print(f"  - {name}: 0x{va:08X}")
    else:
        print(f"Decomp file: {result['decomp_file']}")

    print("Targeted changed files (1.34.0 -> 1.34.1):")
    for rel in result["targeted_changed_files_1340_vs_1341"]:
        print(f"  - {rel}")
    print("Runtime-relevant changed files:")
    for rel in result["runtime_relevant_changed_files"]:
        print(f"  - {rel}")

    print("Signature analysis:")
    print(f"  verdict: {sig['verdict']}")
    print(f"  shared signature vars: {', '.join(sig['shared_signature_vars']) or '(none)'}")
    print(f"  strong signature vars: {', '.join(sig['strong_signature_vars']) or '(none)'}")

    if sig["verdict"] == "boost_1_34_1_signature_detected":
        print("Conclusion: binary/decomp behavior matches Boost 1.34.1 tss.cpp patch signatures.")
    elif sig["verdict"] == "boost_1_34_1_likely":
        print("Conclusion: 1.34.1 is likely, but not all strong checks matched.")
    else:
        print("Conclusion: inconclusive for 1.34.1; could be 1.34.0 or patched variant.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
