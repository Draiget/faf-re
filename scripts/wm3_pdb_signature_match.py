"""Cross-reference upstream WildMagic3p8 Foundation.lib symbols against the
FA binary's `Wm3::*` functions, to validate (and potentially extend) the
external_dependency set produced by the namespace-prefix sweep.

Pipeline:
  1. Parse `tmp/foundation_symbols.txt` (output of `dumpbin /symbols
     output/Foundation/Win32/Debug/Foundation.lib`) to get every
     defined external symbol's (mangled, demangled) pair.
  2. Filter to demangled names whose qualified path starts with `Wm3::`.
  3. Load the FA callgraph index sqlite and pull every function whose
     best-demangled name starts with `Wm3::`.
  4. Compare the two name sets and emit four buckets:
       - both:    Wm3 functions present in FA AND in Foundation.lib
                  (canonical external_dependency hits, high confidence)
       - fa_only: Wm3-named functions in FA that have NO matching symbol
                  in Foundation.lib — investigate (possibly template
                  instantiations FA emitted explicitly, or upstream
                  inlined them, or signature drift)
       - lib_only: Wm3 symbols in Foundation.lib that don't appear in
                   the FA binary (not interesting — Wm3 ships more than
                   FA used)
       - 73-recovered: Wm3 functions already recovered into src/sdk/wm3
                       (informational; these become wrappers in the
                       last step)

Run after `dependencies/WildMagic3p8/tools/dumpbin_symbols.bat` has produced
`tmp/foundation_symbols.txt`.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_NAMESPACE = "fa_full_2026_03_26"


def parse_dumpbin_symbols(path: Path) -> dict[str, str]:
    """Return {demangled_name: mangled_name} for every defined external symbol.

    Skips:
      - UNDEF entries (imports from other TUs, not defined here)
      - Static / Label storage classes
      - Symbols with no demangled annotation (compiler-internal stuff)
    """
    out: dict[str, str] = {}
    # dumpbin row: `IDX HEX SECT     notype ()    External    | MANGLED (DEMANGLED)`
    pat = re.compile(
        r"^[0-9A-F]+\s+[0-9A-F]+\s+(\S+)\s+\S+(?:\s+\(\))?\s+External\s+\|\s+(\S+)\s*(?:\((.*)\))?\s*$"
    )
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = pat.match(line)
        if not m:
            continue
        section, mangled, demangled = m.group(1), m.group(2), (m.group(3) or "")
        if section == "UNDEF":
            continue
        if not demangled.strip():
            continue
        # Strip trailing whitespace/parens artifacts
        demangled = demangled.strip()
        # Some demangled forms have a trailing `)` from the symbol annotation
        # because the regex above is greedy on the inner group; ensure
        # parentheses balance.
        if demangled.count("(") < demangled.count(")"):
            demangled = demangled.rsplit(")", 1)[0]
        if mangled in out:
            continue
        out[mangled] = demangled
    return out


def normalize_qualified(name: str) -> str:
    """Strip return type / calling convention / parameter list from a demangled
    function name to get just the qualified path (e.g.
    `void __thiscall Wm3::Vector3<float>::Normalize(void)` → `Wm3::Vector3<float>::Normalize`).
    """
    s = name
    # Drop the parameter list
    paren = s.find("(")
    if paren != -1:
        # Walk back over `__thiscall ` etc to keep just `RetType QName`
        s = s[:paren].rstrip()
    # The last whitespace-separated token before the param list is usually
    # the qualified path; but with templates we might have spaces inside `<>`.
    # Strip top-level return type: split at the LAST top-level whitespace.
    depth = 0
    cut = -1
    for i, ch in enumerate(s):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch.isspace() and depth == 0:
            cut = i
    if cut != -1:
        s = s[cut + 1 :]
    return s


# Map MSVC `<float>`/`<double>`/`<int>` template suffixes onto the Wm3 typedef
# aliases that the FA binary's IDA-derived names use. We normalize BOTH sides
# to the typedef form (Vector3f, Vector3d, etc.) so equivalences collapse.
TEMPLATE_SUFFIX_MAP = [
    ("<float>", "f"),
    ("<double>", "d"),
    ("<int>", "i"),
    ("<int64>", "i64"),
    ("<__int64>", "i64"),
    ("<unsigned int>", "u"),
    ("<unsigned char>", "uc"),
    ("<char>", "c"),
    ("<short>", "s"),
    ("<unsigned short>", "us"),
]


def fold_template_aliases(qname: str) -> str:
    """Convert template-instantiation names like `Wm3::Vector3<float>::Add`
    into their Wm3 typedef-alias equivalents (`Wm3::Vector3f::Add`).

    The FA binary's IDA exports use the typedef forms because they were
    written that way in the original source; the modern MSVC compiler emits
    the explicit template form in PDB symbols. This pass normalizes both
    sides to the typedef form so name comparison works.
    """
    s = qname
    for template, suffix in TEMPLATE_SUFFIX_MAP:
        s = s.replace(template, suffix)
    return s


def collect_wm3_symbols_from_lib(symbols: dict[str, str]) -> set[str]:
    out: set[str] = set()
    for mangled, demangled in symbols.items():
        qname = normalize_qualified(demangled)
        if qname.startswith("Wm3::"):
            out.add(fold_template_aliases(qname))
    return out


def best_demangled(fn: str | None, dm: str | None, ln: str | None) -> str:
    for n in (dm, ln, fn):
        if n and not n.startswith("?"):
            if " [" in n:
                n = n.split(" [")[0]
            return n
    return fn or ""


def collect_wm3_from_fa(db_path: Path, progress_path: Path, namespace: str) -> tuple[set[str], dict[str, str], dict[str, str]]:
    """Return (wm3_names, name->token, token->status) for Wm3-owned FA functions."""
    progress = json.loads(progress_path.read_text(encoding="utf-8"))
    rec_db = progress.get("namespaces", {}).get(namespace, {}).get("recovered", {})

    con = sqlite3.connect(db_path)
    rows = con.execute("SELECT token, function_name, demangled_name, listing_name FROM functions").fetchall()
    con.close()

    names: set[str] = set()
    name_to_token: dict[str, str] = {}
    token_to_status: dict[str, str] = {}
    for token, fn, dm, ln in rows:
        raw_name = best_demangled(fn, dm, ln)
        if not raw_name.startswith("Wm3::"):
            continue
        # Strip parameter list if any (some FA names already lack it).
        normalized = fold_template_aliases(raw_name.split("(", 1)[0].strip())
        names.add(normalized)
        name_to_token[normalized] = token
        token_to_status[token] = rec_db.get(token, {}).get("status", "<not in progress>")
    return names, name_to_token, token_to_status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--symbols",
        type=Path,
        default=REPO / "tmp" / "foundation_symbols.txt",
        help="Path to the dumpbin /symbols output (run dumpbin_symbols.bat to produce).",
    )
    parser.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=f"FA recovery namespace key (default: {DEFAULT_NAMESPACE}).",
    )
    parser.add_argument(
        "--progress",
        type=Path,
        default=REPO / "decomp" / "recovery" / "recovered_progress.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO / "tmp",
    )
    parser.add_argument(
        "--print-samples",
        type=int,
        default=10,
    )
    args = parser.parse_args()

    if not args.symbols.exists():
        print(f"Symbols dump not found: {args.symbols}", file=sys.stderr)
        print("Run: dependencies/WildMagic3p8/tools/dumpbin_symbols.bat output/Foundation/Win32/Debug/Foundation.lib tmp/foundation_symbols.txt", file=sys.stderr)
        return 2

    db_path = REPO / "decomp" / "recovery" / "disasm" / args.namespace / "_callgraph_index.sqlite"
    if not db_path.exists():
        print(f"FA callgraph index not found: {db_path}", file=sys.stderr)
        return 2

    print(f"Parsing {args.symbols.name}...")
    raw_symbols = parse_dumpbin_symbols(args.symbols)
    print(f"  parsed {len(raw_symbols)} defined external symbols")

    lib_wm3 = collect_wm3_symbols_from_lib(raw_symbols)
    print(f"  {len(lib_wm3)} Wm3:: qualified names in Foundation.lib")

    print(f"Loading FA Wm3 functions from {args.namespace}...")
    fa_wm3, name_to_token, token_to_status = collect_wm3_from_fa(db_path, args.progress, args.namespace)
    print(f"  {len(fa_wm3)} Wm3:: functions in FA binary")

    both = fa_wm3 & lib_wm3
    fa_only = fa_wm3 - lib_wm3
    lib_only = lib_wm3 - fa_wm3
    print()
    print(f"both (in FA AND Foundation.lib):    {len(both)}")
    print(f"fa_only (in FA, not in Foundation):  {len(fa_only)}")
    print(f"lib_only (in Foundation, not in FA): {len(lib_only)}")

    # Within fa_only, break out by current recovery status
    fa_only_by_status: dict[str, list[str]] = {}
    for name in sorted(fa_only):
        tok = name_to_token[name]
        status = token_to_status.get(tok, "<unknown>")
        fa_only_by_status.setdefault(status, []).append(f"{tok}  {name}")
    print()
    print("fa_only by current recovery status:")
    for status in sorted(fa_only_by_status.keys(), key=lambda s: -len(fa_only_by_status[s])):
        items = fa_only_by_status[status]
        print(f"  {status:<24} {len(items):>4}")
        for it in items[: args.print_samples]:
            print(f"      {it}")
        if len(items) > args.print_samples:
            print(f"      ... ({len(items) - args.print_samples} more)")

    print()
    print("both by current recovery status:")
    both_by_status: dict[str, int] = {}
    for name in both:
        tok = name_to_token[name]
        status = token_to_status.get(tok, "<unknown>")
        both_by_status[status] = both_by_status.get(status, 0) + 1
    for status in sorted(both_by_status.keys(), key=lambda s: -both_by_status[s]):
        print(f"  {status:<24} {both_by_status[status]:>4}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "wm3_pdb_both.txt").write_text(
        "\n".join(sorted(both)) + "\n", encoding="utf-8"
    )
    (args.out_dir / "wm3_pdb_fa_only.txt").write_text(
        "\n".join(sorted(fa_only)) + "\n", encoding="utf-8"
    )
    (args.out_dir / "wm3_pdb_lib_only.txt").write_text(
        "\n".join(sorted(lib_only)) + "\n", encoding="utf-8"
    )

    # Wrapper-conversion seed list: FA Wm3 functions that are
    #   (a) currently `recovered` (manual recovery exists in src/sdk/wm3/), AND
    #   (b) confirmed to exist as a matching symbol in upstream Foundation.lib.
    # These are the highest-confidence wrapper candidates for the next step.
    wrapper_seeds: list[tuple[str, str]] = []
    for name in sorted(both):
        tok = name_to_token[name]
        status = token_to_status.get(tok, "")
        if status == "recovered":
            wrapper_seeds.append((tok, name))
    seed_path = args.out_dir / "wm3_wrapper_seeds.txt"
    with seed_path.open("w", encoding="utf-8") as f:
        for tok, name in wrapper_seeds:
            f.write(f"{tok}  {name}\n")

    print()
    print(f"Wrote tmp/wm3_pdb_both.txt, tmp/wm3_pdb_fa_only.txt, tmp/wm3_pdb_lib_only.txt")
    print(f"Wrote tmp/wm3_wrapper_seeds.txt: {len(wrapper_seeds)} high-confidence wrapper candidates")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
