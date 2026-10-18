#!/usr/bin/env python3
"""callcheck -- find recovered functions that call a DIFFERENT helper than retail.

For every function definition carrying a Doxygen `Address:` block in the given
source files/dirs, compare:

  retail  : direct call targets in the IDA/capstone export
            (decomp/recovery/disasm/<ns>/FUN_X.asm), `call imm` plus `jmp imm`
            tail-calls out of the function, with jmp-thunks followed and ICF
            twins folded by body sha256;
  ours    : identifiers our body calls (`Name(`, `Qual::Name(`, `.Name(`,
            `->Name(`) that resolve through the faidx anchor index
            (decomp/recovery/_source_index.sqlite) to binary addresses.
            Unannotated same-file helpers called from the body are expanded
            (depth 2) so a static wrapper does not hide its callees.

Tags: [wrap]  the pair is explained by one calling the other (demoted);
      [trunc] the retail export stops at a jmp out of the function (FAF patch
              hook / split chunk) so retail's callee list is incomplete --
              confirm with cdb `u` past the cut before believing it.

Findings:
  (A) SWAP    our body calls annotated X that retail never calls here, while
              retail calls annotated Y that our body never calls, and X/Y share
              a name family (camel-case word overlap, same class).  Highest
              signal: this is the MatrixToQuat vs MatrixRowsToQuatCanonical
              shape.  Pairs explained by wrapping (Y is a callee of X or vice
              versa) are demoted and tagged `wrap`.
  (B) MISSING retail callee annotated in our tree that our body never reaches.
              Lower signal (inlining is legal), listed per function.

Usage:
  python tools/callcheck/callcheck.py src/sdk/moho/sim src/sdk/moho/unit ...
  python tools/callcheck/callcheck.py --fn FUN_006FC010 src/sdk/moho/entity
  python tools/callcheck/callcheck.py --min-score 0.3 --top 80 --missing <paths>

Refresh the anchor index first after edits: `python scripts/faidx.py update`.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NS = "fa_full_2026_03_26"
DISASM = REPO / "decomp" / "recovery" / "disasm" / NS
CG_DB = DISASM / "_callgraph_index.sqlite"
SRC_DB = REPO / "decomp" / "recovery" / "_source_index.sqlite"

KEYWORDS = {
    "if", "while", "for", "switch", "return", "sizeof", "alignof", "decltype",
    "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast", "catch",
    "throw", "new", "delete", "assert", "static_assert", "offsetof", "noexcept",
    "defined", "operator", "typeid", "co_return", "requires", "do", "else",
}
# Container/trivial names that resolve to dozens of template emissions; they
# carry no "which helper" signal.
GENERIC_MAX_CANDIDATES = 12
# Retail callees with more callers than this are plumbing (string, allocator,
# container emissions); never report them as "missing".
GENERIC_CALLERS = 60
STOP_WORDS = {"to", "of", "from", "the", "a", "an", "and", "or", "by", "for",
              "in", "on", "at", "with", "is", "get", "set", "fn", "func", "impl",
              "sub", "cfunc", "lua", "l", "ex", "this", "moho", "gpg", "wm3"}

CALL_RE = re.compile(
    r"(?:(?P<qual>[A-Za-z_]\w*(?:<[^<>;(){}]*>)?)\s*::\s*)?"
    r"(?P<name>~?[A-Za-z_]\w*)\s*(?:<[^<>;(){}]*(?:<[^<>;(){}]*>[^<>;(){}]*)*>)?\s*\(")
ASM_LINE = re.compile(r"^0x([0-9A-Fa-f]+):\s+(?:[0-9A-F]{2} )+\s*(\w+)\s+(.*)$")


def camel_words(name: str) -> set[str]:
    name = name.lstrip("~")
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+|[A-Z]+", name)
    return {p.lower() for p in parts if p.lower() not in STOP_WORDS}


def short_and_class(symbol: str) -> tuple[str, str]:
    sym = re.sub(r"<[^<>]*>", "", symbol or "")
    parts = [p for p in sym.split("::") if p]
    if not parts:
        return "", ""
    return parts[-1], (parts[-2] if len(parts) > 1 else "")


# --------------------------------------------------------------------------- retail

class Retail:
    def __init__(self) -> None:
        self.cg = sqlite3.connect(str(CG_DB))
        self.fn_by_start: dict[int, tuple[str, int, int, str, int]] = {}
        self.virtual_only: set[int] = set()
        self.callers_count: dict[int, int] = {}
        for tok, start, end, sha, n, ncallers, ndata in self.cg.execute(
                "select token,start_ea,end_ea,function_sha256,instruction_count,"
                "callers_count,incoming_xrefs_data_count from functions"):
            self.fn_by_start[start] = (tok, start, end, sha or tok, n)
            self.callers_count[start] = ncallers
            # Reached only through a vtable/table: our call to it is a virtual
            # dispatch that never shows up as a direct retail `call imm`.
            if ncallers == 0 and ndata > 0:
                self.virtual_only.add(start)
        self.sorted_starts = sorted(self.fn_by_start)

    @lru_cache(maxsize=None)
    def asm(self, ea: int) -> list[tuple[int, str, str]]:
        path = DISASM / f"FUN_{ea:08X}.asm"
        out = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = ASM_LINE.match(line)
                    if m:
                        out.append((int(m.group(1), 16), m.group(2), m.group(3)))
        except OSError:
            pass
        return out

    @lru_cache(maxsize=None)
    def resolve(self, ea: int, depth: int = 0) -> int:
        """Follow single-jmp thunks to the body they forward to."""
        info = self.fn_by_start.get(ea)
        if not info or depth > 4:
            return ea
        if info[4] <= 2:
            ins = self.asm(ea)
            if ins and ins[0][1] == "jmp":
                m = re.match(r"0x([0-9a-fA-F]+)\b", ins[0][2].strip())
                if m:
                    return self.resolve(int(m.group(1), 16), depth + 1)
        return ea

    @lru_cache(maxsize=None)
    def export_end(self, ea: int) -> int | None:
        try:
            with open(DISASM / f"FUN_{ea:08X}.asm", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("function_end:"):
                        return int(line.split(":", 1)[1].strip(), 16)
                    if line.startswith("[disassembly]"):
                        break
        except OSError:
            pass
        return None

    @lru_cache(maxsize=None)
    def truncated(self, ea: int) -> bool:
        """The capstone export (FAF-patched exe) stops before the callgraph
        index's extent for the same function -- typically at a `jmp` into the
        FAF patch section.  Its callee list is then incomplete; `callees()`
        merges the index's call edges in, and findings carry a [trunc] tag."""
        info = self.fn_by_start.get(ea)
        end = self.export_end(ea)
        return info is not None and end is not None and end < info[2]

    def sha(self, ea: int) -> str:
        info = self.fn_by_start.get(ea)
        return info[3] if info else f"ea:{ea:x}"

    @lru_cache(maxsize=None)
    def callees(self, ea: int) -> dict[int, list[int]]:
        """resolved target ea -> list of call-site eas."""
        info = self.fn_by_start.get(ea)
        end = info[2] if info else None
        out: dict[int, list[int]] = defaultdict(list)
        for site, mnem, ops in self.asm(ea):
            if mnem not in ("call", "jmp"):
                continue
            m = re.match(r"0x([0-9a-fA-F]+)\b", ops.strip())
            if not m:
                continue
            tgt = int(m.group(1), 16)
            if mnem == "jmp" and end is not None and ea <= tgt < end:
                continue
            if mnem == "jmp" and tgt not in self.fn_by_start:
                continue
            out[self.resolve(tgt)].append(site)
        if self.truncated(ea):
            for dst, site in self.cg.execute(
                    "select dst_ea, src_ea from call_edges where src_token=?", (f"FUN_{ea:08X}",)):
                out[self.resolve(dst)].append(site)
        return dict(out)

    def callees_closure(self, ea: int, depth: int) -> set[int]:
        seen: set[int] = set()
        frontier = {ea}
        for _ in range(depth):
            nxt = set()
            for f in frontier:
                for c in self.callees(f):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
            frontier = nxt
        return seen


# --------------------------------------------------------------------------- source

class Anchors:
    def __init__(self) -> None:
        db = sqlite3.connect(str(SRC_DB))
        self.by_short: dict[str, set[int]] = defaultdict(set)
        self.sym_by_ea: dict[int, str] = {}
        self.cls_by_ea: dict[int, str] = {}
        self.defs: list[tuple[int, str, int, int, int, str]] = []
        self.def_loc: dict[int, tuple[str, int]] = {}
        for ea, file, line, code_line, end_line, kind, symbol in db.execute(
                "select ea,file,line,code_line,end_line,kind,symbol from anchors "
                "where kind in ('def','decl') and symbol is not null"):
            short, cls = short_and_class(symbol)
            if not short:
                continue
            self.by_short[short].add(ea)
            if ea not in self.sym_by_ea or kind == "def":
                self.sym_by_ea[ea] = symbol
                self.cls_by_ea[ea] = cls
            if kind == "def" and code_line and end_line:
                self.defs.append((ea, file.replace("\\", "/"), line, code_line, end_line, symbol))
                self.def_loc.setdefault(ea, (file, code_line))

    def candidates(self, qual: str | None, name: str) -> set[int]:
        eas = self.by_short.get(name, set())
        if qual and eas:
            q = re.sub(r"<.*", "", qual)
            narrowed = {e for e in eas if self.cls_by_ea.get(e) == q
                        or f"{q}::{name}" in self.sym_by_ea.get(e, "")}
            if narrowed:
                return narrowed
        return eas


def strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", text)
    return text


@lru_cache(maxsize=None)
def file_lines(path: str) -> list[str]:
    with open(REPO / path, encoding="utf-8", errors="replace") as fh:
        return strip_comments_and_strings(fh.read()).split("\n")


@lru_cache(maxsize=None)
def local_helper_bodies(path: str) -> dict[str, str]:
    """Bodies of every function-ish definition in the file (name -> text)."""
    text = "\n".join(file_lines(path))
    out: dict[str, str] = {}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*\)\s*"
                         r"(?:const\s*)?(?:noexcept\s*)?(?:->\s*[\w:<>*&\s]+)?\{", text):
        name = m.group(1)
        if name in KEYWORDS:
            continue
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        out.setdefault(name, text[m.end():i])
    return out


def body_calls(text: str) -> list[tuple[str | None, str]]:
    calls = []
    for m in CALL_RE.finditer(text):
        name = m.group("name")
        if name in KEYWORDS:
            continue
        calls.append((m.group("qual"), name))
    return calls


# --------------------------------------------------------------------------- analysis

def is_special(short: str, cls: str) -> bool:
    """ctor / dtor / operator: implicit or overload-selected, no helper-choice signal."""
    return short.startswith("~") or (cls and short == cls) or short.startswith("operator")


def similarity(a: str, b: str, cls_a: str, cls_b: str) -> float:
    wa, wb = camel_words(a), camel_words(b)
    if not wa or not wb:
        return 0.0
    inter = wa & wb
    if not inter:
        return 0.0
    # One shared word between two long names is coincidence (Write vs WriteFloat
    # is not, so short names keep their full ratio).
    if len(inter) == 1 and max(len(wa), len(wb)) > 2:
        return 0.5 * len(inter) / len(wa | wb)
    score = len(inter) / len(wa | wb)
    if cls_a and cls_a == cls_b:
        score += 0.15
    return score


INIT_RANGE_START = 0x00BC0000  # static-init / registration thunks; no sim behaviour
# Save/load and reflection plumbing: virtual archive calls make it noisy and it
# never runs during a replay.
SER_NAME_RE = re.compile(r"Serialize|Deserialize|^Ser[A-Z]|^Load|^Save|TypeInfo|^Init$|^Register|^add_|RType")


def analyse(paths: list[str], fn_filter: set[int] | None, min_score: float,
            show_missing: bool, top: int, include_init: bool = False) -> int:
    retail = Retail()
    anchors = Anchors()
    roots = []
    for p in paths:
        p = p.replace("\\", "/").rstrip("/")
        if p.startswith(str(REPO).replace("\\", "/")):
            p = os.path.relpath(p, REPO).replace("\\", "/")
        roots.append(p)

    def in_scope(file: str) -> bool:
        return any(file == r or file.startswith(r + "/") for r in roots)

    # A definition annotated with several addresses is a template body shared by
    # per-type emissions; its retail callees are the per-type siblings, so
    # name pairing against them is meaningless.
    eas_per_def: dict[tuple[str, int], int] = defaultdict(int)
    for d in anchors.defs:
        eas_per_def[(d[1], d[3])] += 1

    swaps = []
    missing_rows = []
    checked = 0
    for ea, file, line, code_line, end_line, symbol in anchors.defs:
        if not in_scope(file) or ea not in retail.fn_by_start:
            continue
        if fn_filter and ea not in fn_filter:
            continue
        lines = file_lines(file)
        body = "\n".join(lines[code_line - 1:end_line])
        retail_callees = retail.callees(ea)
        if not retail_callees and not fn_filter:
            continue
        checked += 1
        retail_shas = {retail.sha(c): c for c in retail_callees}

        # Our resolved call sites (with depth-2 expansion of unannotated helpers).
        ours: dict[str, set[int]] = {}
        helpers = local_helper_bodies(file)
        seen_helpers: set[str] = set()
        queue = [(body, 0)]
        own_short = short_and_class(symbol)[0]
        while queue:
            text, depth = queue.pop()
            for qual, name in body_calls(text):
                cands = anchors.candidates(qual, name)
                if cands:
                    if len(cands) <= GENERIC_MAX_CANDIDATES:
                        key = f"{qual}::{name}" if qual else name
                        ours.setdefault(key, set()).update(cands)
                    continue
                if depth < 2 and name in helpers and name not in seen_helpers and name != own_short:
                    seen_helpers.add(name)
                    queue.append((helpers[name], depth + 1))

        def matched(cands: set[int]) -> bool:
            return any(retail.sha(retail.resolve(c)) in retail_shas or retail.resolve(c) in retail_callees
                       for c in cands)

        unmatched_ours = {k: v for k, v in ours.items()
                          if not matched(v) and not all(c in retail.virtual_only for c in v)}
        all_our_eas = set().union(*ours.values()) if ours else set()
        our_shas = {retail.sha(retail.resolve(e)) for e in all_our_eas}
        retail_unmatched = [c for c in retail_callees
                            if c in anchors.sym_by_ea and retail.sha(c) not in our_shas
                            and c not in all_our_eas]

        if eas_per_def[(file, code_line)] > 2:
            unmatched_ours = {}
        if not include_init and (ea >= INIT_RANGE_START or "register_" in symbol
                                 or SER_NAME_RE.search(short_and_class(symbol)[0])):
            unmatched_ours = {}
        for key, cands in unmatched_ours.items():
            name = key.split("::")[-1]
            for rc in retail_unmatched:
                rsym = anchors.sym_by_ea[rc]
                rshort, rcls = short_and_class(rsym)
                if is_special(rshort, rcls):
                    continue
                best = 0.0
                best_c = None
                for c in cands:
                    if c == ea:
                        continue
                    oshort, ocls = short_and_class(anchors.sym_by_ea.get(c, ""))
                    if is_special(oshort, ocls):
                        continue
                    s = similarity(name, rshort, anchors.cls_by_ea.get(c, ""), rcls)
                    if s > best:
                        best, best_c = s, c
                if best < min_score or best_c is None:
                    continue
                wrap = (rc in retail.callees_closure(best_c, 2)
                        or best_c in retail.callees_closure(rc, 2))
                trunc = retail.truncated(ea)
                swaps.append({
                    "score": best - (0.5 if wrap else 0.0) - (0.4 if trunc else 0.0),
                    "raw": best, "wrap": wrap, "trunc": trunc,
                    "fn": ea, "fn_sym": symbol, "file": file, "line": code_line,
                    "ours": key, "ours_ea": best_c, "ours_sym": anchors.sym_by_ea.get(best_c, "?"),
                    "retail_ea": rc, "retail_sym": rsym,
                    "sites": retail_callees[rc],
                })
        if show_missing and retail_unmatched:
            # Drop callees reachable (retail graph, depth 2) from something our
            # body does call: that is a wrapper/inlining difference, not a
            # missing call.  Also drop ctor/dtor/operators and very generic
            # helpers (string, allocators, containers).
            reach: set[int] = set()
            for cands in ours.values():
                hit = {c for c in cands if retail.resolve(c) in retail_callees
                       or retail.sha(retail.resolve(c)) in retail_shas}
                for c in (hit or (cands if len(cands) <= 3 else ())):
                    reach |= retail.callees_closure(retail.resolve(c), 2)
            reach_shas = {retail.sha(x) for x in reach}
            keep = []
            for rc in retail_unmatched:
                rshort, rcls = short_and_class(anchors.sym_by_ea[rc])
                if is_special(rshort, rcls) or retail.callers_count.get(rc, 0) > GENERIC_CALLERS:
                    continue
                if rc in reach or retail.sha(rc) in reach_shas:
                    continue
                keep.append(rc)
            if keep:
                missing_rows.append((ea, symbol + (" [trunc]" if retail.truncated(ea) else ""),
                                     file, code_line, keep))

    swaps.sort(key=lambda s: -s["score"])
    print(f"# callcheck: {checked} functions checked in {', '.join(roots)}")
    print(f"## (A) SWAP candidates (score>= {min_score}), {len(swaps)} total, top {top}")
    for s in swaps[:top]:
        tag = (" [wrap]" if s["wrap"] else "") + (" [trunc]" if s["trunc"] else "")
        sites = ",".join(f"0x{x:08X}" for x in s["sites"][:3])
        print(f"{s['raw']:.2f}{tag}  FUN_{s['fn']:08X} {s['fn_sym']}  {s['file']}:{s['line']}")
        print(f"      ours  : {s['ours']} -> 0x{s['ours_ea']:08X} {s['ours_sym']}")
        print(f"      retail: 0x{s['retail_ea']:08X} {s['retail_sym']}  @ {sites}")
    if show_missing:
        print(f"\n## (B) retail callees annotated in tree but not called by our body ({len(missing_rows)} fns)")
        for ea, symbol, file, line, rcs in missing_rows:
            names = ", ".join(f"0x{c:08X} {short_and_class(anchors.sym_by_ea[c])[0]}" for c in rcs)
            print(f"FUN_{ea:08X} {symbol}  {file}:{line}\n      {names}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="source files or directories (repo-relative or absolute)")
    ap.add_argument("--fn", action="append", default=[], help="restrict to FUN_X / 0xX (repeatable)")
    ap.add_argument("--min-score", type=float, default=0.25)
    ap.add_argument("--top", type=int, default=200)
    ap.add_argument("--missing", action="store_true", help="also list (B) missing retail callees")
    ap.add_argument("--include-init", action="store_true",
                    help="also pair-check static-init/register_*/serializer functions (noisy)")
    args = ap.parse_args()
    fns = None
    if args.fn:
        fns = {int(re.sub(r"^(FUN_|0x)", "", f, flags=re.I), 16) for f in args.fn}
    return analyse(args.paths, fns, args.min_score, args.missing, args.top, args.include_init)


if __name__ == "__main__":
    sys.exit(main())
