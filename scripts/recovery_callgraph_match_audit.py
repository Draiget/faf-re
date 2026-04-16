#!/usr/bin/env python3
"""
Audit recovered source callgraph edges against FA binary callgraph evidence.

This script compares:
1) Source-restored graph inferred from annotated function definitions in src/sdk
2) Binary graph from decomp/recovery/disasm/<namespace>/_callgraph_index.sqlite

It focuses on Doxygen-annotated recovered functions (`Address: 0x...`) and
reports per-address drift:
- missing_out: binary edge exists, source edge missing
- extra_out: source edge exists, binary edge missing
- missing_in / extra_in for incoming symmetry

It also tracks `[[maybe_unused]]` usage so large maybe_unused lanes can be
audited against binary callgraph evidence.
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, DefaultDict, Iterable


SOURCE_FILE_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".inl", ".ipp"}
DOXYGEN_BLOCK_RE = re.compile(r"/\*\*.*?\*/", re.S)
ADDRESS_LINE_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{6,16})(?:\s*\(([^)]*)\))?")
FUN_TOKEN_RE = re.compile(r"\bFUN_([0-9A-Fa-f]{6,16})\b")
CALL_CANDIDATE_RE = re.compile(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(")

CPP_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "sizeof",
    "alignof",
    "decltype",
    "new",
    "delete",
    "throw",
    "case",
    "do",
    "else",
    "typeid",
    "co_await",
    "co_return",
    "co_yield",
    "noexcept",
    "static_cast",
    "reinterpret_cast",
    "const_cast",
    "dynamic_cast",
}

TYPE_CAST_TOKENS = {
    "int",
    "unsigned",
    "signed",
    "char",
    "short",
    "long",
    "float",
    "double",
    "bool",
    "wchar_t",
    "size_t",
    "uintptr_t",
    "intptr_t",
}


def normalize_fun_token(token: str | None) -> str | None:
    if not token:
        return None
    raw = token.strip()
    if not raw:
        return None
    raw = raw.split(",")[0].strip()
    raw = re.sub(r"^FUN_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^sub_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^0x", "", raw, flags=re.IGNORECASE)
    if not re.fullmatch(r"[0-9A-Fa-f]{6,16}", raw):
        return None
    value = int(raw, 16)
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def token_to_addr(token: str | None) -> int | None:
    norm = normalize_fun_token(token)
    if not norm:
        return None
    try:
        return int(norm[4:], 16)
    except ValueError:
        return None


def addr_to_token(addr: int) -> str:
    width = 8 if addr <= 0xFFFFFFFF else 16
    return f"FUN_{addr:0{width}X}"


def build_line_starts(text: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def offset_to_line(line_starts: list[int], offset: int) -> int:
    return bisect.bisect_right(line_starts, offset)


def strip_template_args(name: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in name:
        if ch == "<":
            depth += 1
            continue
        if ch == ">":
            if depth > 0:
                depth -= 1
                continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def normalize_cpp_name(name: str | None) -> str | None:
    if not name:
        return None
    text = name.strip()
    if not text:
        return None
    text = re.sub(r"\s+", "", text)
    text = strip_template_args(text)
    text = text.lstrip(":")
    text = re.sub(r"::+", "::", text)
    return text or None


def maybe_symbol_alias(fragment: str) -> str | None:
    text = fragment.strip()
    if not text:
        return None
    if text.upper().startswith("FUN_"):
        return None
    if text.startswith("?"):
        return None
    if " " in text and "::" not in text:
        return None
    match = re.search(r"([~A-Za-z_][A-Za-z0-9_:<>~]*)", text)
    if not match:
        return None
    return normalize_cpp_name(match.group(1))


def extract_addresses_and_aliases(doxygen_block: str) -> tuple[set[int], set[str]]:
    addresses: set[int] = set()
    aliases: set[str] = set()

    for match in ADDRESS_LINE_RE.finditer(doxygen_block):
        addr = int(match.group(1), 16)
        addresses.add(addr)
        payload = (match.group(2) or "").strip()
        if payload:
            for part in payload.split(","):
                alias = maybe_symbol_alias(part)
                if alias:
                    aliases.add(alias)

    for match in FUN_TOKEN_RE.finditer(doxygen_block):
        addresses.add(int(match.group(1), 16))

    return addresses, aliases


def skip_line_comment(text: str, idx: int) -> int:
    end = text.find("\n", idx)
    return len(text) if end == -1 else end + 1


def skip_block_comment(text: str, idx: int) -> int:
    end = text.find("*/", idx + 2)
    return len(text) if end == -1 else end + 2


def find_signature_terminator(text: str, start: int, max_end: int) -> tuple[int | None, str | None]:
    i = start
    paren = 0
    in_string: str | None = None
    escaped = False

    while i < max_end:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_string is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i = skip_line_comment(text, i)
            continue
        if ch == "/" and nxt == "*":
            i = skip_block_comment(text, i)
            continue
        if ch in {'"', "'"}:
            in_string = ch
            i += 1
            continue

        if ch == "(":
            paren += 1
        elif ch == ")":
            if paren > 0:
                paren -= 1
        elif (ch == "{" or ch == ";") and paren == 0:
            return i, ch

        i += 1

    return None, None


def find_matching_brace(text: str, open_brace_idx: int) -> int | None:
    depth = 0
    i = open_brace_idx
    in_string: str | None = None
    escaped = False

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_string is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i = skip_line_comment(text, i)
            continue
        if ch == "/" and nxt == "*":
            i = skip_block_comment(text, i)
            continue
        if ch in {'"', "'"}:
            in_string = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return None


def extract_function_name(signature: str) -> str | None:
    sig = re.sub(r"\[\[.*?\]\]", " ", signature, flags=re.S).strip()
    paren_idx = sig.find("(")
    if paren_idx == -1:
        return None
    head = sig[:paren_idx].strip()
    if not head:
        return None

    operator_match = re.search(r"(operator\s*(?:\[\]|\(\)|[^\s(]+))\s*$", head)
    if operator_match:
        return operator_match.group(1)

    match = re.search(r"([~A-Za-z_][A-Za-z0-9_:<>~]*)\s*$", head)
    if not match:
        return None
    token = match.group(1).lstrip("*&")
    return token or None


@dataclass(frozen=True)
class CallSite:
    candidate: str
    line: int


@dataclass(frozen=True)
class Definition:
    def_id: int
    path: str
    line: int
    open_brace_line: int
    display_name: str
    lookup_name: str
    short_name: str
    aliases: tuple[str, ...]
    addresses: tuple[int, ...]
    maybe_unused: bool
    calls: tuple[CallSite, ...]


@dataclass
class ParseResult:
    definitions: list[Definition]
    address_to_defs: dict[int, list[int]]
    maybe_unused_mentions_total: int


def sanitize_for_call_scan(body: str) -> str:
    chars = list(body)
    i = 0
    in_string: str | None = None
    escaped = False

    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""

        if in_string is not None:
            if escaped:
                escaped = False
                chars[i] = " "
            elif ch == "\\":
                escaped = True
                chars[i] = " "
            elif ch == in_string:
                in_string = None
                chars[i] = " "
            else:
                chars[i] = " "
            i += 1
            continue

        if ch == "/" and nxt == "/":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue

        if ch == "/" and nxt == "*":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i + 1 < len(chars):
                if chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    break
                chars[i] = " "
                i += 1
            continue

        if ch in {'"', "'"}:
            in_string = ch
            chars[i] = " "
            i += 1
            continue

        i += 1

    return "".join(chars)


def extract_call_sites(body: str, body_start_line: int) -> list[CallSite]:
    cleaned = sanitize_for_call_scan(body)
    body_line_starts = build_line_starts(cleaned)
    calls: list[CallSite] = []
    seen: set[tuple[str, int]] = set()

    for match in CALL_CANDIDATE_RE.finditer(cleaned):
        candidate_raw = match.group(1)
        candidate = normalize_cpp_name(candidate_raw)
        if not candidate:
            continue
        if candidate in CPP_KEYWORDS:
            continue
        if candidate in TYPE_CAST_TOKENS:
            continue
        short = candidate.split("::")[-1]
        if short in CPP_KEYWORDS or short in TYPE_CAST_TOKENS:
            continue

        line = body_start_line + bisect.bisect_right(body_line_starts, match.start(1)) - 1
        key = (candidate, line)
        if key in seen:
            continue
        seen.add(key)
        calls.append(CallSite(candidate=candidate, line=line))

    return calls


def parse_definition_after_block(text: str, block_end: int) -> tuple[int, int, bool, str, str] | None:
    i = block_end
    maybe_unused = False
    max_probe = min(len(text), block_end + 24000)

    while i < max_probe:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if ch.isspace():
            i += 1
            continue
        if ch == "/" and nxt == "/":
            i = skip_line_comment(text, i)
            continue
        if ch == "/" and nxt == "*":
            i = skip_block_comment(text, i)
            continue
        if ch == "[" and nxt == "[":
            end = text.find("]]", i + 2, max_probe)
            if end == -1:
                return None
            attr = text[i : end + 2]
            if "maybe_unused" in attr:
                maybe_unused = True
            i = end + 2
            continue
        break

    sig_start = i
    term_idx, term_char = find_signature_terminator(text, sig_start, max_probe)
    if term_idx is None or term_char != "{":
        return None

    signature = text[sig_start:term_idx].strip()
    if "(" not in signature or ")" not in signature:
        return None
    if "maybe_unused" in signature:
        maybe_unused = True

    display_name = extract_function_name(signature)
    if not display_name:
        return None
    lookup_name = normalize_cpp_name(display_name)
    if not lookup_name:
        return None

    return sig_start, term_idx, maybe_unused, display_name, lookup_name


def iter_source_files(src_root: Path) -> Iterable[Path]:
    for path in src_root.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_FILE_EXTENSIONS:
            yield path


def parse_source_definitions(src_root: Path, repo_root: Path) -> ParseResult:
    definitions: list[Definition] = []
    address_to_defs: dict[int, list[int]] = defaultdict(list)
    maybe_unused_mentions_total = 0
    def_counter = 0

    for path in iter_source_files(src_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        maybe_unused_mentions_total += text.count("[[maybe_unused]]")
        line_starts = build_line_starts(text)
        seen_open_braces: set[int] = set()
        rel_path = str(path.relative_to(repo_root)).replace("\\", "/")

        for block_match in DOXYGEN_BLOCK_RE.finditer(text):
            block = block_match.group(0)
            addresses, aliases = extract_addresses_and_aliases(block)
            if not addresses:
                continue

            parsed = parse_definition_after_block(text, block_match.end())
            if not parsed:
                continue

            sig_start, open_brace_idx, maybe_unused, display_name, lookup_name = parsed
            if open_brace_idx in seen_open_braces:
                continue
            seen_open_braces.add(open_brace_idx)

            close_brace_idx = find_matching_brace(text, open_brace_idx)
            if close_brace_idx is None:
                continue

            body = text[open_brace_idx + 1 : close_brace_idx]
            start_line = offset_to_line(line_starts, sig_start)
            open_line = offset_to_line(line_starts, open_brace_idx)
            calls = extract_call_sites(body, open_line)
            short_name = lookup_name.split("::")[-1]

            alias_names = sorted({alias for alias in aliases if alias and alias != lookup_name})
            addrs_sorted = tuple(sorted(addresses))
            call_tuple = tuple(calls)

            definition = Definition(
                def_id=def_counter,
                path=rel_path,
                line=start_line,
                open_brace_line=open_line,
                display_name=display_name,
                lookup_name=lookup_name,
                short_name=short_name,
                aliases=tuple(alias_names),
                addresses=addrs_sorted,
                maybe_unused=maybe_unused,
                calls=call_tuple,
            )
            definitions.append(definition)
            for addr in addrs_sorted:
                address_to_defs[addr].append(def_counter)
            def_counter += 1

    return ParseResult(
        definitions=definitions,
        address_to_defs=dict(address_to_defs),
        maybe_unused_mentions_total=maybe_unused_mentions_total,
    )


@dataclass
class SourceGraph:
    out_map: dict[int, set[int]]
    in_map: dict[int, set[int]]
    edge_sites: dict[tuple[int, int], list[str]]
    total_call_candidates: int
    resolved_call_candidates: int
    unresolved_call_candidates: int
    unresolved_top: list[tuple[str, int]]


@dataclass
class NameIndex:
    by_lookup: dict[str, list[int]]
    by_short: dict[str, list[int]]


def build_name_index(definitions: list[Definition]) -> NameIndex:
    by_lookup: DefaultDict[str, list[int]] = defaultdict(list)
    by_short: DefaultDict[str, list[int]] = defaultdict(list)

    for d in definitions:
        by_lookup[d.lookup_name].append(d.def_id)
        by_short[d.short_name].append(d.def_id)
        for alias in d.aliases:
            by_lookup[alias].append(d.def_id)
            alias_short = alias.split("::")[-1]
            by_short[alias_short].append(d.def_id)

    for key in list(by_lookup.keys()):
        by_lookup[key] = sorted(set(by_lookup[key]))
    for key in list(by_short.keys()):
        by_short[key] = sorted(set(by_short[key]))

    return NameIndex(by_lookup=dict(by_lookup), by_short=dict(by_short))


def caller_scopes(lookup_name: str) -> list[str]:
    parts = lookup_name.split("::")
    scopes: list[str] = []
    for idx in range(len(parts) - 1, 0, -1):
        scopes.append("::".join(parts[:idx]))
    return scopes


def resolve_candidate(
    *,
    candidate: str,
    caller: Definition,
    definitions: list[Definition],
    name_index: NameIndex,
) -> list[int]:
    cand = normalize_cpp_name(candidate)
    if not cand:
        return []

    def unique_ids(ids: Iterable[int]) -> list[int]:
        return sorted(set(ids))

    # Exact qualified reference first.
    if "::" in cand:
        exact = unique_ids(name_index.by_lookup.get(cand, []))
        if exact:
            return exact
        if cand.startswith("::"):
            exact = unique_ids(name_index.by_lookup.get(cand.lstrip(":"), []))
            if exact:
                return exact

    # Resolve relative to caller scopes (class -> namespace fallthrough).
    scoped_hits: list[int] = []
    for scope in caller_scopes(caller.lookup_name):
        scoped_name = f"{scope}::{cand}"
        scoped_hits.extend(name_index.by_lookup.get(scoped_name, []))
    scoped_hits = unique_ids(scoped_hits)
    if len(scoped_hits) == 1:
        return scoped_hits
    if len(scoped_hits) > 1:
        return []

    # Fall back to globally unique short-name match.
    short = cand.split("::")[-1]
    short_hits = unique_ids(name_index.by_short.get(short, []))
    if len(short_hits) == 1:
        return short_hits
    if len(short_hits) > 1:
        # Narrow by top namespace owner when possible.
        top = caller.lookup_name.split("::")[0] if "::" in caller.lookup_name else ""
        if top:
            narrowed = [
                did
                for did in short_hits
                if definitions[did].lookup_name.startswith(top + "::")
            ]
            narrowed = unique_ids(narrowed)
            if len(narrowed) == 1:
                return narrowed
        return []

    return []


def build_source_graph(
    *,
    definitions: list[Definition],
    name_index: NameIndex,
    max_site_samples: int,
) -> SourceGraph:
    out_map: DefaultDict[int, set[int]] = defaultdict(set)
    in_map: DefaultDict[int, set[int]] = defaultdict(set)
    edge_sites: DefaultDict[tuple[int, int], list[str]] = defaultdict(list)
    unresolved_counter: Counter[str] = Counter()

    total_call_candidates = 0
    resolved_call_candidates = 0
    unresolved_call_candidates = 0

    for caller in definitions:
        for call in caller.calls:
            total_call_candidates += 1
            target_ids = resolve_candidate(
                candidate=call.candidate,
                caller=caller,
                definitions=definitions,
                name_index=name_index,
            )
            if not target_ids:
                unresolved_call_candidates += 1
                unresolved_counter[call.candidate] += 1
                continue

            resolved_call_candidates += 1
            for target_id in target_ids:
                target = definitions[target_id]
                site_str = (
                    f"{caller.path}:{call.line} "
                    f"({caller.lookup_name} -> {target.lookup_name})"
                )
                for src_addr in caller.addresses:
                    for dst_addr in target.addresses:
                        out_map[src_addr].add(dst_addr)
                        in_map[dst_addr].add(src_addr)
                        edge = (src_addr, dst_addr)
                        sites = edge_sites[edge]
                        if len(sites) < max_site_samples and site_str not in sites:
                            sites.append(site_str)

    unresolved_top = unresolved_counter.most_common(50)
    return SourceGraph(
        out_map=dict(out_map),
        in_map=dict(in_map),
        edge_sites=dict(edge_sites),
        total_call_candidates=total_call_candidates,
        resolved_call_candidates=resolved_call_candidates,
        unresolved_call_candidates=unresolved_call_candidates,
        unresolved_top=unresolved_top,
    )


@dataclass
class BinaryGraph:
    function_addrs: set[int]
    out_map: dict[int, set[int]]
    in_map: dict[int, set[int]]
    edge_sites: dict[tuple[int, int], list[int]]


def load_binary_graph(db_path: Path, max_site_samples: int) -> BinaryGraph:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        function_addrs: set[int] = set()
        for row in conn.execute("SELECT token FROM functions"):
            addr = token_to_addr(row["token"])
            if addr is not None:
                function_addrs.add(addr)

        out_map: DefaultDict[int, set[int]] = defaultdict(set)
        in_map: DefaultDict[int, set[int]] = defaultdict(set)
        for row in conn.execute("SELECT src_token, dst_token FROM call_edges"):
            src = token_to_addr(row["src_token"])
            dst = token_to_addr(row["dst_token"])
            if src is None or dst is None:
                continue
            out_map[src].add(dst)
            in_map[dst].add(src)

        edge_sites: DefaultDict[tuple[int, int], list[int]] = defaultdict(list)
        if max_site_samples > 0:
            sql = """
                SELECT owner_token, target_token, from_ea
                FROM incoming_xrefs
                WHERE kind = 'code'
                  AND owner_token IS NOT NULL
                  AND target_token IS NOT NULL
            """
            for row in conn.execute(sql):
                src = token_to_addr(row["owner_token"])
                dst = token_to_addr(row["target_token"])
                if src is None or dst is None:
                    continue
                from_ea = row["from_ea"]
                if from_ea is None:
                    continue
                edge = (src, dst)
                samples = edge_sites[edge]
                if len(samples) < max_site_samples:
                    value = int(from_ea)
                    if value not in samples:
                        samples.append(value)

        return BinaryGraph(
            function_addrs=function_addrs,
            out_map=dict(out_map),
            in_map=dict(in_map),
            edge_sites=dict(edge_sites),
        )
    finally:
        conn.close()


def token_list(values: Iterable[int], limit: int) -> list[str]:
    items = sorted(set(values))
    if limit > 0:
        items = items[:limit]
    return [addr_to_token(v) for v in items]


def fmt_hex_sites(values: Iterable[int], limit: int) -> list[str]:
    items = sorted(set(values))
    if limit > 0:
        items = items[:limit]
    return [f"0x{v:08X}" for v in items]


def compare_graphs(
    *,
    definitions: list[Definition],
    address_to_defs: dict[int, list[int]],
    source_graph: SourceGraph,
    binary_graph: BinaryGraph,
    max_neighbor_sample: int,
    max_site_sample: int,
) -> dict[str, Any]:
    source_addrs = set(address_to_defs.keys())
    compared_addrs = sorted(source_addrs & binary_graph.function_addrs)
    compared_set = set(compared_addrs)

    duplicate_owned = {
        addr: defs
        for addr, defs in address_to_defs.items()
        if len(defs) > 1
    }

    mismatched_tokens: list[str] = []
    maybe_unused_mismatched_tokens: list[str] = []
    maybe_unused_binary_used_source_unused_tokens: list[str] = []
    per_function: list[dict[str, Any]] = []

    drift_counter = 0
    exact_match_counter = 0
    maybe_unused_counter = 0
    maybe_unused_match_counter = 0
    maybe_unused_drift_counter = 0

    for addr in compared_addrs:
        def_ids = address_to_defs.get(addr, [])
        canonical = definitions[def_ids[0]] if def_ids else None
        maybe_unused = any(definitions[d].maybe_unused for d in def_ids)
        if maybe_unused:
            maybe_unused_counter += 1

        binary_out_scope = (binary_graph.out_map.get(addr, set())) & compared_set
        binary_in_scope = (binary_graph.in_map.get(addr, set())) & compared_set
        source_out_scope = (source_graph.out_map.get(addr, set())) & compared_set
        source_in_scope = (source_graph.in_map.get(addr, set())) & compared_set

        missing_out = sorted(binary_out_scope - source_out_scope)
        extra_out = sorted(source_out_scope - binary_out_scope)
        missing_in = sorted(binary_in_scope - source_in_scope)
        extra_in = sorted(source_in_scope - binary_in_scope)

        is_match = not (missing_out or extra_out or missing_in or extra_in)
        if is_match:
            exact_match_counter += 1
            if maybe_unused:
                maybe_unused_match_counter += 1
        else:
            drift_counter += 1
            token = addr_to_token(addr)
            mismatched_tokens.append(token)
            if maybe_unused:
                maybe_unused_drift_counter += 1
                maybe_unused_mismatched_tokens.append(token)

        binary_used_scope = bool(binary_out_scope or binary_in_scope)
        source_used_scope = bool(source_out_scope or source_in_scope)
        if maybe_unused and binary_used_scope and not source_used_scope:
            maybe_unused_binary_used_source_unused_tokens.append(addr_to_token(addr))

        def edge_sample(edge_addrs: list[int], src: int, direction: str) -> list[dict[str, Any]]:
            sample_rows: list[dict[str, Any]] = []
            for other in edge_addrs[:max_neighbor_sample]:
                if direction == "out":
                    edge = (src, other)
                else:
                    edge = (other, src)
                sample_rows.append(
                    {
                        "token": addr_to_token(other),
                        "binary_sites": fmt_hex_sites(binary_graph.edge_sites.get(edge, []), max_site_sample),
                        "source_sites": source_graph.edge_sites.get(edge, [])[:max_site_sample],
                    }
                )
            return sample_rows

        record = {
            "token": addr_to_token(addr),
            "address": f"0x{addr:08X}",
            "definition": {
                "name": canonical.lookup_name if canonical else "",
                "display_name": canonical.display_name if canonical else "",
                "file": canonical.path if canonical else "",
                "line": canonical.line if canonical else 0,
                "maybe_unused": maybe_unused,
                "duplicate_definitions_for_address": len(def_ids),
            },
            "is_match": is_match,
            "drift_score": len(missing_out) + len(extra_out) + len(missing_in) + len(extra_in),
            "counts": {
                "binary_out_total": len(binary_graph.out_map.get(addr, set())),
                "binary_in_total": len(binary_graph.in_map.get(addr, set())),
                "binary_out_in_compared_scope": len(binary_out_scope),
                "binary_in_in_compared_scope": len(binary_in_scope),
                "source_out_in_compared_scope": len(source_out_scope),
                "source_in_in_compared_scope": len(source_in_scope),
                "missing_out": len(missing_out),
                "extra_out": len(extra_out),
                "missing_in": len(missing_in),
                "extra_in": len(extra_in),
            },
            "samples": {
                "missing_out_tokens": token_list(missing_out, max_neighbor_sample),
                "extra_out_tokens": token_list(extra_out, max_neighbor_sample),
                "missing_in_tokens": token_list(missing_in, max_neighbor_sample),
                "extra_in_tokens": token_list(extra_in, max_neighbor_sample),
                "missing_out_edges": edge_sample(missing_out, addr, "out"),
                "extra_out_edges": edge_sample(extra_out, addr, "out"),
                "missing_in_edges": edge_sample(missing_in, addr, "in"),
                "extra_in_edges": edge_sample(extra_in, addr, "in"),
            },
        }
        per_function.append(record)

    per_function_sorted = sorted(
        per_function,
        key=lambda row: (
            0 if not row["is_match"] else 1,
            -int(row["drift_score"]),
            row["token"],
        ),
    )

    summary = {
        "source_annotated_definition_count": len(definitions),
        "source_annotated_address_count": len(source_addrs),
        "binary_function_count": len(binary_graph.function_addrs),
        "compared_address_count": len(compared_addrs),
        "exact_match_count": exact_match_counter,
        "drift_count": drift_counter,
        "drift_percent": (drift_counter / len(compared_addrs) * 100.0) if compared_addrs else 0.0,
        "maybe_unused_mentions_total": None,  # filled later
        "maybe_unused_compared_address_count": maybe_unused_counter,
        "maybe_unused_exact_match_count": maybe_unused_match_counter,
        "maybe_unused_drift_count": maybe_unused_drift_counter,
        "maybe_unused_binary_used_source_unused_count": len(maybe_unused_binary_used_source_unused_tokens),
        "duplicate_address_ownership_count": len(duplicate_owned),
    }

    return {
        "summary": summary,
        "duplicate_address_ownership": {
            addr_to_token(addr): [
                {
                    "name": definitions[d].lookup_name,
                    "file": definitions[d].path,
                    "line": definitions[d].line,
                }
                for d in def_ids
            ]
            for addr, def_ids in sorted(duplicate_owned.items())
        },
        "mismatched_tokens": sorted(set(mismatched_tokens)),
        "maybe_unused_mismatched_tokens": sorted(set(maybe_unused_mismatched_tokens)),
        "maybe_unused_binary_used_source_unused_tokens": sorted(set(maybe_unused_binary_used_source_unused_tokens)),
        "functions": per_function_sorted,
    }


def write_queue(path: Path, tokens: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(tokens)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any], top: int = 200) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report["summary"]
    rows = report["functions"]

    lines: list[str] = [
        "# Recovery Callgraph Match Audit",
        "",
        "## Summary",
        "",
        f"- Source annotated definitions: `{summary['source_annotated_definition_count']:,}`",
        f"- Source annotated addresses: `{summary['source_annotated_address_count']:,}`",
        f"- Binary indexed functions: `{summary['binary_function_count']:,}`",
        f"- Compared addresses: `{summary['compared_address_count']:,}`",
        f"- Exact matches: `{summary['exact_match_count']:,}`",
        f"- Drifted addresses: `{summary['drift_count']:,}` (`{summary['drift_percent']:.2f}%`)",
        f"- maybe_unused mentions (raw): `{summary['maybe_unused_mentions_total']:,}`",
        f"- maybe_unused compared addresses: `{summary['maybe_unused_compared_address_count']:,}`",
        f"- maybe_unused drifted addresses: `{summary['maybe_unused_drift_count']:,}`",
        (
            "- maybe_unused binary-used but source-unused: "
            f"`{summary['maybe_unused_binary_used_source_unused_count']:,}`"
        ),
        (
            "- Duplicate address ownership entries: "
            f"`{summary['duplicate_address_ownership_count']:,}`"
        ),
        "",
        f"## Top Drifted Addresses (Top {top})",
        "",
        "| Token | maybe_unused | Drift | Missing Out | Extra Out | Missing In | Extra In | Source |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    added = 0
    for row in rows:
        if row["is_match"]:
            continue
        if added >= top:
            break
        src = row["definition"]
        counts = row["counts"]
        source_loc = f"{src['file']}:{src['line']}" if src["file"] else ""
        lines.append(
            "| "
            + f"{row['token']} | "
            + f"{'yes' if src['maybe_unused'] else 'no'} | "
            + f"{row['drift_score']} | "
            + f"{counts['missing_out']} | "
            + f"{counts['extra_out']} | "
            + f"{counts['missing_in']} | "
            + f"{counts['extra_in']} | "
            + f"`{source_loc}` |"
        )
        added += 1

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit recovered source callgraph against binary callgraph.")
    parser.add_argument("--repo-root", type=Path, default=Path("."), help="Repository root (default: current dir).")
    parser.add_argument("--src-root", type=Path, default=Path("src/sdk"), help="Source root to scan.")
    parser.add_argument(
        "--callgraph-db",
        type=Path,
        default=Path("decomp/recovery/disasm/fa_full_2026_03_26/_callgraph_index.sqlite"),
        help="Path to _callgraph_index.sqlite.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("decomp/recovery/reports/callgraph_match_audit.json"),
        help="JSON report output path.",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("decomp/recovery/reports/callgraph_match_audit.md"),
        help="Markdown summary output path.",
    )
    parser.add_argument(
        "--queue-out",
        type=Path,
        default=Path("decomp/recovery/queues/callgraph_mismatch_tokens.txt"),
        help="Queue output for drifted FUN tokens.",
    )
    parser.add_argument(
        "--maybe-unused-queue-out",
        type=Path,
        default=Path("decomp/recovery/queues/callgraph_maybe_unused_mismatch_tokens.txt"),
        help="Queue output for drifted maybe_unused FUN tokens.",
    )
    parser.add_argument(
        "--maybe-unused-binary-used-source-unused-out",
        type=Path,
        default=Path("decomp/recovery/queues/callgraph_maybe_unused_binary_used_source_unused.txt"),
        help="Queue output for maybe_unused tokens with binary usage but no source usage in compared scope.",
    )
    parser.add_argument(
        "--max-neighbor-sample",
        type=int,
        default=40,
        help="Per-function sample cap for neighbor token lists.",
    )
    parser.add_argument(
        "--max-site-sample",
        type=int,
        default=5,
        help="Per-edge sample cap for binary/source callsite evidence.",
    )
    parser.add_argument(
        "--markdown-top",
        type=int,
        default=200,
        help="Max drift rows in markdown summary.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Console output format.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    src_root = (repo_root / args.src_root).resolve() if not args.src_root.is_absolute() else args.src_root.resolve()
    callgraph_db = (repo_root / args.callgraph_db).resolve() if not args.callgraph_db.is_absolute() else args.callgraph_db.resolve()
    json_out = (repo_root / args.json_out).resolve() if not args.json_out.is_absolute() else args.json_out.resolve()
    markdown_out = (repo_root / args.markdown_out).resolve() if not args.markdown_out.is_absolute() else args.markdown_out.resolve()
    queue_out = (repo_root / args.queue_out).resolve() if not args.queue_out.is_absolute() else args.queue_out.resolve()
    maybe_unused_queue_out = (
        (repo_root / args.maybe_unused_queue_out).resolve()
        if not args.maybe_unused_queue_out.is_absolute()
        else args.maybe_unused_queue_out.resolve()
    )
    maybe_unused_binary_used_source_unused_out = (
        (repo_root / args.maybe_unused_binary_used_source_unused_out).resolve()
        if not args.maybe_unused_binary_used_source_unused_out.is_absolute()
        else args.maybe_unused_binary_used_source_unused_out.resolve()
    )

    if not src_root.exists():
        print(f"error: src root not found: {src_root}", file=sys.stderr)
        return 2
    if not callgraph_db.exists():
        print(f"error: callgraph db not found: {callgraph_db}", file=sys.stderr)
        return 2

    parse_result = parse_source_definitions(src_root=src_root, repo_root=repo_root)
    name_index = build_name_index(parse_result.definitions)
    source_graph = build_source_graph(
        definitions=parse_result.definitions,
        name_index=name_index,
        max_site_samples=max(args.max_site_sample, 0),
    )
    binary_graph = load_binary_graph(callgraph_db, max_site_samples=max(args.max_site_sample, 0))

    report = compare_graphs(
        definitions=parse_result.definitions,
        address_to_defs=parse_result.address_to_defs,
        source_graph=source_graph,
        binary_graph=binary_graph,
        max_neighbor_sample=max(args.max_neighbor_sample, 0),
        max_site_sample=max(args.max_site_sample, 0),
    )
    report["summary"]["maybe_unused_mentions_total"] = parse_result.maybe_unused_mentions_total
    report["source_call_resolution"] = {
        "total_call_candidates": source_graph.total_call_candidates,
        "resolved_call_candidates": source_graph.resolved_call_candidates,
        "unresolved_call_candidates": source_graph.unresolved_call_candidates,
        "resolved_percent": (
            (source_graph.resolved_call_candidates / source_graph.total_call_candidates * 100.0)
            if source_graph.total_call_candidates
            else 0.0
        ),
        "unresolved_top": [
            {"candidate": name, "count": count}
            for name, count in source_graph.unresolved_top
        ],
    }

    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(markdown_out, report, top=max(args.markdown_top, 0))
    write_queue(queue_out, report["mismatched_tokens"])
    write_queue(maybe_unused_queue_out, report["maybe_unused_mismatched_tokens"])
    write_queue(
        maybe_unused_binary_used_source_unused_out,
        report["maybe_unused_binary_used_source_unused_tokens"],
    )

    summary = report["summary"]
    if args.format == "json":
        print(json.dumps({"summary": summary, "source_call_resolution": report["source_call_resolution"]}, indent=2))
    else:
        print("Recovery Callgraph Match Audit")
        print("==============================")
        print(f"Source root: {src_root}")
        print(f"Callgraph DB: {callgraph_db}")
        print()
        print(f"Annotated definitions: {summary['source_annotated_definition_count']:,}")
        print(f"Annotated addresses:   {summary['source_annotated_address_count']:,}")
        print(f"Compared addresses:    {summary['compared_address_count']:,}")
        print(f"Exact matches:         {summary['exact_match_count']:,}")
        print(f"Drifted addresses:     {summary['drift_count']:,} ({summary['drift_percent']:.2f}%)")
        print()
        print(f"maybe_unused mentions: {summary['maybe_unused_mentions_total']:,}")
        print(f"maybe_unused compared: {summary['maybe_unused_compared_address_count']:,}")
        print(f"maybe_unused drifted:  {summary['maybe_unused_drift_count']:,}")
        print(
            "maybe_unused binary-used/source-unused: "
            f"{summary['maybe_unused_binary_used_source_unused_count']:,}"
        )
        print(f"duplicate ownership:   {summary['duplicate_address_ownership_count']:,}")
        print()
        src_res = report["source_call_resolution"]
        print(
            "source call resolution: "
            f"{src_res['resolved_call_candidates']:,}/{src_res['total_call_candidates']:,} "
            f"({src_res['resolved_percent']:.2f}%)"
        )
        print()
        print(f"JSON report:           {json_out}")
        print(f"Markdown summary:      {markdown_out}")
        print(f"Drift queue:           {queue_out}")
        print(f"maybe_unused queue:    {maybe_unused_queue_out}")
        print(f"maybe_unused binary-used/source-unused queue: {maybe_unused_binary_used_source_unused_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

