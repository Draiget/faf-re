#!/usr/bin/env python3
"""faidx - the FA source index.

One queryable place for "where is FUN_X in src/sdk, what is it, who calls it,
what does it call, what is its status", so agents stop re-deriving that join
with grep fan-outs.

Ground truth stays in the tree: the Doxygen `Address: 0x........` blocks in
src/sdk are the anchors.  This index is a rebuildable cache over them, joined
at query time onto the IDA callgraph index (attached read-only) and onto an
import of recovered_progress.json.  Nothing here is hand-maintained; a stale
index is never worse than `faidx update`.

Commands
  update  [--full] [--files F ...]   re-index changed source files, progress, notes
  rebuild                            drop the db and index everything
  verify  [--list CATEGORY] [--json] drift between anchors, callgraph, progress db
  card    TARGET [--json]            everything about one function (token, 0xADDR, name)
  at      FILE:LINE                  which recovered function owns a source line
  find    SUBSTRING [--limit N]      search symbols, labels and IDA names
  notes   QUERY [--limit N]          full-text search over reports, notes, memory
  owner   TARGET                     address-locality neighbours (which file it belongs in)
  stats                              index statistics
  hook                               PostToolUse entry point (reads the hook JSON on stdin)

Paths default to the repo this script lives in; override with --repo / --db.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import sys
import time
from typing import Iterable

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC_ROOT = "src/sdk"
DB_REL = "decomp/recovery/_source_index.sqlite"
LOG_REL = "decomp/recovery/_source_index.log"
NAMESPACE = "fa_full_2026_03_26"
CG_DB_REL = f"decomp/recovery/disasm/{NAMESPACE}/_callgraph_index.sqlite"
PROGRESS_REL = "decomp/recovery/recovered_progress.json"
NOTE_ROOTS = (
    ("report", "decomp/recovery/reports"),
    ("memory", ".memory"),
    ("skill", "skills"),
)
SRC_EXTS = {".cpp", ".h", ".hpp", ".inl", ".c", ".cc", ".cxx", ".hxx"}

ADDR_LINE_RE = re.compile(r"Address:\s*(0x[0-9A-Fa-f]{6,8})(.*)$")
MANGLED_RE = re.compile(r"Mangled:\s*(\S+)")
TOKEN_RE = re.compile(r"^FUN_[0-9A-Fa-f]{8}$")
HEX_RE = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")
SCOPE_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?(class|struct|namespace|union)\s+(?:[A-Z_][A-Z0-9_]*\s+)?"
    r"(?:alignas\([^)]*\)\s*)?([A-Za-z_][\w:]*)\b"
)
SYMBOL_TAIL_RE = re.compile(r"((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*$")
OPERATOR_RE = re.compile(r"((?:[A-Za-z_]\w*::)*)operator\s*(\(\s*\)|\[\s*\]|[^\s\w(]+|\s+[A-Za-z_]\w*)\s*\(")
HEADING_RE = re.compile(r"^\s*#{1,3}\s+(.+?)\s*$")
FAST_LINE_RE = re.compile(r"[/\"']")


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: str, repo: str) -> str:
    p = os.path.relpath(os.path.abspath(path), repo).replace("\\", "/")
    return p


def norm_rel(path: str) -> str:
    """Normalise a path as recorded in the progress db (absolute, ./, backslashes)."""
    p = (path or "").replace("\\", "/")
    low = p.lower()
    k = low.find("/src/sdk/")
    if k >= 0:
        p = p[k + 1:]
    elif low.startswith("src/sdk/"):
        pass
    elif p.startswith("./"):
        p = p[2:]
    return p


def sha1_of(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def log_line(repo: str, msg: str) -> None:
    try:
        with open(os.path.join(repo, LOG_REL), "a", encoding="utf-8") as fh:
            fh.write(f"{utc_now()} {msg}\n")
    except OSError:
        pass


def is_source(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in SRC_EXTS


# --------------------------------------------------------------------------- #
# database
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(
  path TEXT PRIMARY KEY, sha1 TEXT, size INTEGER, mtime REAL, indexed_utc TEXT, anchor_count INTEGER);
CREATE TABLE IF NOT EXISTS anchors(
  id INTEGER PRIMARY KEY,
  ea INTEGER NOT NULL,
  token TEXT,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  code_line INTEGER,
  end_line INTEGER,
  kind TEXT,
  symbol TEXT,
  label TEXT,
  mangled TEXT,
  scope TEXT);
CREATE INDEX IF NOT EXISTS anchors_ea ON anchors(ea);
CREATE INDEX IF NOT EXISTS anchors_token ON anchors(token);
CREATE INDEX IF NOT EXISTS anchors_file ON anchors(file, line);
CREATE INDEX IF NOT EXISTS anchors_symbol ON anchors(symbol);
CREATE TABLE IF NOT EXISTS progress(
  token TEXT PRIMARY KEY, status TEXT, note TEXT, source_paths TEXT, report_paths TEXT,
  updated_utc TEXT, blocker_type TEXT, confidence REAL, last_worker TEXT, depends_on TEXT);
CREATE INDEX IF NOT EXISTS progress_status ON progress(status);
CREATE TABLE IF NOT EXISTS notes(path TEXT PRIMARY KEY, kind TEXT, mtime REAL, size INTEGER, title TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
  path UNINDEXED, title, body, tokenize = "unicode61 tokenchars '_'");
"""


def _file_uri(path: str, query: str) -> str:
    # pathlib produces file:///G:/... on Windows and percent-encodes spaces, which is
    # the form SQLite's URI parser accepts on every platform.
    return pathlib.Path(os.path.abspath(path)).as_uri() + "?" + query


def open_db(repo: str, db_path: str, create: bool = True) -> sqlite3.Connection:
    if not create and not os.path.exists(db_path):
        raise SystemExit(f"index not built yet: {db_path}\n  run: python scripts/faidx.py rebuild")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    # URI mode on the main connection so the callgraph index can be attached read-only.
    con = sqlite3.connect(_file_uri(db_path, "mode=rwc"), timeout=30.0, uri=True)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA synchronous = NORMAL")
    con.execute("PRAGMA busy_timeout = 30000")
    con.executescript(SCHEMA)
    return con


def attach_callgraph(con: sqlite3.Connection, repo: str) -> bool:
    cg = os.path.join(repo, CG_DB_REL)
    if not os.path.exists(cg):
        return False
    con.execute("ATTACH DATABASE ? AS cg", (_file_uri(cg, "mode=ro"),))
    return True


def meta_get(con: sqlite3.Connection, key: str) -> str | None:
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def meta_set(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))


# --------------------------------------------------------------------------- #
# source scanning
# --------------------------------------------------------------------------- #

class FileScan:
    """Comment/string-stripped lines, brace depth before each line, scope names."""

    __slots__ = ("raw", "clean", "depth_before", "scope_at")

    def __init__(self, raw_lines: list[str]):
        self.raw = raw_lines
        self.clean: list[str] = []
        self.depth_before: list[int] = []
        self.scope_at: list[str] = []
        in_block = False
        depth = 0
        scope: list[tuple[str, int]] = []
        pending: str | None = None
        for raw in raw_lines:
            self.depth_before.append(depth)
            self.scope_at.append("::".join(n for n, _ in scope))
            if in_block or FAST_LINE_RE.search(raw):
                line, in_block = _strip_line(raw, in_block)
            else:
                line = raw
            self.clean.append(line)
            m = SCOPE_RE.match(line)
            if m and m.group(1) in ("class", "struct", "namespace", "union"):
                stripped = line.rstrip()
                if "{" in line or not stripped.endswith(";"):
                    pending = m.group(2)
            for ch in line:
                if ch == "{":
                    if pending is not None:
                        scope.append((pending, depth))
                        pending = None
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if scope and scope[-1][1] == depth:
                        scope.pop()
            if pending is not None and line.rstrip().endswith(";") and "{" not in line:
                pending = None


def _strip_line(raw: str, in_block: bool) -> tuple[str, bool]:
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        if in_block:
            j = raw.find("*/", i)
            if j < 0:
                return "".join(out), True
            in_block = False
            i = j + 2
            continue
        c = raw[i]
        if c == "/" and i + 1 < n:
            nxt = raw[i + 1]
            if nxt == "*":
                in_block = True
                i += 2
                continue
            if nxt == "/":
                break
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < n and raw[i] != q:
                if raw[i] == "\\":
                    i += 1
                i += 1
            i += 1
            out.append(q + q)
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def _split_items(inner: str) -> list[str]:
    items, buf, depth = [], [], 0
    for ch in inner:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            items.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _parse_anchor_rest(rest: str) -> tuple[str | None, str | None, str | None]:
    """(token, label, mangled) from the text after the address."""
    token = label = mangled = None
    labels: list[str] = []
    m = re.search(r"\(([^)]*(?:\([^)]*\)[^)]*)*)\)", rest)
    if m:
        for item in _split_items(m.group(1)):
            item = item.strip("`' ")
            if not item:
                continue
            if TOKEN_RE.match(item):
                token = token or item.upper().replace("FUN_", "FUN_")
            elif item.startswith("?") or item.startswith("??"):
                mangled = mangled or item
            elif re.match(r"^sub_[0-9A-Fa-f]{6,8}$", item):
                labels.append(item)
            else:
                labels.append(item)
    if labels:
        label = " | ".join(labels)
    return token, label, mangled


def _classify_and_symbol(code: str, scope: str) -> tuple[str, str]:
    """Return (kind, symbol) for the collapsed code text that follows a block."""
    text = re.sub(r"\s+", " ", code).strip()
    term = ""
    if text and text[-1] in "{;":
        term = text[-1]
        text = text[:-1].rstrip()
    head = text.split(" ", 1)[0] if text else ""
    kind = "def" if term == "{" else "decl"
    if head == "static_assert":
        return "assert", ""
    if head in ("class", "struct", "union", "enum") or text.startswith("enum class"):
        return "type", (re.search(r"(?:class|struct|union|enum(?: class)?)\s+([A-Za-z_][\w:]*)", text) or [None, ""])[1]
    if head in ("typedef", "using"):
        return "alias", ""
    if head == "#define":
        return "macro", ""
    symbol = ""
    m = OPERATOR_RE.search(text)
    if m:
        symbol = (m.group(1) or "") + "operator" + m.group(2).replace(" ", "")
    else:
        idx = text.find("(")
        if idx >= 0:
            prefix = text[:idx].rstrip()
        else:
            prefix = re.split(r"[=;{]", text, 1)[0].rstrip()
            if term == ";" or "=" in text:
                kind = "data"
        m2 = SYMBOL_TAIL_RE.search(prefix)
        symbol = m2.group(1) if m2 else ""
        if kind == "def" and idx < 0:
            kind = "data"
    if symbol and scope and "::" not in symbol:
        symbol = scope + "::" + symbol
    elif symbol and scope and not symbol.startswith(scope + "::"):
        # definition written with a partial qualifier inside a namespace block
        first = symbol.split("::", 1)[0]
        if first not in scope.split("::"):
            symbol = scope + "::" + symbol
    return kind, symbol


def scan_source_file(abs_path: str, rel_path: str) -> list[tuple]:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.read().split("\n")
    except OSError:
        return []
    if not any("Address:" in ln for ln in raw_lines):
        return []
    scan = FileScan(raw_lines)
    n = len(raw_lines)
    rows: list[tuple] = []
    for i, raw in enumerate(raw_lines):
        m = ADDR_LINE_RE.search(raw)
        if not m or "Address:" not in raw:
            continue
        # only comment lines count as anchors
        st = raw.lstrip()
        if not (st.startswith("*") or st.startswith("/") or st.startswith("///") or "/**" in raw or "//" in raw):
            continue
        ea = int(m.group(1), 16)
        token, label, mangled = _parse_anchor_rest(m.group(2))
        # find the end of the enclosing comment block
        block_end = i
        if "*/" not in raw and st.startswith("*") or st.startswith("/*") and "*/" not in raw:
            j = i + 1
            while j < n and "*/" not in raw_lines[j]:
                if mangled is None:
                    mm = MANGLED_RE.search(raw_lines[j])
                    if mm:
                        mangled = mm.group(1)
                j += 1
            block_end = j
        # first code line after the block
        code_line = None
        j = block_end + 1
        while j < n and j < block_end + 40:
            c = scan.clean[j].strip()
            r = raw_lines[j].strip()
            if c and not r.startswith("//") and not r.startswith("#") and not r.startswith("*") and not r.startswith("/*"):
                code_line = j
                break
            j += 1
        kind, symbol, end_line = "orphan", "", None
        if code_line is not None:
            # collect until a top-level ';' or '{'
            buf: list[str] = []
            depth = 0
            k = code_line
            done = False
            while k < n and k < code_line + 40 and not done:
                seg = scan.clean[k]
                piece: list[str] = []
                for ch in seg:
                    piece.append(ch)
                    if ch in "([":
                        depth += 1
                    elif ch in ")]":
                        depth = max(0, depth - 1)
                    elif ch in "{;" and depth == 0:
                        done = True
                        break
                buf.append("".join(piece))
                k += 1
            code = " ".join(buf)
            kind, symbol = _classify_and_symbol(code, scan.scope_at[code_line])
            if kind == "def":
                end_line = _find_block_end(scan, code_line)
        rows.append((ea, token, rel_path, i + 1, (code_line + 1) if code_line is not None else None,
                     (end_line + 1) if end_line is not None else None, kind, symbol, label, mangled,
                     scan.scope_at[code_line] if code_line is not None else scan.scope_at[i]))
    return rows


def _find_block_end(scan: FileScan, start: int) -> int | None:
    depth = 0
    opened = False
    n = len(scan.clean)
    k = start
    limit = min(n, start + 20000)
    while k < limit:
        for ch in scan.clean[k]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return k
        k += 1
    return None


# --------------------------------------------------------------------------- #
# indexing
# --------------------------------------------------------------------------- #

def iter_source_files(repo: str) -> Iterable[str]:
    root = os.path.join(repo, SRC_ROOT)
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if is_source(fn):
                yield os.path.join(dp, fn)


def index_file(con: sqlite3.Connection, repo: str, abs_path: str, force: bool = False) -> bool:
    rel_path = rel(abs_path, repo)
    try:
        st = os.stat(abs_path)
    except OSError:
        con.execute("DELETE FROM anchors WHERE file = ?", (rel_path,))
        con.execute("DELETE FROM files WHERE path = ?", (rel_path,))
        return True
    row = con.execute("SELECT sha1, size, mtime FROM files WHERE path = ?", (rel_path,)).fetchone()
    if row and not force and row[1] == st.st_size and abs(row[2] - st.st_mtime) < 1e-6:
        return False
    digest = sha1_of(abs_path)
    if row and not force and row[0] == digest:
        con.execute("UPDATE files SET size = ?, mtime = ? WHERE path = ?", (st.st_size, st.st_mtime, rel_path))
        return False
    rows = scan_source_file(abs_path, rel_path)
    con.execute("DELETE FROM anchors WHERE file = ?", (rel_path,))
    con.executemany(
        "INSERT INTO anchors(ea, token, file, line, code_line, end_line, kind, symbol, label, mangled, scope)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.execute(
        "INSERT OR REPLACE INTO files(path, sha1, size, mtime, indexed_utc, anchor_count) VALUES (?,?,?,?,?,?)",
        (rel_path, digest, st.st_size, st.st_mtime, utc_now(), len(rows)))
    return True


def update_sources(con: sqlite3.Connection, repo: str, only: list[str] | None = None, force: bool = False) -> tuple[int, int]:
    changed = 0
    seen: set[str] = set()
    paths = [os.path.abspath(p) for p in only] if only else list(iter_source_files(repo))
    for p in paths:
        if not is_source(p):
            continue
        seen.add(rel(p, repo))
        if index_file(con, repo, p, force=force):
            changed += 1
    removed = 0
    if only is None:
        for (path,) in con.execute("SELECT path FROM files").fetchall():
            if path not in seen:
                con.execute("DELETE FROM anchors WHERE file = ?", (path,))
                con.execute("DELETE FROM files WHERE path = ?", (path,))
                removed += 1
    return changed, removed


def update_progress(con: sqlite3.Connection, repo: str, force: bool = False) -> bool:
    path = os.path.join(repo, PROGRESS_REL)
    if not os.path.exists(path):
        return False
    st = os.stat(path)
    fp = f"{st.st_size}:{st.st_mtime:.3f}"
    if not force and meta_get(con, "progress_fp") == fp:
        return False
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    ns = (data.get("namespaces") or {}).get(NAMESPACE) or {}
    rec = ns.get("recovered") or {}
    rows = []
    for token, r in rec.items():
        if not isinstance(r, dict):
            continue
        rows.append((
            token, r.get("status"), r.get("note"),
            json.dumps([norm_rel(p) for p in (r.get("source_paths") or [])]),
            json.dumps([p.replace("\\", "/").lstrip("./") for p in (r.get("report_paths") or [])]),
            r.get("updated_utc"), r.get("blocker_type"), r.get("confidence"),
            r.get("last_worker") or r.get("worker"),
            json.dumps(r.get("depends_on") or []),
        ))
    con.execute("DELETE FROM progress")
    con.executemany("INSERT INTO progress VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    meta_set(con, "progress_fp", fp)
    meta_set(con, "progress_rows", str(len(rows)))
    return True


def iter_note_files(repo: str) -> Iterable[tuple[str, str]]:
    for kind, sub in NOTE_ROOTS:
        root = os.path.join(repo, sub)
        if not os.path.isdir(root):
            continue
        for dp, dn, fns in os.walk(root):
            dn[:] = [d for d in dn if d not in ("__pycache__", "node_modules")]
            for fn in fns:
                if fn.lower().endswith(".md"):
                    yield kind, os.path.join(dp, fn)
    for fn in ("CLAUDE.md", "README.md"):
        p = os.path.join(repo, fn)
        if os.path.exists(p):
            yield "doc", p


def update_notes(con: sqlite3.Connection, repo: str, force: bool = False) -> tuple[int, int]:
    known = {p: (m, s) for p, m, s in con.execute("SELECT path, mtime, size FROM notes").fetchall()}
    seen: set[str] = set()
    changed = 0
    batch: list[tuple] = []
    for kind, abs_path in iter_note_files(repo):
        rel_path = rel(abs_path, repo)
        seen.add(rel_path)
        try:
            st = os.stat(abs_path)
        except OSError:
            continue
        old = known.get(rel_path)
        if old and not force and old[1] == st.st_size and abs(old[0] - st.st_mtime) < 1e-6:
            continue
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        title = ""
        for ln in body.split("\n", 60)[:60]:
            hm = HEADING_RE.match(ln)
            if hm:
                title = hm.group(1)
                break
        if not title:
            title = os.path.basename(abs_path)
        batch.append((rel_path, kind, st.st_mtime, st.st_size, title, body))
        changed += 1
        if len(batch) >= 2000:
            _flush_notes(con, batch)
            batch = []
    if batch:
        _flush_notes(con, batch)
    removed = 0
    for path in list(known):
        if path not in seen:
            con.execute("DELETE FROM notes WHERE path = ?", (path,))
            con.execute("DELETE FROM notes_fts WHERE path = ?", (path,))
            removed += 1
    return changed, removed


def _flush_notes(con: sqlite3.Connection, batch: list[tuple]) -> None:
    con.executemany("DELETE FROM notes_fts WHERE path = ?", [(b[0],) for b in batch])
    con.executemany("INSERT OR REPLACE INTO notes(path, kind, mtime, size, title) VALUES (?,?,?,?,?)",
                    [b[:5] for b in batch])
    con.executemany("INSERT INTO notes_fts(path, title, body) VALUES (?,?,?)",
                    [(b[0], b[4], b[5]) for b in batch])


def cmd_update(args) -> int:
    repo, db_path = args.repo, args.db
    t0 = time.time()
    con = open_db(repo, db_path)
    with con:
        if args.files:
            changed, removed = update_sources(con, repo, only=args.files, force=args.full)
            prog = False
            n_changed = n_removed = 0
        else:
            changed, removed = update_sources(con, repo, force=args.full)
            prog = update_progress(con, repo, force=args.full)
            n_changed, n_removed = update_notes(con, repo, force=args.full)
        meta_set(con, "last_update_utc", utc_now())
    if not args.quiet:
        print(f"sources: {changed} reindexed, {removed} removed | progress: {'reimported' if prog else 'unchanged'}"
              f" | notes: {n_changed} reindexed, {n_removed} removed | {time.time() - t0:.1f}s")
    return 0


def cmd_rebuild(args) -> int:
    for suffix in ("", "-wal", "-shm"):
        p = args.db + suffix
        if os.path.exists(p):
            os.remove(p)
    args.full = True
    args.files = None
    return cmd_update(args)


# --------------------------------------------------------------------------- #
# lookups shared by the query commands
# --------------------------------------------------------------------------- #

def status_of(con: sqlite3.Connection, token: str) -> tuple[str, str]:
    row = con.execute("SELECT status, note FROM progress WHERE token = ?", (token,)).fetchone()
    return (row[0] or "", row[1] or "") if row else ("", "")


def anchors_for(con: sqlite3.Connection, ea: int) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM anchors WHERE ea = ? ORDER BY CASE kind WHEN 'def' THEN 0 WHEN 'decl' THEN 1 ELSE 2 END,"
        " CASE WHEN file LIKE '%.cpp' THEN 0 ELSE 1 END, file, line", (ea,)).fetchall()


def def_location(con: sqlite3.Connection, ea: int) -> str:
    rows = anchors_for(con, ea)
    for r in rows:
        if r["kind"] == "def":
            return f"{r['file']}:{r['code_line'] or r['line']}"
    return f"{rows[0]['file']}:{rows[0]['code_line'] or rows[0]['line']}" if rows else ""


def resolve_target(con: sqlite3.Connection, target: str, has_cg: bool) -> list[tuple[str, int]]:
    """Return [(token, ea)] candidates for a token, address or name."""
    t = target.strip()
    if TOKEN_RE.match(t):
        return [(t.upper().replace("FUN_", "FUN_"), int(t[4:], 16))]
    if HEX_RE.match(t):
        ea = int(t, 16)
        if has_cg:
            row = con.execute("SELECT token FROM cg.functions WHERE ea = ?", (ea,)).fetchone()
            if row:
                return [(row[0], ea)]
            row = con.execute("SELECT token, start_ea FROM cg.functions WHERE start_ea <= ? AND end_ea > ?"
                              " ORDER BY start_ea DESC LIMIT 1", (ea, ea)).fetchone()
            if row:
                return [(row[0], row[1])]
        return [(f"FUN_{ea:08X}", ea)]
    like = f"%{t}%"
    out: list[tuple[str, int]] = []
    seen: set[int] = set()
    for (ea,) in con.execute("SELECT DISTINCT ea FROM anchors WHERE symbol LIKE ? OR label LIKE ? OR mangled LIKE ?"
                             " ORDER BY ea LIMIT 50", (like, like, like)).fetchall():
        if ea not in seen:
            seen.add(ea)
            tok = None
            if has_cg:
                r = con.execute("SELECT token FROM cg.functions WHERE ea = ?", (ea,)).fetchone()
                tok = r[0] if r else None
            out.append((tok or f"FUN_{ea:08X}", ea))
    if has_cg:
        for tok, ea in con.execute("SELECT token, ea FROM cg.functions WHERE function_name LIKE ? OR demangled_name LIKE ?"
                                   " ORDER BY ea LIMIT 50", (like, like)).fetchall():
            if ea not in seen:
                seen.add(ea)
                out.append((tok, ea))
    return out


def fn_row(con: sqlite3.Connection, token: str):
    return con.execute("SELECT * FROM cg.functions WHERE token = ?", (token,)).fetchone()


def best_name(fn) -> str:
    if fn is None:
        return ""
    return fn["demangled_name"] or fn["function_name"] or fn["listing_name"] or ""


# --------------------------------------------------------------------------- #
# card
# --------------------------------------------------------------------------- #

def build_card(con: sqlite3.Connection, token: str, ea: int, has_cg: bool, limit: int = 12) -> dict:
    card: dict = {"token": token, "ea": f"0x{ea:08X}"}
    fn = fn_row(con, token) if has_cg else None
    if fn:
        card["name"] = best_name(fn)
        card["mangled"] = fn["function_name"] if (fn["function_name"] or "").startswith("?") else ""
        card["span_bytes"] = fn["span_bytes"]
        card["instructions"] = fn["instruction_count"]
        card["sha256"] = fn["function_sha256"]
    st, note = status_of(con, token)
    prow = con.execute("SELECT * FROM progress WHERE token = ?", (token,)).fetchone()
    card["status"] = st
    card["note"] = note
    if prow:
        card["updated_utc"] = prow["updated_utc"]
        card["worker"] = prow["last_worker"]
        card["blocker_type"] = prow["blocker_type"]
        card["db_source_paths"] = json.loads(prow["source_paths"] or "[]")
        card["report_paths"] = json.loads(prow["report_paths"] or "[]")
        card["depends_on"] = json.loads(prow["depends_on"] or "[]")
    anchors = anchors_for(con, ea)
    card["anchors"] = [
        {"file": a["file"], "line": a["line"], "code_line": a["code_line"], "end_line": a["end_line"],
         "kind": a["kind"], "symbol": a["symbol"], "label": a["label"], "mangled": a["mangled"]}
        for a in anchors]
    rp = f"decomp/recovery/reports/{token}.md"
    card["report"] = rp if os.path.exists(os.path.join(REPO, rp)) else ""
    if has_cg:
        card["callers"] = _edge_rows(con, "SELECT e.src_token AS tok FROM cg.call_edges e WHERE e.dst_token = ? ORDER BY e.src_ea", token, limit)
        card["callers_total"] = con.execute("SELECT COUNT(*) FROM cg.call_edges WHERE dst_token = ?", (token,)).fetchone()[0]
        card["callees"] = _edge_rows(con, "SELECT e.dst_token AS tok FROM cg.call_edges e WHERE e.src_token = ? ORDER BY e.dst_ea", token, limit)
        card["callees_total"] = con.execute("SELECT COUNT(*) FROM cg.call_edges WHERE src_token = ?", (token,)).fetchone()[0]
        card["data_xrefs"] = [
            {"from": r[0] or r[1] or "", "line": (r[2] or "")[:90]}
            for r in con.execute("SELECT from_name, owner_name, line FROM cg.incoming_xrefs WHERE target_token = ? AND kind = 'data'"
                                 " LIMIT ?", (token, limit)).fetchall()]
        card["data_xrefs_total"] = con.execute("SELECT COUNT(*) FROM cg.incoming_xrefs WHERE target_token = ? AND kind = 'data'", (token,)).fetchone()[0]
        card["vtable_refs"] = [r[0] for r in con.execute(
            "SELECT DISTINCT from_name FROM cg.incoming_xrefs WHERE target_token = ? AND from_name LIKE '??_7%' LIMIT 8", (token,)).fetchall()]
        card["writes_vtables"] = [r[0] for r in con.execute(
            "SELECT DISTINCT class_name FROM cg.vtable_writers WHERE writer_token = ? LIMIT 8", (token,)).fetchall()]
        reach = con.execute("SELECT root_kind, root_label, depth FROM cg.reachable WHERE token = ?", (token,)).fetchone()
        card["reach"] = {"root_kind": reach[0], "root_label": reach[1], "depth": reach[2]} if reach else None
        roots = con.execute("SELECT root_kind, root_label FROM cg.roots WHERE token = ? LIMIT 6", (token,)).fetchall()
        card["roots"] = [{"kind": r[0], "label": r[1]} for r in roots]
        if fn and fn["function_sha256"]:
            twins = [r[0] for r in con.execute(
                "SELECT token FROM cg.functions WHERE function_sha256 = ? AND token != ? AND function_code_bytes > 0 LIMIT 12",
                (fn["function_sha256"], token)).fetchall()]
            card["icf_twins"] = twins
        card["neighbours"] = neighbours(con, ea)
    return card


def _edge_rows(con: sqlite3.Connection, sql: str, token: str, limit: int) -> list[dict]:
    out = []
    for (tok,) in con.execute(sql + " LIMIT ?", (token, limit)).fetchall():
        fn = fn_row(con, tok)
        st, _ = status_of(con, tok)
        out.append({"token": tok, "name": best_name(fn), "status": st, "def": def_location(con, fn["ea"]) if fn else ""})
    return out


def neighbours(con: sqlite3.Connection, ea: int, count: int = 2) -> dict:
    """Nearest address-neighbours that carry a source anchor, and the file prediction."""
    def side(order: str, cmp: str):
        rows = []
        for tok, nea in con.execute(f"SELECT token, ea FROM cg.functions WHERE ea {cmp} ? ORDER BY ea {order} LIMIT 40", (ea,)).fetchall():
            loc = def_location(con, nea)
            if loc:
                rows.append({"token": tok, "ea": f"0x{nea:08X}", "def": loc})
                if len(rows) >= count:
                    break
        return rows
    prev = side("DESC", "<")
    nxt = side("ASC", ">")
    pred = None
    if prev and nxt:
        pf = prev[0]["def"].split(":")[0]
        nf = nxt[0]["def"].split(":")[0]
        pred = {"file": pf, "confidence": "unanimous"} if pf == nf else {"file": None, "confidence": "split", "prev": pf, "next": nf}
    return {"prev": prev, "next": nxt, "prediction": pred}


def print_card(card: dict) -> None:
    head = f"{card['token']}  {card['ea']}"
    if card.get("name"):
        head += f"  {card['name']}"
    print(head)
    if card.get("mangled"):
        print(f"  mangled: {card['mangled']}")
    meta = []
    if card.get("span_bytes") is not None:
        meta.append(f"span 0x{card['span_bytes']:X}")
    if card.get("instructions") is not None:
        meta.append(f"{card['instructions']} instr")
    st = card.get("status") or "(not in progress db)"
    meta.append(f"status={st}")
    if card.get("updated_utc"):
        meta.append(f"updated {card['updated_utc'][:10]}")
    if card.get("worker"):
        meta.append(f"worker={card['worker']}")
    if card.get("blocker_type"):
        meta.append(f"blocker={card['blocker_type']}")
    print("  " + "  ".join(meta))
    if card.get("note"):
        print(f"  note: {card['note'][:300]}")
    if card.get("anchors"):
        for a in card["anchors"]:
            loc = f"{a['file']}:{a['code_line'] or a['line']}"
            if a["end_line"]:
                loc += f"-{a['end_line']}"
            extra = a["symbol"] or a["label"] or ""
            print(f"  {a['kind']:6s} {loc}  {extra}")
    else:
        print("  source: NO ANCHOR in src/sdk")
    if card.get("db_source_paths"):
        anchored = {a["file"] for a in card.get("anchors", [])}
        flag = "" if anchored & set(card["db_source_paths"]) else "  (DISAGREES with anchors)" if anchored else ""
        print(f"  db source_paths: {', '.join(card['db_source_paths'])}{flag}")
    if card.get("report"):
        print(f"  report: {card['report']}")
    for key, label in (("callers", "callers"), ("callees", "callees")):
        rows = card.get(key)
        if rows is None:
            continue
        total = card.get(key + "_total", len(rows))
        print(f"  {label} ({total}):")
        for r in rows:
            print(f"    {r['token']}  {r['status'] or '--':20s} {r['def'] or '-':60s} {r['name']}")
        if total > len(rows):
            print(f"    ... +{total - len(rows)} more")
    if card.get("vtable_refs"):
        print("  vtable slots: " + "; ".join(card["vtable_refs"]))
    if card.get("data_xrefs_total"):
        print(f"  data xrefs ({card['data_xrefs_total']}): " + "; ".join(x["from"] for x in card["data_xrefs"][:6]))
    if card.get("writes_vtables"):
        print("  writes vtable of: " + ", ".join(card["writes_vtables"]))
    if card.get("roots"):
        print("  roots: " + "; ".join(f"{r['kind']}:{r['label']}" for r in card["roots"]))
    if "reach" in card:
        r = card["reach"]
        print(f"  reach: {'yes via ' + r['root_kind'] + ' depth=' + str(r['depth']) + ' (' + str(r['root_label']) + ')' if r else 'UNREACHED'}")
    if card.get("icf_twins"):
        print("  icf twins: " + ", ".join(card["icf_twins"]))
    nb = card.get("neighbours")
    if nb:
        p = nb["prev"][0]["def"] if nb["prev"] else "-"
        q = nb["next"][0]["def"] if nb["next"] else "-"
        pred = nb["prediction"]
        ptxt = f"{pred['file']} ({pred['confidence']})" if pred and pred.get("file") else (f"split {pred['prev']} | {pred['next']}" if pred else "-")
        print(f"  neighbours: prev {nb['prev'][0]['token'] if nb['prev'] else '-'} @ {p} | next {nb['next'][0]['token'] if nb['next'] else '-'} @ {q}")
        print(f"  locality prediction: {ptxt}")
    if card.get("depends_on"):
        print("  depends_on: " + ", ".join(card["depends_on"][:12]))


def cmd_card(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    con.row_factory = sqlite3.Row
    has_cg = attach_callgraph(con, args.repo)
    cands = resolve_target(con, args.target, has_cg)
    if not cands:
        print(f"no function matches {args.target!r}")
        return 1
    if len(cands) > 1 and not (TOKEN_RE.match(args.target) or HEX_RE.match(args.target)):
        print(f"{len(cands)} matches for {args.target!r}; pick one:")
        for tok, ea in cands[:25]:
            fn = fn_row(con, tok) if has_cg else None
            st, _ = status_of(con, tok)
            print(f"  {tok}  {st or '--':20s} {def_location(con, ea) or '-':55s} {best_name(fn)}")
        return 0
    cards = [build_card(con, tok, ea, has_cg, limit=args.limit) for tok, ea in cands[:1]]
    if args.json:
        print(json.dumps(cards[0], indent=2))
    else:
        print_card(cards[0])
    return 0


# --------------------------------------------------------------------------- #
# at / find / notes / owner / stats
# --------------------------------------------------------------------------- #

def cmd_at(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    con.row_factory = sqlite3.Row
    has_cg = attach_callgraph(con, args.repo)
    spec = args.location
    if ":" not in spec.rsplit("/", 1)[-1]:
        print("usage: faidx at <file>:<line>")
        return 2
    path, _, line_s = spec.rpartition(":")
    line = int(line_s)
    rel_path = norm_rel(rel(path, args.repo)) if os.path.exists(path) else norm_rel(path)
    rows = con.execute(
        "SELECT * FROM anchors WHERE file = ? AND kind = 'def' AND code_line <= ? AND end_line >= ? ORDER BY code_line DESC",
        (rel_path, line, line)).fetchall()
    if not rows:
        rows = con.execute("SELECT * FROM anchors WHERE file = ? AND line <= ? ORDER BY line DESC LIMIT 1", (rel_path, line)).fetchall()
        if rows:
            print(f"no definition spans {rel_path}:{line}; nearest anchor above:")
    if not rows:
        print(f"no anchors in {rel_path} at or above line {line}")
        return 1
    for a in rows:
        tok = a["token"]
        if not tok and has_cg:
            r = con.execute("SELECT token FROM cg.functions WHERE ea = ?", (a["ea"],)).fetchone()
            tok = r[0] if r else f"FUN_{a['ea']:08X}"
        st, _ = status_of(con, tok or "")
        print(f"{tok}  0x{a['ea']:08X}  {a['kind']}  {a['file']}:{a['code_line'] or a['line']}-{a['end_line'] or ''}  {a['symbol'] or a['label'] or ''}  status={st or '--'}")
    return 0


def cmd_find(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    con.row_factory = sqlite3.Row
    has_cg = attach_callgraph(con, args.repo)
    cands = resolve_target(con, args.needle, has_cg)
    if not cands:
        print("no matches")
        return 1
    for tok, ea in cands[: args.limit]:
        fn = fn_row(con, tok) if has_cg else None
        st, _ = status_of(con, tok)
        print(f"{tok}  {st or '--':20s} {def_location(con, ea) or '-':60s} {best_name(fn)}")
    if len(cands) > args.limit:
        print(f"... +{len(cands) - args.limit} more (raise --limit)")
    return 0


def cmd_notes(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    q = args.query
    try:
        rows = con.execute(
            "SELECT n.path, n.kind, n.title, snippet(notes_fts, 2, '[', ']', ' ... ', 18) AS snip, bm25(notes_fts) AS rank"
            " FROM notes_fts JOIN notes n ON n.path = notes_fts.path WHERE notes_fts MATCH ? ORDER BY rank LIMIT ?",
            (q, args.limit)).fetchall()
    except sqlite3.OperationalError as exc:
        print(f"bad query ({exc}); FTS5 syntax: words, \"phrases\", AND/OR/NOT, prefix*")
        return 2
    if not rows:
        print("no notes match")
        return 1
    for path, kind, title, snip, _rank in rows:
        snip = re.sub(r"\s+", " ", snip or "")
        print(f"{kind:7s} {path}\n        {title[:100]}\n        {snip[:240]}")
    return 0


def cmd_owner(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    con.row_factory = sqlite3.Row
    if not attach_callgraph(con, args.repo):
        print("callgraph index missing; owner needs it")
        return 1
    cands = resolve_target(con, args.target, True)
    if not cands:
        print("no match")
        return 1
    tok, ea = cands[0]
    nb = neighbours(con, ea, count=3)
    print(f"{tok} 0x{ea:08X}  own anchor: {def_location(con, ea) or '(none)'}")
    for r in reversed(nb["prev"]):
        print(f"  prev {r['token']} {r['ea']}  {r['def']}")
    for r in nb["next"]:
        print(f"  next {r['token']} {r['ea']}  {r['def']}")
    pred = nb["prediction"]
    if pred and pred.get("file"):
        print(f"  prediction: {pred['file']} (both immediate neighbours agree)")
    elif pred:
        print(f"  prediction: split between {pred['prev']} and {pred['next']}")
    return 0


def cmd_stats(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    has_cg = attach_callgraph(con, args.repo)
    n_files, n_anch = con.execute("SELECT COUNT(*), COALESCE(SUM(anchor_count),0) FROM files").fetchone()
    kinds = con.execute("SELECT kind, COUNT(*) FROM anchors GROUP BY kind ORDER BY 2 DESC").fetchall()
    print(f"files {n_files}  anchors {n_anch}  kinds {dict(kinds)}")
    print("progress:", dict(con.execute("SELECT status, COUNT(*) FROM progress GROUP BY status").fetchall()))
    print("notes:", dict(con.execute("SELECT kind, COUNT(*) FROM notes GROUP BY kind").fetchall()))
    print("last update:", meta_get(con, "last_update_utc"), "| callgraph attached:", has_cg)
    if has_cg:
        print("functions in callgraph:", con.execute("SELECT COUNT(*) FROM cg.functions").fetchone()[0])
    return 0


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #

VERIFY_CATEGORIES = {
    "anchor_outside_any_function": "anchor address is not inside any IDA function (data address or bad hex)",
    "anchor_mid_function": "anchor address is inside a function but not at its start",
    "duplicate_definition": "same address has 'def' anchors in two or more files",
    "recovered_without_anchor": "progress says recovered but no anchor names the address anywhere in src/sdk",
    "source_paths_disagree": "progress source_paths never names the file that holds the anchor",
    "anchored_not_recovered": "an anchor exists but the progress status is not recovered",
    "token_address_mismatch": "the (FUN_) token in the anchor does not match the address",
    "orphan_anchor": "anchor block is not followed by any code",
    "misplaced_anchor": "address is a function start but the block is followed by data/type/alias code, not a function",
}


def run_verify(con: sqlite3.Connection, has_cg: bool) -> dict[str, list]:
    out: dict[str, list] = {k: [] for k in VERIFY_CATEGORIES}
    anchors = con.execute("SELECT ea, token, file, line, kind FROM anchors").fetchall()
    for ea, token, file, line, kind in anchors:
        if token and int(token[4:], 16) != ea:
            out["token_address_mismatch"].append((f"0x{ea:08X}", token, f"{file}:{line}"))
        if kind == "orphan":
            out["orphan_anchor"].append((f"0x{ea:08X}", f"{file}:{line}"))
    if has_cg:
        con.execute("CREATE TEMP TABLE IF NOT EXISTS _eas(ea INTEGER PRIMARY KEY)")
        con.execute("DELETE FROM _eas")
        con.executemany("INSERT OR IGNORE INTO _eas VALUES (?)", [(a[0],) for a in anchors])
        starts = {r[0] for r in con.execute(
            "SELECT _eas.ea FROM _eas JOIN cg.functions f ON f.ea = _eas.ea WHERE f.instruction_count > 0")}
        for ea, token, file, line, kind in anchors:
            if ea in starts and kind not in ("def", "decl"):
                out["misplaced_anchor"].append((f"0x{ea:08X}", kind, f"{file}:{line}"))
        for (ea,) in con.execute("SELECT ea FROM _eas").fetchall():
            if ea in starts:
                continue
            owner = con.execute("SELECT token FROM cg.functions WHERE start_ea <= ? AND end_ea > ? ORDER BY start_ea DESC LIMIT 1",
                                (ea, ea)).fetchone()
            files = [f"{r[0]}:{r[1]}" for r in con.execute("SELECT file, line FROM anchors WHERE ea = ? LIMIT 3", (ea,))]
            if owner:
                out["anchor_mid_function"].append((f"0x{ea:08X}", owner[0], files[0]))
            else:
                out["anchor_outside_any_function"].append((f"0x{ea:08X}", files[0]))
        # progress vs anchors
        anchored_tokens: dict[str, set[str]] = {}
        for tok, file in con.execute("SELECT f.token, a.file FROM anchors a JOIN cg.functions f ON f.ea = a.ea"):
            anchored_tokens.setdefault(tok, set()).add(file)
        for tok, status, sp in con.execute("SELECT token, status, source_paths FROM progress"):
            files = anchored_tokens.get(tok)
            if status == "recovered":
                if not files:
                    out["recovered_without_anchor"].append((tok,))
                else:
                    paths = set(json.loads(sp or "[]"))
                    if paths and not (paths & files):
                        out["source_paths_disagree"].append((tok, sorted(paths)[0], sorted(files)[0]))
            elif files and status not in ("recovered",):
                out["anchored_not_recovered"].append((tok, status or "", sorted(files)[0]))
    for ea, n in con.execute("SELECT ea, COUNT(DISTINCT file) FROM anchors WHERE kind = 'def' AND file LIKE '%.cpp' GROUP BY ea HAVING COUNT(DISTINCT file) > 1"):
        files = [r[0] for r in con.execute("SELECT DISTINCT file FROM anchors WHERE ea = ? AND kind = 'def'", (ea,))]
        out["duplicate_definition"].append((f"0x{ea:08X}", " | ".join(files[:4])))
    return out


def cmd_verify(args) -> int:
    con = open_db(args.repo, args.db, create=False)
    has_cg = attach_callgraph(con, args.repo)
    res = run_verify(con, has_cg)
    if args.json:
        print(json.dumps({k: v for k, v in res.items()}, indent=1))
        return 0
    if args.list:
        cat = args.list
        if cat not in res:
            print("categories: " + ", ".join(res))
            return 2
        for row in res[cat][: args.limit]:
            print("  ".join(str(x) for x in row))
        if len(res[cat]) > args.limit:
            print(f"... +{len(res[cat]) - args.limit} more (raise --limit)")
        return 0
    width = max(len(k) for k in res)
    for k, v in res.items():
        print(f"{k:{width}s} {len(v):7d}   {VERIFY_CATEGORIES[k]}")
    if not has_cg:
        print("(callgraph index not attached: only the source-only categories were checked)")
    worst = sum(len(res[k]) for k in ("token_address_mismatch", "duplicate_definition"))
    return 3 if (args.strict and worst) else 0


# --------------------------------------------------------------------------- #
# hook
# --------------------------------------------------------------------------- #

def cmd_hook(args) -> int:
    """PostToolUse: re-index the file an Edit/Write/MultiEdit just touched. Never fails the tool."""
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        tool_input = payload.get("tool_input") or {}
        path = tool_input.get("file_path") or ""
        if not path or not is_source(path):
            return 0
        rel_path = norm_rel(rel(path, args.repo))
        if not rel_path.startswith(SRC_ROOT + "/"):
            return 0
        if not os.path.exists(args.db):
            return 0
        con = open_db(args.repo, args.db)
        with con:
            index_file(con, args.repo, os.path.abspath(path))
            meta_set(con, "last_update_utc", utc_now())
    except Exception as exc:  # noqa: BLE001 - a hook must never break the tool call
        log_line(args.repo, f"hook error: {exc!r}")
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="faidx", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--db", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("update")
    p.add_argument("--full", action="store_true", help="re-scan even when fingerprints match")
    p.add_argument("--files", nargs="*", help="only these source files")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_update)

    p = sub.add_parser("rebuild")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_rebuild)

    p = sub.add_parser("verify")
    p.add_argument("--list", default=None, help="print the rows of one category")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit 3 when hard inconsistencies exist")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("card")
    p.add_argument("target")
    p.add_argument("--json", action="store_true")
    p.add_argument("--limit", type=int, default=12, help="callers/callees rows to show")
    p.set_defaults(fn=cmd_card)

    p = sub.add_parser("at")
    p.add_argument("location")
    p.set_defaults(fn=cmd_at)

    p = sub.add_parser("find")
    p.add_argument("needle")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(fn=cmd_find)

    p = sub.add_parser("notes")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(fn=cmd_notes)

    p = sub.add_parser("owner")
    p.add_argument("target")
    p.set_defaults(fn=cmd_owner)

    p = sub.add_parser("stats")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("hook")
    p.set_defaults(fn=cmd_hook)

    args = ap.parse_args(argv)
    # Notes and symbols carry UTF-8; the Windows console default is cp1252.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args.repo = os.path.abspath(args.repo)
    args.db = os.path.abspath(args.db) if args.db else os.path.join(args.repo, DB_REL)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
