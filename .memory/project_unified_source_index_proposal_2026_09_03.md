---
name: unified-source-index-proposal-2026-09-03
description: The operator's 2026-09-03 goal is a local index (binary DAG + status + src/sdk file:line) so agents stop grep fan-outs; scripts/faidx.py implements it and is validated on a 6-file scratch build, the full rebuild was paused by the operator before it ran.
metadata:
  type: project
---

**Goal (set by the operator 2026-09-03, still active):** a queryable index over
all binary functions keyed by FUN_ token / address that knows the exact src/sdk
file and line of every recovered body and stays in sync on edits, so recovery
and refactor work stops re-deriving the same join with greps.

**What exists now:** `scripts/faidx.py` (tracked; `skills/` and `.claude/` are
gitignored, `decomp/` too, so the tool lives in `scripts/` and the database in
`decomp/recovery/_source_index.sqlite`). It ATTACHes the IDA callgraph index
read-only instead of copying it (that db already carries every index the
queries need), scans the Doxygen `Address:` anchors in src/sdk with a
comment/string-stripping brace scanner (definition end line, qualified symbol
including class scope for header declarations, kind def/decl/data/type),
imports `recovered_progress.json` when its fingerprint changes, and keeps an
FTS5 table over reports, reconstruction notes, `.memory` and skill docs.
Commands: `update [--files]`, `rebuild`, `verify [--list CAT]`, `card TARGET`,
`at FILE:LINE`, `find`, `notes`, `owner`, `stats`, `hook` (PostToolUse stdin).

**Validated on a scratch db (6 files, 1,641 anchors, 0.3 s; hook re-index of
the 906-anchor Sim.cpp in 0.36 s):** card/at/find/owner/verify all work; the
callgraph attach needs `file:///G:/...` URIs (pathlib `as_uri()`), a plain
`file:G:/...` string fails on Windows.

**Two source-annotation defect classes the tool already surfaces:**
`misplaced_anchor` (a block whose address is a function start sits above a
data/type definition, e.g. the CameraImpl ctor block above `sType` while the
ctor body at CameraImpl.cpp:1527 has no block) and the earlier measured drift
(3,935 recovered tokens with no anchor, 653 wrong `source_paths`, 541
addresses defined in 2+ .cpp files, find_callers' grep missing ~65% of anchors
because only 24,972 of 71,666 anchors carry the `(FUN_)` token form).

**Paused, waiting on the operator:** the first full `rebuild` (they rejected
the tool call), the PostToolUse hook line in `.claude/settings.json`
(`python "G:\projects\faf-main\scripts\faidx.py" hook`, matcher
Write|Edit|MultiEdit; the hook is a no-op until the db exists), and the
CLAUDE.md section telling agents to run `card` before grepping.

**Design points to keep:** tree is the truth, index is a cache; never store
lines anywhere hand-edited; sync is a hook not a step; embeddings only for the
narrative layer and only after FTS5 proves too weak; progress JSON is imported,
not migrated. See [[feedback-dag-blindspot-file-contention]] for why file
ownership is a first-class column.
