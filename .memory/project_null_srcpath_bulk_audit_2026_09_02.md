---
name: project_null_srcpath_bulk_audit_2026_09_02
description: Systematic audit of the 12,153 "recovered" tokens with null source_paths (superseding the older 12,294-count note). Split cleanly into 8,203 real bookkeeping gaps (fixed) and a smaller, still-large "genuinely missing" bucket; found and fixed a 338-token sub-class of mis-tagged compiler jump-thunks within it. ~3,558 tokens remain open for future individual/systematic review.
metadata:
  type: project
---

## Method (reusable — scripts are in this session's scratchpad, not committed to the repo)

1. Collected every `recovered_progress.json` token with `status=recovered` AND
   empty/missing `source_paths` (12,153 as of this pass).
2. Built a full-tree index of every `Address: 0xNNNNNNNN (FUN_NNNNNNNN` Doxygen
   citation across `src/sdk/**/*.h`/`.cpp` (2,179 files, 48,537 distinct
   `FUN_` tokens actually cited).
3. Cross-referenced: does this token's address/FUN_ name appear ANYWHERE in
   that index?
   - **8,257 YES** — a pure bookkeeping gap: the recovery is real, the DB
     entry just never got `source_paths` linked. Bulk-fixed (8,203 landed;
     54 had already been fixed concurrently by other agents mid-run,
     detected and skipped safely).
   - **3,896 NO** — nothing in `src/sdk` cites this address at all.

## The bulk-fix mechanism (safe under concurrent agents)

`recovered_progress.py`'s `mark`/`bulk-mark` CLI don't support "same status,
per-token different source_paths" in one pass, and looping the CLI 8,257
times would take hours. Instead: `import recovered_progress as rp` directly
(its `def main()` is properly guarded behind `if __name__ == "__main__"`, so
importing doesn't trigger CLI execution) and reuse `rp.progress_db_lock`
(the real cross-process file lock, `os.O_CREAT|O_EXCL` + staleness timeout)
and `rp.write_json_atomic` (temp-file + `Path.replace`) directly — one
locked read-modify-write cycle covering all tokens, using the EXACT same
safety primitives the CLI itself uses, so it coexists safely with
concurrently-running agents also calling `mark`. Re-checked each token's
`status`/`source_paths` at write time (not just at snapshot time) and
skipped any that had changed since the audit ran, to avoid clobbering
concurrent work. Always: validate JSON before AND after, keep a timestamped
backup of the 43MB file before a bulk write of this size.

## The "3,896 missing" bucket is NOT one thing — first slice done

Characterizing the missing bucket by `last_worker` showed ~2,969 with
`last_worker=<none>`, but a naive small sample of their notes was
misleadingly uniform ("Compiler thunk: j_X") — the REAL count matching that
exact note pattern (verified precisely, not sampled) was only **340**, not
2,969. Lesson: characterize by an exact query, not by eyeballing a handful of
samples from a large bucket — the `<none>`-worker bucket clearly contains
multiple distinct sub-populations, only one of which is thunks.

Of those 340, **338 were individually re-verified against their own raw
`.asm`** (not trusted from the note text alone): total function size ≤ 8
bytes, disassembly is exactly one `jmp` instruction to another symbol. This
is precisely RULE TWO's `skip` definition ("IDA misclassification ... that
no source line produced") and CLAUDE.md's "Compiler-emitted glue is not
source at all" — a bare `jmp` thunk has no distinct source line to recover;
the real behavior lives at the jump target. Corrected `recovered` → `skip`
for 338 immediately, then checked the 2 outliers individually and fixed
both too (340/340 total): `FUN_006BA270` is a 5-instruction/12-byte
stack-reshuffle-then-tailcall adapter forwarding to the real, named
`Moho::CUnitMotion::MemberConstruct` (same "register-shape adapter" class
cited many other places this session); `FUN_008984B0` IS a genuine
single-jmp thunk (5 bytes) — the verification script's naive whole-file
instruction count was fooled by an unrelated second function
(`SessionEndGame`'s own large body) the `.asm` export tool appended after it
for reference, not part of the token itself.
`README.md` regenerated and committed (`d35fd4cb`, `bff1596e`) since this
changes the recovered/skip counts, unlike the pure source_paths fix.

## Major follow-up finding: 1,631-token register_* static-init family

Further slicing the note-text patterns (not just worker) found the real
prize: **1,631** of the remaining tokens have `note` starting with
`"Static init/cleanup helper: register_"` — CRT static-init registration
thunks for Lua function bindings (`register_X_LuaFuncDef`), console commands
(`register_CConFunc_X`), and shader vars (`register_ShaderVarTerrainStratum*`
etc). This is a genuine, large, well-scoped RECOVERY gap (not a DB-bookkeeping
fix) matching an already-proven pattern from this same session
(`register_MeshShaderVarTransPalette`/`RotPalette`, `Mesh.cpp`, and
`IN_DumpKeyNames`, commit `7669681f`). Dispatched to a dedicated agent
(too large for one pass — 1,631 tokens — land as much as time allows, not
exhaustive). This dwarfs the thunk-cleanup and source_paths-bookkeeping
findings above in potential recovered-count impact; worth checking on and
continuing across future sessions even if the first pass only lands a
fraction of it.

## Third finding: "-throw" batch-worker tokens are real substantial functions, NOT shims

473 tokens have a completely empty `note` (the single most suspicious
pattern — zero explanation for a `recovered` claim). Many trace to
`last_worker=codex-main-batch-20260417f-throw` and similarly-named
`-throw`-suffixed batch workers. Checked one directly against its own
`.asm` (`FUN_004DBE30`, 0x004DBE30-0x004DBFDC, ~460 bytes): it is a full
`msvc8::map<K,V>::insert`-shaped function — real RB-tree rotation/rebalance
logic (`sub_4DCC90`/`sub_4DCBE0`/`sub_4DCC40` callees, red-black color-bit
manipulation at `+0x28`), with a `"map/set<T> too long"` max_size overflow
guard at its TOP. The "-throw" in the batch-worker name refers to that one
guard sub-component, NOT the whole function being a trivial throw-shim —
this is a genuine, substantial, UNWRITTEN recovery gap (RULE ONE territory:
cite this address on the canonical `msvc8::map<K,V>::insert`/`Map.h` member
for whatever K,V this is, exactly like the palette-buffer `Vector.h` work
above), not a DB bookkeeping fix or a skip candidate. Do NOT bulk-treat this
whole `-throw` sub-bucket as either "fix source_paths" or "mark skip" without
per-token verification -- the one sample checked needs REAL work.

## What's still open

- **~3,556 tokens** (3,896 missing − 340 thunk-note matches) still have
  `status=recovered`, no `source_paths`, and no confirmed real source
  anywhere in `src/sdk`. Only characterized by `last_worker` distribution so
  far (see the worker breakdown in the audit output — many `codex-*-batch-*`
  and `codex-main` workers, suggesting older bulk passes, not necessarily
  fabrication — do not assume malice/fabrication without checking a sample
  the way the thunk sub-class was checked).
- The 2 non-conforming "Compiler thunk: j_" outliers (worth a quick
  individual look — one may be a slightly-larger multi-instruction thunk
  chain, the other's line-count-vs-size mismatch suggests the regex/asm
  format might differ for it, check manually rather than assuming).
- No attempt yet to sub-characterize the remaining ~3,556 by note-text
  pattern the way the thunk bucket was found — that's the natural next
  slice, using the same "exact query, then per-token .asm re-verify before
  bulk action" method as this pass.
