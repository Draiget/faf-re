---
name: feedback-stale-absorbed-status-pattern
description: A recurring, easy-to-find class of stale blocked-status bugs - "Absorbs binary helper" doxygen comments that already explain a token is covered by its caller's modern rewrite, but the progress DB status was never flipped. Grep recipe + guardrail for a lookalike trap (RB-tree inserts missing rotation/fixup logic) found 2026-08-19.
metadata:
  type: feedback
---

## The pattern

Several prior recovery passes wrote doxygen comments explicitly explaining
that a binary helper's role is "absorbed" by a caller's modern rewrite
(e.g. `msvc8::map<K,V>::operator[]`'s template emission absorbed by a
hand-coded RB-tree find-or-insert; a `vector<T>::resize` grow-path absorbed
by a `new[]` + `memset` rewrite) - but the actual `recovered_progress.json`
status for the absorbed token was never flipped from `blocked` to
`recovered`. This is a genuine, low-risk, high-value class of bug distinct
from "needs new recovery work": the explanation and modern equivalent
ALREADY EXIST in committed source, only the bookkeeping is stale.

**Why**: Prior CLAUDE.md guidance flagged "stale blocked flags are the
real bottleneck" for this project generally
([[project_frontier_not_exhausted_2026_08]]); this is one concrete,
searchable sub-species of that.

## How to find them

```
grep -rln "Absorbs binary helper\|absorbed by this named helper\|is absorbed by\|corresponds to the\|role is fulfilled by" src/sdk --include=*.cpp
```
Then, for each hit, extract the `FUN_XXXXXXXX` token(s) named in the
comment (both formal `Address:` blocks AND prose mentions - the CInfluenceMap
case named its still-blocked dependency ONLY in prose, "The inner insert
helper FUN_00719AB0 (still blocked) corresponds to...", no separate
Address: line) and check `recovered_progress.json`. If `blocked` while the
explanation is already committed and confident, flip it - add an explicit
address citation to the caller's doxygen first if the mention was
prose-only (matches the project's own "Address:" block convention and
strengthens the evidence trail for future audits), then `mark --status
recovered`.

Fixed 2026-08-19 this way: `FUN_00719AB0` (CInfluenceMap::UpsertBlipCell),
`FUN_0076C850` (PathTables::ResizeLegacyPointerStorage), `FUN_005A08B0`
(CAiBuilderImpl::AddOrUpdateRebuildNode) - three tokens, zero new logic
written, all three already had a complete, correct explanation sitting in
committed source.

## The lookalike trap - verify, don't just pattern-match

Not every "hand-coded RB-tree replaces msvc8::map" claim is actually
complete. Checked `Sim.cpp`'s `InsertBlueprintMapNode` (the presumed
absorber for `FUN_00534580`/`FUN_00534690`, blocked with "unresolved
blueprint-tree insertion dependencies FUN_00535250/FUN_005363B0" etc.) and
found it does a **plain BST insert with every new node hardcoded
`mColor = kTreeBlack`, no rotation/fixup logic anywhere in the function**.
A genuine red-black tree insert requires inserting RED then rebalancing
(rotations + recoloring) to preserve RB invariants; this function does
neither. That's either a deliberate/acceptable simplification (if this
particular map never grows large enough for balance to matter observably)
or a genuine correctness gap - I did NOT mark these tokens recovered,
since I have no caller-written confirmation the simplification is
intentional and safe, unlike the three cases above where the doxygen
explicitly walked through the equivalence. **Do not flip status on
pattern-match alone** ("looks like an absorbed RB-tree case") - require
either an explicit prior confirmation in the caller's own doxygen, or do
your own instruction-level trace proving the modern code's behavior
actually matches (rotation logic included, if the binary token's size/shape
suggests it has any - `FUN_00535250`/`FUN_00535400` are 142 instructions
each, plausibly a real rotate+fixup pass, not obviously "nothing").

## How to apply

Good technique for a "keep finding real progress" loop when the easy fresh
pool is dry: cheap to run, high signal-to-noise when it hits, but always
read the ABSORBING function's actual body before flipping status - the
grep only tells you someone THOUGHT it was absorbed at the time they wrote
the comment, not that the absorption is complete or correct.
