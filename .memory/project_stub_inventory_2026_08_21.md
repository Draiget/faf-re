---
name: project-stub-inventory-2026-08-21
description: "Tree-wide scan for address-annotated empty bodies: only 7 are genuine stubs; CreateMeshes is one and it is the gate on the whole UICommandGraph draw-node cluster"
metadata:
  node_type: project
---

Scanned 2026-08-21 (batch 33). Regex over every committed `src/sdk/**/*.cpp`
for a function carrying an `Address: 0x...` doc block whose body is empty or
comment-only.

## Numbers

- **2,796** raw matches -- but **2,616** are `moho/misc/WinApiImportThunks.cpp`,
  which are legitimately bodiless (`__imp_*` forwarders). Do not treat those as
  debt.
- **184** outside that file. Of those, **177 are benign**: the binary function
  really is empty (no-op virtuals, `noop_*` lanes, deliberately-empty
  overrides).
- 7 initially flagged, but **5 were false positives in my own scan** --
  **only 2 are genuine stubs**:

| file | address | verdict |
|---|---|---|
| `moho/sim/CWldSession.cpp` | 0x00828FB0 `UICommandGraph::CreateMeshes` | **genuine stub** |
| `moho/sim/CWldSession.cpp` | 0x008599D0 `CWldSession::RenderMeshPreviews` | **genuine stub** |
| `cri/sofdec/SofdecAdxPlatformRuntime.cpp` | 0x00B0E8A0/8C0/8D0/8E0 | false positive -- faithful |
| `cri/sofdec/SofdecAdxPlatformRuntime.cpp` | 0x00B0E880 | false positive -- has a real body |

The Sofdec ones matched because the word "stub" appears in comments
*describing* them ("Legacy effect getter stub lane"). Checked against the asm:
FUN_00B0E8C0/8D0/8E0 are a bare `retn`, FUN_00B0E8A0 is `xor eax,eax; retn`,
and FUN_00B0E880 has 4 real instructions and a real recovered body. Those are
correct 1:1 recoveries of genuinely-empty CRI middleware lanes, not debt.

**Real stub debt tree-wide is 2 functions.** If you re-run this scan, filter on
the *body* comment admitting incomplete work, not the doc block -- and confirm
against the asm before calling anything a stub.

## The one that matters: CreateMeshes (0x00828FB0)

`CWldSession.cpp:4855` -- the entire body is
`// Remaining command-graph mesh build pass (0x00829190 chain) is pending deep lift.`

This is the **elided-caller trap** ([[project-elided-caller-false-positives]]):
grep finds the `Address:` annotation and it reads as recovered.

It is the reason the whole UICommandGraph draw-node cluster has no landable
caller. In the binary CreateMeshes calls `sub_826BA0`
(`RecomputeAllDrawNodeOrientations`) at **0x00828FD3**; our body calls nothing.
So `FUN_00826BA0` (27 instrs), `FUN_008275B0` (`RecomputeDrawNodeOrientation`,
268 instrs) and `FUN_00826000` (`PrepareForRebuild`) would all be orphans if
committed -- which is exactly why a previous pass wrote them, build-gated them
clean, and then reverted them.

**Recovering CreateMeshes for real is the gate on that cluster.** Its own
remaining dependency is `FUN_00826740` (`RebuildCommandQueueNodes`), blocked on
the `UserCommandQueue` cross-TU visibility problem -- see the correction I added
to `decomp/recovery/reports/by-source/src/sdk/moho/sim/CWldSession.cpp.reconstruction.md`
(the report's "mechanical type swap" estimate for option 1 is wrong; the view is
a padded-offset overlay and the real class has typed nested members, so the ~23
field reads need semantic remapping, not renaming).

Per CLAUDE.md's no-stub rule neither of these empty bodies should have been
committed in the first place.

## Caveat learned the same batch

`decomp/recovery/recovered_progress.json` is **overwritten wholesale by
concurrent agents**. Two status marks I wrote were silently reverted within
minutes. Source commits survive; DB rows may not. Always re-grep `src/sdk` for
the address before trusting a `recovered` row.

## RESOLVED 2026-08-21 (batch 38/39) -- stub debt is now zero

Both genuine stubs were filled in by worktree agents:
`CWldSession::RenderMeshPreviews` (0x008599D0) in 09e912df, and
`UICommandGraph::CreateMeshes` (0x00828FB0) in f1b92ea5 -- the latter now
36 code lines calling `RebuildCommandQueueNodes()` and
`RecomputeAllDrawNodeOrientations()`, which is the `sub_826BA0` the binary
calls at 0x00828FD3. The draw-node cluster this gated is landed.

**Measurement gotcha when re-checking:** searching for `Address: 0x...` and
then taking the next `{` finds the *declaration's* doc block in files that
carry the class definition inline (CWldSession.cpp does). That made both
functions look like 1-line stubs on a re-check. Anchor on the definition
(`void Class::Name(...)` followed by `{`) instead.
