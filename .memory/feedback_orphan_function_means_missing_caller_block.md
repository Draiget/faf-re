---
name: feedback_orphan_function_means_missing_caller_block
description: A recovered function with zero src callers usually means a whole block is missing from its caller, not that a function is missing - three real bugs found this way on 2026-09-03
metadata:
  type: feedback
---

The highest-yield audit in this project is not "what is unrecovered" but **"what
is recovered and never called"**. Three separate runtime defects on 2026-09-03
were all found this way, and in every case the fix was to restore a *block in
the caller*, not to write a new function.

| Orphan | What was actually missing | Commit |
|---|---|---|
| `IWldTerrainRes::Finalize` | the lazy dispatch in `WRenViewport::Render` | `220b2c48` |
| `Clutter::UpdateCurrent` / `GenerateNew` | the per-frame refresh block in `WRenViewport::Render` | `a444d83d` |
| `CUserSoundManager::StartEntityLoop` / `StartRPCEntityLoop` | the **entire third pass** of `UpdateSoundRequests` | `bf134d98` |

That last one is the pattern at its clearest: a 2830-byte function was recovered
up to 0x008AC9CE and simply stopped, and the ~500 bytes after it were the only
code in the engine that ever *starts* a sound loop. Nothing was flagged --
`tucheck` was clean, the build linked, the two callees existed and looked
finished. Only "who calls these?" surfaced it.

**The scan** (cheap, ~2 min, whole tree):

```python
# 1. collect Class::Method definitions from src/sdk/**/*.cpp
# 2. count occurrences of each bare method name across all of src/sdk
# 3. anything with count <= 2 (its declaration + its definition) is an orphan
```

Then, for each orphan, find its caller in the binary
(`FUN_*.xrefs.txt` / `grep -l '<mangled>' *.asm`) and check whether the
corresponding **region** of that caller exists in our source. Compare the
caller's own length first: `function_end - function_start` in the `.asm` header
against the recovered body. A recovered function noticeably shorter than its
binary is where to look.

**Complementary scan — per-function call diff:**

```bash
grep -oE "call +[A-Za-z_?][A-Za-z0-9_?@$:.]*" FUN_XXXXXXXX.asm | sed 's/call *//' | sort -u
```

then check each symbol appears in that function's recovered body. On
`WRenViewport::Render` this found two real gaps out of ~40 symbols. Run it on
the *big per-frame and per-tick keystones* — that is where a missing block costs
the most and hides the best.

**Both scans are noisy in the same way**: our recovery renames things. Confirmed
false positives from one afternoon -- `CMersenneTwister::IRand` → `NextUInt32`,
`CAnimTexture::GetFrame` → `GetFrameAt`, `Entity::SetCollisionShapeNone` →
`RevertCollisionShape`, `WRenViewport::RenderShadows` → `Shadow::
RenderFrameShadows`. Always read the recovered body before concluding a gap.
Also beware LTCG: argument order on the stack does **not** follow the declared
order, so a "swapped parameters" finding needs the callsite read too.

Related: [[project_terrain_finalize_had_no_caller]],
[[feedback_force_link_unresolved_audit_finds_real_crashes]],
[[project_orphan_debt_is_9890_functions]].
