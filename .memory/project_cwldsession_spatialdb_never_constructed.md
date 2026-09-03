---
name: project_cwldsession_spatialdb_never_constructed
description: BOTH gaps FIXED 2026-09-01 (6c5b4345 + c819a396), NOT yet runtime-verified — CWldSession's own entity spatial database (mSpatialDB/mEntitySpatialDbStorage) and the global MeshRenderer singleton's own spatial db were both left unsized/unconstructed relative to the current map. Used by 4+ consumer call sites (spatial queries for units/props/projectiles).
metadata:
  type: project
---

# `CWldSession::mSpatialDB` was never constructed — FIXED, commit `6c5b4345`

**Landed, tucheck-clean, NOT yet runtime-verified** (no live dbgrun access
at fix time — next session/whoever has the machine should confirm a
spatial query, e.g. an area-effect weapon or box-select, returns real
results post-fix instead of the previous zeroed-object behavior, and that
constructing it doesn't itself crash on the very first session created).

The two open questions this file originally flagged were both resolved by
reading further into the same ground truth (see the dated section below for
the full trace): the destination field (`&this->mSpatialDB`, confirmed by
IDA's own field-name rendering, not a guess) and the argument order
(`ResizeStorageForMap(width, height)`'s own ground-truth signature literally
names its parameters `width`/`height` in that order — matching a normal
call `ResizeStorageForMap(realWidth, realHeight)`, regardless of which
physical register ground truth's `0x00501F50` binds them to internally).
Also settled: ground truth's single call here never touches
`SpatialShardData`, so no separate `InitializeStorage()` call was needed —
one `ResizeStorageForMap` call, immediately after the existing `memset`, is
the complete, faithful construction.

**Second gap also closed, same pass, commit `c819a396`**:
`MeshRenderer::GetInstance()->bd`'s own resize (`create 5`->`create 6`,
lines 324-326) turned out to be even lower-risk than the first — the
target function was already fully recovered under a real, non-orphan-looking
name, `MeshRenderer::UpdateMapSize(width, height)` (`Mesh.cpp:5992`, address
`0x007DF510`), just never called from anywhere (`grep` confirmed zero
callers in `src/sdk` before this fix). `MeshRenderer::MeshRenderer()`'s own
constructor already correctly calls `meshSpatialDb.InitializeStorage()`
(the no-arg `0x00501D80` overload) — this fix adds the missing per-session
resize on top of that already-correct initial construction.

## Original diagnostic trace (kept for the evidence trail)

Found 2026-09-01 (faf-main-f7) while reviewing `CWldSession::CWldSession`'s
"partial lift" comment (peer `faf-main-2c` flagged this constructor as a
known partial lift after finding the missing `VisionDB::Init` call, commit
`0d4a51e1` — this is the SAME investigation, one level deeper).

## The gap

`CWldSession.cpp:14336` (inside the constructor, right after the
`VisionDB::Init` call peer added):

```cpp
std::memset(mEntitySpatialDbStorage, 0, sizeof(mEntitySpatialDbStorage));
// mBuildTemplates ... comment ...
```

`mEntitySpatialDbStorage` is `std::uint8_t[0xA0]` (`CWldSession.h:1435`,
160 bytes) — raw storage for one `SpatialDB_MeshInstance`, reinterpreted by
every consumer via `reinterpret_cast<SpatialDB_MeshInstance*>(&...)` /
`static_cast<SpatialDB_MeshInstance*>(GetEntitySpatialDbStorage())`
(`CWldSession.cpp:6265`, `11387`, `16147`, `20156` — 4+ real consumer call
sites, all doing spatial queries: collecting units/props/projectiles in a
volume/box/sphere/view). **The `memset` is the ONLY thing that ever touches
this storage in our recovered constructor — the actual `SpatialDB_MeshInstance`
object is never constructed, never sized to the map, just left as zero
bytes reinterpreted as if it were a live object.**

## Ground truth confirms a real construction call is missing

`FUN_00893160.c` (the constructor's ground truth), right after the
`VisionDB::Init` call (line 317):

```c
Instance = Moho::MeshRenderer::GetInstance();
v40 = this->mWldMap->mTerrainRes->mMap->mHeightField.field;
Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(v40->height - 1, &Instance->bd, v40->width - 1);
```

That specific call (line 326) constructs `MeshRenderer::GetInstance()->bd`
(the GLOBAL MeshRenderer singleton's OWN spatial db) — a SEPARATE,
SECOND construction, distinct from the session's own.

**UPDATE, same pass: the session's OWN construction site IS unambiguous —
already present in the excerpt above, just under-emphasized on first
read.** `FUN_00893160.c:300-304`, between the ` CWldSession create 3`
(line 297) and ` CWldSession create 4` (line 308) log markers:

```c
mMap = this->mWldMap->mTerrainRes->mMap;
Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(
  mMap->mHeightField.field->height - 1,
  &this->mSpatialDB,
  mMap->mHeightField.field->width - 1);
```

IDA's decompile explicitly names the destination `&this->mSpatialDB` — not
an offset guess, a real field reference. **So there are genuinely TWO
separate missing constructions**, not an ambiguous single one:
1. `this->mSpatialDB` (the session's own, at `create 3`->`create 4`,
   `CWldSession.cpp`'s `mEntitySpatialDbStorage` field) — this is the one
   this file is about.
2. `MeshRenderer::GetInstance()->bd` (the global singleton's own, at
   `create 5`->`create 6`) — a separate gap, likely in whatever file
   `MeshRenderer`'s own construction/setup lives in; not investigated
   further this pass, don't conflate its fix with this one.

**New open question this surfaced, NOT yet resolved — argument order.**
The ground-truth call above passes `(height-1, &this->mSpatialDB, width-1)`
in that literal left-to-right position — IDA's pseudocode sometimes renders
a `__thiscall`'s implicit `this` in the middle of the visible argument list
rather than always as a hidden receiver, so this could mean either
"`this=&mSpatialDB`, real params `(height-1, width-1)`" (HEIGHT first) or a
different binding entirely. Our already-recovered
`ResizeStorageForMap(width, height)` (`Mesh.cpp:4161`) assumes WIDTH first
— if that ordering was independently verified against `0x00501F50`'s own
`.asm` when THAT function was originally recovered (not confirmed either
way this pass), trust it over the call-site pseudocode's left-to-right
rendering; if not, re-derive the real parameter binding from
`0x00501F50`'s own disassembly (register/stack argument order) before
wiring up the call, not from this call site's IDA rendering alone. Getting
this backwards would size the shard grid with width/height swapped —
plausible, silent, hard-to-notice corruption of every spatial query on a
non-square map.

Definitely missing regardless of the argument-order question: our recovered
constructor has **zero** calls to anything `SpatialDB`-shaped after the
`memset`, and ground truth has two (session's own + the global
MeshRenderer's) that we don't have at all.

## The real constructor bodies already exist, just under non-constructor names

Confirmed via the callgraph index (`_callgraph_index.sqlite`,
`functions.demangled_name`): **both** `FUN_00501D80` and `FUN_00501F50` are
literally `Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance` (two
overloads) in the real binary. Our recovery already has both bodies —
just modeled as regular methods, not constructors:

- `FUN_00501D80` -> `SpatialDB_MeshInstance::InitializeStorage()`
  (`Mesh.cpp:4100`) -> `InitializeSpatialDbMeshStorage(storage)`
  (`Mesh.cpp:2627`): zeroes the shard-vector lanes, **placement-constructs
  `storage.shardData` via `new (&storage.shardData) moho::SpatialShardData
  (nullptr)`** (a REAL C++ object construction, not something `memset` can
  substitute for), zeroes map/shard dimensions, seeds an empty map-tree
  sentinel.
- `FUN_00501F50` -> `SpatialDB_MeshInstance::ResizeStorageForMap(width,
  height)` (`Mesh.cpp:4161`) -> `UpdateSpatialDbMeshStorageMapSize(storage,
  width, height)` (`Mesh.cpp:2681`): early-exits if
  `width == storage.mapWidth && height == storage.mapHeight` (a **stale-read
  guard that only makes sense if `mapWidth`/`mapHeight` already hold a
  meaningful prior value** — i.e. this function alone is not a safe
  from-scratch constructor; it assumes `InitializeStorage()` — or an
  equivalent — already ran), then rebuilds the top-level shard array sized
  to the new map dimensions.

There's also an existing, already-recovered, currently-ORPHANED
(`[[maybe_unused]]`) placement-new adapter: `ConstructSpatialDbMeshInstanceAdapter`
(`Mesh.cpp:4113`, address `0x007E2AA0`): `return ::new (storage)
SpatialDB_MeshInstance();` — confirms the "placement-new into caller
storage" pattern is the right shape, but this specific adapter calls the
**no-arg** constructor (unclear which of the two real constructors that
maps to, or whether it's a third, distinct compiled body not yet checked)
and isn't wired to any caller either — a second, related orphan, don't
conflate its fix with this one without checking its own callers separately.

## Why this was NOT fixed this pass, deliberately

Two genuine open questions, not resolved with confidence:

1. **Whether `SpatialDB_MeshInstance` needs formal C++ object construction
   at all**, or whether this codebase's established convention for this
   exact storage field is "reinterpret raw bytes, no object lifetime" (every
   consumer already does a bare `reinterpret_cast`/`static_cast`, never a
   `std::launder` or anything implying formal lifetime tracking matters
   here). If the convention really is "just call the init methods on the
   reinterpreted bytes, no placement-new needed," the fix is:
   ```cpp
   std::memset(mEntitySpatialDbStorage, 0, sizeof(mEntitySpatialDbStorage));
   GetEntitySpatialDbStorage()->InitializeStorage();          // or mSpatialDB., check accessor name
   GetEntitySpatialDbStorage()->ResizeStorageForMap(width, height);
   ```
   matching the `memset`-then-`InitializeStorage()`-then-`ResizeStorageForMap()`
   order this note's own tracing supports, using ONLY already-recovered,
   already-correct functions — no new low-level logic needed. This is the
   most likely correct fix, but "most likely" is doing real work in that
   sentence.
2. **Which exact field(s) in the `FUN_00893160.c` ` CWldSession create 3/4/5`
   sequence correspond to `this->mSpatialDB` vs `this->mVisionDB` vs
   `MeshRenderer::GetInstance()->bd`** — not fully disambiguated (see above).
   Landing a fix for the wrong field, or missing that TWO fields need
   construction here (session's own + the global MeshRenderer singleton's),
   would be worse than not landing anything.

Given the STAKES (a widely-consumed subsystem — 4+ real spatial-query call
sites already found, likely more; getting this wrong risks a subtler bug
than the one being fixed) and that this project has burned real sessions on
overconfident "obviously correct" fixes to under-verified layouts before,
this was deliberately left as a documented, precisely-scoped next step
rather than a rushed commit.

## Next step if resuming

**Runtime-verify `6c5b4345` + `c819a396`** — fresh `/map SCMP_009` run,
confirm the session constructs cleanly (no new crash at session-start) and
a real spatial query returns non-empty results where it previously
wouldn't have (hard to observe directly without a targeted probe; the
previous "reads a zeroed object" state may not have crashed outright —
`db`/`entry`-shaped zeroed fields could plausibly have just made every
query silently return empty rather than fault, so "no crash" alone doesn't
confirm the fix did anything — a probe logging `CollectInBox`'s/
`CollectInVolume`'s return count before and after is the reliable check).
Both gaps this file tracked are now landed; nothing else outstanding here.

Not confirmed to be related to the `PopLaneNode` allocator-corruption thread
peer is chasing — this is an independent finding from reading the
constructor's own ground truth, not from the allocator instrumentation or
wild-free sweep.
