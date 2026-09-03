---
name: project_playablerectupdates_never_populated
description: SSyncData::mPlayableRectUpdates (SimDriver.h +0x230) is read at exactly one site (CWldSession.cpp:16025, driving IWldTerrainRes::NotifyMapChange -> Finalize -> InitNormalMap) but is never written anywhere in src/sdk. Real population site not yet found; CWldSession.cpp is locked, defer the fix.
metadata:
  type: project
---

## Context

Found while re-investigating whether `CWldTerrainRes::Finalize`/`InitNormalMap`
(the terrain-normal-map init path documented as possibly-orphaned in
[[project_session_runs_full_skirmish_display_blocked]]) is really unreachable.
It turned out NOT to be a pure orphan — `IWldTerrainRes::NotifyMapChange`
(`CWldMap.cpp:3944`, real address `0x008A5730`) does call `Finalize()`
conditionally, and `NotifyMapChange` itself IS called, from
`CWldSession::DoBeat` (`CWldSession.cpp:16025`):

```cpp
for (const gpg::Rect2i& playableRect : beat.mPlayableRectUpdates) {
  terrainRes->NotifyMapChange(playableRect);
}
```

Both `Finalize` (`FUN_008A2DD0`) and `NotifyMapChange` (`FUN_008A5730`) were
confirmed via the callgraph index (`incoming_xrefs` table) to have exactly
ONE incoming xref each: a `data` xref from their own vtable slot
(`??_7CWldTerrainRes@Moho@@6B@`). No direct call site exists in the binary
for either — both are genuinely only reachable through virtual dispatch,
and the `NotifyMapChange` call above IS that dispatch site, correctly
modeled. So this part of the recovery is right.

## The actual gap

`SSyncData::mPlayableRectUpdates` (`SimDriver.h:212`, `msvc8::vector<gpg::
Rect2i>`, offset `+0x230`, static_assert present) is read at the ONE site
above and **written nowhere** — grepped the whole `src/sdk` tree for
`mPlayableRectUpdates` and only the read site and the two layout
declarations exist. So the loop body never executes for any beat, on any
map, ever, and `Finalize`/`InitNormalMap` never fire through this path.

This is NOT necessarily a recovery bug — `mPlayableRectUpdates` may
legitimately be empty for most ordinary skirmish maps (it looks like an
INCREMENTAL update mechanism, e.g. for the map editor changing playable
bounds live) rather than something that fires once at load. Traced where
the playable rect actually gets SET, to find whether the setter should
also be enqueuing an update:

- `STIMap::SetPlayableMapRect` (`STIMap.cpp:3233`, real address
  `0x00577DF0`) is the terminal setter — clamps to heightfield bounds and
  stores into `mPlayableRect`. Read in full: it does **not** touch any
  sync queue, and this matches its own cited ground truth exactly (a
  faithful recovery, not a bug).
- Three call sites reach it: `Sim.cpp:7854`, `Sim.cpp:13237` (both look
  like internal Sim-side calls, not yet traced to their own callers), and
  `Sim.cpp:24211` inside `cfunc_SetPlayableRectL` (`FUN_0075C830`) — a
  **Lua-callable** function (`SetPlayableRect(minX,minZ,maxX,maxZ)`),
  meaning ordinary maps that never call this from their script would
  never touch the setter at all.
- `IWldTerrainRes::SetPlayableMapRect` (`CWldMap.cpp:2507`, address
  `0x008A6DA0`, the terrain-res VIRTUAL wrapper one level up, called from
  `CWldSession.cpp:12134`) also just delegates and warns on failure — no
  sync-queue touch either, and this ALSO has only a data xref from its own
  vtable (checked) — so this specific virtual wrapper is real but not
  where the queueing should happen either.

**Not yet found**: the actual producer of `mPlayableRectUpdates` entries.
Given the sibling pattern in `Entity.cpp:354` (`syncData->mNewEntities.
push_back(params)` — a function that takes an explicit `SSyncData*
syncData` parameter and pushes into it directly, imperative/event-driven,
not diff-based), the real mechanism is probably a similar direct-push
somewhere in the beat-building path that our recovery hasn't modeled yet
— OR the terrain-normal init for the COMMON (non-dynamic-playable-rect)
case happens through a completely different, not-yet-identified mechanism
entirely (e.g. baked/loaded directly during `CWldTerrainRes::Load` rather
than computed via `Finalize`/`InitNormalMap` at all), which would make
this whole `mPlayableRectUpdates` thread a red herring for the "why is
terrain sometimes dark" question specifically.

## Why not resolved this pass

`CWldSession.cpp` (where the beat-building / `SSyncData` construction
lives) is locked by a concurrent session as of this writing. The
DECISIVE way to settle "is this the real remaining terrain-lighting gap or
a red herring" is empirical, not more static tracing: run a fresh dbgrun
session with a temp `[INITNM]`-style probe at the top of `InitNormalMap`
(see [[project_session_runs_full_skirmish_display_blocked]] for the
probe's prior incarnation) against the CURRENT head (which now includes
the full heap-corruption fix chain and reaches genuine in-game state
reliably, confirmed in
[[project_commander_spawn_goal_synthesis_2026_09_02]]) — if terrain
renders with correct lighting/normals on a fresh run, this entire thread
is moot and can be closed without further investigation; if it's still
dark, resume here with `CWldSession.cpp` unlocked and trace where
`SSyncData` gets built (search for what constructs the `beat`/`SSyncData`
object passed through `CWldSession::DoBeat`'s caller chain,
`CDecoder::DecodeAdvance` / `CClientManagerImpl::UpdateStates` per
[[project_commander_spawn_script_class_resolution_gap]]'s crash-chain
trace) to find where a `PushBack` onto `mPlayableRectUpdates` is missing.

Low priority relative to the main goal: even if genuinely broken, this
only affects normal-map-driven terrain lighting quality on maps with
near-zero ambient light (like SCMP_009's own SunAmbience=0,0,0), not
whether the commander spawns or the game runs. The two live screenshots in
[[project_commander_spawn_goal_synthesis_2026_09_02]] show ordinary green
terrain (not black/dead), so if this gap is real its practical impact may
already be minor or map-specific.

## Narrowed 2026-09-02 — it is NOT "the terrain has no playable rect"

`STIMap::mPlayableRect` **is** populated, at map init: `STIMap.cpp:3134-3137`
and `:3183-3186` seed it to the full heightfield, and `:3280+` sets an explicit
rect. Fifteen-plus readers across camera, motion, UI and unit code rely on it
and are fine. So the dead lane is only the **sync/update** path
(`SSyncData::mPlayableRectUpdates`, +0x230), i.e. "the playable area *changed*
mid-game", not the initial value.

That matters because it means `normalMapCount=0` is **not** explained by a
missing playable rect. `NotifyMapChange -> Finalize -> InitNormalMap` simply
never gets driven, so the normal map is never built even though the rect it
would use is valid. Look for the real `InitNormalMap` trigger on the terrain
load path instead of chasing the sync lane.

Compare [[project_canipose_empty_bones_hid_every_unit]]: the sibling lane
`mPoseUpdates` looked like the same "never written" bug and turned out to be a
red herring too — units replicate their pose through
`mUnitVarDat.mSharedPose`, not through that lane. Two for two: on this struct,
"read but never written" has meant "this is the rare mid-game update path",
not "the feature is broken".

### And the trigger is NOT missing either

`InitNormalMap` is called directly on the terrain **load** path -
`CWldMap.cpp:3079` and `:5037` - not only from
`NotifyMapChange`/`CWldSession.cpp:16026`. So `normalMapCount=0` cannot be
blamed on a missing trigger at all: the load path calls it, and the playable
rect it reads is valid. The defect is **inside** `InitNormalMap`
(`0x008A54D0`) or in the inputs it reads. That is where to look next; both
sites are in `CWldMap.cpp`, which was peer-locked on 2026-09-02.
