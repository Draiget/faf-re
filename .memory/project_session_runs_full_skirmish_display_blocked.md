---
name: project-session-runs-full-skirmish-display-blocked
description: SUPERSEDED DISPLAY THEORY, 2026-09-01 - the real blocker is a heap use-after-free that kills the sim thread ~49s in. The UI is fine; the allocator's free-side is byte-faithful. "768-byte block, kind=25" is RETRACTED as the corrupted resource - see the 2026-09-01-later update: it's the ThreadHeapCache (0x214=532 bytes) being recycled to a second owner while still live, observed at lanes[25].head (offset 0x12C). Live DR0 watchpoint on that field in flight; a static audit of the allocator's region-carving side (AllocateSmallBlocksAmount/SplitHeapRecord/AllocateFreeRegion/PushHeapBlock) also in flight.
metadata:
  type: project
---

# RESOLVED: it was a raw `operator delete[]` vs array cookie (commit 3cd159aa)

**The heap corruption is fixed and the HUD now renders.** Everything below this
section is the hunt that got here; keep it for method, but the answer is:

`ClearWeaponInfoVectorAndRebindInline` (Unit.cpp) freed the weapon-info
fastvector's heap buffer with `::operator delete[](vec.start_)` — the raw
deallocation FUNCTION. `FastVectorN::GrowToCapacity` allocates it with
`new T[newCap]` (FastVector.h:1849) and `UnitWeaponInfo` has a non-trivial
destructor, so MSVC prefixes a 4-byte element-count cookie and `new T[]` hands
back **base+4**. The `delete[] p` EXPRESSION subtracts that cookie; calling
`::operator delete[]` directly does not. So free() got base+4.

Why that was catastrophic rather than a leak: `GetPageOwner(base+4)` still
resolves (same page, same record), so `free` ran `PushLaneNode(lane, base+4)`,
writing a `next` link at base+4 and putting a misaligned interior pointer on the
768-byte lane. It was handed out later as a block **overlapping the real one** —
two owners, one buffer — which is how packed-int garbage ended up inside a live
Proto's `locvars`.

Result after the fix, same `/map SCMP_009`: `[BADFREE]` 0, `[LOCVARBAD]` 0, no
second-chance fault, Game time advancing, and the in-game UI at
`visited=603 peak=603 ticked=7`. A PrintWindow capture shows the real HUD —
resource bars (650 mass / 3900 energy, i.e. the ACU's starting storage, so the
commander IS spawned), command panel, build menu, minimap frame.

**Still open:** the 3D world viewport renders flat dark — terrain and units are
not drawn. The UI layer draws fine, so this is a world/terrain render problem,
not the UI path.

### RESOLVED PART 2: terrain under-tessellation (commit 38a7af10)

`ren_maxViewError` carried a fabricated `1.0f` placeholder; the shipped binary's
value is **0.003f** (referenced at 0x0080E1B9 `mulss xmm2,
?ren_maxViewError@Moho@@3MA` -> VA 0x00F57DB0 -> file offset 0xB57DB0 in
bin/2025.7.1/ForgedAlliance.exe). `CTesselator::GetIntersectionResult` does
`maxAllowedError = shoreErrorCoeff * projectedDepth * ren_maxViewError` and
accepts when `tierMaxError < maxAllowedError`. At 1.0 with a camera ~900 units
out the threshold was ~900, which no tier error exceeds, so EVERY node accepted:

    before: rectCacheCount=122  mSkirtStartIndex=6      (2 triangles, whole map)
    after:  rectCacheCount=2619 mSkirtStartIndex=10713  (3571 triangles)

Audited the rest of RuntimeTuningGlobals.cpp against the PE at the same time:
all 21 address-annotated globals match. **41 are un-annotated and therefore
unverified** — that is where this placeholder hid, so treat the un-annotated
ones as suspect.

### THE REMAINING DEFECT IS THE TERRAIN NORMAL / DIFFUSE TERM

SCMP_009's ambient really is zero — read byte-for-byte out of its own .scmap
lighting block at file offset 0x2411CC:

    1.5400                  LightingMultiplier   (we read 1.540)
    0.6161 0.5592 0.5547    SunDirection         (we read 0.616,0.559,0.555)
    0.0000 0.0000 0.0000    SunAmbience          (we read 0,0,0)
    1.3800 1.2900 1.1400    SunColor             (we read 1.380,1.290,1.140)
    0.5400 0.5400 0.7000    ShadowFillColor

So the map-lighting load is CORRECT and this map is lit ENTIRELY by diffuse
N.L. Forcing `sunAmbience` to 0.5 makes **real, fully-textured terrain appear**
(screenshot-verified) — which proves geometry, albedo, texturing, technique and
the draw call are all fine, and the normal basis is what is dead.

### ROOT CAUSE FOUND: `CWldTerrainRes::Finalize` is an ORPHAN

Full causal chain, every link measured live:

1. `IWldTerrainRes::Finalize()` (CWldMap.cpp:4985, binary FUN_008A2DD0) calls
   `InitNormalMap(loadControl)` — and **nothing in `src/sdk` ever calls
   Finalize**. `grep "Finalize()"` across `src/sdk/moho` returns only unrelated
   string-builder/audio hits. It is virtual (`?Finalize@CWldTerrainRes@Moho@@UAE_NXZ`)
   and its ONLY incoming xref in the callgraph index is a **data** ref from the
   vtable at 0x00E4BD54 — no direct callers, so it is dispatched from a site we
   have not wired.
2. The other caller of `InitNormalMap` in the binary is
   `CWldTerrainRes::Reset` (FUN_008A6220), which we DO have — but our only call
   to it is from `CWldMap::MapNew`, the **editor's new-map path**. On a normal
   `/map` load neither path runs. (Confirmed: an `[INITNM]` probe at the top of
   InitNormalMap never fires.)
3. -> `GetNormalMapCount()` returns 0 (it returns 0 when
   `mNormalMap.mBegin == nullptr`, and nothing else populates that array —
   only null-init at CWldMap.cpp:1397 and teardown at 1513).
4. -> `HighFidelityTerrain::DrawTerrainNormal`'s `TTerrainBasis` tile loop
   (`for tile < normalMapCount`) never executes. Probe: `[NORMALMAPDIAG]
   normalMapCount=0`.
5. -> the normals target keeps B/A at 0. Dump confirms avg RGB (69,69,**0**).
6. -> `frame.fx`'s `BasisPS` does `float4 raw = tex2D(FrameSampler1,Tex1)*2-1;
   baseNormal.xz = raw.zw; baseNormal.y = sqrt(1-x*x-z*z);` — with blue 0,
   `raw.z == -1`, so `baseNormal.y = sqrt(negative)`.
7. -> `TCreateBasis` emits a constant (dump: pure green (0,255,0) over the whole
   screen).
8. -> terrain N.L is dead, and SCMP_009's ambient is genuinely 0, so terrain
   shades to near-black.

Places already checked for the dispatch and RULED OUT (none call Finalize, in
our source or in their binary decompiles): `CWldMap::MapLoad` (FUN_00890DA0),
`CWldTerrainRes::Load` (FUN_008A1700), `func_WorldSessionUserLoad`
(FUN_00885DE0), and the render-side terrain sources. `Finalize` is vtable index
74 (`?Finalize@CWldTerrainRes@Moho@@UAE_NXZ`) and IDA resolves no direct
dispatch anywhere, so it is reached through an indirect call the export did not
attribute — run `audit_indirect_calls.py` for it rather than grepping.

**The fix is to find and wire Finalize's real dispatch site on the map-load
path.** Neither `CWldMap::MapLoad` (FUN_00890DA0) nor `CWldTerrainRes::Load`
(FUN_008A1700) calls it in the binary, so look upstream in world-session setup
(`CWldSession` / `WLD_*` / the render-side terrain creation) for the virtual
call through the IWldTerrainRes vtable slot holding 0x008A2DD0. Use
`audit_indirect_calls.py` if a plain grep does not find it.

**Both basis targets dumped and inspected** (dump them AS-IS via
`ID3DDeviceResources::Func10` + `DeviceD3D9::Func5`; do NOT use
`REN_MaybeDumpFrame`, which copies the screen over its target first):

- `mSecondaryTargetLocks[head]` (raw normals): renders the **entire terrain
  correctly** — full map, correct perspective, visible relief — but in olive,
  avg RGB **(69,69,0)**. R==G and **blue is exactly 0**, i.e. the encoded
  normal's Z component is dead. This image is also positive proof that
  tessellation, camera and geometry are all correct after 38a7af10.
- `mPrimaryTargetLocks[head]` (TCreateBasis output, the texture the composite
  actually samples): near-constant pure green, avg RGB **(26,255,26)**, covering
  the WHOLE screen including outside the terrain. A degenerate constant, not a
  computed basis.

So the defect is the terrain normal encoding / TCreateBasis pass, and nothing
downstream of it. Start there, not at the draw call.

The basis chain is wired correctly and does run:

    [BASISDIAG] head=0 src(secondary)=07784168 dst(primary)=07784140 size=1024x768
    [COMPDIAG] RenderCompositeTerrain head=0 drewNormals=1 target=07784140

i.e. `RenderTerrainNormals` -> `DrawTerrainNormal` writes normals into
`mSecondaryTargetLocks[head]`, `TransformTerrainNormals` runs TCreateBasis from
secondary into `mPrimaryTargetLocks[head]`, and the composite samples that exact
primary pointer. Pointers match; the CONTENT is the open question. Next step is
to dump `mSecondaryTargetLocks[head]` and `mPrimaryTargetLocks[head]` and look
at them (the engine's own `REN_MaybeDumpFrame` can be pointed at either).

### The whole terrain pipeline measures HEALTHY — ruled out, do not re-audit

Measured in-session (Game time 13:55+), all via `gpg::Warnf` into the `.sclog`
so they can be compared against each other:

    [TERRDIAG-HIGH] rectCacheCount=128 collisionIndexCount=138
    [TERRDIAG-HIGH] rectCacheCount=122 collisionIndexCount=132
    [COMPDIAG] RenderCompositeTerrain head=0 drewNormals=1 target=078AB028 shadowCtx=046734F0
    [CARTODIAG] REN_RenderCartographic drew=0 head=0

So: the tessellator produces real geometry (NOT the old cap-saturated
regression, NOT zero), the vertex-buffer upload runs, `RenderCompositeTerrain`
is reached, `DrawNormals` **returns 1**, the render target and shadow context
are both bound, and the cartographic overlay draws nothing (so it is not
covering the screen). `SetColorWriteState(true, false)` maps to
`colorWriteEnable_ = 0x07` (RGB on) — colour writes are enabled. Shaders all
compile (`terrain.fx`, `mesh.fx`, `sky.fx`). Textures load (1418 batch
textures). Our `Render` tail is faithful to the binary: RenderCartographic ->
DrawUI -> DoBloom -> RenderUI -> `EndScene` (vtable slot 34) ->
`REN_MaybeDumpFrame`.

### It is NOT presentation, DPI, or the window capture

Armed the engine's own frame dumper (`dump_frameRate`/`dump_frameDumpName`,
consumed by `REN_MaybeDumpFrame`) and dumped in-session frames straight from the
render target. The BMP shows **the same flat viewport with the HUD over it** —
so the renderer genuinely produces this image. That rules out the DPI compat
shim, DWM, PrintWindow, and any present/composite theory.

Caveat learned the hard way: arm the dump LATE (I gate on a Render-call counter
> 4000). Armed at the first Render call it captures the Cybran loading screen,
which looks like a dramatic finding and is just the loading phase.

So the remaining question is narrow: the terrain draw call succeeds with valid
geometry, a valid camera, colour writes on and textures loaded, yet produces no
visible pixels. Next candidates are render STATE rather than data — depth/Z
state rejecting the draw, vertex declaration/stream binding, or the shader
constants for the terrain technique.

What is already ruled out on that, probe-measured in one run:

    [WORLDDIAG] terrain=5F626000 ren_Terrain=1 view=5C85511C skyDome=1 water=1
    [SKYDIAG] 1 enter / 2 CreateRenderAbility ok / 3 RenderAtmosphere ok
              4 RenderDecals ok / 5 RenderCirrus ok / 6 RenderCumulus ok

So the per-view world pass DOES execute, `worldView->terrain` is non-null, the
`ren_Terrain`/`ren_SkyDome`/`ren_Water` flags are all true, and `RenderSkyDome`
runs to completion without throwing. The failure is further in — the terrain /
mesh draw runs with valid inputs and still puts nothing on screen.

The camera is also healthy — measured in-game (Game time 03:44) on SCMP_009:

    [WORLDDIAG] terrain=5F4FE000 ren_Terrain=1 view=5C78121C
                camPos=(512.0,757.3,938.6) viewFwd=(0.00,0.87,0.50) zoom=854.2

Map centre, sensible altitude, looking down-forward. So camera placement /
orientation is NOT the cause, and neither is the DPI compat shim (my harness
launches `C:\ProgramData\FAForever\bin\main.exe`, the exact path the
`~ HIGHDPIAWARE` shim is keyed to, and PrintWindow reports `nonblack
12821/13493` — 95% of the window is drawing). Next datum to get is
`rectCacheCount` at HighFidelityTerrain.cpp:826 (and the Medium/Low equivalents
at MediumFidelityTerrain.cpp:1705 / LowFidelityTerrain.cpp:1170) — that is the
real geometry-to-GPU path and the exact quantity that regressed before
(cap-saturated vs a healthy ~20). See
[[project_2026_08_31_ui_fully_works_3d_viewport_still_black]] for the full prior
render investigation, including the `DotMatrixRows` keystone fix a15c5cc8.

**Run-viability warning:** instrumenting the allocator on EVERY malloc/free
(the `[WINDOW]` probe) slows the process so much under dbgrun that most runs
never reach gameplay before the hang timeout. Only trust a run that reports a
`Game time`; keep per-operation probes out of the build when you need the game
to actually start.

**Methodological warning that cost me an hour here:** `[MMDIAG]` is emitted with
`gpg::Warnf` and lands in `bin/<name>.sclog`, while `OutputDebugStringA` probes
land in the dbgrun stdout log. The two sinks flush differently, so counting a
Warnf probe in one file against an OutputDebugString probe in the other produced
a completely false "RenderSkyDome never returns" conclusion. **Always compare
probes within a single sink.**

### The reusable lesson

Grep for `::operator delete[](` / `::operator delete(` called directly on
anything allocated with `new T[...]`. Whenever T has a non-trivial destructor
that pair is a guaranteed +4 wild free, and it is INVISIBLE to a grep for
pointer arithmetic — the offset is added by the compiler, not by the source.
The inverse (raw `::operator new[]` freed with a `delete[]` expression) is the
same bug mirrored.

# (historical) The blocker is a heap UAF, not the display

Earlier reading in this file said the faction loading movie/texture covered the
viewport. **That was wrong** and cost a lot of time. What actually happens is
that the process **crashes**, and the last presented frame is the loading
screen. Do not re-derive the display theory.

## What is actually true (instrumented, clean build, no probes altering behaviour)

The UI works. A `[FRAMEDIAG]` probe in `CMauiFrame::Frame` proved:

    call=1803 frame=07F8C300 visited=4  peak=4  ticked=2   <- loading dialog
    StopLoadingDialog: before RunScript
    StopLoadingDialog: after RunScript
    call=2404 frame=08066680 visited=34 peak=34 ticked=1   <- in-game UI, ticking

So the per-frame walk runs at 60fps, `StopLoadingDialog` dispatches and returns,
`CreateGameInterface` completes, and the client declares ready. A **second**
frame (different pointer) carries the in-game UI.

Then it dies:

    ACCESS_VIOLATION 2nd-chance, read from 00000178
    #00 PopLaneNode+0x21     Global.cpp:281      <- lane.head was 0x178
    #01 malloc_0+0x154
    #02 realloc_0 -> luaHelper_ReallocFunction -> luaM_realloc
    #05 luaD_growstack -> luaD_precall -> luaV_execute -> resume -> lua_resume
    #10 CLuaTask::Execute -> CTaskStage::UserFrame -> Sim::AdvanceBeat
        -> CDecoder::DecodeAdvance -> CClientManagerImpl::UpdateStates
        -> CSimDriver::ExecuteDispatchStepLocked        (SIM thread)

`Game time` never leaves 00:00:00 because the sim thread is dead. Session time
reaches ~00:00:49 and the process exits 0xDEAD (dbgrun's second-chance marker).

## The allocator is NOT the bug - verified against the binary, do not re-audit

All byte-faithful to their decompiles:

- `PopLaneNode` / `PushLaneNode` vs FUN_00957D00 / FUN_00957D20
- `TrimThreadCache` vs FUN_009582C0 (including calling PushHeap even when the
  popped node is null, and `cachedBytes -= initialFlushCount * blockSize`)
- `GetSmallBlockIndex` can only return 44 (OOB) for size > 16384, and `malloc_0`
  gates on `size <= 0x4000` where `kSmallBlockSizes[43] == 16384` exactly
- `gThreadHeapCache` is genuinely `thread_local`, so no shared-cache race
- an earlier `[CACHEFREE]` probe already ruled out the ThreadHeapCache block
  itself being freed while live

Lua side also verified faithful: `correctstack` (FUN_00913850),
`luaD_reallocstack` (FUN_009138D0), `luaF_freeproto` (FUN_00915090), and
`luaD_precall` correctly re-derives `ci->base` from a byte `funcOffset` after
`luaD_growstack`, so it does not hold a stale `StkId`. `sizeof(TObject) == 8`
is pinned (commit 87e09375), which `correctstack`'s `>>3` in the decompile
requires.

## The narrowed fact

A `[LANEBAD]` detector caught the first bad head:

    [LANEBAD] kind=25 blockSize=768 head=00000178 count=11 low=0

So engine code writes into an already-freed **768-byte** block. 768 = 96 x 8, so
it is either a 96-slot Lua stack (`newsize * sizeof(TObject)`) or a Proto
constant array (`sizek * 8`). Dropping the poisoned chain instead of faulting
let the run continue, and it then died a second way:

    write to 0005C05F  traverseproto+0x134
    <- propagatemarks <- mark <- luaC_collectgarbage <- luaC_checkGC
    <- lua_setgcthreshold <- CUIManager::UpdateFrameRate   (MAIN thread)

i.e. the GC marking a **Proto whose arrays are corrupt**. Both failures are the
same underlying UAF around Lua object memory.

## The variance IS the signal

Same binary, same `/map SCMP_009`, three different outcomes:

- in-game frame `visited=603 peak=603 ticked=7`, game time to 00:09:19, healthy
- in-game frame `visited=2 peak=4` - the in-game tree never really builds
- sim thread dies outright in PopLaneNode during Lua stack growth

All three are downstream of the one 768-byte UAF: land it on Lua's stack buffer
and the sim thread dies; land it on a Proto's `locvars` and the GC marks a
garbage `varname` (`traverseproto+0x120`, LuaObject.cpp:8216); land it elsewhere
and the UI Lua only half-builds. **Do not hunt a separate "render bug".**

## Also verified clean - do NOT re-audit these either

- `ren_Ui` is never false. `WRenViewport::RenderPreviewImage` clears
  ren_Ui/ren_Fx/ren_Shadows/fog_DistanceFog/ren_Select/ren_WorldBorder/ren_fog
  around a pile of D3D work and restores them with no RAII guard, so one
  escaping exception would strand the UI off forever - plausible, and a probe
  on the gate proved it never happens. (The exception-unsafety is still real
  and worth an RAII guard one day; it is not this bug.)
- No stray `free()` of an interior/non-block pointer: a validator on
  `(ptr - record->allocation) % blockSize` fired ZERO times over a full run.
- No lock asymmetry: `EnterAllocatorLock(token,true)` just wraps the same
  `gAllocatorSentinel` critical section malloc's refill path takes.
- `traversetable` matches FUN_00915320 including the `tt >= 4` collectable gate
  (LUA_TSTRING == 4) and the unguarded `h->metatable` deref, which the binary
  also does.
- `Proto` offsets (k 0x08, p 0x10, locvars 0x18, upvalues 0x1C, source 0x20,
  sizeupvalues 0x24, sizek 0x28, sizep 0x34, sizelocvars 0x38) and
  `sizeof(LocVar) == 0x0C` all match, so the GC is walking a correctly-typed
  Proto whose buffer was freed underneath it.
- Vtable slot order vs the 2007 binary does NOT cause misdispatch on its own:
  our build resolves `control->Frame(x)` / `child->DoRender(...)` against our
  own vtable at both ends. (Peer landed 8ab3e041 giving CMauiControl a real
  CScriptObject base anyway - correct for fidelity, did not fix this.)

## 2026-09-01, later still: the retraction was TOO STRONG — read this before acting

Two measurements walk back part of the "it's the recycled ThreadHeapCache"
update below. Both are from a live run with the cache identity logged.

**1. No two live threads ever share a cache.** A registry of currently-held
caches (register on creation, unregister in `FlushCurrentThreadHeapCache`, both
sites already under `gAllocatorSentinel`) never printed `[DUPCACHE]`. Seeing the
same cache address handed to two different tids across a run is ordinary reuse
after a thread detaches — `ThreadCacheTlsDetachBridge` (a real `thread_local`
instance at Global.cpp:242, despite the `[[maybe_unused]]`) runs
`FlushCurrentThreadHeapCache` on `DLL_THREAD_DETACH`, which returns the block
via `PushHeapBlock`. So the "handed out twice / second owner" mechanism is
**not** happening.

**2. The cache is HEALTHY, not garbage.** `[LANEBAD]` now prints the cache and
its `cachedBytes`:

    [LANEBAD] kind=25 blockSize=768 head=00000178 count=12 low=0
              cache=080E0D80 tid=77160 cachedBytes=1568628

1,568,628 looked absurd until checked: `kThreadCacheTrimBytes == 0x200000` =
2,097,152, so 1.5 MB is a perfectly normal sub-threshold value. Only
`lanes[25].head` is wrong. Therefore the block is a live, valid cache, and the
"second owner's bytes at offset 0x12C" story does not hold either.

**3. So "768 / kind 25" is NOT retracted after all.** The retire-every-768-block
experiment did not disprove it — with all 768 blocks retired, lane 25 is fed
only by fresh refills, so `[LANEBAD]` *cannot* fire; the different crash that
run was an unrelated one. That experiment removed the observable, not the bug.

**Where that leaves it:** `PopLaneNode` does `lane.head = node->next`, so a bad
`lane.head` means a freed 768-byte block's own first dword is 0x178. The clobber
is in the BLOCK at offset 0, not in the lane slot and not in the cache. That is
also precisely the word the earlier poison probe deliberately skipped (it
poisons from offset 4 to preserve the `next` link), which is why that probe
reported "nothing writes to a freed block" — a real blind spot, exactly here.

A DR0 watchpoint on `&lane.head` was therefore the wrong target and correctly
never fired. **Watch offset 0 of a block sitting mid-chain on the free list.**

**DR0 COVERAGE TRAP:** dbgrun arms DR0 only on threads that exist at arming
time and does not arm threads created later. Arming on the first 768-byte free
covered "4 thread(s)" of ~45 and missed the sim thread entirely, so that run's
zero-hits result was meaningless. Arm late; check the "on N thread(s)" count.

## LEADING MECHANISM (2026-09-01): an undersized CUnitCommand overflows the next block

Not a use-after-free at all — an out-of-bounds WRITE from a live object that is
allocated too small. This explains every clean negative both sessions collected.

- The shipped binary allocates exactly 376 bytes per command:
  `FUN_006E91C0.c:9  operator new(0x178u)` then the CUnitCommand ctor. So
  `sizeof(CUnitCommand) == 0x178` is ground truth, corroborated by an allocation
  site and not just by an assert.
- `sizeof(CUnitCommand) == 0x178` and `offsetof(CUnitCommand, mUnit) == 0x158`
  are asserted ONLY inside the dead `#if defined(MOHO_ABI_MSVC8_COMPAT)` block
  (CUnitCommand.h:370-373), so **nothing in the shipped build ever checked
  them**. (`sizeof(SCommandUnitSet) == 0x28` at line 74 IS live — that one was
  checked.)
- `faf-main-f7` found CUnitCommand missing its real `CScriptObject` base and
  carrying a 0x0C `SCommandUnitSet` where the binary has 0x28 — both make the
  object SMALLER than 0x178.
- The recovered member code still writes at the real binary offsets (`mUnit` at
  +0x158, then `mArgs`, then the tail int, up to 0x178). So each construction
  writes past the end of its own undersized allocation into the adjacent block.
  When that neighbour is sitting on a free lane, the word hit is its `next`
  pointer at **offset 0** — exactly and only the word found corrupted, and
  exactly the word the poison probe skips to preserve the link.
- Fits the determinism (same layout -> same overflow distance -> same clobbered
  word, `0x178` every run) and the timing (CUnitCommand backs every unit order,
  so it churns the moment a skirmish starts).

**FALSIFIED — tested against commit 36c93a06, which makes sizeof(CUnitCommand)
== 0x178 and asserts it unconditionally. `[CLOBBER]` and `[LANEBAD]` still fire
and the same `traverseproto` crash recurs. CUnitCommand is NOT the corruptor.**
The size bug was real and the commit is worth keeping on fidelity grounds, but
it is a different bug. Do not resurrect this theory.

### What the run DID prove (strongest evidence so far)

    [CLOBBER] alloc block=5C803E00 next=00000178 expected=5C804100 freedBy=0 step=0

The redundant `next` copy at +0x0C says the link should be `block + 0x300`, the
magic at +4 is intact, and offset 0 reads `0x178`. So it is a **targeted 4-byte
write at offset 0 with bytes 4..0x0F untouched** — definitively a write, not a
stale read and not a mislinked list. This finally kills the "stale read of freed
memory" framing in [[project_locvars_use_after_free_localized]], and it is only
visible because the copy lives at +0x0C: a poison-from-offset-4 probe still
shows the block as pristine.

Further constraints, all from repeated runs:

- **The victim is always `lane.head`** (`step=0` every time).
- **Heap addresses are NOT deterministic run to run** (victims were 5C803E00,
  5C7D2400, 5C7F1400), so a hardcoded watch address cannot work.
- A block **unlinked from the lane and never reissued was never written** — so
  nothing sprays that region at random.
- One DR0 hit that looked like a catch was legitimate: `newlstr` writing a
  `TString` header (`tt=4`, `marked=0` at offsets 4-5, leaving the magic's high
  `0xFEED` at 6-7) into a block that had been popped and handed to it. When
  watching a block that stays on the lane, expect this false positive.
- `freedBy=0` does NOT prove the block was never freed — the refill stamp
  rewrites every node on the chain with a null freedBy, so it only means "was on
  the lane at the last refill".

Lesson worth keeping regardless: we spent two sessions hunting a use-after-free
shape (poison, double-free walks, freed-block watchpoints, cache registries) and
every instrument came back clean **because the shape was wrong**. When several
independent instruments all return clean negatives, question the shape before
building a fifth instrument.

## THERE ARE TWO INDEPENDENT BUGS — do not conflate them

Proven by a run that had **zero** `[LANEBAD]`, **zero** `[CLOBBER]` and **zero**
`[WINDOW]` hits (the free list was never corrupted) and still died the usual way:

    ACCESS_VIOLATION traverseproto+0x120 reading 0005C05F   LuaObject.cpp:8216

So:

1. **The free-list `0x178` clobber** — a targeted 4-byte write at offset 0 of a
   768-byte block on the lane. Real, reproducible, and characterised above, but
   it is NOT what kills the engine.
2. **The locvars corruption** — the actual killer, and the one to fix. This is
   the same bug [[project_locvars_use_after_free_localized]] localised to
   `enhancementqueue.lua`.

Re-reading that file's own evidence settles the mechanism for (2):
`locvars[0].varname == locvars + 0x400`. A block pointing into its own size
class at offset 0 is a **free-list `next` pointer** — `PushLaneNode` writes
exactly that word when a block is freed. So the locvars array was freed while
the Proto still pointed at it. Not "already corrupt at close_func" in the sense
of garbage; it is a released block.

### The gap nobody has closed

`luaF_freeproto` was cross-checked (5198 calls, none freed the block, none for
that file), so the GC never collects this Proto. But the OTHER release site was
never checked: **`close_func`'s shrink**. It calls `luaM_realloc` to a smaller
size, which takes `realloc_0`'s shrink path (`newsize <= msize/2` -> allocate
new, copy, **free old**). That frees a live array whenever any other holder kept
the pre-shrink pointer.

Probes now in the tree for exactly this cross-reference:
`[LOCVARSHRINK] proto= old= new= n=` in `close_func` (LuaParser.cpp) and
`[LOCVARBAD] proto= locvars= idx= varname= delta=` in `traverseproto`
(LuaObject.cpp) — the latter **validates rather than dereferences** `varname`
and skips bad entries so the run survives and reports every occurrence. Note the
earlier probe's 0x10000 address floor was too low (0x0005C05A passes it and then
faults); this one uses 0x00100000.

Ruled out as second holders: the only other writers of `Proto::locvars` are two
load/deserialize paths (LuaObject.cpp:7899 and :18785) and both allocate a fresh
array with `block=nullptr`, so they can leak but cannot dangle.

## A REAL WILD FREE — free() called on a block+4 interior pointer

    [BADFREE] ptr=4DF12D04 base=4DF0B000 kind=28 blockSize=1280 delta=32004 freedBy=0168B8B2

`32004 = 25 * 1280 + 4`, so `free()` was handed a pointer **4 bytes past a block
start**. That is not survivable: `GetPageOwner` still resolves (same page), so
the allocator happily runs `PushLaneNode(lane, block+4)` — writing a `next` link
at `block+4` and putting a misaligned interior pointer on lane 28. It is then
handed out later as a 1280-byte buffer that **overlaps the real block**, giving
two owners the same memory. That is a mechanism capable of producing every
symptom seen, including garbage appearing inside a live Proto's locvars array.

Note an earlier run of the same validator reported ZERO hits, so this is
intermittent — do not treat one clean run as proof it does not happen.

To name the culprit: dbgrun symbolises any `frame=<hex>` token found in an
`OutputDebugStringA` marker (dbgrun.cpp ~line 466), so emit the caller as
`frame=%08X` rather than `freedBy=%08X` and the function + source line comes
back for free. That trick is reusable for any probe that has a return address.

### Why it is NOT the locvars logic

Ruled out by reading both against ground truth: `adjustlocalvars`
(FUN_0091AD80) and `removevars` write only `startpc` (+4) and `endpc` (+8) —
neither can touch `varname` (+0), and both match the binary exactly. The ONLY
writer of a `varname` slot is `luaI_registerlocalvar`, which writes a valid
`TString*`. The binary's own `traverseproto` loop confirms our reading is right:
`mov eax,[esi+18h]` (locvars), `mov edx,[eax+edi]` (varname at LocVar+0),
`add edi,0Ch` (stride 12), bound `[esi+38h]` (sizelocvars). So the garbage in
locvars is a **foreign write**, not a locvars-logic bug.

Also established: the bad locvars block is the one `close_func` **allocated**
(`[LOCVARSHRINK] proto=5F45EA80 old=5C782104 new=5C649000 n=41` vs
`[LOCVARBAD] proto=5F45EA80 locvars=5C649000 idx=2/41`), not one it freed — so
the shrink-frees-a-live-array theory is dead too, and the corruption predates
the shrink (the old array was already bad, matching the prior session's
`validAtClose` result).

## Method that got here (reuse it)

- `/log <name>` - ONE slash. `//log` silently produces no file.
- The repo's `gamedata/` is NOT mounted. `fa_path.lua` points at the Steam
  install and FAF's own `C:\ProgramData\FAForever\gamedata\*.nx2/.nx5` zips, so
  **editing repo Lua does nothing**. Extract the live file from the zip instead.
- Run: `dbgrun.exe C:\ProgramData\FAForever\bin\main.exe C:\ProgramData\FAForever\bin /map SCMP_009 /log <name>`
  with `FAF_HANG_TIMEOUT_MS` set high. argv is `<exe> <workdir> [args...]`.
  Build stages itself to `FafRunDir` = that bin dir; kill `main.exe` before
  building or the linker cannot write.
- dbgrun symbolises a stack for any `OutputDebugStringA` marker, and arms a DR0
  write watchpoint from a `lane8=<hex>` marker.
- **dbgrun WAS SILENTLY DISCARDING WATCHPOINT HITS.** Its DR0 handler only
  reported a hit when the stored word looked like a non-heap POINTER:
  `stored > 0x10000 && VirtualQueryEx(stored).Type != MEM_PRIVATE`. The value
  actually being written here is `0x00000178`, which fails `> 0x10000`, so every
  real hit was dropped with no log line at all — indistinguishable from "the
  watchpoint never fired". **This invalidates every pre-2026-09-01 "the
  watchpoint never fires" negative**, including the one that motivated the
  "stale read, not a wild write" framing in
  [[project_locvars_use_after_free_localized]]. Fixed in
  `skills/init-recovery/scripts/dbgrun.cpp` to report null / misaligned /
  `< 0x10000` / non-private values, plus `FAF_WATCH_ALL=1` for every write.
  Rebuild it with `cl /EHsc /O2 dbgrun.cpp dbghelp.lib psapi.lib`.
- **DR0 coverage trap:** dbgrun arms only threads that exist at arming time and
  never arms threads created later. Arming early reported "on 4 thread(s)" out
  of ~45 and missed the sim thread entirely, making that run's zero-hits
  meaningless. Always check the "on N thread(s)" count before trusting a
  negative, and arm late.
- **Dead layout asserts:** `MOHO_ABI_MSVC8_COMPAT` is **never defined anywhere**
  in `src/`, so 21 `static_assert`s across 13 files never compile — including
  `sizeof(CUnitCommand) == 0x178`, `sizeof(CWaitHandleSet) == 0x50`,
  `sizeof(MapImager) == 0x14`, `sizeof(DeviceD3D9BackendObject) == 0x84` and the
  `CDecalManager` offsets. Note these describe the *MSVC8-compat* layout, and
  the `#if !defined(...)` sites ADD `MOHO_EBO_PADDING_FIELD`s in our real build,
  so you cannot simply define the macro to check them — but it does mean those
  classes have **no size check at all** in the build we ship.
- Remove behaviour-changing probes (the free-poisoner) before drawing runtime
  conclusions - it changes which failure you see.

See [[project_resize_path_and_depth_stencil]] for the older GC-wild-write
hypotheses that are already dead.

## 2026-09-01, later: "768-byte block, kind=25" RETRACTED — it's the ThreadHeapCache, recycled

Peer (`faf-main-2c`) ran the decisive test: made `free()` retire every 768-byte
block permanently so none is ever handed out twice. **The crash still
happened, and earlier** (died before any Game time). So the 768-byte class was
never the damaged resource — it was collateral. `kind=25` just happens to be
the lane index whose `head` value passed a naive "looks like a pointer"
plausibility check (`< 0x10000`); everything else in the same cache region was
equally-garbage bytes that didn't happen to look pointer-shaped.

The reconciled picture, matching [[project_locvars_use_after_free_localized]]'s
older "ThreadHeapCache itself is used after free" conclusion exactly:
`lanes[25].head` sits at byte offset `25*12 = 300 = 0x12C` **inside a
`ThreadHeapCache` block** (`lanes[44]` then `cachedBytes`, ~0x214 = **532**
bytes total — not 768, `GetSmallBlockIndex(532)` is the 640-byte class). The
repeatedly-observed constant `head=0x00000178` is not a corrupted pointer at
all — it's a **second owner's real data** sitting at that same offset, because
the ThreadHeapCache block was freed/recycled while a first owner (the
allocator itself) still holds and reads it. That also explains why the value
is deterministic run-to-run: a specific second owner's field at a fixed
offset, not random heap noise.

**In flight, not yet resolved:**
- Peer is running a DR0 write watchpoint on `&cache->lanes[25].head` itself
  (the cache's own memory, not a locvars/freed-block target — the earlier
  locvars watchpoint was armed on the wrong object entirely, which is why it
  correctly never fired). Only `PushLaneNode`/`PopLaneNode`/`TrimThreadCache`/
  the refill loop should legitimately touch that word; anything else naming
  itself on the stack is the second owner.
- A parallel static audit (dispatched as a background agent, `faf-main-f7`,
  same session) is comparing `AllocateSmallBlocksAmount`/`SplitHeapRecord`/
  `AllocateFreeRegion`/`PushHeapBlock`/`gSmallBlockPrototypes` against their
  ground-truth decompiles — the **region-carving / first-handout side** of the
  allocator, which had NOT been audited before (only the free-side had).
  Peer's reasoning: no double-free (walked), no same-thread free of a live
  cache (checked), so a block handed out twice without an intervening
  `free()` has to originate on the carving side. Results not in yet.

Everything in "The allocator is NOT the bug" section above still stands
**for the free-side functions it lists** — this update only retracts the
"768-byte / kind=25" framing of WHICH resource is corrupted, it does not
reopen any of the already-verified functions.
