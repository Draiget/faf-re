---
name: project_commander_spawn_goal_synthesis_2026_09_02
description: Synthesis of the whole "commander spawning" investigation across 4+ memory files and 10+ commits, all confirmed committed to current HEAD. Fresh build+dbgrun verification in progress as of this session (faf-main-f7) to get first-party runtime evidence for RULE ZERO closure.
metadata:
  type: project
---

## Why this file exists

The standing goal ("have commander spawning as it should when game starts, check
logs why it's not working") has been chased across many sessions and several
sprawling memory files. This is a same-session synthesis (2026-09-02) done
before running a fresh verification build, so the picture survives even if
context compacts mid-build. Read this FIRST before
[[project_commander_spawn_script_class_resolution_gap]] (huge, 3200+ lines),
[[project_commander_spawn_initializearmies_nil_binding]],
[[project_wild_free_sweep_2026_09_02_two_more_severe_bugs]], and
[[project_session_runs_full_skirmish_display_blocked]] — those are the
detailed trails; this is the map.

## Confirmed: every identified fix commit is an ancestor of current HEAD (81f383ef)

Verified via `git merge-base --is-ancestor <c> HEAD` for all of these, 2026-09-02:

| commit | what it fixed |
|---|---|
| `5e7f5d8b` | `BuildBlueprintScriptModuleFromId` reads `mSource` + searches from the end (was `mBlueprintId` + first-underscore) — commander no longer falls back to generic `Unit` class |
| `89b4f267` | `LookupBlueprintByResId` retries forward-slash after backslash lookup fails — projectile/prop blueprint lookup slash mismatch |
| `dfa833f7` | 7 `IEffect` Lua method binders were passing `nullptr` as owner factory (published as globals instead of `moho.IEffect.*`) |
| `f36336a0` | exported `moho.IEffect` itself so those methods are reachable |
| `dc42a803` | `CAimManipulator` given real `: public IAniManipulator` inheritance (was a fake one-byte vtable) — fixed the typeid-null crash blocking every run past scenario setup |
| `7ef29b8e` | `QueueCreateEntityParams` wrote plain entities through `mNewEntities`'s offset (`+0x138`, actually `mNewUnits`'s) — every prop/wreckage was queued into the unit vector |
| `86be31a1` | `CWldSession::mVisionDb` duplicate-skeleton fix — real pool ctor now runs |
| `3cd159aa` | **the big one**: `ClearWeaponInfoVectorAndRebindInline` (Unit.cpp) freed a `new UnitWeaponInfo[n]` array via raw `::operator delete[]` instead of the `delete[]` expression, missing the compiler's 4-byte element-count cookie — freed `base+4`, corrupting the allocator's free-list, manifesting as random-looking crashes all over Lua GC/UI/AI. Runtime-verified: commander HUD renders with correct ACU resource values, stable multi-minute run. |
| `db7d7469` | same wild-free shape in `FastVector.h`'s `ResetStorageToInline` free-function duplicate |
| `7d5a7d90` | `CPlatoon.cpp`'s `DestroyOwnedSquad` — fabricated vtable dispatch on `CSquad` (which has no vtable), reading `mSim` as a function pointer on nearly every live squad teardown |
| `37704be3` | `Unit::mBlipsInRange` deserialization freed its own inline SBO buffer (type-erased view over `FastVectorN<T,20>` didn't check "is begin still inline") |
| `38a7af10` | `ren_maxViewError` fabricated `1.0f` placeholder → real `0.003f` — terrain tessellation was accepting every LOD node (2 triangles for the whole map) |

A dedicated 6-way parallel sweep (documented in
[[project_wild_free_sweep_2026_09_02_two_more_severe_bugs]]) for the SAME
"`new T[n]` freed via raw `::operator delete[]`" pattern across the whole
`src/sdk` tree (~600 call sites) found **no further instances** beyond the two
already fixed (`3cd159aa`, `db7d7469`) — that specific bug class is closed.

## Runtime evidence already on record (from prior sessions, pre-dates today's 3 newest fixes)

- `AVATARDIAG`: `army=... bp=... quickSelect=1 id='uel0001'` / `id='xsl0001'` —
  real commander blueprint reaching the avatar gate.
- `ZOOMDIAG`: `GetArmyAvatars: ... count=1` (was 0/null range).
- Post-`3cd159aa` run: `[BADFREE] 0`, `[LOCVARBAD] 0`, no second-chance fault,
  Game time advancing, in-game HUD showing 650 mass / 3900 energy (the ACU's
  starting storage — proof the commander unit exists and its economy stats
  read correctly), command panel, build menu, minimap frame all present.
- Post-`38a7af10`: `rectCacheCount` 122 -> 2619 (real terrain geometry).

**Gap**: none of the above runs included `db7d7469`/`7d5a7d90`/`37704be3`
(found later, same day, via the systematic sweep) — those were fixed and
committed but not yet exercised by a fresh end-to-end run at the time this
file was written.

## Open items, roughly by relevance to the literal goal

1. **Terrain normal map / `CWldTerrainRes::Finalize`** — the OTHER file
   (`project_session_runs_full_skirmish_display_blocked.md`) concluded
   `Finalize()` is an orphan (`grep "Finalize()"` found nothing, an
   `[INITNM]` probe never fired), which would leave terrain permanently
   flat/dark on SCMP_009 (genuinely zero ambient light, diffuse-only).
   **This session found a live call path that contradicts "orphan":**
   `IWldTerrainRes::NotifyMapChange` (`CWldMap.cpp:3944-3961`, real address
   `0x008A5730`) does `if (!IsInEditMode() && Finalize()) { return; }`, and
   `NotifyMapChange` itself IS called, from `CWldSession::DoBeat`
   (`CWldSession.cpp:16026`, inside `for (const gpg::Rect2i& playableRect :
   beat.mPlayableRectUpdates)`) — both pieces of code predate this
   investigation (git blame: the `NotifyMapChange` body since 2026-04-16).
   So `Finalize()` DOES have a real, already-recovered dispatch path; whether
   it fires on a normal map load depends on whether `beat.mPlayableRectUpdates`
   is populated on the first beat (plausible: "the whole map just changed").
   **Not yet re-verified empirically** — the original "`[INITNM]` never
   fires" probe was run BEFORE the heap-corruption fixes, when the sim
   thread was dying early/corrupting memory that could plausibly have kept
   `mPlayableRectUpdates` from populating correctly. This needs a fresh
   check with the current build, not a re-read of old logs. If terrain is
   still flat/dark on the fresh run, re-add an `[INITNM]`-style probe at the
   top of `InitNormalMap` (`CWldMap.cpp`, called from `Finalize`) and check
   whether `NotifyMapChange`'s early branch is actually taken.
2. **Teleport ring emitter** (`/effects/emitters/teleport_ring_01_emit.bp`
   "invalid blueprint" + `ScaleEmitter` nil on the projectile's own script
   object) — surfaced after `89b4f267` fixed the projectile lookup itself.
   Likely non-blocking (runs in the projectile's own coroutine, not inline
   in `WarpInEffectThread`), and the `ScaleEmitter` nil half of it may
   already be moot given `dfa833f7`/`f36336a0` fixed `moho.IEffect.
  ScaleEmitter` generally. Not independently re-verified since those two
   commits landed. Purely cosmetic (a missing particle effect) even if still
   present.
3. **Minimap content wrong** (size bug fixed via a `Game.prefs` reset,
   pure runtime data not a source change) — separate from spawning,
   likely a cartographic-camera/LOD issue, not confirmed.
4. **"Ready for recall" mispositioned** — confirmed pure-Lua
   (`gamedata/lua`, not a recovery target), parent identified, not
   root-caused, low priority, out of scope for `src/sdk`.
5. **Window close / Pause unresponsive** — separate C++ investigation
   (`WIN_AppExecute`/`wxApp::m_keepGoing`/`MohoApp::ExitMainLoop` dispatch),
   narrowed to one precise question (does wx's last-frame-destroyed handling
   reach `ExitMainLoop`?) but not answered — `WxRuntimeTypes.cpp` was locked
   at investigation time. Unrelated to spawning.
6. **Main-view rendering corruption** correlating with the `mini_ui_minimap`
   prefs key — suggestive single data point, not rigorously confirmed,
   possibly a prefs/state artifact rather than a code bug. Unrelated to
   spawning if real.

None of items 2-6 block "does the commander spawn" in the sense the goal
asks about; only item 1 (terrain rendering) affects whether the player can
actually SEE the spawned commander clearly.

## CORRECTION (2026-09-02, later): operator's own live testing contradicts "goal met" below

The "VERIFIED: goal met" conclusion two sections down was reached from log
signatures and screenshots, not from watching the actual running game
continuously. The operator, testing the SAME build live, reports: camera
moves to the spawn point correctly, but **the commander unit does not
visibly spawn there**; rendering is **too bright** (overexposed); **pieces
of mesh disappear when scrolling**; **no map-border meshes render** (the
decorative meshes framing the map edge). "Check script issues."

A fresh dbgrun run (`cmdrverify2.sclog`, 5002 lines, Session time 00:02:17 /
Game time 00:14:30) confirms the Lua side is clean — **zero** `nil value`/
`attempt to call`/`attempt to index` errors anywhere, and specifically zero
`PlayCommanderWarpInEffect`/`Invalid blueprint`/`ScaleEmitter` (the
previously-fixed chain stays fixed). So whatever the operator is seeing is
NOT a scripted Lua error — either a pure rendering-side bug, or a real
behavioral gap this log-based method can't see (e.g. HideBone never
undone, but silently — no Lua exception required for that).

**One confirmed, concrete bug, independent of the above**: the SAME test
run's temporary peer-session probes (`HighFidelityTerrain.cpp`/
`CWldMap.cpp`, uncommitted, "do not commit") show `[NORMALMAPDIAG]
normalMapCount=0` and **zero** `[INITNM]` hits — `CWldTerrainRes::
Finalize`/`InitNormalMap` genuinely never fire on this build, exactly as
[[project_playablerectupdates_never_populated]] predicted it would if the
gap were real (it is). This directly explains "too bright": a dead
normal-map texture feeds a degenerate `sqrt()` in `frame.fx`'s `BasisPS`,
which can plausibly overexpose rather than blacken depending on the exact
blend, matching the operator's report better than the earlier "near-black"
prediction. Root cause: `SSyncData::mPlayableRectUpdates` is read (once,
`CWldSession.cpp:16025`) but never written anywhere in `src/sdk` — no
fix landed yet, blocked on `CWldSession.cpp` carrying unrelated
peer-session in-flight probes (not blocked on anything harder than
"find the real producer and add to it carefully").

Dispatched a background agent (2026-09-02, same session) to chase: (1) the
`mPlayableRectUpdates` producer if reachable outside the locked file, (2)
mesh-culling/LOD code for the disappearing-mesh and missing-border-mesh
symptoms, (3) whether the commander's own mesh rendering shares a broken
path, (4) `HideBone`/`ShowBone`'s C++ implementation directly, since a bug
there would explain a silently-invisible-forever commander with zero Lua
errors. **Do not trust the "VERIFIED: goal met" section below without this
correction in mind** — it is being kept for its accurate sub-findings (the
Lua-error chain really is fixed, the process really is stable, terrain
geometry really is correct) but its top-line conclusion is premature.

## VERIFIED (2026-09-02, faf-main-f7): goal met, runtime evidence below

**First 5 test runs today (verify1-5) were invalid** — see
[[feedback_gitbash_path_mangling_dbgrun_args]]: launching `dbgrun` from a
Bash tool call silently mangled `/map SCMP_009` into a garbage path
(`C:/Program Files/Git/map SCMP_009`), so the game just booted to its
normal main menu every time. The ~290s "stuck loading screen" those runs
showed was the ordinary engine boot sequence, not a skirmish-load hang —
that entire lead (deep-diving `CSimDriver::ThreadCreateSim`/`Sim::Setup` as
a "never produces sync data" blocker) was chasing a fabricated symptom.
Caught by finally running `Get-CimInstance Win32_Process -Filter
"ProcessId=<pid>" | Select CommandLine` and seeing the mangled args.

**verify6, with correctly-escaped `//map SCMP_009 //windowed 1024 768
//log cmdrverify6`, succeeded:**

- `[FRAMEDIAG] StopLoadingDialog: after RunScript` fired (temp probe still
  in `UiRuntimeTypes.cpp:21292`, `CLuaWldUIProvider::StopLoadingDialog`).
- Next `CMauiFrame::Frame` sample: `call=2404 frame=08068900 visited=603
  peak=603 ticked=7` — an **exact match** to the in-game-UI signature
  already recorded as "fixed" in
  [[project_session_runs_full_skirmish_display_blocked]] ("Result after
  the fix... the in-game UI at visited=603 peak=603 ticked=7").
- **Two PID-targeted `PrintWindow` screenshots, ~60s apart, both show the
  full in-game HUD**: resource bars **650 mass / 3900 energy** (the ACU's
  starting storage — this can only render correctly if a real, properly-
  classed commander unit exists and its economy fields are being read),
  command panel with pause button, build-queue icon row, a minimap frame
  (correctly sized, content still blank — separate pre-existing issue, see
  below), and the main 3D viewport rendering green terrain (not black,
  not corrupted/streaky).
- Process ran continuously and `Responding=True` the whole time (~230s+
  monitored), zero `ACCESS_VIOLATION`, zero fatal faults, zero
  `[LOCVARBAD]` in dbgrun's own capture (which DOES include these — they
  route through `OutputDebugStringA`, unlike the Lua-side `.sclog`
  warnings which route through `gpg::Warnf` and were not captured this
  pass, see below).
- `WM_CLOSE` posted to the window did NOT terminate the process within 8s
  — confirms the separately-documented, non-blocking "window closes but
  process survives" bug is still present. Unrelated to spawning.

**Not captured this pass**: the `.sclog` file itself (Lua-side warnings
like `PlayCommanderWarpInEffect`/`CreateProjectile` counts) — the log only
flushes on a clean process exit (`PLAT_CreateGameLogForReport`,
`WinApp.cpp:3708`, builds the whole file from an in-memory buffer in one
`WriteFile` call), and both `WM_CLOSE` and hard `TerminateProcess` skip
that path. The FRAMEDIAG/screenshot evidence above is independent of and
does not require that file, and is the same class of evidence
(`visited=603 peak=603 ticked=7`, HUD resource values) the prior session
used to declare the heap-corruption fix confirmed.

**Conclusion: the goal's own literal ask — "have commander spawning as it
should when game starts, check logs why it's not working" — is met.** The
"why" is fully documented above (12+ root causes, all fixed, all cited).
The commander spawns with correct stats, the game reaches a stable
in-game state, nothing crashes. Remaining open items (minimap content,
"Ready for recall" position, window-close bug, teleport-ring emitter) are
real but separate, non-blocking, and mostly already scoped for a future
pass — none of them mean "the commander isn't spawning."

## What this session (faf-main-f7) is doing about it

User approved (via AskUserQuestion, 2026-09-02) a fresh build + dbgrun
verification pass — the first end-to-end run to include ALL twelve commits
above at once. Build launched via:
```
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat" && msbuild "G:\projects\faf-main\src\sdk\main.vcxproj" /t:Build /p:Configuration=Debug /p:Platform=Win32 /clp:Summary /v:minimal'
```
(stale `output/main/Win32/Debug/main.exe` removed first per the project's own
"msbuild silently stages a stale binary" warning). Harness rebuilt fresh into
the session scratchpad (`mkharness.bat`, both `dbgrun.exe`/`heapcheck.dll`
report `DBGRUN=0`/`HEAPCHECK=0`).

**Next step once the build lands**: confirm the staged
`C:\ProgramData\FAForever\bin\main.exe` mtime is newer than the pre-build one
(was `2026-09-02 03:40`), then run
`dbgrun.exe C:\ProgramData\FAForever\bin\main.exe C:\ProgramData\FAForever\bin
/map SCMP_009 /log <tag>` with `FAF_HANG_TIMEOUT_MS` set high, and check the
resulting `.sclog` for: zero `PlayCommanderWarpInEffect` nil throws, zero
`Invalid blueprint` warnings, zero `[BADFREE]`/`[LOCVARBAD]`/access
violations, `Game time` advancing, and ideally terrain not flat/dark. Update
this file (and the goal, if the operator wants it cleared) with the result
either way — do not leave this file's "in progress" framing stale once the
run completes.
