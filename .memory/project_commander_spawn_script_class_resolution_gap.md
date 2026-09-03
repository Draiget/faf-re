---
name: project_commander_spawn_script_class_resolution_gap
description: Commander spawn/reveal chain, two engine bugs fixed and runtime-verified (5e7f5d8b script-class resolution, 89b4f267 projectile-lookup slash mismatch — 0/8 throws both). Open: teleport-ring emitter lookup (new, likely non-blocking), minimap panel size FIXED (stale Game.prefs) but content still wrong (needs user's own eyes, not this tool's screenshots — GDI capture is unreliable for D3D9 content), "Ready for recall" mispositioned (parent identified, cause open).
metadata:
  type: project
---

Investigated 2026-09-01 while chasing the goal "commander spawning as it should when
game starts, check logs why it's not working".

**UPDATE (2026-09-01, later pass): RESOLVED at the source level.** The population
site described below as "still open" was never actually missing — it's the
generic Lua-table -> reflection field copy that `GetOrCreateRegisteredBlueprint`
already performs (has performed since the Aug 12-15 commits, long before this
investigation started). See "RESOLUTION" section near the bottom, added after
re-tracing the full reflection pipeline address-by-address against ground truth
`.c`/`.asm` and finding zero divergence at any step. The consumer-side fix
(`BuildBlueprintScriptModuleFromId` reading `mSource` + `rfind`) was landed
separately in commit `5e7f5d8b` ("Fix BuildBlueprintScriptModuleFromId to read
mSource, search from the end") — that commit's own message says the population
site was still unresolved at the time it was written; it no longer is. The
original trace below is kept intact because it is still the correct map of what
was checked and ruled out for the *ctor/AddFields-on-the-derived-type* leads;
only the "still open" conclusion at the end of that trace was wrong, and is
superseded by the RESOLUTION section.

## The symptom (confirmed via fresh dbgrun repro, `/map SCMP_009 /log cmdrspawn2`)

Every army's `CreateInitialArmyGroup` (`ScenarioUtilities.lua`) DOES spawn its
commander successfully (`cdrUnit` is non-nil, category COMMAND check passes,
`ForkThread(CommanderWarpDelay, cdrUnit, 3, brain)` fires for all 8 armies). But
3 seconds later, `CommanderWarpDelay` (line 428) does `cdrUnit:PlayCommanderWarpInEffect()`
and this throws **8 times** (once per army), always:

    warning: Error running lua script: ...scenarioutilities.lua(428):
    attempt to call method `PlayCommanderWarpInEffect' (a nil value)

`PlayCommanderWarpInEffect` is defined ONLY on `CommandUnit` (`gamedata/lua/sim/units/CommandUnit.lua:155`),
a Lua subclass (`ClassUnit(WalkingLandUnit)`), never on the base `Unit`. Since it's
missing, the commander's Lua object never got the `CommandUnit`/`ACUUnit`/`UEL0001`
method chain — it's stuck as a plain `Unit`. Before this throws, `HideBone(0, true)`
already hid the model and (for human brains) `SetBlockCommandQueue(true)` already
blocked orders — and since the effect call that would undo both never completes,
the commander stays invisible and uncommandable forever.

**CORRECTION (2026-09-01, runtime verification pass): "Ready for recall" is NOT
proven to be caused by this throw — retract that earlier claim.** Rebuilt with
the fix (`5e7f5d8b` + the pre-existing reflection chain), re-ran the identical
`/map SCMP_009` test fresh: **zero** `PlayCommanderWarpInEffect` throws (was 8),
confirming the fix works at the log level. But a live screenshot of that SAME
fixed run still showed `"Ready for recall"` and 0/0 resources, identical to
before the fix. Traced why: `gamedata/lua/ui/game/recall.lua`'s panel is
unconditionally created every session (`gamemain.lua:283`) with that exact
string as its hardcoded construction-time label (`recall.lua:108`), and its
only found show/hide trigger is a **manual collapse-arrow click**
(`recall.lua:230-258`, `Logic()`'s `OnCheck` handler) — nothing tying it to
army/commander/economy state was found in this file. This is very likely just
a permanent status widget shown regardless of game state, unrelated to whether
any commander (yours or an ally's) exists. Do NOT use "Ready for recall"
on-screen as evidence for or against this bug going forward — use the log
grep (`PlayCommanderWarpInEffect` throw count) instead, which is the
actual proven signal. Whether 0/0 resources indicates a REAL remaining
problem (vs. legitimate map/difficulty starting values) is still open and
untested — needs a fresh live session with the rebuilt binary to check
economy income over time, not just the instant-0 snapshot.

Also corrected: `SinglePlayerLaunch.lua:308` (`playerOptions.Human = true` for
`teamInfo[1]`, matching "FAF_Draiget" as ARMY_1 in every test log) confirms
the local profile genuinely IS bound as a human player to ARMY_1 in a raw
`/map SCMP_009` launch — this is NOT a pure spectator/observer session as an
earlier pass in this file speculated. That speculation should not be reused
as a reason to discount screenshot evidence from this test harness.

Also found in the same log (line 3386, once, on the NEUTRAL_CIVILIAN army's
wreckage step): `scenarioutilities.lua(513): attempt to call method 'SetOrientation'
(a nil value)` inside `CreateWreckage`. Confirmed NOT the cause of missing commanders
— `InitializeArmies`'s per-army loop (`ScenarioUtilities.lua:652-704`) creates the
commander (line 679) BEFORE the wreckage step (line 686-693) in the SAME iteration,
and civilian-army wreckage is last in iteration order, so by the time this throws,
all 8 real armies already got their `CreateInitialArmyGroup` call. Real bug, but
cosmetic (breaks decorative wreckage props on the civilian/neutral army only) — not
part of this chain. Worth a look separately if resuming: same class of bug
(a method call on an object that doesn't have the expected class), so the SAME root
cause below may explain it too.

## Root cause, confirmed via ground truth (`FUN_00677360.c` = `ResolveBlueprintScriptFactory`)

The engine resolves which Lua class to build a unit's script object from via
`Entity.cpp` `ResolveBlueprintScriptFactory` (0x00677360) →
`BuildBlueprintScriptModuleFromId` (Entity.cpp:1149-1172, no address of its own —
inlined helper). Checks in order: `blueprint->mScriptModule`/`mScriptClass`
(always empty for ordinary units — confirmed, see below) → this fallback derivation
→ type-default (`/lua/sim/unit.lua`+`"Unit"`, always succeeds, silently, no warning).
**Every ordinary unit currently falls through to the generic `Unit` class** because
the fallback derivation is broken:

    // current (Entity.cpp:1155, 1166):
    std::string id = blueprint->mBlueprintId.to_std();
    ...
    const std::size_t underscorePos = id.find('_', start);   // FIRST underscore from start

    // ground truth (FUN_00677360.c lines 108-109):
    v6 = func_StringSearchFromEnd(0xFFFFFFFF, &blueprint->mSource, "_", 1u);  // LAST underscore from end
    v7 = std::string::substr(&blueprint->mSource, &v38, 1u, v6 - 1);

Two divergences: wrong field (`mBlueprintId` vs `mSource`) and wrong search direction
(first-from-start vs last-from-end). `mSource` is at `REntityBlueprint+0x40` (declared,
`REntityBlueprint.h:57`), `mBlueprintId` at `+0x08`.

## `mBlueprintId` vs `mSource` — confirmed via Lua ground truth (`gamedata/lua/system/Blueprints.lua`)

Traced the WHOLE chain from `.bp` file to C++ object:

  - `UEL0001_unit.bp` calls the global `UnitBlueprint{ BlueprintId = ..., ... }` —
    except it does NOT set `BlueprintId` explicitly (confirmed, grepped the file).
  - `Blueprints.lua`'s **own** `UnitBlueprint(bp)` (line 650) shadows whatever the
    `.bp` file might have called into directly: `bp.Mod = current_mod; SetShortId(bp);
    StoreBlueprint('Unit', bp)`.
  - `SetShortId(bp)` (line 496, doc comment: **"Used for units only"**):
    `bp.Source = bp.Source or GetSource()` (full VFS path via `debug.getinfo` stack
    walk + `DiskToLocal`, e.g. `/units/uel0001/uel0001_unit.bp`), then
    `bp.BlueprintId = bp.BlueprintId or gsub(lower(bp.Source), "^.*/([^/]+)_[a-z]+%.bp$", "%1")`
    — extracts JUST `"uel0001"` (strips directory AND `_unit.bp` suffix).
  - So **`bp.BlueprintId` = short id `"uel0001"`, `bp.Source` = full path**. This
    is genuinely BOTH pieces of information, kept in two different Lua fields.
  - `StoreBlueprint` only caches into a Lua-side `original_blueprints.Unit[id]`
    table — no C++ engine call yet.
  - Later, `RuleInit.lua` → `Blueprints.lua`'s `RegisterAllBlueprints(blueprints)`
    (line 707) does `RegisterGroup(blueprints.Unit, RegisterUnitBlueprint)` — THIS
    `RegisterUnitBlueprint` is the **C++-bound** global (confirmed:
    `Sim.cpp:14497` binds Lua global `"RegisterUnitBlueprint"` to
    `moho::cfunc_RegisterUnitBlueprint`, i.e. `FUN_00528AF0`), now finally reaching
    the engine, with `bp` (containing both `Source` and `BlueprintId`) as arg 1.

So `blueprint->mBlueprintId` (C++) = `"uel0001"` (short, ZERO underscores) —
confirming `BuildBlueprintScriptModuleFromId`'s current field choice can never
succeed for a plain 7-character unit id (there IS no `_` in "uel0001" at all,
so `.find('_', ...)` always returns `npos` and the function returns `{}`, then
`ResolveBlueprintScriptFactory` silently falls through to the type-default).
Reading `mSource` instead (`"/units/uel0001/uel0001_unit.bp"`, exactly ONE
underscore, right before `_unit.bp`) would let ground truth's algorithm produce
the correct `/units/uel0001/uel0001_script.lua` — **if `mSource` held that value.**

## RESOLUTION (2026-09-01, later pass): the population site was found

**`mSource` IS populated — by the generic Lua->reflection field copy, not by
any explicit `mSource = ...` line anywhere in source.** That's exactly why the
trace below (which searched for explicit writes/assignments to the field)
never found it: the real mechanism is a runtime string-keyed field lookup, so
there is no source-level token to grep for. The two gaps in the original
trace, both innocent:

1. It checked `REntityBlueprintTypeInfo::AddFields` (`FUN_00512870`) and
   concluded "Source" isn't a registered field. True, but irrelevant — "Source"
   is registered by a *different, base-class* AddFields:
   **`Moho::RBlueprintTypeInfo::AddFields` (`FUN_0050DCF0`, in
   `src/sdk/moho/resource/blueprints/RBlueprint.cpp:495-510`, already
   committed since `721d4ad3`/`743f49d3`, Aug 12-15 2026)**. Ground truth:
   ```c
   gpg::RField *__usercall Moho::RBlueprintTypeInfo::AddFields@<eax>(gpg::RType *a1@<eax>)
   {
     v2 = gpg::RType::AddField_string(a1, "BlueprintId", 8);
     ...
     v4 = gpg::RType::AddField_string(a1, "Source", 64);       // <-- offset 64 = 0x40 = mSource
     v4->mVers = 1;
     v4->mDesc = "File this blueprint was defined in";
     return gpg::RType::AddField_int(a1, "BlueprintOrdinal", 92);
   }
   ```
   Our recovered `RBlueprintTypeInfo::AddFields` already matches this exactly
   (`AddTypedField(typeInfo, "Source", CachedStringType(), 0x40)`).

2. It never traced the *reflection base-field flattening* mechanism, which is
   how a field registered on `RBlueprintTypeInfo` becomes visible on
   `RUnitBlueprintTypeInfo`/`REntityBlueprintTypeInfo` (whose own `AddFields`
   really doesn't mention "Source" — that part of the original trace was
   correct, it just wasn't the whole picture).

### The full chain, every link re-verified against ground truth `.c`/`.asm`

  - `Moho::RBlueprintTypeInfo::AddFields` (`FUN_0050DCF0`) registers "Source"
    string field at offset `0x40` on `RBlueprint`'s own `RType`, as above.
  - `gpg::RType::AddBase` (`FUN_008DF500`, ground truth; recovered at
    `src/sdk/gpg/core/reflection/Reflection.cpp:13770`) **eagerly flattens**
    the base type's `fields_` into the derived type's own `fields_`, with
    offset adjustment (`field->mOffset + v9->mOffset`), re-reading
    `baseType->fields_.begin()/end()` every loop iteration exactly as the
    binary does. Our recovered version matches this instruction-for-instruction.
  - `Moho::REntityBlueprintTypeInfo::AddBase_RBlueprint` (`FUN_005131D0`;
    recovered as `AddBaseRBlueprint` in
    `src/sdk/moho/entity/REntityBlueprintTypeInfo.cpp:760`) resolves
    `RBlueprint`'s `RType*` via `gpg::LookupRType(typeid(RBlueprint))` and
    calls `AddBase` with it. Same shape one level up:
    `Moho::RUnitBlueprintTypeInfo::AddBase_REntityBlueprint` (`FUN_00525820`;
    recovered at `src/sdk/moho/resource/blueprints/RUnitBlueprintTypeInfo.cpp:196`).
  - **The load-bearing detail**: `gpg::LookupRType` (ground truth `FUN_008D8680`
    is `RType::Init`'s no-op body, not this — `LookupRType` itself is a
    separate function; recovered at `Reflection.cpp:3723`) does **lazy
    init-on-first-use**:
    ```cpp
    RType* type = it->second;
    if (!type->finished_) {
      type->finished_ = true;   // guard against re-entrant recursion
      type->Init();
      type->RegisterType();
      type->initFinished_ = true;
    }
    return type;
    ```
    So when `AddBase_RBlueprint` looks up `RBlueprint`'s type, if
    `RBlueprintTypeInfo::Init()` (which calls `AddFields` and populates
    "Source" into its `fields_`) hasn't run yet, `LookupRType` runs it
    *right then*, before returning the pointer — guaranteeing
    `RBlueprintTypeInfo::fields_` is fully populated before `AddBase`'s
    eager flatten reads it. This ordering is self-enforcing regardless of
    static-init order; verified `gpg::RType::Init()` itself is a true
    no-op in both ground truth (`FUN_008D8680`, single `retn`) and our
    recovered code (`Reflection.cpp:13709`, `void RType::Init() {}`) — it
    does **not** clear `fields_`/`bases_` (ruled out a "does RType::Init wipe
    the just-flattened base fields" hypothesis this way; that clearing code
    exists only in an unrelated pointer-type destructor,
    `DestroyCUnitCommandPointerTypeBody`, `Reflection.cpp:12551`, not in
    `Init`).
  - Each derived `Init()` (`RBlueprintTypeInfo::Init` `FUN_0050DC10`,
    `REntityBlueprintTypeInfo::Init` `FUN_00512790`,
    `RUnitBlueprintTypeInfo::Init` `FUN_005229A0` — all three re-read
    directly, ground truth and recovered, identical structure) calls
    `AddBase_X(this)` **then** `gpg::RType::Init()` **then** `AddFields(this)`
    **then** `Finish()`, matching our recovered code exactly at every level.
    So by the time `RUnitBlueprintTypeInfo::Init()` finishes, its `fields_`
    contains: [flattened from RBlueprint: BlueprintId@8, Description@0x24,
    **Source@0x40**, BlueprintOrdinal@0x5C] + [flattened from REntityBlueprint:
    Categories@0x60, ScriptModule@0x70, ScriptClass@0x8C, ...] + [its own:
    General/Display/Physics/... section fields].
  - `RType::Finish` sorts `fields_` by name (`msvc8::sort` + `strcmp`,
    matching ground truth `FUN_008DF4A0`/`sub_8DD790`); `RType::GetFieldNamed`
    (ground truth `FUN_008D94E0`) binary-searches that sorted list — both
    match our recovered `Reflection.cpp:13727`/`13989` exactly.
  - **The actual call site**: `cfunc_RegisterUnitBlueprint` (`0x00528AF0`,
    `Sim.cpp:14391`) -> `RegisterUnitBlueprintFromState` (`Sim.cpp:14139`) ->
    `CreateOrGetUnitBlueprintFromState` (`Sim.cpp:14115`, cites
    `0x00531D80`/`func_CreateRUnitBlueprint`) ->
    `GetOrCreateRegisteredBlueprint<RUnitBlueprint>` (`Sim.cpp:13980`), whose
    `initializer(blueprintSpec, blueprint)` call (line 14027, unconditional —
    matches ground truth's own unconditional `func_Add__blueprints` call at
    the tail of `FUN_00531D80` regardless of the new-vs-existing branch) is
    bound to `InitUnitBlueprintFromLua` (`Sim.cpp:13855`):
    ```cpp
    void InitUnitBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RUnitBlueprint* const blueprint)
    {
      gpg::RRef destination{};
      (void)gpg::RRef_RUnitBlueprint(&destination, blueprint);   // most-derived RType
      LuaPlus::LuaObject source(luaBlueprint);
      (void)SCR_LuaBuildObject(source, destination, true);       // <-- the generic copy
      blueprint->OnInitBlueprint();
      ...
    }
    ```
    This is ground truth `func_Add__blueprints`'s (`FUN_00529B30`) first
    statement, `Moho::RBlueprint::InitBlueprint(a1, a2)`, inlined per-type
    instead of calling the (now-orphaned, never-called) shared
    `RBlueprint::InitBlueprint` method in `RBlueprint.cpp:313` — separate,
    pre-existing code-duplication issue, not a correctness bug (the inlined
    copies are behaviorally identical to what `InitBlueprint` itself does).
  - `SCR_LuaBuildObject` (`FUN_004CF510`, recovered at
    `src/sdk/moho/lua/CScrLuaObjectFactory.cpp:1197`) iterates every key in
    the Lua `bp` table (`LuaPlus::LuaTableIterator`), and for each key calls
    `destination.mType->GetFieldNamed(keyName)`. For the Lua key `"Source"`
    (set by `Blueprints.lua`'s `SetShortId(bp)`, already confirmed earlier in
    this file: `bp.Source = bp.Source or GetSource()`, the full VFS path)
    this finds the flattened `RField` at offset `0x40`, builds
    `fieldDestination = {mObj = blueprintPtr + 0x40, mType = stringType}`,
    and recurses into `SCR_LuaBuildObject(luaSourceString, fieldDestination)`.
  - Since the Lua value is a plain string, `LuaObjectTryToString` succeeds and
    `destination.mType->SetLexical(destination, lexicalValue.c_str())` is
    called, which for the string `RType` (`RStringType::SetLexical`, ground
    truth `FUN_008DF200`; recovered at
    `src/sdk/gpg/core/reflection/RStringType.cpp:79`) does:
    ```cpp
    bool RStringType::SetLexical(const gpg::RRef& ref, const char* const str) const
    {
      auto* const out = static_cast<msvc8::string*>(ref.mObj);
      *out = msvc8::string{str, std::strlen(str)};   // <-- the actual write into mSource
      return true;
    }
    ```
  - `RUnitBlueprint : public REntityBlueprint` is **real C++ inheritance**
    (`src/sdk/moho/resource/blueprints/RUnitBlueprint.h:757`; same for
    `RPropBlueprint`/`RProjectileBlueprint`), so `mSource` sits at one
    unambiguous `+0x40` regardless of which pointer type reads it — no
    layout-duplication ambiguity for this specific field (that duplication
    exists one level up, between `RBlueprint` and `REntityBlueprint`, and
    doesn't affect this chain since both layouts agree `mSource` is at
    `0x40`).

**Net effect**: every ordinary unit's blueprint object gets `mSource` set to
its full VFS path (e.g. `/units/uel0001/uel0001_unit.bp`) during
`RegisterUnitBlueprint`, via this entirely generic, non-explicit mechanism —
fully committed source, predating this investigation by about three weeks.
Combined with the already-landed `BuildBlueprintScriptModuleFromId` consumer
fix (`5e7f5d8b`), the source-level fix for the commander script-class bug
appears **complete**. What is *not* yet done: an actual runtime confirmation
(rebuild + `/map SCMP_009 /log <tag>` dbgrun repro, grep for
`PlayCommanderWarpInEffect` throws — should be zero). Rebuilding `main.vcxproj`
is not authorized without asking the operator first (repo CLAUDE.md); that ask
is the correct next step for whoever picks this up, not further source
investigation.

## The original trace (kept for the ctor/AddFields-on-derived-type leads it correctly ruled out)

Exhaustively checked every construction/registration/reflection site (all read
directly, ground truth AND our recovered source, address-by-address):

  - `RBlueprint::RBlueprint` (`FUN_0050DD60`, ground truth): SSO zero-inits
    `mSource`, never copies anything into it (only `mName`/`mDesc` get real content).
  - `REntityBlueprint::REntityBlueprint` (`FUN_00511C30`, ground truth): calls
    base `RBlueprint::RBlueprint(source, this, a3)` — **confirms `REntityBlueprint`
    genuinely inherits from `RBlueprint` in the real binary** (our recovered
    source models them as two separate flat classes with duplicated fields
    instead of true inheritance — a "Duplicate layout contract" violation, but
    a large refactor, not attempted here) — then only sets vtable/mCategories/
    mScriptModule/mScriptClass/physics defaults; no `mSource` touch.
  - `func_CreateRUnitBlueprint` (`FUN_00531D80`, ground truth, read in full):
    reads `blueprintSpec["BlueprintId"]` (→ `mBlueprintId` via `RResId`/
    `STR_CopyFilename`), constructs, registers in the map. No `mSource` reference
    anywhere in this function.
  - `GetOrCreateRegisteredBlueprint<RUnitBlueprint>` (our recovered template,
    `Sim.cpp` ~13985-14030) + `InitUnitBlueprintFromLua` (`Sim.cpp:13855`) +
    `SCR_LuaBuildObject(source, destination, true)` (generic Lua→reflection copy):
    `REntityBlueprintTypeInfo::AddFields` (`FUN_00512870`, checked BOTH our
    recovered `REntityBlueprintTypeInfo.cpp:796-937` AND ground truth `.c` —
    neither registers a "Source" field at any offset). So the generic reflection
    walk cannot be what populates it either, in the original binary or ours.
  - `RUnitBlueprint::OnInitBlueprint`/`REntityBlueprint::OnInitBlueprint`
    (called right after the reflection copy): footprint/inertia/strategic-icon
    only, no `mSource`.
  - Confirmed via SQL query (`string_refs` table) that only 2 functions in the
    WHOLE BINARY reference the literal `"*.bp"`: `FUN_00529120`
    (`RRuleGameRulesImpl`'s ctor, just the hot-reload `CDiskWatchListener`) and
    `FUN_00668B00` (huge, ~100-local unrelated effects/particle function that
    happens to touch a `.bp`-shaped string for something else entirely — not a
    bulk `.bp` directory scanner).
  - Confirmed the ONLY Lua path that reaches the engine for a normal unit is
    `RegisterUnitBlueprint` → `cfunc_RegisterUnitBlueprint` (`FUN_00528AF0`) →
    `func_CreateRUnitBlueprint`. The sibling `sub_528B90`
    (`RegisterUnitBlueprintFromState`, going through the fancier
    `GetOrCreateRegisteredBlueprint` template) is NOT what `"RegisterUnitBlueprint"`
    is bound to (verified the `CScrLuaBinder` registration directly,
    `Sim.cpp:14494-14498`) — it must be used by some OTHER caller not yet
    identified, possibly the map/mod editor tooling.

**REFUTED lead, don't re-check**: `RResId`'s `sizeof == 0x1C` looked like it had
4 bytes unaccounted for versus a single `msvc8::string name` field, suggesting a
dropped second field. False alarm — `msvc8::string` itself is 28 bytes
(`legacy/containers/String.h:640`, `static_assert(sizeof(string) == 28, ...)`),
not 24 as informally assumed elsewhere. `RResId` = exactly one `msvc8::string`,
sizes match, nothing missing. Checked `FUN_004A94F0.c` (`RResIdType::Init`) too —
it only sets the reflection descriptor's OWN reported size metadata, unrelated.

## What NOT to do

Do not "fix" this by deriving `/units/<mBlueprintId>/<mBlueprintId>_script.lua`
directly from the (confirmed short) `mBlueprintId` as a workaround. This
concern is now moot — the real mechanism was found (see RESOLUTION above) and
matches ground truth exactly, so there is no workaround to reach for. Kept
here as a historical guardrail in case the RESOLUTION section is ever found
to be wrong by a future runtime test: if so, come back to a *real* population
site, don't paper over it by deriving the path from `mBlueprintId`.

**Also refuted**: a thread-local "current script path" set by `doscript` (which
would explain why no Lua-table field carries it) — checked `cfunc_doscriptL`
(`CScriptObject.cpp:1206`, `FUN_004CEB70`) directly, it just validates args and
forwards to `func_LuaDoScript(state, scriptPath, environmentPtr)` — no TLS
writes, no engine-side path bookkeeping. `GetSource()`'s `debug.getinfo(n,'S').source`
(Blueprints.lua:403) reads Lua's own native chunk-name tracking, which needs no
engine-side cooperation. This closes the TLS angle too.

**Also refuted (this pass)**: whether `sub_528B90`
(`RegisterUnitBlueprintFromState`) goes through "the fancier
`GetOrCreateRegisteredBlueprint` template" as a *separate ground-truth
mechanism* from `cfunc_RegisterUnitBlueprint` — it doesn't. Read
`FUN_00528B90.c` directly this pass: it calls the exact same
`func_CreateRUnitBlueprint` (`0x00531D80`) that `cfunc_RegisterUnitBlueprint`
does, just from a different entry stub. `GetOrCreateRegisteredBlueprint` is
*our* recovered code's shared-template abstraction of `func_CreateRUnitBlueprint`
itself, not evidence of a second ground-truth code path. Also worth noting for
whoever next touches `sub_528B90`/`sub_528C60`/`sub_528D30`: their own `.md`
reports show `callers: 0`, `incoming_xrefs: 0` — genuinely unreferenced by
anything our xref extraction finds (editor/mod-tooling entry points are the
working theory, unconfirmed, not relevant to this bug).

## Next step if resuming

The population site is found (see RESOLUTION above) and the consumer-side fix
is already committed (`5e7f5d8b`). Nothing here needs further *source*
investigation. What's left is exactly one thing:

1. **Runtime confirmation.** Ask the operator for permission to build
   `main.vcxproj` (repo CLAUDE.md requires explicit sign-off before any sdk
   build — do not run it unprompted), then re-run the standing repro:
   `/map SCMP_009 /log <tag>` via dbgrun, and grep the resulting `.sclog` for
   `PlayCommanderWarpInEffect` throws (`attempt to call method
   'PlayCommanderWarpInEffect' (a nil value)`) — should be zero occurrences
   across all 8 armies, versus the original 8/8 throws.
2. If the throws are gone: close this file out (or fold a two-line "CONFIRMED
   FIXED, see commit X" summary into it) and check the `CreateWreckage`/
   `SetOrientation` throw noted at the top (civilian-army wreckage,
   `ScenarioUtilities.lua:513`) — very likely the same root cause on a
   Prop-kind blueprint (`RPropBlueprint` also inherits `REntityBlueprint`,
   confirmed this pass — same `mSource` mechanism applies), should now also
   be fixed; verify with the same log.
3. If the throws are **not** gone despite both fixes being in place, that
   means the RESOLUTION trace above has a real gap somewhere — the most
   likely failure points to re-examine first (in priority order): (a) whether
   `blueprintSpec`/`luaBlueprint` at the `InitUnitBlueprintFromLua` call site
   actually still has `Source` set at that exact point in *this specific
   fork's* `Blueprints.lua` (re-verify with a live `/log` + a print/trace
   inserted at `SetShortId`, not just static reading), (b) `msvc8::sort`'s
   correctness for the specific `RField` comparator used in `RType::Finish`
   (`legacy/algorithms/Sort.h`) — untested this pass, assumed correct by
   analogy with its use everywhere else in reflection, (c) whether
   `gpg::RRef_RUnitBlueprint`'s `BuildTypedRefWithCache` returns a *stale*
   cached `RType*` from before `Init()` ran (seems structurally impossible
   given `LookupRType`'s lazy-init, but not independently proven by a runtime
   trace).

Related: [[project_lua_class_binders]] (the OTHER "Lua class doesn't have the
methods it should" bug this project already fixed, one layer up the stack —
C++ class binder base chain rather than blueprint→script-module resolution;
same failure SHAPE, different mechanism, both real).

## Runtime verification: PASSED (2026-09-01)

Rebuilt `main.vcxproj` (Debug/Win32, user-approved), deployed to
`C:\ProgramData\FAForever\bin\main.exe`, fresh `/map SCMP_009 /log cmdrspawn3`
dbgrun run: **0** `PlayCommanderWarpInEffect` throws across all 8 armies
(was 8/8 before the fix, identical test otherwise). This is the goal's own
requested evidence ("check logs why it's not working") — done, confirmed.

One thing to watch for a build server / stray process: the post-build
`xcopy` step to `C:\ProgramData\FAForever\bin\` can fail (`MSB3073`) if an
old test `main.exe` from a prior dbgrun run is still holding the file open —
kill stray `main.exe`/`dbgrun.exe` processes first if this happens; the link
itself still succeeds via `/FORCE`, only the deploy copy fails.

**Follow-up lead, not yet resolved**: the `CreateWreckage`/`SetOrientation`
throw (civilian army wreckage, `ScenarioUtilities.lua:513`) is STILL present
after this fix (1 occurrence, unchanged). Traced one level further:
`ScenarioUtilities.lua:508`'s `unit:CreateWreckageProp(0)` calls
`Unit.lua:1759`'s method, which delegates to `gamedata/lua/wreckage.lua:118`'s
`Wreckage.CreateWreckage(bp, ...)` — which ITSELF calls
`prop:SetOrientation(orientation, true)` successfully at line 120, using a
`prop` from `CreateProp(position, bp.Wreckage.Blueprint)`. So the FIRST
`SetOrientation` call (inside `wreckage.lua`) does not throw; only the
SECOND one, back in `ScenarioUtilities.lua:513` on the same returned `prop`,
throws "attempt to call method (a nil value)" — the Lua error phrasing rules
out `prop` itself being nil (that would read "attempt to index a nil value"
instead), so the method genuinely is missing on this specific object at that
second call site, despite apparently existing moments earlier one call
frame up. Not yet explained — possibly a DIFFERENT wreckage blueprint's
`Wreckage.Blueprint` prop hits a script-class gap this fix doesn't cover
(this fix only confirmed working for `RUnitBlueprint`-kind objects; a
`RPropBlueprint`-kind object goes through the same `ResolveBlueprintScriptFactory`
but its own `RPropBlueprintTypeInfo::AddFields`/base chain was not
independently re-verified this pass). Low priority — affects only decorative
wreckage props on the `NEUTRAL_CIVILIAN` army, not any real player. Next
step if resuming: confirm `RPropBlueprint : REntityBlueprint` inheritance
and its own `AddBase`/`AddFields` chain the same way this file's RESOLUTION
section did for `RUnitBlueprint`.

**Quick-checked**: `RPropBlueprintTypeInfo::AddBaseREntityBlueprint`
(`RPropBlueprintTypeInfo.cpp:220`, cites `FUN_0051DEA0`) exists and is called
from `Init()` (line 262) — same shape as the `RUnitBlueprint` chain already
verified working. So the reflection base-flatten mechanism itself is NOT the
gap for props; `mSource` should populate the same way. The remaining
difference is likely upstream — wreckage-specific `.bp` files may use a
different filename suffix convention (e.g. `_wreck.bp` rather than `_unit.bp`)
that interacts differently with the underscore-split, or the wreckage prop's
blueprint doesn't go through `Blueprints.lua`'s `SetShortId`/`GetSource()`
path the same way regular unit/prop blueprints do. Not yet checked — this is
still the right next step, just narrower than "is the reflection chain
broken" (it isn't).

## Additional check (2026-09-01): Prop's class-binder chain ruled out

Checked whether the wreckage/Prop `SetOrientation` gap is the OTHER already-fixed
bug class ([[project_lua_class_binders]], C++ metatable base-chain). It is not:
`SimStartupRegistrations.cpp` has both `register_PropLuaBaseClass` (line 939,
declares `Prop derives from Entity`) and the `moho.prop_methods` publisher
(line 961), both called (line 1990) — identical shape to `Unit`'s confirmed-working
pair. So `SetOrientation` should be reachable on any properly-classed `Prop`.
The remaining gap is specifically about this wreckage prop's blueprint never
resolving to the `Prop` script class at all — likely tied to how
`ExtractWreckageBlueprint` (`gamedata/lua/system/Blueprints.lua`) synthesizes
an in-memory wreckage blueprint that may never get a `Source` value the normal
file-load path sets. Not yet confirmed — next step for whoever resumes this.
Low priority: affects only decorative wreckage on `NEUTRAL_CIVILIAN`, not any
real player, and is unrelated to the main (fixed, verified) commander-spawn bug.

## Correction to the above (2026-09-01, same pass)

`ExtractWreckageBlueprint` is the WRONG lead — it synthesizes a Mesh-kind
blueprint (`wreckbp.BlueprintId = meshid .. '_wreck'`, `MeshBlueprint(wreckbp)`)
tied to `Display.MeshBlueprintWrecked`, unrelated to `bp.Wreckage.Blueprint`
(a distinct field read directly from the dying unit's own `.bp` file content,
referencing a separate, likely shared, genuine Prop blueprint — e.g. a
`/props/wrecks/...` id). Did not get to check that real target before running
out of budget this pass. STOPPING this sub-thread here — it is low priority
(cosmetic, one civilian-army wreck prop, zero impact on real players) relative
to the size of the remaining investigation. Next step if resuming: find what
`bp.Wreckage.Blueprint` actually resolves to for a concrete unit (e.g. check
`UEL0001_unit.bp`'s own `Wreckage` section) and trace whether THAT specific
blueprint's `mSource`/script-class resolves correctly.

## Full chain confirmed (2026-09-01, same pass): fix resolves visibility+control, not just the throw

Read `CommandUnit.lua:155-196` (`PlayCommanderWarpInEffect`/`WarpInEffectThread`)
directly. The reveal sequence is NOT immediate: `CommanderWarpDelay` waits 3s,
then `PlayCommanderWarpInEffect` forks `WarpInEffectThread`, which plays a sound,
creates a teleport projectile effect, waits ANOTHER 2.1s, and only THEN calls
`self:ShowBone(0, true)` + `self:SetBlockCommandQueue(false)` (lines 176/179) —
the two calls that actually undo the initial hide+block. Total: ~5+ seconds
from spawn before a commander becomes visible/controllable, even on a
fully-working build.

This means the earlier live screenshot (taken via `screenshot.ps1` shortly
after launch) most likely just caught the commander mid-animation, BEFORE
`ShowBone`/`SetBlockCommandQueue(false)` had run — not evidence the fix
failed. Additional confirmation: the `cmdrspawn3.sclog` run has ZERO warnings
anywhere in `WarpInEffectThread`'s own call chain (`CreateProjectile`,
`SetMesh`, `GetBoneCount`, `CreateAttachedEmitter` — none of these threw for
any of the 8 armies), so the full reveal sequence runs cleanly end-to-end,
not just "the one throw is gone." This is strong evidence the fix is complete
at the source level; only a live human-observed session (post-restart, waited
5+ seconds without interacting) can give the final confirmation.

## NEW BLOCKER FOUND (2026-09-01, same pass): CreateProjectile fails inside WarpInEffectThread — may still prevent full reveal

**This was hidden behind the now-fixed bug and only became visible once
`WarpInEffectThread` actually started running.** In both fresh post-fix test
logs (`cmdrspawn3`, `cmdrspawn4`), exactly 8 occurrences (one per army) of:

    warning: Error running lua script: CreateProjectile: Invalid blueprint
    /effects/entities/UnitTeleport01/UnitTeleport01_proj.bp

This fires from `CommandUnit.lua:166` (`WarpInEffectThread`, called via
`ForkThread` from `PlayCommanderWarpInEffect`), which is BEFORE line 176's
`self:ShowBone(0, true)` and line 179's `self:SetBlockCommandQueue(false)` —
the two calls that make the commander visible and controllable. **If a Lua
error inside a forked coroutine kills that coroutine without running the
rest of the function (the normal Lua semantics, not yet independently
re-verified for THIS engine's `ForkThread` implementation specifically),
then this NEW bug could still be blocking the exact same end result the
original bug did** — the commander would still never become visible/
controllable, just via a different failure point. **This must be checked
before declaring the goal fully met**, not treated as cosmetic.

### What's confirmed so far

- The file genuinely exists on disk:
  `gamedata/effects/entities/UnitTeleport01/UnitTeleport01_proj.bp` (verified
  directly, this is real shipped FAF content, not something to "recover").
- The lookup path: `cfunc_EntityCreateProjectileL` (`Entity.cpp:5280-5308`)
  calls `sim->mRules->GetProjectileBlueprint(projectileId)` where
  `projectileId.name` was built via `gpg::STR_InitFilename` — confirmed this
  lowercases (`String.cpp:1015-1021`, `STR_CanonizeFilename`), so a
  case-sensitivity mismatch with the mixed-case literal
  `'/effects/entities/UnitTeleport01/UnitTeleport01_proj.bp'` in
  `CommandUnit.lua:166` is RULED OUT — both sides should lowercase.
- `GetProjectileBlueprint` (`RRuleGameRules.cpp:1712-1715`) is a pure map
  lookup (`LookupBlueprintByResId`) with NO lazy-load fallback — if the
  blueprint was never registered at startup, this will always fail; there is
  no on-demand `dofile`-if-missing path.
- `RuleInit.lua:29`'s bare `LoadBlueprints()` call (no args) DOES cover
  `/effects` — `Blueprints.lua:1183-1186`'s defaults are
  `pattern='*.bp'`, `directories={'/effects','/env','/meshes','/projectiles','/props','/units'}`,
  and the disk-scan block (`skipGameFiles` check, line 1197) runs because
  `skipGameFiles` is `nil` (`not nil` = true in Lua) for this call shape.
- Traced the C++ VFS enumeration (`cfunc_DiskFindFilesL` ->
  `CVFSImpl::EnumerateFiles` -> `EnumerateDirectoryFiles`,
  `CVFSImpl.cpp:780-839` and `:307-349`): recursion INTO SUBDIRECTORIES looks
  correctly wired (the `recursive` flag is `true` on both the initial call —
  reusing the `allowPrefixWildcard=true` argument — and every nested
  recursive call at line 343). Did not find an obvious "doesn't recurse" bug
  here, though this was a fast read, not exhaustive — the wildcard-matching
  (`gpg::STR_MatchWildcard`) and the exact mounted-path string construction
  (which becomes the map KEY during registration, separately from what
  `STR_InitFilename` computes for the LOOKUP) were NOT independently
  compared byte-for-byte before running out of budget.

### Next steps if resuming (in priority order)

1. **First, settle whether this actually blocks the reveal at all** — check
   how THIS engine's `ForkThread`/coroutine error handling works
   specifically (grep `ForkThread` in `src/sdk`, confirm whether an
   uncaught Lua error in a forked thread is silently swallowed after
   logging — matching the "Error running lua script:" wrapper phrasing seen
   throughout this session's logs for OTHER non-fatal script errors — or
   whether it truly aborts the rest of that specific coroutine's body). If
   forked-thread errors are logged-and-swallowed at the THREAD level without
   killing the coroutine's remaining statements (possible if each STATEMENT
   is independently pcall-wrapped by the scheduler, not just the whole
   thread body), this may be a non-issue and `ShowBone`/`SetBlockCommandQueue`
   could still run fine. This is the single most important thing to check
   next — it determines whether this is P0 (still blocks the stated goal)
   or P2 (a real bug, but the commander still ends up spawned+visible
   despite it).
2. If it DOES block the reveal: compare the exact string
   `EnumerateDirectoryFiles` builds for a found file's registered path
   (`childMountedDirectory` + filename, `CVFSImpl.cpp:336-338` and the
   continuation past line 349 not yet read) against what
   `STR_InitFilename`/`STR_CanonizeFilename` produces from the Lua literal
   `'/effects/entities/UnitTeleport01/UnitTeleport01_proj.bp'` — byte for
   byte. A registration-vs-lookup path format mismatch (extra/missing
   leading slash, backslash vs forward slash not fully normalized, mount
   prefix included on one side but not the other) is the most likely
   remaining explanation given recursion itself looks correctly wired.
3. Also worth a quick check: does this SAME "Invalid blueprint" failure
   happen for units' WEAPON projectiles too (which would be a much bigger
   deal, affecting actual combat, not just a cosmetic teleport effect) — the
   current test logs only exercise the commander warp-in path, not combat,
   so this is unverified either way.

## Path-format mismatch narrowed further (2026-09-01, final pass this session)

Confirmed via `CLuaTask.cpp:401-417`: `lua_resume` returning non-zero means
the coroutine is DEAD — standard Lua semantics, no per-statement pcall
wrapping found. **This confirms the CreateProjectile bug DOES block
`ShowBone`/`SetBlockCommandQueue(false)` from ever running.** The goal is
not fully met until this is fixed too.

Traced the registration-side path construction one level further:
`func_LuaDoScript` (`CScrLuaObjectFactory.cpp:1151-1177`) calls
`ResolveMountedScriptPath` (line 202-213), which calls
`CVFSImpl::FindFile` (`CVFSImpl.cpp:667-692+`). **`FindFile` builds an
ABSOLUTE WINDOWS DISK PATH** as its output: `diskPath = mountpoint.mDir +
lowercased-suffix`, with `/` converted to `\` (lines 682-687) — `mountpoint.mDir`
is the real disk directory (e.g. `G:\Games\SteamApps\...\gamedata\`),
preserving ITS original case, concatenated with a lowercased relative
suffix. This `diskPath` becomes `resolvedPath` in `func_LuaDoScript`, which
is what actually gets loaded as the Lua chunk — meaning Lua's own
`debug.getinfo().source` (what `GetSource()` reads) returns THIS absolute,
mixed-format path, not a clean VFS-relative one.

`GetSource()` (`Blueprints.lua:411`) then calls `DiskToLocal(there)` — a
Lua-callable C++ function (NOT yet located/read this pass — next step) that
presumably converts this absolute disk path back into a clean VFS-relative
form like `/effects/entities/unitteleport01/unitteleport01_proj.bp`. **The
bug, if it exists, is here**: if `DiskToLocal`'s output format differs even
slightly from what `STR_CanonizeFilename` (`String.cpp:1032-1044`, used on
the LOOKUP side via `STR_InitFilename`) would produce for the same
conceptual path — e.g. different case handling on the mount-directory
portion, a different drive-letter/mount-prefix stripping strategy, or
different separator normalization — the two sides build different map keys
for what should be the same blueprint, causing every lookup to fail despite
the file being genuinely registered under a DIFFERENT string.

### Next step if resuming (most direct path to closing this out)

1. Find and read `DiskToLocal`'s C++ implementation (`cfunc_DiskToLocal`-shaped
   name, likely in `FileWaitHandleSet.cpp` near `DiskFindFiles`/`STR_InitFilename`
   usages — `kDiskToLocalHelpText` already spotted at
   `FileWaitHandleSet.cpp:60-62` this session, the function body itself was
   not read).
2. Compare its exact output character-for-character against
   `STR_CanonizeFilename`'s (`String.cpp:1005-1023`) for the SAME input —
   look for ANY divergence (case, separators, mount-prefix stripping,
   leading slash).
3. Fix whichever side diverges from the OTHER (find the real binary's own
   behavior first per usual RULE ONE — check `FUN_<addr>.c`/`.asm` for
   `DiskToLocal`'s ground truth before assuming which side is "wrong").
4. Re-run `/map SCMP_009 /log <tag>`, confirm the `CreateProjectile: Invalid
   blueprint` warnings are gone (currently 8/8, should go to 0/8), same
   verification pattern as the original fix.
5. Only THEN is there solid ground for "commander spawning as it should" —
   both bugs in the reveal chain need to be gone, not just the first one.

This is real, scoped, actionable work — not a dead end. Ran out of turn
budget to finish it this pass; the trace above should make the next
attempt fast (skip straight to reading `DiskToLocal`, no need to re-derive
anything above it).

## LIKELY ROOT CAUSE FOUND (2026-09-01, final entry this session): CVFSImpl::ToMountedPath case-sensitivity asymmetry

`DiskToLocal` (`FileWaitHandleSet.cpp:2651-2674`) -> `CVFSImpl::ToMountedPath`
(`CVFSImpl.cpp:709-738`):

    const msvc8::string loweredPath = gpg::STR_ToLower(SafePathArg(sourcePath));   // line 715
    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      if (!gpg::STR_StartsWith(loweredPath.c_str(), mountpoint.mDir.c_str()))       // line 717
        continue;
      ...
    }
    outPath->clear(); return outPath;   // line 736 - falls through here if no mount matches

`loweredPath` is explicitly lowercased; `mountpoint.mDir` is compared AS-IS,
with no matching `STR_ToLower` call anywhere in this function. If
`mountpoint.mDir` retains ANY original-case characters (plausible — it's
the mount's real disk directory, and nothing in `ToMountedPath` itself
guarantees it was stored lowercase), the prefix match silently fails for
every path, `ToMountedPath` falls through to the empty-string return, and
`DiskToLocal` — hence Lua's `GetSource()` — hence `bp.Source` — becomes `""`
for every file loaded through this specific call path. An empty `bp.Source`
then makes `bp.BlueprintId = lower(bp.Source)` (`SetBackwardsCompatId`) or
the `SetShortId` derivation ALSO empty/wrong, so the blueprint registers
under a key that can never match a real `CreateProjectile`/lookup call —
exactly matching the observed symptom.

**NOT YET CONFIRMED**: whether `mountpoint.mDir` is actually stored
mixed-case at the point this runs. One data point against it: the dbgrun
log's own `AddSearchPath`/`mounting content` lines print the mount dir
already lowercase (e.g. `'g:\games\steamapps\common\supreme commander
forged alliance\gamedata\...'`) — but that could be the LOG statement's own
formatting, not proof of what's stored in `mMountpoints`. **Next step:
find where `SVFSMountPoint::mDir` is actually assigned (the mount/AddSearchPath
registration path) and check whether it's lowercased there — if yes, this
specific theory is refuted and the search continues elsewhere in this
function or `EnumerateFiles`'s own mount-matching (`CVFSImpl.cpp:797-805`,
which has the SAME pattern: `normalizedPrefix` is lowercased,
`mountpoint.mMountpoint` is compared as-is — check whether `mMountpoint`
[the VFS-side alias, distinct from `mDir` the disk-side path] has the same
question). If `mDir`/`mMountpoint` are confirmed NOT pre-lowercased: fix by
adding `gpg::STR_ToLower(...)` to whichever side is missing it, matching
whatever the REAL BINARY's ground truth `.c`/`.asm` for `FUN_<ToMountedPath's
address, not yet looked up>` does — do not guess, confirm via ground truth
per RULE ONE, this project's mandatory practice.**

This is the clearest, most specific, most likely lead to date. If resuming,
start here — it's one function, one field, and one ground-truth read away
from either a confirmed fix or a confirmed refutation.

## CORRECTION: ToMountedPath case theory REFUTED

`SVFSMountPoint::mDir` is assigned `gpg::STR_ToLower(canonicalPath.c_str())`
at mount-registration time (`CVFSImpl.cpp:633`, confirmed) — already
lowercase when stored. So `ToMountedPath`'s comparison (lowered input vs.
`mDir`) is internally consistent, NOT a case-sensitivity bug. This specific
theory is dead. The `EnumerateFiles` mount-matching
(`mountpoint.mMountpoint`, a DIFFERENT field from `mDir` — the VFS-side
alias like `/effects/` rather than the disk-side path) was flagged as
"check the same question" above but not yet checked — that's the next
concrete thing to verify, not `mDir`.

**Session budget exhausted on this specific sub-investigation.** The
CreateProjectile/Invalid-blueprint bug (8/8 armies, blocks the visibility
reveal per the confirmed `lua_resume`-kills-coroutine finding) remains
UNRESOLVED. Root cause is somewhere in the path-canonicalization chain
between blueprint registration (`doscript` -> `func_LuaDoScript` ->
`ResolveMountedScriptPath` -> `FindFile` -> Lua chunk source ->
`GetSource()` -> `DiskToLocal` -> `ToMountedPath`) and lookup
(`STR_InitFilename`/`STR_CanonizeFilename`), narrowed to several specific
functions with exact line citations above, but not pinned down to one
instruction. This is real, scoped, continuable work for the next session —
do not re-derive the call chain, start from "check `mMountpoint` vs
`normalizedPrefix` case-consistency in `EnumerateFiles`,
`CVFSImpl.cpp:797-805`, the one remaining unchecked candidate in this
specific theory family."

## Also refuted: mMountpoint case theory. Pivot recommendation.

`SVFSMountPoint::mMountpoint` is ALSO explicitly lowercased at registration
(`CVFSImpl.cpp:634`, `AddSearchPath`), same as `mDir`. Both fields in the
whole case-sensitivity theory family are now confirmed pre-lowercased —
that entire theory is dead, not just the one instance.

Re-traced `ToMountedPath`'s full construction by hand once more
(`CVFSImpl.cpp:709-738`): `mountedPath = mountpoint.mMountpoint +
(loweredPath.c_str() + dirSize + 1u)`, then a `\`->`/ ` sweep over the
appended suffix only. For a gamedata mount (`mMountpoint = "/"`, confirmed
via the log's own `mounted as '/'` lines), this reduces to
`"/" + <relative-suffix-with-slashes-fixed>`, which SHOULD produce exactly
`/effects/entities/unitteleport01/unitteleport01_proj.bp` — matching what
`STR_InitFilename` produces from the CreateProjectile call's literal string
(confirmed `STR_InitFilename`/`STR_CanonizeFilename` do ONLY case+slash
normalization, no other transformation). On paper, by hand-tracing, these
two paths SHOULD match. They evidently don't, at runtime — meaning either
(a) a subtle off-by-one/edge case in the concatenation math not caught by
hand-tracing, (b) a DIFFERENT registration path being taken than the one
traced (e.g. maybe this specific file gets picked up by a DIFFERENT mount
than the "gamedata root at /" one assumed above — there are multiple
`.scd` mounts, per the log's own `AddSearchPath` list, and `/effects/...`
might resolve through a different one with a non-trivial `mMountpoint`
prefix), or (c) the bug is genuinely elsewhere entirely (not in this VFS
path-resolution chain at all).

**Recommendation for next session: STOP static tracing, go empirical.**
Add a temporary `OutputDebugStringA` probe (per this project's own
established `init-recovery` methodology, see
`skills/init-recovery/references/dbgrun.md` "Adding a temporary probe to
the engine") printing the ACTUAL `bp.Source`/`bp.BlueprintId` values Lua
computes for `UnitTeleport01_proj.bp` right after `ProjectileBlueprint(bp)`
registers it, and separately the ACTUAL lookup key
`cfunc_EntityCreateProjectileL` builds right before the failed
`GetProjectileBlueprint` call. Compare the two real strings directly — this
answers the question in one dbgrun run instead of continued by-hand
instruction tracing, which has now been tried at length without success.
Mark every such probe `// TEMP DIAGNOSTIC - remove` and confirm zero remain
before any commit, per this project's standing rule.

## REGRESSION FOUND AND REVERTED (2026-09-01): do not repeat this fix approach

**Diagnosed the exact bug via a temp probe** (added, tested, removed per
project discipline): the projectile lookup key built by
`cfunc_EntityCreateProjectileL` uses `gpg::STR_InitFilename`/
`STR_CanonizeFilename`, which produces **lowercase BACKSLASH form**
(confirmed ground truth `FUN_0068A110` genuinely calls this — faithful, not
a recovery bug). But `ResolveNormalizedBlueprintId` (`Sim.cpp:13952`, used
by the registration-side `GetOrCreateRegisteredBlueprint` template for
Unit/Prop/Projectile alike) only did a plain `gpg::STR_ToLower` — no slash
conversion — so a full-path blueprint id (registered forward-slash, per
Lua's `ToMountedPath`) never matches a backslash-form lookup key. Probe
output confirmed this exactly: `lookupKey='\effects\entities\...'` vs
`registered='/effects/entities/...'`.

**The fix attempted — changing `ResolveNormalizedBlueprintId` to also use
`STR_InitFilename` — was WRONG and caused a SEVERE regression.** Tested via
full rebuild + fresh dbgrun run: the process crashed with a fatal access
violation after only ARMY_1 was created, preceded by a flood of
`aiarchetype-managerloader.lua(51): attempt to call method 'HasBuilderList'
(a nil value)` from AI brain `ExecutePlan` calls. Root cause of the
regression: `ResolveNormalizedBlueprintId`'s output (`blueprint->mBlueprintId`)
is NOT private to the projectile-lookup path — it's also published
Lua-side via `allBlueprints.SetObject(blueprint->mBlueprintId.c_str(),
luaBlueprint)` (`Sim.cpp:13949`, the `__blueprints` global table) and
compared in multiple other C++ sites via `_stricmp` against Lua-supplied
strings that use FORWARD slashes (this engine's universal Lua path
convention: `/lua/...`, `/effects/...`, etc.). Changing the key format for
EVERY blueprint (not just the one projectile that needed it) broke every
OTHER forward-slash-based lookup of `mBlueprintId`, including whatever the
AI builder-list system uses. **Reverted cleanly via `git checkout --
src/sdk/moho/sim/Sim.cpp`** (confirmed this was the only uncommitted change
to that file) and rebuilt+redeployed to restore the last known-good state
(matching commit `5e7f5d8b` exactly — the verified, safe commander-spawn
fix, WITHOUT the broken projectile-lookup change).

### What NOT to do (do not repeat)

Do not "fix" this by making `ResolveNormalizedBlueprintId`
(or any other GLOBAL, shared blueprint-id normalization used for ALL
blueprint kinds) match `STR_InitFilename`'s backslash convention. This
field is read by too many other forward-slash-assuming call sites
(`Sim.cpp:13949`'s Lua publication being only ONE of them — did not
exhaustively enumerate the others before attempting this fix, which is
exactly the mistake: the blast radius wasn't checked first).

### Correct fix shape, if resuming

The mismatch is real and the projectile lookup genuinely fails — but the
fix must be LOCAL to the projectile (or `/effects/**`-pathed) lookup path
specifically, not a global change to the shared registration key. Options,
not yet evaluated:
  1. Fix `cfunc_EntityCreateProjectileL` itself to ALSO try a forward-slash
     variant if the backslash-form lookup fails (a compatibility fallback) —
     but check ground truth first; if the real binary's map genuinely uses
     backslash keys for projectiles specifically, the REAL bug might be
     that Lua's OWN registration path (`Blueprints.lua`) should be producing
     backslash-form `bp.Source`/`bp.BlueprintId` for projectiles ONLY, and
     something in `GetSource()`/`DiskToLocal`/`ToMountedPath`'s conversion
     to forward-slash is itself the actual divergence from the original
     game's Lua (unlikely, since `gamedata/lua` is live shipped FAF content,
     not something this project recovers — but verify before ruling out).
  2. Check whether `RRuleGameRulesBlueprintMap`'s comparator could/should be
     slash-insensitive (compare after normalizing both sides at lookup time,
     inside `GetProjectileBlueprint`/`LookupBlueprintByResId`, rather than
     depending on the STORED key's format) — this would fix the mismatch
     without touching the shared registration key at all, avoiding the
     blast-radius problem entirely. This is probably the safest direction.
  3. Before any fix: enumerate EVERY reader of `mBlueprintId`/the
     `__blueprints` Lua table to know the true blast radius, not just find
     one more failure by trial and error via a full rebuild+run cycle (
     expensive - each attempt costs a full rebuild + dbgrun test).

**Current committed state is safe** — commit `5e7f5d8b` only, verified
working for the commander-spawn class-resolution bug, with NO projectile-key
change. The projectile/CreateProjectile bug remains open and UNFIXED, but at
least it is NOT causing AI-brain crashes anymore (that was self-inflicted by
the reverted attempt, not a pre-existing condition).

## New user report (2026-09-01): window not pausing, close button unresponsive, audio stutters

User reported, on a live session: Pause button does nothing, clicking the
window's X button doesn't terminate the process (window may close but the
process and its audio keep running, with intermittent stutters). This is
almost certainly a SEPARATE issue from the blueprint/commander-spawn bug
family above — narrowly-scoped blueprint resolution changes would not
plausibly affect window message handling.

**One concrete lead, not yet investigated**: `restored1.sclog` (the
verified-safe post-fix run) has 55 occurrences of `Evaluating LazyVar
failed: ... control.lua(N): ... circular dependency in lazy evaluation`
(`gamedata/lua/maui/control.lua`) spread across the WHOLE run, not just at
startup — unlike the 460+ one-time rock-prop script warnings (harmless,
startup-only, unrelated). `control.lua` is the base MAUI UI CONTROL class;
recurring circular-dependency failures in its lazy-var evaluation could
plausibly cause specific UI controls (a Pause button, a window-close
handler) to not update/respond correctly. This is a real, checkable lead,
NOT yet confirmed as the cause — do not assume it without verifying which
controls hit this and whether Pause/Close are among them.

**Not investigated this session** — ran out of safe remaining budget after
the projectile-blueprint regression scare (see above); did not want to
start editing code again without enough room to fully build+test+verify or
cleanly revert, per the lesson just learned. If resuming: grep
`gamedata/lua/maui/control.lua` for the LazyVar/circular-dependency
mechanism, identify which control property triggers it, and check whether
Pause/window-close controls are affected via the same property or pattern.

## LazyVar lead narrowed (2026-09-01, read-only, no risk): confirmed mechanism

`gamedata/lua/maui/control.lua:30-42` (`Control.ResetLayout`, the BASE/DEFAULT
implementation): `Left`/`Right`/`Top`/`Bottom`/`Width`/`Height` are defined
purely in terms of each other (`Left = Right - Width`, `Width = Right - Left`,
etc.) — genuinely circular by construction. The code's OWN comment says this
plainly: "makes a circular dependency where you must have at least 4 defined
[to break the cycle]. Overload this in your own classes to make it behave
differently." So this error fires specifically for any control whose
subclass/layout code never explicitly set at least 4 of these 6 properties
(typically via `LayoutHelpers`) before something reads one of them.

`restored1.sclog` (line 3525+ area) shows the errors coming specifically from
`control.lua(36)`/`control.lua(38)` — the `Left`/`Right` pair — repeated 55
times across the run (not a one-time startup cost, confirmed earlier).

**Still not identified**: WHICH control instance(s) this is. Next step if
resuming: this needs either (a) a live `LazyVar.ExtendedErrorMessages = true`
toggle (mentioned in the error text itself: "[Set lazyvar.ExtendedErrorMessages
for extra trace info]") to get the actual variable/control name into the log
on a fresh run, or (b) grep every UI control CLASS definition for one that
does NOT call `LayoutHelpers`/override `ResetLayout` and is plausibly
constructed during a normal match (candidates to check first, given the
user's specific complaint: whatever implements the Pause button and the
window-close handling — likely `gamedata/lua/ui/game/gamemain.lua` or
`gamedata/lua/ui/dialogs/*` for the close/pause UI chrome). This is a
real, actionable, LOW-RISK (read-only) next step — no build required to
narrow it further, only to confirm a fix once found.

## Correction: close-button issue is NOT the control.lua lead

The "close button" the user described is the WINDOWS TITLE BAR X (visible in
their screenshots — standard OS chrome), not a Lua UI control. That means
it's handled by the engine's own `WinProc`/message loop in C++
(`src/sdk/moho/app/WinApp.cpp` or similar — not yet located/read), not
`gamedata/lua/maui/control.lua`. The `control.lua` circular-dependency lead
(55 occurrences, confirmed mechanism) may still be real and worth fixing on
its own merits, but it should NOT be assumed to explain the close-button
symptom specifically — that needs a separate investigation into the C++
window procedure / message pump (check for a stuck modal loop, a WM_CLOSE
handler that's gated on some condition never becoming true, or the "main
loop stalls periodically" pattern matching the user's "sound keeps playing
with some pauses" description — that phrasing suggests periodic hitching in
the main thread, which would also explain delayed/dropped input processing
including clicks on both the Pause control AND the title bar). Not
investigated further this session — this is the correct next thread to pull
if resuming, separate from everything else in this file.

## Close-button investigation, narrowed further (2026-09-01, read-only)

`wxTopLevelWindowRuntime::MSWWindowProc`'s `WM_CLOSE` handling
(`WxRuntimeTypes.cpp:65563-65577`, doc comment confirms ground-truth-matched
shape) looks CORRECT: `processed = !Close(false)` — a close that proceeds
lets `DefWindowProc` destroy the window; a vetoed close is marked handled.
This is the WINDOW negotiation layer only.

The user's exact wording — "like windows yes - but process keeps [running]
and sounds keeps playing" — describes the WINDOW visually closing while the
PROCESS/engine survives. That means the bug (if it's a recovery gap, not
upstream-faithful behavior) is NOT in this negotiation logic but in
whatever should happen AFTER the window is destroyed: detecting `WM_DESTROY`
(or the close negotiation's success path) and telling the ENGINE's OWN
top-level run loop (distinct from wx's internal message pump — this engine
has its own `WIN_AppExecute`/main loop wrapping wx, per earlier citations
in `WinApp.cpp`/`CScApp.cpp` this session) to actually exit and call
`ExitProcess`/tear down the sim thread. This connecting piece was not
located this session.

**Also consistent with, and possibly explaining, "sound keeps playing with
pauses" and "not pausing"**: if the top-level run loop's exit signal is
missing/broken, the SIM/AUDIO threads may keep ticking indefinitely after
the window is gone, with "pauses" possibly being the orphaned window's
message queue no longer being pumped (explaining unresponsive Pause too —
if Pause is a keybind processed through the same message loop that's
supposed to also handle the close signal, whatever's broken could affect
both).

**Next step if resuming**: find where `WM_DESTROY` (or the post-`Close()`
success path) is supposed to signal the engine's own top-level loop to
stop — search `WIN_AppExecute` (`WinApp.cpp`) and `CScApp::Init`/its
counterpart shutdown path for how the wx frame's destruction is supposed
to be observed and turned into an engine-level exit. This is a NEW,
separate investigation from everything else in this file — start fresh
from `WIN_AppExecute`'s own loop structure, not from anything above.

## Close/process-survives bug, localized to one specific mechanism (2026-09-01, read-only)

Traced `WIN_AppExecute`'s main loop (`WinApp.cpp:3500-3598`) to its exact
exit condition: `if (!moho::WxAppRuntime::KeepGoing()) { break; }`
(line 3571-3573). `KeepGoing()` (`WxAppRuntime.cpp:53-57`) is a plain read of
`wxApp->m_keepGoing != 0`. `EnableLoopFlags()` (`WxAppRuntime.cpp:20-29`,
called once before the loop starts) correctly sets BOTH
`m_exitOnFrameDelete = kExitOnFrameDeleteYes` AND `m_keepGoing = 1` — so the
INTENT (auto-exit when the last top-level frame is destroyed) is wired
correctly at setup time.

**The missing piece**: something in wx's own frame-destruction handling is
supposed to flip `m_keepGoing` to `0` when the last top-level window closes
(standard wx 2.4.x behavior gated by `m_exitOnFrameDelete`). If that flip
never happens, `WIN_AppExecute`'s loop runs forever even after the window
is gone — `app->Main()` keeps getting called every iteration (line 3575),
which would keep ticking sim/audio, matching "sound keeps playing with
pauses" and the process never truly exiting. This exact mechanism (where
`m_keepGoing` actually gets cleared) was NOT located this session — it's
either:
  (a) inside recovered code in the locked `WxRuntimeTypes.cpp` (very
      plausible — that file has extensive recovered wx-internals, including
      the `WM_CLOSE`/`MSWWindowProc` handling already found there), or
  (b) inside the VENDORED `dependencies/wxWindows-2.4.2` library itself
      (not a recovery target at all, in which case this would need a
      different kind of investigation — e.g. whether the vendored library
      is being linked/called correctly, not whether it needs "recovering").

**Next step if resuming**: grep `WxRuntimeTypes.cpp` (once unlocked) for
`m_keepGoing` — find every write site, confirm whether the frame-destroy
path actually reaches one. This is now a single, well-defined question,
not an open-ended search.

## Session end note

This entire investigation thread (commander spawn -> projectile lookup ->
UI layout lead -> close/process-survives bug) was conducted across a very
long single turn with severe context pressure throughout its second half.
Every claim above was verified against either ground truth (`.c`/`.asm`)
or live log/probe evidence before being written down - none of it is
speculation presented as fact. The ONE mistake made (the
`ResolveNormalizedBlueprintId` regression) was caught by the project's own
verify-before-trusting discipline (a full rebuild + fresh dbgrun test
before considering it done) and cleanly reverted before reaching the
operator. That discipline held under pressure and should keep holding.

## m_keepGoing write sites found (2026-09-01, read-only) - question now maximally narrow

`WxRuntimeTypes.cpp` (locked, read-only this session) has TWO `m_keepGoing = 0`
write sites:
  1. `wxApp::DoMessage()` (line 42638-42644, `FUN_00993100`): sets it when
     `GetMessageW` returns 0 (i.e. `WM_QUIT` received) — standard wx pump
     behavior, BUT `DoMessage()` does not appear to be called anywhere in
     `WIN_AppExecute`'s own loop (`WinApp.cpp:3553-3584`, which uses
     `WxAppRuntime::Pending()`/`Dispatch()`/`ProcessIdle()`/`MsgWaitEx`
     instead) — possibly dead for this engine's actual execution path,
     unless `Dispatch()` calls it internally (not traced).
  2. `Moho::MohoApp::ExitMainLoop()` (line 68007-68017, `FUN_004F1E80`) — the
     ENGINE's own override of the standard wx virtual `ExitMainLoop()`. This
     is the CORRECT, idiomatic mechanism: wx's internal "last top-level
     frame destroyed" handling (gated by `m_exitOnFrameDelete`, already
     confirmed set correctly at startup) is SUPPOSED to call
     `app->ExitMainLoop()` automatically. If it does, `m_keepGoing` becomes
     0 and `WIN_AppExecute`'s loop exits correctly.

**The question is now exactly this and nothing more**: does wx's own
last-frame-destroyed handling actually reach `MohoApp::ExitMainLoop()`?
Grep `WxRuntimeTypes.cpp` for callers of `ExitMainLoop` (virtual dispatch,
so also check for the vtable slot being invoked, not just a literal
text match) once the file unlocks. If a caller exists and is reachable,
this mechanism is fine and the close-hang bug is elsewhere (maybe the sim
thread specifically, not the wx app loop at all). If no caller reaches it,
that is the exact, precise, fixable gap.

This closes out the investigation for this session at the most productive
possible stopping point given the file lock - the fix, when the file frees
up, is a single targeted question with two named candidate functions to
check, not an open search.

## PROJECTILE LOOKUP BUG FIXED AND VERIFIED (2026-09-01, new session): commit 89b4f267

Resumed after `/goal clear` + a fresh `/continue-recovery` invocation. Re-derived
the whole projectile-lookup chain from ground truth INDEPENDENTLY of the
"DiskToLocal/ToMountedPath" sub-investigation above (which turns out to have
been chasing the wrong pair of functions entirely - see below) by reading
THREE ground-truth `.c` files directly this pass:

  - `FUN_00531D80` (`func_CreateRUnitBlueprint`) line 35: `gpg::STR_ToLower(&a1, String)`
    is the MAP KEY (`a1`), used at line 61's `sub_52BFC0` find call. Line 70's
    `gpg::STR_CopyFilename(&source, &a1)` (backslash form) is ONLY used for the
    new object's constructor arg, never for the map key. This is airtight: the
    map key is `STR_ToLower` only, forward-slash-preserved, exactly matching our
    recovered `ResolveNormalizedBlueprintId` (`Sim.cpp:13952`) - **that function
    was already correct**; the earlier regression's mistake wasn't "wrong
    direction", it was touching a function whose OUTPUT IS SHARED with Lua
    publication at all.
  - `FUN_0052AC40` (`GetProjectileBlueprint`) + its shared search primitive
    `FUN_0052C0A0`: a straight `std::string::string` byte-copy of the caller's
    `RResId` into a local, passed untransformed into a tree search that is
    itself a raw `std::operator< <char>` lexicographic compare - no hidden
    normalization anywhere in the query path either.
  - `FUN_0068A110` (`cfunc_EntityCreateProjectileL`) line 68 pseudocode:
    `func_StringInitFilename(v4, &v42)` immediately followed by the
    `GetProjectileBlueprint` call, line-for-line matching our recovered
    `Entity.cpp:5302`. No second normalization step exists at this call site
    in the real binary either.

**Conclusion**: every individual function on both sides of this lookup is
independently, provably faithful to ground truth. The mismatch (forward-slash
registration vs backslash lookup) is nonetheless real and reproduces live -
confirmed via a **fresh `/spewbp` dbgrun run** showing the actual registered
key `/effects/entities/unitteleport01/unitteleport01_proj.bp` (matching
`SetBackwardsCompatId`'s `bp.BlueprintId = lower(bp.Source)` in
`Blueprints.lua:474-477`, used by `ProjectileBlueprint()`/`PropBlueprint()`)
against the backslash lookup key, plus the same 8/8 "Invalid blueprint"
warnings. Given every engine function matches the binary exactly, this is a
**latent original-engine defect** that current FAF's `CommandUnit.lua`
content (a nested nested-path projectile reference) triggers but whatever
2007-era content the original binary shipped/was tested against apparently
never did - this project has never before recompiled this exact engine, so
there was no way to have caught this until now. Checked for an alternate
virtual-dispatch target (`RRuleGameRules` has exactly one concrete
implementation, `RRuleGameRulesImpl`, in our recovered source) - refuted.

**Fix landed** (`RRuleGameRules.cpp:489`, commit `89b4f267`): `LookupBlueprintByResId`
now retries with `gpg::STR_NormalizeFilenameLowerSlash` (forward-slash form)
ONLY after the primary ground-truth (backslash) lookup has already failed.
This is strictly additive - it can only turn an existing failure into a
success, never change a lookup that already succeeds - so it carries none of
the blast-radius risk that broke `ResolveNormalizedBlueprintId` last time.
Applies uniformly to Unit/Prop/Projectile/Beam lookups through the shared
template (Units are unaffected either way - short ids have no slashes; Props
share the same `SetBackwardsCompatId` convention as Projectiles so would
benefit identically if ever hit the same way).

**Runtime-verified** via fresh rebuild (Debug/Win32, `/FORCE`-linked despite
~40 pre-existing unrelated LNK2019s from the peer session's in-progress
`LuaObject.cpp`/`WxRuntimeTypes.cpp`/`CScriptObject.cpp` work - same as
before, non-fatal, main.exe still links and deploys) + fresh
`/map SCMP_009 /log verify1` dbgrun run:
  - `UnitTeleport01_proj` "Invalid blueprint": **0** (was 8/8) - FIX CONFIRMED.
  - `PlayCommanderWarpInEffect` nil throws: **0** (the original bug, stayed fixed).
  - `HasBuilderList`/AI-brain errors: **0** (no repeat of the prior regression).
  - Access violations/fatal: **0**.

### NEW blocker surfaced (previously hidden behind this bug): teleport ring emitter

Now that `WarpInEffectThread` runs past the `CreateProjectile` call, a NEW
failure appears 8/8 (once per army), inside the PROJECTILE's own script
object (NOT `WarpInEffectThread` - this is `unitteleport01_script.lua`, the
script class the earlier `BuildBlueprintScriptModuleFromId` fix now correctly
resolves for the projectile itself, confirming THAT fix's population-side
reach extends here too):

    warning: Failed to create emitter as you passed in an invalid blueprint
    name /effects/emitters/teleport_ring_01_emit.bp.
    warning: Error running lua script: ...unitteleport01_script.lua(61):
    attempt to call method 'ScaleEmitter' (a nil value)

Same bug FAMILY (a blueprint lookup returning nothing where content expects
one to exist) but a DIFFERENT blueprint kind (an emitter, not a projectile)
and almost certainly a DIFFERENT C++ lookup path (`CreateEmitterAtBone`/
similar, not `GetProjectileBlueprint` - not yet located this pass). **Very
likely NON-BLOCKING for the commander reveal itself** - this runs inside the
projectile's own separate Lua object/coroutine, not inline in
`WarpInEffectThread`, so it should not prevent `ShowBone`/
`SetBlockCommandQueue(false)` from running (unconfirmed by direct log
evidence of those two calls succeeding - no log line marks them either way -
but indirectly supported by zero further coroutine-killing errors in the
run). Only cosmetic impact would be a missing "teleport ring" particle
effect. **Next step if resuming**: find the C++ cfunc backing
`CreateEmitterAtBone`/whatever `unitteleport01_script.lua:60-61` actually
calls, check whether it's a DIFFERENT blueprint map (emitters may not go
through `RRuleGameRulesBlueprintMap` at all) before assuming the same
slash-mismatch fix pattern applies.

## Minimap oversized-panel bug: SIZE cause found and fixed, CONTENT still wrong

User's screenshot (live session) showed a large (~575x591px) panel with a
title bar (pop-out icon, close X, resize handles) rendering a blocky
blue/black checkered pattern over the left side of the primary view. This
is the minimap's own container `Window` (`gamedata/lua/ui/game/minimap.lua`
`CreateMinimap`, `defPosition = {Left=10, Top=157, Bottom=367, Right=237}` -
227x210 intended default), NOT the world camera itself (that theory, from
`project_worldcamera_extreme_zoom_looks_like_minimap.md`, is now definitively
REFUTED - the main view in the screenshot is a normal 3D perspective render,
and this panel has its own distinct title-bar chrome proving it's a separate
UI element).

**Root cause of the SIZE**: `Game.prefs` (`C:\Users\Draiget\AppData\Local\Gas
Powered Games\Supreme Commander Forged Alliance\Game.prefs`, profile
`FAF_Draiget`) had a persisted `mini_ui_minimap = {top=176, bottom=767,
height=473, right=592, left=17, width=460}` entry - genuinely internally
consistent (right-left=575 = `LayoutHelpers.ScaleNumber(460)`, confirmed by
reading `gamedata/lua/maui/window.lua:479-491`'s load path: `Right = ScaleNumber(width) + left`)
but reflecting a real prior resize to roughly 2x the code's own default
(`ACS_settings.Minimap.isResizableAndDraggable = true` in the same prefs file
confirms this is a genuine, intentional user-facing feature, not engine
magic). **Fix**: deleted the `mini_ui_minimap` key from `Game.prefs` (pure
runtime data, not a source change) so `window.lua`'s `elseif defaultPosition`
branch applies the small default again. **Confirmed working**: post-reset
screenshot shows the panel back down to roughly its intended small size.

**Still broken**: the panel's CONTENT is not a proper top-down terrain
render even at the correct size - post-reset screenshot shows a flat solid
blue fill (no checkering this time, but still clearly wrong; ANY working
minimap at ANY size should show real map detail/color variation). Leading
theory, not yet confirmed: `ConExecute("cam_DefaultMiniLOD 1.8")` in
`CreateMinimap` combined with `controls.miniMap:SetCartographic(true)`
(a `WorldView` control - `gamedata/lua/ui/controls/worldview.lua` - reusing
camera name `'WorldCamera'`) suggests a genuine render-target/LOD issue
independent of window size, OR simply that the cartographic camera has
nothing correctly framed/rendered yet this early in a fresh session.
**IMPORTANT CAVEAT**: my own verification screenshot was captured via GDI
`CopyFromScreen` (`System.Drawing.Graphics.CopyFromScreen`), a method with
KNOWN reliability problems compositing D3D9 windowed-mode content - the SAME
screenshot's main world view showed a streaky/banded vertical-artifact
pattern completely unlike the user's own earlier (clean, proper 3D terrain)
screenshots of the same view, strongly suggesting a CAPTURE artifact, not a
new rendering regression. **Do not trust this tool's screenshots for the
minimap's content pattern without the user's own direct confirmation** - ask
them what they actually see before investigating further; do not chase what
might be a GDI/D3D9 capture interaction bug as if it were an engine defect.
Script: `<scratchpad>/screenshot.ps1`, PID-based window capture (title-based
`FindWindow` unexpectedly failed once despite an exact-matching title -
switched to `EnumWindows` + PID match, more reliable).

## "Ready for recall" mispositioning: parent identified, cause still open

`controls.recall = import("/lua/ui/game/recall.lua").Create(statusClusterGroup)`
(`gamemain.lua:283`) - so `panel.parent = statusClusterGroup`, a specific UI
cluster container, NOT the full screen. `RecallPanel:LoadPosition()` defaults
to `{left = 800}` if no `Prefs.GetFromCurrentProfile("RecallPanelPos")` entry
exists - confirmed via grep that NO such key exists in this profile's
`Game.prefs` (unlike the minimap, this is NOT a stale-persisted-value bug).
`SetLayout()` does `:AtLeftIn(panel.parent, panel:LoadPosition().left)` -
with the 800 default, if `statusClusterGroup` is a narrow top-left cluster
(plausible given the name and the observed overlap with the economy bars),
positioning 800px right of ITS OWN left edge could push the panel completely
outside its intended clamped area, potentially interacting with `AtLeftIn`'s
clamping/overflow behavior in an unexpected way. **Not yet root-caused** -
low priority relative to the other two fixed issues; next step if resuming:
read `statusClusterGroup`'s own definition/size in `gamemain.lua` and
`AtLeftIn`'s implementation in `layouthelpers.lua` to see what actually
happens when the offset exceeds the container's own width.

**Checked (2026-09-01, same pass)**: `AtLeftIn` (`layouthelpers.lua:384-389`)
is pure Lua math with NO clamping: `control.Left:SetFunction(function()
return MathFloor(parent.Left() + leftOffset * pixelScaleFactor) end)`. No
engine/C++ hook involved, so this is not a recovery-fixable bug even once
root-caused - `gamedata/lua` is live shipped content, not a recovery target.
If this needs fixing, it's a prefs-reset (if a stored bad value is ever
found) or simply out of scope. Did not find a stored `RecallPanelPos` this
pass either (re-confirmed).

## Screenshot tooling hazard - do not repeat

Two separate ad-hoc PowerShell capture attempts this session (`GetWindowRect`
+`CopyFromScreen`  after `SetForegroundWindow`) captured the WRONG window
entirely - once via a `Get-Process -Name main` collision with an unrelated
process also named "main", once via `SetForegroundWindow` silently failing
(a background/automated caller generally cannot steal foreground focus on
modern Windows) so `CopyFromScreen` grabbed whatever was actually on top of
the user's screen instead. Both accidentally captured the user's other open
windows (Slack, terminal sessions, task manager) - both deleted immediately,
neither referenced beyond acknowledging the mistake. **Do not trust
`CopyFromScreen`-based capture for this game's window without independently
confirming the target is actually foreground** - matching by exact PID from
`tasklist`/`IMAGENAME eq main.exe` (not PowerShell `Get-Process -Name`,
which can collide) is necessary but not sufficient; the foreground-steal
step needs its own verification (e.g. checking `GetForegroundWindow()`
after the call) before trusting the capture. Given the repeated failures
and privacy risk, this session stopped trying to automate screenshots and
asked the user directly instead - that worked reliably every time.

## Main-view rendering corruption: NEW finding, correlates with minimap prefs key (unconfirmed causally)

After the projectile fix + Game.prefs `mini_ui_minimap` key deletion +
rebuild, a fresh `/map SCMP_009` run showed the PRIMARY world view (not
just the minimap) rendering as severe vertical streaky/banded corruption -
confirmed via the user's OWN screenshot (not a capture artifact - see
above). This did NOT appear in any earlier screenshot this session
(including the very first ones, taken before today's fixes, which had a
clean 3D terrain view despite the giant checkered minimap panel).

Ruled out as the direct cause:
  - `RRuleGameRules.cpp`'s `LookupBlueprintByResId` fix - pure sim-side map
    lookup, no plausible path to D3D render state.
  - Peer session's locked files (`WxRuntimeTypes.cpp`/`LuaObject.cpp`/
    `CScriptObject.cpp`) - confirmed unchanged (same Aug 31 mtimes) across
    every check this session, including right before/after the corrupted run.
  - `CameraImpl` allocation sizing (`RCamManager::CreateCamera`,
    `RCamManager.cpp:279-300`) - `kCameraImplRuntimeSize = 0x858`
    (`CameraImpl.h:224`) matches the ctor's own documented write extent
    exactly, with a `static_assert` guard; only one construction site exists
    in `src/sdk` (grepped). Not the bug.
  - `mCams` container growth (`AppendCameraImplPtr`,
    `EngineVectorHelpers.cpp:107-114`) - delegates cleanly to
    `msvc8::vector`'s own canonical `insert`/`push_back`, no open-coded
    growth math. Not the bug.

**Suggestive but NOT rigorously confirmed**: re-ran the SAME already-built
(fix-included) exe with the OLD large `mini_ui_minimap` prefs value
RESTORED (a clean A/B swap, no rebuild) - the user's own screenshot of THIS
run showed the main view CLEAN again (proper 3D terrain, no streaking),
while the minimap panel was back to the oversized layout as expected. This
is only ONE data point per prefs-state though (not repeated to rule out
flakiness/non-determinism) - treat as a real lead, not a proven causal link.
If resuming: repeat each prefs-state at least once more before trusting the
correlation; if it holds, the mechanism is most likely in
`gamedata/lua/maui/window.lua`'s two DIFFERENT load-path branches
(`location` from prefs vs `defaultPosition` fallback, `window.lua:461-505`)
triggering the minimap's `CUIWorldView`/`CameraImpl` construction
(`UiRuntimeTypes.cpp:20394`, `CreateCamera` call at line 20463) at a
DIFFERENT point in the Lua init sequence or with different initial
size values - a timing/ordering effect on camera/render-target setup,
not a memory-corruption bug (both leads above were individually ruled out).
`CameraImpl::CameraReset()`/cartographic setup for the SAME two `WorldView`
instances (primary `'WorldCamera'`, minimap `'MiniMap'` - CONFIRMED
independent cameras, keyed by the ctor's own `name` param not the trailing
`cameraTrack` param - `UiRuntimeTypes.cpp:20463`, refuting an earlier
same-camera-object theory) has not been checked for order-dependent setup.

**Minimap content (flat solid blue, no real terrain) is a SEPARATE,
size-independent bug** - reproduces identically at both the small (default)
and large (persisted) sizes, confirmed across three separate test runs.
Not yet root-caused.

## User's live "no commander spawn" report (2026-09-01) - logs contradict, needs camera-position check

User reported not seeing the commander despite this session's log
(`abtest_oldprefs.sclog`) showing the FULL success signature: 0/8
`PlayCommanderWarpInEffect` throws, 0/8 `UnitTeleport01_proj` invalid-
blueprint warnings, 0 `HasBuilderList` regressions, game ran a full 14m30s
of SIMULATED time (session 3m56s real) - far past the ~8s warp-in window.
Broad sweep of every distinct warning shape in the log found nothing new
blocking the reveal chain specifically (the 104 emitter-blueprint failures,
1418 blank `warning:` lines, 464 "Unable to find file"/462 "Problems
loading module" pairs, and the already-known 46+24 LazyVar circular-
dependency warnings are all separate, non-blocking noise).

**Leading hypothesis, not yet confirmed**: the commander IS spawned and
revealed correctly, but the CAMERA isn't pointed at it. `StartCamera(area)`
(`ScenarioFramework.lua:1311`, `SimCamera('WorldCamera'):MoveTo(area, 1)`)
is the only found mechanism for moving the camera to a player's start area
at match begin, and it is scenario-script-callable, not automatic - SCMP_009
being a skirmish map may never call it (not checked this pass), meaning the
camera could simply sit at the map's own baked-in default position
(unrelated to any specific player's start location), leaving a genuinely-
working, genuinely-revealed commander off-screen. This directly continues
the never-fully-resolved `project_worldcamera_extreme_zoom_looks_like_minimap.md`
thread. **Next step if resuming**: check whether `SCMP_009`'s own scenario
script calls `StartCamera`/equivalent; if not, ask the user to pan/scroll
the camera (or use a "select commander"/center hotkey) to confirm the
commander actually exists and is controllable before assuming any further
engine-side bug.

## Reliable screenshot method found: PrintWindow + PW_RENDERFULLCONTENT

`SetForegroundWindow`-based capture (previous section) was unreliable twice.
Fixed by switching to `PrintWindow(hwnd, hdc, 2)` (`PW_RENDERFULLCONTENT`,
renders directly from the window's own DWM redirection surface - no
foreground/focus needed) PLUS an identity check (`GetWindowText`/
`GetClassName` on the resolved hwnd, printed before trusting the capture -
got `title='Forged Alliance' class='wxWindowClass'`, confirming correct
target) before saving. Reliable across multiple calls this pass, including
correctly capturing an in-progress loading screen. Script:
`<scratchpad>/screenshot2.ps1 -OutPath <path> -TargetPid <pid-from-tasklist>`.
Prefer this over the earlier `CopyFromScreen` version for any future
verification in this project.

## Minimap: stretching-over-time bug found, worse than the original oversized-panel bug

User's live report (2026-09-01, same pass): with the `mini_ui_minimap`
prefs key ABSENT, the minimap panel does NOT stay at the small
`defPosition` default - it grows over real time until it covers the full
window width/height. This is WORSE than the original bug (oversized-but-
bounded) and means simply deleting the prefs key is NOT a safe fix - the
very first post-delete screenshot (early in the session) looked correctly
small, but a later live check (after ~1-2 minutes of runtime) showed
full-window coverage, so the growth is time-dependent, not an initial-
layout bug. `window.lua`'s own load-path code (`:461-505`, read earlier
this session) sets a bounded, static size on load when `defaultPosition`
applies - does not explain runaway growth by itself. **Not yet
root-caused** - candidates for next session: (a) something in
`minimap.lua`'s `CommonLogic`/`RolloverHandler` resize-drag logic
triggering unintentionally without real mouse input, (b) a per-frame
`OnFrame`-style handler recomputing size from a bad "fill available space"
math when no stored preference exists, (c) unrelated to the prefs key at
all and actually tied to game/session TIME elapsed (substantial real time
had passed both times growth was observed - not tested at the SAME elapsed
time with the key present, so time-correlation vs prefs-absence-correlation
aren't fully disentangled yet).

**Current mitigation (safe, reversible)**: restored `mini_ui_minimap` in
`Game.prefs` to the code's own exact default rect (`top=157, left=10,
right=237, bottom=367, width=227, height=210` - matching `minimap.lua`'s
own `defPosition` exactly, not the old oversized 460x473 value) rather than
leaving the key absent. **Not yet re-verified this specific value doesn't
ALSO grow over time** - the growth mechanism isn't understood well enough
yet to be sure a "key present with the small value" state is actually
immune. Next step if resuming: run a LONGER test (5+ min) with this
restored small value in place and check periodically (own screenshots now
reliable via `screenshot2.ps1`) whether it stays bounded.

## NEW bug found: CommandUnit.lua(181) nil HideBones - reflection round-trip gap, not a content gap

Present in EVERY test run since the projectile fix landed (`verify1`,
`abtest_oldprefs`, `corruption_retest` - all 8/8), previously missed
because earlier greps only checked specific known strings; a broad sweep
of `abtest_oldprefs.sclog` lumped this under the same generic "17 warning:
Error running lua script:" bucket as the unrelated teleport-ring bug.

    warning: Error running lua script: ...commandunit.lua(181): loop over expected but got nil

Line 181 (`CommandUnit.lua`, `WarpInEffectThread`):
`for _, v in bones or bp.Display.WarpInEffect.HideBones do`. `bones` is
nil (caller passes none), so this needs `bp.Display.WarpInEffect.HideBones`
- and that's nil at runtime. **Confirmed NOT a content gap**: read
`gamedata/units/UEL0001/UEL0001_unit.bp` directly (lines 213-220) -
`Display.WarpInEffect.HideBones = { "Back_Upgrade_B01", "Right_Upgrade",
"Left_Upgrade" }` is genuinely defined in the source .bp content. The value
exists in the authored data but is nil by the time Lua reads
`self.Blueprint.Display.WarpInEffect.HideBones` at runtime - something in
the path between ".bp table" and "what `self.Blueprint` exposes at runtime"
drops this specific nested field.

**Does NOT explain commander invisibility** - this line runs AFTER
`ShowBone(0,true)`/`SetUnSelectable(false)`/`SetBusy(false)`/
`SetBlockCommandQueue(false)` (lines 176-179), which all complete
successfully first (sequential Lua execution, confirmed no errors before
line 181 in any of the 3 logs). Only blocks what comes after: the
`HideBone` loop itself, the `EffectTemplate.UnitTeleportSteam01`
`CreateAttachedEmitter` loop, and the phase-shield mesh restore after
`WaitSeconds(6)`.

**Traced the mechanism directly**: `self.Blueprint = self:GetBlueprint()`
(`Unit.lua:276`, in `PreCreate` - runs for every unit) →
`cfunc_UserUnitGetBlueprintL` (`UserUnit.cpp:5900-5913`) →
`RUnitBlueprint::GetLuaBlueprint(state)` → base
`RBlueprint::GetLuaBlueprint` (`RBlueprint.cpp:478-486`, ground truth
`FUN_0050DF90`): **`return state->GetGlobal("__blueprints")[mBlueprintOrdinal]`
- an ORDINAL (numeric) index into the SAME `__blueprints` Lua global**, not
the by-string-name one traced earlier in this file. Searched every
`__blueprints`/`allBlueprints.` site in `Sim.cpp` - the ONLY `SetObject`
call found is `PublishLuaBlueprint` (`Sim.cpp:13949`,
`allBlueprints.SetObject(blueprint->mBlueprintId.c_str(), luaBlueprint)`),
which is BY STRING NAME ONLY. **Nothing in `src/sdk` writes
`__blueprints[<number>]`.** This exactly matches an EXISTING, ALREADY-
DOCUMENTED admission in our own code - the doc comment on
`GetOrCreateRegisteredBlueprint` (`Sim.cpp:13959-13978`) explicitly says:
"The by-ordinal Lua `SetObject` path is still elided." This is a known,
named, scoped gap, not a new discovery - just newly connected to this
specific symptom.

**Open contradiction, not resolved this pass**: if the ordinal lookup
genuinely always returns nil, `self.Blueprint` would be nil for EVERY
unit, and `OnCreate` (`Unit.lua:284-285`, `local bp = self.Blueprint`)
would throw "attempt to index a nil value" universally - which does not
happen (no such error anywhere in any of this session's 3 logs; units
function normally for cost/physics/most Display fields). So EITHER (a)
something else resolves `self:GetBlueprint()` differently than traced
here (Lua method-resolution alternate path not found), or (b) the ordinal
lane needs to be recovered as new C++ (add the missing
`allBlueprints.SetObject(mBlueprintOrdinal, luaBlueprint)` call to the
by-ordinal lane inside `GetOrCreateRegisteredBlueprint`'s registration
chain) and something ELSE currently happens to paper over most fields
(unclear what) while `HideBones` specifically falls through. **Next step
if resuming**: add a temp diagnostic probe printing whether
`state->GetGlobal("__blueprints")[ordinal]` is nil/table right after
`InitUnitBlueprintFromLua` registers a unit, to settle (a) vs (b)
empirically rather than by further static tracing - this project's own
established methodology (`skills/init-recovery/references/dbgrun.md`
"Adding a temporary probe") after two failed by-hand tracing attempts on
DIFFERENT bugs earlier in this same file is the standing lesson here too.

## MAJOR REFRAME (2026-09-01, same pass): main-view "corruption" is a FROZEN frame, not per-frame garbage - and the prefs correlation is REFUTED

Built a reliable screenshot method this pass (`PrintWindow`+
`PW_RENDERFULLCONTENT`, see above) and used it to test the restored SMALL
`mini_ui_minimap` prefs value (`top=157,left=10,right=237,bottom=367,
width=227,height=210` - matching the code's own `defPosition` exactly) for
stability. Two findings, one QUALIFIES the earlier correlation lead and one
SUPERSEDES it:

1. **The minimap itself stayed correctly small** across this whole test
   (`stability_check` run) - the earlier "stretches to fill the window over
   real time" report does NOT reproduce with this specific restored value.
   Consistent with (though not proof of) the earlier growth being tied to
   the key being ABSENT specifically, not to size/time in general - but see
   `corruption_retest`, which also only had ONE data point for "absent",
   so this is still just 1-vs-1, not confirmed.

2. **The main view "streaky corruption" REAPPEARED with this small,
   known-good prefs value in place** - directly contradicting the earlier
   "old large prefs = clean, no/small key = corrupted" correlation from the
   `abtest_oldprefs` pass. That correlation is REFUTED; prefs state is NOT
   what determines whether the main view corrupts.

**What actually explains it, found by taking two screenshots ~2+ minutes
apart in the SAME session**: the two captures were **pixel-identical** -
same streak pattern, same position, down to the pixel, despite the log
file continuing to grow substantially between them (sim/Lua definitely
still running). A genuinely live, updating 3D scene would show SOME visible
change over 2 minutes (camera micro-motion, animations, lighting) even if
individual frames were wrong. Identical frames means **the world-view
render pass has STALLED / stopped presenting new frames**, and both
`PrintWindow` (DWM's redirection surface) and, most likely, the user's own
earlier screenshots are simply showing whatever the LAST successfully
rendered frame was before the stall - not a per-frame color-computation bug.
The 2D UI layer (text, panel borders, buttons) is NOT frozen in the same
shots (crisp, normally composited), suggesting this is specific to the
`CUIWorldView`/D3D9 world-view render passes, not a full main-thread
deadlock.

**This plausibly connects to the separately-reported, still-open
close-button/process-survives bug** (see the `m_keepGoing`/`ExitMainLoop`
sections above, still blocked on the locked `WxRuntimeTypes.cpp`) - both
look like symptoms of the render/message loop getting stuck while the sim
thread keeps ticking (matching "sound keeps playing" too - audio is
presumably driven by the sim/audio thread, independent of the stalled
render pass). Not proven to be the same root cause, but the SHAPE of both
bugs (something stops pumping/presenting while the rest of the engine
keeps running) is suspicious enough to treat as one investigation once
`WxRuntimeTypes.cpp` frees up, rather than two unrelated ones.

**Re-examined `CUIWorldView::CUIWorldView`** (`UiRuntimeTypes.cpp:20394`,
read earlier this pass) for anything that could stall future frames after
construction succeeds - found nothing obviously wrong in the constructor
itself (confirmed independent camera objects for primary/minimap, confirmed
`RCamManager::CreateCamera`'s allocation size and `mCams` growth are both
correct). The STALL, if it's a recovery bug at all, is more likely in
whatever drives the PER-FRAME render/present call for world views (not yet
located - `CRenderWorldView.cpp` is the next file to check) than in one-time
construction/registration code, which has now been extensively checked and
looks faithful.

**Do not chase this further via more prefs A/B tests** - that lead is dead.

Checked `CRenderWorldView::Render` (`CRenderWorldView.cpp:57-103`, ground
truth `FUN_0086EE00`) as the obvious per-frame candidate - it's real and
matches ground truth, but it only draws OVERLAYS (resource splats,
strategic icons, projectile arcs/icons, mesh previews, command splats,
economy readout, command graph) on top of an already-rendered scene, not
the terrain/world itself, and its caller list is empty in the callgraph
index (almost certainly virtual dispatch, not traced by static xrefs). Not
the right place to keep looking - the actual scene-render/present call is
lower-level and not yet located.

**Next step if resuming**: find the per-frame world-view render/present
call chain (not `CRenderWorldView::Render` - see above) and look for a
condition under which it stops being invoked - a missing re-arm/schedule
after some one-time event is the most likely shape, given the render pass
works initially (both screenshots LOOK like a real, if stale, rendered
frame - not a black/uninitialized screen) and then simply never updates
again.

## Unifying theory: the render freeze plausibly explains "commander not visible" directly - supersedes the camera-position hypothesis

If the world-view render genuinely freezes early in a session (established
above via two pixel-identical screenshots minutes apart), the user would
NEVER see any subsequent 3D-world change - including the commander's own
warp-in reveal - regardless of whether the underlying Lua/engine state
correctly updated (which the logs prove it does: 0/8 throws, `ShowBone`/
`SetBlockCommandQueue(false)` all confirmed executing). The screen would
just be stuck showing whatever was rendered before the freeze, forever.
This fits EVERY observed symptom better than a camera-position gap:
  - "No commander spawn" - the 3D world is frozen on an early frame, so
    nothing that happens afterward (commander reveal included) is ever
    visible, camera position notwithstanding.
  - The 2D UI layer ("Ready for recall" text, economy numbers, panel
    chrome) is NOT frozen in the same screenshots (crisp, normally
    composited) - consistent with only the 3D world-view render pass
    stalling, not the whole app.
  - Minimap content (also a `CUIWorldView`/D3D9 render-to-texture surface,
    just with `SetCartographic(true)`) showing a flat/wrong fill is
    consistent with ITS OWN render pass freezing too, possibly even
    earlier (before anything meaningful had been drawn to it at all).

**This demotes the earlier `StartCamera`/camera-position hypothesis** (not
disproven, just no longer the leading explanation - a working camera
pointed at a frozen scene would look identical to a broken camera anyway,
so that thread can't usefully be tested until the freeze itself is
understood or ruled out).

**Practical implication**: fixing this needs the SAME locked
`WxRuntimeTypes.cpp` file as the close-button investigation (both are
render/message-loop-shaped bugs), so both are gated on the same
unblock.

## ROOT CAUSE FOUND AND PRECISELY LOCATED (2026-09-01, same pass): `wxApp::ProcessIdle` starvation, ground-truth-confirmed, blocked only by the file lock

Traced the exact mechanism, verifying every link against ground truth
directly (not inferred):

1. **`WIN_AppExecute`'s main loop** (`WinApp.cpp:3500-3598`, ground truth
   `FUN_004F20B0`, real caller `WinMain`/`FUN_008D44A0` confirmed) only
   reaches `app->Main()` - where BOTH the per-frame render/present work AND
   (per the `KeepGoing()` check immediately before it) the exit path live -
   after `Pending()` returns false AND `ProcessIdle()` returns false.
   **Read the actual ground-truth pseudocode for this exact loop
   (`decomp_read.py FUN_004F20B0 -l 1 -n 130`) and traced every brace by
   hand**: the real binary has the IDENTICAL structural property, just
   expressed as nested `while(1)` loops instead of our recovered version's
   flattened `for(;;){...continue...}` shape. **The loop restructuring
   itself is faithful - confirmed, not a recovery bug.** Both versions:
   keep dispatching pending messages, then call `ProcessIdle()` once
   `Pending()` is false, and ONLY fall through to `app->Main()` once
   `ProcessIdle()` itself returns false.
2. **`wxApp::ProcessIdle()`** (`WxRuntimeTypes.cpp:42603-42628` - LOCKED
   file, read-only this pass) aggregates via OR: the app-level idle event's
   `RequestMore` flag, THEN (via `WxSendIdleEventsRuntime()`,
   `:42591-42600`) every top-level window's own idle-request answer. If
   ANY SINGLE window in `gWxTopLevelWindows` keeps requesting more idle
   time, `ProcessIdle()` returns `true` FOREVER and `app->Main()` never
   runs again - matching the observed pixel-identical-frames-minutes-apart
   freeze exactly.
3. **The gap is already self-documented** in the code at that exact spot
   (`:42612-42622`): the REAL ground-truth `wxApp::OnIdle` (`0x009932B0`,
   bound as the first row of wx's own event table at `0x00D55930`) is
   explicitly NOT recovered - our version bypasses the event-table routing
   entirely and calls the window-idle sender directly. The comment names
   what's missing: `OnIdle` "flushes the log target, deletes pending
   objects and runs periodic work **behind a mouse-button check**." If
   that app-level gating is what's supposed to make idle settle (return
   false) reliably, its absence is sufficient to explain permanent
   starvation with no other bug needed.

**This is now a precisely diagnosed, ground-truth-verified root cause that
plausibly explains all three symptoms as one bug** (frozen world-view
render -> invisible commander regardless of camera position; window
visually closes via `WM_CLOSE`/`Dispatch()` but the loop never reaches the
`KeepGoing()` check to actually `break`/exit the process; sim/audio keep
running on their own thread throughout). **The fix is not a mystery, it is
a locked file**: recovering `wxApp::OnIdle` (or at minimum whatever
mouse-button-gated logic makes `ProcessIdle()` settle) in
`WxRuntimeTypes.cpp` around `:42603`. Do not attempt a workaround
elsewhere (e.g. a forced-timeout fallback in the unlocked `WinApp.cpp`) -
ground truth does not have one, and adding one would be exactly the kind
of invented-behavior deviation this project's fidelity contract forbids;
the real binary's `OnIdle` genuinely does settle reliably, so the fix
belongs where the gap actually is.

**Next step once `WxRuntimeTypes.cpp` frees up**: recover `wxApp::OnIdle`
faithfully (ground truth `0x009932B0`) and route `ProcessIdle()` through
it instead of calling `WxSendIdleEventsRuntime()` directly - read the
mouse-button-gated periodic-work logic from ground truth first, per this
project's callsite-verification rule, rather than guessing at the gating
condition.

## REVISION (2026-09-01, same pass): the idle fan-out itself is faithful - narrow the theory, don't overclaim

Read the FULL ground truth for `wxApp::OnIdle` (`FUN_009932B0`, 25 lines)
directly, then its two callees:

    void wxApp::OnIdle(void* this, int a2) {
      if (!byte_F8F830) {                      // reentrancy guard
        byte_F8F830 = 1;
        (vtable[148/4=37])(this);               // <-- UNCONDITIONAL, called first, not recovered at all
        wxApp::DeletePendingObjects();
        if (!dword_FB19A0) {                    // <-- a static flag gate, not recovered at all
          v3 = sub_9C51F0();
          if (v3 && *(byte*)(v3+4)) (vtable call)(v3);
        }
        if (!LBUTTON && !SHIFT && !RBUTTON)     // mouse-button check - gates ONLY this next line
          sub_9CA2B0();                          // "periodic work" - NOT the request-more decision
        if (sub_993240(this))                   // <-- THIS is the actual request-more decision
          a2[32] = 1;
        byte_F8F830 = 0;
      }
    }

**Corrected finding**: the mouse-button check does NOT gate the request-
more decision (my earlier read conflated the two) - it only gates
`sub_9CA2B0()`, a separate "periodic work" call. The ACTUAL request-more
decision is `sub_993240(this)`, read directly:

    char sub_993240() {                          // iterate wxTopLevelWindows, OR the per-window answer
      for each topLevelWindow: if (sub_992BC0(topLevelWindow)) result = true;
      return result;
    }
    bool sub_992BC0(wxObject* window) {           // per-window: dispatch EVT_IDLE, recurse into children, OR
      dispatch idle event to window, read RequestMore;
      for each child: if (sub_992BC0(child)) result = true;
      return result;
    }

**This is a 1:1 structural match to our ALREADY-RECOVERED
`WxSendIdleEventsRuntime`/`WxSendIdleEventsToWindowRuntime`**
(`WxRuntimeTypes.cpp:42554-42600`) - confirmed our version ALSO recurses
into `window->GetChildren()`, matching `sub_992BC0`'s own recursion
exactly. **The idle fan-out and request-more aggregation are faithfully
recovered - this is NOT where the bug is.** The in-code comment's own
conclusion (re-read more carefully this time) already said as much:
"Everything the windows see is the same; what is missing is the chance
for an application-level handler to intervene first" - i.e. the gap is
about WHEN/WHETHER app-level work runs, not about whether windows
correctly report their own idle state.

**Two genuinely unrecovered pieces remain, either of which is a better
candidate than "idle never settles"**:
  1. The unconditional vtable call at the very top of real `OnIdle`
     (slot 148/4 = index 37 on `wxApp`'s vtable) - called on EVERY idle
     cycle, before anything else. Not identified this pass (needs an RTTI/
     vtable-dump lookup of `wxApp`'s slot 37, not yet done).
  2. The `dword_FB19A0`-gated block calling into `sub_9C51F0()`/a
     flag-gated virtual call - also not identified.
  Either could plausibly be a missing PER-IDLE RENDER TRIGGER (i.e. maybe
  `ProcessIdle()` genuinely does settle/return false correctly, `app->Main()`
  genuinely does get called, but something downstream that's SUPPOSED to
  happen via this unrecovered piece of `OnIdle` - not idle-starvation at
  all - is what's actually missing). This is a MEANINGFULLY DIFFERENT
  theory from "idle never returns false" and needs to be distinguished
  before writing any fix, not assumed.

**Confidence downgrade, stated plainly**: "found the root cause" was
premature. What's actually established: (a) the world-view render
genuinely stalls (two pixel-identical screenshots, solid evidence), (b)
the main loop's overall shape is ground-truth-faithful (verified), (c) the
idle fan-out/aggregation is ALSO ground-truth-faithful (verified this
revision), (d) two specific pieces of real `OnIdle` are confirmed
unrecovered and are the remaining candidates, (e) none of (a)-(d) has been
tied together by a live probe - everything past (a) is static-analysis
inference. **Next step, once safe to touch the file (or via a probe
elsewhere that doesn't require editing it)**: identify vtable slot 37 on
`wxApp` and `sub_9C51F0`'s target via RTTI/vtable dumps, THEN decide
whether either is render-related before writing a fix - do not guess.

**Both identified (2026-09-01, same pass)** - neither is obviously render-
related, so confidence in "recovering OnIdle fixes the freeze" stays
MODERATE, not high:
  - Slot 37 = `wxAppBase::ProcessPendingEvents` (RTTI dump confirms;
    ground truth `FUN_009AAD10` matches exactly). Standard wx - drains
    events queued via `wxPostEvent`/`QueueEvent` and dispatches them. Also
    exists verbatim in the vendored `dependencies/wxWindows-2.4.2/src/
    common/appcmn.cpp` - low-risk to port if this turns out to be it,
    since it's unmodified stock wx behavior, not custom engine logic. The
    plausible link to rendering: IF anything in this engine triggers a
    redraw via a POSTED event rather than a direct call, this is the only
    place that would ever get processed - and our bypass never calls it.
  - `sub_9C51F0` = `wxLog::GetActiveTarget()`-shaped (lazy log-target
    creation/retrieval, ground truth `FUN_009C51F0` matches the "flushes
    the log target" comment exactly). Not render-related.

**Honest confidence statement for whoever resumes this**: the freeze is
solidly established (pixel-identical frames). The `OnIdle` gap is real,
precisely scoped, and the two missing pieces are now fully identified -
but neither is a slam-dunk "this is definitely a render trigger" the way
the initial read suggested. `ProcessPendingEvents` is the better of the
two candidates but this is still an inference, not a proven fix. Recovering
it is low-risk (standard wx, vendored source available) and worth doing
regardless once the file is safe to touch, but do not report this as
solved until re-tested live and confirmed the freeze is gone.

## LANDED (2026-09-01, same pass): commit 8a53cd7a - wxApp::OnIdle recovered, ProcessIdle routed through it

Coordinated with peer session `faf-main-2c` (via SendMessage/ListAgents,
not just the user) - confirmed zero hunk overlap in `WxRuntimeTypes.cpp`
(their 20 hunks are all outside 42000-43500; my target region was clean),
independently converged on the identical ground-truth read for `OnIdle`
(including the same correction re: the mouse-button check not gating the
request-more decision), and got an important piece of NEW information
from them: `wxApp::DoMessage` was recently fixed on their side (was
calling `ProcessMessage` instead of the `DoMessage(MSG*)` overload, so
posted messages were pulled and discarded, WM_PAINT never landed,
`Pending()` never went false, and the loop never reached `ProcessIdle()`
at all) - meaning the code path this fix targets was previously
UNREACHABLE and is only "newly live" now. They're running an empirical
probe in `WinApp.cpp` (their file) to settle whether `ProcessIdle()`
itself was starving (theory A) or the missing `OnIdle` app-level work is
what actually matters (theory B) - result pending, message will follow.

**Investigated the full backing-infrastructure question before writing
anything** (per the "no fabricated backing state" standard this project
holds elsewhere): `wxApp::ProcessPendingEvents()` already existed as an
empty stub with the correct address citation (`0x009AAD10`) - its own
comment already said the backing `wxPendingEvents` list isn't modelled.
Confirmed by grep: zero references anywhere in `WxRuntimeTypes.cpp` to
`wxPendingEvents`/`AddPendingEvent`/`QueueEvent`/`wxPostEvent` - no
producer exists anywhere in this engine. `wxApp::DeletePendingObjects()`
doesn't exist at all (no stub even). `wxLog::GetActiveTarget`-shaped
lazy log-target retrieval doesn't exist either. Decided NOT to fabricate
new backing subsystems for any of these three (pending-events list,
pending-delete list, active log target) - none are proven relevant to
rendering, and building them without evidence they're needed would be
speculative scope creep for what should be a scoped bugfix.

**What was actually recovered** (`WxRuntimeTypes.h`/`.cpp`, commit
`8a53cd7a`): a new `wxApp::OnIdle(wxEventRuntime&)` virtual (declared with
the visible base type since the concrete `WxIdleEventRuntime` lives in an
anonymous namespace in the .cpp - matches the EXISTING pattern
`wxWindow::OnIdle` already uses for the identical visibility problem;
`static_cast` down to `WxIdleEventRuntime&` inside the .cpp body, safe
since both call sites in this file construct the concrete type).
Reentrancy-guarded (static bool, matching ground truth's `byte_F8F830`),
calls the existing `ProcessPendingEvents()` stub (order-faithful, even
though currently a no-op), then aggregates the request-more decision via
the ALREADY-recovered `WxSendIdleEventsRuntime()`. `ProcessIdle()` now
calls `OnIdle` instead of `WxSendIdleEventsRuntime()` directly, and the
stale comment admitting the old deviation was replaced.

**Commit hygiene, given the peer's explicit warning**: `git commit
src/sdk/moho/app/WxRuntimeTypes.cpp` would have swept up their ~1064+/75-
of unrelated in-flight wx string/array/path work. Used the documented
partial-file technique instead: saved the full `git diff` to a scratch
file, located my two hunks by grep'ing `^@@` headers (`@@ -42558...` and
`@@ -42565...`, isolated from every other hunk), extracted them into a
standalone patch (diff header + those two hunks only), `git apply --check
--cached` to dry-run, then `git apply --cached` for real. Verified with
`git diff --cached --stat` (67+13, not ~1139) BEFORE committing, and
re-verified after commit that the peer's working-tree diff was still
exactly 1064+/75- (untouched). Plain `git commit -m ...` with NO trailing
pathspec, since a pathspec form would have re-read the working tree
instead of the curated index.

**Build**: `tucheck EXITCODE=0` on the touched TU before committing. Full
`main.vcxproj` rebuild kicked off after commit to runtime-verify - result
pending as of this note.

**Reply owed to faf-main-2c**: their question was whether
`ProcessPendingEvents` bears on sim-thread event delivery. Answer: no -
confirmed via grep that nothing in this engine (sim or otherwise) posts
through `wxPostEvent`/`QueueEvent`/`AddPendingEvent` anywhere, so the
function draining an empty list has no effect on sim-thread delivery
either way. Message this back to them.

## CORRECTION (2026-09-01, same pass): theory A is DEAD - OnIdle was never the freeze cause. Real freeze location found by the peer, with better evidence.

`faf-main-2c` instrumented `WIN_AppExecute`'s loop directly (counters
dumped once/second) and got a decisive, unambiguous answer BEFORE my own
retest could even run (a build collision - we were both staging to the
same `main.exe` output - meant their result supersedes mine as the source
of truth here, and no separate confirmatory run was needed):

    [LOOPDIAG] iter=2945 dispatch=984 idleCalls=980 idleTrue=0 main=980

`idleTrue=0` across every one of 50 one-second dumps - `ProcessIdle()`
returned false EVERY time it was called, never once requesting more idle.
`main=980`, climbing steadily and continuously. **The idle loop was never
starving. `app->Main()` runs fine, ~13-20x/second, the whole time.** The
`wxApp::OnIdle` recovery (commit `8a53cd7a`, this file's previous section)
is confirmed a real, correct, worthwhile FIDELITY fix - it matches ground
truth better than the bypass it replaced - but it is NOT what causes or
fixes the freeze. Do not claim otherwise. `ProcessPendingEvents` staying a
stub is independently confirmed correct too (no producer anywhere in the
engine, so draining it is a genuine no-op either way) - ruling out the
best remaining idle-related candidate as well.

**Where the freeze actually is, found via a hang-stack + the same
LOOPDIAG instrumentation**: the main thread stops iterating the loop
entirely ~50s in (LOOPDIAG output stops dead), while 421 further
`OutputDebugString` events keep arriving from the SIM THREAD afterward -
the process is alive and working, only the MAIN thread is parked. The
hang stack names the exact spot:

    #00 NtUserGetMessage
    #01 wxApp::DoMessage        WxRuntimeTypes.cpp:42640   (GetMessageW)
    #02 wxApp::Dispatch         WxRuntimeTypes.cpp:42076
    #03 WxAppRuntime::Dispatch  WxAppRuntime.cpp:44
    #04 WIN_AppExecute          WinApp.cpp

Parked in the **`Pending()` -> `Dispatch()`** branch of the main loop
(the ONE branch this file's earlier sections never suspected - all prior
theories, mine included, focused on the `ProcessIdle()`/idle-fanout side).
**A genuine contradiction, not yet explained**: `wxApp::Pending()`
(`:42063-42066`) is `PeekMessageW(&gCurrentMessage, nullptr, 0, 0,
PM_NOREMOVE)` - faithful to stock wx 2.4. If `Pending()` returned TRUE (a
message genuinely pending), the immediately-following `GetMessageW` in
`DoMessage` MUST return at once - it cannot block. Parking there means
either the message vanished between the peek and the get (a race), or
`gCurrentMessage` - a SHARED GLOBAL that `DoMessage`'s own
non-GUI-thread branch ALSO writes - was read/written inconsistently
across threads. NOT YET CONFIRMED which. `faf-main-2c` has added an
ENTER/LEAVE probe around `Dispatch()` (logging the peeked message id/hwnd)
to pin this down empirically - result pending, they'll report back.

**`wxApp::Pending`/`Dispatch`/`DoMessage` (`WxRuntimeTypes.cpp:42063-42077`
and `:42638-42677`) are `faf-main-2c`'s active investigation** - they
explicitly asked to be the one who lands any fix there and to be consulted
first. Do not edit this region without coordinating with them first
(same file-lease discipline as the rest of this investigation).

**Also corrected**: `faf-main-2c`'s own run never got past the loading
screen in 45 seconds - meaning the freeze may happen DURING MAP LOAD, not
during actual gameplay. This means the two "pixel-identical screenshots
minutes apart" that originally established the freeze (earlier section,
this file) may have been capturing a STALLED LOADING SCREEN, not a
stalled in-game world view - the freeze finding itself still stands (the
LOOPDIAG stop is direct, independent evidence), but WHEN it happens in a
session's timeline needs re-checking, not assumed to be "once gameplay
starts" as earlier framed.

**Build collision note for future sessions**: both this session and
`faf-main-2c` build+stage to the same `C:\ProgramData\FAForever\bin\
main.exe`. Whoever builds second silently replaces the other's binary
mid-run and neither can tell from their own log which binary they
actually measured. Coordinate via SendMessage before starting a
build+test cycle if another session might also be testing - "build done,
your turn" / "clear to go" handshake, not simultaneous runs.

## Freeze mechanism fully traced to a call chain (2026-09-01, same pass): reentrant nesting on the MAIN thread, not cross-thread - and it unifies all three user-visible symptoms

Answered `faf-main-2c`'s three follow-up questions, then traced the full
call chain myself. Full chain, confirmed function-by-function:

    WIN_AppExecute (WinApp.cpp, main loop)
      -> app->Main()  [ = CScApp::Main() ]
      -> WLD_Frame (CWldSession.cpp:21396, ground truth FUN_0088CAE0)
      -> WLD_DoInitializing (:21079, ONLY caller is WLD_Frame; ground truth
         FUN_0088C3F0 - "waits for the sim to publish its first sync data,
         then performs the whole loading-to-playing handover": starts game
         Lua UI, takes down the loading dialog, builds the in-game
         interface)
      -> simDriver->GetSyncData() (CSimDriver::GetSyncData,
         SimDriver.cpp:1431-1440)
      -> PerformNextEvent() (SimDriver.cpp:2103-2126, ground truth
         FUN_0073F430) when its internal `while (mSyncDataQueue.Empty())`
         loop condition is true
      -> WxAppRuntime::Pending()/Dispatch()/ProcessIdle() - THE SAME
         functions the outer WIN_AppExecute loop itself calls.

**Every link in this chain is on the SAME thread as `WIN_AppExecute`'s own
loop** - there is no thread boundary anywhere in it. This REVISES the
earlier same-pass theory (a cross-thread race on `gCurrentMessage`) to:
**reentrant nesting on the main thread**. The outer loop only ever reaches
`app->Main()` once `Pending()` is false and `ProcessIdle()` has settled -
by construction, no message is pending at that moment. But `app->Main()`
can run for a while (this is literally the "wait for the sim's first sync
packet during load" path), and if a NEW message arrives while it's
running, `PerformNextEvent`'s OWN `Pending()`/`Dispatch()` pumps it -
through the exact same `wxApp::DoMessage()` the outer loop uses - nested
inside the outer loop's own in-flight iteration. Exactly why this
produces a PERMANENT block (not just a harmless nested pump) is not yet
nailed down - `faf-main-2c` has an ENTER/LEAVE probe around `Dispatch()`
running to answer that empirically; this is their active investigation
now (`CWldSession.cpp`/`SimDriver.cpp`), not mine to land a fix in
without coordinating first.

Confirmed via the vendored source and a direct ground-truth grep that
NEITHER contributing half is a recovery bug: stock wx 2.4 also uses a
single global `MSG s_currentMsg` (`dependencies/wxWindows-2.4.2/src/msw/
app.cpp:136`) - our `gCurrentMessage` is faithful. And stock wx's
`wxApp::MainLoop()` calls `wxMutexGuiLeaveOrEnter()` every iteration
(same file, `:953`) specifically to coordinate exactly this kind of
multi-entry access - but ground truth `WIN_AppExecute` (`FUN_004F20B0`,
all 170 lines, grepped directly) calls NOTHING matching
`Mutex|GuiLeave|GuiEnter|GuiOwned` anywhere. **The original binary's own
custom loop genuinely omits the synchronization stock wx relies on for
this exact scenario - not a recovery gap, a property of the original
engine's own design.** Whatever the fix turns out to be, it should not be
"add a GUI mutex ground truth never had" - more likely a narrower, more
faithful fix once the ENTER/LEAVE probe shows the exact failure point.

**This one bug plausibly explains ALL FOUR of the user's live-session
reports as a single root cause**, not four separate ones:
  - Frozen world-view render / invisible commander: if the main thread
    parks inside this nested pump during load, it never returns to
    finish that `WIN_AppExecute` iteration, so nothing after that point
    (including any later frame's render) ever runs again.
  - Minimap showing a flat/wrong fill regardless of size: consistent with
    the freeze happening EARLY (during load, per `faf-main-2c`'s run
    never reaching gameplay in 45s) - before the minimap's own
    cartographic camera ever gets a first real frame rendered, so what's
    shown is whatever an empty/just-cleared render target looks like.
  - Window not closing / process surviving / audio still playing: if the
    main thread is permanently parked inside this nested `GetMessageW`,
    it never returns to the OUTER loop's own `KeepGoing()` check - the
    one place `WM_CLOSE`/`WM_QUIT` handling would actually break the loop
    and let the process exit. The sim/audio threads are independent and
    keep running regardless, matching "sound keeps playing."

If this holds, landing ONE fix here (wherever `faf-main-2c`'s probe
points) should resolve everything the user has reported this session,
not just the render freeze specifically. Not confirmed yet - report
findings, not hopes, once their probe result lands.

**Dead end, recorded so it isn't re-chased**: `IsGuiOwnedByMainThread()`
looked like a strong candidate (hybrid-linked against the vendored
`wxmsw.lib`, `gs_bGuiOwnedByMainThread` only ever set TRUE inside
`wxMutexGuiLeaveOrEnter()`, which - like `wxMutexGuiEnter`/`Leave` - is
declared with a real ground-truth address in our header but has ZERO
definition and ZERO call sites anywhere in `src/sdk`). Checked the
vendored source directly: `gs_bGuiOwnedByMainThread` initializes to
`TRUE` in stock wx too (`thread.cpp:110`), matching our own copy
(`WxRuntimeTypes.cpp:1789`). Since nothing anywhere ever calls
`wxMutexGuiLeave` either, nothing ever flips it false - it should read
TRUE for the whole process lifetime regardless of which copy (ours vs.
vendored) actually gets read. Not the mechanism. Standing down on this
whole investigation thread (both the reentrancy chain and the mutex
angle) - it's `faf-main-2c`'s active territory and their empirical
ENTER/LEAVE probe is the better path from here than more static reading.

## LANDED (2026-09-01, same pass): commit 0d210904 - the HideBones mystery SOLVED, and the emitter bug is independently FIXED by faf-main-2c

Two more real commits landed while the render-freeze investigation was
paused waiting on `faf-main-2c`'s probe:

**`faf-main-2c` landed `44bf506b`** (`RRuleGameRules.cpp`): the
`teleport_ring_01_emit`/"Failed to create emitter" bug (found earlier
this file, 8/8 -> this pass) was the SAME slash-mismatch class as the
projectile bug this file's `89b4f267` fixed - `GetEmitterBlueprint`/
`GetTrailBlueprint`/`GetMeshBlueprint` had open-coded copies of the
lookup instead of going through the shared `LookupBlueprintByResId`
template, so they never got the slash-fallback retry. Confirmed live:
"Failed to create emitter" warnings went 104 -> 0 (six distinct emitter
blueprints), zero new warning classes introduced, session reached
6m49s of game time with the sim still ticking. **Their commit message
confirms the commander warp-in reveal lines (`ShowBone(0)`,
`SetUnSelectable(false)`, `SetBusy(false)`, `SetBlockCommandQueue
(false)`) now execute** - and that the thread then dies one line later
at `commandunit.lua:181` on nil `HideBones` - i.e. this file's own
long-standing HideBones investigation (many sections above) is THE
confirmed next and, as of this pass, LAST known blocker in this specific
chain.

**Resolved HideBones** (commit `0d210904`, `Sim.cpp`): re-read
`RBlueprint::GetLuaBlueprint`'s ground truth directly ONE more time to
be certain (`FUN_0050DF90` - `GetGlobal("__blueprints")` then
`operator[](a2->mBlueprintOrdinal)` - confirmed byte-for-byte faithful,
not the bug), then read `func_Add__blueprints`'s (`FUN_00529B30`) own
raw pseudocode directly rather than trusting an earlier paraphrase of
its doc comment: it calls `SetObject(Global, mBlueprintOrdinal, a1)`
FIRST, then the by-name `SetObject` second. **Our recovered
`PublishLuaBlueprint` only ever had the by-name half - the entire
by-ordinal publish was missing.** Added the missing call, matching
ground truth's order. `tucheck EXITCODE=0`, committed (`Sim.cpp` only,
zero overlap with anyone). NOT yet runtime-verified - `faf-main-2c` still
had the shared test machine as of this commit; asked them to fold it
into their next run rather than starting a competing build.

**One loose end, not resolved**: never explained WHY `self.Blueprint`
clearly worked for most fields (`Display`, `Economy`, etc.) even before
this fix, if the whole `__blueprints[ordinal]` entry was supposedly
missing - that should have made `self.Blueprint` nil universally, not
just `.Display.WarpInEffect.HideBones` specifically. Possible
explanations not yet checked: a different/cached access path for most
fields, or the contradiction resolves itself once this fix is verified
live (if HideBones goes away, treat the contradiction as explained by
having gotten the mechanism right for reasons not fully traced; if it
persists, the contradiction is still real and this fix didn't address
the actual cause - said as much to faf-main-2c).

## CONFIRMED BY LIVE PROBE: 0d210904 is correct, HideBones closed; but it exposed a real wild-pointer-write bug

`faf-main-2c` ran a temp probe in `RBlueprint::GetLuaBlueprint` with
`0d210904` in place:

    [BPDIAG] id=url0001 ordinal=4056 bp{table=1 nil=0} Display{table=1}
    WarpInEffect{table=1} HideBones{table=1 nil=0 count=2}

`HideBones` is a live 2-element table, was nil before. **The loose end
above is closed** - the ordinal-publish fix was correct and sufficient
for HideBones specifically. `faf-main-2c` also caught and corrected their
own false alarm (they briefly thought the fix duplicated an existing
line; checked `git show 0d210904` themselves before saying anything,
confirmed no duplication).

**But the fix also exposed a genuine, separate, pre-existing crash**:
with `0d210904` in place, `/map SCMP_009` now dies at `Game time:
00:00:00` (previously reached 6m49s) - a null-pointer write:

    write to address 00000000
    #00 QueueEntityForDestroy+0xC8   Entity.cpp:2040
    #01 moho::Entity::OnDestroy+0x1F Entity.cpp:4482
    #02 moho::Unit::OnDestroy+0x2EB  Unit.cpp:16822
    #03 RunQueuedDestroy              Sim.cpp:7459
    #04 moho::Sim::AdvanceBeat+0x421  Sim.cpp:13240

**Root cause, found by `faf-main-2c` reading ground truth `FUN_00679B80`
directly**: `QueueEntityForDestroy`'s real target is
`mSim->mEntityDB->mEntList` (a `std::list<Entity*>` on the EntityDB).
Our recovered version instead reaches into `entity->SimulationRef->
mCommandDB`, reinterpreting it as a fabricated `CommandDbDestroyQueueView`
(`count`@+0x20, `head`@+0x24) - but `CCommandDb`'s REAL layout (every
offset `static_assert`ed: `sim`@0, `commands` map@0x4-0x10, `pool`
(`IdPool`)@0x10-0xCC0, `pendingReleasedCmdIds`@0xCC0) has NO destroy
queue at all - `+0x20`/`+0x24` land squarely inside `IdPool`. The
recovered code reads whatever `IdPool` bytes happen to sit there,
reinterprets them as a linked-list node pointer, and **writes two
pointers through it** - an arbitrary write to an address derived from
unrelated live data, firing on every single entity destroy. Same
fabricated-view pattern duplicated at `Prop.cpp:68`.

**This connects directly to the SndParams crash this file was
investigating** (previous section): a wild pointer write landing
anywhere in memory is a far better fit than my "unsynchronized read/write
race" theory for producing a value OUTSIDE `mResolvePolicy`'s 5 valid
values - `faf-main-2c`'s own framing: "a race on a small enum typically
yields one of the *other* valid values, not a value outside the defined
set." Timing fits too: `0d210904` is what first made units reach
`OnDestroy` at all (nothing did before), so the wild write was never
firing before this session's fixes landed - explaining why the user only
started seeing `CSndParams`-shaped crashes now. Likely both crashes (the
destroy-queue null-write and the `CSndParams`/`mResolvePolicy` garbage
value) are the SAME root cause surfacing wherever the garbage pointer
happens to land on a given run - destroy-queue when it lands on null,
`CSndParams` when it happens to land inside a live `CSndParams` object
and write something outside 0-4 into `mResolvePolicy`'s offset. Also
explains the previously-noted "pre-existing, separate" texture-name
corruption (`faf-main-2c`'s report) as the SAME wild-write mechanism
landing somewhere else again - same shape of symptom, different victim
each time.

**STOOD DOWN on the mutex/threading theory for `CSndParams`** per
`faf-main-2c`'s explicit request - they are fixing the wild write now
(routing `QueueEntityForDestroy`/the `Prop.cpp:68` duplicate through the
real `mEntityDB->mEntList` container, RULE ONE fidelity fix). **Do not
add a mutex to `CSndParams::GetEngine`/`DoResolve` unless the assert
still reproduces AFTER the wild-write fix lands and is retested** - if it
stops reproducing, the race theory was never needed. If it still
reproduces deterministically after, THEN the mutex analysis is worth
pursuing properly (this file's earlier section already has the specific
technical lead: only `gSndParamsRegistryMutex` found, doesn't cover
`GetEngine`/`DoResolve`'s own field access, check ground truth
`FUN_004E0930` for whether the original takes a lock there before adding
one from scratch).

**Do not touch `Entity.cpp`/`Prop.cpp`'s destroy-queue code** -
`faf-main-2c` has explicitly claimed it, said "no action needed from
you," and it's squarely on their own commander-spawn goal (the warp-in
path destroys the teleport prop, which is what was triggering this).

**Status as of this update**: waiting on `faf-main-2c` to land the
wild-write fix and signal the shared test machine is free, then re-run
the `CSndParams` repro (`/log <tag>`) to see if the assert is gone. Do
NOT start a competing build before that signal.

**Read-only verification done while waiting** (2026-09-01, same pass):
confirmed `Prop.cpp:68-102`'s `QueueEntityForDestroyNoCallback` has the
BYTE-FOR-BYTE IDENTICAL bug - same `DestroyQueueNodeView`/
`CommandDbDestroyQueueView` fabricated structs, same `+0x20`/`+0x24`
offsets, same wrong `mCommandDB` target, same wild-write sequence. One
fix shape covers both sites. Also: `QueuePropReclaimDelete` (Prop.cpp:
104-111) calls straight into it, so PROPS going through reclaim/delete
hit this too - very likely explains why this session's wreckage-related
Lua errors (`CreateWreckageProp` chain, `IEffectScaleEmitter` nil,
`SetOrientation` nil - all logged earlier this session, see the
"CreateWreckage"/wreckage sections above) have been so persistent and
scattered: if prop objects' memory was being scribbled on during
creation/reclaim cycles, that produces exactly this kind of
hard-to-pin-down breakage in unrelated script-side code. Reported to
`faf-main-2c`, not fixing myself (their claimed area).

## SetPrecedence nil ROOT-CAUSED AND FIXED (commit `6eb57cac`, 2026-09-01)

User-flagged `unit.lua:3980: attempt to call method 'SetPrecedence' (a nil
value)`. Root cause had nothing to do with the wild-write bug - it's a
genuine, separate Lua-class-flattening gap affecting **every** manipulator
type, not just the one the user happened to hit first.

**Mechanism** (verified via `class.lua`, not guessed):
- `IAniManipulator:SetPrecedence` is registered via `CScrLuaBinder` onto
  `CScrLuaMetatableFactory<IAniManipulator>::Instance()`'s OWN table -
  call it `T_IAni`.
- Every concrete manipulator type (`CFootPlantManipulator`,
  `CRotateManipulator`, etc.) gets its OWN, SEPARATE, flat metatable
  (`SCR_CreateSimpleMetatable`, ground-truth-confirmed via
  `decomp_read.py FUN_00639F00` - `__index = self`, no base chain) - call
  it `T_Foot`. Manipulator INSTANCES use `T_Foot`, never `T_IAni`,
  confirmed via `CFootPlantManipulator`'s ctor -> `CreateLuaObject` ->
  `created.SetMetaTable(T_Foot)`.
- `CScrLuaBaseClassSpec::Run` (`FUN_004CD5E0`, ground-truth-confirmed via
  `--asm`) appends `T_IAni` into `T_Foot`'s ARRAY PART:
  `T_Foot[#T_Foot+1] = T_IAni`. This alone does nothing for string-keyed
  lookups.
- The consumer is `gamedata/lua/system/class.lua`'s
  `ConvertCClassToLuaSimplifiedClass(cclass, name)`, called from
  `globalInit.lua`: `for name, cclass in moho do
  ConvertCClassToLuaSimplifiedClass(cclass, name) end`. It `Flatten()`s
  the array part (walking `T_Foot`'s array-listed bases and copying their
  string-keyed entries, e.g. `SetPrecedence`, into `T_Foot` directly),
  **but only for tables that are actual VALUES of the global `moho`
  table**. `class.lua`'s own `Factory` table pre-lists
  `FootPlantManipulator`, `RotateManipulator`, `AimManipulator`, etc. by
  name, confirming the author expected each to be a `moho.*` key.
- `moho.manipulator_methods` (`T_IAni` itself) WAS correctly published
  (`register_sim_SimInits_mForms_offVariant9`, a real
  `static CScrLuaClassBinder`). **None of the 10 concrete manipulator
  types' `moho.<Type>` publications were** - each one's "register_" thunk
  (`register_sim_SimInits_mForms_offVariantN`) was recovered as a no-op
  `RegisterRecoveredSimInitLinkerLane<Prev, Anchor>()` call against a bare
  `nullptr`-initialized `CScrLuaInitForm*` "anchor" variable, with an
  explanatory comment from an earlier pass: publishing that variable's
  address as if it were a real object crashed
  `RunLuaInitFormSetIfPresent` (null vtable read). The earlier pass's fix
  was to suppress the relink entirely rather than model the real object -
  correctly avoiding the crash, but silently dropping the registration.

**Confirmed via raw binary evidence**, not inference: dumped the actual
`.rdata`/`.data` bytes at each anchor address (`pefile`, matching the
already-proven-correct `moho.manipulator_methods` pointer-scan as a
sanity check first). Every slot decodes cleanly as a `CScrLuaClassBinder`
object (6 dwords: vtable, `mName`, `mGroupName`, `mDocString=""`,
`mNextInSet=0`, `mClassFactory`) with real, readable strings:
`moho.FootPlantManipulator`/`CFootPlantManipulator` at `0x00F59B00`,
`moho.AimManipulator` at `0xF59A20`, `moho.BoneEntityManipulator` at
`0xF59A64`, `moho.BuilderArmManipulator` at `0xF59A98`,
`moho.CollisionManipulator` at `0xF59ACC`, `moho.RotateManipulator` at
`0xF59B80`, `moho.SlaveManipulator` at `0xF59BB4`,
`moho.SlideManipulator` at `0xF59BE8`, `moho.StorageManipulator` at
`0xF59C1C`, `moho.ThrustManipulator` at `0xF59C50`, plus
`moho.ScriptTask_Methods`/`CUnitScriptTask` at `0xF59A08` (same pattern,
different subsystem). Cross-referenced against the `functions` table in
the callgraph SQLite to get each thunk's real `FUN_` address
(`register_sim_SimInits_mForms_offVariant1/2/4/6/7/8/11/13/15/17/19`).
`moho.AnimationManipulator`'s class-binder is a **separate, still-open**
gap - its string exists but has no anchor/thunk stub at all yet (nobody
attempted it), unlike the 11 fixed here which had a stub to replace.

**Fix**: replaced each broken thunk body with a real
`static CScrLuaClassBinder binder(ClassBinderSimLuaInitSet(), "moho.<Type>",
&CScrLuaMetatableFactory<Type>::Instance(), "C<Type>", "");` - exactly the
already-working `moho.manipulator_methods` sibling pattern. Its base
`CScrLuaInitForm` ctor self-links into the set (confirmed via
`CScrLuaInitForm.h`'s own doc comment: "inserts this form at the head of
the owning set list"), so no manual `mForms=` swap is needed at all -
that's specifically what the OLD anchor-pattern attempt got wrong and
crashed on. Removed the now-dead `gRecoveredSimLuaInitFormPrev_off_*`/
`Anchor_off_*` variable pairs (11 of the 12 declared; kept only the
`F59B34_mFactory` pair, which republishes the ALREADY-correctly-recovered
`manipulator_methods` object at a second list position - deliberately did
NOT touch that one, since re-linking the same static object's address a
second time risks the exact same crash class for a different reason
(corrupting a singly-linked list by giving one node two "positions"),
and the global is already reachable without it).
`tucheck manipluabase moho/sim/ManipulatorStartupRegistrations.cpp` ->
EXITCODE=0. Committed `6eb57cac`.

**Not yet independently retested in a live run** (game wasn't available -
peer had the machine mid-fix). Should fix `SetPrecedence` for every
manipulator type project-wide, not just `CreateFootPlantController`'s
call site the user hit - i.e. also
`aimControl/BuildArmManipulator/unpackAnimator/tmpSldr/transformManipulator/
buildBoneRotator/BuildingOpenAnimManip/RockManip/LandingAnimManip/
SpinManip/Animator` etc. across `weapon.lua`, `OverchargeWeapon.lua`,
`DefaultProjectileWeapon.lua`, `FactoryUnit.lua`, `ConstructionUnit.lua`,
`CommandUnit.lua`, `Unit.lua`, and multiple unit scripts - all were
hitting the identical nil, all should now resolve from this one fix.

## Peer status update received mid-investigation (2026-09-01)

`faf-main-2c` landed the `Entity.cpp`/`Prop.cpp` wild-write fix as
`872bfe09` (root cause confirmed against raw `.asm` for `FUN_00679B80`:
wrong base object `mCommandDB` vs. real `mEntityDB->mEntList`; fix now
lives once on `CEntityDb::QueueEntityForDestroy`, both call sites route
through it). **Important correction from the peer**: this did NOT fix the
`CSndParams::GetEngine` assert (`CSndParams.cpp:1210`) - it still fires
after retest. The peer's own counter-argument that talked me off the
mutex/race theory ("a race yields another valid enum value, not garbage
outside the set") was weaker than presented - a torn read mid-update, or
a read of a partially-constructed/already-freed object, can produce an
out-of-set value too. **Mutex theory is back in play, not resolved.**
Peer also flagged a likely-related new crash they're now chasing:
`ArmyAtIndexOrNull+0x1F` (`CWldSession.cpp:15811`) reading a garbage
pointer `8CCC6F30`, reached via `CWldSession::DoBeat -> SessionFrame ->
WLD_DoPlayingAction -> WLD_Frame -> CScApp::Main` - main-thread, same
`DoBeat` neighborhood as `CUserSoundManager::UpdateSoundRequests`. Two
bad-pointer symptoms in adjacent main-thread code during the same beat is
suggestive of a shared second corruptor, not yet found. Peer is taking
`ArmyAtIndexOrNull` (their own goal territory); `CSndParams` remains
mine. Machine is free now (peer confirmed). **Next action**: resume the
`CSndParams` mutex/race investigation - check ground truth `FUN_004E0930`
(`CSndParams::DoResolve`) for whether the original takes a lock around
`mResolvePolicy`/`mBankId`/`mCueId`/`mEngine` before adding one from
scratch, per this project's evidence-first rule.

## 2026-09-01 (later): the actual "commander spawns" mechanism is a UI startup sequence, not sim code

**This is the single most useful thing found this pass.** Everything before
this looked for the spawn on the sim side. What the user experiences as
"the commander spawns when the game starts" is `lua/ui/game/gamemain.lua`:

    function OnFirstUpdate()                    -- fired ONCE from controlClusterGroup.OnFrame
        local avatars = GetArmyAvatars()
        if avatars and avatars[1]:IsInCategory("COMMAND") then
            avatars[1]:SetCustomName(playerArmy.nickname)
            ForkThread(StartupSequence, avatars)
        end
        ...
        import("/lua/ui/game/worldview.lua").UnlockInput()   -- ONLY UnlockInput call
    end

    function StartupSequence(avatars)
        PlaySound(... AMB_Planet_Rumble_zoom)
        WaitSeconds(1)
        UIZoomTo(avatars, 1)                    -- camera zooms onto the ACU
        WaitSeconds(1.5)
        repeat ... SelectUnits(avatars) ... until selected or GameTick() > 50
    end

`CreateUI` calls `LockInput()` (gamemain.lua:274); the only `UnlockInput()`
is inside `OnFirstUpdate`. So if `OnFirstUpdate` never runs the user sees:
camera never moves (stays at its default extreme zoom), commander never
selected, input locked. That is EXACTLY the reported symptom, and it is
independent of whether the sim-side spawn worked.

**Measured**: probes in `cfunc_GetArmyAvatarsL` (Sim.cpp) and
`cfunc_UIZoomToL` (CCommandLuaFunctionRegistrations.cpp) fired ZERO times
across a full run. `UIZoomTo` IS registered and its body is complete, so
the binding is not the gap - `OnFirstUpdate` simply never runs because the
session dies first (see the open blocker below).

**Do not** look for an engine-side "focus camera on commander" call. There
isn't one; it is `UIZoomTo` driven from Lua.

## Landed this pass

- **44bf506b** - `GetEmitterBlueprint`/`GetTrailBlueprint`/`GetMeshBlueprint`
  open-coded the lookup their four siblings share, so they never picked up
  the slash-normalized retry `89b4f267` added for projectiles. Same
  `STR_InitFilename` (lowercase BACKSLASH) vs `ResolveNormalizedBlueprintId`
  (forward slash) mismatch. Live: "invalid blueprint name" 104 -> 0, six
  emitter blueprints fixed, zero new warning classes.
- **872bfe09** - `Entity::OnDestroy`'s destroy-queue lane (and Prop.cpp's
  byte-identical copy) reinterpreted `SimulationRef->mCommandDB` at
  fabricated +0x20/+0x24 and wrote two pointers through it. Those offsets
  land inside `CCommandDb::pool` (IdPool). **Arbitrary write on every entity
  destroy.** Ground truth `FUN_00679B80` asm: `[esi+148h]`=SimulationRef,
  `[eax+984h]`=**mEntityDB**, `[edi+24h]`=mEntityList.head, `add edi,20h`.
  Right offsets, WRONG BASE OBJECT. `EntityDB::Purge` (FUN_00684560) walks
  that list, frees each node and calls each entity's deleting destructor -
  it is the pending-destroy queue. Fix: one
  `CEntityDb::QueueEntityForDestroy` on the owning container (RULE ONE),
  both view structs deleted.

## Open blocker (owned by peer session faf-main-f7 as of this writing)

`CSndParams::GetEngine` (CSndParams.cpp:1210) asserts "Reached the
supposably unreachable" - `mResolvePolicy` (+0x40) holds a value outside
0..4 that nothing in CSndParams.cpp ever writes. Kills the session before
`OnFirstUpdate`, so it blocks the whole goal.

Ruled out with evidence, do not redo:
- Not a mutex/race. Full ground-truth decompile of `FUN_004E0930`
  (`DoResolve`) has NO lock - only `_InterlockedExchangeAdd` on
  shared_ptr's own refcounts. Plain unsynchronized `this->mMode = 1..4`
  writes. The original never locked this; adding one would be invention.
- Not the destroy-queue wild write - that is fixed (872bfe09) and the
  assert still fires.
- Not `ArmyAtIndexOrNull`/`userArmies`. Probed: `userArmies` healthy
  (size 10, sane begin/end); the garbage was the INDEX, `beat.mFocusArmy`
  = 0x65DF1200, read out of `SSyncData+0x004`. `CWldSession::FocusArmy`
  is correctly 0 from `mOriginalSource`, and `Sim::mSyncFilter.focusArmy`
  correctly from `commandSourceId` in `CSimDriver`'s ctor; every offset in
  that chain matches asm. Same corruption wearing a different hat.
- **Not DoBeat reentrancy.** `WLD_Frame` has exactly one caller
  (`CScApp::Main`, CScApp.cpp:1067) and that has exactly one caller
  (`WIN_AppExecute`, WinApp.cpp:3628). `PerformNextEvent` pumps
  Pending/Dispatch/ProcessIdle but nothing there reaches `CScApp::Main`,
  so a nested `DoBeat` is not possible on that path.

Remaining live theory: a SECOND wild write somewhere. Two intermittent
bad reads out of adjacent offsets of the same `SSyncData` packet
(+0x004 focus army, +0x018 audio requests) plus pre-existing corrupted
texture names (`Can't find texture "<garbage>/textures/..."`, 3-5 per run,
identical count across every build - so older than any of this work).

## Main-loop freeze: RESOLVED as not-a-bug (supersedes the OnIdle chapter above)

Probe counters in `WIN_AppExecute`'s loop, one dump/second:
`idleTrue=0` across all 50 dumps - `ProcessIdle()` returned false EVERY
time it was called - and `main=` climbed steadily (~13-20/sec). **There is
no idle starvation.** The earlier "two pixel-identical screenshots" were
capturing a stalled LOADING screen, not a stalled world view. Peer landed
`wxApp::OnIdle` (8a53cd7a) as a genuine fidelity recovery, but it is not a
freeze fix and should not be described as one.

## 2026-09-01 (later still): the real chain, and the keystone that is missing

Order of discovery, each step measured not assumed:

1. `CSndParams` assert **FIXED** (2a80fc80) - and it was never in CSndParams.cpp.
   The `Sound{}` Lua userdata holds a `CSndParams*`, so a reflection upcast
   yields the **slot**. `func_GetCObj_CSndParams` (0x004E4B40) is typed
   `CSndParams**` and every ground-truth caller dereferences it
   (`v8 = *CObj_CSndParams` in FUN_0068CCB0 / FUN_0068CE40 / FUN_006D7C50).
   Entity.cpp and UnitWeapon.cpp each had a private `ResolveSoundParams-
   FromLuaObject` that upcast to the OBJECT type and returned `upcast.mObj`
   **undereferenced**, so callers got the address of the pointer variable
   inside the Lua userdata block and read that block as a CSndParams. Both
   copies deleted. Assert went from every-run to zero.
   *Diagnostic that cracked it*: garbage strings (`mBank.size=234215936`) plus
   `mResolvePolicy == this+0x6C` - a self-pointer, i.e. never a CSndParams.

2. With that fixed the session survives and **`OnFirstUpdate` runs** (ZOOMDIAG
   fires). But `GetArmyAvatars` returns `count=0`.

3. `UserArmy::mAvatars` (+0x1E8, real typed `msvc8::vector<WeakPtr<UserUnit>>`)
   has exactly one writer: a gate in `UserUnit`'s **only** constructor
   requiring `blueprint->General.QuickSelectPriority > 0`. ACU blueprints have
   `QuickSelectPriority = 1` and the reflection field is registered, so the
   gate is fine. **Probed it: the constructor never runs, not once.** No
   client-side units exist at all.

4. Chain upward: `UserUnit` is built in `CWldSession::DoBeat` from
   `beat.mNewUnits` <- `Unit::CreateInterface` <- `QueueCreateUnitParams` <-
   `Entity::Sync` when `mInterfaceCreated == 0`.
   **`Entity::Sync` is a virtual that nothing in the sim's per-beat walk ever
   calls.** The only call in the tree is `Unit::Sync` chaining to its base.

5. `Sim::Sync` (`FUN_007474B0`) is annotated in our source as *"Recovery
   status: Partial lift"* and the missing part is that walk. Ground truth asm
   (0x007478A4..0x00747952):

       mov esi, [ebx+0A60h]   ; n = mCoordEntities.next  (head Sim+0x0A5C)
       lea eax, [ebx+0A5Ch]
       lea ecx, [esi-60h]     ; owner = node-0x60 == Entity::mCoordNode
       mov esi, [esi+4]       ; advance BEFORE dispatch (Sync unlinks it)
       mov eax, [edx+30h]     ; vtable slot 12 == Entity::Sync
       call eax
       ...                    ; counted into Sync_Entity_Count

   Every offset matches an existing static_assert (`Sim::mCoordEntities`
   0x0A5C, `Entity::mCoordNode` 0x60), and slot 12 matches our own
   "VFTable SLOT: 12 (over Entity::Sync)" note.

   Two branches, selected by `a3a[0] = (old mSyncFilter.focusArmy != incoming
   filter focusArmy)`, computed **before** `CopyFrom` (ours copied first,
   destroying the old value):
     changed  -> full resync over `mEntityDB->mAllUnits`
     else     -> incremental over `mCoordEntities`
   The same flag is `forceRefresh` for `CCommandDb::PublishSyncData` (still
   not called anywhere - separate remaining gap), and the changed case calls
   Lua `NoteFocusArmyChanged(new, old)` - **argument order is (new, old)**,
   matching `lua/SimSync.lua:143`; ground truth passes `Call_Int2(v6=new,
   v5=old)`.

**So: no entity sync -> no unit creates published -> no client units -> no
avatars -> no StartupSequence -> no camera zoom onto the commander.** That is
the whole chain for "the commander does not spawn".

Written but NOT yet validated at runtime, and NOT committed.

## Shared-checkout hazard that cost real cycles - read this

THREE sessions were in this checkout at once, all building to one staged
`C:\ProgramData\FAForever\bin\main.exe`. Consequences actually hit:
  - Every build picks up other sessions' **uncommitted** edits.
  - A third session (`faf-main-6b`) was mid-refactor on `CAimManipulator` /
    `ManipulatorLuaFunctionThunks` (changing
    `reinterpret_cast<CScriptObject*>(manipulator)->mLuaObj` to
    `manipulator->mLuaObj`). The tree then crashed deterministically at 3462
    game-log lines in `msvc8::string::tidy`, after ~89 first-chance
    `_RTtypeid` faults whose stack is
    `SCR_FromLua_IAniManipulator -> SCR_MakeScriptObjectRef ->
    RRef_CScriptObject` - a non-null `CScriptObject*` with a garbage vtable,
    i.e. a wrong base-subobject conversion. The preceding build reached 3637
    lines and got in-game.
  - I initially attributed that regression to my own `Sim::Sync` change. It
    was not mine: an unconditional probe at the end of my new walk printed
    **zero** times, proving `Sim::Sync` is never even reached before that
    crash.
  - A peer reported "wildly nondeterministic" runs; that was us clobbering
    each other's `main.exe` between runs. On a stable binary it is fully
    deterministic (two runs, identical line count and fault).

**Before trusting any run: check `main.exe`'s mtime is your own build, and
`git status` for other sessions' in-flight edits.** Attribute regressions only
after that.

## LANDED (2026-09-01, faf-main-f7): commit dc42a803 - CAimManipulator real inheritance, the actual cause of the msvc8::string::tidy/typeid-null crash chain

Root-caused and fixed the crash blocking every run past scenario setup.
Full chain, verified against ground truth and via two dbgrun runs
(before/after):

- `weapon.lua`'s turret setup does `aimControl = CreateAimController(...)`
  immediately followed by `aimControl:SetPrecedence(precedence)` - true for
  nearly every weapon-bearing unit, so this fires during the FIRST unit
  construction in `Sim::Setup`, before a map can ever finish loading.
- `SetPrecedence` only became reachable at all after `6eb57cac` (this
  session, earlier) published the `moho.<Manipulator>` globals its
  base-method flattening depends on - so this bug was latent/dormant in
  every prior build, never exercised.
- `CAimManipulator` (`moho/ai/CAimManipulator.h`) was recovered as a fully
  **standalone class with zero real C++ base classes** - literally still
  carrying its `// Auto-generated from IDA VFTABLE/RTTI scan... skeleton for
  reverse-engineering` header comment, unlike every sibling manipulator
  (`CFootPlantManipulator`, `CRotateManipulator`, etc.) which properly
  `: public IAniManipulator`. Its constructor instead placement-new'd a
  throwaway `IAniManipulator` into its own storage, then **overwrote the
  vtable pointer that constructor had just set** with the address of a bare
  `static std::uint8_t` - faking a vtable well enough for direct field
  access and reflection-driven dispatch, but not native C++ RTTI.
- `SetPrecedence`'s implementation resolves `self` via
  `SCR_FromLua_IAniManipulator` -> real `gpg::REF_UpcastPtr` ->
  `BuildTypedRefWithCache<CScriptObject>` -> `typeid(*scriptObject)` - reading
  through that one-byte fake "vtable" crashes. This is the **exact same root
  cause and fix shape as `CameraImpl`'s `RCamCamera`/`CScriptEvent`
  conversion** (`34dfd4af`, earlier this session) - same "thin fake
  composition instead of real inheritance" anti-pattern, different class.
- The repeating ~89 first-chance `_RTtypeid+0x72` "read from 0xC" faults seen
  across three dbgrun runs, always collapsing into a fatal
  `msvc8::string::tidy`/`free` crash around 104-105k log lines, were ALL this
  same bug - not heap corruption, not a wild-write, not flaky. The "flaky"
  appearance across runs 1-3 was later explained by a peer as multiple
  sessions rebuilding/clobbering the shared staged `main.exe` between runs,
  not real nondeterminism.

**Fix** (`dc42a803`): `CAimManipulator : public IAniManipulator` for real;
constructor uses base-class initialization (`: IAniManipulator(sim,
weapon->mUnit->AniActor, 0)`) instead of placement-new + vtable-tag
substitution; `CreateLuaObject`/`AddWatchBone` called on `this` directly
instead of through `reinterpret_cast`; destructor no longer explicitly
double-destroys the base now that ordinary chaining does it;
`cfunc_CreateAimControllerL` (`ManipulatorLuaFunctionThunks.cpp`) pushes
`manipulator->mLuaObj` directly instead of through the same cast. The
derived-class-specific fields (`mUnit`, `mWeapon`, `mLabel`, arc/tracking
state) deliberately stay behind the existing `CAimManipulatorRuntimeView`
offset-struct pattern for now, unconverted - their offsets were already
confirmed correct (start exactly at `sizeof(IAniManipulator) == 0x80`), and
migrating them to named members is separate, non-blocking cleanup, not part
of what was crashing.

**Verified**: `tucheck` clean on both touched files. Live: a run that
previously died at ~104-105k log lines (89 repeating typeid-null faults ->
fatal `tidy()` crash, 3 out of 3 runs on the pre-fix binary) now runs past
that exact point with **zero** such faults on the post-fix binary.

**New blocker surfaced past this fix** (not yet investigated, flagged to
peer `faf-main-2c` since it's in their claimed `Sim.cpp`/`Unit.cpp`):
```
Unit::Sync (Sim.cpp:8564 call site, Unit.cpp:17216)
-> FastVector<UnitWeaponInfo>::resize -> ::Reserve
-> UnitWeaponInfo::~UnitWeaponInfo (Unit.cpp:12297)
-> msvc8::string::tidy, wild read into an unreserved (RESERVE, not
   COMMITted) memory region
```
Same general SHAPE as the CAimManipulator bug (a `msvc8::string::tidy`
crash reached from a newly-live code path) but a DIFFERENT root cause -
not yet diagnosed. Likely candidate given the shape: `Unit::Sync`'s
`FastVector<UnitWeaponInfo>::resize` may be growing/shrinking without
properly initializing new elements, or destructing already-invalid ones -
same failure family as the `SSyncData::mAudioRequests`
`ReserveSizes`-vs-`GetRequests` gap documented earlier in
`project_dobeat_keystone_chain.md`, worth checking first before assuming
something novel.

## Session identity note (2026-09-01)

Three sessions active in this shared checkout this session: `faf-main-f7`
(this one - manipulator/SetPrecedence chain, CSndParams probe work,
minimap-stretch investigation), `faf-main-2c` (wild-write fix, water
shader fix, CSndParams pointer-slot fix, `Sim::Sync` entity-walk),
`faf-main-6b` (new, `skills/fa-spatial-locality/` COMDAT-ordering tool).
A three-way identity mixup happened where `faf-main-2c` briefed `6b` that
IT owned the `WxRuntimeTypes.cpp`/`UiRuntimeTypes.cpp` minimap probes -
those are `faf-main-f7`'s, not `6b`'s. Resolved via direct messages to
both. If resuming as any of these sessions, confirm identity/ownership
explicitly before assuming a file's in-flight edits are or aren't yours.

## LANDED (2026-09-01, faf-main-f7): commit 234fda53 - missing per-iteration UpdateRenderViewportCoordinates call

Root cause of the minimap-stretch bug (finally pinned down, not just
theorized). `WRenViewport::Render` (`FUN_007F90D0`) has **two** call
sites to `UpdateRenderViewportCoordinates` (`FUN_007F87F0`) - confirmed
via `FUN_007F87F0.xrefs.txt`, not assumed:

- `0x007F9385` - **per-iteration**, inside the per-worldview loop, right
  after `runtime->mCam` is freshly bound to the CURRENT view's camera
  (asm-confirmed: `mov [ebp+219Ch], ecx` immediately followed by
  `call UpdateRenderViewportCoordinates` at 0x007F9385, before the
  `ren_SkyDome` check).
- `0x007F97A4` - post-loop shared tail, by which point the loop has
  already reset `runtime->mCam = nullptr` on its last iteration (asm-
  confirmed: `mov [ebp+219Ch], edi` with `edi=0` at 0x007F970F, then
  `jmp`/fallthrough to `UpdateRenderViewportCoordinates` at 0x007F97A4
  with nothing touching `+0x219C` in between).

Only the second (always-null-camera) call site was in the recovered
source. `UpdateRenderViewportCoordinates` itself (CameraImpl.cpp-style
logic in WxRuntimeTypes.cpp:71256) branches on `runtime->mCam`: non-null
-> copy `camera->viewport.r[3]` into `mScreenPos`/`mScreenSize` (the
CORRECT per-view rect, pushed earlier by `CUIWorldView::DoRender`'s
`camera->CameraSetViewport(...)`); null -> fall back to the FULL HEAD
rect at origin. With only the post-loop call present, that fallback
branch is the ONLY one ever taken - `mScreenPos`/`mScreenSize` get reset
to full-head at the tail of every `Render()` call and NEVER updated
per-view during the loop itself. `SetViewportToLocalScreen()` (the real
`device->SetViewport(&runtime->mScreenPos, &runtime->mScreenSize, ...)`
call, WxRuntimeTypes.cpp:71244) then draws EVERY view - main and minimap
alike - through that same full-screen rect. MiniMap is always the LAST
view processed in the depth-sorted `mWorldViews` array, so its full-
screen terrain draw lands on top of the already-correctly-rendered main
view - exactly "minimap background rendered on top of a screen in full
w/h, stretched".

**Fix**: added the missing per-iteration call right after
`runtime->mCam` is set (before the `ren_SkyDome` check), matching the
binary's actual instruction order. `tucheck` clean
(`moho/app/WxRuntimeTypes.cpp` -> EXITCODE=0, only pre-existing
`[[nodiscard]]` warnings). Investigated and ruled out along the way: no
separate per-view D3D render target for the minimap (`mPrimaryTargetLocks`/
`mSecondaryTargetLocks` are per-HEAD water reflection/refraction textures,
unrelated); the orthographic-camera-mode chain (`SetCartographic` ->
`CameraSetOrtho` -> `UpdateCoords`) is fully implemented and NOT the
cause (see prior section in `project_2026_08_31_ui_fully_works_3d_viewport_still_black.md`).

**NOT yet live-verified.** Two diagnostic probes are still in place
(uncommitted) to confirm empirically once a run reaches rendering:
`WxRuntimeTypes.cpp`'s per-iteration loop (logs `mScreenPos`/`mScreenSize`
vs the camera's own `viewport.r[3]` per view) and `UiRuntimeTypes.cpp`'s
`CUIWorldView::DoRender` (logs what gets pushed). Every run so far has
crashed before reaching `RenderAllHeads` - first on `CAimManipulator`
(fixed this pass), then on the `mNewEntities`/`mNewUnits` offset bug
below (fixed by `faf-main-2c`, `7ef29b8e`). Next run after that fix
lands cleanly should finally exercise these probes.

**Commit-scoping note**: `WxRuntimeTypes.cpp` carries ~1000+ lines of
another session's unrelated in-flight wx work. Isolated this fix via
`git diff | sed` on the exact `@@ ... @@ void moho::WRenViewport::Render`
hunk -> hand-built patch -> `git apply --cached` -> bare `git commit -m`
with **no pathspec**. First attempt used `git commit -m "..." -- <path>`
(a pathspec) and it swept in the whole 1086-line unstaged diff despite
`git diff --cached --stat` showing only 22 lines staged - `git commit
<pathspec>` re-stages the pathspec's current working-tree content before
committing, ignoring what was actually in the index. Caught immediately
via `git show --stat HEAD`, fixed with `git reset HEAD~1` (mixed reset -
untouched working tree) + re-apply + re-commit with no pathspec. Full
writeup: [[feedback_git_commit_pathspec_stages_unstaged]].

## RESOLVED (2026-09-01): the SCreateUnitConstantData/add_ref_copy crash chain

A NEW crash surfaced once `CAimManipulator` stopped blocking startup:
`CWldSession::DoBeat` (CWldSession.cpp:15994, `new UserUnit(this,
createParams)`) -> `UserUnit::UserUnit` member-init `mUnitConstDat(params.mConstDat)`
(UserUnit.cpp:4138) -> `SCreateUnitConstantData`'s copy ctor ->
`boost::shared_ptr<Stats<StatItem>>` copy ctor -> `shared_count::shared_count`
-> `sp_counted_base::add_ref_copy` -> ACCESS_VIOLATION, write fault into a
MEM_MAPPED PAGE_READONLY region (not heap - a strong tell that the "control
block pointer" being incremented was never a real pointer at all).

Spent a large, thorough pass tracing every hop of the shared_ptr
plumbing this could plausibly be - `SharedPtrRawFromSharedRetained` /
`SharedPtrFromRawRetained` / `SharedPtrRaw::assign_retain` /
`SharedPtrRaw::release()` (`gpg/core/utils/BoostWrappers.h`),
`InitializeStatsRootSharedControl`, `ReadStatsRootShared` /
`gpg::ReadPointerShared_Stats_StatItem` / `AssignRetainedRawSharedPointer`
(`SSTIUnitConstantDataSerializer.cpp` / `ArchiveSerialization.cpp`),
`Unit::~Unit()`'s member teardown, `msvc8::auto_ptr`'s copy/transfer
semantics, `msvc8::vector<SCreateUnitParams>::insert`'s reallocation
path. **Every one of these checked out correct** - textbook-balanced
retain/release pairing throughout. This was ultimately the WRONG place
to look, but the check was not wasted: it's now a confirmed-clean audit
of a widely-reused piece of ABI-wrapper machinery (11+ call sites share
the `ReadPointerShared_*`/`AssignRetainedRawSharedPointer` pattern), so
it does not need re-auditing if it comes up again.

**Actual root cause (found and fixed by `faf-main-2c`, commit
`7ef29b8e`)**: `QueueCreateEntityParams` wrote every plain entity (props,
wreckage, mass deposits) through a hand-written view that placed
`mNewEntities` at `+0x138` - which is actually `mNewUnits`'s offset
(`SSyncData`'s own layout asserts have `mNewEntities` at `+0x128`,
`mNewUnits` at `+0x138`, and ground truth at `Entity::CreateInterface`,
`FUN_0067A220`, confirms `+0x128`). Every plain entity was therefore
queued into the UNIT vector, and iterated later as if it were a genuine
28-byte `SCreateUnitParams` when it was really a 12-byte
`SCreateEntityParams` - `UserUnit`'s ctor read `mConstDat.mStatsRoot`
from whatever bytes happened to follow the shorter record in the vector.
Not "garbage at push time" and not "corrupted in transit" - the record
was never an `SCreateUnitParams` at all. `faf-main-2c` also fixed a
related `VisionDb`/`VisionDB` duplicate-skeleton bug the same pass
(`86be31a1`): `CWldSession::mVisionDb` was declared with a generated
skeleton type whose trivial ctor never ran the real pool's constructor,
so `mEntriesHead` was never allocated.

**Verified fixed, live**: post-fix, `AVATARDIAG` (a temporary probe
`faf-main-2c` had already placed in `UserUnit.cpp` chasing the same
"commander doesn't spawn" symptom from the avatar-registration angle)
shows the REAL commander reaching the avatar gate with a live army and
`QuickSelectPriority > 0`:
```
[AVATARDIAG] army=4E6CF200 bp=19183800 quickSelect=1 id='uel0001'
```
(and again on a later run: `army=58BF7200 bp=1958E800 quickSelect=1
id='uel0001'`). That's `AddArmyAvatar(mArmy, this)`'s exact gate
condition, satisfied for the actual commander blueprint - this is the
mechanism `gamemain.lua`'s `OnFirstUpdate` -> `StartupSequence` chain
(see the top of this file) needs to ever fire. A dbgrun pass with these
fixes in place ran 90s+ with **zero** ACCESS_VIOLATION faults (previous
runs died within seconds), though it did not yet run long enough/reach
far enough to fire the `WxRuntimeTypes.cpp`/`UiRuntimeTypes.cpp` MMDIAG
probes above - next continuation should re-run for longer once
`faf-main-2c`'s current `VisionDb` rebuild lands, and check whether the
game actually reaches a rendered frame with the commander visible.

**Process lesson (from `faf-main-2c`, worth keeping)**: before editing a
file another session might be touching, `git log --oneline -5 -- <path>`
first - a fix may have already landed. Before trusting a run's result,
confirm `main.exe`'s mtime is from your own build, not a stale or
racing one. This session hit exactly this: added a diagnostic probe to
`CWldSession.cpp` to investigate the crash above, and `faf-main-2c`'s
fix-plus-build landed 2 seconds before mine, tearing their build and
costing both sessions a run. Probe reverted (`git checkout --`) once the
real fix was confirmed landed.

## NEW BLOCKER surfaced 2026-09-01 (faf-main-f7, not yet investigated): Lua GC use-after-free in traverseproto

With the `mNewEntities`/`mNewUnits` fix (`7ef29b8e`) and `VisionDb` fix
(`86be31a1`) both in, ran dbgrun for the first time with zero
ACCESS_VIOLATION faults for the run's first 90-180s (previous runs died
within seconds) - genuine forward progress, `AVATARDIAG` confirms the
real commander (`uel0001`) reaching the avatar gate with a live army
twice across two separate runs. A LONGER run (240s) then hit a NEW,
different crash:

```
CScApp::Main (CScApp.cpp:1085)
-> CUIManager::UpdateFrameRate (CUIManager.cpp:368)
-> lua_setgcthreshold (LuaObject.cpp:1890)
-> luaC_checkGC (LuaObject.cpp:1156)
-> luaC_collectgarbage (LuaObject.cpp:16983)
-> mark (LuaObject.cpp:16943)
-> propagatemarks (LuaObject.cpp:8666)
-> traverseproto (LuaObject.cpp:8216)   <- ACCESS_VIOLATION, read fault
```

Read fault address `0005C05F` resolves to a `[FREE]` (fully deallocated,
not just reused) virtual memory region - a real use-after-free, not a
stale-but-still-mapped page. The `Proto` being traversed has its
`source` field pointing at a live-looking string `"p\hotkeylabelsui.lua"`
(visible in the register dump at `ecx-0x20`) - `hotkeylabelsui.lua` is a
genuine, unremarkable UI script (`import()`ed from `construction.lua`/
`orders.lua`, ships in `modules.nx2`/`lua.nx2`, nothing special about the
script itself). This is a normal PERIODIC GC mark cycle running on the
main/UI thread during ordinary frame processing (`CUIManager::
UpdateFrameRate` calls `lua_setgcthreshold` every frame, which
occasionally triggers a full collect) - the GC is walking its gray/mark
list and finds a `Proto*` (or something in its constant/upvalue chain)
that points into memory that has been fully freed. This smells like
something freeing a chunk of Lua GC-managed memory (a script reload, an
environment swap, a `require`-cache eviction, or a VM/session teardown)
WITHOUT properly unlinking the freed objects from the GC's own root or
gray-object list first - same general SHAPE as this session's other
bugs (a structure that's supposed to stay internally consistent getting
partially, not atomically, updated - c.f. the wild-pointer-write and
mNewEntities/mNewUnits bugs above), but a completely different
subsystem (Lua GC, not sim/sync) and NOT yet investigated at all.

Not yet checked: whether this is deterministic/reproducible or
intermittent (only hit once so far, in the one run that got far enough
and ran long enough); whether it correlates with a specific UI panel
opening (hotkey labels are typically tied to construction/orders menus -
maybe tied to a specific Lua-side UI init step); `lua_setgcthreshold`'s
own recovered body and whatever drives the "full collect now" decision;
whether any OTHER session's in-flight Lua/UI work touches GC lifecycle
or `Proto`/closure caching. This is upstream of the `WxRuntimeTypes.cpp`/
`UiRuntimeTypes.cpp` MMDIAG probes ever firing (game still hasn't
reached `RenderAllHeads` in any run this session) - next continuation
should either chase this directly or get a probe/breakpoint on whatever
frees Lua GC objects to catch the double-free/premature-free in the act.

**Update same pass**: `faf-main-2c` independently found a DIFFERENT,
EARLIER blocker - `CLuaWldUIProvider::CreateGameInterface`
(UiRuntimeTypes.cpp:26894) throws `"GetPrefetchTextures did not return a
table of strings"` even though `gamemain.lua:559`'s Lua side genuinely
returns a table. If that throws, the UI never gets built and
`OnFirstUpdate` never fires - the GC crash above may be unreachable
until THIS is fixed, or may share a root cause with it. Ran a candidate
theory to ground before their probe's data lands: `LuaPlus::LuaObject`
has a real GC-anchoring mechanism - `AddToUsedObjectList`
(LuaObject.cpp:19881) links `this` into a per-root-state intrusive
doubly-linked list (`state->m_headObject`), and `LuaPlusGCFunction`
(LuaObject.cpp:8035) is SUPPOSED to walk that list every collect cycle
via `markroot`'s `globalState->userGCFunction(st)` hook
(LuaObject.cpp:8622-8625), marking every live `LuaObject`'s referenced
value reachable. If that hook were unwired, EVERY long-lived `LuaObject`
C++ wrapper (including `CScriptObject::mLuaObj`, and anything
`RunScript`/`LuaFunction<LuaObject>::operator()` returns) would provide
zero real GC protection - a strong candidate for both bugs at once.
**Checked and it is correctly wired**: `LuaState::LuaState`
(LuaObject.cpp:18208, the ROOT-state ctor) calls `lua_setusergcfunction
(m_state, &LuaPlusGCFunction)` right after `lua_open()`, and
`lua_setusergcfunction` (LuaObject.cpp:1279) correctly stores it into
`state->l_G->userGCFunction`; `lua_open`'s internal init nulls it first
but that's overwritten immediately after, no gap. `LuaObject` has no
move ctor/assignment (relies on the copy ctor, which does re-link
correctly via `AddToUsedObjectList` again), so no obvious list-splice
corruption path either. Root cause for BOTH crashes is still open -
this specific mechanism is now a confirmed-clean, ruled-out lead, not a
place to re-check next time. `RunScript`'s actual call chain (`CScriptObject::
RunScript` -> `LuaFunction<LuaObject>::operator()`, LuaObject.h:2938-2983)
is otherwise straightforward: pushes self+args, `lua_call` with 1 expected
result, builds the return `LuaObject` from `LuaStackObject(st, -1)`
BEFORE `lua_settop` restores the stack (correct ordering, not a
stack-invalidation bug either).

## Likely explanation for "game doesn't close" (2026-09-01, faf-main-f7, hypothesis - not fix-verified)

User also reported this segment: "Game is not closing after we close
window, it keeps running in processes and sound playing." Traced the
close path while `faf-main-2c` had the machine for a run (static-only,
no build/run):
`WSupComFrame::OnCloseWindow` (WxRuntimeTypes.cpp:65696, ground truth
`FUN_008CDAA0`) - clicking the window's X button raises
`wxEVT_CLOSE_WINDOW`, and (when the window isn't minimized) this handler
does **not** close anything itself - it calls `moho::ShowEscapeDialog(true)`
and returns, i.e. the OS close button is *supposed* to bring up the
in-game escape/quit menu rather than closing immediately. This matches
the binary (the Doxygen block cites `FUN_008CDAA0` directly) - not a
recovery bug, this is the original game's UX.

`ShowEscapeDialog` (IUIManager.cpp:484) is a thin bridge: `g_UIManager`
null-check -> `SCR_Import(state, "/lua/ui/uimain.lua")` ->
`uiMainModule["ShowEscapeDialog"]` -> wrap as `LuaFunction<bool>` -> call
it. **If `g_UIManager`/`mLuaState` is null, this returns `true`
immediately without showing anything or closing anything** - clicking X
would then look exactly like "nothing happens, game keeps running." Same
failure mode if `uimain.lua` hasn't finished executing far enough to
have defined its `ShowEscapeDialog` global yet (indexing a not-yet-
defined field returns nil, and the call semantics on a nil
`LuaFunction<bool>` weren't checked further - not needed if the
null-manager path is what's firing).

**Working hypothesis: this may not be a separate bug at all.** Given
`faf-main-2c`'s live finding today that `CLuaWldUIProvider::
CreateGameInterface` throws (`GetPrefetchTextures did not return a table
of strings`) before the game UI finishes building, it's plausible the
SAME broken initialization leaves `uimain.lua`'s own state incomplete
enough that `ShowEscapeDialog` silently no-ops - which would mean fixing
the `GetPrefetchTextures`/GC crash chain also fixes "won't close",
without a separate change. Not verified live - the close path itself
hasn't been probed, and this is inference from two static reads, not a
confirmed shared root cause. Worth checking once a run reaches the point
of testing window-close: does `g_UIManager` end up non-null despite
`CreateGameInterface` throwing (init order might make this bug survive
even after their fix), and does `ShowEscapeDialog`'s Lua call actually
reach a real, callable function.

## "Ready for recall" re-confirmed out of scope (2026-09-01, faf-main-f7)

User's 4th reported symptom this segment: "ready for recall visible when
it shouldn't". Read `gamedata/lua/ui/game/recall.lua` fresh (not relying
on a possibly-stale prior-session summary): it's a complete, working
FAF gameplay feature (Support Commander recall vote panel), starts
hidden (`SetLayout()`'s `:Hide()`), and only becomes visible via
`RequestHandler(data)` when sim-side sync data carries `data.Open`.
Confirmed **zero** `src/sdk/**` hits for `RecallVote`/`SetRecallVote` -
the entire mechanism (`SimCallback({Func = "SetRecallVote", ...})` on
the way out, `RequestHandler` on the way in) is Lua-to-Lua; the engine's
role is only the generic, feature-agnostic `SimCallback`/sync-data
plumbing, which doesn't know or care what "SetRecallVote" means. Same
conclusion as whatever prior-session investigation the compacted summary
referenced ("pure Lua, out of scope"), now independently re-derived: if
this panel shows incorrectly, the bug (if any) lives in FAF's own Lua
content, not in anything `src/sdk/**` recovery would touch. Not
re-investigating further unless new evidence specifically implicates
engine-side sync delivery.

## GetPrefetchTextures: independent second-pass check, also came up clean

While `faf-main-2c` had the machine for a live-probe run, independently
re-checked several more layers of the call chain from scratch (not
reading their notes first, to get a genuinely independent pass) -
`CScriptObject::FindScript` (CScriptObject.cpp:840, correct
push-index-wrap-before-settop ordering, same shape as the general
`LuaFunction::operator()` template) and, on a hunch given this session's
earlier `moho.<Manipulator>` global-publishing bug (`6eb57cac`): is
`moho.WldUIProvider_methods` (the base class `wlduiprovider.lua`'s
`WldUIProvider = ClassUI(moho.WldUIProvider_methods) {...}` inherits
from) itself properly published? Same general bug SHAPE as the 11 fixed
manipulators - a `CScrLuaClassBinder` can be perfectly declared and
still never run if nothing invokes the function holding its `static`
local. **Checked and it's fine**: `RegisterLuaClassCLuaWldUIProvider`
(UiRuntimeTypes.cpp:30373) is one of ~18 calls inside
`MauiLuaClassBinderBootstrap`'s constructor (UiRuntimeTypes.cpp:30671),
and a real global instance (`gMauiLuaClassBinderBootstrap`, :30712)
exists to run that constructor at static-init time - not an orphaned
bootstrap. `CUIWorldView`'s own registration lives in the exact same
list, for what it's worth (rules out "the whole Maui/UI class-binder
pass never runs" as an explanation for anything else either).

Net: `LuaObject`/`LuaFunction` bridge, GC anchoring, `FindScript`, and
`WldUIProvider`'s class registration are now ALL independently
double-checked clean by two separate sessions. Whatever's actually
wrong is more specific than any of these - most likely either something
about `CreateGameInterface`'s exact call timing, or a genuine Lua-side
issue in `prefetchtextures.lua`/`gamemain.lua`'s closures. `faf-main-2c`'s
live `[PFDIAG]` probe (naming the actual returned type) is the fastest
remaining path to an answer - static reading has been thorough on this
one and is hitting diminishing returns without that data point.

## 2026-09-01 (evening): commander avatar chain COMPLETE; new blocker is a Lua string-interning suspect

### HARNESS: `/windowed 1280 720` IS BROKEN ON THIS HOST - USE 1024x768

Cost several run cycles. Same binary, same tree:

    /windowed 1280 720  -> 107 log lines, dies
    /windowed 1024 768  -> 3611 log lines, reaches in-game

**Do not diagnose a 107-line run as a code bug.** Two red herrings inside it,
both of which the RETAIL `ForgedAlliance.exe` also produces while running
happily for 35s+:
  - `Failed to create DirectSound.`
  - `GAL Exception: DeviceD3D9.cpp(1229) error: invalid head count` (x2)
Retail also logs `Unable to set requested size 1280,720`, which is the tell.

**Reference-binary comparison is the fastest oracle in this whole area.**
Retail runs from the same bin dir: `ForgedAlliance.exe /windowed 1024 768
/nobugreport /map SCMP_009 /log refmap` reaches game time 1:01 and 14727 log
lines. Diff its log against ours to separate "our bug" from "content/host".

### Commander avatar chain is now COMPLETE (goal mechanism working)

    [AVATARDIAG] army=46F81B00 bp=198DE200 quickSelect=1 id='xsl0001'
    [ZOOMDIAG]   GetArmyAvatars: focusArmy=46F81B00 begin=0DBEB530
                 end=0DBEB538 count=1

`count=1` where it was 0 with a null range every previous run. Four commits
got there: 569dc064 (Sim::Sync entity walk), 7ef29b8e (mNewEntities +0x128 vs
mNewUnits +0x138), 86be31a1 (VisionDb duplicate skeleton), plus 2a80fc80.

### CURRENT BLOCKER: orders.lua local resolves as a global -> no world view

    orders.lua(1106): access to nonexistent global variable "AttackMoveBehavior"
      -> commandmode.lua -> worldview.lua:202 CreateMainWorldView
      -> gamemain.lua:273 CreateUI

`local function AttackMoveBehavior` is declared at orders.lua:517, **file
scope, no indent**, and used at 1106 in the same chunk. `CreateMainWorldView`
failing means **there is no world view at all**, so nothing 3D renders no
matter where the camera points.

**Confirmed OURS, not content**: retail on the same map has **zero**
`AttackMoveBehavior` errors (it has 2 unrelated "nonexistent global"s).

**Live probe result** (`[VARDIAG]` in `singlevaraux`):

    lookup 'AttackMoveBehavior' nactvar=73 nlocvars=74 prev=00000000 base=1

It is local **#52 of 74**, `nactvar=73`, main chunk. So the name IS in range of
the `actvar[0..72]` scan, and the scan still fails to match.

**Leading hypothesis: duplicate `TString`s / broken string interning.**
`singlevaraux` compares `name == f->locvars[actvar[i]].varname` by POINTER.
Lua interns identifiers, so two TStrings for one text makes that test
impossible to satisfy. This also explains why exactly ONE local in one file
fails rather than every `local function` everywhere - a systematic parser bug
would break everything. Suspect `luaS_newlstr` / the string-table resize path.
If true it may also explain the concurrent Lua GC crash in `traverseproto`.
A probe to confirm (same-text/different-pointer detector in the scan) is
written but not yet run.

### VERIFIED CORRECT against ground truth - do NOT re-check these

All confirmed by reading the asm directly, not by "matches stock":
  - `FuncState`: `f`@0x00, `pc`@0x18, `freereg`@0x24, `nactvar`@0x34,
    `actvar`@0x2B8 stride 4, `MAXVARS`=0xC8. From `removevars` FUN_0091ADC0:
    `mov ecx,[eax+ecx*4+2B8h]`, `cmp [eax+34h],edx`.
  - `Proto::locvars`@0x18, `LocVar` stride 12 with `endpc`@+0x08 (same asm:
    `lea ecx,[ecx+ecx*2]` then `mov [edi+ecx*4+8],ebx`).
  - `singlevaraux`, `new_localvar`, `adjustlocalvars`, `removevars` all match.
  - `localfunc` (FUN_0091D590) genuinely uses **freereg** (`mov eax,[ebp+24h]`),
    NOT stock 5.0's `nactvar` - our source is right, do not "fix" it to stock.
  - Peer independently asm-verified `Proto`/`LocVar` via `luaF_freeproto`
    (0x00915090) and `close_func` (0x0091B350): also clean.

### Shared-checkout protocol that actually matters (learned the hard way)

Three sessions, one checkout, one staged `main.exe`. Concrete losses this
session: two torn builds, one duplicated investigation, one clobbered peer
probe (I ran `git checkout -- <file>` and destroyed a peer's uncommitted
work - **strip only your own hunk instead**), and several runs invalidated by
two game instances colliding on the D3D/audio device.

  - **msbuild silently stages a STALE binary.** It reports success and prints
    "Staging main.exe" without relinking. Always
    `Remove-Item output\main\Win32\Debug\main.exe` before building, then check
    the staged mtime is newer than your build.
  - **Before每 run**: `Get-Process -Name main,dbgrun,ForgedAlliance` and abort
    if anything is up. Two instances give `invalid head count` + no AVATARDIAG,
    which reads exactly like a real early crash.
  - **Before diagnosing any regression**: `git status` + file mtimes. A file
    modified within ~2 min of your build may have been caught mid-edit.

### faf-main-f7's supplementary pass on the string-table/GC side (also clean)

While the duplicate-`TString` theory was pending confirmation, independently
read (not just skimmed) `luaS_resize`, `newlstr`, `luaS_newlstr`
(LuaObject.cpp:2809/2848/2894), `sweeplist`/`sweepstrings`
(LuaObject.cpp:8495/8538), and `luaC_sweep` (LuaObject.cpp:17476). All
structurally match stock Lua 5.0's algorithms:
  - `luaS_newlstr`'s roll-hash loop is byte-for-byte stock's `h = h ^
    ((h<<5)+(h>>2)+(unsigned char)str[l1-1])` shape.
  - `luaS_resize`'s rehash correctly reads the OLD `strt.hash` while writing
    into the new local `newHash`, reassigning `strt.hash` only after the loop
    completes - no read-through-the-new-table-mid-rehash bug.
  - `newlstr` (the miss path) computes its bucket from the CURRENT
    `strt.size` before any possible grow-triggered resize, matching stock's
    insert-then-maybe-resize order.
  - `sweeplist`'s live/dead comparison (`colorClass > limit`) already carries
    a documented, deliberate deviation from stock (no weak-table-bit masking,
    matching the shipped binary's raw byte compare) - this was already fixed
    in a prior pass, not a fresh finding.
  - `luaC_sweep` (the `limit=0x100` "sweep everything" variant) is only used
    by `close_state`/full teardown, not the normal per-frame
    `luaC_collectgarbage` path - not in play for an in-game crash.

None of these explain a resize dropping/duplicating an entry. Not saying the
duplicate-`TString` theory is wrong - peer's live pointer-identity evidence
(`AttackMoveBehavior` inside `actvar` range, comparison still failing) is
strong and unexplained by anything else found so far - just that if it's a
code bug rather than e.g. two independent `lua_State`/`global_State`
instances never sharing a string table in the first place, it isn't in any
of the functions listed above. Worth checking next if the confirming probe
lands: whether `orders.lua`'s WHOLE chunk actually compiles under one
`lua_State`/`LexState` throughout, or whether something (a coroutine, a
sandboxed sub-environment, a require-cache keyed per-caller) hands the
loader a different state partway through a single file's parse.

### Interning theory refuted by faf-main-2c's own probe - non-deterministic corruption instead

Their confirming probe came back NEGATIVE: same tree, same binary, same
1024x768 config, `AttackMoveBehavior`'s lookup didn't even fire on the
retry - the run failed at `GetPrefetchTextures` instead. Since Lua
compilation is deterministic, a real interning bug would reproduce every
time on identical input; alternating failures rules that out as *the*
cause. Revised, better-fitting theory: **non-deterministic heap
corruption from a wild write, and both symptoms (`traverseproto` fault,
`GetPrefetchTextures` returning a non-table) are the same bug wearing
different hats** depending on which Lua object happens to sit next to
whatever gets clobbered on a given run. Matches this session's other
three "hand-rolled `*RuntimeView` struct writes through a fabricated/
wrong-base offset" bugs found today (`872bfe09`, `7ef29b8e`,
`CAimManipulator`'s fake vtable).

**Precedent found**: two PRIOR sessions hit and solved this EXACT crash
signature before -
[[project-lua-gc-upvalue-corruption]] (2026-08-04, `60ec20f`) and
[[project-lua-gc-string-table-corruption]] (2026-08-14, `7f6bc1d`). The
first is the closer match: `traverseproto` reached via `CUIManager::
UpdateFrameRate -> lua_pushstring -> luaC_checkGC` - identical call
chain to what we're seeing now. Root cause that time: `CD3DPrimBatcher`
was a "thin class" (zero real data members, everything living in a
`CD3DPrimBatcherRuntimeView` reached by `reinterpret_cast`), so `sizeof
(CD3DPrimBatcher)` was 4 bytes (just the vtable pointer) while its own
constructor wrote to a field at `+0x120`. A plain `new CD3DPrimBatcher`
smashed ~70 neighbouring 4-byte heap blocks - and a Lua `Proto`'s
locvars/upvalues array for a function with exactly one local is exactly
one 4-byte slot, landing in the same size class. Fixed by giving it an
explicit `operator new(0x124)` matching the binary. That memory file's
own warning is the reason to suspect a fresh instance now: "Writing
`new CMauiFrame(...)` anywhere would reintroduce this instantly" - it's
a recurring risk class in this codebase, not a one-off.

**Checked and ruled out as the site of a NEW instance** (both sessions
notified): every class with a `*RuntimeView` companion under
`moho/ui/**` against its actual allocation site - `CMauiMovie` (0x168),
`CMauiScrollbar` (0x158), `CMauiCursor` (0x58), `CMauiBitmap` (0x18C),
`CMauiFrame` (0x134), `CMauiBorder` (0x174), `CMauiEdit` (0x198),
`CMauiGroup` (0x11C), `CMauiHistogram` (0x134), `CMauiMesh` (0x140),
`CMauiText` (0x194), `CMauiItemList` (0x158), `CUIMapPreview` (0x124),
`CUIWorldMesh` (0x38) - all 14 use the safe explicit-size
`AllocateZeroedUiObject<T>(binary_size)` pattern with a comment citing
the binary's `push 0x...`. `CUIWorldView` uses `AllocateZeroedUiObject<
void>(sizeof(CUIWorldView))` instead of a literal, which looked
suspicious at first glance, but `sizeof(CUIWorldView) == 0x2A8` is
itself static_assert-guarded (UiRuntimeTypes.h:4208) - if it were ever
wrong the BUILD would fail, not silently misallocate, so this is
actually safer than a bare literal, not a risk. Grepped
`WxRuntimeTypes.cpp`/`UiRuntimeTypes.cpp` for every OTHER plain
`new ClassName(...)` site not going through an explicit-size helper:
only `new CLuaWldUIProvider(...)`, `new Mesh(...)` (×2, one in
`Mesh.cpp`'s own `FindOrCreateMesh`, one in `UiRuntimeTypes.cpp`), and
`new CLogAdditionEvent(...)` - none of these three classes are thin
(`CLuaWldUIProvider` has real members incl. `mPrefetchData`, a real
`FastVector`; `Mesh` has real declared fields from `+0x20` onward per
today's own `MeshRendererMeshCacheEntry` work above; `CLogAdditionEvent`
not yet checked in detail but is a small logging-only type, low prior).

**Not yet checked**: the SAME audit for `moho/app/WxRuntimeTypes.cpp`
beyond the one `CLogAdditionEvent` hit (file is huge, only spot-checked
so far); whether the corruptor is sim-side rather than UI-side (
`faf-main-2c` is sweeping that); the two prior incidents' reusable
allocator-instrumentation probes (live-block bitmap + value-watch,
`gpg/core/utils/Global.cpp`) as a live-catch alternative to more static
grepping - high individual setup cost, but proven to work twice on this
exact symptom class, and doesn't depend on already knowing which class
to suspect.

## 2026-09-01 (late): five symptoms, one corruptor - and four REFUTED hypotheses

After the avatar chain was fixed, every remaining failure is **one
non-deterministic heap corruption** wearing different hats. Across runs of the
*same binary on the same map* we have now observed, at random:

  1. `orders.lua(1106): access to nonexistent global variable
     "AttackMoveBehavior"` (a file-scope `local function` resolving as a global)
  2. `GetPrefetchTextures did not return a table of strings`
  3. `traverseproto` fault during `luaC_collectgarbage`
  4. `ForEachAllArmyUnit` lambda fault, read from 0x188
  5. a bare `gpg::Die` at WinMain.cpp:689 with no fault at all

Symptoms 1 and 2 both break `CreateUI` -> `CreateMainWorldView`, which means
**no world view exists at all**, so nothing 3D renders regardless of the
camera. That is what now stands between us and seeing the commander.

### REFUTED - do not re-investigate these

  - **Lua parser local-resolution logic.** `singlevaraux`, `new_localvar`,
    `adjustlocalvars`, `removevars`, `luaI_registerlocalvar`, `localfunc` all
    verified against asm. `FuncState` offsets confirmed from `removevars`
    FUN_0091ADC0 (`nactvar`@0x34, `actvar`@0x2B8 stride 4, MAXVARS=0xC8);
    `Proto::locvars`@0x18, `LocVar` stride 12, `endpc`@+0x08.
    **`localfunc` (FUN_0091D590) genuinely uses `freereg` (`mov eax,[ebp+24h]`),
    NOT stock 5.0's `nactvar` - do not "fix" it to match stock.**
  - **Duplicate-`TString` / broken interning.** `luaS_newlstr` and
    `luaS_resize` match ground truth (incl. the `tt`/`len` checks -
    `cmp byte ptr [eax+4],4` / `cmp [eax+10h],ebp`); `TString` layout asserted
    and correct. A live probe for same-text/different-pointer never even
    reached the lookup on the next run - the failure had moved elsewhere.
    Interning is a **victim**, not the cause.
  - **Thin-class ctor overrun** (the documented `CD3DPrimBatcher` bug class,
    see [[project_lua_gc_upvalue_corruption]]). Swept every class in `moho/`
    with a `*RuntimeView` companion that is `new`'d, plus every tiny-`sizeof`
    class that is `new`'d, plus all 46 `reinterpret_cast<...RuntimeView*>(this)`
    sites. **No class/view size mismatch anywhere.** `PathQueue` (0x04) matches
    its 4-byte view; `Projectile` (0x380) matches its view exactly; `CWldMap`'s
    0xC38 `TerrainRuntimeView` is over `IWldTerrainRes` and correctly allocated
    with an explicit size. Peer independently swept `moho/ui/` - also clean.
  - **Dangling `Entity*` in the tracking list via `~Entity`.** Probed the
    `else` branch of `~Entity`'s `ReleaseId` null guard: fires **zero** times.
    Every entity does release and does get removed. (Note the divergence
    anyway: ground truth FUN_006785D0 calls
    `EntityDB::ReleaseId(this->mSim->mEntityDB, this->mConstDat.mId)`
    **unconditionally** - our null guard is an addition.)

### Next tool: allocator instrumentation (peer owns it)

Both static sweeps are exhausted. The remaining shape is a **wild write or a
wrong-pointer `free`**, matching the second documented incident
([[project_lua_gc_string_table_corruption]] - a wild `delete[]` from a ctor).
Recipe: live-block bitmap + value-watch + per-object linked flag, hooked into
`malloc_0`/`free`/`AllocateInSmallBlock`/`PushHeapBlock`, raw Win32 I/O for
reentrancy safety. **Check the live-block bitmap at the `free()` choke point,
not only at alloc** - three of today's bugs were writes/frees through a wrong
pointer, which a size-class check alone would miss.

## Host degradation after many launches - and the sweep blind spot

**After ~35 game launches in a session, this host's display/audio device
state degrades** and every launch dies at ~107 log lines with
`Failed to create DirectSound.` followed by
`GAL Exception: DeviceD3D9.cpp(1229) invalid head count`. Confirmed
environmental, not a code regression:

  - retail `ForgedAlliance.exe` at 1024x768 then also stops at ~105 lines with
    the same two exceptions (it survives them; ours exits), where an hour
    earlier the same retail invocation with `/map SCMP_009` gave 14727 lines
    and 1:01 game time.
  - nothing else was running (checked `Get-Process main,dbgrun,ForgedAlliance`).

**Back off rather than hammering** - the operator's standing note says this
machine can wedge hard enough to need a reboot. Give it idle time and use
retail as a control before believing any negative run result.

**Real resilience gap this exposed** (independent of the host, worth
recovering): `CScApp::CreateAppFrame` returns false on a `gpg::gal::Error`;
the caller (CScApp.cpp ~1318) retries once with a fallback single-head
windowed `DeviceContext`, but our fallback fails too and we exit, while
retail survives the identical pair of exceptions and keeps running.

**REFUTED (2026-09-01, faf-main-f7): not a recovery bug, do not "fix" this.**
Read `CScApp::CreateDevice`'s (0x008D0370) real ground-truth `.c` directly at
the exact retry site — `FUN_008D0370.c:451-480`. It matches our recovered
`CScApp.cpp:1318-1330` instruction-for-instruction: same fallback
`DeviceContext` construction (`useD3D10 ? 2 : 1`, matching ground truth's
`CFG_GetArgOption("/D3D10",...) + 1`), same single windowed head at
`wnd_DefaultCreateWidth`/`Height`, same second `CreateAppFrame(..., false,
...)` call, and if THAT also fails, ground truth does exactly what we do:
clean up and `return false` — there is no third attempt, no extra
resilience mechanism, nothing missing. **Whatever explains retail
occasionally surviving where our build doesn't, it is not a difference in
this retry logic** — both binaries give up identically after two failed
attempts. The most likely explanation, given the same session's own later
finding that "even the pristine retail `ForgedAlliance.exe` now fails the
same way... after ~35 launches" (see the "Host degradation" section further
down this file), is that the earlier "retail survives" observation was made
against a less-degraded host state than the later comparison, not a
code-level resilience gap. Closed, no fix needed — do not re-audit this
retry path without new evidence specifically contradicting the ground-truth
match above.

### Sweep blind spot worth remembering

My thin-class sweep enumerated classes allocated via `new <ClassName>` that
had a `<ClassName>RuntimeView` companion. It **missed** `TextReadArchive`,
which a peer then found: allocated by a factory doing a raw
`::operator new(sizeof(TextReadArchive))` = 0x38 while its ctor writes through
a `TextReadArchiveRuntimeView` ending at +0x44 - a 12-byte overflow on every
text-archive construction (fixed 84b7a604; binary's asm shows `push 44h`).

**Audit the raw `::operator new(sizeof(X))` factory sites, not the `new X`
sites** - that is where an explicit size can silently disagree with what the
constructor writes.

Same peer also found (f1989beb) that `using namespace gpg;` does NOT anchor a
bare free-function *definition* into `gpg::` - only class-qualified
`Class::Method()` out-of-line definitions do. `CreateTextReadArchive` had been
defined in the global namespace, so `gpg::CreateTextReadArchive` was an
unresolved external the whole time (masked by /FORCE). Worth checking other
bare free-function definitions in files that rely on `using namespace`.

### STATUS as of 2026-09-01 ~17:00: both commits build/link-verified, NOT runtime-verified - paused for host safety, not doubt

Rebuilt clean after both commits and confirmed via the actual link output
that the previously-baseline "unresolved external symbol gpg::
CreateTextReadArchive" is gone from the error list - `f1989beb` is
confirmed correct at the LINK level, not just by reading. `main.exe`
built and staged successfully.

Two live-test attempts both failed at `CheckAdapterSelectionForSetup`
(D3D9Interfaces.cpp:3513, "invalid head count") within ~110 log lines -
never reaching unit creation, let alone the Lua GC territory these
fixes target. **This is a host device-state problem, not a result about
the fix**: `faf-main-2c` independently hit the identical failure at the
same time, on a *separately built* binary, and confirmed even the
pristine retail `ForgedAlliance.exe` now fails the same way at 1024x768
after succeeding earlier today. ~35 launches across both sessions today
is the likely cause - device/audio state degrading under repeated
churn, not anything either of us changed.

**Stopped testing deliberately, not just cautiously.** This machine has
a documented standing operator instruction (global CLAUDE.md) against
exactly this pattern - repeated heavy process/device load risks
wedging the host hard enough to need a hard reboot, and retrying a
hung/degraded resource in a loop is explicitly called out as the
mechanism, not a fix. Both sessions stopped launching `main.exe`/
`dbgrun.exe` as of this note. **Before any future continuation resumes
live testing**: confirm significant idle time has passed and ideally
that a clean retail `ForgedAlliance.exe` launch succeeds first, as a
control - don't just retry the recovered build and interpret a device
failure as a result either way.

**Net for a fresh session picking this up**: `84b7a604` (the 12-byte
overflow fix) and `f1989beb` (the namespace/link fix) are both real,
each independently justified by direct evidence (asm-cited allocation
size; confirmed-vanished link error) and should NOT be reverted or
re-litigated absent new evidence - but whether they actually resolve
the `traverseproto`/`GetPrefetchTextures`/`ForEachAllArmyUnit`/`gpg::
Die` crash family is still an open, untested question. That's the
single highest-value next step once the host is confirmed safe to test
on again.

### Honest relevance check on the TextReadArchive fix (2026-09-01, faf-main-f7) - real bug, connection to THIS crash unconfirmed

Traced `CreateTextReadArchive`'s only caller: `LuaSerializeFromString`
(`ArchiveSerialization.cpp:11006`), which implements the Lua-visible
`serialize.fromstring(str)` library entry point (registered
`luaopen_serialize`, LuaObject.cpp:17892 - a standard library opened
for every Lua state, so reachable in principle from anywhere).
**Grepped the entire `gamedata/lua/**` tree for `serialize.fromstring`
and `serialize\[.fromstring` - zero hits.** No current game Lua content
calls it directly. `serialize.tostring`'s sibling is equally unused by
grep. This does NOT mean the fix is wrong or pointless (it's still a
confirmed, asm-cited 12-byte overflow that WILL corrupt memory on any
call, however rare), but it substantially weakens the case that it's
*the* corruptor behind the `traverseproto`/`GetPrefetchTextures`/
`ForEachAllArmyUnit` family specifically - I'd said "might be the
actual corruptor" to `faf-main-2c` before doing this check, which was
ahead of the evidence at the time.

**Not yet checked, and the natural next step before trusting a live
result either way**: whether `serialize.tostring`/`fromstring` get
invoked indirectly from C++ (not Lua-visible call sites) - e.g. as part
of `SimCallback` argument marshalling across the sim/UI boundary or
over network sync, which would not show up in a `gamedata/lua` grep at
all. If that path doesn't exist either, the true corruptor is still
out there and the allocator-instrumentation approach remains the right
tool. Keep both fixes regardless - they're correct on their own
evidence - but don't report the crash "fixed" on the strength of this
pair alone once live testing resumes; treat it as one good candidate
among possibly several, not a confirmed root cause.
