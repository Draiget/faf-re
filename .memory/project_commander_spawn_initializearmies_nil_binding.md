---
name: project-commander-spawn-initializearmies-nil-binding
description: FIXED and runtime-verified 2026-09-01 (dfa833f7 + f36336a0). InitializeArmies aborted on a nil `moho.IEffect.ScaleEmitter` upvalue; moho.IEffect was never exported. Army init now completes.
metadata:
  type: project
---

# Why the commander doesn't spawn — FIXED, runtime-verified

## RESOLUTION (2026-09-01): two commits, both needed

`moho.IEffect` was never *exported*, and separately its method binders were
publishing as globals. Neither fix works alone:

- **`dfa833f7`** — the seven IEffect `CScrLuaBinder`s passed `nullptr` as the
  owner factory, so `CScrLuaBinder::Run` published them as plain globals.
  Now they pass `&CScrLuaMetatableFactory<IEffect>::Instance()`, as the binary
  does (`func_IEffectScaleEmitter_LuaFuncDef`, 0x0066DA40).
- **`f36336a0`** — there was no `CScrLuaClassBinder` for `"moho.IEffect"` at
  all, so that factory's table was never named into the `moho` namespace.
  Evidence: the string is at VA 0x00E25EF4 (.rdata) with exactly one pointer to
  it in the image, at VA 0x00F59EE8 — the class-binder record, adjacent fields
  name "moho.IEffect" / group "IEffect" / help "".

**Verified at runtime.** The nil-upval warning is gone and army initialization
now runs to completion:

    info: Initialize Skirmish for Isus (AI: Rush)
    info: CreateArmy group ARMY_5
    info: Initialize Armies brain nickname is Ahn-Ushithow (AI: Rush)
    ... ARMY_6, ARMY_7, ARMY_8, NEUTRAL_CIVILIAN
    debug: NavGenerator / marker caching ...

Previously it died inside `InitializeArmies` before any of that.

**Next blocker after this fix:** `GetPrefetchTextures did not return a table of
strings` (`CLuaWldUIProvider::CreateGameInterface`). Checked and NOT the cause:
our `LuaObject::IsNil` matches the binary (0x009072F0,
`m_state && tt == LUA_TNIL`), and `RunScriptObj_Obj` (0x007CB940) also
default-constructs a state-less object on the not-found path, exactly like our
`RunScript`. So the guard shapes agree; the returned object is genuinely
non-nil and non-table.

The generalisable finding is in
[[project_moho_class_exports_10_missing]] — 10 of the engine's 56 `moho.*`
exports are missing, and two of the remaining nine are executable rather than
annotation-only.

---

## Original investigation (kept for the evidence trail)



Captured 2026-09-01 from the game's own Fatal Error dialog (which prints the
last 100 log lines) on `/map SCMP_009`. This is the answer to the standing
goal's "check logs why it's not working".

## How far it gets

Much further than any previous run. The log shows `CreateArmy group ARMY_8`,
`NEUTRAL_CIVILIAN`, full NavGenerator output (190 labels culled, 47873 cells,
per-layer Air/Amphibious/Hover/Land/Water tables), and all the marker caching
(rally points, naval areas, expansion areas). So map load and army creation are
working.

## Where it dies

    warning: ...lua.nx2\lua\defaultexplosions.lua(706):
             attempt to call upval 'IEffectScaleEmitter' (a nil value)
    warning: stack traceback:
      unit.lua:1828              in function 'CreateWreckageProp'
      scenariutilities.lua:508   in function 'CreateWreckage'
      scenarioutilities.lua:567  in function 'CreateWreckageUnit'
      scenarioutilities.lua:691  in function 'InitializeArmies'
      scmp_009_script.lua:4
      siminit.lua:408            in function 'BeginSessionMapSetup'
      siminit.lua:309            in function 'BeginSession'

**`InitializeArmies` is where the commander is created.** It aborts partway
through, while creating the map's pre-placed wreckage, so army setup never
completes and no ACU is spawned. That is the goal's root cause.

The process then dies on the second symptom:

    Unhandled exception: GetPrefetchTextures did not return a table of strings
      gpg::Die  <- WinMain (WinMain.cpp:689)

## The nil value, precisely

`defaultexplosions.lua:665` does:

    local IEffectScaleEmitter = _G.moho.IEffect.ScaleEmitter

captured **at module load time** and called at line 706. So `moho.IEffect.
ScaleEmitter` was nil when that module loaded. Two candidate causes, not yet
separated:

1. **The binding is never published.** Our registration looks correct —
   `EffectLuaStartupRegistrations.cpp:2297` builds a `CScrLuaBinder` with
   `SimLuaInitSet()`, name `"ScaleEmitter"`, class `"IEffect"`, and an instance
   of the driving bootstrap struct *is* created
   (`gEffectLuaStartupRegistrationsLuaFuncDefBootstrap`, line 3522) so it is not
   the classic never-instantiated-registrar bug. But "registered into the set"
   and "present in the sim Lua state's `moho.IEffect` table when
   defaultexplosions.lua loads" are different claims, and only the first is
   verified.
2. **Load-order.** The module captures the method into a local at load time; if
   the set is published to the state after that, the local is nil forever even
   though the method later exists.

### Traced to the boundary (2026-09-01), and one real fix landed

**Landed (`dfa833f7`): all seven IEffect binders were passing `nullptr` as the
owner factory.** `CScrLuaBinder::Run` is:

    if (mOwnerFactory) { mOwnerFactory->Get(state).Register(mName, ...); return; }
    state->GetGlobals().Register(mName, ...);

The `groupName` ("IEffect") is used by nothing but `DumpDocs`, so every one of
those methods was being published as a plain global. The binary sets the
factory explicitly — `func_IEffectScaleEmitter_LuaFuncDef` (0x0066DA40) does
`mFactory = &CScrLuaMetatableFactory<Moho::IEffect>::sInstance`, and
`func_IEffectResizeEmitterCurve_LuaFuncDef` (0x0066DBC0) the same. Fixed, and
the sibling CDecalHandle binder in the same file already did it right.

**An audit of the whole tree found this was the only instance:** 775
class-scoped binders already pass a factory, 444 are genuine `<global>`
binders, and after the fix zero pass `nullptr` with a class group.

**But the fix alone does not clear the symptom** — verified by a full rebuild
and re-run, which produced the identical `IEffectScaleEmitter (a nil value)`
error. (Careful: the Lua warning goes to the game log, NOT to
`OutputDebugString`, so grepping the dbgrun log for it always returns zero and
proves nothing. Use the Fatal Error dialog screenshot.)

The reason is the next link: `CScrLuaObjectFactory::Get` caches factory tables
in a global named **`__factory_objects`**, keyed by a numeric
`mFactoryObjectIndex`, and `CScrLuaMetatableFactory<T>::Create` returns
`SCR_CreateSimpleMetatable(state)` — an anonymous metatable. That table serves
instance-style calls (`effect:ScaleEmitter(...)`) as an `__index`, but it is
never published under a name, so `_G.moho.IEffect` is a different object.

**Where `moho` comes from is the open question, and it is outside this exe.**
`globalinit.lua:45` does `for name, cclass in moho do` and calls the table "a
list of exported methods and base classes" built by the engine — but there is
no `"moho"` string literal anywhere in `src/sdk`, and a `string_refs` query
over the whole corpus finds no `moho` string in the binary either. Several of
these factory internals carry `0x100xxxxx` addresses (e.g.
`CScrLuaMetatableFactory<CScriptObject*>::Create` at 0x100BA690, annotated
"MohoEngine.dll"), so the class-export publication very likely lives in
**MohoEngine.dll**, a separate module from `main.exe`.

That is the next thing to establish: whether `moho` is populated by
MohoEngine.dll code we have not recovered, and if so what fills each
`moho.<Class>` with its method list.

Note this is the same *shape* as the `AttackMoveBehavior` symptom (a Lua
name reading nil) but not necessarily the same cause — that one was a genuine
file-scope local, this one is a table lookup that can legitimately be nil.
See [[project_locvars_use_after_free_localized]].

## How to reproduce the log

`//log` **needs a filename argument** — `//log` alone writes no file, which is
why earlier runs in this session produced no `.sclog` at all. Even with one, the
file is only flushed on a clean exit, so killing the process loses it. The Fatal
Error dialog's "Last 100 lines of log" is the reliable capture, via a DPI-aware
screenshot (this box is 3840x2160; see
[[project_render_goal_first_frame_confirmed]]).

Healthy host state for a representative run is **4 D3D9 adapters** (two GPUs,
four displays) — see [[project_d3d9_zero_adapters_is_host_not_code]].

## Static re-verification of the whole publish chain (2026-09-01, faf-main-f7) — mechanism is sound, load-order theory REFUTED, mystery narrows further

Independently re-traced every link in "how does `_G.moho.IEffect` get built"
from scratch, reading each implementation directly rather than trusting the
paraphrase above. All of it checks out correct:

- **Load-order theory (candidate cause 2 above) is REFUTED with hard
  evidence.** `Sim.cpp:9821-9843`: `coreSet->RunInits(mLuaState)` and
  `simSet->RunInits(mLuaState)` (the "Sim"-named `CScrLuaInitFormSet`, which
  is what BOTH `SimLuaInitSet()` and `ClassBinderSimLuaInitSet()` resolve to
  — confirmed they're the same underlying set via `SCR_FindLuaInitFormSet
  ("Sim")` in both, `CAiBrainLuaFunctionThunks.cpp:868` /
  `CAiAttackerImpl.cpp:582` / `CAiBrain.cpp:707`) both run **before** the
  first `SCR_LuaDoScript(mLuaState, "/lua/simInit.lua", nullptr)` call at
  line 9843, which is the root of everything that eventually
  `import()`s `defaultexplosions.lua`. So every "Sim"-set registration,
  `moho.IEffect`'s class binder included, is published before any Lua
  content loads. This class of theory should not be re-investigated
  without new evidence it's a DIFFERENT set/state than "Sim" on
  `mLuaState`.
- **The `moho.IEffect` class binder itself is real and already present** —
  found this pass, not previously noted here: `EffectLuaStartupRegistrations.cpp:1084`,
  `static CScrLuaClassBinder binder(SimLuaInitSet(), "moho.IEffect",
  &CScrLuaMetatableFactory<IEffect>::Instance(), "IEffect", "")`. This is
  the SAME shape as the 11 manipulator class binders `6eb57cac` fixed
  (`moho.FootPlantManipulator` etc.) — `moho.IEffect` was never missing a
  class binder the way those were.
- **`CScrLuaClassBinder::Run()`** (`CScrLuaClassBinder.cpp:42-62`, ground
  truth `FUN_004CD460`) is exactly what builds `_G.moho`: walks `mName`
  ("moho.IEffect") splitting on `.`, creates each missing intermediate
  table under globals (`_G.moho = {}` on first use, by ANY class binder —
  not specific to IEffect), then `scope.SetObject("IEffect",
  mClassFactory->Get(state))` at the tail. Read directly, matches the
  binary per its own citation.
- **`CScrLuaMetatableFactory<T>::Instance()`** (`CScrLuaObjectFactory.h:279-283`)
  is a plain Meyers singleton (`static CScrLuaMetatableFactory sInstance;`)
  — one instance per `T` for the whole process, guaranteed by the C++
  standard (no ODR-violation risk across TUs for the same template
  arguments). The class binder's `Instance()` and the per-method binder's
  `sInstance` (the fix target of `dfa833f7`) are provably the exact same
  object.
- **`CScrLuaObjectFactory::Get()`** (`CScrLuaObjectFactory.cpp:1360-1377`)
  is a correct lazy-cache: reads global `__factory_objects[mFactoryObjectIndex]`,
  creates+stores via `Create(state)` on a miss. `mFactoryObjectIndex` is
  assigned once per singleton at construction (`AllocateFactoryObjectIndex()`),
  so every caller going through the SAME singleton's `Get()` — the class
  binder AND the per-method binder both do, per the point above — reads/
  writes the SAME `__factory_objects` slot in the SAME `state`.
- **`CScrLuaInitFormSet::RunInits`** (`CScrLuaInitForm.cpp:147-153`) is a
  plain, correct singly-linked-list walk calling `form->Run(state)` on
  every form — no early-exit, no form-type filter.

**Net: every individual link in the chain is independently correct, and the
ordering is correct.** If `dfa833f7`'s fix (setting the 7 method binders'
`mOwnerFactory`) is itself complete and those 7 `static CScrLuaBinder`
locals genuinely get constructed (their OWN bootstrap-instantiation was
not re-verified this pass — only the CLASS binder's was previously
confirmed, per the "not the classic never-instantiated-registrar bug" note
above; that check has not been independently repeated for the 7 per-method
binders specifically), then `_G.moho.IEffect.ScaleEmitter` should resolve.
Given the memory's own note that a rebuild+rerun after `dfa833f7` still
reproduced the identical nil error, either that per-method-binder
instantiation check is where the real gap is, or there's a subtlety
`Get()`'s Lua-table mechanics have that a static read can't catch (e.g. a
SECOND, different `mLuaState`/`LuaPlus::LuaState` object reading the
factory before the Sim state's `RunInits` pass — worth checking whether
`defaultexplosions.lua` genuinely loads on `mLuaState`, the same state
`Sim.cpp:9812` just built, and not some other/earlier state object with the
same content).

**Suggested next empirical step for whoever has live dbgrun access**: a
temp probe printing `mFactoryObjectIndex` (or `state` pointer identity)
from both `CScrLuaClassBinder::Run()`'s `mClassFactory->Get(state)` call
(for "moho.IEffect" specifically) and `CScrLuaBinder::Run()`'s
`mOwnerFactory->Get(state).Register(...)` call (for `ScaleEmitter`
specifically) — confirm they see the same index AND the same `state`
pointer. That's the one thing static reading can't settle and would
either close this out or point straight at the real remaining gap.
Static reading is exhausted on this specific sub-thread — further passes
should be empirical, not more code tracing of the same functions.
