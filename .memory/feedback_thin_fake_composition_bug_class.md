---
name: feedback_thin_fake_composition_bug_class
description: Reusable bug-class alert — a class recovered as standalone with a fake vtable-tag byte (or just NO base clause at all) instead of real C++ inheritance from a base the binary's RTTI/vtable actually has. 7 confirmed+fixed instances/clusters as of 2026-09-02. Highest-impact instance: CUnitCommand (backs every unit order), which ALSO had a member struct (SCommandUnitSet) independently undersized by 0x1C bytes — see [[project_cunitcommand_missing_base_and_undersized]], leading theory for the session's crash blocker. A full 65-class RTTI sweep (every Moho::CScriptObject-derived class) found no other outstanding candidates. WildMagic/boost instances never independently verified, treat as open if resuming.
metadata:
  type: feedback
---

Watch for this shape whenever recovering a class whose header still carries
the boilerplate `// Auto-generated from IDA VFTABLE/RTTI scan... skeleton for
reverse-engineering` comment, or whose constructor placement-news a base type
into its own storage and then overwrites the vtable pointer that base
constructor just set.

**The pattern**: the binary's real class has a genuine C++ base (confirmed via
RTTI Class Hierarchy Descriptor / a virtual slot dispatching to the base's
method / the base's fields living at the expected offset). The recovery
instead modeled it as a **standalone class with zero real C++ bases**, faking
just enough of the base's shape for direct field access and reflection-driven
dispatch: placement-new a throwaway instance of the base type into the
derived object's own storage, then **overwrite the vtable pointer that
constructor just wrote** with the address of a bare `static std::uint8_t`
"tag" byte. This is enough to fool code that only reads specific known
offsets, but not real C++ RTTI (`typeid`).

**The crash it causes**: any code path that resolves the object via
`SCR_FromLua_X` → `gpg::REF_UpcastPtr` → `BuildTypedRefWithCache<CScriptObject>`
→ `typeid(*scriptObject)` reads through the fake one-byte "vtable" and faults
(`_RTtypeid+0x72` "read from 0xC", or a downstream `msvc8::string::tidy`/free
crash once corrupted state propagates). **Stays completely latent** until
something exercises that specific path — in several of the instances below,
the bug had shipped for a long time before an UNRELATED fix (publishing a
`moho.*` Lua class binder) made the crashing path reachable for the first
time, making it look like a regression from that unrelated fix rather than a
pre-existing dormant bug.

**Fix shape**: give the class real forwarding constructors (`Derived(...) :
Base(...) {}`) and placement-new the DERIVED type directly instead of the
base — the compiler then sets up every vtable slot (primary + any secondary
sub-object, e.g. `CScriptObject`) correctly on its own, no manual tag needed.
No layout change: a derived class that adds no new data members is exactly
the base's size, so the same storage bytes get touched either way. Watch for
one wrinkle: if the derived class's full declaration sits AFTER the helper
function in the file (only forward-declared where the helper lives), the
helper must be relocated after the class body — placement-new needs the
complete type. Derived-class-specific fields already living behind an
offset-struct/RuntimeView pattern can stay there unconverted if their offsets
were already confirmed correct — migrating them to named members is separate
cleanup, not part of the fix.

## Confirmed instances (2026-09-01)

1. **`CameraImpl`/`RCamCamera`↔`CScriptEvent`** — commit `34dfd4af`.
2. **`CAimManipulator`** (should be `: public IAniManipulator`) — commit
   `dc42a803`. Crashed on the FIRST unit construction once `SetPrecedence`
   became reachable via `6eb57cac` (an unrelated fix earlier the same
   session) — every prior build had this bug latent and unexercised.
3. **`CAiAttackerImpl`** — commit `c68161f4` ("Stop destroying
   CAiAttackerImpl's unconstructed CScriptObject subobject"), landed by
   `faf-main-2c`.
4. **`CThrustManipulator`** (`moho/animation/CThrustManipulator.cpp`) —
   commit `c23ad589`, `faf-main-f7`. `InitializeCThrustManipulatorDefaultRuntime`/
   `ConstructCThrustManipulatorRuntime` both placement-new'd a bare
   `IAniManipulator` then smashed both vtable slots with static tags; the
   backing `CThrustManipulatorSerializerRuntimeView` already properly
   derived from `IAniManipulator`, so the fix was purely: give
   `CThrustManipulator` real forwarding constructors and placement-new
   *that* instead of the base. Reachable via `cfunc_CreateThrustControllerL`
   (Lua `CreateThrustController`) and the generic reflection
   new/ctor-ref typeinfo callbacks.
5. **`CStorageManipulator`** (`moho/animation/CStorageManipulator.cpp`) —
   commit `c23ad589`, `faf-main-f7`. Same shape, but the backing
   `CStorageManipulatorRuntimeView` had **no base clause at all** (raw
   `void* mPrimaryVTable`/`mScriptObjectVTable` fields), closer to the
   pre-fix `CAimManipulator` shape. `InitializeCStorageManipulatorDefaultRuntime`
   had to be relocated to after `CStorageManipulator`'s class body in the
   file (it was originally defined before the class, which only had a
   forward declaration in scope there — needed the complete type for
   placement-new). Reachable via `cfunc_CreateStorageManipL` (Lua
   `CreateStorageManip`).

4 of 5 are in or adjacent to `moho/ai/`+`moho/animation/` — all under the
`IAniManipulator` family or its immediate neighbors.

6. **`CMauiControl`** (`moho/ui/UiRuntimeTypes.h`/`.cpp`) — a variant shape:
   NO base clause at all (not even a fake tag byte), `mControlStateStorage`
   raw bytes standing in for the first 0x34 bytes of what should have been
   a real `CScriptObject` base sub-object. Ground truth
   (`FUN_007867B0.c:10`, the ctor) opens with
   `Moho::CScriptObject::CScriptObject((Moho::CScriptObject *)this);` — a
   genuine base-constructor call the recovery had replaced with manual
   `reinterpret_cast<CScriptObject*>(this)` + placement-new of just the two
   `LuaObject` fields, skipping `WeakObject::weakLinkHead_ = 0u` and the
   instance-counter bump entirely. Every `RunScript*` call in the class
   (i.e. nearly every script callback: OnFrame, OnInit, OnDestroy, OnHide,
   OnKeyboardFocusChange, ...) goes through
   `WeakObject::ScopedWeakLinkGuard`, which walks `weakLinkHead_` as a live
   intrusive pointer chain — uninitialized garbage there is a plausible
   wild-write source, not just an RTTI nicety. The destructor already had a
   comment admitting the shape ("this class does not derive from
   CScriptObject - it overlays one") and worked around it with an explicit
   qualified `reinterpret_cast<CScriptObject*>(this)->CScriptObject::~CScriptObject()`
   instead of fixing the base — a second, independent tell for this bug
   class: **a hand-written comment justifying a non-virtual-dispatch
   qualified call to a base member is itself a symptom**, worth grepping for.
   Fixed real: `class CMauiControl : public CScriptObject`, ctor changed to
   `: CScriptObject()` member-init (removing the two manual placement-news,
   which the base ctor now does implicitly), dtor's explicit qualified call
   deleted (compiler auto-chains it), `mControlStateStorage` shrunk from
   `[0x118]` to `[0xE8]` to stop double-counting CScriptObject's own bytes
   (same total object size, `sizeof(CMauiControl) == 0x11C` unchanged — the
   RuntimeView overlay structs needed ZERO changes since they reinterpret
   raw bytes regardless of the C++ base-class shape). Full writeup:
   [[project_cmaui_control_hierarchy_missing_cscriptobject_base]].

## Sweep status: COMPLETE for the IAniManipulator family, 2 areas flagged unverified

A background-agent sweep (2026-09-01, `faf-main-f7`) covered: the original
candidate list (`AirPlatformExtractor.h`, `AITarget_LuaFuncDef.h`,
`INetNATTraversalHandler.cpp`, `CClientManagerImpl.h`,
`gpg/core/algorithms/Cluster.h`, `gpg/core/containers/WriteArchive.h`/
`ReadArchive.h`) — all CLEAN (genuine abstract interfaces, real inheritance,
or not classes at all) — plus every other `IAniManipulator`-derived class
(`CCollisionManipulator`, `CFootPlantManipulator`, `CBoneEntityManipulator`,
`CSlideManipulator`, `CSlaveManipulator`, `CAnimationManipulator`,
`CRotateManipulator`, `CBuilderArmManipulator`) — all clean, genuine
`: IAniManipulator(...)` member-init construction, no placement-new/tag
trick. **The `IAniManipulator` family sweep is done** — `CThrustManipulator`/
`CStorageManipulator` (found by that sweep, fixed same day) were the only
two live instances left in it.

Already independently confirmed CLEAN before the agent ran (real
inheritance, not this pattern): `Unit` (`: public IUnit, public Entity`),
`IUnit` (`: public WeakObject`), `UserUnit` (fully modeled with real named
`static_assert(offsetof(...))` fields, not thin at all). The `gpg/gal/*.hpp`
files carrying the same boilerplate comment are legitimately abstract
interface-only base classes with no data members — not instances of this
bug, don't flag them.

**Confirmed dead, same mechanism, zero callers — do not "fix" these,
they'd need a caller found first, not a construction rewrite**:
`ISTIDriver.cpp:20` (`ResetISTIDriverBaseVtableLane`), `EntityMotor.cpp:20`
(`ResetEntityMotorBaseVtableLane`), `ICommandSink.cpp:21/39`
(`ResetICommandSinkBaseVtableLaneA/B`, only call each other) — all
`[[maybe_unused]]`, real `= default` constructors sit right next to them
already clean. `WxRuntimeTypes.cpp` has a large `wxConstruct*RuntimeBase`
cluster (~15+ sampled, e.g. lines 2007-2162) using the identical tag trick
with zero callers found for every sampled function — this matches the
already-tracked orphan wx factory cluster
([[project_wxruntimetypes_orphan_factory_cluster]]), not a new finding;
don't re-flag it as this bug class without also finding a real caller first.

**CLOSED 2026-09-01 (second background sweep, `faf-main-f7`)**:
`RangeExtractor.cpp` (all 9: `RangeExtractor`, `WeaponExtractor`,
`CountermeasureExtractor`, `MiscellaneousExtractor`, `IntelExtractor`,
`RadarExtractor`, `SonarExtractor`, `OmniExtractor`, `CounterIntelExtractor`,
plus 10 sibling zero-caller forwarders), `CombinedMilitaryExtractor.cpp`,
`SimpleRenderWorldView.cpp`, and `IRenderWorldView.cpp` — all 12 confirmed
**DEAD**, none fixed (fixing dead code would just be wiring up something
nothing calls). Every one: anonymous-namespace internal linkage, zero
callers in recovered source AND zero callers/xrefs in the original binary's
own callgraph (`callers_count=0`, `reach=None` for every raw address), and
— the actual reason they're harmless — every real derived class
(`WeaponExtractor.h` etc., `SimpleRenderWorldView.h`) has **no explicit
constructor at all**, so the compiler's implicit default ctor already
chains correctly to the real base ctor with no fake-tag involved; real
construction sites (`std::make_unique<T>()` in `RangeExtractor.cpp`'s
`PopulateBlueprintExtractors`; a plain stack object at
`WxRuntimeTypes.cpp:70389` for `SimpleRenderWorldView`) are already clean.
`IRenderWorldView.cpp`'s two candidates turned out to be sha256-identical
ICF twins of the already-correctly-recovered canonical
`IRenderWorldView::IRenderWorldView()` ctor (0x007F6280) — same body,
different address, not a second bug. **`SimpleRenderWorldView` being dead is
a useful negative result for the render/world-view thread specifically** —
it rules this bug class out as a contributor there.

**The sweep for this bug class is now complete** — no further candidates
are outstanding. The WildMagic (`SimRecoveryRuntime.cpp`)/boost
(`BoostWrappers.cpp`) instances noted in an earlier draft of this file were
dropped from the "flagged unverified" list without being separately swept;
if picking this thread up again, treat those as still fully unverified
(liveness never checked, and per CLAUDE.md's WildMagic-is-terminal stance
"give it real inheritance" may not even be the right fix there) rather than
assuming the closure above covers them.
