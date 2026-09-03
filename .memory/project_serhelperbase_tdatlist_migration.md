---
name: project_serhelperbase_tdatlist_migration
description: "IN PROGRESS 2026-08-25, wide multi-agent sweep underway. Root fix landed (gpg::SerHelperBase real vtable + TDatListItem, commit c4c7a788), SerSaveLoadHelperListRuntime.h DELETED (b71cc71f). Confirmed full remaining scope via `grep -rl mHelperNext|mHelperPrev src/sdk`: ~230 files, matching the earlier 236 estimate almost exactly. Landed this session beyond the original ~30: CEconomy.cpp's 4-class cluster (commit ca10f085), a NEW canonical gpg::PrimitiveSerHelper<T,IntType=int> template covering 57 enum-wrapper instantiations (commit 3e7ea613, pilot EEconResourceTypeInfo done, 2 more 5-type agent batches in flight), most of moho/ai/*Serializer.h/*Construct.h (batch1 fully done, batch2 in flight covering 13 files), ArchiveSerialization.cpp's HPathCell/PathQueue/PathQueueImpl (agent in flight, gNavPathSerializerHelper deliberately deferred on a real NavPath-vs-SNavPath type-identity blocker, gRRuleGameRulesOwnerFieldSaveConstructHelper being picked up same agent). User's direct mandate driving this: \"we should have 0 vtable pointers as void* in whole project.\" This is now a standing multi-session goal, not a side quest -- keep sweeping directory by directory with 2-4 parallel agents until the grep returns empty."
metadata:
  type: project
  originSessionId: 2f95d9ee-a280-45c4-a276-72d0801966df
  modified: 2026-08-25T18:40:00.000Z
---

## RESOLVED — the user's original complaint is fully addressed

`gpg::SerSaveLoadHelperListRuntime.h` is DELETED (commit `b71cc71f`). `grep -rn
"SerSaveLoadHelperListRuntime\|UnlinkSerSaveLoadHelperNode" src/sdk` now returns
only two explanatory comments (`Shield.cpp`, `EScrollTypeTypeInfo.cpp`
documenting why those two files deliberately did NOT force the pattern without
proof) and `ArchiveSerialization.cpp`'s own unrelated, locally-scoped function
of the same name operating on a locally-declared type (`SerSaveLoadHelperNodeRuntime`,
not the deleted shared struct) — that local copy backs 4-5 still-dead/orphaned
helpers there, tracked separately below, not blocking.

**A second, worse bug surfaced repeatedly while fixing the first one**: at
least 9 classes (`CAiBrainConstruct`, `CAiSiloBuildImplConstruct`,
`IAiAttackerSerializer`, `SReconKeySerializer`, `CAiReconDBImplSerializer`,
`IAiTransportSerializer`, `CAiBuilderImplConstruct`, `CAiNavigatorAirConstruct`,
`CAiNavigatorLandConstruct`, `CAiPersonalityConstruct`, `CAiTransportImplConstruct`,
`IAiCommandDispatchImplConstruct` — the last 6 via one agent's sweep) had a
recovered `register_X()` body that eagerly called
`RegisterConstructFunction()`/`RegisterSerializeFunctions()`/`Init()`
immediately — but the REAL disassembly for every single one of these `register_X()`
addresses shows only: base-ctor-call (`gpg::SerHelperBase::SerHelperBase()`) →
set callback field(s) → install the derived vtable → `atexit(cleanup)`. **No
eager dispatch call exists in any of them.** Real dispatch is always deferred,
once, via `gpg::SerHelperBase::InitNewHelpers()` walking the pending list. This
was independently reproduced by both direct work and a dispatched agent, on
totally different classes, every time — it's a systemic mis-recovery pattern
this project should watch for whenever touching a `register_X()`-named
function that manually replicates ctor-shaped field setup.

User's direct correction that triggered this: *"UnlinkSerSaveLoadHelperNode is a
dirty-shit helper that should be restructured to TDatList or any other existing
structure! Do not use SerSaveLoadHelperListRuntime, it's wrong"* — followed later
by *"SerSaveLoadHelperListRuntime still there and it's wrong... TDatList it looks
like it"* when the header still existed mid-fix.

## Root cause, proven from raw .asm (not inferred)

`FUN_009501D0` (`SerHelperBase::SerHelperBase`) writes
`mov dword ptr [edi], offset ??_7SerHelperBase@gpg@@6B@` at `this+0` — a REAL
vtable install, contradicting the old `sizeof(SerHelperBase)==0x8` assert (no
vtable modeled). `FUN_00950D50` (`InitNewHelpers`) recovers the owning object
from a link-node pointer via `node - 4`, matching a `moho::TDatListItem<T,U>`
embedded right after a vtable pointer. IDA's own inferred type for the pending
list root literally reads `gpg::DList<gpg::SerHelperBase,void>*` — the
original-source name for what this project already reconstructed as
`moho::TDatList<T,U>`. Field-order ambiguity (which physical slot is "next" vs
"prev") is provably unresolvable from asm alone for a symmetric doubly-linked
list — decoded the ctor's splice op two ways (`ListLinkAfter` with one field
order, `ListLinkBefore` with the other) and both produce byte-identical
machine code, so adopting `TDatListItem`'s own established field order
(`mPrev` first) was safe and is NOT a fidelity violation.

## What landed (commits c4c7a788, 97222a98)

- `SerHelperBase : public moho::TDatListItem<SerHelperBase, void>`, pure
  virtual `Init()` (vtable slot 0 — was wrongly named
  `RegisterConstructFunction`/`RegisterSerializeFunctions`/
  `RegisterSaveConstructArgsFunction` in every existing derived class; several
  IDA-demangled names prove the real name is `Init`, e.g.
  `gpg::SerConstructHelper_CIntelPosHandle::Init`,
  `gpg::SerSaveLoadHelper<Rect2<int>>::Init`). `sNewHelpers` retyped
  `moho::TDatList<SerHelperBase,void>*`. Ctor/`ResetLinks()`/`InitNewHelpers()`
  rewritten onto `push_back`/`pop_front`/`ListUnlinkSelf` — no more hand-rolled
  pointer surgery.
- All 7 pre-existing correctly-inheriting derived classes fixed to `Init()
  override`, `offsetof(mNext/mPrev)` asserts dropped (now inherited private
  detail): `CIntelPosHandleConstruct`, `CIntelCounterHandleConstruct`,
  `CAniDefaultSkelConstruct`, `CAniDefaultSkelSaveConstruct`,
  `CSimSoundManagerConstruct`, `CSimSoundManagerSaveConstruct`,
  `CAniResourceSkelConstruct`.
- Found+fixed a REAL pre-existing bug along the way: `Rect2iSerializer`/
  `Rect2fSerializer` (`Reflection.h`/`.cpp`) manually zeroed `mHelperNext`/
  `mHelperPrev` instead of running `SerHelperBase`'s real ctor, so neither was
  ever actually spliced into `sNewHelpers` — their `Init()` (Rect2<int>/
  Rect2<float> load/save callback binding) never ran. Converting to real
  inheritance fixes this automatically (base-class construction order).
- `ArchiveSerialization.cpp`'s `SPathNeighborSerializer` (the one properly-
  wired helper in that file) migrated off its `SerSaveLoadHelperNodeRuntime`
  POD + hand-built one-entry fake vtable array + standalone
  `QueueSerSaveLoadHelperNodeForInit` (which hand-rolled the exact splice
  logic `SerHelperBase`'s real ctor now does). All deleted.
- 4 parallel agents dispatched (session-internal ids `a23cb3ca25c809ef5`,
  `a420dde8fbd4a0c18`, `a747cf7c90de7921a`, `af934a58c753414b9`) covering the
  other ~29 files that `#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"`
  or have their own local duplicate (`RScaResource.cpp`, `CDecalTypes.cpp`,
  `RPropBlueprint.cpp`, `RScmResource.cpp`, `CEconomyEvent.cpp`,
  `SSTITarget.cpp`, `CTextureScroller.cpp`, `Shield.cpp`,
  `SSTIEntityConstantData.cpp`, `SSTIEntityVariableData.cpp`,
  `EScrollTypeTypeInfo.cpp`, `CAiFormationInstance.cpp`,
  `CFactoryBuildTask.cpp`, `CBuildTaskHelper.cpp`,
  `CUnitCarrierLandTypeInfo.cpp`, `CUnitWaitForFerryTask.cpp`,
  `CUnitUpgradeTask.cpp`, `CUnitAttackTargetTask.cpp`,
  `CUnitSacrificeTask.cpp`, `Unit.cpp`, `CUnitGetBuiltTask.cpp`,
  `CUnitCarrierRetrieve.cpp`, `CUnitPatrolTask.cpp`, `CUnitFerryTask.cpp`,
  `CUnitRepairTask.cpp`, `CUnitGuardTask.cpp`, `CUnitCarrierLaunch.cpp`,
  `CUnitMeleeAttackTargetTask.cpp`, `CUnitMoveTask.cpp`). Status of these
  agents not yet known as of this writing — check `/workflows` or task
  notifications before assuming done. **Do not delete
  `gpg/core/reflection/SerSaveLoadHelperListRuntime.h`'s bad content until
  all consumers, from all 4 agents + the 2 done directly, are confirmed
  migrated** — several files still `#include` it.

## NOT fixed, deliberately deferred — two much bigger discoveries

1. **A codebase-wide 236-file instance of the same disease.**
   `grep -rl "gpg::SerHelperBase\* m(Next|Prev|HelperNext|HelperPrev)"
   src/sdk` returns 236 files — vastly larger than the ~30 files that
   literally use `SerSaveLoadHelperListRuntime`/`UnlinkSerSaveLoadHelperNode`
   by name. Most are `*Serializer.h`/`*Construct.h`/`*SaveConstruct.h` pairs
   across `moho/ai`, `moho/resource/blueprints`, `moho/sim`, `moho/effects`,
   etc. — e.g. an entire `lua/LuaStateConstruct.h` cluster (8 distinct
   Lua-runtime construct helpers: `LuaStateConstruct`, `lua_StateConstruct`,
   `TStringConstruct`, `TableConstruct`, `LClosureConstruct`,
   `UpValConstruct`, `ProtoConstruct`, `UdataConstruct`) using raw
   `void* vftable_; gpg::SerHelperBase* mNext; gpg::SerHelperBase* mPrev;`
   fields instead of real inheritance, same as `LuaObjectSerializer.h`/
   `LuaObject.cpp`. This is NOT attempted this pass — it needs a dedicated,
   probably multi-session sweep, same precedent as the already-documented
   `LegacyContainerFillLanes.cpp` debt. The root fix (this file's work) is
   the prerequisite that makes that future sweep mechanical rather than
   exploratory: every one of those 236 files can now just inherit the real,
   fixed `SerHelperBase` and override `Init()`.

2. **`ArchiveSerialization.cpp`'s own 127-function `SerSaveLoadHelperInitView`
   mega-cluster** (distinct from the smaller `SerSaveLoadHelperNodeRuntime`
   cluster fixed this pass — different local struct, doesn't call
   `UnlinkSerSaveLoadHelperNode` at all, so technically out of scope for the
   user's literal complaint but the SAME underlying disease). A single shared
   `InstallSerSaveLoadHelperCallbacksByTypeName(SerSaveLoadHelperInitView*,
   const char* reflectedTypeName)` backs 127 near-identical
   `InstallMoho<Type>SerializerCallbacks`/`InstallWm3<Type>SerializerCallbacks`
   thin wrappers (one per reflected leaf type — `Wm3::AxisAlignedBox3f`,
   `Moho::VTransform`, `Moho::SCoordsVec2`, `Moho::HPathCell`, `Moho::NavPath`,
   `Moho::PathQueue`, `Moho::CEconomy`, `Moho::EScrollType`, `Moho::SDecalInfo`,
   dozens more). This is almost certainly the REAL `Init()` mechanism for at
   least 3 of the "dead" helpers below (`InstallMohoHPathCellSerializerCallbacks`
   @0x007632D0, `InstallMohoNavPathSerializerCallbacks`@0x00763370,
   `InstallMohoPathQueueSerializerCallbacks`@0x00767080 all resolve their
   RType by name string already) — meaning the OTHER `SerSaveLoadHelperNodeRuntime`-
   typed globals for the same types are likely a **parallel, conflicting,
   dead-code duplicate recovery** of the same binary registration, not two
   independent things. Needs careful disambiguation before touching — did NOT
   rush this.

3. **5 confirmed-dead/orphaned helper globals in `ArchiveSerialization.cpp`**
   left on the old `SerSaveLoadHelperNodeRuntime` local struct (deliberately,
   not touched): `gHPathCellSerializerHelper`, `gNavPathSerializerHelper`,
   `gPathQueueSerializerHelper`, `gPathQueueImplSerializerHelper`,
   `gRRuleGameRulesOwnerFieldSaveConstructHelper`. None of these are ever
   queued into `sNewHelpers` anywhere in the current recovered source (no
   `QueueSerSaveLoadHelperNodeForInit`-equivalent call for any of them) — their
   `[[maybe_unused]]` `UnlinkXxxNodeVariantA/B` wrappers are the only surviving
   trace, real addresses, never called. `gRRuleGameRulesOwnerFieldSaveConstructHelper`
   additionally has a type mismatch smell: named like the single-callback
   `SaveConstructHelper` family (`mSerSaveConstructArgsFunc` only, matching
   `CAniDefaultSkelSaveConstruct`'s shape) but modeled with the two-callback
   `SerSaveLoadHelperNodeRuntime` shape instead — needs its own investigation,
   not a blind conversion.

## Design notes for whoever does the wider 236-file sweep next

Reference pattern (already-correct, use as template):
`src/sdk/moho/entity/intel/CIntelPosHandleConstruct.h`/`.cpp` (construct/delete
callback style, dedicated ctor + atexit cleanup) and `Rect2iSerializer`/
`Rect2fSerializer` in `Reflection.h` (~line 4487, load/save callback style, no
dedicated ctor). Both now `: public gpg::SerHelperBase`, `void Init() override`.
Kill the raw view-struct/`AsXxxRuntime(...)` reinterpret_cast helper, the
`#include ".../SerSaveLoadHelperListRuntime.h"`, and any manual
`helper.mNext=nullptr` init — `SerHelperBase`'s real ctor does the splice
automatically as part of base-class construction now.
