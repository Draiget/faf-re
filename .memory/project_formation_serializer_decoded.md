---
name: project-formation-serializer-decoded
description: CFormationInstance's MemberSerialize/MemberDeserialize are both absent (499 instrs, closure 1) and fully decoded here - but the whole chain is orphaned until the serializer install site is found.
metadata:
  type: project
---

`CFormationInstance::MemberSerialize` (FUN_005744E0, 254 instrs) and
`MemberDeserialize` (FUN_005741D0, 245 instrs) are **both absent from source**,
so a formation instance cannot be saved or loaded at all. Both have
**closure = 1** - every callee is already recovered - which makes this the
cleanest large target found in this run.

## ⛔ ROOT BLOCKER (traced 2026-08-17): the CFormationInstance class split

The serializer is a method on **`CFormationInstance`**, which does not exist as
a type in `src/sdk` - it is only forward-declared (`Unit.h:54`). Our
`CAiFormationInstance` derives straight from `IFormationInstance`
(`CAiFormationInstance.h:335`) while holding the fields that belong to the
missing middle class: every offset the serializer touches (0x18 mCommandType
through 0x320 mMaxUnitSlotCount) is on `CAiFormationInstance` in source.

The binary disagrees: `CAiFormationInstanceTypeInfo::Init` calls
`AddCFormationInstanceBaseToCAiFormationInstanceType`, i.e. `CAiFormationInstance`
derives *from* `CFormationInstance`, and the fields live on the base.

**So the serializer cluster cannot land until that split happens** - otherwise
the methods attach to the wrong class and the base registration keeps pointing
at a type with no members. This is the same split already tracked in
[[project-cformationinstance-split-blocked]]; that note should now record that
the save/load subsystem depends on it, not just the Lua side.

Do the split first, as its own commit, then the six reflection globals, then the
seven-piece cluster. Everything below is already decoded and waiting.

## The install site, and the real scope

`data_refs` misses it but **`incoming_xrefs` has it** - always check both:

    SELECT kind, from_ea, owner_token, owner_name, line
      FROM incoming_xrefs WHERE target_token = 'FUN_0056A870';
    -> mov Moho__CFormationInstanceSerializer.mSerialize, offset ...Serialize
       owner: FUN_00BCAC40 register_CFormationInstanceSerializer

`register_CFormationInstanceSerializer` (FUN_00BCAC40) is itself absent from
source. Its whole body:

    gpg::SerHelperBase::SerHelperBase(&CFormationInstanceSerializer);
    CFormationInstanceSerializer.mDeserialize = &...::Deserialize;
    CFormationInstanceSerializer.mSerialize   = &...::Serialize;
    CFormationInstanceSerializer.__vftable    = &...::`vftable';
    atexit(&...::~CFormationInstanceSerializer);

**So this is not a gap, it is an entire missing subsystem: formation instances
have no save/load path at all in the recovered engine.** Seven pieces, ~520
instrs:

1. `CFormationInstanceSerializer` struct - `SerHelperBase` shape, verified
   against the recovered `TableSerializer` (`lua/LuaObject.cpp:148-158`):
   vptr +0x00, `mHelperNext` +0x04, `mHelperPrev` +0x08, `mDeserialize` +0x0C,
   `mSerialize` +0x10, size 0x14.
2. `::Serialize` (FUN_0056A870, 8 instrs) - forwards to `MemberSerialize`
3. `::Deserialize` - forwards to `MemberDeserialize`
4. `CFormationInstance::MemberSerialize` (FUN_005744E0, 254)
5. `CFormationInstance::MemberDeserialize` (FUN_005741D0, 245)
6. `register_CFormationInstanceSerializer` (FUN_00BCAC40)
7. the helper dtor registered via `atexit`

Land it as one atomic cluster - no piece has a caller outside the group.

### Reflected types the lanes need

`Moho::IFormationInstance::sType` (exists, `IFormationInstance.h:27`),
`Moho::EUnitCommandType::sType`, `Moho::SCoordsVec2::sType` (exists,
`SCoordsVec2.h:11`), `gpg::fastvector_WeakPtr_IUnit::sType`,
`gpg::fastvector_SOffsetInfo::sType`, `gpg::fastvector_SAssignedLocInfo::sType`,
`std::map_EntId_SCoordsVec2::sType`, `Wm3::Vector3f::sType`,
`Wm3::Quaternionf::sType`.

**Checked (2026-08-17): six of these do not exist in `src/sdk` in any form** -
not under these spellings, not as `Cached*Type()` accessors:

    gpg::fastvector_WeakPtr_IUnit::sType
    gpg::fastvector_SOffsetInfo::sType
    gpg::fastvector_SAssignedLocInfo::sType
    std::map_EntId_SCoordsVec2::sType
    Wm3::Quaternionf::sType
    Moho::EUnitCommandType::sType

Note these are **container/enum** RTypes; the *element* accessors already exist
in `CAiFormationInstance.cpp` (`CachedWeakPtrIUnitType`, `CachedSCoordsVec2Type`,
`CachedVector3fType`, `CachedMapEntIdSUnitOffsetInfoType`) and are the idiom to
copy - each caches into a class static, e.g.
`CachedMapEntIdSUnitOffsetInfoType` stores into `moho::SOffsetInfo::sType`.

So the real prerequisite is **modelling six reflected-type globals**. Their
binary addresses (read from `FUN_005744E0.asm`, all one `.data` cluster):

    0x010C6EDC  Moho::EUnitCommandType::sType
    0x010C6F74  Moho::IFormationInstance::sType        (already modelled)
    0x010C6F90  std::map_EntId_SCoordsVec2::sType
    0x010C6F94  gpg::fastvector_WeakPtr_IUnit::sType
    0x010C6F98  gpg::fastvector_SOffsetInfo::sType
    (+ gpg::fastvector_SAssignedLocInfo::sType, Wm3::Quaternionf::sType - same
     block, grab the exact addresses the same way)

**The open design question is where they live in source**, and it is a real one,
not a lookup. `IFormationInstance::sType` is an `inline static` on the class,
which works for classes; `EUnitCommandType` is an enum and cannot hold one, and
`gpg::fastvector<T>` / `std::map<K,V>` specializations have no natural home
class in this tree. Options are a namespace-scope global per binary global
(most faithful), or a traits struct. **Pick one deliberately and apply it to all
six** - do not scatter file-local statics, which is the
[[project-descriptor-cache-defect-class]] defect at file scope.

### Related pre-existing mis-homing worth fixing in the same pass

`CachedMapEntIdSUnitOffsetInfoType` (`CAiFormationInstance.cpp:677`) caches the
**map** descriptor into `moho::SOffsetInfo::sType`, while the element accessor
`CachedSUnitOffsetInfoType` uses `moho::SUnitOffsetInfo::sType`. Those are two
different classes, and the binary keeps `gpg::fastvector_SOffsetInfo::sType`
separate from any element static. Nothing else reads `SOffsetInfo::sType` today,
so it is latent rather than live - but it is the same mis-homing this cluster
must avoid.

## The deserializer is exactly symmetric (verified)

18 lanes, same order. The two pointer lanes use typed readers rather than a raw
form: `ReadPointer_LuaState(&mLuaState, ...)` and
`ReadPointer_RRuleGameRules2(&mGameRules, ...)` mirror the two
`WriteRawPointer(RRef_*(...), UNOWNED)` calls. Tail is
`ReadString(&mScriptName)`, `Read(SCoordsVec2, &mFormationCenter)`,
`ReadFloat(&mFormationUpdateScale)`, `ReadBool(&mPlanUpdateRequested)`,
`ReadInt(&mMaxUnitSlotCount)`.

`CAiFormationInstanceTypeInfo::Init` (0x0059BDE0) is **not** it: source matches
the emission exactly (size, four allocation callbacks, `RType::Init`, base
registration, `Finish`) and installs no serializers.

## The serializer, fully mapped (offsets read from FUN_005744E0.asm)

Write order, with IDA's field names resolved against `CAiFormationInstance`
(`CAiFormationInstance.h:612-635`):

| # | Offset | Source field | Operation |
|---|---|---|---|
| 1 | - | (whole object) | `Write(IFormationInstance::sType, this)` |
| 2 | +0x010 | `mLuaState` | `WriteRawPointer(RRef_LuaState(...), UNOWNED)` |
| 3 | +0x014 | `mGameRules` | `WriteRawPointer(RRef_RRuleGameRules(...), UNOWNED)` |
| 4 | +0x018 | `mCommandType` | `Write(EUnitCommandType::sType, ...)` |
| 5 | +0x020 | `mUnits` | `Write(fastvector_WeakPtr_IUnit::sType, ...)` |
| 6 | +0x050 | `mLanes[0]` | `Write(fastvector_SOffsetInfo::sType, ...)` |
| 7 | +0x0F8 | `mLanes[1]` | same type (0x50 + 0xA8) |
| 8 | +0x1A0 | `mOccupiedSlots` | `Write(fastvector_SAssignedLocInfo::sType, ...)` |
| 9 | +0x2B0 | `mCoordCachePrimary` | `Write(<map type>, ...)` |
| 10 | +0x2BC | `mCoordCacheSecondary` | `Write(<map type>, ...)` |
| 11 | +0x2C8 | `mForwardVector` | `Write(<Vec3f type>, ...)` |
| 12 | +0x2D4 | `mOrientation` | `Write(<Quatf type>, ...)` |
| 13 | +0x2E4 | `mOrientationBaseline` | `Write(<Quatf type>, ...)` |
| 14 | +0x2F4 | `mScriptName` | `WriteString(...)` |
| 15 | +0x310 | `mFormationCenter` | `Write(SCoordsVec2::sType, ...)` |
| 16 | +0x318 | `mFormationUpdateScale` | `WriteFloat` |
| 17 | +0x31C | `mPlanUpdateRequested` | `WriteBool` |
| 18 | +0x320 | `mMaxUnitSlotCount` | `WriteInt` |

`mFormationUnitSpacingMultiplier` (+0x324) and `mSim` (+0x328) are deliberately
**not** serialized - runtime-only lanes.

Every `Write` is preceded by the cache-and-store idiom
(`if (!X::sType) X::sType = LookupRType(...)`) - see
[[project-descriptor-cache-defect-class]]; reproduce the store, do not use a
function-local cache.

`MemberDeserialize` mirrors this list; read FUN_005741D0 to confirm before
writing, but expect the same 18 lanes in the same order.

Model the body on the already-recovered
`RBroadcasterRType_ECommandEvent::SerSave` (`Broadcaster.cpp:537`) for the
archive idiom, and on `SUnitOffsetInfo::MemberSerialize`
(`CAiFormationInstance.cpp:3677`) for the per-field style.
