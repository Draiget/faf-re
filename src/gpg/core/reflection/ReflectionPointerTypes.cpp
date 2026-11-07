#include "gpg/core/reflection/ReflectionPrivate.h"

namespace
{

  template <class TPointee>
  void AssignPointerSlotWithTypeCache(void* const obj, const gpg::RRef& from, gpg::RType*& typeCache)
  {
    auto* const slot = static_cast<TPointee**>(obj);
    if (!slot) {
      gpg::HandleAssertFailure("void_pptr", 663, kReflectionHeaderPath);
    }

    gpg::RType* pointeeType = typeCache;
    if (!pointeeType) {
      pointeeType = gpg::LookupRType(typeid(TPointee));
      typeCache = pointeeType;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(from, pointeeType);
    if (from.mObj && !upcast.mObj) {
      throw gpg::BadRefCast("type error");
    }

    *slot = static_cast<TPointee*>(upcast.mObj);
  }
  gpg::RType* gShieldRRefType = nullptr;

// The `T*` descriptor always comes from `T::GetPointerType()`: every
// `RRef_T_P` and `RRef::TryUpcast_T_P` body in the binary calls it (e.g.
// 0x0066C800 and 0x0066D110 both call 0x0066C980 for IEffect), and for most
// `T` that call is also what constructs and pre-registers the descriptor.

template <class T>
RRef MakePointerSlotRef(T** const slot)
{
    RRef out{};
    out.mObj = slot;
    out.mType = T::GetPointerType();
    return out;
}

template <class T>
T* const* TryUpcastPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, T::GetPointerType());
    if (!upcast.mObj) {
        throw gpg::BadRefCast("type error");
    }

    return static_cast<T* const*>(upcast.mObj);
}

/**
 * What it does:
 * Upcasts `source` to a `T*` slot, or throws `BadRefCast` naming both types.
 * As 0x0066D110 does, the failure path asks `T::GetPointerType()` again for
 * the target name rather than reusing the first result.
 */
template <class T>
T** TryUpcastPointerSlotWithTypeNameOrThrow(const RRef& source)
{
  const RRef upcast = gpg::REF_UpcastPtr(source, T::GetPointerType());
  auto* const slot = static_cast<T**>(upcast.mObj);
  if (!slot) {
    RType* const targetType = T::GetPointerType();
    const char* const sourceName = source.mType ? source.mType->GetName() : "null";
    throw gpg::BadRefCast(nullptr, sourceName, targetType->GetName());
  }

  return slot;
}

// FUN_00750100 is the AssignPointer vtable slot of RPointerType<moho::SimArmy>,
// recovered as a method of that specialization (one-address-one-function).

// FUN_00750510 is the AssignPointer vtable slot of RPointerType<moho::Shield>,
// recovered as a method of that specialization (one-address-one-function).

// FUN_0077EE30 is the AssignPointer vtable slot of
// RPointerType<moho::CDecalHandle>, recovered as a method of that
// specialization (one-address-one-function). The earlier free-helper
// transcription (AssignCDecalHandlePointerSlotFromRef) was the same address
// and has been re-homed into the specialization.

template <class T>
RRef MakePointeeRef(T* const object, RType* const baseType)
{
    RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;

    if (!object || !baseType) {
        return out;
    }

    RType* dynamicType = baseType;
    try {
        dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
        dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
        out.mObj = object;
        out.mType = dynamicType;
        return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
}

template <class T>
fa::string BuildPointerLexical(void* const slotObject, RType* const pointeeType)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (!slot || !*slot) {
        return fa::string("NULL");
    }

    const RRef pointeeRef = MakePointeeRef<T>(*slot, pointeeType);
    if (!pointeeRef.mObj) {
        return fa::string("NULL");
    }

    const fa::string inner = pointeeRef.GetLexical();
    return STR_Printf("[%s]", inner.c_str());
}

/**
 * Address: 0x0059D990 (FUN_0059D990, gpg::RPointerType_IFormationInstance::NewRef)
 * Address: 0x005DE700 (FUN_005DE700, gpg::RPointerType_CAcquireTargetTask::NewRef)
 * Address: 0x0063E010 (FUN_0063E010, gpg::RPointerType_IAniManipulator::NewRef)
 * Address: 0x0067EBB0 (FUN_0067EBB0, gpg::RPointerType_Entity::NewRef)
 * Address: 0x006E3B80 (FUN_006E3B80, gpg::RPointerType_CUnitCommand::NewRef)
 * Address: 0x00712190 (FUN_00712190, gpg::RPointerType_CArmyStatItem::NewRef)
 *
 * What it does:
 * Allocates one `T*` pointer-slot lane and wraps it as a reflected `RRef`.
 *
 * Every cited emission is the same 14-instruction body — `operator new(4)`,
 * then the pointee's `RRef_<T>_P` slot factory — differing only in which
 * factory is called. Confirm a new T's body matches before extending the list;
 * types whose `NewRef` diverges (UnitWeapon, IEffect, ReconBlip, CEconomyEvent)
 * are recovered as their own named helpers.
 */
template <class T>
RRef NewPointerSlotRef()
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    return MakePointerSlotRef<T>(slot);
}

/**
 * Address: 0x0059D9C0 (FUN_0059D9C0, gpg::RPointerType_IFormationInstance::CpyRef)
 * Address: 0x005DE730 (FUN_005DE730, gpg::RPointerType_CAcquireTargetTask::CpyRef)
 * Address: 0x0063E040 (FUN_0063E040, gpg::RPointerType_IAniManipulator::CpyRef)
 * Address: 0x0067EBE0 (FUN_0067EBE0, gpg::RPointerType_Entity::CpyRef)
 * Address: 0x006E3BB0 (FUN_006E3BB0, gpg::RPointerType_CUnitCommand::CpyRef)
 * Address: 0x007121C0 (FUN_007121C0, gpg::RPointerType_CArmyStatItem::CpyRef)
 *
 * What it does:
 * Allocates one `T*` pointer-slot lane, copies the upcast source slot value
 * into it, and wraps the lane as a reflected `RRef`. The allocation is guarded
 * by an EH funclet that frees the lane and rethrows when the upcast throws.
 *
 * Every cited emission is the same 48-instruction body (`__CxxFrameHandler3`
 * frame, `operator new(4)`, `RRef::TryUpcast_<T>_P`, `RRef_<T>_P`, unwind
 * funclet calling `operator delete`), differing only in the two per-type
 * helpers. Confirm a new T's body matches before extending the list.
 */
template <class T>
RRef CopyPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    *slot = nullptr;
    if (sourceRef) {
        T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakePointerSlotRef<T>(slot);
}

/**
 * Address: 0x005C8C80 (FUN_005C8C80)
 *
 * What it does:
 * Allocates one `ReconBlip*` slot, copies the source lane pointer, and wraps
 * it as `gpg::RRef_ReconBlip_P`.
 */
RRef CopyReconBlipPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::ReconBlip**>(::operator new(sizeof(moho::ReconBlip*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastReconBlipPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::ReconBlip*>(slot);
    return out;
}

/**
 * Address: 0x005C8D10 (FUN_005C8D10)
 *
 * What it does:
 * Wraps one existing `ReconBlip*` slot lane as `gpg::RRef_ReconBlip_P`.
 */
RRef ConstructReconBlipPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::ReconBlip*>(static_cast<moho::ReconBlip**>(slotObject));
    return out;
}

/**
 * Address: 0x005C8D40 (FUN_005C8D40)
 *
 * What it does:
 * Moves one reflected `ReconBlip*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_ReconBlip_P` payload.
 */
RRef MoveReconBlipPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::ReconBlip**>(slotObject);
    moho::ReconBlip** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastReconBlipPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::ReconBlip*>(resolvedSlot);
    return out;
}

/**
 * Address: 0x0066CF40 (FUN_0066CF40)
 *
 * What it does:
 * Allocates one `IEffect*` slot, copies the source lane pointer, and wraps it
 * as `gpg::RRef_IEffect_P`.
 */
RRef CopyIEffectPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::IEffect**>(::operator new(sizeof(moho::IEffect*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastIEffectPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::IEffect*>(slot);
    return out;
}

/**
 * Address: 0x0066CFD0 (FUN_0066CFD0)
 *
 * What it does:
 * Wraps one existing `IEffect*` slot lane as `gpg::RRef_IEffect_P`.
 */
RRef ConstructIEffectPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::IEffect*>(static_cast<moho::IEffect**>(slotObject));
    return out;
}

/**
 * Address: 0x0066D000 (FUN_0066D000)
 *
 * What it does:
 * Moves one reflected `IEffect*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_IEffect_P` payload.
 */
RRef MoveIEffectPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::IEffect**>(slotObject);
    moho::IEffect** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastIEffectPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::IEffect*>(resolvedSlot);
    return out;
}

/**
 * Address: 0x006B2A10 (FUN_006B2A10)
 *
 * What it does:
 * Allocates one `CEconomyEvent*` slot, copies the source lane pointer, and
 * wraps it as `gpg::RRef_CEconomyEvent_P`.
 */
RRef CopyCEconomyEventPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CEconomyEvent**>(::operator new(sizeof(moho::CEconomyEvent*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastCEconomyEventPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CEconomyEvent*>(slot);
    return out;
}

/**
 * Address: 0x006B2AA0 (FUN_006B2AA0)
 *
 * What it does:
 * Wraps one existing `CEconomyEvent*` slot lane as
 * `gpg::RRef_CEconomyEvent_P`.
 */
RRef ConstructCEconomyEventPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::CEconomyEvent*>(static_cast<moho::CEconomyEvent**>(slotObject));
    return out;
}

/**
 * Address: 0x006B2AD0 (FUN_006B2AD0)
 *
 * What it does:
 * Moves one reflected `CEconomyEvent*` source slot into one destination slot
 * lane and wraps the destination as one `gpg::RRef_CEconomyEvent_P` payload.
 */
RRef MoveCEconomyEventPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CEconomyEvent**>(slotObject);
    moho::CEconomyEvent** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastCEconomyEventPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CEconomyEvent*>(resolvedSlot);
    return out;
}

/**
 * Address: 0x00750B60 (FUN_00750B60)
 *
 * What it does:
 * Allocates one `SimArmy*` slot, copies the source lane pointer, and wraps it
 * as `gpg::RRef_SimArmy_P`.
 */
[[maybe_unused]] RRef CopySimArmyPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::SimArmy**>(::operator new(sizeof(moho::SimArmy*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastSimArmyPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::SimArmy*>(slot);
    return out;
}

/**
 * Address: 0x00750BF0 (FUN_00750BF0)
 *
 * What it does:
 * Wraps one existing `SimArmy*` slot lane as `gpg::RRef_SimArmy_P`.
 */
[[maybe_unused]] RRef ConstructSimArmyPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::SimArmy*>(static_cast<moho::SimArmy**>(slotObject));
    return out;
}

/**
 * Address: 0x00750C20 (FUN_00750C20)
 *
 * What it does:
 * Moves one reflected `SimArmy*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_SimArmy_P` payload.
 */
[[maybe_unused]] RRef MoveSimArmyPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::SimArmy**>(slotObject);
    moho::SimArmy** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastSimArmyPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::SimArmy*>(resolvedSlot);
    return out;
}

/**
 * Address: 0x00750D60 (FUN_00750D60)
 *
 * What it does:
 * Wraps one `Shield*` slot pointer as a reflected `gpg::RRef_Shield_P`
 * payload.
 */
[[maybe_unused]] RRef CopyShieldPointerSlotRef(moho::Shield** const slot)
{
    RRef out{};
    out = gpg::MakeRRef<moho::Shield*>(slot);
    return out;
}

/**
 * Address: 0x00750D90 (FUN_00750D90)
 *
 * What it does:
 * Moves one reflected `Shield*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_Shield_P` payload.
 */
[[maybe_unused]] RRef MoveShieldPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::Shield**>(slotObject);
    moho::Shield** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastShieldPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::Shield*>(resolvedSlot);
    return out;
}

/**
 * Address: 0x0077F040 (FUN_0077F040)
 *
 * What it does:
 * Wraps one `CDecalHandle*` slot pointer as a reflected
 * `gpg::RRef_CDecalHandle_P` payload.
 */
[[maybe_unused]] RRef CopyCDecalHandlePointerSlotRef(moho::CDecalHandle** const slot)
{
    RRef out{};
    out = gpg::MakeRRef<moho::CDecalHandle*>(slot);
    return out;
}

/**
 * Address: 0x0077F070 (FUN_0077F070)
 *
 * What it does:
 * Moves one reflected `CDecalHandle*` source slot into one destination slot
 * lane and wraps the destination as one `gpg::RRef_CDecalHandle_P` payload.
 */
[[maybe_unused]] RRef MoveCDecalHandlePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CDecalHandle**>(slotObject);
    moho::CDecalHandle** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastCDecalHandlePointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CDecalHandle*>(resolvedSlot);
    return out;
}

// NOTE: 0x00672380/0x00672410/0x006723F0/0x00672480/0x00672490 (CEfxTrailEmitter
// TypeInfo NewRef/CtrRef/Delete/Destruct/AddBase_CEffectImpl) are recovered and
// wired at their real caller, `CEfxTrailEmitterTypeInfo::Init`
// (moho/effects/rendering/CEfxTrailEmitterTypeInfo.cpp) -- not here. This
// file's NewCEfxTrailEmitterRef/ConstructCEfxTrailEmitterRefInPlace/
// DeleteCEfxTrailEmitterStorage/DestructCEfxTrailEmitterStorage/
// AddCEffectImplBaseField were unwired [[maybe_unused]] duplicates; removed
// in favor of the single canonical, actually-called citations on the real
// class. 0x006722A0 (BindCEfxTrailEmitterLifecycleCallbacks) was also removed:
// it had zero code callers and zero data xrefs in the callgraph index
// (verified, NO_CALLSITE_EVIDENCE/UNREACHED) -- the real Init (0x00671F30)
// writes its four lifecycle-callback fields inline (confirmed via .asm),
// matching the already-evidenced shared gpg::BindRTypeLifecycleCallbacks
// helper's other ~40 citations, not a call to a separate function.

/**
 * Address: 0x0059DA50 (FUN_0059DA50, gpg::RPointerType_IFormationInstance::CtrRef)
 * Address: 0x005DE7C0 (FUN_005DE7C0, gpg::RPointerType_CAcquireTargetTask::CtrRef)
 * Address: 0x0063E0D0 (FUN_0063E0D0, gpg::RPointerType_IAniManipulator::CtrRef)
 * Address: 0x0067EC70 (FUN_0067EC70, gpg::RPointerType_Entity::CtrRef)
 * Address: 0x006E3C40 (FUN_006E3C40, gpg::RPointerType_CUnitCommand::CtrRef)
 * Address: 0x00712250 (FUN_00712250, gpg::RPointerType_CArmyStatItem::CtrRef)
 *
 * What it does:
 * Wraps existing `T*` pointer-slot storage as a reflected `RRef` without
 * allocating.
 *
 * Every cited emission is the same 13-instruction body — a straight forward to
 * the pointee's `RRef_<T>_P` slot factory — differing only in which factory is
 * called. Confirm a new T's body matches before extending the list.
 */
template <class T>
RRef ConstructPointerSlotRef(void* const slotObject)
{
    return MakePointerSlotRef<T>(static_cast<T**>(slotObject));
}

/**
 * Address: 0x0059DA80 (FUN_0059DA80, gpg::RPointerType_IFormationInstance::MovRef)
 * Address: 0x005DE7F0 (FUN_005DE7F0, gpg::RPointerType_CAcquireTargetTask::MovRef)
 * Address: 0x0063E100 (FUN_0063E100, gpg::RPointerType_IAniManipulator::MovRef)
 * Address: 0x0067ECA0 (FUN_0067ECA0, gpg::RPointerType_Entity::MovRef)
 * Address: 0x006E3C70 (FUN_006E3C70, gpg::RPointerType_CUnitCommand::MovRef)
 * Address: 0x00712280 (FUN_00712280, gpg::RPointerType_CArmyStatItem::MovRef)
 *
 * What it does:
 * Writes the upcast source slot pointer value into the destination `T*` slot
 * lane and wraps that lane as a reflected `RRef`.
 *
 * Every cited emission is the same 43-instruction body. It differs from
 * `CopyPointerSlotRef` in that the lane is caller-supplied rather than
 * allocated, so the unwind funclet is the compiler's empty
 * (`nullsub`) cleanup rather than an `operator delete` call. Confirm a new T's
 * body matches before extending the list.
 */
template <class T>
RRef MovePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakePointerSlotRef<T>(slot);
}

/**
 * Address: 0x00557440 (FUN_00557440, gpg::RPointerType_RBlueprint::Delete)
 * Address: 0x0059D960 (FUN_0059D960, gpg::RPointerType_IFormationInstance::Delete)
 * Address: 0x005A1A80 (FUN_005A1A80, gpg::RPointerType_RUnitBlueprint::Delete)
 * Address: 0x005DE530 (FUN_005DE530, gpg::RPointerType_UnitWeapon::Delete)
 * Address: 0x005DE560 (FUN_005DE560, gpg::RPointerType_CAcquireTargetTask::Delete)
 * Address: 0x0063DFE0 (FUN_0063DFE0, gpg::RPointerType_IAniManipulator::Delete)
 * Address: 0x0067EB80 (FUN_0067EB80, gpg::RPointerType_Entity::Delete)
 * Address: 0x006E3B50 (FUN_006E3B50, gpg::RPointerType_CUnitCommand::Delete)
 * Address: 0x00712150 (FUN_00712150, gpg::RPointerType_CArmyStatItem::Delete)
 *
 * What it does:
 * Releases one allocated pointer-slot lane. IDA marks the instantiation
 * body a plain thunk (`::operator delete(slotObject)`, no other type-
 * specific logic), so this template citation is added per verified T;
 * confirm a new T's `Delete` body matches exactly before extending the list.
 */
template <class T>
void DeletePointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

/**
 * Address: 0x0040D3B0 (FUN_0040D3B0, sub_40D3B0)
 *
 * What it does:
 * Wraps a `CTaskThread*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCTaskThreadPointerSlotRef(moho::CTaskThread** const slot)
{
    return MakePointerSlotRef<moho::CTaskThread>(slot);
}

/**
 * Address: 0x0040D580 (FUN_0040D580, sub_40D580)
 *
 * What it does:
 * Attempts to upcast one reflected reference lane to `CTaskThread*` slot and
 * returns null on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlot(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, moho::CTaskThread::GetPointerType());
    return static_cast<moho::CTaskThread**>(upcast.mObj);
}

/**
 * Address: 0x0040D3E0 (FUN_0040D3E0, gpg::RRef::TryUpcast_CTaskThread_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CTaskThread*` slot and throws
 * `BadRefCast` on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlotOrThrow(const RRef& source)
{
    moho::CTaskThread** const slot = TryUpcastCTaskThreadPointerSlot(source);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x0040CDB0 (FUN_0040CDB0, sub_40CDB0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and returns it as typed `RRef`.
 */
RRef NewCTaskThreadPointerSlotRef()
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CDE0 (FUN_0040CDE0, sub_40CDE0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and copies pointer lane value from source.
 */
RRef CopyCTaskThreadPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CE70 (FUN_0040CE70, sub_40CE70)
 *
 * What it does:
 * Wraps existing `CTaskThread*` slot storage as typed `RRef`.
 */
RRef ConstructCTaskThreadPointerSlotRef(void* const slotObject)
{
    return MakeCTaskThreadPointerSlotRef(static_cast<moho::CTaskThread**>(slotObject));
}

/**
 * Address: 0x0040CEA0 (FUN_0040CEA0, sub_40CEA0)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CTaskThread*` slot.
 */
RRef MoveCTaskThreadPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CD90 (FUN_0040CD90, sub_40CD90)
 *
 * What it does:
 * Binds new/construct callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCTaskThreadPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x0040CDA0 (FUN_0040CDA0, sub_40CDA0)
 *
 * What it does:
 * Binds copy/move callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCTaskThreadPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421910 (FUN_00421910, gpg::RRef_CLuaConOutputHandler_P)
 *
 * What it does:
 * Wraps one `CLuaConOutputHandler*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCLuaConOutputHandlerPointerSlotRef(moho::CLuaConOutputHandler** const slot)
{
    return MakePointerSlotRef<moho::CLuaConOutputHandler>(slot);
}

/**
 * Address: 0x00421BD0 (FUN_00421BD0, gpg::RRef::TryUpcast_CLuaConOutputHandler_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CLuaConOutputHandler*` slot and
 * throws `BadRefCast` on mismatch.
 */
moho::CLuaConOutputHandler** TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, moho::CLuaConOutputHandler::GetPointerType());
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(upcast.mObj);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x00421680 (FUN_00421680, sub_421680)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and returns it as typed `RRef`.
 */
RRef NewCLuaConOutputHandlerPointerSlotRef()
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x004216B0 (FUN_004216B0, sub_4216B0)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and copies pointer lane value from source.
 */
RRef CopyCLuaConOutputHandlerPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421740 (FUN_00421740, sub_421740)
 *
 * What it does:
 * Wraps existing `CLuaConOutputHandler*` slot storage as typed `RRef`.
 */
RRef ConstructCLuaConOutputHandlerPointerSlotRef(void* const slotObject)
{
    return MakeCLuaConOutputHandlerPointerSlotRef(static_cast<moho::CLuaConOutputHandler**>(slotObject));
}

/**
 * Address: 0x00421770 (FUN_00421770, sub_421770)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CLuaConOutputHandler*` slot.
 */
RRef MoveCLuaConOutputHandlerPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421660 (FUN_00421660, sub_421660)
 *
 * What it does:
 * Binds new/construct callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCLuaConOutputHandlerPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421670 (FUN_00421670, sub_421670)
 *
 * What it does:
 * Binds copy/move callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCLuaConOutputHandlerPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421620 (FUN_00421620, sub_421620)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `CLuaConOutputHandler*` reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::CLuaConOutputHandler*);
    BindCLuaConOutputHandlerPointerNewAndConstruct(typeInfo);
    BindCLuaConOutputHandlerPointerCopyAndMove(typeInfo);
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::CLuaConOutputHandler>;
    return typeInfo;
}

/**
 * Address: 0x004C8A60 (FUN_004C8A60, sub_4C8A60)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `CScriptObject*` reflection.
 */
gpg::RPointerTypeBase* BindCScriptObjectPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::CScriptObject*);
    typeInfo->newRefFunc_ = &NewCScriptObjectPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCScriptObjectPointerSlotRef;
    typeInfo->cpyRefFunc_ = &CopyCScriptObjectPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCScriptObjectPointerSlotRef;
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::CScriptObject>;
    return typeInfo;
}

/**
 * Address: 0x004E6060 (FUN_004E6060, gpg::RPointerType_CSndParams::Delete)
 *
 * What it does:
 * Releases one allocated `CSndParams*` pointer-slot lane.
 */
void DeleteCSndParamsPointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

/**
 * Address: 0x004E6090 (FUN_004E6090, gpg::RPointerType_CSndParams::NewRef)
 *
 * What it does:
 * Allocates one `CSndParams*` pointer-slot lane and wraps it as `RRef`.
 */
RRef NewCSndParamsPointerSlotRef()
{
    auto* const slot = static_cast<moho::CSndParams**>(::operator new(sizeof(moho::CSndParams*)));
    RRef out{};
    out = gpg::MakeRRef<moho::CSndParams*>(slot);
    return out;
}

/**
 * Address: 0x004E60C0 (FUN_004E60C0, gpg::RPointerType_CSndParams::CpyRef)
 *
 * What it does:
 * Allocates one `CSndParams*` pointer-slot lane and copies source slot value.
 */
RRef CopyCSndParamsPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CSndParams**>(::operator new(sizeof(moho::CSndParams*)));
    if (slot) {
        const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CSndParams::GetPointerType());
        auto* const sourceSlot = static_cast<moho::CSndParams**>(upcast.mObj);
        if (!sourceSlot) {
            throw gpg::BadRefCast("type error");
        }
        *slot = *sourceSlot;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CSndParams*>(slot);
    return out;
}

/**
 * Address: 0x004E6150 (FUN_004E6150, gpg::RPointerType_CSndParams::CtrRef)
 *
 * What it does:
 * Wraps existing `CSndParams*` pointer-slot storage as reflected `RRef`.
 */
RRef ConstructCSndParamsPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::CSndParams*>(static_cast<moho::CSndParams**>(slotObject));
    return out;
}

/**
 * Address: 0x004E6180 (FUN_004E6180, gpg::RPointerType_CSndParams::MovRef)
 *
 * What it does:
 * Writes source slot pointer value into destination `CSndParams*` slot lane.
 */
RRef MoveCSndParamsPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CSndParams**>(slotObject);
    if (slot) {
        const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CSndParams::GetPointerType());
        auto* const sourceSlot = static_cast<moho::CSndParams**>(upcast.mObj);
        if (!sourceSlot) {
            throw gpg::BadRefCast("type error");
        }
        *slot = *sourceSlot;
    } else {
        slot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CSndParams*>(slot);
    return out;
}

/**
 * Address: 0x00557470 (FUN_00557470, gpg::RPointerType_RBlueprint::NewRef)
 *
 * What it does:
 * Allocates one `RBlueprint*` pointer-slot lane and wraps it as `RRef`.
 */
RRef NewRBlueprintPointerSlotRef()
{
    auto* const slot = static_cast<moho::RBlueprint**>(::operator new(sizeof(moho::RBlueprint*)));
    RRef out{};
    out = gpg::MakeRRef<moho::RBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x005574A0 (FUN_005574A0, gpg::RPointerType_RBlueprint::CpyRef)
 *
 * What it does:
 * Allocates one `RBlueprint*` pointer-slot lane and copies the upcast source
 * slot value into it. Frees the new slot and rethrows if the upcast fails.
 */
RRef CopyRBlueprintPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::RBlueprint**>(::operator new(sizeof(moho::RBlueprint*)));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastRBlueprintPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::RBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x00557530 (FUN_00557530, gpg::RPointerType_RBlueprint::CtrRef)
 *
 * What it does:
 * Wraps existing `RBlueprint*` pointer-slot storage as a reflected `RRef`.
 */
RRef ConstructRBlueprintPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::RBlueprint*>(static_cast<moho::RBlueprint**>(slotObject));
    return out;
}

/**
 * Address: 0x00557560 (FUN_00557560, gpg::RPointerType_RBlueprint::MovRef)
 *
 * What it does:
 * Writes the upcast source slot pointer value into the destination
 * `RBlueprint*` slot lane.
 */
RRef MoveRBlueprintPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::RBlueprint**>(slotObject);
    if (slot) {
        *slot = *sourceRef->TryUpcastRBlueprintPointerSlot();
    }

    RRef out{};
    out = gpg::MakeRRef<moho::RBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x005A1AB0 (FUN_005A1AB0, gpg::RPointerType_RUnitBlueprint::NewRef)
 *
 * What it does:
 * Allocates one `RUnitBlueprint*` pointer-slot lane and wraps it as `RRef`.
 */
RRef NewRUnitBlueprintPointerSlotRef()
{
    auto* const slot = static_cast<moho::RUnitBlueprint**>(::operator new(sizeof(moho::RUnitBlueprint*)));
    RRef out{};
    out = gpg::MakeRRef<moho::RUnitBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x005A1AE0 (FUN_005A1AE0, gpg::RPointerType_RUnitBlueprint::CpyRef)
 *
 * What it does:
 * Allocates one `RUnitBlueprint*` pointer-slot lane and copies the upcast
 * source slot value into it. Frees the new slot and rethrows if the upcast
 * fails.
 */
RRef CopyRUnitBlueprintPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::RUnitBlueprint**>(::operator new(sizeof(moho::RUnitBlueprint*)));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastRUnitBlueprintPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::RUnitBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x005A1B70 (FUN_005A1B70, gpg::RPointerType_RUnitBlueprint::CtrRef)
 *
 * What it does:
 * Wraps existing `RUnitBlueprint*` pointer-slot storage as a reflected
 * `RRef`.
 */
RRef ConstructRUnitBlueprintPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::RUnitBlueprint*>(static_cast<moho::RUnitBlueprint**>(slotObject));
    return out;
}

/**
 * Address: 0x005A1BA0 (FUN_005A1BA0, gpg::RPointerType_RUnitBlueprint::MovRef)
 *
 * What it does:
 * Writes the upcast source slot pointer value into the destination
 * `RUnitBlueprint*` slot lane.
 */
RRef MoveRUnitBlueprintPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::RUnitBlueprint**>(slotObject);
    if (slot) {
        *slot = *sourceRef->TryUpcastRUnitBlueprintPointerSlot();
    }

    RRef out{};
    out = gpg::MakeRRef<moho::RUnitBlueprint*>(slot);
    return out;
}

/**
 * Address: 0x005DE590 (FUN_005DE590, gpg::RPointerType_UnitWeapon::NewRef)
 *
 * What it does:
 * Allocates one `UnitWeapon*` pointer-slot lane and wraps it as `RRef`.
 */
RRef NewUnitWeaponPointerSlotRef()
{
    auto* const slot = static_cast<moho::UnitWeapon**>(::operator new(sizeof(moho::UnitWeapon*)));
    RRef out{};
    out = gpg::MakeRRef<moho::UnitWeapon*>(slot);
    return out;
}

/**
 * Address: 0x005DE5C0 (FUN_005DE5C0, gpg::RPointerType_UnitWeapon::CpyRef)
 *
 * What it does:
 * Allocates one `UnitWeapon*` pointer-slot lane and copies the upcast source
 * slot value into it. Frees the new slot and rethrows if the upcast fails.
 */
RRef CopyUnitWeaponPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::UnitWeapon**>(::operator new(sizeof(moho::UnitWeapon*)));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastUnitWeaponPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    out = gpg::MakeRRef<moho::UnitWeapon*>(slot);
    return out;
}

/**
 * Address: 0x005DE650 (FUN_005DE650, gpg::RPointerType_UnitWeapon::CtrRef)
 *
 * What it does:
 * Wraps existing `UnitWeapon*` pointer-slot storage as a reflected `RRef`.
 */
RRef ConstructUnitWeaponPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::UnitWeapon*>(static_cast<moho::UnitWeapon**>(slotObject));
    return out;
}

/**
 * Address: 0x005DE680 (FUN_005DE680, gpg::RPointerType_UnitWeapon::MovRef)
 *
 * What it does:
 * Writes the upcast source slot pointer value into the destination
 * `UnitWeapon*` slot lane.
 */
RRef MoveUnitWeaponPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::UnitWeapon**>(slotObject);
    if (slot) {
        *slot = *sourceRef->TryUpcastUnitWeaponPointerSlot();
    }

    RRef out{};
    out = gpg::MakeRRef<moho::UnitWeapon*>(slot);
    return out;
}

/**
 * Address: 0x004E6380 (FUN_004E6380)
 *
 * What it does:
 * Upcasts one reflected reference to a `CSndParams*` pointer-slot lane and
 * returns the upcast object pointer lane without mismatch checks.
 */
[[maybe_unused]] [[nodiscard]] void* UpcastCSndParamsPointerSlotUnchecked(const gpg::RRef* const sourceRef)
{
    gpg::RType* const pointerType = moho::CSndParams::GetPointerType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, pointerType);
    return upcast.mObj;
}
  gpg::RPointerType<moho::CAcquireTargetTask> gCAcquireTargetTaskPointerType;
  gpg::RPointerType<moho::SimArmy> gSimArmyPointerType;
  gpg::RPointerType<moho::Shield> gShieldPointerType;
  gpg::RPointerType<moho::CDecalHandle> gCDecalHandlePointerType;
}

namespace gpg
{
gpg::RType* preregister_CAcquireTargetTaskPointerTypeStartup()
{
  gpg::PreRegisterRType(typeid(moho::CAcquireTargetTask*), &gCAcquireTargetTaskPointerType);
  return &gCAcquireTargetTaskPointerType;
}

/**
 * Address: 0x0074FE70 (FUN_0074FE70, preregister_SimArmyPointerTypeStartup)
 *
 * What it does:
 * Preregisters the startup-owned pointer reflection descriptor for
 * `moho::SimArmy*` and returns it.
 */
gpg::RType* preregister_SimArmyPointerTypeStartup()
{
  gpg::PreRegisterRType(typeid(moho::SimArmy*), &gSimArmyPointerType);
  return &gSimArmyPointerType;
}

/**
 * Address: 0x00750280 (FUN_00750280, preregister_ShieldPointerTypeStartup)
 *
 * What it does:
 * Preregisters the startup-owned pointer reflection descriptor for
 * `moho::Shield*` and returns it.
 */
gpg::RType* preregister_ShieldPointerTypeStartup()
{
  gpg::PreRegisterRType(typeid(moho::Shield*), &gShieldPointerType);
  return &gShieldPointerType;
}

/**
 * Address: 0x0077EBA0 (FUN_0077EBA0, preregister_CDecalHandlePointerTypeStartup)
 *
 * What it does:
 * Preregisters the startup-owned pointer reflection descriptor for
 * `moho::CDecalHandle*` and returns it.
 */
gpg::RType* preregister_CDecalHandlePointerTypeStartup()
{
  gpg::PreRegisterRType(typeid(moho::CDecalHandle*), &gCDecalHandlePointerType);
  return &gCDecalHandlePointerType;
}

/**
 * Address: 0x00557A90 (FUN_00557A90, gpg::RRef::TryUpcast_RBlueprint_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `RBlueprint*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::RBlueprint** RRef::TryUpcastRBlueprintPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::RBlueprint>(*this);
}

/**
 * Address: 0x0059DE10 (FUN_0059DE10, gpg::RRef::TryUpcast_IFormationInstance_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IFormationInstance*` pointer-slot
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::IFormationInstance** RRef::TryUpcastIFormationInstancePointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IFormationInstance>(*this);
}

/**
 * Address: 0x005A1E90 (FUN_005A1E90, gpg::RRef::TryUpcast_RUnitBlueprint_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `RUnitBlueprint*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::RUnitBlueprint** RRef::TryUpcastRUnitBlueprintPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::RUnitBlueprint>(*this);
}

/**
 * Address: 0x005CA2E0 (FUN_005CA2E0, gpg::RRef::TryUpcast_ReconBlip_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `ReconBlip*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::ReconBlip** RRef::TryUpcastReconBlipPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::ReconBlip>(*this);
}

/**
 * Address: 0x005DF630 (FUN_005DF630, gpg::RRef::TryUpcast_UnitWeapon_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `UnitWeapon*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::UnitWeapon** RRef::TryUpcastUnitWeaponPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::UnitWeapon>(*this);
}

/**
 * Address: 0x005DF6B0 (FUN_005DF6B0, gpg::RRef::TryUpcast_CAcquireTargetTask_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CAcquireTargetTask*` pointer-slot
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CAcquireTargetTask** RRef::TryUpcastCAcquireTargetTaskPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CAcquireTargetTask>(*this);
}

/**
 * Address: 0x0063E6E0 (FUN_0063E6E0, gpg::RRef::TryUpcast_IAniManipulator_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IAniManipulator*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::IAniManipulator** RRef::TryUpcastIAniManipulatorPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IAniManipulator>(*this);
}

/**
 * Address: 0x0066D110 (FUN_0066D110, gpg::RRef::TryUpcast_IEffect_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IEffect*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::IEffect** RRef::TryUpcastIEffectPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IEffect>(*this);
}

/**
 * Address: 0x0067FD80 (FUN_0067FD80, gpg::RRef::TryUpcast_Entity_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `Entity*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::Entity** RRef::TryUpcastEntityPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::Entity>(*this);
}

/**
 * Address: 0x006B3D00 (FUN_006B3D00, gpg::RRef::TryUpcast_CEconomyEvent_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CEconomyEvent*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CEconomyEvent** RRef::TryUpcastCEconomyEventPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CEconomyEvent>(*this);
}

/**
 * Address: 0x006E3E10 (FUN_006E3E10, gpg::RRef::TryUpcast_CUnitCommand_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CUnitCommand*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CUnitCommand** RRef::TryUpcastCUnitCommandPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CUnitCommand>(*this);
}

/**
 * Address: 0x00712B20 (FUN_00712B20, gpg::RRef::TryUpcast_CArmyStatItem_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CArmyStatItem*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CArmyStatItem** RRef::TryUpcastCArmyStatItemPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CArmyStatItem>(*this);
}

/**
 * Address: 0x00751F10 (FUN_00751F10, gpg::RRef::TryUpcast_SimArmy_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `SimArmy*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::SimArmy** RRef::TryUpcastSimArmyPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::SimArmy>(*this);
}

/**
 * Address: 0x00751FC0 (FUN_00751FC0, gpg::RRef::TryUpcast_Shield_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `Shield*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::Shield** RRef::TryUpcastShieldPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::Shield>(*this);
}

/**
 * Address: 0x0077F430 (FUN_0077F430, gpg::RRef::TryUpcast_CDecalHandle_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CDecalHandle*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CDecalHandle** RRef::TryUpcastCDecalHandlePointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CDecalHandle>(*this);
}

/**
 * Address: 0x0040C8B0 (FUN_0040C8B0)
 * Demangled: sub_40C8B0
 */
gpg::RPointerType<moho::CTaskThread>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CTaskThread*), this);
}

/**
 * Address: 0x0040C7C0 (FUN_0040C7C0)
 * Address: 0x00BEE580 (FUN_00BEE580, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CTaskThread::GetName
 */
const char* gpg::RPointerType<moho::CTaskThread>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0040C950 (FUN_0040C950)
 * Demangled: gpg::RPointerType_CTaskThread::GetLexical
 */
fa::string gpg::RPointerType<moho::CTaskThread>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CTaskThread>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0040CAD0 (FUN_0040CAD0)
 * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040CAE0 (FUN_0040CAE0)
 * Demangled: gpg::RPointerType_CTaskThread::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040C920 (FUN_0040C920)
 * Demangled: gpg::RPointerType_CTaskThread::Init
 */
void gpg::RPointerType<moho::CTaskThread>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CTaskThread*);
    BindCTaskThreadPointerNewAndConstruct(this);
    BindCTaskThreadPointerCopyAndMove(this);
    deleteFunc_ = &DeletePointerSlot<moho::CTaskThread>;
}

RType* gpg::RPointerType<moho::CTaskThread>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CTaskThread>();
}

/**
 * Address: 0x005DDF20 (FUN_005DDF20)
 * Address: 0x00BF8670 (FUN_00BF8670, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetName
 */
const char* gpg::RPointerType<moho::CAcquireTargetTask>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x005DE0B0 (FUN_005DE0B0)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetLexical
 */
fa::string gpg::RPointerType<moho::CAcquireTargetTask>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CAcquireTargetTask>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005DE230 (FUN_005DE230)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE240 (FUN_005DE240)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE2A0 (FUN_005DE2A0)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CAcquireTargetTask*` and stores it
 * in the destination pointer slot.
 */
void gpg::RPointerType<moho::CAcquireTargetTask>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CAcquireTargetTask>(obj, from, moho::CAcquireTargetTask::sType);
}

/**
 * Address: 0x005DE080 (FUN_005DE080)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::Init
 */
void gpg::RPointerType<moho::CAcquireTargetTask>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CAcquireTargetTask*);
    newRefFunc_ = &NewPointerSlotRef<moho::CAcquireTargetTask>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CAcquireTargetTask>;
    deleteFunc_ = &DeletePointerSlot<moho::CAcquireTargetTask>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CAcquireTargetTask>;
    movRefFunc_ = &MovePointerSlotRef<moho::CAcquireTargetTask>;
}

RType* gpg::RPointerType<moho::CAcquireTargetTask>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CAcquireTargetTask>();
}

/**
 * Address: 0x0074FD80 (FUN_0074FD80)
 * Address: 0x00C01100 (FUN_00C01100, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_SimArmy::GetName
 *
 * What it does:
 * Builds and caches the `"SimArmy*"` pointer-type name lane from the pointee's
 * reflected name.
 */
const char* gpg::RPointerType<moho::SimArmy>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0074FF10 (FUN_0074FF10)
 * Demangled: gpg::RPointerType_SimArmy::GetLexical
 *
 * What it does:
 * Renders a reflected `SimArmy*` slot as `"[<pointee lexical>]"`, or `"NULL"`
 * when the slot is empty.
 */
fa::string gpg::RPointerType<moho::SimArmy>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::SimArmy>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x00750090 (FUN_00750090)
 * Demangled: gpg::RPointerType_SimArmy::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::SimArmy>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007500A0 (FUN_007500A0)
 * Demangled: gpg::RPointerType_SimArmy::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::SimArmy>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007500C0 (FUN_007500C0)
 * Demangled: gpg::RPointerType_SimArmy::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `SimArmy` in the array the
 * pointer slot addresses (stride `sizeof(SimArmy)`).
 */
RRef gpg::RPointerType<moho::SimArmy>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::SimArmy**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::SimArmy>((*slot) + ind);
    return out;
}

/**
 * Address: 0x007500B0 (FUN_007500B0)
 * Demangled: gpg::RPointerType_SimArmy::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds at
 * most one element).
 */
size_t gpg::RPointerType<moho::SimArmy>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::SimArmy* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x00750100 (FUN_00750100)
 * Demangled: gpg::RPointerType_SimArmy::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `SimArmy*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::SimArmy>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::SimArmy>(obj, from, moho::SimArmy::sType);
}

/**
 * Address: 0x0074FEE0 (FUN_0074FEE0)
 * Demangled: gpg::RPointerType_SimArmy::Init
 *
 * What it does:
 * Marks the descriptor active, records the pointer element size, and installs
 * the per-`SimArmy` slot new/copy/delete/construct/move operation handlers.
 */
void gpg::RPointerType<moho::SimArmy>::Init()
{
    v24 = true;
    size_ = sizeof(moho::SimArmy*);
    newRefFunc_ = &NewPointerSlotRef<moho::SimArmy>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::SimArmy>;
    deleteFunc_ = &DeletePointerSlot<moho::SimArmy>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::SimArmy>;
    movRefFunc_ = &MovePointerSlotRef<moho::SimArmy>;
}

RType* gpg::RPointerType<moho::SimArmy>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::SimArmy>();
}

/**
 * Address: 0x00750190 (FUN_00750190)
 * Address: 0x00C010D0 (FUN_00C010D0, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_Shield::GetName
 *
 * What it does:
 * Builds and caches the `"Shield*"` pointer-type name lane from the pointee's
 * reflected name.
 */
const char* gpg::RPointerType<moho::Shield>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x00750320 (FUN_00750320)
 * Demangled: gpg::RPointerType_Shield::GetLexical
 *
 * What it does:
 * Renders a reflected `Shield*` slot as `"[<pointee lexical>]"`, or `"NULL"`
 * when the slot is empty.
 */
fa::string gpg::RPointerType<moho::Shield>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::Shield>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x007504A0 (FUN_007504A0)
 * Demangled: gpg::RPointerType_Shield::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::Shield>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007504B0 (FUN_007504B0)
 * Demangled: gpg::RPointerType_Shield::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::Shield>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007504D0 (FUN_007504D0)
 * Demangled: gpg::RPointerType_Shield::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `Shield` in the array the
 * pointer slot addresses (stride `sizeof(Shield)`).
 */
RRef gpg::RPointerType<moho::Shield>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::Shield**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::Shield>((*slot) + ind);
    return out;
}

/**
 * Address: 0x007504C0 (FUN_007504C0)
 * Demangled: gpg::RPointerType_Shield::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds at
 * most one element).
 */
size_t gpg::RPointerType<moho::Shield>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::Shield* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x00750510 (FUN_00750510)
 * Demangled: gpg::RPointerType_Shield::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `Shield*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::Shield>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::Shield>(obj, from, gShieldRRefType);
}

/**
 * Address: 0x007502F0 (FUN_007502F0)
 * Demangled: gpg::RPointerType_Shield::Init
 *
 * What it does:
 * Marks the descriptor active, records the pointer element size, and installs
 * the per-`Shield` slot new/copy/delete/construct/move operation handlers.
 */
void gpg::RPointerType<moho::Shield>::Init()
{
    v24 = true;
    size_ = sizeof(moho::Shield*);
    newRefFunc_ = &NewPointerSlotRef<moho::Shield>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::Shield>;
    deleteFunc_ = &DeletePointerSlot<moho::Shield>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::Shield>;
    movRefFunc_ = &MovePointerSlotRef<moho::Shield>;
}

RType* gpg::RPointerType<moho::Shield>::GetPointeeType() const
{
    if (gShieldRRefType == nullptr) {
        gShieldRRefType = gpg::LookupRType(typeid(moho::Shield));
    }
    return gShieldRRefType;
}

/**
 * Address: 0x0077EAB0 (FUN_0077EAB0)
 * Address: 0x00C02A60 (FUN_00C02A60, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CDecalHandle::GetName
 *
 * What it does:
 * Builds and caches the `"CDecalHandle*"` pointer-type name lane from the
 * pointee's reflected name.
 */
const char* gpg::RPointerType<moho::CDecalHandle>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0077EC40 (FUN_0077EC40)
 * Demangled: gpg::RPointerType_CDecalHandle::GetLexical
 *
 * What it does:
 * Renders a reflected `CDecalHandle*` slot as `"[<pointee lexical>]"`, or
 * `"NULL"` when the slot is empty.
 */
fa::string gpg::RPointerType<moho::CDecalHandle>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CDecalHandle>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0077EDC0 (FUN_0077EDC0)
 * Demangled: gpg::RPointerType_CDecalHandle::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CDecalHandle>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0077EDD0 (FUN_0077EDD0)
 * Demangled: gpg::RPointerType_CDecalHandle::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CDecalHandle>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0077EDF0 (FUN_0077EDF0)
 * Demangled: gpg::RPointerType_CDecalHandle::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `CDecalHandle` in the array the
 * pointer slot addresses (stride `sizeof(CDecalHandle)`).
 */
RRef gpg::RPointerType<moho::CDecalHandle>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::CDecalHandle**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::CDecalHandle>((*slot) + ind);
    return out;
}

/**
 * Address: 0x0077EDE0 (FUN_0077EDE0)
 * Demangled: gpg::RPointerType_CDecalHandle::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds at
 * most one element).
 */
size_t gpg::RPointerType<moho::CDecalHandle>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::CDecalHandle* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x0077EE30 (FUN_0077EE30)
 * Demangled: gpg::RPointerType_CDecalHandle::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CDecalHandle*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::CDecalHandle>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CDecalHandle>(obj, from, moho::CDecalHandle::sType);
}

/**
 * Address: 0x0077EC10 (FUN_0077EC10)
 * Demangled: gpg::RPointerType_CDecalHandle::Init
 *
 * What it does:
 * Marks the descriptor active, records the pointer element size, and installs
 * the per-`CDecalHandle` slot new/copy/delete/construct/move operation
 * handlers.
 */
void gpg::RPointerType<moho::CDecalHandle>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CDecalHandle*);
    newRefFunc_ = &NewPointerSlotRef<moho::CDecalHandle>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CDecalHandle>;
    deleteFunc_ = &DeletePointerSlot<moho::CDecalHandle>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CDecalHandle>;
    movRefFunc_ = &MovePointerSlotRef<moho::CDecalHandle>;
}

RType* gpg::RPointerType<moho::CDecalHandle>::GetPointeeType() const
{
    if (moho::CDecalHandle::sType == nullptr) {
        moho::CDecalHandle::sType = gpg::LookupRType(typeid(moho::CDecalHandle));
    }
    return moho::CDecalHandle::sType;
}

/**
 * Address: 0x00556F00 (FUN_00556F00)
 * Address: 0x00BF4D00 (FUN_00BF4D00, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_RBlueprint::GetName
 */
const char* gpg::RPointerType<moho::RBlueprint>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x00557090 (FUN_00557090)
 * Demangled: gpg::RPointerType_RBlueprint::GetLexical
 */
fa::string gpg::RPointerType<moho::RBlueprint>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::RBlueprint>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x00557210 (FUN_00557210)
 * Demangled: gpg::RPointerType_RBlueprint::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::RBlueprint>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00557220 (FUN_00557220)
 * Demangled: gpg::RPointerType_RBlueprint::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::RBlueprint>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00557240 (FUN_00557240)
 * Demangled: gpg::RPointerType_RBlueprint::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `RBlueprint` in the array the
 * pointer slot addresses (stride `sizeof(RBlueprint)`).
 */
RRef gpg::RPointerType<moho::RBlueprint>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::RBlueprint**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::RBlueprint>((*slot) + ind);
    return out;
}

/**
 * Address: 0x00557230 (FUN_00557230)
 * Demangled: gpg::RPointerType_RBlueprint::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds
 * at most one element).
 */
size_t gpg::RPointerType<moho::RBlueprint>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::RBlueprint* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x00557280 (FUN_00557280)
 * Demangled: gpg::RPointerType_RBlueprint::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `RBlueprint*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::RBlueprint>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::RBlueprint>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x00557060 (FUN_00557060)
 * Demangled: gpg::RPointerType_RBlueprint::Init
 */
void gpg::RPointerType<moho::RBlueprint>::Init()
{
    v24 = true;
    size_ = sizeof(moho::RBlueprint*);
    newRefFunc_ = &NewRBlueprintPointerSlotRef;
    cpyRefFunc_ = &CopyRBlueprintPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::RBlueprint>;
    ctorRefFunc_ = &ConstructRBlueprintPointerSlotRef;
    movRefFunc_ = &MoveRBlueprintPointerSlotRef;
}

RType* gpg::RPointerType<moho::RBlueprint>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::RBlueprint>();
}

/**
 * Address: 0x005DDB10 (FUN_005DDB10)
 * Address: 0x00BF86A0 (FUN_00BF86A0, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_UnitWeapon::GetName
 */
const char* gpg::RPointerType<moho::UnitWeapon>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x005DDCA0 (FUN_005DDCA0)
 * Demangled: gpg::RPointerType_UnitWeapon::GetLexical
 */
fa::string gpg::RPointerType<moho::UnitWeapon>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::UnitWeapon>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005DDE20 (FUN_005DDE20)
 * Demangled: gpg::RPointerType_UnitWeapon::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::UnitWeapon>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DDE30 (FUN_005DDE30)
 * Demangled: gpg::RPointerType_UnitWeapon::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::UnitWeapon>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DDE50 (FUN_005DDE50)
 * Demangled: gpg::RPointerType_UnitWeapon::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `UnitWeapon` in the array the
 * pointer slot addresses (stride `sizeof(UnitWeapon)`).
 */
RRef gpg::RPointerType<moho::UnitWeapon>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::UnitWeapon**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::UnitWeapon>((*slot) + ind);
    return out;
}

/**
 * Address: 0x005DDE40 (FUN_005DDE40)
 * Demangled: gpg::RPointerType_UnitWeapon::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds
 * at most one element).
 */
size_t gpg::RPointerType<moho::UnitWeapon>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::UnitWeapon* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x005DDE90 (FUN_005DDE90)
 * Demangled: gpg::RPointerType_UnitWeapon::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `UnitWeapon*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::UnitWeapon>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::UnitWeapon>(obj, from, moho::UnitWeapon::sType);
}

/**
 * Address: 0x005DDC70 (FUN_005DDC70)
 * Demangled: gpg::RPointerType_UnitWeapon::Init
 */
void gpg::RPointerType<moho::UnitWeapon>::Init()
{
    v24 = true;
    size_ = sizeof(moho::UnitWeapon*);
    newRefFunc_ = &NewUnitWeaponPointerSlotRef;
    cpyRefFunc_ = &CopyUnitWeaponPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::UnitWeapon>;
    ctorRefFunc_ = &ConstructUnitWeaponPointerSlotRef;
    movRefFunc_ = &MoveUnitWeaponPointerSlotRef;
}

RType* gpg::RPointerType<moho::UnitWeapon>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::UnitWeapon>();
}

/**
 * Address: 0x0063DB40 (FUN_0063DB40)
 * Address: 0x00BFAF40 (FUN_00BFAF40, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_IAniManipulator::GetName
 */
const char* gpg::RPointerType<moho::IAniManipulator>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0063DCD0 (FUN_0063DCD0)
 * Demangled: gpg::RPointerType_IAniManipulator::GetLexical
 */
fa::string gpg::RPointerType<moho::IAniManipulator>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IAniManipulator>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0063DE50 (FUN_0063DE50)
 * Demangled: gpg::RPointerType_IAniManipulator::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IAniManipulator>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0063DE60 (FUN_0063DE60)
 * Demangled: gpg::RPointerType_IAniManipulator::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IAniManipulator>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0063DEC0 (FUN_0063DEC0)
 * Demangled: gpg::RPointerType_IAniManipulator::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IAniManipulator*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::IAniManipulator>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IAniManipulator>(obj, from, moho::IAniManipulator::sType);
}

/**
 * Address: 0x0063DCA0 (FUN_0063DCA0)
 * Demangled: gpg::RPointerType_IAniManipulator::Init
 */
void gpg::RPointerType<moho::IAniManipulator>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IAniManipulator*);
    newRefFunc_ = &NewPointerSlotRef<moho::IAniManipulator>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::IAniManipulator>;
    deleteFunc_ = &DeletePointerSlot<moho::IAniManipulator>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::IAniManipulator>;
    movRefFunc_ = &MovePointerSlotRef<moho::IAniManipulator>;
}

RType* gpg::RPointerType<moho::IAniManipulator>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::IAniManipulator>();
}

/**
 * Address: 0x0066CB30 (FUN_0066CB30)
 */
gpg::RPointerType<moho::IEffect>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::IEffect*), this);
}

/**
 * Address: 0x0066CA40 (FUN_0066CA40)
 * Address: 0x00BFC150 (FUN_00BFC150, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_IEffect::GetName
 */
const char* gpg::RPointerType<moho::IEffect>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0066CBD0 (FUN_0066CBD0)
 * Demangled: gpg::RPointerType_IEffect::GetLexical
 */
fa::string gpg::RPointerType<moho::IEffect>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IEffect>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0066CD50 (FUN_0066CD50)
 * Demangled: gpg::RPointerType_IEffect::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IEffect>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0066CD60 (FUN_0066CD60)
 * Demangled: gpg::RPointerType_IEffect::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IEffect>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0066CDC0 (FUN_0066CDC0)
 * Demangled: gpg::RPointerType_IEffect::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IEffect*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::IEffect>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IEffect>(obj, from, moho::IEffect::sType);
}

/**
 * Address: 0x0066CBA0 (FUN_0066CBA0)
 * Demangled: gpg::RPointerType_IEffect::Init
 */
void gpg::RPointerType<moho::IEffect>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IEffect*);
    newRefFunc_ = &NewPointerSlotRef<moho::IEffect>;
    cpyRefFunc_ = &CopyIEffectPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::IEffect>;
    ctorRefFunc_ = &ConstructIEffectPointerSlotRef;
    movRefFunc_ = &MoveIEffectPointerSlotRef;
}

RType* gpg::RPointerType<moho::IEffect>::GetPointeeType() const
{
    return moho::IEffect::StaticGetClass();
}

/**
 * Address: 0x006E36B0 (FUN_006E36B0)
 * Address: 0x00BFEA90 (FUN_00BFEA90, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CUnitCommand::GetName
 */
const char* gpg::RPointerType<moho::CUnitCommand>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x006E3840 (FUN_006E3840)
 * Demangled: gpg::RPointerType_CUnitCommand::GetLexical
 */
fa::string gpg::RPointerType<moho::CUnitCommand>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CUnitCommand>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x006E39C0 (FUN_006E39C0)
 * Demangled: gpg::RPointerType_CUnitCommand::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CUnitCommand>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006E39D0 (FUN_006E39D0)
 * Demangled: gpg::RPointerType_CUnitCommand::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CUnitCommand>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006E3A30 (FUN_006E3A30)
 * Demangled: gpg::RPointerType_CUnitCommand::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CUnitCommand*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CUnitCommand>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::CUnitCommand>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x006E3810 (FUN_006E3810)
 * Demangled: gpg::RPointerType_CUnitCommand::Init
 */
void gpg::RPointerType<moho::CUnitCommand>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CUnitCommand*);
    newRefFunc_ = &NewPointerSlotRef<moho::CUnitCommand>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CUnitCommand>;
    deleteFunc_ = &DeletePointerSlot<moho::CUnitCommand>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CUnitCommand>;
    movRefFunc_ = &MovePointerSlotRef<moho::CUnitCommand>;
}

RType* gpg::RPointerType<moho::CUnitCommand>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CUnitCommand>();
}

/**
 * Address: 0x0067E320 (FUN_0067E320)
 * Address: 0x00BFC960 (FUN_00BFC960, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_Entity::GetName
 */
const char* gpg::RPointerType<moho::Entity>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0067E4B0 (FUN_0067E4B0)
 * Demangled: gpg::RPointerType_Entity::GetLexical
 */
fa::string gpg::RPointerType<moho::Entity>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::Entity>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0067E630 (FUN_0067E630)
 * Demangled: gpg::RPointerType_Entity::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E640 (FUN_0067E640)
 * Demangled: gpg::RPointerType_Entity::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E6A0 (FUN_0067E6A0)
 * Demangled: gpg::RPointerType_Entity::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `Entity*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::Entity>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::Entity>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x0067E480 (FUN_0067E480)
 * Demangled: gpg::RPointerType_Entity::Init
 */
void gpg::RPointerType<moho::Entity>::Init()
{
    v24 = true;
    size_ = sizeof(moho::Entity*);
    newRefFunc_ = &NewPointerSlotRef<moho::Entity>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::Entity>;
    deleteFunc_ = &DeletePointerSlot<moho::Entity>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::Entity>;
    movRefFunc_ = &MovePointerSlotRef<moho::Entity>;
}

RType* gpg::RPointerType<moho::Entity>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::Entity>();
}

/**
 * Address: 0x006B2510 (FUN_006B2510)
 * Address: 0x00BFDD00 (FUN_00BFDD00, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetName
 */
const char* gpg::RPointerType<moho::CEconomyEvent>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x006B26A0 (FUN_006B26A0)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetLexical
 */
fa::string gpg::RPointerType<moho::CEconomyEvent>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CEconomyEvent>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x006B2820 (FUN_006B2820)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2830 (FUN_006B2830)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2890 (FUN_006B2890)
 * Demangled: gpg::RPointerType_CEconomyEvent::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CEconomyEvent*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CEconomyEvent>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CEconomyEvent>(obj, from, moho::CEconomyEvent::sType);
}

/**
 * Address: 0x006B2670 (FUN_006B2670)
 * Demangled: gpg::RPointerType_CEconomyEvent::Init
 */
void gpg::RPointerType<moho::CEconomyEvent>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CEconomyEvent*);
    newRefFunc_ = &NewPointerSlotRef<moho::CEconomyEvent>;
    cpyRefFunc_ = &CopyCEconomyEventPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::CEconomyEvent>;
    ctorRefFunc_ = &ConstructCEconomyEventPointerSlotRef;
    movRefFunc_ = &MoveCEconomyEventPointerSlotRef;
}

RType* gpg::RPointerType<moho::CEconomyEvent>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CEconomyEvent>();
}

/**
 * Address: 0x004212A0 (FUN_004212A0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::RPointerType
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), this);
}

/**
 * Address: 0x004211B0 (FUN_004211B0)
 * Address: 0x00BEEE20 (FUN_00BEEE20, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
 */
const char* gpg::RPointerType<moho::CLuaConOutputHandler>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x00421340 (FUN_00421340)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
 */
fa::string gpg::RPointerType<moho::CLuaConOutputHandler>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CLuaConOutputHandler>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004214C0 (FUN_004214C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004214D0 (FUN_004214D0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00421310 (FUN_00421310)
  * Alias of FUN_00421620 (non-canonical helper lane).
  * Alias of FUN_00421660 (non-canonical helper lane).
  * Alias of FUN_00421670 (non-canonical helper lane).
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
 */
void gpg::RPointerType<moho::CLuaConOutputHandler>::Init()
{
    BindCLuaConOutputHandlerPointerAll(this);
}

RType* gpg::RPointerType<moho::CLuaConOutputHandler>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CLuaConOutputHandler>();
}

/**
 * Address: 0x004C85F0 (FUN_004C85F0)
 * Address: 0x00BF0A10 (FUN_00BF0A10, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CScriptObject::GetName
 */
const char* gpg::RPointerType<moho::CScriptObject>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x004C8780 (FUN_004C8780)
 * Demangled: gpg::RPointerType_CScriptObject::GetLexical
 */
fa::string gpg::RPointerType<moho::CScriptObject>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CScriptObject>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004C8900 (FUN_004C8900)
 * Demangled: gpg::RPointerType_CScriptObject::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8910 (FUN_004C8910)
 * Demangled: gpg::RPointerType_CScriptObject::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8930 (FUN_004C8930)
 * Demangled: gpg::RPointerType_CScriptObject::SubscriptIndex
 */
RRef gpg::RPointerType<moho::CScriptObject>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::CScriptObject**>(obj);
    return moho::SCR_MakeScriptObjectRef((*slot) + ind);
}

/**
 * Address: 0x004C8920 (FUN_004C8920)
 * Demangled: gpg::RPointerType_CScriptObject::GetCount
 */
size_t gpg::RPointerType<moho::CScriptObject>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::CScriptObject* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x004C8970 (FUN_004C8970)
 * Demangled: gpg::RPointerType_CScriptObject::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CScriptObject*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CScriptObject>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CScriptObject>(obj, from, moho::CScriptObject::sType);
}

/**
 * Address: 0x004C8750 (FUN_004C8750)
 * Demangled: gpg::RPointerType_CScriptObject::Init
 */
void gpg::RPointerType<moho::CScriptObject>::Init()
{
    BindCScriptObjectPointerAll(this);
}

RType* gpg::RPointerType<moho::CScriptObject>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CScriptObject>();
}

/**
 * Address: 0x004E5BC0 (FUN_004E5BC0)
 * Address: 0x00BF1170 (FUN_00BF1170, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CSndParams::GetName
 */
const char* gpg::RPointerType<moho::CSndParams>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x004E5D50 (FUN_004E5D50)
 * Demangled: gpg::RPointerType_CSndParams::GetLexical
 */
fa::string gpg::RPointerType<moho::CSndParams>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CSndParams>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004E5ED0 (FUN_004E5ED0)
 * Demangled: gpg::RPointerType_CSndParams::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5EE0 (FUN_004E5EE0)
 * Demangled: gpg::RPointerType_CSndParams::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5F00 (FUN_004E5F00)
 * Demangled: gpg::RPointerType_CSndParams::SubscriptIndex
 */
RRef gpg::RPointerType<moho::CSndParams>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::CSndParams**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::CSndParams>((*slot) + ind);
    return out;
}

/**
 * Address: 0x004E5EF0 (FUN_004E5EF0)
 * Demangled: gpg::RPointerType_CSndParams::GetCount
 */
size_t gpg::RPointerType<moho::CSndParams>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::CSndParams* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x004E5F40 (FUN_004E5F40)
 * Demangled: gpg::RPointerType_CSndParams::AssignPointer
 */
void gpg::RPointerType<moho::CSndParams>::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<moho::CSndParams**>(obj);
    if (!slot) {
        gpg::HandleAssertFailure("void_pptr", 663, kReflectionHeaderPath);
    }

    RType* pointeeType = moho::CSndParams::sType2;
    if (!pointeeType) {
        pointeeType = gpg::LookupRType(typeid(moho::CSndParams));
        moho::CSndParams::sType2 = pointeeType;
    }

    const RRef upcast = gpg::REF_UpcastPtr(from, pointeeType);
    if (from.mObj && !upcast.mObj) {
        throw BadRefCast("type error");
    }

    *slot = static_cast<moho::CSndParams*>(upcast.mObj);
}

/**
 * Address: 0x004E5D20 (FUN_004E5D20)
 * Demangled: gpg::RPointerType_CSndParams::Init
 */
void gpg::RPointerType<moho::CSndParams>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CSndParams*);
    newRefFunc_ = &NewCSndParamsPointerSlotRef;
    cpyRefFunc_ = &CopyCSndParamsPointerSlotRef;
    deleteFunc_ = &DeleteCSndParamsPointerSlot;
    ctorRefFunc_ = &ConstructCSndParamsPointerSlotRef;
    movRefFunc_ = &MoveCSndParamsPointerSlotRef;
}

RType* gpg::RPointerType<moho::CSndParams>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CSndParams>();
}

/**
 * Address: 0x0059D4C0 (FUN_0059D4C0)
 * Address: 0x00BF6950 (FUN_00BF6950, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_IFormationInstance::GetName
 */
const char* gpg::RPointerType<moho::IFormationInstance>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x0059D650 (FUN_0059D650)
 * Demangled: gpg::RPointerType_IFormationInstance::GetLexical
 */
fa::string gpg::RPointerType<moho::IFormationInstance>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IFormationInstance>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0059D7D0 (FUN_0059D7D0)
 * Demangled: gpg::RPointerType_IFormationInstance::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IFormationInstance>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0059D7E0 (FUN_0059D7E0)
 * Demangled: gpg::RPointerType_IFormationInstance::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IFormationInstance>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0059D840 (FUN_0059D840)
 * Demangled: gpg::RPointerType_IFormationInstance::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IFormationInstance*` and stores it
 * in the destination pointer slot.
 */
void gpg::RPointerType<moho::IFormationInstance>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IFormationInstance>(obj, from, moho::IFormationInstance::sType);
}

/**
 * Address: 0x0059D620 (FUN_0059D620)
 * Demangled: gpg::RPointerType_IFormationInstance::Init
 */
void gpg::RPointerType<moho::IFormationInstance>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IFormationInstance*);
    newRefFunc_ = &NewPointerSlotRef<moho::IFormationInstance>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::IFormationInstance>;
    deleteFunc_ = &DeletePointerSlot<moho::IFormationInstance>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::IFormationInstance>;
    movRefFunc_ = &MovePointerSlotRef<moho::IFormationInstance>;
}

RType* gpg::RPointerType<moho::IFormationInstance>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::IFormationInstance>();
}

/**
 * Address: 0x005A14F0 (FUN_005A14F0)
 * Address: 0x00BF6BB0 (FUN_00BF6BB0, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_RUnitBlueprint::GetName
 */
const char* gpg::RPointerType<moho::RUnitBlueprint>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x005A1680 (FUN_005A1680)
 * Demangled: gpg::RPointerType_RUnitBlueprint::GetLexical
 */
fa::string gpg::RPointerType<moho::RUnitBlueprint>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::RUnitBlueprint>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005A1800 (FUN_005A1800)
 * Demangled: gpg::RPointerType_RUnitBlueprint::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::RUnitBlueprint>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005A1810 (FUN_005A1810)
 * Demangled: gpg::RPointerType_RUnitBlueprint::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::RUnitBlueprint>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005A1830 (FUN_005A1830)
 * Demangled: gpg::RPointerType_RUnitBlueprint::SubscriptIndex
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th `RUnitBlueprint` in the array
 * the pointer slot addresses (stride `sizeof(RUnitBlueprint)`).
 */
RRef gpg::RPointerType<moho::RUnitBlueprint>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::RUnitBlueprint**>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::RUnitBlueprint>((*slot) + ind);
    return out;
}

/**
 * Address: 0x005A1820 (FUN_005A1820)
 * Demangled: gpg::RPointerType_RUnitBlueprint::GetCount
 *
 * What it does:
 * Returns 1 when the pointer slot is non-null, else 0 (a pointer type holds
 * at most one element).
 */
size_t gpg::RPointerType<moho::RUnitBlueprint>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::RUnitBlueprint* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x005A1870 (FUN_005A1870)
 * Demangled: gpg::RPointerType_RUnitBlueprint::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `RUnitBlueprint*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::RUnitBlueprint>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::RUnitBlueprint>(obj, from, sAssignPointeeType);
}
namespace
{
/**
 * Address: 0x005A1AA0 (FUN_005A1AA0)
 *
 * What it does:
 * Binds copy/move callback lanes for `RUnitBlueprint*` pointer reflection.
 */
gpg::RPointerTypeBase* BindRUnitBlueprintPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyRUnitBlueprintPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveRUnitBlueprintPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x005A1A40 (FUN_005A1A40)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `RUnitBlueprint*` reflection.
 */
gpg::RPointerTypeBase* BindRUnitBlueprintPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::RUnitBlueprint*);
    typeInfo->newRefFunc_ = &NewRUnitBlueprintPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructRUnitBlueprintPointerSlotRef;
    (void)BindRUnitBlueprintPointerCopyAndMove(typeInfo);
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::RUnitBlueprint>;
    return typeInfo;
}
}


/**
 * Address: 0x005A1650 (FUN_005A1650)
 * Demangled: gpg::RPointerType_RUnitBlueprint::Init
 */
void gpg::RPointerType<moho::RUnitBlueprint>::Init()
{
    (void)BindRUnitBlueprintPointerAll(this);
}

RType* gpg::RPointerType<moho::RUnitBlueprint>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::RUnitBlueprint>();
}

/**
 * Address: 0x005C8080 (FUN_005C8080)
 * Address: 0x00BF7C30 (FUN_00BF7C30, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_ReconBlip::GetName
 */
const char* gpg::RPointerType<moho::ReconBlip>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x005C8210 (FUN_005C8210)
 * Demangled: gpg::RPointerType_ReconBlip::GetLexical
 */
fa::string gpg::RPointerType<moho::ReconBlip>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::ReconBlip>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005C8390 (FUN_005C8390)
 * Demangled: gpg::RPointerType_ReconBlip::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::ReconBlip>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005C83A0 (FUN_005C83A0)
 * Demangled: gpg::RPointerType_ReconBlip::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::ReconBlip>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005C8400 (FUN_005C8400)
 * Demangled: gpg::RPointerType_ReconBlip::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `ReconBlip*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::ReconBlip>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::ReconBlip>(obj, from, moho::ReconBlip::sType);
}

/**
 * Address: 0x005C81E0 (FUN_005C81E0)
 * Demangled: gpg::RPointerType_ReconBlip::Init
 */
void gpg::RPointerType<moho::ReconBlip>::Init()
{
    v24 = true;
    size_ = sizeof(moho::ReconBlip*);
    newRefFunc_ = &NewPointerSlotRef<moho::ReconBlip>;
    cpyRefFunc_ = &CopyReconBlipPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::ReconBlip>;
    ctorRefFunc_ = &ConstructReconBlipPointerSlotRef;
    movRefFunc_ = &MoveReconBlipPointerSlotRef;
}

RType* gpg::RPointerType<moho::ReconBlip>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::ReconBlip>();
}

/**
 * Address: 0x007115D0 (FUN_007115D0)
 * Address: 0x00BFFA00 (FUN_00BFFA00, atexit destructor of GetName's cached name)
 * Demangled: gpg::RPointerType_CArmyStatItem::GetName
 */
const char* gpg::RPointerType<moho::CArmyStatItem>::GetName() const
{
    static const fa::string sName = fa::string(GetPointeeType()->GetName()) + "*";
    return sName.c_str();
}

/**
 * Address: 0x00711760 (FUN_00711760)
 * Demangled: gpg::RPointerType_CArmyStatItem::GetLexical
 */
fa::string gpg::RPointerType<moho::CArmyStatItem>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CArmyStatItem>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x007118E0 (FUN_007118E0)
 * Demangled: gpg::RPointerType_CArmyStatItem::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CArmyStatItem>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007118F0 (FUN_007118F0)
 * Demangled: gpg::RPointerType_CArmyStatItem::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CArmyStatItem>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00711950 (FUN_00711950)
 * Demangled: gpg::RPointerType_CArmyStatItem::AssignPointer
 *
 * What it does:
 * Upcasts one reflected source reference to `CArmyStatItem*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CArmyStatItem>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CArmyStatItem>(obj, from, moho::CArmyStatItem::sType);
}

/**
 * Address: 0x00711730 (FUN_00711730)
 * Demangled: gpg::RPointerType_CArmyStatItem::Init
 */
void gpg::RPointerType<moho::CArmyStatItem>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CArmyStatItem*);
    newRefFunc_ = &NewPointerSlotRef<moho::CArmyStatItem>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CArmyStatItem>;
    deleteFunc_ = &DeletePointerSlot<moho::CArmyStatItem>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CArmyStatItem>;
    movRefFunc_ = &MovePointerSlotRef<moho::CArmyStatItem>;
}

RType* gpg::RPointerType<moho::CArmyStatItem>::GetPointeeType() const
{
    return gpg::RTypeOf<moho::CArmyStatItem>();
}
}

