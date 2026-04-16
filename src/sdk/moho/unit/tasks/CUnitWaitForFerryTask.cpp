#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskWaitForFerry = (1ull << 21);

  [[nodiscard]] gpg::RType* CachedCUnitWaitForFerryTaskType()
  {
    gpg::RType* type = moho::CUnitWaitForFerryTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitWaitForFerryTask));
      moho::CUnitWaitForFerryTask::sType = type;
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
}

namespace moho
{
  gpg::RType* CUnitWaitForFerryTask::sType = nullptr;

  /**
   * Address: 0x0060FAA0 (FUN_0060FAA0, Moho::CUnitWaitForFerryTask::CUnitWaitForFerryTask)
   * Mangled: ??0CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes wait-for-ferry task state from dispatch context, stores ferry
   * unit weak-link ownership, snapshots move goal payload, and sets owner unit
   * focus/state for ferry assignment.
   */
  CUnitWaitForFerryTask::CUnitWaitForFerryTask(
    Unit* const ferryUnit,
    IAiCommandDispatchImpl* const dispatch,
    const SNavGoal& moveGoal
  )
    : CCommandTask(static_cast<CCommandTask*>(dispatch))
    , mDispatch(dispatch)
    , mFerryUnit()
    , mMoveGoal(moveGoal)
  {
    mFerryUnit.Set(ferryUnit);

    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      ownerUnit->UnitStateMask |= kUnitStateMaskWaitForFerry;
      ownerUnit->SetFocusEntity(ferryUnit);
    }
  }

  /**
   * Address: 0x0060FB90 (FUN_0060FB90, Moho::CUnitWaitForFerryTask::~CUnitWaitForFerryTask)
   * Mangled: ??1CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Clears owner assigned-transport/focus weak-link lanes, frees pending
   * occupancy-grid reservation, and drops wait-for-ferry state ownership.
   */
  CUnitWaitForFerryTask::~CUnitWaitForFerryTask()
  {
    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      ownerUnit->AssignedTransportRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
      ownerUnit->SetFocusEntity(nullptr);
      ownerUnit->FreeOgridRect();
      ownerUnit->UnitStateMask &= ~kUnitStateMaskWaitForFerry;
    }

    mFerryUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060FF50 (FUN_0060FF50, Moho::CUnitWaitForFerryTask::operator new)
   * Mangled: ??2CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Allocates one wait-for-ferry task object and forwards dispatch, move-goal,
   * and ferry-unit context into in-place construction.
   */
  CUnitWaitForFerryTask* CUnitWaitForFerryTask::Create(
    IAiCommandDispatchImpl* const dispatch,
    const SNavGoal& moveGoal,
    Unit* const ferryUnit
  )
  {
    void* const storage = ::operator new(sizeof(CUnitWaitForFerryTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitWaitForFerryTask(ferryUnit, dispatch, moveGoal);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace moho

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitWaitForFerryTaskSerializer{};

  /**
   * Address: 0x0060F9E0 (FUN_0060F9E0)
   *
   * What it does:
   * Unlinks `CUnitWaitForFerryTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitWaitForFerryTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitWaitForFerryTaskSerializer);
  }

  /**
   * Address: 0x0060FA10 (FUN_0060FA10)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitWaitForFerryTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitWaitForFerryTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitWaitForFerryTaskSerializer);
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x00610800 (FUN_00610800, gpg::RRef_CUnitWaitForFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitWaitForFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitWaitForFerryTask(gpg::RRef* const outRef, moho::CUnitWaitForFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitWaitForFerryTaskType());
    return outRef;
  }

  /**
   * Address: 0x006105E0 (FUN_006105E0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CUnitWaitForFerryTask` and copies object/type fields into the
   * destination reference record.
   */
  gpg::RRef* AssignCUnitWaitForFerryTaskRef(gpg::RRef* const outRef, moho::CUnitWaitForFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitWaitForFerryTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
