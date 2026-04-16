#include "moho/unit/tasks/CUnitFerryTask.h"

#include <memory>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskFerryTaskFlags = (1ull << 20) | (1ull << 32);
  constexpr std::uint64_t kUnitStateMaskFerryTaskAssigned = (1ull << 20);
  constexpr const char* kFactoryCategoryName = "FACTORY";
  constexpr const char* kFerryBeaconCategoryName = "FERRYBEACON";
  constexpr const char* kOnFerryPointSetScriptName = "OnFerryPointSet";

  [[nodiscard]] gpg::RType* CachedCUnitFerryTaskType()
  {
    gpg::RType* type = moho::CUnitFerryTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFerryTask));
      moho::CUnitFerryTask::sType = type;
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

  void MarkOwnerFerryTaskAssigned(moho::Unit* const ownerUnit)
  {
    if (ownerUnit == nullptr) {
      return;
    }

    ownerUnit->UnitStateMask |= kUnitStateMaskFerryTaskAssigned;
  }

  void RunOwnerFerryPointSetScript(moho::Unit* const ownerUnit)
  {
    if (ownerUnit == nullptr) {
      return;
    }

    ownerUnit->RunScript(kOnFerryPointSetScriptName);
  }

  [[nodiscard]] bool IsLiveFactoryWithBuilder(const moho::Unit* const unit)
  {
    return unit != nullptr && unit->IsInCategory(kFactoryCategoryName) && unit->AiBuilder != nullptr && !unit->IsDead();
  }

  void ResolveFactoryTransportOwner(moho::WeakPtr<moho::Unit>& ferryUnitRef)
  {
    while (true) {
      moho::Unit* const ferryUnit = ferryUnitRef.GetObjectPtr();
      if (ferryUnit == nullptr) {
        break;
      }

      if (ferryUnit->IsInCategory(kFactoryCategoryName)) {
        return;
      }

      ferryUnitRef.Set(ferryUnit->GetTransportedBy());
    }
  }

  [[nodiscard]] moho::Unit* ResolveHeadCommandFerryBeacon(moho::Unit* const ownerUnit)
  {
    if (ownerUnit == nullptr || ownerUnit->CommandQueue == nullptr || ownerUnit->CommandQueue->mCommandVec.empty()) {
      return nullptr;
    }

    moho::CUnitCommand* const headCommand = ownerUnit->CommandQueue->mCommandVec.front().GetObjectPtr();
    if (headCommand == nullptr) {
      return nullptr;
    }

    if (boost::shared_ptr<moho::Unit> beaconFromWeak = headCommand->mUnit.lock(); beaconFromWeak != nullptr) {
      return beaconFromWeak.get();
    }

    moho::Entity* const targetEntity = headCommand->mTarget.GetEntity();
    return (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
  }
}

namespace moho
{
  gpg::RType* CUnitFerryTask::sType = nullptr;

  /**
   * Address: 0x0060DD70 (FUN_0060DD70, Moho::CUnitFerryTask::CUnitFerryTask)
   *
   * What it does:
   * Initializes one ferry task from dispatch-position context, snapshots
   * transport loaded-state into task-state, and binds head-command beacon
   * ownership when present.
   */
  CUnitFerryTask::CUnitFerryTask(IAiCommandDispatchImpl* const dispatch, const Wm3::Vector3f& ferryPosition)
    : CCommandTask(static_cast<CCommandTask*>(dispatch))
    , mDispatch(dispatch)
    , mCommandIndex(0)
    , mHasResolvedFerryTarget(false)
    , mPos(ferryPosition)
    , mCommandUnit()
    , mFerryUnit()
    , mBeacon()
  {
    MarkOwnerFerryTaskAssigned(mUnit);

    bool hasLoadedUnits = false;
    if (mUnit != nullptr && mUnit->AiTransport != nullptr) {
      const EntitySetTemplate<Unit> loadedUnits = mUnit->AiTransport->TransportGetLoadedUnits(false);
      hasLoadedUnits = !loadedUnits.Empty();
    }
    mTaskState = hasLoadedUnits ? TASKSTATE_Waiting : TASKSTATE_Complete;

    if (Unit* const ferryBeacon = ResolveHeadCommandFerryBeacon(mUnit); ferryBeacon != nullptr) {
      mBeacon.Set(ferryBeacon);
      RunOwnerFerryPointSetScript(mUnit);
    }
  }

  /**
   * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
   *
   * What it does:
   * Initializes one ferry-task lane from parent command-task context and one
   * target unit, resolves ferry/beacon ownership, then publishes the ferry
   * script hook and completes immediately.
   */
  CUnitFerryTask::CUnitFerryTask(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(parentTask))
    , mCommandIndex(0)
    , mHasResolvedFerryTarget(false)
    , mPos(targetUnit != nullptr ? targetUnit->GetPosition() : Wm3::Vector3f{})
    , mCommandUnit()
    , mFerryUnit()
    , mBeacon()
  {
    mCommandUnit.Set(targetUnit);
    MarkOwnerFerryTaskAssigned(mUnit);

    if (IsLiveFactoryWithBuilder(targetUnit)) {
      mFerryUnit.Set(targetUnit);
    } else if (targetUnit != nullptr && targetUnit->IsUnitState(UNITSTATE_Attached)) {
      mHasResolvedFerryTarget = true;
      mFerryUnit.Set(targetUnit);
      ResolveFactoryTransportOwner(mFerryUnit);
    } else if (targetUnit != nullptr && targetUnit->IsInCategory(kFerryBeaconCategoryName)) {
      mHasResolvedFerryTarget = true;
      mBeacon.Set(targetUnit);
      mPos = targetUnit->GetPosition();
    }

    RunOwnerFerryPointSetScript(mUnit);
    mTaskState = TASKSTATE_Complete;
  }

  /**
   * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
   *
   * What it does:
   * Aborts active unit navigation, clears ferry task owner-state bits, and
   * unlinks all ferry-task weak-unit ownership lanes.
   */
  CUnitFerryTask::~CUnitFerryTask()
  {
    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      if (IAiNavigator* const navigator = ownerUnit->AiNavigator; navigator != nullptr) {
        navigator->AbortMove();
      }

      ownerUnit->UnitStateMask &= ~kUnitStateMaskFerryTaskFlags;
    }

    mBeacon.UnlinkFromOwnerChain();
    mFerryUnit.UnlinkFromOwnerChain();
    mCommandUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060F790 (FUN_0060F790, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards dispatch-position context
   * into in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::CreateFromDispatch(
    IAiCommandDispatchImpl* const dispatch,
    const Wm3::Vector3f& ferryPosition
  )
  {
    auto* const raw = static_cast<CUnitFerryTask*>(::operator new(sizeof(CUnitFerryTask)));
    auto guard = std::unique_ptr<CUnitFerryTask, void (*)(CUnitFerryTask*)>(raw, [](CUnitFerryTask* p) {
      ::operator delete(p);
    });
    return std::construct_at(guard.release(), dispatch, ferryPosition);
  }

  /**
   * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::Create(
    CCommandTask* parentTask,
    Unit* targetUnit
  )
  {
    auto* raw = static_cast<CUnitFerryTask*>(::operator new(sizeof(CUnitFerryTask)));
    auto guard = std::unique_ptr<CUnitFerryTask, void (*)(CUnitFerryTask*)>(raw, [](CUnitFerryTask* p) {
      ::operator delete(p);
    });
    return std::construct_at(guard.release(), parentTask, targetUnit);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00610650 (FUN_00610650, gpg::RRef_CUnitFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFerryTask(gpg::RRef* const outRef, moho::CUnitFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitFerryTaskType());
    return outRef;
  }

  /**
   * Address: 0x006105B0 (FUN_006105B0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFerryTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFerryTaskRef(gpg::RRef* const outRef, moho::CUnitFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitFerryTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
