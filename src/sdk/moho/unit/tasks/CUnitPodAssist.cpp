#include "moho/unit/tasks/CUnitPodAssist.h"

#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/EntityFastVectorReflection.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitRepairTask.h"

namespace
{
  class CUnitRepairTaskDispatchView final : public moho::CUnitRepairTask
  {
  public:
    using moho::CUnitRepairTask::CUnitRepairTask;

    int Execute() override
    {
      return -1;
    }

    void OnEvent(moho::ECommandEvent) override {}
  };

  static_assert(
    sizeof(CUnitRepairTaskDispatchView) == sizeof(moho::CUnitRepairTask),
    "CUnitRepairTaskDispatchView size must match CUnitRepairTask"
  );

  [[nodiscard]] gpg::RType* CachedCUnitPodAssistType()
  {
    gpg::RType* type = moho::CUnitPodAssist::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitPodAssist));
      moho::CUnitPodAssist::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] moho::IAiCommandDispatchImpl* AsDispatchImpl(moho::CCommandTask* const dispatchTask) noexcept
  {
    return static_cast<moho::IAiCommandDispatchImpl*>(dispatchTask);
  }

  [[nodiscard]] float DistanceSquared(const Wm3::Vec3f& a, const Wm3::Vec3f& b) noexcept
  {
    const float dx = a.x - b.x;
    const float dy = a.y - b.y;
    const float dz = a.z - b.z;
    return (dx * dx) + (dy * dy) + (dz * dz);
  }

  void DispatchRepairTask(
    moho::CUnitPodAssist* const task,
    moho::Unit* const targetUnit,
    const bool isSiloBuild
  )
  {
    (void)new (std::nothrow) CUnitRepairTaskDispatchView(AsDispatchImpl(task->mDispatchTask), targetUnit, isSiloBuild);
  }

  void DispatchReclaimTask(moho::CUnitPodAssist* const task, moho::Entity* const targetEntity)
  {
    moho::CAiTarget target{};
    (void)target.UpdateTarget(targetEntity);
    AsDispatchImpl(task->mDispatchTask)->IssueReclaimTask(target);
  }

  [[nodiscard]] moho::Unit* ResolveFocusUnit(moho::Unit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    moho::Entity* const focusEntity = unit->GetFocusEntity();
    return (focusEntity != nullptr) ? focusEntity->IsUnit() : nullptr;
  }

  [[nodiscard]] bool IsEligibleNearbyAssistCandidate(
    moho::Unit* const ownerUnit,
    moho::Unit* const candidateUnit
  )
  {
    if (ownerUnit == nullptr || candidateUnit == nullptr) {
      return false;
    }

    if (candidateUnit == ownerUnit || candidateUnit->IsDead()) {
      return false;
    }

    if (ownerUnit->ArmyRef == nullptr || candidateUnit->SimulationRef == nullptr || candidateUnit->SimulationRef->mMapData == nullptr) {
      return false;
    }

    if (!candidateUnit->SimulationRef->mMapData->IsWithin(candidateUnit->Position, 1.0f, ownerUnit->ArmyRef->UseWholeMap())) {
      return false;
    }

    if (Wm3::Vector3f::Compare(&candidateUnit->Position, &candidateUnit->PrevPosition) != 0) {
      return false;
    }

    const moho::CArmyImpl* const ownerArmy = ownerUnit->ArmyRef;
    const moho::CArmyImpl* const candidateArmy = candidateUnit->ArmyRef;
    return candidateArmy == ownerArmy || ownerArmy->GetAllianceWith(candidateArmy) == moho::ALLIANCE_Ally;
  }

  [[nodiscard]] moho::Unit* ResolveAssistDistanceTarget(moho::Unit* const candidateUnit) noexcept
  {
    if (candidateUnit == nullptr) {
      return nullptr;
    }

    if (!candidateUnit->IsUnitState(moho::UNITSTATE_BeingReclaimed)) {
      if (!candidateUnit->IsBeingBuilt() && candidateUnit->Health >= candidateUnit->MaxHealth) {
        if (moho::Unit* const focusUnit = ResolveFocusUnit(candidateUnit); focusUnit != nullptr) {
          return focusUnit;
        }

        if (!candidateUnit->IsUnitState(moho::UNITSTATE_Enhancing)
            && !candidateUnit->IsUnitState(moho::UNITSTATE_SiloBuildingAmmo)) {
          return nullptr;
        }
      }
    }

    return candidateUnit;
  }

  void GatherNearbyAssistEntities(moho::Unit* const ownerUnit, moho::EntityGatherVector& outEntities)
  {
    outEntities.ResetStorageToInline();
    if (ownerUnit == nullptr || ownerUnit->SimulationRef == nullptr || ownerUnit->SimulationRef->mOGrid == nullptr) {
      return;
    }

    const moho::RUnitBlueprint* const blueprint = ownerUnit->GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    const Wm3::Vec3f& ownerPosition = ownerUnit->GetPosition();
    const float scanRadius = blueprint->AI.GuardScanRadius;
    const gpg::Rect2f worldRect{
      ownerPosition.x - scanRadius,
      ownerPosition.z - scanRadius,
      ownerPosition.x + scanRadius,
      ownerPosition.z + scanRadius
    };

    moho::CollisionDBRect cellRect{};
    (void)moho::func_Rect2fToInt16(&cellRect, worldRect);
    (void)ownerUnit->SimulationRef->mOGrid->mEntityOccupationManager.GatherUnmarkedEntities(
      outEntities,
      cellRect,
      moho::ENTITYTYPE_Unit
    );
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
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitPodAssist::sType = nullptr;

  /**
   * Address: 0x0061D3B0 (FUN_0061D3B0, ??0CUnitPodAssist@Moho@@QAE@@Z)
   */
  CUnitPodAssist::CUnitPodAssist(
    CCommandTask* const dispatchTask
  )
    : CCommandTask(dispatchTask)
    , mDispatchTask(dispatchTask)
    , mAssistTarget{}
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_AssistingCommander);
    }

    Unit* const creatorUnit = (mUnit != nullptr) ? mUnit->CreatorRef.ResolveObjectPtr<Unit>() : nullptr;
    mAssistTarget.ResetFromObject(creatorUnit);

    bool detachAssistTarget = true;
    Unit* const assistTarget = mAssistTarget.GetObjectPtr();
    if (assistTarget != nullptr) {
      detachAssistTarget = !assistTarget->IsInCategory("PODSTAGINGPLATFORM");
    }

    if (detachAssistTarget) {
      mAssistTarget.ResetFromObject(nullptr);
    }

    mTaskState = TASKSTATE_Waiting;
  }

  /**
   * Address: 0x0061D7D0 (FUN_0061D7D0, Moho::CUnitPodAssist::operator new)
   */
  CUnitPodAssist* CUnitPodAssist::Create(
    CCommandTask* const dispatchTask
  )
  {
    return new (std::nothrow) CUnitPodAssist(dispatchTask);
  }

  /**
   * Address: 0x0061D4F0 (FUN_0061D4F0, ??1CUnitPodAssist@Moho@@QAE@@Z)
   */
  CUnitPodAssist::~CUnitPodAssist()
  {
    Kill();
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_AssistingCommander);
    mAssistTarget.UnlinkFromOwnerChain();
  }

  int CUnitPodAssist::Execute()
  {
    return 1;
  }

  /**
   * Address: 0x0061D820 (FUN_0061D820, Moho::CUnitPodAssist::Kill)
   *
   * What it does:
   * Stops active pod-assist motion/transport work, rebinds expired assist
   * target weak-link to creator when needed, and returns this task to
   * preparing state.
   */
  void CUnitPodAssist::Kill()
  {
    if (mUnit->IsMobile()) {
      Unit* const creatorUnit = mUnit->GetCreator();
      if (creatorUnit == nullptr || creatorUnit->IsDead()) {
        mUnit->Kill(nullptr, "", 0.0f);
      } else {
        Unit* const assistTarget = mAssistTarget.GetObjectPtr();
        if (assistTarget == nullptr || assistTarget->IsDead()) {
          mAssistTarget.Set(creatorUnit);
        } else {
          if (mUnit->GetTransportedBy() == assistTarget) {
            IAiTransport* const targetTransport = assistTarget->AiTransport;
            if (targetTransport != nullptr) {
              (void)targetTransport->TransportDetachUnit(mUnit);
            }
          } else {
            IAiTransport* const targetTransport = assistTarget->AiTransport;
            if (targetTransport != nullptr) {
              targetTransport->TransportRemovePickupUnit(mUnit, true);
            }
          }
        }
      }

      if (mUnit->UnitMotion != nullptr) {
        mUnit->UnitMotion->Stop(nullptr);
        mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      mTaskState = TASKSTATE_Preparing;
    }
  }

  /**
   * Address: 0x0061D9C0 (FUN_0061D9C0, Moho::CUnitPodAssist::HasNextCommand)
   *
   * What it does:
   * Returns true when owner command queue has at least two entries and the
   * next entry resolves to a live command object.
   */
  bool CUnitPodAssist::HasNextCommand() const
  {
    const msvc8::vector<WeakPtr<CUnitCommand>>& commands = mUnit->CommandQueue->mCommandVec;
    if (commands.size() < 2u) {
      return false;
    }

    return commands[1].GetObjectPtr() != nullptr;
  }

  /**
   * Address: 0x0061DA00 (FUN_0061DA00)
   *
   * What it does:
   * For station-assist pod auto mode, scans nearby allied units in guard
   * radius, chooses the nearest eligible assist target, then dispatches
   * repair or reclaim follow-up work.
   */
  bool CUnitPodAssist::TryIssueNearbyAssistTask()
  {
    if (!mUnit->IsAutoMode()) {
      return false;
    }

    if (mUnit->IsInCategory("STATIONASSISTPOD") && ((mUnit->ScriptBitMask & 0x10u) != 0u)) {
      return false;
    }

    EntityGatherVector nearbyEntities{};
    GatherNearbyAssistEntities(mUnit, nearbyEntities);

    Unit* bestTargetUnit = nullptr;
    float bestDistanceSquared = std::numeric_limits<float>::infinity();
    for (Entity* const nearbyEntity : nearbyEntities) {
      Unit* const nearbyUnit = (nearbyEntity != nullptr) ? nearbyEntity->IsUnit() : nullptr;
      if (!IsEligibleNearbyAssistCandidate(mUnit, nearbyUnit)) {
        continue;
      }

      Unit* const distanceTarget = ResolveAssistDistanceTarget(nearbyUnit);
      if (distanceTarget == nullptr) {
        continue;
      }

      const float candidateDistanceSquared = DistanceSquared(mUnit->GetPosition(), distanceTarget->GetPosition());
      if (candidateDistanceSquared < bestDistanceSquared) {
        bestDistanceSquared = candidateDistanceSquared;
        bestTargetUnit = distanceTarget;
      }
    }

    if (bestTargetUnit == nullptr) {
      return false;
    }

    Kill();
    if (bestTargetUnit->AiSiloBuild != nullptr && bestTargetUnit->IsUnitState(UNITSTATE_SiloBuildingAmmo)) {
      DispatchRepairTask(this, bestTargetUnit, true);
      return true;
    }

    if (bestTargetUnit->IsUnitState(UNITSTATE_BeingReclaimed)) {
      DispatchReclaimTask(this, static_cast<Entity*>(bestTargetUnit));
      return true;
    }

    DispatchRepairTask(this, bestTargetUnit, false);
    return true;
  }

  /**
   * Address: 0x0061DE50 (FUN_0061DE50)
   *
   * What it does:
   * For non-station pod assist lanes, evaluates current assist-target/focus
   * state and dispatches repair or reclaim follow-up work when possible.
   */
  bool CUnitPodAssist::TryIssueFocusedAssistTask()
  {
    if (!mUnit->IsAutoMode()) {
      return false;
    }

    Unit* const assistTargetUnit = mAssistTarget.GetObjectPtr();
    if (assistTargetUnit == nullptr) {
      return false;
    }

    if (assistTargetUnit->IsUnitState(UNITSTATE_Enhancing)) {
      Kill();
      DispatchRepairTask(this, assistTargetUnit, false);
      return true;
    }

    Entity* const focusEntity = assistTargetUnit->GetFocusEntity();
    if (focusEntity == nullptr) {
      return false;
    }

    Unit* const focusUnit = focusEntity->IsUnit();
    if (focusUnit != nullptr && focusUnit->AiSiloBuild != nullptr && focusUnit->IsUnitState(UNITSTATE_SiloBuildingAmmo)) {
      Kill();
      DispatchRepairTask(this, focusUnit, true);
      return true;
    }

    if (assistTargetUnit->IsUnitState(UNITSTATE_Repairing) || assistTargetUnit->IsUnitState(UNITSTATE_Building)) {
      Kill();
      DispatchRepairTask(this, focusUnit, false);
      return true;
    }

    if (assistTargetUnit->IsUnitState(UNITSTATE_Reclaiming)) {
      Kill();
      DispatchReclaimTask(this, focusEntity);
      return true;
    }

    return false;
  }

  /**
   * Address: 0x0061E970 (FUN_0061E970, Moho::CUnitPodAssist::MemberDeserialize)
   *
   * What it does:
   * Reads CCommandTask base via cached `CCommandTask` RType, then reads
   * `mDispatchTask` (raw owned ptr) and `mAssistTarget` (WeakPtr<Unit>)
   * from the archive.
   */
  void CUnitPodAssist::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    const gpg::RRef baseRef{};
    archive->Read(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef ptrRef{};
    archive->ReadPointer_CCommandTask(&mDispatchTask, &ptrRef);

    const gpg::RRef weakRef{};
    archive->Read(CachedWeakPtrUnitType(), &mAssistTarget, weakRef);
  }

  /**
   * Address: 0x0061EA10 (FUN_0061EA10, Moho::CUnitPodAssist::MemberSerialize)
   *
   * What it does:
   * Writes CCommandTask base via cached RType, then writes `mDispatchTask`
   * as an UNOWNED raw pointer ref, then writes `mAssistTarget` weak ref.
   */
  void CUnitPodAssist::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    const gpg::RRef baseRef{};
    archive->Write(CachedCCommandTaskType(), const_cast<CUnitPodAssist*>(this), baseRef);

    gpg::RRef ptrRef{};
    (void)gpg::RRef_CCommandTask(&ptrRef, mDispatchTask);
    gpg::WriteRawPointer(archive, ptrRef, gpg::TrackedPointerState::Unowned, baseRef);

    const gpg::RRef weakRef{};
    archive->Write(CachedWeakPtrUnitType(), const_cast<WeakPtr<Unit>*>(&mAssistTarget), weakRef);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061E7C0 (FUN_0061E7C0, gpg::RRef_CUnitPodAssist)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitPodAssist*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitPodAssist(gpg::RRef* const outRef, moho::CUnitPodAssist* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitPodAssistType());
    return outRef;
  }
} // namespace gpg
