#include "moho/unit/tasks/CUnitPodAssist.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
#include "moho/containers/SCoordsVec2.h"
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
#include "moho/unit/tasks/CUnitReclaimTask.h"
#include "moho/unit/tasks/CUnitRepairTask.h"

namespace
{
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

  // The attach approach aims ten ticks of host motion ahead of the bone, so a
  // pod chasing a moving host converges instead of trailing it.
  constexpr float kAttachApproachLeadTicks = 10.0f;
  // Distance at which the pod counts as having reached the bone.
  constexpr float kAttachContactDistance = 0.5f;

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
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
    (void)moho::CUnitRepairTask::Allocate(AsDispatchImpl(task->mDispatchTask), targetUnit, isSiloBuild);
  }

  void DispatchReclaimTask(moho::CUnitPodAssist* const task, moho::Entity* const targetEntity)
  {
    moho::CAiTarget target{};
    (void)target.UpdateTarget(targetEntity);
    IssueReclaimTask(task->mDispatchTask, target);
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

    // A neighbour that is already being reclaimed is not a candidate at all in
    // the binary -- the whole selection block sits inside its `!BeingReclaimed`
    // guard. Such a unit can still become the chosen target indirectly, by
    // being some other candidate's focus entity.
    if (candidateUnit->IsUnitState(moho::UNITSTATE_BeingReclaimed)) {
      return false;
    }

    if (ownerUnit->ArmyRef == nullptr || candidateUnit->SimulationRef == nullptr || candidateUnit->SimulationRef->mMapData == nullptr) {
      return false;
    }

    if (!candidateUnit->SimulationRef->mMapData->IsWithin(candidateUnit->mVarDat.mCurTransform.pos_, 1.0f, ownerUnit->ArmyRef->UseWholeMap())) {
      return false;
    }

    if (candidateUnit->mVarDat.mCurTransform.pos_ != candidateUnit->mVarDat.mLastTransform.pos_) {
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
      if (!candidateUnit->IsBeingBuilt() && candidateUnit->mVarDat.mHealth >= candidateUnit->mVarDat.mMaxHealth) {
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

  /**
   * Sphere query over the owner's guard-scan radius, matching the binary's
   * `COGrid::ForAllEntitiesIterator` call rather than an axis-aligned
   * approximation of it.
   */
  void GatherNearbyAssistUnits(moho::Unit* const ownerUnit, gpg::core::FastVectorN<moho::CollisionResult, 10>& outHits)
  {
    if (ownerUnit == nullptr || ownerUnit->SimulationRef == nullptr || ownerUnit->SimulationRef->mOGrid == nullptr) {
      return;
    }

    const moho::RUnitBlueprint* const blueprint = ownerUnit->GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    Wm3::Sphere3f scanSphere{};
    scanSphere.Center = ownerUnit->GetPosition();
    scanSphere.Radius = blueprint->AI.GuardScanRadius;

    ownerUnit->SimulationRef->mOGrid->ForAllEntitiesIterator(outHits, moho::ENTITYTYPE_Unit, scanSphere);
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
   * Address: 0x0061E5EA-0x0061E5F9, inlined into
   * `CUnitPodAssistTypeInfo::NewRef` (0x0061E5B0) and its `CtrRef` sibling:
   * the object is 0x3C bytes and only the dispatch lane at +0x30 and the
   * assist link at +0x34 are written.
   *
   * What it does:
   * Default-constructs one task for the reflection factory.
   */
  CUnitPodAssist::CUnitPodAssist()
  {
    mDispatchTask = nullptr;
    mAssistTarget = WeakPtr<Unit>{};
  }

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
      mUnit->mUnitVarDat.mUnitStates |= (1ull << UNITSTATE_AssistingCommander);
    }

    Unit* const creatorUnit = (mUnit != nullptr) ? mUnit->CreatorRef.GetObjectPtr() : nullptr;
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
   * Address: 0x0061D580 (FUN_0061D580, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   */
  CUnitPodAssist::~CUnitPodAssist()
  {
    Kill();
    mUnit->mUnitVarDat.mUnitStates &= ~(1ull << UNITSTATE_AssistingCommander);
    mAssistTarget.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0061E020 (FUN_0061E020, Moho::CUnitPodAssist::TaskTick)
   *
   * IDA signature:
   * int __thiscall Moho::CUnitPodAssist::TaskTick(Moho::CUnitPodAssist *this);
   *
   * What it does:
   * Each tick, first tries to hand the pod some assist work; failing that,
   * runs the four-step docking sequence that returns the pod to its host —
   * claim a pickup slot, fly to the attach bone (leading the host's motion),
   * and attach.
   */
  int CUnitPodAssist::Execute()
  {
    Unit* const unit = mUnit;
    if (unit->IsDead() || unit->DestroyQueued()) {
      return -1;
    }

    // A mobile pod needs a live host with transport AI to dock into; a static
    // one (a build pod welded to its factory) has no host to check.
    Unit* host = nullptr;
    if (unit->IsMobile()) {
      host = mAssistTarget.GetObjectPtr();
      if (host == nullptr || host->IsDead() || host->AiTransport == nullptr) {
        return -1;
      }
    }

    // Another command is already queued behind this one: let it through.
    if (HasNextCommand()) {
      return -1;
    }

    if (unit->IsInCategory("STATIONASSISTPOD")) {
      if (!unit->IsMobile()) {
        // Welded pods never dock; they only ever look for work.
        (void)TryIssueNearbyAssistTask();
        return 1;
      }

      if (mTaskState != TASKSTATE_Preparing && TryIssueNearbyAssistTask()) {
        return 1;
      }
    } else if (mTaskState != TASKSTATE_Preparing && TryIssueFocusedAssistTask()) {
      return 1;
    }

    switch (mTaskState) {
    case TASKSTATE_Preparing:
      mTaskState = NextTaskState(mTaskState);
      return 3;

    case TASKSTATE_Waiting: {
      // Ask the host for a pickup slot for this one pod.
      EntitySetTemplate<Unit> pickupSet{};
      (void)pickupSet.Add(unit);

      if (!host->AiTransport->TransportAssignSlot(unit, -1)) {
        mAssistTarget.UnlinkFromOwnerChain();
        return -1;
      }

      const Wm3::Vec3f& hostPos = host->GetPosition();
      host->AiTransport->TransportAddPickupUnits(pickupSet, SCoordsVec2{hostPos.x, hostPos.z});
      mTaskState = NextTaskState(mTaskState);
      return 0;
    }

    case TASKSTATE_Starting: {
      IAiTransport* const transport = host->AiTransport;

      // Steer at where the attach bone will be, not where it is: the host may
      // be moving, so the bone position is led by ten ticks of its velocity.
      const Wm3::Vec3f attachPos = transport->TransportGetAttachBonePosition(unit);
      const Wm3::Vec3f hostVelocity = host->GetVelocity();
      const Wm3::Vec3f leadPos{
        attachPos.x + (hostVelocity.x * kAttachApproachLeadTicks),
        attachPos.y + (hostVelocity.y * kAttachApproachLeadTicks),
        attachPos.z + (hostVelocity.z * kAttachApproachLeadTicks)
      };
      const Wm3::Vec3f attachFacing = transport->TransportGetAttachFacing(unit);

      unit->UnitMotion->SetTarget(leadPos, attachFacing, LAYER_Land);
      unit->UnitMotion->mHeight = attachPos.y;

      // Keep flying until the pod is on the bone (or has settled onto land).
      const Wm3::Vec3f& unitPos = unit->GetPosition();
      const float distanceToBone = std::sqrt(DistanceSquared(attachPos, unitPos));
      if (distanceToBone >= kAttachContactDistance && unit->mVarDat.mLayerMask != LAYER_Land) {
        return 1;
      }

      mTaskState = NextTaskState(mTaskState);
      return 0;
    }

    case TASKSTATE_Processing:
      // On the bone: hand the pod to the host and release the height hold.
      host->AiTransport->TransportAttachUnit(unit);
      unit->UnitMotion->SetFacing(Wm3::Vec3f{0.0f, 0.0f, 0.0f});
      unit->UnitMotion->mHeight = gpg::pInf;
      mTaskState = NextTaskState(mTaskState);
      return 1;

    case TASKSTATE_Complete:
      // Docked. Idle here until something gives the pod new work.
      return 10;

    default:
      return 1;
    }
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
        mUnit->UnitMotion->mHeight = gpg::pInf;
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

    if (mUnit->IsInCategory("STATIONASSISTPOD") && ((mUnit->mUnitVarDat.mScriptbits & 0x10u) != 0u)) {
      return false;
    }

    gpg::core::FastVectorN<CollisionResult, 10> nearbyHits{};
    GatherNearbyAssistUnits(mUnit, nearbyHits);

    Unit* bestTargetUnit = nullptr;
    float bestDistanceSquared = gpg::pInf;
    for (const CollisionResult* hit = nearbyHits.start_; hit != nearbyHits.end_; ++hit) {
      Unit* const nearbyUnit = (hit->sourceEntity != nullptr) ? hit->sourceEntity->IsUnit() : nullptr;
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
    archive->ReadPointer(&mDispatchTask, &ptrRef);

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

namespace moho
{
} // namespace moho

namespace
{
} // namespace

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

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CUnitPodAssist>`, vtable 0x00E20838.
   *
   * Address: 0x00BD1590 (FUN_00BD1590 -- constructs the global and registers its destructor.)
   * Address: 0x00BFA260 (FUN_00BFA260 -- the global's destructor.)
   * Address: 0x0061E500 (FUN_0061E500 -- `Init`.)
   * Address: 0x0061D720 (FUN_0061D720 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0061D730 (FUN_0061D730 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CUnitPodAssistSerializer : gpg::SerSaveLoadHelper<CUnitPodAssist>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B1B34 -- process-global `CUnitPodAssistSerializer` singleton.
  moho::CUnitPodAssistSerializer gCUnitPodAssistSerializer;
} // namespace
