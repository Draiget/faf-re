#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/SFootprint.h"
#include "moho/math/Vector3f.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  // Air-staging-call uses four 64-bit state-vector lanes on the owning unit:
  //   bit  7  (0x0000000000000080) = UNITSTATE_WaitingForTransport
  //   bit  8  (0x0000000000000100) = UNITSTATE_TransportLoading
  //   bit 32  (0x0000000100000000) = UNITSTATE_ForceSpeedThrough
  //   bit 35  (0x0000000800000000) = UNITSTATE_LandingOnPlatform
  // The ctor and Execute() previously referred to bit 8 as `TaskPending` and
  // bit 35 as `AirStagingPending`; the canonical enum names are kept as the
  // primary constants below to match the rest of the unit-task subsystem.
  constexpr std::uint64_t kUnitStateMaskWaitingForTransport = 0x0000000000000080ull;
  constexpr std::uint64_t kUnitStateMaskTransportLoading = 0x0000000000000100ull;
  constexpr std::uint64_t kUnitStateMaskForceSpeedThrough = 0x0000000100000000ull;
  constexpr std::uint64_t kUnitStateMaskLandingOnPlatform = 0x0000000800000000ull;
  // Back-compat aliases retained for unchanged ctor/Execute() bodies.
  constexpr std::uint64_t kUnitStateMaskTaskPending = kUnitStateMaskTransportLoading;
  constexpr std::uint64_t kUnitStateMaskAirStagingPending = kUnitStateMaskLandingOnPlatform;

  [[nodiscard]] gpg::RType* CachedCUnitCallAirStagingPlatformType()
  {
    gpg::RType* type = moho::CUnitCallAirStagingPlatform::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallAirStagingPlatform));
      moho::CUnitCallAirStagingPlatform::sType = type;
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
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return cached;
  }

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] moho::SOCellPos ToCellPos(const Wm3::Vector3f& position, const moho::SFootprint& footprint) noexcept
  {
    moho::SOCellPos cell{};
    cell.x = static_cast<std::int16_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    cell.z = static_cast<std::int16_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return cell;
  }

  [[nodiscard]] moho::SNavGoal BuildSingleCellGoal(const moho::SOCellPos& cell, const moho::ELayer layer) noexcept
  {
    moho::SNavGoal goal{};
    goal.minX = static_cast<std::int32_t>(cell.x);
    goal.minZ = static_cast<std::int32_t>(cell.z);
    goal.maxX = static_cast<std::int32_t>(cell.x) + 1;
    goal.maxZ = static_cast<std::int32_t>(cell.z) + 1;
    goal.aux0 = 0;
    goal.aux1 = 0;
    goal.aux2 = 0;
    goal.aux3 = 0;
    goal.mLayer = layer;
    return goal;
  }

  void QueueMoveGoal(moho::CCommandTask* const ownerTask, const moho::SNavGoal& goal)
  {
    moho::NewMoveTask(goal, ownerTask, 0, nullptr, 0);
  }

  [[nodiscard]] bool CommandHeadsMatch(moho::Unit* const a, moho::Unit* const b)
  {
    const moho::CUnitCommand* const aHead = (a && a->CommandQueue) ? a->CommandQueue->GetCurrentCommand() : nullptr;
    const moho::CUnitCommand* const bHead = (b && b->CommandQueue) ? b->CommandQueue->GetCurrentCommand() : nullptr;
    return aHead == bHead;
  }

  [[nodiscard]] bool HasLandingAirUnit(const moho::CUnitCommand* const command)
  {
    if (!command) {
      return false;
    }

    for (moho::CScriptObject* const entry : command->mUnitSet.mVec) {
      if (!moho::SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      moho::Unit* const candidate = moho::SCommandUnitSet::UnitFromEntry(entry);
      if (!candidate || !candidate->mIsAir) {
        continue;
      }

      if (candidate->IsInCategory("AIRSTAGINGPLATFORM")) {
        continue;
      }

      if (candidate->IsUnitState(moho::UNITSTATE_LandingOnPlatform)) {
        return true;
      }
    }

    return false;
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
  gpg::RType* CUnitCallAirStagingPlatform::sType = nullptr;

  /**
   * Address: 0x00601E00 (FUN_00601E00, Moho::CUnitCallAirStagingPlatform::TaskTick)
   *
   * What it does:
   * Runs the air-staging call task state machine, steering the owner unit to
   * pickup/attach goals and finalizing transport attach completion.
   */
  int CUnitCallAirStagingPlatform::Execute()
  {
    Unit* const unit = mUnit;
    if (!unit || unit->IsDead()) {
      return -1;
    }

    Unit* const platformUnit = mPlatform.GetObjectPtr();
    if (!platformUnit || platformUnit->IsDead()) {
      return -1;
    }

    if (platformUnit->mCurrentLayer == LAYER_Seabed) {
      return -1;
    }

    if (mTaskState != TASKSTATE_Preparing && !platformUnit->IsUnitState(UNITSTATE_TransportLoading)) {
      return -1;
    }

    switch (mTaskState) {
    case TASKSTATE_Preparing:
      if (!platformUnit->IsUnitState(UNITSTATE_TransportLoading)) {
        return 10;
      }
      if (!CommandHeadsMatch(platformUnit, unit)) {
        return 10;
      }
      mTaskState = NextTaskState(mTaskState);
      return 3;

    case TASKSTATE_Waiting: {
      IAiTransport* const transport = platformUnit->AiTransport;
      if (!transport) {
        return -1;
      }

      if (transport->TransportIsUnitAssignedForPickup(unit)) {
        unit->UnitStateMask &= ~kUnitStateMaskForceSpeedThrough;
        if (transport->TransportIsReadyForUnit(unit)) {
          mTaskState = NextTaskState(mTaskState);
        }
        return 1;
      }

      if (platformUnit->IsInCategory("CARRIER")) {
        return -1;
      }

      unit->UnitStateMask |= kUnitStateMaskForceSpeedThrough;
      const SOCellPos goalCell = ToCellPos(platformUnit->GetPosition(), unit->GetFootprint());
      const SNavGoal goal = BuildSingleCellGoal(goalCell, LAYER_Air);
      QueueMoveGoal(this, goal);
      return 10;
    }

    case TASKSTATE_Starting: {
      IAiTransport* const transport = platformUnit->AiTransport;
      if (!transport) {
        return -1;
      }

      const Wm3::Vector3f attachPosition = transport->TransportGetAttachBonePosition(unit);
      const Wm3::Vector3f attachFacing = transport->TransportGetAttachFacing(unit);
      if (!IsValidVector3f(attachPosition)) {
        return -1;
      }

      const SOCellPos goalCell = ToCellPos(attachPosition, unit->GetFootprint());
      const SNavGoal goal = BuildSingleCellGoal(goalCell, LAYER_Land);
      QueueMoveGoal(this, goal);
      mTaskState = NextTaskState(mTaskState);

      if (unit->UnitMotion) {
        unit->UnitMotion->mHeight = attachPosition.y;
        unit->UnitMotion->SetFacing(attachFacing);
      }
      return 1;
    }

    case TASKSTATE_Processing: {
      IAiTransport* const transport = platformUnit->AiTransport;
      if (!transport) {
        return -1;
      }

      if (transport->TransportAttachUnit(unit)) {
        mDone = true;
      }
      mTaskState = NextTaskState(mTaskState);
      unit->UnitStateMask &= ~kUnitStateMaskAirStagingPending;
      return 1;
    }

    case TASKSTATE_Complete: {
      CUnitCommandQueue* const queue = unit->CommandQueue;
      if (!queue || !queue->GetNextCommand()) {
        return -1;
      }

      const CUnitCommand* const currentCommand = queue->GetCurrentCommand();
      if (!HasLandingAirUnit(currentCommand)) {
        return -1;
      }

      const SOCellPos goalCell = ToCellPos(platformUnit->GetPosition(), unit->GetFootprint());
      const SNavGoal goal = BuildSingleCellGoal(goalCell, LAYER_None);

      unit->UnitStateMask |= kUnitStateMaskForceSpeedThrough;
      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->SetSpeedThroughGoal(true);
        navigator->SetGoal(goal);
      }
      return 10;
    }

    default:
      return 1;
    }
  }

  /**
   * Address: 0x006018E0 (FUN_006018E0, ??0CUnitCallAirStagingPlatform@Moho@@QAE@@Z)
   */
  CUnitCallAirStagingPlatform::CUnitCallAirStagingPlatform(CCommandTask* const parentTask, Unit* const platformUnit)
    : CCommandTask(parentTask)
  {
    mPlatform.BindObjectUnlinked(platformUnit);
    (void)mPlatform.LinkIntoOwnerChainHeadUnlinked();
    mDone = false;

    if (mUnit) {
      mUnit->UnitStateMask |= kUnitStateMaskTaskPending;
      mUnit->UnitStateMask |= kUnitStateMaskAirStagingPending;
    }
  }

  /**
   * Address: 0x00601950 (FUN_00601950, ??1CUnitCallAirStagingPlatform@Moho@@QAE@@Z)
   * Address: 0x00601AA0 (FUN_00601AA0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * IDA signature:
   * void __thiscall Moho::CUnitCallAirStagingPlatform::~CUnitCallAirStagingPlatform(
   *     Moho::CUnitCallAirStagingPlatform *this);
   *
   * What it does:
   * Tears down one air-staging call task. Clears the four owner-unit state
   * lanes the task owns (`ForceSpeedThrough`, `LandingOnPlatform`,
   * `TransportLoading`, `WaitingForTransport`); if the attach handshake did
   * not complete (`!mDone`), restores `UnitMotion::mHeight` to positive
   * infinity and asks the still-living platform's transport interface to drop
   * the unit's pickup reservation; finalises the dispatch result lane (1 on
   * success, 2 on cancellation); unlinks the platform weak-pointer slot from
   * the platform Unit's intrusive weak-link chain; the base `CCommandTask`
   * destructor runs implicitly via the standard C++ teardown chain.
   */
  CUnitCallAirStagingPlatform::~CUnitCallAirStagingPlatform()
  {
    // Drop the four state-mask lanes the air-staging-call task owns on the
    // owning unit (the binary clears these unconditionally before any further
    // checks; `mUnit` is non-null on a constructed task — the ctor stores
    // through it -- so the explicit guard is omitted).
    mUnit->UnitStateMask &= ~kUnitStateMaskForceSpeedThrough;
    mUnit->UnitStateMask &= ~kUnitStateMaskLandingOnPlatform;
    mUnit->UnitStateMask &= ~kUnitStateMaskTransportLoading;
    mUnit->UnitStateMask &= ~kUnitStateMaskWaitingForTransport;

    if (!mDone) {
      // Cancellation path: the platform never finished the load handshake.
      // Float the unit back to the configured ceiling and ask the platform
      // transport to drop our pickup reservation (the binary's "+0x55C ==
      // AiTransport" load and slot-5 `TransportRemovePickupUnit(unit, true)`
      // dispatch). The `IsDead()` guard avoids dispatching through a stale
      // vtable when the platform was destroyed mid-flight.
      if (CUnitMotion* const unitMotion = mUnit->UnitMotion; unitMotion != nullptr) {
        unitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      if (Unit* const platformUnit = mPlatform.GetObjectPtr();
          platformUnit != nullptr && platformUnit->AiTransport != nullptr && !platformUnit->IsDead()) {
        platformUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    // Dispatch result: success (mDone) writes 1, cancellation writes 2. The
    // binary computes `*mDispatchResult = 2 - mDone` literally; the typed
    // form preserves the cast through `EAiResult` for the same width.
    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mDone));

    // Detach the platform weak-pointer slot from the platform Unit's
    // intrusive weak-link chain. The binary inlines the chain walk; the
    // recovered helper performs the same find-and-relink in one call.
    mPlatform.UnlinkFromOwnerChain();

    // ~CCommandTask runs implicitly here.
  }

  /**
   * Address: 0x00603DF0 (FUN_00603DF0)
   *
   * What it does:
   * Loads base command-task state plus air-staging platform weak pointer and
   * completion flag from archive data.
   */
  void CUnitCallAirStagingPlatform::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CUnitCallAirStagingPlatform* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(task), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &task->mPlatform, nullOwner);
    archive->ReadBool(&task->mDone);
  }

  /**
   * Address: 0x00603E80 (FUN_00603E80)
   *
   * What it does:
   * Saves base command-task state plus air-staging platform weak pointer and
   * completion flag into archive data.
   */
  void CUnitCallAirStagingPlatform::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallAirStagingPlatform* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(task), nullOwner);
    archive->Write(CachedWeakPtrUnitType(), &task->mPlatform, nullOwner);
    archive->WriteBool(task->mDone);
  }

  /**
   * Address: 0x00602F80 (FUN_00602F80)
   *
   * What it does:
   * Preserves one deserialize callback thunk lane for call-air-staging task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallAirStagingPlatformMemberDeserializeAdapterLaneA(
    gpg::ReadArchive* const archive,
    CUnitCallAirStagingPlatform* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00602F90 (FUN_00602F90)
   *
   * What it does:
   * Preserves one serialize callback thunk lane for call-air-staging task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallAirStagingPlatformMemberSerializeAdapterLaneA(
    gpg::WriteArchive* const archive,
    const CUnitCallAirStagingPlatform* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x006031B0 (FUN_006031B0)
   *
   * What it does:
   * Alternate deserialize callback thunk lane for call-air-staging task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallAirStagingPlatformMemberDeserializeAdapterLaneB(
    gpg::ReadArchive* const archive,
    CUnitCallAirStagingPlatform* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x006031C0 (FUN_006031C0)
   *
   * What it does:
   * Alternate serialize callback thunk lane for call-air-staging task serializer
   * registration.
   */
  [[maybe_unused]] void CUnitCallAirStagingPlatformMemberSerializeAdapterLaneB(
    gpg::WriteArchive* const archive,
    const CUnitCallAirStagingPlatform* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberSerialize(archive, task, version, ownerRef);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006036E0 (FUN_006036E0, gpg::RRef_CUnitCallAirStagingPlatform)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallAirStagingPlatform*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallAirStagingPlatform(
    gpg::RRef* const outRef,
    moho::CUnitCallAirStagingPlatform* const value
  )
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallAirStagingPlatformType());
    return outRef;
  }

  /**
   * Address: 0x00603030 (FUN_00603030)
   *
   * What it does:
   * Materializes one `RRef_CUnitCallAirStagingPlatform` result into a stack
   * local and copies that pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* StoreRRefCUnitCallAirStagingPlatformAdapter(
    moho::CUnitCallAirStagingPlatform* const value,
    gpg::RRef* const outRef
  )
  {
    gpg::RRef temp{};
    (void)RRef_CUnitCallAirStagingPlatform(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }
} // namespace gpg
