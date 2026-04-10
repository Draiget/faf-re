#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

#include <cmath>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskTaskPending = 0x0000000000000100ull;
  constexpr std::uint64_t kUnitStateMaskForceSpeedThrough = 0x0000000100000000ull;
  constexpr std::uint64_t kUnitStateMaskAirStagingPending = 0x0000000800000000ull;

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

  [[nodiscard]] bool IsValidVector3f(const Wm3::Vector3f& value) noexcept
  {
    return std::isfinite(value.x) && std::isfinite(value.y) && std::isfinite(value.z);
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
} // namespace gpg
