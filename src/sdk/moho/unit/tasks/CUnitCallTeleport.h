#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Quaternion.h"

namespace moho
{
  class Unit;
  class VTransform;

  class CUnitCallTeleport : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    CUnitCallTeleport() = default;

    /**
     * Address: 0x00600E90 (FUN_00600E90, ??0CUnitCallTeleport@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes a teleport-call task using parent dispatch context, binds a
     * weak target-unit link, clears runtime flags, and sets the teleport state
     * bit on the owning unit.
     */
    CUnitCallTeleport(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x00600EF0 (FUN_00600EF0, Moho::CUnitCallTeleport::~CUnitCallTeleport)
     *
     * What it does:
     * Clears call-teleport state flags on the owner unit, removes transport
     * waiting/pickup links when needed, publishes dispatch result, and unlinks
     * the weak transport-unit lane.
     */
    ~CUnitCallTeleport() override;

    /**
     * Address: 0x00603CD0 (FUN_00603CD0)
     *
     * What it does:
     * Loads base command-task state plus teleport-task weak-unit and status
     * flags from archive data.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00603D60 (FUN_00603D60)
     *
     * What it does:
     * Saves base command-task state plus teleport-task weak-unit and status
     * flags into archive data.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, const CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006013D0 (FUN_006013D0, Moho::CUnitCallTeleport::TaskTick)
     *
     * What it does:
     * Runs teleport-call state transitions between pickup staging, attach
     * movement, and teleport-task spawn while keeping O-grid occupancy state.
     */
    int Execute() override;

  private:
    /**
     * Address: 0x005E2340 (FUN_005E2340, CUnitCallTeleport::BuildGroundTeleportTarget)
     *
     * What it does:
     * Builds one ground-target payload from world position, clears entity-link
     * lanes, and resets target-point/mobile flags.
     */
    [[nodiscard]] static CAiTarget BuildGroundTeleportTarget(const Wm3::Vector3f& worldPos) noexcept;

  public:
    WeakPtr<Unit> mTargetTransportUnit; // 0x30
    bool mCompletedSuccessfully;         // 0x38
    bool mIsOccupying;                  // 0x39
    std::uint8_t mPadding3A[2];         // 0x3A
  };

  static_assert(sizeof(CUnitCallTeleport) == 0x3C, "CUnitCallTeleport size must be 0x3C");
  static_assert(
    offsetof(CUnitCallTeleport, mTargetTransportUnit) == 0x30,
    "CUnitCallTeleport::mTargetTransportUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mCompletedSuccessfully) == 0x38,
    "CUnitCallTeleport::mCompletedSuccessfully offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mIsOccupying) == 0x39,
    "CUnitCallTeleport::mIsOccupying offset must be 0x39"
  );

  class CUnitTeleportTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x0060AB20 (FUN_0060AB20, Moho::CUnitTeleportTask::CUnitTeleportTask)
     *
     * What it does:
     * Initializes one teleport execution task with copied target payload,
     * weak-linked beacon lane, and source orientation snapshot.
     */
    CUnitTeleportTask(
      CCommandTask* parentTask,
      const CAiTarget& target,
      Unit* teleportBeaconUnit,
      const VTransform& sourceTransform
    );

    /**
     * Address: 0x0060AEC0 (FUN_0060AEC0, Moho::CUnitTeleportTask::~CUnitTeleportTask)
     *
     * What it does:
     * Clears unit teleport state, publishes dispatch result, restores motion
     * collision processing, and unlinks beacon/target weak references.
     */
    ~CUnitTeleportTask() override;

    /**
     * Address: 0x0060AAC0 (FUN_0060AAC0, Moho::CUnitTeleportTask::operator new)
     *
     * What it does:
     * Allocates one teleport execution task and forwards constructor arguments
     * into in-place construction.
     */
    static CUnitTeleportTask* Create(
      CAiTarget* target,
      CCommandTask* parentTask,
      Unit* teleportBeaconUnit,
      const VTransform* sourceTransform
    );

    /**
     * Address: 0x0060AC00 (FUN_0060AC00, Moho::CUnitTeleportTask::TaskTick)
     *
     * What it does:
     * Runs teleport execution state transitions, validating beacon readiness,
     * reserving teleport placement viability, and dispatching script callback
     * payloads for teleport application.
     */
    int Execute() override;

  public:
    CAiTarget mTarget;              // 0x30
    WeakPtr<Unit> mTeleportBeaconUnit; // 0x50
    Wm3::Quaternionf mOrientation;  // 0x58
  };

  static_assert(sizeof(CUnitTeleportTask) == 0x68, "CUnitTeleportTask size must be 0x68");
  static_assert(offsetof(CUnitTeleportTask, mTarget) == 0x30, "CUnitTeleportTask::mTarget offset must be 0x30");
  static_assert(
    offsetof(CUnitTeleportTask, mTeleportBeaconUnit) == 0x50,
    "CUnitTeleportTask::mTeleportBeaconUnit offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitTeleportTask, mOrientation) == 0x58,
    "CUnitTeleportTask::mOrientation offset must be 0x58"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00603530 (FUN_00603530, gpg::RRef_CUnitCallTeleport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTeleport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTeleport(gpg::RRef* outRef, moho::CUnitCallTeleport* value);
} // namespace gpg
