#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Carrier-landing task lane used by transport pickup/load flow.
   */
  class CUnitCarrierLand : public CCommandTask
  {
  public:
    /**
     * Address: 0x00607B50 (FUN_00607B50, Moho::CUnitCarrierLandTypeInfo::NewRef)
     * Address: 0x00607C30 (FUN_00607C30, Moho::CUnitCarrierLandTypeInfo::CtrRef)
     *
     * What it does:
     * Default-constructs an unbound carrier-land task for the reflection /
     * deserialization path. The binary inlines this constructor into both
     * `NewRef` and `CtrRef`, which is why it carries their addresses rather
     * than one of its own.
     */
    CUnitCarrierLand();

    /**
     * Address: 0x00606500 (FUN_00606500, ??0CUnitCarrierLand@Moho@@QAE@@Z)
     *
     * IDA signature:
     * Moho::CUnitCarrierLand *__thiscall Moho::CUnitCarrierLand::CUnitCarrierLand(
     *     Moho::CCommandTask *parentTask, Moho::CUnitCarrierLand *this, int carrier);
     *
     * What it does:
     * Starts a carrier landing for `parentTask`'s unit: links the target
     * carrier weak pointer, zeroes the reservation payload, raises
     * `UNITSTATE_TransportLoading` on the unit, and points the unit's focus
     * entity at the carrier (which fires `OnAssignedFocusEntity`).
     */
    CUnitCarrierLand(CCommandTask* parentTask, Unit* carrier);

    /**
     * Address: 0x006067A0 (FUN_006067A0, ?TaskTick@CUnitCarrierLand@Moho@@UAE?AW4ETaskStatus@2@XZ)
     *
     * IDA signature:
     * int __thiscall Moho::CUnitCarrierLand::TaskTick(Moho::CUnitCarrierLand *this);
     *
     * What it does:
     * Runs the carrier-landing state machine: reserve a bay, fly to the
     * standoff point the reservation names, wait out the carrier's surfacing,
     * descend onto the attach point, and hand the unit to the carrier's
     * storage.
     */
    int Execute() override;

    /**
     * Address: 0x00606610 (FUN_00606610, Moho::CUnitCarrierLand::~CUnitCarrierLand)
     *
     * What it does:
     * Aborts an in-progress carrier landing (clears carrier motion/state,
     * releases the focus-entity link, resets the flyer to climb, clears the
     * target carrier's transport reservation) before base teardown.
     */
    ~CUnitCarrierLand() override;

    /**
     * Address: 0x006086C0 (FUN_006086C0, Moho::CUnitCarrierLand::MemberDeserialize)
     *
     * What it does:
     * Deserializes base command-task state, target transport weak pointer, and
     * carrier-landing reservation payload lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00608800 (FUN_00608800, Moho::CUnitCarrierLand::MemberSerialize)
     *
     * What it does:
     * Serializes base command-task state, target transport weak pointer, and
     * carrier-landing reservation payload lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    WeakPtr<Unit> mTargetCarrier;      // +0x30
    bool mHasLoadedIntoCarrier;        // +0x38
    std::uint8_t mPad39_3B[0x03];      // +0x39
    std::int32_t mReservationResult;   // +0x3C
    float mCarrierHeight;              // +0x40
    Wm3::Vector3f mCarrierAttachPos;   // +0x44
    Wm3::Vector3f mCarrierAttachDir;   // +0x50
    Wm3::Vector3f mCarrierApproachPos; // +0x5C
  };

  static_assert(sizeof(CUnitCarrierLand) == 0x68, "CUnitCarrierLand size must be 0x68");
  static_assert(offsetof(CUnitCarrierLand, mTargetCarrier) == 0x30, "CUnitCarrierLand::mTargetCarrier offset must be 0x30");
  static_assert(
    offsetof(CUnitCarrierLand, mHasLoadedIntoCarrier) == 0x38,
    "CUnitCarrierLand::mHasLoadedIntoCarrier offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitCarrierLand, mReservationResult) == 0x3C,
    "CUnitCarrierLand::mReservationResult offset must be 0x3C"
  );
  static_assert(offsetof(CUnitCarrierLand, mCarrierHeight) == 0x40, "CUnitCarrierLand::mCarrierHeight offset must be 0x40");
  static_assert(
    offsetof(CUnitCarrierLand, mCarrierAttachPos) == 0x44,
    "CUnitCarrierLand::mCarrierAttachPos offset must be 0x44"
  );
  static_assert(
    offsetof(CUnitCarrierLand, mCarrierAttachDir) == 0x50,
    "CUnitCarrierLand::mCarrierAttachDir offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitCarrierLand, mCarrierApproachPos) == 0x5C,
    "CUnitCarrierLand::mCarrierApproachPos offset must be 0x5C"
  );
} // namespace moho

