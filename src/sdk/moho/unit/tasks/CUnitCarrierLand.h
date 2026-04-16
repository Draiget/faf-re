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

