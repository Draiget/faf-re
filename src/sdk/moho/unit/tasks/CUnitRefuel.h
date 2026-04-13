#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class IAiCommandDispatchImpl;
  class Unit;

  /**
   * Command task lane used to drive unit refuel behavior.
   */
  class CUnitRefuel : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00620F50 (FUN_00620F50, ??0CUnitRefuel@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes refuel task target weak-link lane, marks owner unit with
     * `UNITSTATE_Refueling`, recomputes movement speed-through state, and
     * caches whether the target is a `CARRIER` category unit.
     */
    CUnitRefuel(Unit* targetUnit, IAiCommandDispatchImpl* dispatchTask);

    /**
     * Address: 0x00621060 (FUN_00621060, ??1CUnitRefuel@Moho@@QAE@@Z)
     *
     * What it does:
     * Clears refuel/speed-through state bits, releases any active transport
     * pickup reservation lane, finalizes carrier reservation reset, and reports
     * successful command completion.
     */
    ~CUnitRefuel() override;

    /**
     * Address: 0x00622680 (FUN_00622680, Moho::CUnitRefuel::MemberDeserialize)
     *
     * What it does:
     * Loads `CCommandTask` base state, then deserializes target-unit weak link
     * and both refuel task runtime flags from the archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00622710 (FUN_00622710, Moho::CUnitRefuel::MemberSerialize)
     *
     * What it does:
     * Saves `CCommandTask` base state, then serializes target-unit weak link
     * and both refuel task runtime flags into the archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    int Execute() override;

  public:
    WeakPtr<Unit> mTargetUnit;          // 0x30
    bool mHasTransportReservation;      // 0x38
    bool mIsCarrier;                    // 0x39
    std::uint8_t mPad3A[0x02];          // 0x3A
  };

  static_assert(sizeof(CUnitRefuel) == 0x3C, "CUnitRefuel size must be 0x3C");
  static_assert(offsetof(CUnitRefuel, mTargetUnit) == 0x30, "CUnitRefuel::mTargetUnit offset must be 0x30");
  static_assert(
    offsetof(CUnitRefuel, mHasTransportReservation) == 0x38,
    "CUnitRefuel::mHasTransportReservation offset must be 0x38"
  );
  static_assert(offsetof(CUnitRefuel, mIsCarrier) == 0x39, "CUnitRefuel::mIsCarrier offset must be 0x39");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006224D0 (FUN_006224D0, gpg::RRef_CUnitRefuel)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitRefuel*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitRefuel(gpg::RRef* outRef, moho::CUnitRefuel* value);
} // namespace gpg
