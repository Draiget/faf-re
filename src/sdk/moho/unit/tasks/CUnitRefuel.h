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
     * Address: 0x00620F30 (FUN_00620F30, ??0CUnitRefuel@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds one default refuel-task lane with null target and cleared
     * reservation/carrier flags.
     */
    CUnitRefuel();

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

    /**
     * Address: 0x00621490 (FUN_00621490, ?TaskTick@CUnitRefuel@Moho@@UAE?AW4ETaskStatus@2@XZ)
     *
     * IDA signature:
     * int __thiscall Moho::CUnitRefuel::TaskTick(Moho::CUnitRefuel *this);
     *
     * What it does:
     * Runs the refuel/rearm state machine that flies the owning unit onto an
     * air staging platform (or into a carrier's storage bay), holds it there
     * while fuel and health refill, and releases it again. Aborts (returns -1)
     * whenever the owner or the platform dies, the platform is moving up or
     * down, the platform stops being idle, or the platform submerges — the
     * submerged case being the only abort that detaches an already-attached
     * unit first.
     */
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
