#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/CAiTarget.h"
#include "moho/task/CTask.h"

namespace moho
{
  class Unit;
  class UnitWeapon;

  class CFireWeaponTask : public CTask
  {
  public:
    /**
     * Address: 0x006D3C50 (FUN_006D3C50, default construction body)
     *
     * What it does:
     * Initializes a reflected fire-task object with null unit/weapon lanes.
     */
    CFireWeaponTask();

    /**
     * Address: 0x006D3D40 (FUN_006D3D40, unit-weapon construction body)
     *
     * What it does:
     * Binds this task to a unit weapon, captures its owning unit, and resets
     * the fire clock.
     */
    explicit CFireWeaponTask(UnitWeapon* weapon);

    /**
     * Address: 0x006D3CF0 (FUN_006D3CF0, non-deleting body)
     *
     * What it does:
     * Decrements the fire-task instance counter before base-task teardown.
     */
    ~CFireWeaponTask() override;

    /**
     * Address: 0x006D3DC0 (FUN_006D3DC0, ?Execute@CFireWeaponTask@Moho@@UAEHXZ)
     *
     * What it does:
     * Services weapon-fire cooldown, checks target/weapon gates, and triggers
     * a weapon fire when the task is ready.
     */
    int Execute() override;

    /**
     * Address: 0x006DF270 (FUN_006DF270, MemberDeserialize)
     *
     * What it does:
     * Loads the reflected base task, weapon pointer, unit pointer, and fire
     * clock from archive storage.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CFireWeaponTask* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DF300 (FUN_006DF300, MemberSerialize)
     *
     * What it does:
     * Saves the reflected base task, weapon pointer, unit pointer, and fire
     * clock into archive storage.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, const CFireWeaponTask* task, int version, gpg::RRef* ownerRef);

  public:
    std::uint32_t mReserved18;
    Unit* mUnit;            // 0x1C
    UnitWeapon* mWeapon;    // 0x20
    std::int32_t mFireClock; // 0x24
  };

  static_assert(sizeof(CFireWeaponTask) == 0x28, "CFireWeaponTask size must be 0x28");
  static_assert(offsetof(CFireWeaponTask, mReserved18) == 0x18, "CFireWeaponTask::mReserved18 offset must be 0x18");
  static_assert(offsetof(CFireWeaponTask, mUnit) == 0x1C, "CFireWeaponTask::mUnit offset must be 0x1C");
  static_assert(offsetof(CFireWeaponTask, mWeapon) == 0x20, "CFireWeaponTask::mWeapon offset must be 0x20");
  static_assert(offsetof(CFireWeaponTask, mFireClock) == 0x24, "CFireWeaponTask::mFireClock offset must be 0x24");
} // namespace moho
