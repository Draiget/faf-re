#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/entity/ECollisionBeamEvent.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/WeakObject.h"
#include "moho/projectile/EProjectileImpactEvent.h"
#include "moho/task/CTask.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

namespace moho
{
  template <class TEvent>
  class ManyToOneListener;

  template <>
  class ManyToOneListener<EProjectileImpactEvent> : public WeakObject
  {
  public:
    virtual int HandleProjectileImpactListenerState(int action) = 0;

  public:
    static gpg::RType* sType;
  };

  template <>
  class ManyToOneListener<ECollisionBeamEvent> : public WeakObject
  {
  public:
    virtual int HandleCollisionBeamListenerState(int action) = 0;

  public:
    static gpg::RType* sType;
  };

  using ManyToOneListener_EProjectileImpactEvent = ManyToOneListener<EProjectileImpactEvent>;
  using ManyToOneListener_ECollisionBeamEvent = ManyToOneListener<ECollisionBeamEvent>;

  /**
   * VFTABLE: 0x00E1E86C
   * COL: 0x00E75F24
   */
  class CAcquireTargetTask
    : public CTask
    , public ManyToOneListener_EProjectileImpactEvent
    , public ManyToOneListener_ECollisionBeamEvent
    , public InstanceCounter<CAcquireTargetTask>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x005D8A20 (??0CAcquireTargetTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the task, both listener lanes, and the weapon/attacker state
     * tracked by the acquire-target scheduler.
     */
    CAcquireTargetTask(UnitWeapon* weapon, CAiAttackerImpl* attacker);

    /**
     * Address: 0x005D88D0 (FUN_005D88D0, Moho::CAcquireTargetTask::dtr)
     * Slot: 0
     */
    ~CAcquireTargetTask() override;

    /**
     * Address: 0x005D8D10 (FUN_005D8D10, Moho::CAcquireTargetTask::TaskTick)
     * Slot: 1
     *
     * What it does:
     * Advances target acquisition for the bound weapon and attacker.
     */
    int Execute() override;

    /**
     * Address: 0x005D97F0 (FUN_005D97F0, listener callback lane)
     *
     * What it does:
     * Clears the projectile-impact listener state when the listener lane is
     * detached or reset.
     */
    int HandleProjectileImpactListenerState(int action);

    /**
     * Address: 0x005D9830 (FUN_005D9830, listener callback lane)
     *
     * What it does:
     * Clears the collision-beam listener state when the listener lane is
     * detached or reset.
     */
    int HandleCollisionBeamListenerState(int action);

    /**
     * Address: 0x005E16A0 (FUN_005E16A0, Moho::CAcquireTargetTask::MemberDeserialize)
     *
     * What it does:
     * Loads the reflected base task, weapon pointer, attacker pointer, owning
     * unit, and task-side recovery lanes from archive storage.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CAcquireTargetTask* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E1750 (FUN_005E1750, Moho::CAcquireTargetTask::MemberSerialize)
     *
     * What it does:
     * Saves the reflected base task, weapon pointer, attacker pointer, owning
     * unit, and task-side recovery lanes to archive storage.
     */
    static void MemberSerialize(
      gpg::WriteArchive* archive,
      const CAcquireTargetTask* task,
      int version,
      gpg::RRef* ownerRef
    );

    /**
     * Address: 0x005D8C40 (FUN_005D8C40, Moho::CAcquireTargetTask::CheckAutoInitiate)
     *
     * What it does:
     * Evaluates whether the current command queue state should auto-initiate a
     * target-change action.
     */
    bool CheckAutoInitiate() const;

  public:
    UnitWeapon* mWeapon;           // 0x28
    CAiAttackerImpl* mAttacker;    // 0x2C
    Unit* mUnit;                   // 0x30
    std::int32_t mTargetCooldown;  // 0x34
    std::uint8_t mUpdateAttackerState; // 0x38
    std::uint8_t mPad39[3]{};
  };

  static_assert(sizeof(ManyToOneListener_EProjectileImpactEvent) == 0x08, "ManyToOneListener<EProjectileImpactEvent> size must be 0x08");
  static_assert(sizeof(ManyToOneListener_ECollisionBeamEvent) == 0x08, "ManyToOneListener<ECollisionBeamEvent> size must be 0x08");
  static_assert(sizeof(CAcquireTargetTask) == 0x3C, "CAcquireTargetTask size must be 0x3C");
  static_assert(offsetof(CAcquireTargetTask, mWeapon) == 0x28, "CAcquireTargetTask::mWeapon offset must be 0x28");
  static_assert(offsetof(CAcquireTargetTask, mAttacker) == 0x2C, "CAcquireTargetTask::mAttacker offset must be 0x2C");
  static_assert(offsetof(CAcquireTargetTask, mUnit) == 0x30, "CAcquireTargetTask::mUnit offset must be 0x30");
  static_assert(
    offsetof(CAcquireTargetTask, mTargetCooldown) == 0x34, "CAcquireTargetTask::mTargetCooldown offset must be 0x34"
  );
  static_assert(
    offsetof(CAcquireTargetTask, mUpdateAttackerState) == 0x38,
    "CAcquireTargetTask::mUpdateAttackerState offset must be 0x38"
  );
} // namespace moho
