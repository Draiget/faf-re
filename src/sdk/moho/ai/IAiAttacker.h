#pragma once

#include <cstddef>

#include "moho/unit/Broadcaster.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  class RType;
} // namespace gpg

namespace gpg::core
{
  template <class T, std::size_t N>
  class FastVectorN;
} // namespace gpg::core

namespace moho
{
  class CAcquireTargetTask;
  class CAiTarget;
  class CollisionBeamEntity;
  class CTaskStage;
  class Entity;
  class Projectile;
  class Unit;
  class UnitWeapon;
  struct RUnitBlueprintWeapon;
  struct SWeakRefSlot;

  /**
   * RTTI: `Broadcaster<EAiAttackerEvent>` at +0x04, the ring the attack and
   * melee tasks subscribe to.
   */
  class IAiAttacker : public Broadcaster<EAiAttackerEvent>
  {
  public:
    /**
     * Address: 0x005D6A80 (FUN_005D6A80)
     *
     * What it does:
     * Installs the interface vtable; the `Broadcaster` base self-links the
     * listener ring.
     */
    IAiAttacker();

    /**
     * Address: 0x005D5780 (FUN_005D5780)
     * Address: 0x005D56D0 (FUN_005D56D0)
     *
     * What it does:
     * Unlinks the listener ring (the base's destructor) and, in the deleting
     * form, frees the object.
     */
    virtual ~IAiAttacker();

    // Slots 1..28 are `_purecall` in the interface vtable (0x00E1E7C4) and
    // resolve to `CAiAttackerImpl`'s overrides (0x00E1E9CC), the only
    // implementation; names and signatures are that class's.
    virtual void WeaponsOnDestroy() = 0;                                              // slot 1
    virtual Unit* GetUnit() = 0;                                                      // slot 2
    virtual bool WeaponsBusy() = 0;                                                   // slot 3
    virtual CTaskStage* GetTaskStage() = 0;                                           // slot 4
    virtual UnitWeapon* CreateWeapon(RUnitBlueprintWeapon* weaponBlueprint) = 0;      // slot 5
    virtual int GetWeaponCount() = 0;                                                 // slot 6
    virtual UnitWeapon* GetWeapon(int index) = 0;                                     // slot 7
    virtual void SetDesiredTarget(CAiTarget* target) = 0;                             // slot 8
    virtual CAiTarget* GetDesiredTarget() = 0;                                        // slot 9
    virtual void OnWeaponHaltFire() = 0;                                              // slot 10
    virtual bool CanAttackTarget(CAiTarget* target) = 0;                              // slot 11
    virtual bool PickTarget(Entity* targetEntity) = 0;                                // slot 12
    virtual Entity* FindBestEnemy(
      UnitWeapon* weapon,
      gpg::core::FastVectorN<SWeakRefSlot, 20>* blipsInRange,
      float maxRange,
      bool use3DDistance
    ) = 0;                                                                            // slot 13
    virtual UnitWeapon* GetTargetWeapon(CAiTarget* target) = 0;                       // slot 14
    virtual UnitWeapon* GetPrimaryWeapon() = 0;                                       // slot 15
    virtual float GetMaxWeaponRange() = 0;                                            // slot 16
    virtual bool VectorIsWithinWeaponAttackRange(UnitWeapon* weapon, const Wm3::Vector3f* targetPos) = 0; // slot 17
    virtual bool VectorIsWithinAttackRange(const Wm3::Vector3f* targetPos) = 0;       // slot 18
    virtual bool TargetIsWithinWeaponAttackRange(UnitWeapon* weapon, CAiTarget* target) = 0; // slot 19
    virtual bool TargetIsWithinAttackRange(CAiTarget* target) = 0;                    // slot 20
    virtual bool IsTooClose(CAiTarget* target) = 0;                                   // slot 21
    virtual bool IsTargetExempt(Entity* target) = 0;                                  // slot 22
    virtual CAiTarget* HasSlavedTarget(UnitWeapon** outWeapon) = 0;                   // slot 23
    virtual void ResetReportingState() = 0;                                           // slot 24
    virtual void TransmitProjectileImpactEvent(UnitWeapon* weapon, Projectile* projectile) = 0; // slot 25
    virtual void TransmitBeamImpactEvent(UnitWeapon* weapon, CollisionBeamEntity* beam) = 0;    // slot 26
    virtual void ForceEngage(Entity* target) = 0;                                     // slot 27
    virtual void PushStack(LuaPlus::LuaState* luaState) = 0;                          // slot 28

  public:
    static gpg::RType* sType;
  };

  static_assert(offsetof(IAiAttacker, mListeners) == 0x04, "IAiAttacker::mListeners offset must be 0x04");
  static_assert(sizeof(IAiAttacker) == 0x0C, "IAiAttacker size must be 0x0C");

  /**
   * Address: 0x005DF860 (FUN_005DF860, preregister_RBroadcasterRType_EAiAttackerEvent)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `Broadcaster<EAiAttackerEvent>`.
   */
  [[nodiscard]] gpg::RType* preregister_RBroadcasterRType_EAiAttackerEvent();

  /**
   * Address: 0x00BCEAA0 (FUN_00BCEAA0, sub_BCEAA0)
   *
   * What it does:
   * Registers the broadcaster reflection lane for `EAiAttackerEvent` and
   * installs process-exit cleanup.
   */
  void register_RBroadcasterRType_EAiAttackerEvent();

  /**
   * Address: 0x00BCEAC0 (FUN_00BCEAC0, register_RListenerRType_EAiAttackerEvent)
   *
   * What it does:
   * Registers the listener reflection lane for `EAiAttackerEvent` and installs
   * process-exit cleanup.
   */
  void register_RListenerRType_EAiAttackerEvent();

  /**
   * Address: 0x005DF920 (FUN_005DF920, preregister_RVectorType_UnitWeaponPtr)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `msvc8::vector<moho::UnitWeapon*>`.
   */
  [[nodiscard]] gpg::RType* preregister_RVectorType_UnitWeaponPtr();

  /**
   * Address: 0x005DF990 (FUN_005DF990, preregister_RVectorType_CAcquireTargetTaskPtr)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `msvc8::vector<moho::CAcquireTargetTask*>`.
   */
  [[nodiscard]] gpg::RType* preregister_RVectorType_CAcquireTargetTaskPtr();

  /**
   * Address: 0x00BCEAE0 (FUN_00BCEAE0, sub_BCEAE0)
   *
   * What it does:
   * Registers `msvc8::vector<UnitWeapon*>` reflection metadata and installs
   * process-exit cleanup.
   */
  void register_RVectorType_UnitWeaponPtr();

  /**
   * Address: 0x00BCEB00 (FUN_00BCEB00, sub_BCEB00)
   *
   * What it does:
   * Registers `msvc8::vector<CAcquireTargetTask*>` reflection metadata and
   * installs process-exit cleanup.
   */
  void register_RVectorType_CAcquireTargetTaskPtr();
} // namespace moho
