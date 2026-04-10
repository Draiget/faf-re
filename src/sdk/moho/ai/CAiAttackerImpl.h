// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"
#include "wm3/Vector3.h"

#include <cstddef>
#include <cstdint>

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace gpg::core
{
  template <class T, std::size_t N>
  class FastVectorN;
}

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  struct SWeakRefSlot;
  struct WeaponExtraRefSubobject;
  struct RUnitBlueprintWeapon;
  class CAiTarget;
  class CollisionBeamEntity;
  class CScrLuaInitForm;
  class CTaskStage;
  class Entity;
  class Projectile;
  class Unit;
  class UnitWeapon;

  /**
   * VFTABLE: 0x00E1E9CC
   * COL:  0x00E75AF8
   */
  class CAiAttackerImpl
  {
  public:
    /**
     * Address: 0x005D6A60
     * Slot: 0
     * Demangled: public: __thiscall Moho::CAiAttackerImpl::~CAiAttackerImpl()
     */
    virtual ~CAiAttackerImpl();

    /**
     * Address: 0x005D6D30
     * Slot: 1
     * Demangled: Moho::CAiAttackerImpl::WeaponsOnDestroy
     */
    virtual void WeaponsOnDestroy();

    /**
     * Address: 0x005D5D60
     * Slot: 2
     * Demangled: Moho::CAiAttackerImpl::GetUnit
     */
    virtual Unit* GetUnit();

    /**
     * Address: 0x005D6D80
     * Slot: 3
     * Demangled: Moho::CAiAttackerImpl::WeaponsBusy
     */
    virtual bool WeaponsBusy();

    /**
     * Address: 0x005D5D80
     * Slot: 4
     * Demangled: Moho::CAiAttackerImpl::GetTaskStage
     */
    virtual CTaskStage* GetTaskStage();

    /**
     * Address: 0x005D76E0
     * Slot: 5
     * Demangled: Moho::CAiAttackerImpl::CreateWeapon
     */
    virtual UnitWeapon* CreateWeapon(RUnitBlueprintWeapon* weaponBlueprint);

    /**
     * Address: 0x005D5D90
     * Slot: 6
     * Demangled: Moho::CAiAttackerImpl::GetWeaponCount
     */
    virtual int GetWeaponCount();

    /**
     * Address: 0x005D77D0
     * Slot: 7
     * Demangled: Moho::CAiAttackerImpl::GetWeapon
     */
    virtual UnitWeapon* GetWeapon(int index);

    /**
     * Address: 0x005D75B0
     * Slot: 8
     * Demangled: Moho::CAiAttackerImpl::SetDesiredTarget
     */
    virtual void SetDesiredTarget(CAiTarget* target);

    /**
     * Address: 0x005D5D70
     * Slot: 9
     * Demangled: Moho::CAiAttackerImpl::GetDesiredTarget
     */
    virtual CAiTarget* GetDesiredTarget();

    /**
     * Address: 0x005D7570
     * Slot: 10
     * Demangled: Moho::CAiAttackerImpl::OnWeaponHaltFire
     */
    virtual void OnWeaponHaltFire();

    /**
     * Address: 0x005D6FA0
     * Slot: 11
     * Demangled: Moho::CAiAttackerImpl::CanAttackTarget
     */
    virtual bool CanAttackTarget(CAiTarget* target);

    /**
     * Address: 0x005D6F40
     * Slot: 12
     * Demangled: Moho::CAiAttackerImpl::PickTarget
     */
    virtual bool PickTarget(Entity* targetEntity);

    /**
     * Address: 0x005D7A10
     * Slot: 13
     * Demangled: Moho::CAiAttackerImpl::FindBestEnemy
     */
    virtual Entity*
    FindBestEnemy(
      UnitWeapon* weapon,
      gpg::core::FastVectorN<SWeakRefSlot, 20>* blipsInRange,
      float maxRange,
      bool use3DDistance
    );

    /**
     * Address: 0x005D6DC0
     * Slot: 14
     * Demangled: Moho::CAiAttackerImpl::GetTargetWeapon
     */
    virtual UnitWeapon* GetTargetWeapon(CAiTarget* target);

    /**
     * Address: 0x005D6E30
     * Slot: 15
     * Demangled: Moho::CAiAttackerImpl::GetPrimaryWeapon
     */
    virtual UnitWeapon* GetPrimaryWeapon();

    /**
     * Address: 0x005D6E80
     * Slot: 16
     * Demangled: Moho::CAiAttackerImpl::GetMaxWeaponRange
     */
    virtual float GetMaxWeaponRange();

    /**
     * Address: 0x005D7190
     * Slot: 17
     * Demangled: Moho::CAiAttackerImpl::VectorIsWithinWeaponAttackRange
     */
    virtual bool VectorIsWithinWeaponAttackRange(UnitWeapon* weapon, const Wm3::Vector3f* targetPos);

    /**
     * Address: 0x005D70E0
     * Slot: 18
     * Demangled: Moho::CAiAttackerImpl::VectorIsWithinAttackRange
     */
    virtual bool VectorIsWithinAttackRange(const Wm3::Vector3f* targetPos);

    /**
     * Address: 0x005D7090
     * Slot: 19
     * Demangled: Moho::CAiAttackerImpl::TargetIsWithinWeaponAttackRange
     */
    virtual bool TargetIsWithinWeaponAttackRange(UnitWeapon* weapon, CAiTarget* target);

    /**
     * Address: 0x005D7000
     * Slot: 20
     * Demangled: Moho::CAiAttackerImpl::TargetIsWithinAttackRange
     */
    virtual bool TargetIsWithinAttackRange(CAiTarget* target);

    /**
     * Address: 0x005D7210
     * Slot: 21
     * Demangled: Moho::CAiAttackerImpl::IsTooClose
     */
    virtual bool IsTooClose(CAiTarget* target);

    /**
     * Address: 0x005D7340
     * Slot: 22
     * Demangled: Moho::CAiAttackerImpl::IsTargetExempt
     */
    virtual bool IsTargetExempt(Entity* target);

    /**
     * Address: 0x005D72B0
     * Slot: 23
     * Demangled: Moho::CAiAttackerImpl::HasSlavedTarget
     */
    virtual CAiTarget* HasSlavedTarget(UnitWeapon** outWeapon);

    /**
     * Address: 0x005D5DB0
     * Slot: 24
     * Demangled: Moho::CAiAttackerImpl::ResetReportingState
     */
    virtual void ResetReportingState();

    /**
     * Address: 0x005D7800
     * Slot: 25
     * Demangled: Moho::CAiAttackerImpl::TransmitProjectileImpactEvent
     */
    virtual void TransmitProjectileImpactEvent(UnitWeapon* weapon, Projectile* projectile);

    /**
     * Address: 0x005D7870
     * Slot: 26
     * Demangled: Moho::CAiAttackerImpl::TransmitBeamImpactEvent
     */
    virtual void TransmitBeamImpactEvent(UnitWeapon* weapon, CollisionBeamEntity* beam);

    /**
     * Address: 0x005D8650
     * Slot: 27
     * Demangled: Moho::CAiAttackerImpl::ForceEngage
     */
    virtual void ForceEngage(Entity* target);

    /**
     * Address: 0x005D5DC0
     * Slot: 28
     * Demangled: Moho::CAiAttackerImpl::PushStack
     */
    virtual void PushStack(LuaPlus::LuaState* luaState);

  public:
    /**
     * Address: 0x005D56F0 (FUN_005D56F0, CAiAttackerImpl::Stop)
     *
     * What it does:
     * Applies a null/clear desired-target payload to the attacker and unlinks
     * the temporary weak-target node from owner chain state.
     */
    void Stop();

    /**
     * Address: 0x005E13B0 (FUN_005E13B0, Moho::CAiAttackerImpl::MemberDeserialize)
     *
     * What it does:
     * Loads the serialized attacker state lanes and repopulates owned pointer
     * vectors.
     */
    static void MemberDeserialize(CAiAttackerImpl* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x005E1520 (FUN_005E1520, Moho::CAiAttackerImpl::MemberSerialize)
     *
     * What it does:
     * Saves attacker base, pointer-vector, stage/thread, desired-target, and
     * reporting-state lanes.
     */
    static void MemberSerialize(const CAiAttackerImpl* object, gpg::WriteArchive* archive);

    /**
     * Address: 0x005D85B0 (FUN_005D85B0, Moho::CAiAttackerImpl::DeserializePointerVectors)
     *
     * What it does:
     * Loads owned `UnitWeapon*` and `CAcquireTargetTask*` pointer vectors.
     */
    static void DeserializePointerVectors(gpg::ReadArchive* archive, CAiAttackerImpl* object);

    /**
     * Address: 0x005D84E0 (FUN_005D84E0, Moho::CAiAttackerImpl::SerializePointerVectors)
     *
     * What it does:
     * Saves owned `UnitWeapon*` and `CAcquireTargetTask*` pointer vectors.
     */
    static void SerializePointerVectors(gpg::WriteArchive* archive, const CAiAttackerImpl* object);

    struct WeaponExtraData
    {
      std::int32_t key;
      WeaponExtraRefSubobject* ref;
    };

    /**
     * Reads key/ref payload used by Unit::GetExtraData from weapon emitter entry.
     */
    [[nodiscard]] bool TryGetWeaponExtraData(int index, WeaponExtraData& out) const;

    /**
     * Decodes packed value from a weapon extra-data ref (returns 0xF0000000 when missing).
     */
    [[nodiscard]] static std::int32_t ReadExtraDataValue(const WeaponExtraRefSubobject* ref);
  };

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  /**
   * Address: 0x005D9950 (FUN_005D9950, func_CAiAttackerImplGetUnit_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetUnit_LuaFuncDef();
  /**
   * Address: 0x005D9A90 (FUN_005D9A90, func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef();
  /**
   * Address: 0x005D9BD0 (FUN_005D9BD0, func_CAiAttackerImplGetWeaponCount_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetWeaponCount_LuaFuncDef();
  /**
   * Address: 0x005D9D20 (FUN_005D9D20, func_CAiAttackerImplSetDesiredTarget_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplSetDesiredTarget_LuaFuncDef();
  /**
   * Address: 0x005D9EC0 (FUN_005D9EC0, func_CAiAttackerImplGetDesiredTarget_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetDesiredTarget_LuaFuncDef();
  /**
   * Address: 0x005DA020 (FUN_005DA020, func_CAiAttackerImplStop_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplStop_LuaFuncDef();
  /**
   * Address: 0x005DA150 (FUN_005DA150, func_CAiAttackerImplCanAttackTarget_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplCanAttackTarget_LuaFuncDef();
  /**
   * Address: 0x005DA300 (FUN_005DA300, func_CAiAttackerImplFindBestEnemy_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplFindBestEnemy_LuaFuncDef();
  /**
   * Address: 0x005DA4B0 (FUN_005DA4B0, func_CAiAttackerImplGetTargetWeapon_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetTargetWeapon_LuaFuncDef();
  /**
   * Address: 0x005DA670 (FUN_005DA670, func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef();
  /**
   * Address: 0x005DA7C0 (FUN_005DA7C0, func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef();
  CScrLuaInitForm* func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef();
  /**
   * Address: 0x005DAD00 (FUN_005DAD00, func_CAiAttackerImplIsTooClose_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplIsTooClose_LuaFuncDef();
  /**
   * Address: 0x005DAEB0 (FUN_005DAEB0, func_CAiAttackerImplIsTargetExempt_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplIsTargetExempt_LuaFuncDef();
  /**
   * Address: 0x005DB030 (FUN_005DB030, func_CAiAttackerImplHasSlavedTarget_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplHasSlavedTarget_LuaFuncDef();
  /**
   * Address: 0x005DB1C0 (FUN_005DB1C0, func_CAiAttackerImplResetReportingState_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplResetReportingState_LuaFuncDef();
  /**
   * Address: 0x005DB2F0 (FUN_005DB2F0, func_CAiAttackerImplForceEngage_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiAttackerImplForceEngage_LuaFuncDef();

  /**
   * Address: 0x00BCE970 (FUN_00BCE970, register_CAiAttackerImplLuaInitFormAnchor)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links it to recovered
   * attacker-Lua anchor lane `off_F599F0`.
   */
  CScrLuaInitForm* register_CAiAttackerImplLuaInitFormAnchor();

  /**
   * Address: 0x00BCE990 (FUN_00BCE990, register_CAiAttackerImplGetUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetUnit_LuaFuncDef();

  /**
   * Address: 0x00BCE9A0 (FUN_00BCE9A0, register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef();

  /**
   * Address: 0x00BCE9B0 (FUN_00BCE9B0, register_CAiAttackerImplGetWeaponCount_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetWeaponCount_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetWeaponCount_LuaFuncDef();

  /**
   * Address: 0x00BCE9C0 (FUN_00BCE9C0, register_CAiAttackerImplSetDesiredTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplSetDesiredTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplSetDesiredTarget_LuaFuncDef();

  /**
   * Address: 0x00BCE9D0 (FUN_00BCE9D0, register_CAiAttackerImplGetDesiredTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetDesiredTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetDesiredTarget_LuaFuncDef();

  /**
   * Address: 0x00BCE9E0 (FUN_00BCE9E0, register_CAiAttackerImplStop_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplStop_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplStop_LuaFuncDef();

  /**
   * Address: 0x00BCE9F0 (FUN_00BCE9F0, register_CAiAttackerImplCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplCanAttackTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplCanAttackTarget_LuaFuncDef();

  /**
   * Address: 0x00BCEA00 (FUN_00BCEA00, register_CAiAttackerImplFindBestEnemy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplFindBestEnemy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplFindBestEnemy_LuaFuncDef();

  /**
   * Address: 0x00BCEA10 (FUN_00BCEA10, register_CAiAttackerImplGetTargetWeapon_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetTargetWeapon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetTargetWeapon_LuaFuncDef();

  /**
   * Address: 0x00BCEA20 (FUN_00BCEA20, register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef();

  /**
   * Address: 0x00BCEA30 (FUN_00BCEA30, register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef();

  /**
   * Address: 0x00BCEA40 (FUN_00BCEA40, register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef();

  /**
   * Address: 0x00BCEA50 (FUN_00BCEA50, register_CAiAttackerImplIsTooClose_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplIsTooClose_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplIsTooClose_LuaFuncDef();

  /**
   * Address: 0x00BCEA60 (FUN_00BCEA60, register_CAiAttackerImplIsTargetExempt_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplIsTargetExempt_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplIsTargetExempt_LuaFuncDef();

  /**
   * Address: 0x00BCEA70 (FUN_00BCEA70, register_CAiAttackerImplHasSlavedTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplHasSlavedTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplHasSlavedTarget_LuaFuncDef();

  /**
   * Address: 0x00BCEA80 (FUN_00BCEA80, register_CAiAttackerImplResetReportingState_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplResetReportingState_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplResetReportingState_LuaFuncDef();

  /**
   * Address: 0x00BCEA90 (FUN_00BCEA90, register_CAiAttackerImplForceEngage_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiAttackerImplForceEngage_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiAttackerImplForceEngage_LuaFuncDef();

  /**
   * Address: 0x00BCEB20 (FUN_00BCEB20, register_CScrLuaMetatableFactory_CAiAttackerImpl_Index)
   *
   * What it does:
   * Allocates and stores the recovered startup Lua factory index lane for
   * `CScrLuaMetatableFactory<CAiAttackerImpl>`.
   */
  int register_CScrLuaMetatableFactory_CAiAttackerImpl_Index();

  /**
   * VFTABLE: 0x00E1EB3C
   * COL:  0x00E75600
   */
  using CAiAttackerImplGetUnit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB44
   * COL:  0x00E755B0
   */
  using CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB4C
   * COL:  0x00E75560
   */
  using CAiAttackerImplGetWeaponCount_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB54
   * COL:  0x00E75510
   */
  using CAiAttackerImplSetDesiredTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB5C
   * COL:  0x00E754C0
   */
  using CAiAttackerImplGetDesiredTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB64
   * COL:  0x00E75470
   */
  using CAiAttackerImplStop_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB6C
   * COL:  0x00E75420
   */
  using CAiAttackerImplCanAttackTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB74
   * COL:  0x00E753D0
   */
  using CAiAttackerImplFindBestEnemy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB7C
   * COL:  0x00E75380
   */
  using CAiAttackerImplGetTargetWeapon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB84
   * COL:  0x00E75330
   */
  using CAiAttackerImplGetPrimaryWeapon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB8C
   * COL:  0x00E752E0
   */
  using CAiAttackerImplGetMaxWeaponRange_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB94
   * COL:  0x00E75290
   */
  using CAiAttackerImplIsWithinAttackRange_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EB9C
   * COL:  0x00E75240
   */
  using CAiAttackerImplIsTooClose_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EBA4
   * COL:  0x00E751F0
   */
  using CAiAttackerImplIsTargetExempt_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EBAC
   * COL:  0x00E751A0
   */
  using CAiAttackerImplHasSlavedTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EBB4
   * COL:  0x00E75150
   */
  using CAiAttackerImplResetReportingState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1EBBC
   * COL:  0x00E75100
   */
  using CAiAttackerImplForceEngage_LuaFuncDef = ::moho::CScrLuaBinder;

} // namespace moho
