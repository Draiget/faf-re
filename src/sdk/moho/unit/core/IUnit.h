// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <cstdint>
#include <string>

#include "UnitAttributes.h"
#include "gpg/core/containers/String.h"
#include "moho/misc/WeakObject.h"
#include "wm3/Vector3.h"

namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  /**
   * Lexical/value mapping recovered from EUnitStateTypeInfo registration:
   * - sub_55BBD0 (ForgedAlliance.exe, 0x0055BBD0)
   */
  enum EUnitState : std::int32_t
  {
    UNITSTATE_None = 0,
    UNITSTATE_Immobile = 1,
    UNITSTATE_Moving = 2,
    UNITSTATE_Attacking = 3,
    UNITSTATE_Guarding = 4,
    UNITSTATE_Building = 5,
    UNITSTATE_Upgrading = 6,
    UNITSTATE_WaitingForTransport = 7,
    UNITSTATE_TransportLoading = 8,
    UNITSTATE_TransportUnloading = 9,
    UNITSTATE_MovingDown = 10,
    UNITSTATE_MovingUp = 11,
    UNITSTATE_Patrolling = 12,
    UNITSTATE_Busy = 13,
    UNITSTATE_Attached = 14,
    UNITSTATE_BeingReclaimed = 15,
    UNITSTATE_Repairing = 16,
    UNITSTATE_Diving = 17,
    UNITSTATE_Surfacing = 18,
    UNITSTATE_Teleporting = 19,
    UNITSTATE_Ferrying = 20,
    UNITSTATE_WaitForFerry = 21,
    UNITSTATE_AssistMoving = 22,
    UNITSTATE_PathFinding = 23,
    UNITSTATE_ProblemGettingToGoal = 24,
    UNITSTATE_NeedToTerminateTask = 25,
    UNITSTATE_Capturing = 26,
    UNITSTATE_BeingCaptured = 27,
    UNITSTATE_Reclaiming = 28,
    UNITSTATE_AssistingCommander = 29,
    UNITSTATE_Refueling = 30,
    UNITSTATE_GuardBusy = 31,
    UNITSTATE_ForceSpeedThrough = 32,
    UNITSTATE_UnSelectable = 33,
    UNITSTATE_DoNotTarget = 34,
    UNITSTATE_LandingOnPlatform = 35,
    UNITSTATE_CannotFindPlaceToLand = 36,
    UNITSTATE_BeingUpgraded = 37,
    UNITSTATE_Enhancing = 38,
    UNITSTATE_BeingBuilt = 39,
    UNITSTATE_NoReclaim = 40,
    UNITSTATE_NoCost = 41,
    UNITSTATE_BlockCommandQueue = 42,
    UNITSTATE_MakingAttackRun = 43,
    UNITSTATE_HoldingPattern = 44,
    UNITSTATE_SiloBuildingAmmo = 45,
  };
  enum ELayer : std::int32_t;
  typedef std::int32_t EntId;
  class IUnit;
  class RUnitBlueprint;
  class STIMap;
  class StatItem;
  class Unit;
  class UserUnit;
  class VTransform;
} // namespace moho

namespace moho
{
  /**
   * VFTABLE: 0x00E2A514
   * COL:  0x00E83F24
   */
  class IUnit : public WeakObject
  {
  public:
    /**
     * Address: 0x006A48C0
     * Slot: 0
     * Demangled: public: virtual class Unit const near * __thiscall IUnit::IsUnit(void)const
     */
    virtual Unit const* IsUnit() const;

    /**
     * Address: 0x006A48B0
     * Slot: 1
     * Demangled: public: virtual class Unit near * __thiscall IUnit::IsUnit(void)
     */
    virtual Unit* IsUnit();

    /**
     * Address: 0x006A48E0
     * Slot: 2
     * Demangled: public: virtual class UserUnit const near * __thiscall IUnit::IsUserUnit(void)const
     */
    virtual UserUnit const* IsUserUnit() const;

    /**
     * Address: 0x006A48D0
     * Slot: 3
     * Demangled: public: virtual class UserUnit near * __thiscall IUnit::IsUserUnit(void)
     */
    virtual UserUnit* IsUserUnit();

    /**
     * Address: 0x006A49A0
     * Slot: 4
     * Demangled: public: virtual class EntId __thiscall Unit::GetEntityId(void)const
     */
    virtual EntId GetEntityId() const = 0;

    /**
     * Address: 0x006A49B0
     * Slot: 5
     * Demangled: public: virtual class Wm3::Vec3f const near & __thiscall Unit::GetPosition(void)const
     */
    virtual Wm3::Vec3f const& GetPosition() const = 0;

    /**
     * Address: 0x006A49C0
     * Slot: 6
     * Demangled: public: virtual class VTransform const near & __thiscall Unit::GetTransform(void)const
     */
    virtual VTransform const& GetTransform() const = 0;

    /**
     * Address: 0x006A8B20
     * Slot: 7
     * Demangled: public: virtual class RUnitBlueprint const near * __thiscall Unit::GetBlueprint(void)const
     */
    virtual RUnitBlueprint const* GetBlueprint() const = 0;

    /**
     * Address: 0x006A49D0
     * Slot: 8
     * Demangled: public: virtual class LuaPlus::LuaObject __thiscall Unit::GetLuaObject(void)
     */
    virtual LuaPlus::LuaObject GetLuaObject() = 0;

    /**
     * Address: 0x006A8B30
     * Slot: 9
     * Demangled: public: virtual float __thiscall Unit::CalcTransportLoadFactor(void)const
     */
    virtual float CalcTransportLoadFactor() const = 0;

    /**
     * Address: 0x006A49F0
     * Slot: 10
     * Demangled: public: virtual bool __thiscall Unit::IsDead(void)const
     */
    virtual bool IsDead() const = 0;

    /**
     * Address: 0x006A4A00
     * Slot: 11
     * Demangled: public: virtual bool __thiscall Unit::DestroyQueued(void)const
     */
    virtual bool DestroyQueued() const = 0;

    /**
     * Address: 0x006A4A10
     * Slot: 12
     * Demangled: public: virtual bool __thiscall Unit::IsMobile(void)const
     */
    virtual bool IsMobile() const = 0;

    /**
     * Address: 0x006A4A20
     * Slot: 13
     * Demangled: public: virtual bool __thiscall Unit::IsBeingBuilt(void)const
     */
    virtual bool IsBeingBuilt() const = 0;

    /**
     * Address: 0x006A7DC0
     * Slot: 14
     * Demangled: public: virtual bool __thiscall Unit::IsNavigatorIdle(void)const
     */
    virtual bool IsNavigatorIdle() const = 0;

    /**
     * Address: 0x006A4AF0
     * Slot: 15
     * Demangled: public: virtual bool __thiscall Unit::IsUnitState(enum EUnitState)const
     */
    virtual bool IsUnitState(EUnitState) const = 0;

    /**
     * Address: 0x006A4990
     * Slot: 16
     * Demangled: public: virtual struct UnitAttributes near & __thiscall Unit::GetAttributes(void)
     */
    virtual UnitAttributes& GetAttributes() = 0;

    /**
     * Address: 0x006A4980
     * Slot: 17
     * Demangled: public: virtual struct UnitAttributes const near & __thiscall Unit::GetAttributes(void)const
     */
    virtual UnitAttributes const& GetAttributes() const = 0;

    /**
     * Address: 0x006A4B90
     * Slot: 18
     * Demangled: public: virtual class StatItem near * __thiscall Unit::GetStat(gpg::StrArg,std::string const&)
     */
    virtual StatItem* GetStat(gpg::StrArg, std::string const&) = 0;

    /**
     * Address: 0x006A4B70
     * Slot: 19
     * Demangled: public: virtual class StatItem near * __thiscall Unit::GetStat(gpg::StrArg,float const&)
     */
    virtual StatItem* GetStat(gpg::StrArg, float const&) = 0;

    /**
     * Address: 0x006A4B50
     * Slot: 20
     * Demangled: public: virtual class StatItem near * __thiscall Unit::GetStat(gpg::StrArg,int const&)
     */
    virtual StatItem* GetStat(gpg::StrArg, int const&) = 0;

    /**
     * Address: 0x006A4B30
     * Slot: 21
     * Demangled: public: virtual class StatItem near * __thiscall Unit::GetStat(gpg::StrArg)
     */
    virtual StatItem* GetStat(gpg::StrArg) = 0;

    /**
     * Address: 0x00541540 (FUN_00541540), 0x1012EEF0 (FUN_1012EEF0)
     * Mangled: ?CalcSpawnElevation@IUnit@Moho@@SAMPBVSTIMap@2@W4ELayer@2@VVTransform@2@ABUUnitAttributes@2@@Z
     *
     * What it does:
     * Computes spawn elevation from layer mask, map terrain/water surface, and
     * UnitAttributes::spawnElevationOffset.
     */
    static float
    CalcSpawnElevation(const STIMap* map, ELayer layer, VTransform transform, const UnitAttributes& attributes);
  };

  static_assert(sizeof(IUnit) == 0x08, "IUnit head must be 8 bytes");
} // namespace moho
