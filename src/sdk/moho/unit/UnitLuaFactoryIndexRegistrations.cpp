#include "moho/unit/CUnitCommand.h"

#include <cstdint>

#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  class CUnitScriptTask;
  class UnitWeapon;
}

namespace
{
  std::int32_t gRecoveredCScrLuaMetatableFactoryUnitIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCUnitScriptTaskIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryUnitWeaponIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCUnitCommandIndex = 0;

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCF040 (FUN_00BCF040, register_CScrLuaMetatableFactory_Unit_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<Unit>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_Unit_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryUnitIndex>();
  }

  /**
   * Address: 0x00BD1A20 (FUN_00BD1A20, register_CScrLuaMetatableFactory_CUnitScriptTask_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<CUnitScriptTask>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_CUnitScriptTask_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCUnitScriptTaskIndex>();
  }

  /**
   * Address: 0x00BD8B70 (FUN_00BD8B70, sub_BD8B70)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<UnitWeapon>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_UnitWeapon_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryUnitWeaponIndex>();
  }

  /**
   * Address: 0x00BD9050 (FUN_00BD9050, sub_BD9050)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<CUnitCommand>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_CUnitCommand_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCUnitCommandIndex>();
  }
} // namespace moho

namespace
{
  struct UnitLuaFactoryIndexRegistrationsBootstrap
  {
    UnitLuaFactoryIndexRegistrationsBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_Unit_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUnitScriptTask_Index();
      (void)moho::register_CScrLuaMetatableFactory_UnitWeapon_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUnitCommand_Index();
    }
  };

  UnitLuaFactoryIndexRegistrationsBootstrap gUnitLuaFactoryIndexRegistrationsBootstrap;
} // namespace
