#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

#include <cstdint>

namespace
{
  std::int32_t gRecoveredCScrLuaMetatableFactoryCollisionBeamEntityIndex = 0;

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardCollisionBeamLuaThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  CScrLuaInitForm* func_CollisionBeamEntity__init_LuaFuncDef();
  CScrLuaInitForm* func_CollisionBeamEntitySetBeamFx_LuaFuncDef();
  CScrLuaInitForm* func_CollisionBeamEntityDisable_LuaFuncDef();
  CScrLuaInitForm* func_CollisionBeamEntityEnable_LuaFuncDef();
  CScrLuaInitForm* func_CollisionBeamEntityIsEnabled_LuaFuncDef();
  CScrLuaInitForm* func_CollisionBeamEntityGetLauncher_LuaFuncDef();

  /**
   * Address: 0x00BD4D10 (FUN_00BD4D10, register_CollisionBeamEntity__init_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntity__init_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntity__init_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D20 (FUN_00BD4D20, j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntitySetBeamFx_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D30 (FUN_00BD4D30, j_func_CollisionBeamEntityDisable_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CollisionBeamEntityDisable_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D40 (FUN_00BD4D40, register_CollisionBeamEntityEnable_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityEnable_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D50 (FUN_00BD4D50, register_CollisionBeamEntityIsEnabled_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityIsEnabled_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityIsEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D60 (FUN_00BD4D60, register_CollisionBeamEntityGetLauncher_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityGetLauncher_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityGetLauncher_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D70 (FUN_00BD4D70, register_CScrLuaMetatableFactory_CollisionBeamEntity_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered collision-beam metatable-factory startup index lane.
   */
  int register_CScrLuaMetatableFactory_CollisionBeamEntity_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCollisionBeamEntityIndex>();
  }
} // namespace moho

namespace
{
  struct CollisionBeamEntityLuaFunctionThunksBootstrap
  {
    CollisionBeamEntityLuaFunctionThunksBootstrap()
    {
      (void)moho::register_CollisionBeamEntity__init_LuaFuncDef();
      (void)moho::j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef();
      (void)moho::j_func_CollisionBeamEntityDisable_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityEnable_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityIsEnabled_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityGetLauncher_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_CollisionBeamEntity_Index();
    }
  };

  [[maybe_unused]] CollisionBeamEntityLuaFunctionThunksBootstrap gCollisionBeamEntityLuaFunctionThunksBootstrap;
} // namespace
