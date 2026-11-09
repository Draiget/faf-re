// Engine addition (dedicated-server plan WPL.4, WPR.11): the register_ thunks
// SimStartupRegistrations.cpp held for user Lua state functions
// (ClearBuildTemplates, RenderOverlayMilitary/Intel/Economy, TeamColorMode,
// GetUnitByIdUser; their definitions are in moho/sim/UserLuaFunctions.cpp),
// moved unchanged. Listed right after that file; its bootstrap calls the
// thunks that file's bootstrap called, in the same order.
#include "moho/sim/SimStartupRegistrations.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

#include "moho/console/CConAlias.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/MotorFallDown.h"
#include "moho/entity/Prop.h"
#include "moho/projectile/Projectile.h"
#include "moho/unit/core/Unit.h"
#include "moho/lua/CScrLuaBaseClassSpec.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardSimStartupLuaThunk() noexcept
  {
    return Target();
  }
} // namespace


namespace moho
{
  /**
   * Address: 0x00BE4D10 (FUN_00BE4D10, register_ClearBuildTemplates_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ClearBuildTemplates_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ClearBuildTemplates_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ClearBuildTemplates_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D20 (FUN_00BE4D20, j_func_RenderOverlayMilitary_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayMilitary_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_RenderOverlayMilitary_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayMilitary_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D30 (FUN_00BE4D30, register_RenderOverlayIntel_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayIntel_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayIntel_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D40 (FUN_00BE4D40, register_RenderOverlayEconomy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayEconomy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayEconomy_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayEconomy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D50 (FUN_00BE4D50, j_func_TeamColorModeUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_TeamColorMode_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_TeamColorModeUser_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_TeamColorMode_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D60 (FUN_00BE4D60, register_GetUnitByIdUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitByIdUser_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitByIdUser_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetUnitByIdUser_LuaFuncDef>();
  }

} // namespace moho

namespace
{
  /**
   * Engine addition (dedicated-server plan WPL.4): drives this file's Lua binder
   * definitions, the calls SimStartupRegistrations.cpp's
   * SimStartupRegistrationsLuaBinderBootstrap made for them, in the same order
   * (see that object for why a bootstrap is needed).
   */
  struct UserStartupRegistrationsBootstrap
  {
    UserStartupRegistrationsBootstrap()
    {
      (void)::moho::register_ClearBuildTemplates_LuaFuncDef();
      (void)::moho::register_RenderOverlayIntel_LuaFuncDef();
      (void)::moho::register_RenderOverlayEconomy_LuaFuncDef();
      (void)::moho::register_GetUnitByIdUser_LuaFuncDef();
    }
  };

  const UserStartupRegistrationsBootstrap gUserStartupRegistrationsBootstrap{};
} // namespace
