// Lua access to the format of the loaded map (docs/mapformat/): `GetMapFormat()` in the Sim and the User Lua states.
#pragma once

namespace moho
{
  class CScrLuaInitForm;

  /// Publishes sim-side `GetMapFormat()`.
  CScrLuaInitForm* func_GetMapFormat_Sim_LuaFuncDef();
  /// Publishes UI-side `GetMapFormat()`.
  CScrLuaInitForm* func_GetMapFormat_User_LuaFuncDef();
} // namespace moho
