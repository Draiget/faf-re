// SPDX: faf engine recovery
//
// UnrecoveredLuaCallbackStubs.cpp
//
// Linker stubs for engine Lua callbacks and binder factories whose
// implementations have not yet been recovered from binary evidence.
// Each stub satisfies the link with a no-op behavior:
//   * cfunc_*(lua_State*)       -> returns 0 (no values pushed)
//   * cfunc_*L(LuaPlus::LuaState*) -> returns 0 (no values pushed)
//   * func_*_LuaFuncDef()       -> returns nullptr (lib not registered)
//
// Game scripts that invoke these will see no return values or missing
// bindings. Each stub should be replaced with the recovered
// implementation from the matching FUN_XXXXXXXX address as recovery
// progresses (see decomp/recovery/disasm/fa_full_2026_03_26/).

struct lua_State;

namespace LuaPlus { class LuaState; }

namespace moho
{
  class CScrLuaInitForm;
}

namespace moho
{
  // ===== Unrecovered cfunc(lua_State*) callbacks =====
  int cfunc_CAiBrainCreateResourceBuildingNearest(lua_State*) { return 0; }
  int cfunc_CAiBrainFindPlaceToBuild(lua_State*) { return 0; }
  int func_FlushEvents(lua_State*) { return 0; }
}

namespace moho
{
  // ===== Unrecovered cfunc_*L(LuaPlus::LuaState*) inner callbacks =====
  int cfunc_IssueDockCommandL(LuaPlus::LuaState*) { return 0; }
  int cfunc_OpenURLL(LuaPlus::LuaState*) { return 0; }
}

namespace moho
{
  // ===== Unrecovered func_*_LuaFuncDef binder factories =====
  CScrLuaInitForm* func_CAiBrainCanBuildStructureAt_LuaFuncDef() { return nullptr; }
  // func_CAiBrainGetThreatsAroundPosition_LuaFuncDef recovered in CAiBrain.cpp (FUN_00590C20).
  // func_CAiBrainPickBestAttackVector_LuaFuncDef recovered in CAiBrain.cpp (FUN_0058EF80).
  // func_CreateUnit2_LuaFuncDef recovered in Unit.cpp (FUN_006D0020).
  CScrLuaInitForm* func_CreateUnitHPR_LuaFuncDef() { return nullptr; }
  CScrLuaInitForm* func_CreateUnit_LuaFuncDef() { return nullptr; }
}

