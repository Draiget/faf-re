#include "moho/render/SelectionBracketParams.h"

#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace
{
  void LoadLuaNumberIfPresent(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaObject& tableObject,
    const char* const fieldName,
    float& outValue
  )
  {
    const LuaPlus::LuaObject probe = moho::SCR_GetLuaTableField(state, tableObject, fieldName);
    if (probe.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject field = moho::SCR_GetLuaTableField(state, tableObject, fieldName);
    outValue = static_cast<float>(field.GetNumber());
  }

  void LoadLuaUnsignedIfPresent(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaObject& tableObject,
    const char* const fieldName,
    std::uint32_t& outValue
  )
  {
    const LuaPlus::LuaObject probe = moho::SCR_GetLuaTableField(state, tableObject, fieldName);
    if (probe.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject field = moho::SCR_GetLuaTableField(state, tableObject, fieldName);
    outValue = static_cast<std::uint32_t>(field.GetInteger());
  }
} // namespace

namespace moho
{
  float ren_SelectionSizeFudge = 0.0f;
  float ren_SelectionHeightFudge = 0.0f;
  float ren_UnitSelectionScale = 0.0f;
  std::uint32_t ren_SelectColor = 0u;
  float ren_SelectBracketMinPixelSize = 0.0f;
  float ren_SelectBracketSize = 0.0f;

  /**
   * Address: 0x007FC4B0 (FUN_007FC4B0, func_LoadLuaSelectionParams)
   *
   * What it does:
   * Imports `/lua/renderselectparams.lua`, reads `RenderSelectParams`, and
   * updates optional selection-bracket render tuning globals.
   */
  void* LoadLuaSelectionParams(void* const selectionParamsSentinel)
  {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject importObject = SCR_ImportLuaModule(state, "/lua/renderselectparams.lua");
    if (!importObject.IsNil()) {
      LuaPlus::LuaObject renderSelectParams = SCR_GetLuaTableField(state, importObject, "RenderSelectParams");
      if (renderSelectParams.IsTable()) {
        LoadLuaNumberIfPresent(state, renderSelectParams, "ren_SelectionSizeFudge", ren_SelectionSizeFudge);
        LoadLuaNumberIfPresent(state, renderSelectParams, "ren_SelectionHeightFudge", ren_SelectionHeightFudge);
        LoadLuaNumberIfPresent(state, renderSelectParams, "ren_UnitSelectionScale", ren_UnitSelectionScale);
        LoadLuaUnsignedIfPresent(state, renderSelectParams, "ren_SelectColor", ren_SelectColor);
        LoadLuaNumberIfPresent(
          state, renderSelectParams, "ren_SelectBracketMinPixelSize", ren_SelectBracketMinPixelSize
        );
        LoadLuaNumberIfPresent(state, renderSelectParams, "ren_SelectBracketSize", ren_SelectBracketSize);
      }
    }

    return selectionParamsSentinel;
  }
} // namespace moho
