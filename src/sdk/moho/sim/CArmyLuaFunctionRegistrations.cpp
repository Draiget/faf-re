#include "moho/sim/CArmyLuaFunctionRegistrations.h"

#include <cstring>

#include "lua/LuaTableIterator.h"
#include "moho/console/CConAlias.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/misc/XDataError.h"
#include "moho/resource/RResId.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr const char* kGlobalLuaClassName = "<global>";
  constexpr const char* kCreateInitialArmyUnitName = "CreateInitialArmyUnit";
  constexpr const char* kCreateInitialArmyUnitHelpText = "CreateInitialArmyUnit(armyName, initialUnitName";
  constexpr const char* kSetArmyColorIndexName = "SetArmyColorIndex";
  constexpr const char* kSetArmyColorIndexHelpText = "SetArmyColorIndex(army,index)";
  constexpr const char* kAddBuildRestrictionName = "AddBuildRestriction";
  constexpr const char* kAddBuildRestrictionHelpText =
    "AddBuildRestriction(army,category) - Add a category to the restricted list";
  constexpr const char* kRemoveBuildRestrictionName = "RemoveBuildRestriction";
  constexpr const char* kRemoveBuildRestrictionHelpText =
    "RemoveBuildRestriction(army,category) - Remove a category from the restricted list";
  constexpr const char* kGameColorsScriptPath = "/lua/gameColors.lua";
  constexpr const char* kGameColorsTableName = "GameColors";
  constexpr const char* kPlayerColorsTableName = "PlayerColors";
  constexpr const char* kArmyColorsTableName = "ArmyColors";
  constexpr const char* kCivilianArmyColorFieldName = "CivilianArmyColor";
  constexpr const char* kUnidentifiedColorFieldName = "UnidentifiedColor";

  [[nodiscard]] moho::CConAlias& ConAlias_SetArmyColor()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc& SimConFunc_SetArmyColor()
  {
    static moho::CSimConFunc sCommand(false, "SetArmyColor", &moho::Sim::SetArmyColor);
    return sCommand;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  /**
   * Address: 0x00506850 (FUN_00506850, Moho::GetColorLuaState)
   *
   * What it does:
   * Returns process-static Lua state used for game-color table loading.
   */
  [[nodiscard]] LuaPlus::LuaState* GetColorLuaState()
  {
    static LuaPlus::LuaState sColorLuaState(LuaPlus::LuaState::LIB_OSIO);
    return &sColorLuaState;
  }

  /**
   * Address: 0x00506760 (FUN_00506760, ?GetColors@Moho@@YA?AVLuaObject@LuaPlus@@AAVLuaState@3@@Z)
   *
   * What it does:
   * Lazily creates and loads the static `sGameColorsObj` table by executing
   * `/lua/gameColors.lua`; throws `XDataError` when script load fails.
   */
  [[nodiscard]] LuaPlus::LuaObject* GetColors()
  {
    static LuaPlus::LuaObject sGameColorsObject;
    static bool sLoadOnce = true;

    if (sLoadOnce) {
      LuaPlus::LuaState* const colorState = GetColorLuaState();
      sGameColorsObject.AssignNewTable(colorState, 0, 0);
      if (!moho::SCR_LuaDoScript(colorState, kGameColorsScriptPath, &sGameColorsObject)) {
        throw moho::XDataError("Error reading gameColors");
      }
      sLoadOnce = false;
    }

    return &sGameColorsObject;
  }

  [[nodiscard]] std::uint32_t ResolvePlayerColorByIndex(LuaPlus::LuaState* const state, const int colorIndex)
  {
    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject playerColors = gameColors[kPlayerColorsTableName];
    const LuaPlus::LuaObject colorObject = playerColors.GetByIndex(colorIndex + 1);
    return moho::SCR_DecodeColor(state, colorObject);
  }

  [[nodiscard]] std::uint32_t ResolveArmyColorByIndex(LuaPlus::LuaState* const state, const int colorIndex)
  {
    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject armyColors = gameColors[kArmyColorsTableName];
    const LuaPlus::LuaObject colorObject = armyColors.GetByIndex(colorIndex + 1);
    return moho::SCR_DecodeColor(state, colorObject);
  }

  [[nodiscard]] std::uint32_t ResolveGameColorField(LuaPlus::LuaState* const state, const char* const fieldName)
  {
    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject colorObject = gameColors[fieldName];
    return moho::SCR_DecodeColor(state, colorObject);
  }

  [[nodiscard]] msvc8::string ResolvePlayerColorNameByIndex(LuaPlus::LuaState* const state, const int colorIndex)
  {
    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject playerColors = gameColors[kPlayerColorsTableName];
    const LuaPlus::LuaObject colorObject = playerColors.GetByIndex(colorIndex + 1);
    return msvc8::string(colorObject.GetString());
  }

  [[nodiscard]] std::uint32_t ResolvePlayerColorCount(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject playerColors = gameColors[kPlayerColorsTableName];
    return static_cast<std::uint32_t>(playerColors.GetCount());
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardArmyLuaRegistrationThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  int cfunc_CreateInitialArmyUnit(lua_State* luaContext);
  int cfunc_SetArmyColorIndex(lua_State* luaContext);
  int cfunc_AddBuildRestriction(lua_State* luaContext);
  int cfunc_RemoveBuildRestriction(lua_State* luaContext);
  int cfunc_CreateInitialArmyUnitL(LuaPlus::LuaState* state);
  int cfunc_SetArmyColorIndexL(LuaPlus::LuaState* state);
  int cfunc_AddBuildRestrictionL(LuaPlus::LuaState* state);
  int cfunc_RemoveBuildRestrictionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005068B0 (FUN_005068B0, ?GetPlayerColor@Moho@@YAIH@Z)
   *
   * int idx
   *
   * What it does:
   * Resolves one configured player color entry by index and decodes it into
   * packed ARGB.
   */
  std::uint32_t GetPlayerColor(const int idx)
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolvePlayerColorByIndex(colorState, idx);
  }

  /**
   * Address: 0x00506970 (FUN_00506970, ?GetArmyColor@Moho@@YAIH@Z)
   *
   * int idx
   *
   * What it does:
   * Resolves one configured army color entry by index and decodes it into
   * packed ARGB.
   */
  std::uint32_t GetArmyColor(const int idx)
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolveArmyColorByIndex(colorState, idx);
  }

  /**
   * Address: 0x00506A30 (FUN_00506A30, ?GetPlayerColorName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z)
   *
   * int idx
   *
   * What it does:
   * Returns one player-color token string from the game color table.
   */
  msvc8::string GetPlayerColorName(const int idx)
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolvePlayerColorNameByIndex(colorState, idx);
  }

  /**
   * Address: 0x00506B20 (FUN_00506B20, ?GetPlayerColorCount@Moho@@YAIXZ)
   *
   * What it does:
   * Returns the number of configured player colors.
   */
  std::uint32_t GetPlayerColorCount()
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolvePlayerColorCount(colorState);
  }

  /**
   * Address: 0x00506BB0 (FUN_00506BB0, ?GetCivilianArmyColor@Moho@@YAIXZ)
   *
   * What it does:
   * Decodes the configured civilian army color token into packed ARGB.
   */
  std::uint32_t GetCivilianArmyColor()
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolveGameColorField(colorState, kCivilianArmyColorFieldName);
  }

  /**
   * Address: 0x00506C40 (FUN_00506C40, ?GetUnidentifiedColor@Moho@@YAIXZ)
   *
   * What it does:
   * Decodes the configured unidentified color token into packed ARGB.
   */
  std::uint32_t GetUnidentifiedColor()
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();
    return ResolveGameColorField(colorState, kUnidentifiedColorFieldName);
  }

  /**
   * Address: 0x00506CD0 (FUN_00506CD0, func_GetColorIndex)
   *
   * int packedColor
   *
   * What it does:
   * Scans the configured army-color table and returns the first index whose
   * decoded color matches `packedColor`; defaults to `3` when not found.
   */
  int func_GetColorIndex(const int packedColor)
  {
    LuaPlus::LuaState* const colorState = GetColorLuaState();

    LuaPlus::LuaObject* const gameColorsRoot = GetColors();

    const LuaPlus::LuaObject gameColors = (*gameColorsRoot)[kGameColorsTableName];
    const LuaPlus::LuaObject armyColors = gameColors[kArmyColorsTableName];
    LuaPlus::LuaTableIterator iter(armyColors, 1);

    int colorIndex = 0;
    while (iter.IsValid()) {
      const int decodedColor = static_cast<int>(moho::SCR_DecodeColor(colorState, iter.GetValue()));
      if (packedColor == decodedColor) {
        return colorIndex;
      }

      iter.Next();
      ++colorIndex;
    }

    return 3;
  }

  /**
   * Address: 0x007092E0 (FUN_007092E0, func_CreateInitialArmyUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateInitialArmyUnit`.
   */
  CScrLuaInitForm* func_CreateInitialArmyUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateInitialArmyUnitName,
      &cfunc_CreateInitialArmyUnit,
      nullptr,
      kGlobalLuaClassName,
      kCreateInitialArmyUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00709E70 (FUN_00709E70, func_SetArmyColorIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyColorIndex`.
   */
  CScrLuaInitForm* func_SetArmyColorIndex_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetArmyColorIndexName,
      &cfunc_SetArmyColorIndex,
      nullptr,
      kGlobalLuaClassName,
      kSetArmyColorIndexHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0070A700 (FUN_0070A700, func_AddBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `AddBuildRestriction`.
   */
  CScrLuaInitForm* func_AddBuildRestriction_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kAddBuildRestrictionName,
      &cfunc_AddBuildRestriction,
      nullptr,
      kGlobalLuaClassName,
      kAddBuildRestrictionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0070A820 (FUN_0070A820, func_RemoveBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RemoveBuildRestriction`.
   */
  CScrLuaInitForm* func_RemoveBuildRestriction_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kRemoveBuildRestrictionName,
      &cfunc_RemoveBuildRestriction,
      nullptr,
      kGlobalLuaClassName,
      kRemoveBuildRestrictionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007092C0 (FUN_007092C0, cfunc_CreateInitialArmyUnit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CreateInitialArmyUnitL`.
   */
  int cfunc_CreateInitialArmyUnit(lua_State* const luaContext)
  {
    return cfunc_CreateInitialArmyUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00709E50 (FUN_00709E50, cfunc_SetArmyColorIndex)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyColorIndexL`.
   */
  int cfunc_SetArmyColorIndex(lua_State* const luaContext)
  {
    return cfunc_SetArmyColorIndexL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00709ED0 (FUN_00709ED0, cfunc_SetArmyColorIndexL)
   *
   * What it does:
   * Reads `(army, colorIndex)`, resolves one configured player color by index,
   * and writes both army color lanes.
   */
  int cfunc_SetArmyColorIndexL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetArmyColorIndexHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
    CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

    LuaPlus::LuaStackObject colorIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      colorIndexArg.TypeError("integer");
    }

    const int colorIndex = static_cast<int>(lua_tonumber(rawState, 2));
    const std::uint32_t packedColor = GetPlayerColor(colorIndex);
    army->PlayerColorBgra = packedColor;
    army->ArmyColorBgra = packedColor;
    return 0;
  }

  /**
   * Address: 0x0070A6E0 (FUN_0070A6E0, cfunc_AddBuildRestriction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_AddBuildRestrictionL`.
   */
  int cfunc_AddBuildRestriction(lua_State* const luaContext)
  {
    return cfunc_AddBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0070A800 (FUN_0070A800, cfunc_RemoveBuildRestriction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_RemoveBuildRestrictionL`.
   */
  int cfunc_RemoveBuildRestriction(lua_State* const luaContext)
  {
    return cfunc_RemoveBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00709340 (FUN_00709340, cfunc_CreateInitialArmyUnitL)
   *
   * What it does:
   * Reads `(army, initialUnitName)`, resolves one unit blueprint from rules,
   * and creates one initial unit at that army start position.
   */
  int cfunc_CreateInitialArmyUnitL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCreateInitialArmyUnitHelpText, 2, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
    CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

    LuaPlus::LuaStackObject initialUnitArg(state, 2);
    const char* initialUnitName = lua_tostring(rawState, 2);
    if (!initialUnitName) {
      initialUnitArg.TypeError("string");
      initialUnitName = "";
    }

    RResId blueprintId{};
    blueprintId.name.assign_owned(initialUnitName);

    RUnitBlueprint* blueprint = nullptr;
    if (sim && sim->mRules) {
      blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
    }
    if (!blueprint) {
      LuaPlus::LuaState::Error(state, "Unknown initial unit: %s", blueprintId.name.c_str());
    }

    Wm3::Vector2f startPosition{};
    army->GetArmyStartPos(startPosition);

    SUnitConstructionParams constructionParams{
      0,
      Wm3::Vector3f{startPosition.x, 0.0f, startPosition.y},
      army,
      blueprint,
      nullptr,
      true
    };
    constructionParams.mTransform.orient_.x = 1.0f;
    constructionParams.mTransform.orient_.y = 0.0f;
    constructionParams.mTransform.orient_.z = 0.0f;
    constructionParams.mTransform.orient_.w = 0.0f;
    constructionParams.mUseLayerOverride = 1;

    Unit* const unit = sim ? sim->CreateUnitForScript(constructionParams, true) : nullptr;
    if (!unit) {
      LuaPlus::LuaState::Error(state, "SetArmyStart() failed");
    }

    unit->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0070A760 (FUN_0070A760, cfunc_AddBuildRestrictionL)
   *
   * What it does:
   * Reads `(army, categorySet)` and applies one build restriction to that army.
   */
  int cfunc_AddBuildRestrictionL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kAddBuildRestrictionHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
    CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

    const LuaPlus::LuaObject restrictionObject(LuaPlus::LuaStackObject(state, 2));
    void* const restriction = static_cast<void*>(func_GetCObj_EntityCategory(restrictionObject));
    army->AddBuildRestriction(restriction);
    return 0;
  }

  /**
   * Address: 0x0070A880 (FUN_0070A880, cfunc_RemoveBuildRestrictionL)
   *
   * What it does:
   * Reads `(army, categorySet)` and removes one build restriction from that
   * army.
   */
  int cfunc_RemoveBuildRestrictionL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kRemoveBuildRestrictionHelpText,
        2,
        argumentCount
      );
    }

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
    CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

    const LuaPlus::LuaObject restrictionObject(LuaPlus::LuaStackObject(state, 2));
    void* const restriction = static_cast<void*>(func_GetCObj_EntityCategory(restrictionObject));
    army->RemoveBuildRestriction(restriction);
    return 0;
  }

  /**
   * Address: 0x00BD9D00 (FUN_00BD9D00, j_func_ListArmies_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ListArmies_LuaFuncDef` to `func_ListArmies_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ListArmies_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_ListArmies_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D10 (FUN_00BD9D10, register_GetArmyBrain_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GetArmyBrain_LuaFuncDef` to `func_GetArmyBrain_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetArmyBrain_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_GetArmyBrain_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D20 (FUN_00BD9D20, j_func_SetArmyStart_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyStart_LuaFuncDef` to `func_SetArmyStart_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyStart_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyStart_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D30 (FUN_00BD9D30, register_GenerateArmyStart_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GenerateArmyStart_LuaFuncDef` to `func_GenerateArmyStart_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GenerateArmyStart_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_GenerateArmyStart_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D40 (FUN_00BD9D40, register_SetArmyPlans_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyPlans_LuaFuncDef` to `func_SetArmyPlans_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyPlans_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyPlans_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D50 (FUN_00BD9D50, register_InitializeArmyAI_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_InitializeArmyAI_LuaFuncDef` to `func_InitializeArmyAI_LuaFuncDef`.
   */
  CScrLuaInitForm* register_InitializeArmyAI_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_InitializeArmyAI_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D60 (FUN_00BD9D60, register_ArmyInitializePrebuiltUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyInitializePrebuiltUnits_LuaFuncDef` to `func_ArmyInitializePrebuiltUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyInitializePrebuiltUnits_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_ArmyInitializePrebuiltUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D70 (FUN_00BD9D70, register_ArmyGetHandicap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyGetHandicap_LuaFuncDef` to `func_ArmyGetHandicap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyGetHandicap_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_ArmyGetHandicap_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D80 (FUN_00BD9D80, j_func_SetArmyEconomy_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyEconomy_LuaFuncDef` to `func_SetArmyEconomy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyEconomy_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyEconomy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9D90 (FUN_00BD9D90, j_func_GetArmyUnitCostTotal_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_GetArmyUnitCostTotal_LuaFuncDef` to `func_GetArmyUnitCostTotal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_GetArmyUnitCostTotal_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_GetArmyUnitCostTotal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DA0 (FUN_00BD9DA0, register_GetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GetArmyUnitCap_LuaFuncDef` to `func_GetArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetArmyUnitCap_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_GetArmyUnitCap_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DB0 (FUN_00BD9DB0, register_SetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyUnitCap_LuaFuncDef` to `func_SetArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyUnitCap_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyUnitCap_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DC0 (FUN_00BD9DC0, register_SetIgnoreArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetIgnoreArmyUnitCap_LuaFuncDef` to `func_SetIgnoreArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetIgnoreArmyUnitCap_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetIgnoreArmyUnitCap_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DD0 (FUN_00BD9DD0, j_func_SetIgnorePlayableRect_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetIgnorePlayableRect_LuaFuncDef` to `func_SetIgnorePlayableRect_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetIgnorePlayableRect_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetIgnorePlayableRect_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DE0 (FUN_00BD9DE0, register_CreateInitialArmyUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreateInitialArmyUnit_LuaFuncDef` to `func_CreateInitialArmyUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateInitialArmyUnit_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_CreateInitialArmyUnit_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9DF0 (FUN_00BD9DF0, register_SetAlliance_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetAlliance_LuaFuncDef` to `func_SetAlliance_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetAlliance_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetAlliance_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E00 (FUN_00BD9E00, register_SetAllianceOneWay_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetAllianceOneWay_LuaFuncDef` to `func_SetAllianceOneWay_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetAllianceOneWay_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetAllianceOneWay_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E10 (FUN_00BD9E10, j_func_SetAlliedVictory_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetAlliedVictory_LuaFuncDef` to `func_SetAlliedVictory_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetAlliedVictory_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetAlliedVictory_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E20 (FUN_00BD9E20, j_func_IsAllySim_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IsAllySim_LuaFuncDef` to `func_IsAllySim_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IsAllySim_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_IsAllySim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E30 (FUN_00BD9E30, register_IsEnemySim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IsEnemySim_LuaFuncDef` to `func_IsEnemySim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsEnemySim_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_IsEnemySim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E40 (FUN_00BD9E40, register_IsNeutralSim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IsNeutralSim_LuaFuncDef` to `func_IsNeutralSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsNeutralSim_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_IsNeutralSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E50 (FUN_00BD9E50, j_func_ArmyIsCivilian_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ArmyIsCivilian_LuaFuncDef` to `func_ArmyIsCivilian_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ArmyIsCivilian_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_ArmyIsCivilian_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E60 (FUN_00BD9E60, j_func_SetArmyColorIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyColorIndex_LuaFuncDef` to `func_SetArmyColorIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyColorIndex_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyColorIndex_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E70 (FUN_00BD9E70, register_SetArmyFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyFactionIndex_LuaFuncDef` to `func_SetArmyFactionIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyFactionIndex_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyFactionIndex_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E80 (FUN_00BD9E80, j_func_SetArmyAIPersonality_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyAIPersonality_LuaFuncDef` to `func_SetArmyAIPersonality_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyAIPersonality_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyAIPersonality_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9E90 (FUN_00BD9E90, register_SetArmyColor_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyColor_LuaFuncDef` to `func_SetArmyColor_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyColor_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyColor_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9EA0 (FUN_00BD9EA0, register_SetArmyColor_ConAliasDef)
   *
   * What it does:
   * Registers the `SetArmyColor` console alias that routes to
   * `DoSimCommand SetArmyColor`.
   */
  void register_SetArmyColor_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_SetArmyColor().InitializeRecovered(
      "SetArmyColor(army,r,g,b)",
      "SetArmyColor",
      "DoSimCommand SetArmyColor"
    );
  }

  /**
   * Address: 0x00BD9ED0 (FUN_00BD9ED0, register_SetArmyColor_SimConFuncDef)
   *
   * What it does:
   * Registers the `SetArmyColor` sim-console command callback.
   */
  void register_SetArmyColor_SimConFuncDef()
  {
    (void)SimConFunc_SetArmyColor();
  }

  /**
   * Address: 0x00BD9F10 (FUN_00BD9F10, j_func_SetArmyShowScore_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyShowScore_LuaFuncDef` to `func_SetArmyShowScore_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyShowScore_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyShowScore_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9F20 (FUN_00BD9F20, register_AddBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_AddBuildRestriction_LuaFuncDef` to `func_AddBuildRestriction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_AddBuildRestriction_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_AddBuildRestriction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9F30 (FUN_00BD9F30, register_RemoveBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_RemoveBuildRestriction_LuaFuncDef` to `func_RemoveBuildRestriction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RemoveBuildRestriction_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_RemoveBuildRestriction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9F40 (FUN_00BD9F40, j_func_OkayToMessWithArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_OkayToMessWithArmy_LuaFuncDef` to `func_OkayToMessWithArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_OkayToMessWithArmy_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_OkayToMessWithArmy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9F50 (FUN_00BD9F50, register_ArmyIsOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyIsOutOfGame_LuaFuncDef` to `func_ArmyIsOutOfGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyIsOutOfGame_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_ArmyIsOutOfGame_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9F60 (FUN_00BD9F60, register_SetArmyOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyOutOfGame_LuaFuncDef` to `func_SetArmyOutOfGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyOutOfGame_LuaFuncDef()
  {
    return ForwardArmyLuaRegistrationThunk<&func_SetArmyOutOfGame_LuaFuncDef>();
  }

} // namespace moho
