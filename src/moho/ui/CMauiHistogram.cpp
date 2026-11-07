#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCMauiHistogramSetXIncrementHelpText = "CMauiHistogram:SetXIncrement(increment)";
  constexpr const char* kCMauiHistogramSetYIncrementHelpText = "CMauiHistogram:SetYIncrement(increment)";
  constexpr const char* kCMauiHistogramSetDataHelpText = "SetData(dataTable)";
  constexpr const char* kInternalCreateHistogramHelpText =
    "InternalCreateHistogram(luaobj,parent) -- For internal use by CreateHistogram()";
}

gpg::RType* moho::CMauiHistogram::sType = nullptr;

/**
 * Address: 0x00797AD0 (FUN_00797AD0, cfunc_CMauiHistogramSetXIncrement)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetXIncrementL`.
 */
int moho::cfunc_CMauiHistogramSetXIncrement(
  lua_State* const luaContext
)
{
  return cfunc_CMauiHistogramSetXIncrementL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797AF0 (FUN_00797AF0, func_CMauiHistogramSetXIncrement_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetXIncrement(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetXIncrement_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetXIncrement",
    &moho::cfunc_CMauiHistogramSetXIncrement,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetXIncrementHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797B50 (FUN_00797B50, cfunc_CMauiHistogramSetXIncrementL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus integer X-increment lane and updates the
 * histogram runtime view.
 */
int moho::cfunc_CMauiHistogramSetXIncrementL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiHistogramSetXIncrementHelpText);

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  CMauiHistogram* const histogram = SCR_FromLua_CMauiHistogram(histogramObject, state);

  LuaPlus::LuaStackObject incrementArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&incrementArg, "integer");
  }

  histogram->mXIncrement = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00797C50 (FUN_00797C50, cfunc_CMauiHistogramSetYIncrement)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetYIncrementL`.
 */
int moho::cfunc_CMauiHistogramSetYIncrement(
  lua_State* const luaContext
)
{
  return cfunc_CMauiHistogramSetYIncrementL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797C70 (FUN_00797C70, func_CMauiHistogramSetYIncrement_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetYIncrement(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetYIncrement_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetYIncrement",
    &moho::cfunc_CMauiHistogramSetYIncrement,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetYIncrementHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797CD0 (FUN_00797CD0, cfunc_CMauiHistogramSetYIncrementL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus integer Y-increment lane and updates the
 * histogram runtime view.
 */
int moho::cfunc_CMauiHistogramSetYIncrementL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiHistogramSetYIncrementHelpText);

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  CMauiHistogram* const histogram = SCR_FromLua_CMauiHistogram(histogramObject, state);

  LuaPlus::LuaStackObject incrementArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&incrementArg, "integer");
  }

  histogram->mYIncrement = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00797DD0 (FUN_00797DD0, cfunc_CMauiHistogramSetData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetDataL`.
 */
int moho::cfunc_CMauiHistogramSetData(
  lua_State* const luaContext
)
{
  return cfunc_CMauiHistogramSetDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797DF0 (FUN_00797DF0, func_CMauiHistogramSetData_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetData",
    &moho::cfunc_CMauiHistogramSetData,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797E50 (FUN_00797E50, cfunc_CMauiHistogramSetDataL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus data table and validates per-entry
 * color/data lanes.
 */
int moho::cfunc_CMauiHistogramSetDataL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiHistogramSetDataHelpText);

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CMauiHistogram(histogramObject, state);

  if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject dataRowsObject(LuaPlus::LuaStackObject(state, 2));
    const int dataRowCount = dataRowsObject.GetCount();
    for (int rowIndex = 1; rowIndex <= dataRowCount; ++rowIndex) {
      LuaPlus::LuaObject rowObject = dataRowsObject[rowIndex];
      LuaPlus::LuaObject colorObject = rowObject.GetByName("color");
      const std::uint32_t sampleColor = SCR_DecodeColor(state, colorObject);
      (void)sampleColor;

      LuaPlus::LuaObject valueTableObject = rowObject.GetByName("data");
      const int valueCount = valueTableObject.GetCount();
      std::vector<float> sampleValues{};
      if (valueCount > 0) {
        sampleValues.reserve(static_cast<std::size_t>(valueCount));
      }
      for (int valueIndex = 1; valueIndex <= valueCount; ++valueIndex) {
        LuaPlus::LuaObject valueObject = valueTableObject[valueIndex];
        sampleValues.push_back(static_cast<float>(valueObject.GetNumber()));
      }
    }
  } else {
    gpg::Warnf("Histogram:SetData a table of data!");
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00797920 (FUN_00797920, cfunc_InternalCreateHistogram)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateHistogramL`.
 */
int moho::cfunc_InternalCreateHistogram(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateHistogramL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797940 (FUN_00797940, func_InternalCreateHistogram_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateHistogram(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateHistogram_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateHistogram",
    &moho::cfunc_InternalCreateHistogram,
    nullptr,
    "<global>",
    kInternalCreateHistogramHelpText
  );
  return &binder;
}

/**
 * Address: 0x007979A0 (FUN_007979A0, cfunc_InternalCreateHistogramL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiHistogram`, dispatches
 * `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateHistogramL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateHistogramHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x134)`.
  auto* const histogram = AllocateZeroedUiObject<CMauiHistogram>(0x134u);
  new (histogram) CMauiHistogram(&luaObject, parentControl);
  histogram->DoInit();
  histogram->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007977A0 (FUN_007977A0, Moho::CMauiHistogram::CMauiHistogram)
 *
 * What it does:
 * Constructs one histogram control from Lua object + parent lanes and
 * initializes histogram runtime counters/state lanes.
 */
moho::CMauiHistogram::CMauiHistogram(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "group")
{}

/**
 * Address: 0x00797900 (FUN_00797900, Moho::CMauiHistogram::Dump)
 *
 * What it does:
 * Logs base control debug state plus one histogram class banner line.
 */
void moho::CMauiHistogram::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiHistogram");
}

/**
 * Address: 0x007978F0 (FUN_007978F0, Moho::CMauiHistogram::Draw)
 *
 * What it does:
 * No-op draw lane used by the histogram vtable.
 */
void moho::CMauiHistogram::DoRender(
  CD3DPrimBatcher* const /*primBatcher*/,
  const std::int32_t /*drawMask*/
)
{}

/**
 * Address: 0x007975F0 (FUN_007975F0, Moho::CMauiHistogram::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiHistogram`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiHistogram::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiHistogram));
  }
  return sType;
}

/**
 * Address: 0x00797610 (FUN_00797610, Moho::CMauiHistogram::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiHistogram::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
