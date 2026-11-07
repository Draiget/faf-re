#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kInternalCreateGroupHelpText =
    "InternalCreateGroup(luaobj,parent) -- For internal use by CreateGroup()";
}

gpg::RType* moho::CMauiGroup::sType = nullptr;

/**
 * Address: 0x00797310 (FUN_00797310, cfunc_InternalCreateGroup)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InternalCreateGroupL`.
 */
int moho::cfunc_InternalCreateGroup(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateGroupL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797330 (FUN_00797330, func_InternalCreateGroup_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateGroup(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateGroup_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateGroup",
    &moho::cfunc_InternalCreateGroup,
    nullptr,
    "<global>",
    kInternalCreateGroupHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797390 (FUN_00797390, cfunc_InternalCreateGroupL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one group control, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateGroupL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateGroupHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x11C)`.
  auto* const group = AllocateZeroedUiObject<CMauiGroup>(0x11Cu);
  new (group) CMauiGroup(&luaObject, parentControl);
  group->DoInit();
  group->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00797280 (FUN_00797280, ??0CMauiGroup@Moho@@QAE@@Z)
 *
 * What it does:
 * Constructs one group control from Lua object + parent lanes.
 */
moho::CMauiGroup::CMauiGroup(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "group")
{}

/**
 * Address: 0x00797300 (FUN_00797300, Moho::CMauiGroup::Draw)
 *
 * What it does:
 * No-op draw lane used by the group control vtable.
 */
void moho::CMauiGroup::DoRender(
  CD3DPrimBatcher* const /*primBatcher*/,
  const std::int32_t /*drawMask*/
)
{}

/**
 * Address: 0x007970F0 (FUN_007970F0, Moho::CMauiGroup::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiGroup`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiGroup::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiGroup));
  }
  return sType;
}

/**
 * Address: 0x00797110 (FUN_00797110, Moho::CMauiGroup::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiGroup::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
