#include "moho/lua/CScrLuaBinder.h"

namespace moho
{
  /**
   * Address: 0x10015970 (FUN_10015970)
   *
   * What it does:
   * Initializes a CScrLuaBinder instance and links it into the set via CScrLuaInitForm.
   */
  CScrLuaBinder::CScrLuaBinder(
    CScrLuaInitFormSet& set,
    const char* name,
    const LuaFunction function,
    CScrLuaObjectFactory* ownerFactory,
    const char* groupName,
    const char* docString
  )
    : CScrLuaInitForm(set, name, groupName, docString)
    , mFunction(function)
    , mOwnerFactory(ownerFactory)
  {}

  /**
   * Address: 0x100159C0 (FUN_100159C0)
   *
   * What it does:
   * Copies base form metadata and all binder-local fields.
   */
  CScrLuaBinder::CScrLuaBinder(const CScrLuaBinder& other)
    : CScrLuaInitForm(other)
    , mFunction(other.mFunction)
    , mOwnerFactory(other.mOwnerFactory)
    , mUnknown1C(other.mUnknown1C)
    , mUnknown20(other.mUnknown20)
  {}

  /**
   * Address: 0x100BEE80 (FUN_100BEE80)
   * Address: 0x004CD3A0 (FUN_004CD3A0, Moho::CScrLuaBinder::Run)
   *
   * What it does:
   * Registers the bound function on either a factory-produced object table or Lua globals.
   */
  void CScrLuaBinder::Run(LuaPlus::LuaState* const state)
  {
    if (mOwnerFactory) {
      LuaPlus::LuaObject owner = mOwnerFactory->Get(state);
      owner.Register(mName, mFunction, 0);
      return;
    }

    LuaPlus::LuaObject globals = state->GetGlobals();
    globals.Register(mName, mFunction, 0);
  }
} // namespace moho
