#include "moho/lua/CScrLuaBaseClassSpec.h"

namespace moho
{
  /**
   * Address: 0x10015A90 (FUN_10015A90)
   *
   * What it does:
   * Initializes a "base" class specification form and wires both class factories.
   */
  CScrLuaBaseClassSpec::CScrLuaBaseClassSpec(
    CScrLuaInitFormSet& set,
    CScrLuaObjectFactory* derivedClassFactory,
    CScrLuaObjectFactory* baseClassFactory,
    const char* groupName,
    const char* docString
  )
    : CScrLuaInitForm(set, "base", groupName, docString)
    , mDerivedClassFactory(derivedClassFactory)
    , mBaseClassFactory(baseClassFactory)
  {}

  /**
   * Address: 0x10015AE0 (FUN_10015AE0)
   *
   * What it does:
   * Copy-constructs base-class spec metadata and factory pointers.
   */
  CScrLuaBaseClassSpec::CScrLuaBaseClassSpec(const CScrLuaBaseClassSpec& other)
    : CScrLuaInitForm(other)
    , mDerivedClassFactory(other.mDerivedClassFactory)
    , mBaseClassFactory(other.mBaseClassFactory)
  {}

  /**
   * Address: 0x100BF090 (FUN_100BF090)
   *
   * What it does:
   * Pushes the base class table into the derived class table at index GetN()+1.
   */
  void CScrLuaBaseClassSpec::Run(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject derivedClassTable = mDerivedClassFactory->Get(state);
    LuaPlus::LuaObject baseClassTable = mBaseClassFactory->Get(state);
    derivedClassTable.SetObject(derivedClassTable.GetN() + 1, baseClassTable);
  }
} // namespace moho
