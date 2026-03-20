#include "moho/lua/CScrLuaClassBinder.h"

#include <cstring>
#include <string>

namespace moho
{
  /**
   * Address: 0x10015A10 (FUN_10015A10)
   *
   * What it does:
   * Initializes a class binder record and links it into the owning init set.
   */
  CScrLuaClassBinder::CScrLuaClassBinder(
    CScrLuaInitFormSet& set,
    const char* name,
    CScrLuaObjectFactory* classFactory,
    const char* groupName,
    const char* docString
  )
    : CScrLuaInitForm(set, name, groupName, docString)
    , mClassFactory(classFactory)
  {}

  /**
   * Address: 0x10015A50 (FUN_10015A50)
   *
   * What it does:
   * Copy-constructs class binder base metadata and class factory pointer.
   */
  CScrLuaClassBinder::CScrLuaClassBinder(const CScrLuaClassBinder& other)
    : CScrLuaInitForm(other)
    , mClassFactory(other.mClassFactory)
  {}

  /**
   * Address: 0x100BEF20 (FUN_100BEF20)
   *
   * What it does:
   * Ensures dotted path prefixes exist as tables under globals, then writes the class object at the tail symbol.
   */
  void CScrLuaClassBinder::Run(LuaPlus::LuaState* const state)
  {
    const char* segmentStart = mName;
    LuaPlus::LuaObject scope = state->GetGlobals();

    for (const char* dot = std::strchr(segmentStart, '.'); dot; dot = std::strchr(dot + 1, '.')) {
      std::string segment(segmentStart, static_cast<std::size_t>(dot - segmentStart));
      LuaPlus::LuaObject subScope = scope.GetByName(segment.c_str());

      if (subScope.IsNil()) {
        subScope.AssignNewTable(state, 0, 0);
        scope.SetObject(segment.c_str(), subScope);
      }

      scope = subScope;
      segmentStart = dot + 1;
    }

    LuaPlus::LuaObject classObj = mClassFactory->Get(state);
    scope.SetObject(segmentStart, classObj);
  }
} // namespace moho
