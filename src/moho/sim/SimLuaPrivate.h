#pragma once

// Private to moho/sim: helpers the pieces of the former SimLuaFunctions.cpp share.

#include "moho/sim/SimPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{

  [[nodiscard]] CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }
}

