#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"

namespace moho
{
  /**
   * Engine addition: the reflected reference a Lua userdata holds, or an empty
   * one for any other value.
   */
  [[nodiscard]] inline gpg::RRef SCR_UserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
  }
} // namespace moho
