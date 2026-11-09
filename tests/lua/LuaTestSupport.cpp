#include "LuaTestSupport.h"

namespace faf_lua_tests
{
  namespace
  {
    std::string TopMessage(lua_State* const L)
    {
      const char* const text = lua_tostring(L, -1);
      return text != nullptr ? std::string(text, lua_strlen(L, -1)) : std::string("(non-string error value)");
    }
  } // namespace

  int LuaFixture::Load(const std::string& source, std::string* const message)
  {
    lua_State* const lua = L();
    const int top = lua_gettop(lua);
    const int status = luaL_loadbuffer(lua, source.data(), source.size(), "=test");
    if (status != 0 && message != nullptr) {
      *message = TopMessage(lua);
    }
    lua_settop(lua, top);
    return status;
  }

  LuaPlus::LuaObject LuaFixture::Run(const std::string& source)
  {
    lua_State* const lua = L();
    const int top = lua_gettop(lua);
    if (luaL_loadbuffer(lua, source.data(), source.size(), "=test") != 0) {
      ADD_FAILURE() << "load error: " << TopMessage(lua) << "\nin: " << source;
      lua_settop(lua, top);
      return LuaPlus::LuaObject(&state);
    }
    if (LuaCallProtected(lua, 0, 1) != 0) {
      ADD_FAILURE() << "run error: " << TopMessage(lua) << "\nin: " << source;
      lua_settop(lua, top);
      return LuaPlus::LuaObject(&state);
    }
    LuaPlus::LuaObject result(&state, -1);
    lua_settop(lua, top);
    return result;
  }

  std::string LuaFixture::Str(const std::string& source)
  {
    const LuaPlus::LuaObject result = Run(source);
    if (!result.IsString()) {
      ADD_FAILURE() << "expected a string, got " << result.TypeName() << "\nin: " << source;
      return {};
    }
    const auto* const text = static_cast<const TString*>(result.m_object.value.p);
    return std::string(text->str, text->len);
  }

  double LuaFixture::Num(const std::string& source)
  {
    const LuaPlus::LuaObject result = Run(source);
    if (!result.IsNumber()) {
      ADD_FAILURE() << "expected a number, got " << result.TypeName() << "\nin: " << source;
      return 0.0;
    }
    return result.GetNumber();
  }

  bool LuaFixture::Bool(const std::string& source)
  {
    const LuaPlus::LuaObject result = Run(source);
    if (!result.IsBoolean()) {
      ADD_FAILURE() << "expected a boolean, got " << result.TypeName() << "\nin: " << source;
      return false;
    }
    return result.GetBoolean();
  }

  std::string LuaFixture::ErrorOf(const std::string& source)
  {
    lua_State* const lua = L();
    const int top = lua_gettop(lua);
    std::string message;
    if (luaL_loadbuffer(lua, source.data(), source.size(), "=test") != 0) {
      message = TopMessage(lua);
    } else if (LuaCallProtected(lua, 0, 0) != 0) {
      message = TopMessage(lua);
    } else {
      ADD_FAILURE() << "expected an error from: " << source;
    }
    lua_settop(lua, top);
    return message;
  }
} // namespace faf_lua_tests
