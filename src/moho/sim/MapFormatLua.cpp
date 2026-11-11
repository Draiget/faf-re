#include "moho/sim/MapFormatLua.h"

#include <string>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/mapformat/FeatureBits.h"
#include "moho/sim/mapformat/MapFormatCommon.h"
#include "moho/sim/mapformat/MapFormat.h"

namespace
{
  constexpr const char* kGetMapFormatName = "GetMapFormat";
  constexpr const char* kGetMapFormatHelpText = "info = GetMapFormat()";

  [[nodiscard]] moho::CScrLuaInitFormSet& LuaInitSetNamed(const char* const name)
  {
    // Resolve the set that already exists: a second static set of the same name is never run.
    if (moho::CScrLuaInitFormSet* const existing = moho::SCR_FindLuaInitFormSet(name); existing != nullptr) {
      return *existing;
    }
    static moho::CScrLuaInitFormSet sSim("Sim");
    static moho::CScrLuaInitFormSet sUser("User");
    return name[0] == 'S' ? sSim : sUser;
  }

  /// Returns { id, name, container, revision, requiredFeatures = "0x..", features = {names...}, simHash = "hex" }.
  /// Lua numbers are 32-bit floats, so the 64-bit feature mask travels as hex text and as a list of names.
  int PushMapFormat(LuaPlus::LuaState* const state)
  {
    const moho::mapformat::SMapFormatInfo& info = moho::WLD_GetMapFormatInfo();
    LuaPlus::LuaObject table(state);
    table.AssignNewTable(state, 0, 0);
    table.SetInteger("id", static_cast<std::int32_t>(info.id));
    table.SetString("name", moho::mapformat::MapFormatName(info.id));
    table.SetInteger("container", static_cast<std::int32_t>(info.container));
    table.SetInteger("revision", static_cast<std::int32_t>(info.revision));
    table.SetString("requiredFeatures", ("0x" + moho::mapformat::TextDump::Hex(info.requiredFeatures, 16)).c_str());
    table.SetString("simHash", moho::mapformat::HexString(info.simHash.data(), info.simHash.size()).c_str());

    LuaPlus::LuaObject names(state);
    names.AssignNewTable(state, 0, 0);
    std::int32_t index = 1;
    for (std::uint32_t bit = 0; bit < 64; ++bit) {
      if ((info.requiredFeatures >> bit) & 1ULL) {
        names.SetString(index++, moho::mapformat::FeatureName(bit).c_str());
      }
    }
    table.SetObject("features", names);
    table.PushStack(state);
    return 1;
  }

  int cfunc_GetMapFormat(lua_State* const luaContext)
  {
    return PushMapFormat(moho::SCR_ResolveBindingState(luaContext));
  }
} // namespace

moho::CScrLuaInitForm* moho::func_GetMapFormat_Sim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    LuaInitSetNamed("Sim"), kGetMapFormatName, &cfunc_GetMapFormat, nullptr, "<global>", kGetMapFormatHelpText
  );
  return &binder;
}

moho::CScrLuaInitForm* moho::func_GetMapFormat_User_LuaFuncDef()
{
  static CScrLuaBinder binder(
    LuaInitSetNamed("User"), kGetMapFormatName, &cfunc_GetMapFormat, nullptr, "<global>", kGetMapFormatHelpText
  );
  return &binder;
}
