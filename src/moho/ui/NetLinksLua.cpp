// Engine addition (in-game launcher, WP5b): the UI Lua's read of the game's own peer links (NETLINK_GetSnapshot, the
// network panel's source), so the lobby screen can show each player's link: direct or relayed, its state and its
// round trip. Read only; the links stay the netlink module's.

#include <cstdint>
#include <string>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/net/NetlinkPeers.h"

namespace
{
  void SetString(
    lua_State* const L,
    const char* const key,
    const std::string& value
  )
  {
    lua_pushstring(L, key);
    lua_pushstring(L, value.c_str());
    lua_settable(L, -3);
  }

  void SetNumber(
    lua_State* const L,
    const char* const key,
    const double value
  )
  {
    lua_pushstring(L, key);
    lua_pushnumber(L, static_cast<lua_Number>(value));
    lua_settable(L, -3);
  }

  void SetBool(
    lua_State* const L,
    const char* const key,
    const bool value
  )
  {
    lua_pushstring(L, key);
    lua_pushboolean(L, value ? 1 : 0);
    lua_settable(L, -3);
  }

  /**
   * table = FafNet_Links(): { mode = "native" | "in-engine" | "" (the links are an ICE adapter's, not the game's),
   * forceRelay = bool, peers = { { id (the FAF player id, as text), login, state, connected, localType, remoteType,
   * rttMs (-1 without a sample), lossPercent, attempts }, ... } }
   */
  int LinksBody(
    lua_State* const L
  )
  {
    const moho::SNetlinkSnapshot snapshot = moho::NETLINK_GetSnapshot();
    lua_newtable(L);
    SetString(L, "mode", snapshot.mode);
    SetBool(L, "forceRelay", snapshot.forceRelay);
    lua_pushstring(L, "peers");
    lua_newtable(L);
    int index = 1;
    for (const moho::SNetlinkPeerInfo& peer : snapshot.peers) {
      lua_pushnumber(L, static_cast<lua_Number>(index++));
      lua_newtable(L);
      // As text: lobby owner ids are text, and a float Lua number can't hold every 64-bit id.
      SetString(L, "id", std::to_string(peer.id));
      SetString(L, "login", peer.login);
      SetString(L, "state", peer.state);
      SetBool(L, "connected", peer.connected);
      SetString(L, "localType", peer.localType);
      SetString(L, "remoteType", peer.remoteType);
      SetNumber(L, "rttMs", peer.rttMs);
      SetNumber(L, "lossPercent", peer.lossPercent);
      SetNumber(L, "attempts", static_cast<double>(peer.attempts));
      lua_settable(L, -3);
    }
    lua_settable(L, -3);
    return 1;
  }

  template <int (*Body)(lua_State*)>
  int Binding(
    lua_State* const luaContext
  )
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    return state != nullptr && state->m_state != nullptr ? Body(state->m_state) : 0;
  }

  void RegisterNetLinksBindings()
  {
    static moho::CScrLuaBinder links(
      moho::SCR_UserLuaInitSet(),
      "FafNet_Links",
      &Binding<&LinksBody>,
      nullptr,
      "<global>",
      "table FafNet_Links() - the game's own peer links (mode, forceRelay, peers: id, login, state, connected, "
      "localType, remoteType, rttMs, lossPercent, attempts)."
    );
  }

  struct NetLinksLuaFuncDefBootstrap
  {
    NetLinksLuaFuncDefBootstrap()
    {
      RegisterNetLinksBindings();
    }
  };

  NetLinksLuaFuncDefBootstrap gNetLinksLuaFuncDefBootstrap;
} // namespace
