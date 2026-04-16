#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "moho/serialization/SSavedGameHeader.h"

struct lua_State;

namespace gpg
{
  class ReadArchive;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
  class LuaObject;
} // namespace LuaPlus

namespace moho
{
  class CScrLuaInitForm;
  struct SWldSessionInfo;

  /**
   * Address: 0x00880330 (FUN_00880330, `Moho::CSavedGame::CSavedGame`)
   * Address: 0x00880770 (FUN_00880770, `Moho::CSavedGame::~CSavedGame`)
   *
   * What it does:
   * Opens and validates one saved-game file, then loads the serialized
   * `SSavedGameHeader` payload and owning read-archive state.
   */
  class CSavedGame
  {
  public:
    /**
     * Address: 0x00880330 (FUN_00880330)
     *
     * What it does:
     * Opens and validates one saved-game file and loads its header archive lane.
     */
    explicit CSavedGame(gpg::StrArg filename);

    /**
     * Address: 0x00880770 (FUN_00880770)
     *
     * What it does:
     * Releases the loaded read-archive lane and header-owned fields.
     */
    ~CSavedGame();

    /**
     * Address: 0x008807F0 (FUN_008807F0)
     *
     * What it does:
     * Builds one single-player `SWldSessionInfo` from loaded save payload.
     */
    [[nodiscard]] msvc8::auto_ptr<SWldSessionInfo> CreateSinglePlayerSessionInfo();

  private:
    msvc8::string mFilename;      // +0x00
    gpg::ReadArchive* mReader;    // +0x1C
    SSavedGameHeader mHeader;     // +0x20
  };

  static_assert(sizeof(CSavedGame) == 0x78, "CSavedGame size must be 0x78");

  /**
   * Address: 0x008765E0 (FUN_008765E0)
   * Mangled:
   * ?VCR_SetupReplaySession@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Loads replay file payload, reconstructs `LaunchInfoNew`, and creates
   * one replay `SWldSessionInfo` bootstrap object.
   */
  [[nodiscard]] msvc8::auto_ptr<SWldSessionInfo> VCR_SetupReplaySession(gpg::StrArg filename);

  /**
   * Address: 0x0088CBC0 (FUN_0088CBC0)
   * Mangled:
   * ?WLD_SetupSessionInfo@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@ABVLuaObject@LuaPlus@@@Z
   *
   * What it does:
   * Builds one single-player `SWldSessionInfo` from Lua launch payload.
   */
  [[nodiscard]] msvc8::auto_ptr<SWldSessionInfo> WLD_SetupSessionInfo(const LuaPlus::LuaObject& launchData);

  /**
   * Address: 0x00876DD0 (FUN_00876DD0, cfunc_LaunchReplaySession)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_LaunchReplaySessionL`.
   */
  int cfunc_LaunchReplaySession(lua_State* luaContext);

  /**
   * Address: 0x00876DF0 (FUN_00876DF0, func_LaunchReplaySession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `LaunchReplaySession`.
   */
  CScrLuaInitForm* func_LaunchReplaySession_LuaFuncDef();

  /**
   * Address: 0x00876E50 (FUN_00876E50, cfunc_LaunchReplaySessionL)
   *
   * What it does:
   * Validates one replay filename arg, builds replay session info, starts
   * world-session begin flow on success, and returns one boolean status.
   */
  int cfunc_LaunchReplaySessionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088D340 (FUN_0088D340, cfunc_LaunchSinglePlayerSession)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_LaunchSinglePlayerSessionL`.
   */
  int cfunc_LaunchSinglePlayerSession(lua_State* luaContext);

  /**
   * Address: 0x0088D360 (FUN_0088D360, func_LaunchSinglePlayerSession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `LaunchSinglePlayerSession`.
   */
  CScrLuaInitForm* func_LaunchSinglePlayerSession_LuaFuncDef();

  /**
   * Address: 0x0088D3C0 (FUN_0088D3C0, cfunc_LaunchSinglePlayerSessionL)
   *
   * What it does:
   * Validates one launch payload from Lua, rejects launches while world-frame
   * startup/runtime is active, builds single-player session info, and starts
   * world-session begin flow.
   */
  int cfunc_LaunchSinglePlayerSessionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088DA80 (FUN_0088DA80, cfunc_SessionSendChatMessage)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SessionSendChatMessageL`.
   */
  int cfunc_SessionSendChatMessage(lua_State* luaContext);

  /**
   * Address: 0x0088DAA0 (FUN_0088DAA0, func_SessionSendChatMessage_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionSendChatMessage`.
   */
  CScrLuaInitForm* func_SessionSendChatMessage_LuaFuncDef();

  /**
   * Address: 0x0088DB00 (FUN_0088DB00, cfunc_SessionSendChatMessageL)
   *
   * What it does:
   * Validates optional chat recipient selector(s), serializes one Lua message
   * payload to byte-stream form, enforces length cap, and broadcasts to the
   * selected network clients.
   */
  int cfunc_SessionSendChatMessageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897AF0 (FUN_00897AF0, cfunc_SessionGetCommandSourceNames)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SessionGetCommandSourceNamesL`.
   */
  int cfunc_SessionGetCommandSourceNames(lua_State* luaContext);

  /**
   * Address: 0x00897B10 (FUN_00897B10, func_SessionGetCommandSourceNames_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `SessionGetCommandSourceNames`.
   */
  CScrLuaInitForm* func_SessionGetCommandSourceNames_LuaFuncDef();

  /**
   * Address: 0x00897B70 (FUN_00897B70, cfunc_SessionGetCommandSourceNamesL)
   *
   * What it does:
   * Builds and returns a Lua table of active session command-source names.
   */
  int cfunc_SessionGetCommandSourceNamesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00881AB0 (FUN_00881AB0, cfunc_InternalSaveGame)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_InternalSaveGameL`.
   */
  int cfunc_InternalSaveGame(lua_State* luaContext);

  /**
   * Address: 0x00881AD0 (FUN_00881AD0, func_InternalSaveGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `InternalSaveGame`.
   */
  CScrLuaInitForm* func_InternalSaveGame_LuaFuncDef();

  /**
   * Address: 0x00881B30 (FUN_00881B30, cfunc_InternalSaveGameL)
   *
   * What it does:
   * Validates one save request payload from Lua, seeds `CSaveGameRequestImpl`
   * archive lanes with shared `SSessionSaveData`, and queues request dispatch
   * on the active sim driver.
   */
  int cfunc_InternalSaveGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00880C40 (FUN_00880C40, cfunc_LoadSavedGame)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_LoadSavedGameL`.
   */
  int cfunc_LoadSavedGame(lua_State* luaContext);

  /**
   * Address: 0x00880C60 (FUN_00880C60, func_LoadSavedGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `LoadSavedGame`.
   */
  CScrLuaInitForm* func_LoadSavedGame_LuaFuncDef();

  /**
   * Address: 0x00886350 (FUN_00886350, cfunc_PrefetchSession)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_PrefetchSessionL`.
   */
  int cfunc_PrefetchSession(lua_State* luaContext);

  /**
   * Address: 0x00886370 (FUN_00886370, func_PrefetchSession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PrefetchSession`.
   */
  CScrLuaInitForm* func_PrefetchSession_LuaFuncDef();

  /**
   * Address: 0x0088D4C0 (FUN_0088D4C0, cfunc_GetSessionClients)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetSessionClientsL`.
   */
  int cfunc_GetSessionClients(lua_State* luaContext);

  /**
   * Address: 0x0088D4E0 (FUN_0088D4E0, func_GetSessionClients_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSessionClients`.
   */
  CScrLuaInitForm* func_GetSessionClients_LuaFuncDef();
} // namespace moho
