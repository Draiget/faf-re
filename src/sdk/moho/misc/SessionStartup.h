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
   * Address: 0x0088DA80 (FUN_0088DA80, cfunc_SessionSendChatMessage)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SessionSendChatMessageL`.
   */
  int cfunc_SessionSendChatMessage(lua_State* luaContext);

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
   * Address: 0x00881AB0 (FUN_00881AB0, cfunc_InternalSaveGame)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_InternalSaveGameL`.
   */
  int cfunc_InternalSaveGame(lua_State* luaContext);

  /**
   * Address: 0x00881B30 (FUN_00881B30, cfunc_InternalSaveGameL)
   *
   * What it does:
   * Validates one save request payload from Lua, seeds `CSaveGameRequestImpl`
   * archive lanes with shared `SSessionSaveData`, and queues request dispatch
   * on the active sim driver.
   */
  int cfunc_InternalSaveGameL(LuaPlus::LuaState* state);
} // namespace moho
