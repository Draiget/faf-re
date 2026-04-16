#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/time/Timer.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"

struct lua_State;
namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  class CScrLuaInitForm;
  class INetDatagramSocket;

  /**
   * Runtime lane for one discovered game entry in discovery-service storage.
   * Field ownership is partially recovered from timeout/update call lanes.
   */
  struct DiscoveredGameRecord
  {
    std::int32_t mUnknown00{0};       // +0x00 (semantic unresolved)
    std::uint32_t mHostAddress{0};    // +0x04
    std::uint16_t mHostPort{0};       // +0x08
    std::uint16_t mPad0A{0};          // +0x0A
    float mLastReplyTimeSeconds{0.0f}; // +0x0C
  };
  static_assert(offsetof(DiscoveredGameRecord, mHostAddress) == 0x04, "DiscoveredGameRecord::mHostAddress offset");
  static_assert(offsetof(DiscoveredGameRecord, mHostPort) == 0x08, "DiscoveredGameRecord::mHostPort offset");
  static_assert(
    offsetof(DiscoveredGameRecord, mLastReplyTimeSeconds) == 0x0C,
    "DiscoveredGameRecord::mLastReplyTimeSeconds offset"
  );
  static_assert(sizeof(DiscoveredGameRecord) == 0x10, "DiscoveredGameRecord size must be 0x10");

  class CDiscoveryService : public CScriptObject
  {
  public:
    /**
     * Address: 0x007BF650 (FUN_007BF650, ??0CDiscoveryService@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes Lua/script base lanes, pull/push task subobjects, discovery
     * storage pointers, timer state, and datagram-socket wait-handle wiring.
     */
    explicit CDiscoveryService(const LuaPlus::LuaObject& clazz);

    /**
     * Address: 0x007BF7F0 (FUN_007BF7F0, ??1CDiscoveryService@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases datagram socket/wait-handle ownership, frees discovered-game
     * heap storage, tears down embedded pull/push task subobjects, then
     * continues base `CScriptObject` destruction.
     */
    ~CDiscoveryService() override;

    /**
     * Address: 0x007BF4B0 (FUN_007BF4B0, Moho::CDiscoveryService::GetClass)
     */
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x007BF4D0 (FUN_007BF4D0, Moho::CDiscoveryService::GetDerivedObjectRef)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Returns current tracked-discovery-game count.
     */
    [[nodiscard]] int GetGameCount() const noexcept;

  public:
    void* mDatagramHandlerVTable{nullptr};           // +0x34
    alignas(void*) std::uint8_t mPullTaskStorage[0x18]{}; // +0x38
    std::uint8_t mUnknown50_53[0x04]{};              // +0x50
    alignas(void*) std::uint8_t mPushTaskStorage[0x1C]{}; // +0x54
    DiscoveredGameRecord* mGamesBegin{nullptr};       // +0x70
    DiscoveredGameRecord* mGamesEnd{nullptr};         // +0x74
    DiscoveredGameRecord* mGamesCapacityEnd{nullptr}; // +0x78
    std::uint8_t mUnknown7C[0x04]{};                  // +0x7C
    gpg::time::Timer mTimer;                          // +0x80
    float mNextDiscoveryBroadcastTimeSeconds{0.0f};   // +0x88
    INetDatagramSocket* mDatagramSocket{nullptr};     // +0x8C
  };

  static_assert(
    offsetof(CDiscoveryService, mDatagramHandlerVTable) == 0x34,
    "CDiscoveryService::mDatagramHandlerVTable must be +0x34"
  );
  static_assert(
    offsetof(CDiscoveryService, mPullTaskStorage) == 0x38,
    "CDiscoveryService::mPullTaskStorage must be +0x38"
  );
  static_assert(
    offsetof(CDiscoveryService, mUnknown50_53) == 0x50,
    "CDiscoveryService::mUnknown50_53 must be +0x50"
  );
  static_assert(
    offsetof(CDiscoveryService, mPushTaskStorage) == 0x54,
    "CDiscoveryService::mPushTaskStorage must be +0x54"
  );
  static_assert(offsetof(CDiscoveryService, mGamesBegin) == 0x70, "CDiscoveryService::mGamesBegin must be +0x70");
  static_assert(offsetof(CDiscoveryService, mGamesEnd) == 0x74, "CDiscoveryService::mGamesEnd must be +0x74");
  static_assert(
    offsetof(CDiscoveryService, mGamesCapacityEnd) == 0x78,
    "CDiscoveryService::mGamesCapacityEnd must be +0x78"
  );
  static_assert(offsetof(CDiscoveryService, mTimer) == 0x80, "CDiscoveryService::mTimer must be +0x80");
  static_assert(
    offsetof(CDiscoveryService, mNextDiscoveryBroadcastTimeSeconds) == 0x88,
    "CDiscoveryService::mNextDiscoveryBroadcastTimeSeconds must be +0x88"
  );
  static_assert(offsetof(CDiscoveryService, mDatagramSocket) == 0x8C, "CDiscoveryService::mDatagramSocket must be +0x8C");
  static_assert(sizeof(CDiscoveryService) == 0x90, "CDiscoveryService size must be 0x90");

  /**
   * Address: 0x007C01C0 (FUN_007C01C0, cfunc_CDiscoveryServiceGetGameCount)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CDiscoveryServiceGetGameCountL`.
   */
  int cfunc_CDiscoveryServiceGetGameCount(lua_State* luaContext);

  /**
   * Address: 0x007C01E0 (FUN_007C01E0, func_CDiscoveryServiceGetGameCount_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CDiscoveryService:GetGameCount()`.
   */
  CScrLuaInitForm* func_CDiscoveryServiceGetGameCount_LuaFuncDef();

  /**
   * Address: 0x007C0240 (FUN_007C0240, cfunc_CDiscoveryServiceGetGameCountL)
   *
   * What it does:
   * Validates one `self` arg and returns tracked discovery-game count.
   */
  int cfunc_CDiscoveryServiceGetGameCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C0310 (FUN_007C0310, cfunc_CDiscoveryServiceReset)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CDiscoveryServiceResetL`.
   */
  int cfunc_CDiscoveryServiceReset(lua_State* luaContext);

  /**
   * Address: 0x007C0330 (FUN_007C0330, func_CDiscoveryServiceReset_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CDiscoveryService:Reset()`.
   */
  CScrLuaInitForm* func_CDiscoveryServiceReset_LuaFuncDef();

  /**
   * Address: 0x007C0390 (FUN_007C0390, cfunc_CDiscoveryServiceResetL)
   *
   * What it does:
   * Validates one `self` arg and dispatches callback-based game-list reset.
   */
  int cfunc_CDiscoveryServiceResetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C0430 (FUN_007C0430, cfunc_CDiscoveryServiceDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CDiscoveryServiceDestroyL`.
   */
  int cfunc_CDiscoveryServiceDestroy(lua_State* luaContext);

  /**
   * Address: 0x007C0450 (FUN_007C0450, func_CDiscoveryServiceDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CDiscoveryService:Destroy()`.
   */
  CScrLuaInitForm* func_CDiscoveryServiceDestroy_LuaFuncDef();

  /**
   * Address: 0x007C04B0 (FUN_007C04B0, cfunc_CDiscoveryServiceDestroyL)
   *
   * What it does:
   * Validates one `self` arg, resolves optional object, and destroys it.
   */
  int cfunc_CDiscoveryServiceDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BDFDE0 (FUN_00BDFDE0, register_CDiscoveryServiceGetGameCount_LuaFuncDef)
   */
  CScrLuaInitForm* register_CDiscoveryServiceGetGameCount_LuaFuncDef();

  /**
   * Address: 0x00BDFDF0 (FUN_00BDFDF0, register_CDiscoveryServiceReset_LuaFuncDef)
   */
  CScrLuaInitForm* register_CDiscoveryServiceReset_LuaFuncDef();

  /**
   * Address: 0x00BDFE00 (FUN_00BDFE00, register_CDiscoveryServiceDestroy_LuaFuncDef)
   */
  CScrLuaInitForm* register_CDiscoveryServiceDestroy_LuaFuncDef();
} // namespace moho
