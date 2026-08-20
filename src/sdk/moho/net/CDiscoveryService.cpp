#include "moho/net/CDiscoveryService.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "moho/app/WinApp.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/Common.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/INetDatagramHandler.h"
#include "moho/net/INetDatagramSocket.h"
#include "moho/script/CScriptEvent.h"
#include "moho/task/CTask.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCDiscoveryServiceGetGameCountHelp = "CDiscoveryService.GetCount(self)";
  constexpr const char* kCDiscoveryServiceResetHelp = "CDiscoveryService.Reset(self)";
  constexpr const char* kCDiscoveryServiceDestroyHelp = "CDiscoveryService.Destory(self)";

  // Fixed discovery-reply wire header (mirrors the 0x0B/0x01/0x00 bytes
  // `CLobby::OnDatagram` writes when replying to a discovery request).
  constexpr std::uint8_t kDiscoveryReplyMagic = 0x0B;
  constexpr std::uint8_t kDiscoveryLobbyProtocolVersion = 0x01;
  constexpr std::uint8_t kDiscoverySupComGameTypeFlag = 0x00;

  [[nodiscard]] gpg::RType* CachedCDiscoveryServiceRuntimeType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CDiscoveryService));
    }
    return cached;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    return moho::SCR_FindLuaInitFormSet("User");
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  [[nodiscard]] moho::CDiscoveryService* OwnerFromPullTaskSubobject(
    moho::CPullTask<moho::CDiscoveryService>* const pullTask
  ) noexcept
  {
    if (pullTask == nullptr) {
      return nullptr;
    }

    auto* const taskBytes = reinterpret_cast<std::uint8_t*>(pullTask);
    return reinterpret_cast<moho::CDiscoveryService*>(taskBytes - offsetof(moho::CDiscoveryService, mPullTaskStorage));
  }

  [[nodiscard]] moho::CDiscoveryService* OwnerFromPushTaskSubobject(
    moho::CPushTask<moho::CDiscoveryService>* const pushTask
  ) noexcept
  {
    if (pushTask == nullptr) {
      return nullptr;
    }

    auto* const taskBytes = reinterpret_cast<std::uint8_t*>(pushTask);
    return reinterpret_cast<moho::CDiscoveryService*>(taskBytes - offsetof(moho::CDiscoveryService, mPushTaskStorage));
  }

  /**
   * Address: 0x007C0010 (FUN_007C0010)
   *
   * What it does:
   * Removes every currently tracked discovery-game entry by issuing one
   * `RemoveGame(index)` callback from back to front and compacting list bounds.
   */
  void RemoveTrackedDiscoveryGames(moho::CDiscoveryService* const discoveryService)
  {
    if (discoveryService == nullptr || discoveryService->mGamesBegin == nullptr) {
      return;
    }

    int remainingGames = discoveryService->GetGameCount();
    while (remainingGames != 0) {
      --remainingGames;
      discoveryService->CallbackInt("RemoveGame", remainingGames);

      moho::DiscoveredGameRecord* const gamesBegin = discoveryService->mGamesBegin;
      if (gamesBegin != nullptr && discoveryService->mGamesEnd != gamesBegin) {
        --discoveryService->mGamesEnd;
      }
    }
  }

  /**
   * Address: 0x007BF8D0 (FUN_007BF8D0)
   *
   * What it does:
   * Pulls datagram updates, expires stale discovery replies from the tracked
   * game list, emits timeout logs/callback removal, and arms the next wakeup.
   */
  void ExpireStaleDiscoveryReplies(moho::CDiscoveryService* const discoveryService)
  {
    if (discoveryService == nullptr) {
      return;
    }

    if (discoveryService->mDatagramSocket != nullptr) {
      discoveryService->mDatagramSocket->Pull();
    }

    const float nowSeconds = gpg::time::CyclesToSeconds(discoveryService->mTimer.ElapsedCycles());
    const float timeoutCutoffSeconds = nowSeconds - 5.0f;
    float nextWakeDelaySeconds = 5.0f;
    int removeIndex = 0;

    moho::DiscoveredGameRecord* record = discoveryService->mGamesBegin;
    while (record != nullptr && record != discoveryService->mGamesEnd) {
      const float ageSinceReply = record->mLastReplyTimeSeconds - timeoutCutoffSeconds;
      if (ageSinceReply >= 0.0f) {
        if (nextWakeDelaySeconds > ageSinceReply) {
          nextWakeDelaySeconds = ageSinceReply;
        }
        ++record;
        ++removeIndex;
        continue;
      }

      const msvc8::string hostName = moho::NET_GetHostName(record->mHostAddress);
      gpg::Logf("LOBBY: Discovery reply from %s:%d timed out.", hostName.c_str(), record->mHostPort);

      for (moho::DiscoveredGameRecord* nextRecord = record + 1; nextRecord != discoveryService->mGamesEnd; ++nextRecord) {
        *(nextRecord - 1) = *nextRecord;
      }
      --discoveryService->mGamesEnd;
      discoveryService->CallbackInt("RemoveGame", removeIndex);
    }

    if (discoveryService->mGamesBegin != nullptr && discoveryService->GetGameCount() > 0) {
      moho::WIN_SetWakeupTimer(nextWakeDelaySeconds * 1000.0f);
    }
  }

  /**
   * Address: 0x007BFA60 (FUN_007BFA60)
   *
   * What it does:
   * Broadcasts periodic discovery-request datagrams and updates wakeup timing
   * for the next scheduled broadcast tick.
   */
  void BroadcastDiscoveryRequestTick(moho::CDiscoveryService* const discoveryService)
  {
    if (discoveryService == nullptr || discoveryService->mDatagramSocket == nullptr) {
      return;
    }

    const float nowSeconds = gpg::time::CyclesToSeconds(discoveryService->mTimer.ElapsedCycles());
    if (nowSeconds >= discoveryService->mNextDiscoveryBroadcastTimeSeconds) {
      gpg::Logf("LOBBY: Broadcasting discovery request to port %d.", 15000);

      moho::CMessage request(moho::ELobbyMsg::LOBMSG_DiscoveryRequest);
      discoveryService->mDatagramSocket->SendDefault(&request, 15000);
      discoveryService->mNextDiscoveryBroadcastTimeSeconds = nowSeconds + 2.0f;
    }

    moho::WIN_SetWakeupTimer((discoveryService->mNextDiscoveryBroadcastTimeSeconds - nowSeconds) * 1000.0f);
  }

  [[nodiscard]] moho::CTask* PullTaskSubobject(moho::CDiscoveryService* const discoveryService) noexcept
  {
    return reinterpret_cast<moho::CTask*>(discoveryService->mPullTaskStorage);
  }

  [[nodiscard]] moho::CTask* PushTaskSubobject(moho::CDiscoveryService* const discoveryService) noexcept
  {
    return reinterpret_cast<moho::CTask*>(discoveryService->mPushTaskStorage);
  }

  class CDiscoveryServicePullTask final : public moho::CPullTask<moho::CDiscoveryService>
  {
  public:
    /**
     * Address: 0x007C8630 (FUN_007C8630)
     *
     * What it does:
     * Executes discovery pull-task maintenance by expiring stale discovery
     * reply lanes in the owning `CDiscoveryService`.
     */
    int Execute() override
    {
      ExpireStaleDiscoveryReplies(OwnerFromPullTaskSubobject(this));
      return 1;
    }
  };

  class CDiscoveryServicePushTask final : public moho::CPushTask<moho::CDiscoveryService>
  {
  public:
    /**
     * Address: 0x007C86F0 (FUN_007C86F0)
     *
     * What it does:
     * Executes discovery push-task maintenance by issuing periodic discovery
     * broadcast requests for the owning `CDiscoveryService`.
     */
    int Execute() override
    {
      BroadcastDiscoveryRequestTick(OwnerFromPushTaskSubobject(this));
      return 1;
    }
  };

  static_assert(sizeof(CDiscoveryServicePullTask) == 0x18, "CDiscoveryServicePullTask size must be 0x18");
  static_assert(sizeof(CDiscoveryServicePushTask) == 0x1C, "CDiscoveryServicePushTask size must be 0x1C");
} // namespace

/**
 * Address: 0x007BF650 (FUN_007BF650, ??0CDiscoveryService@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes Lua/script base lanes, pull/push task subobjects, discovery
 * storage pointers, timer state, and datagram-socket wait-handle wiring.
 */
moho::CDiscoveryService::CDiscoveryService(const LuaPlus::LuaObject& clazz)
  : CScriptObject(clazz, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
{
  ::new (static_cast<void*>(mPullTaskStorage)) CDiscoveryServicePullTask();
  ::new (static_cast<void*>(mPushTaskStorage)) CDiscoveryServicePushTask();

  mGamesBegin = nullptr;
  mGamesEnd = nullptr;
  mGamesCapacityEnd = nullptr;
  mNextDiscoveryBroadcastTimeSeconds = 0.0f;

  INetDatagramSocket* const openedSocket = NET_OpenDatagramSocket(0, this);
  INetDatagramSocket* const previousSocket = mDatagramSocket;
  mDatagramSocket = openedSocket;
  if (previousSocket != nullptr) {
    delete previousSocket;
  }

  if (mDatagramSocket != nullptr) {
    WIN_GetWaitHandleSet()->AddHandle(mDatagramSocket->CreateEvent());
  }
}

/**
 * Address: 0x007BF7F0 (FUN_007BF7F0, ??1CDiscoveryService@Moho@@QAE@@Z)
 *
 * What it does:
 * Releases datagram socket/wait-handle ownership, frees discovered-game heap
 * storage, tears down embedded pull/push task subobjects, then continues base
 * `CScriptObject` destruction.
 */
moho::CDiscoveryService::~CDiscoveryService()
{
  if (mDatagramSocket != nullptr) {
    WIN_GetWaitHandleSet()->RemoveHandle(mDatagramSocket->CreateEvent());
  }

  if (mDatagramSocket != nullptr) {
    delete mDatagramSocket;
  }

  if (mGamesBegin != nullptr) {
    ::operator delete(static_cast<void*>(mGamesBegin));
  }

  mGamesBegin = nullptr;
  mGamesEnd = nullptr;
  mGamesCapacityEnd = nullptr;

  PushTaskSubobject(this)->~CTask();
  PullTaskSubobject(this)->~CTask();
}

/**
 * Address: 0x007BF7A0 (FUN_007BF7A0, Moho::CDiscoveryService::dtr)
 *
 * What it does:
 * Runs `CDiscoveryService` non-deleting teardown and conditionally frees
 * object storage when `deleteFlags & 1`.
 */
[[maybe_unused]] moho::CScriptObject* DestroyDiscoveryServiceWithDeleteFlagThunk(
  moho::CDiscoveryService* const discoveryService,
  const std::uint8_t deleteFlags
) noexcept
{
  if (discoveryService == nullptr) {
    return nullptr;
  }

  discoveryService->~CDiscoveryService();
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(discoveryService);
  }
  return static_cast<moho::CScriptObject*>(discoveryService);
}

/**
 * Address: 0x007D0060 (FUN_007D0060)
 *
 * What it does:
 * Adjusts one `CPushTask<CDiscoveryService>` subobject `this` lane back to the
 * owning `CDiscoveryService` object, then forwards to scalar deleting teardown.
 */
[[maybe_unused]] moho::CScriptObject* DestroyDiscoveryServiceFromPushTaskAdjustorThunk(
  void* const pushTaskSubobject,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const owner = reinterpret_cast<moho::CDiscoveryService*>(
    static_cast<std::uint8_t*>(pushTaskSubobject) - offsetof(moho::CDiscoveryService, mPushTaskStorage)
  );
  return DestroyDiscoveryServiceWithDeleteFlagThunk(owner, deleteFlags);
}

/**
 * Address: 0x007D0070 (FUN_007D0070)
 *
 * What it does:
 * Adjusts one `CPullTask<CDiscoveryService>` subobject `this` lane back to the
 * owning `CDiscoveryService` object, then forwards to scalar deleting teardown.
 */
[[maybe_unused]] moho::CScriptObject* DestroyDiscoveryServiceFromPullTaskAdjustorThunk(
  void* const pullTaskSubobject,
  const std::uint8_t deleteFlags
) noexcept
{
  auto* const owner = reinterpret_cast<moho::CDiscoveryService*>(
    static_cast<std::uint8_t*>(pullTaskSubobject) - offsetof(moho::CDiscoveryService, mPullTaskStorage)
  );
  return DestroyDiscoveryServiceWithDeleteFlagThunk(owner, deleteFlags);
}

/**
 * Address: 0x007BF4B0 (FUN_007BF4B0, Moho::CDiscoveryService::GetClass)
 *
 * What it does:
 * Returns cached reflection type for `CDiscoveryService`.
 */
gpg::RType* moho::CDiscoveryService::GetClass() const
{
  return CachedCDiscoveryServiceRuntimeType();
}

/**
 * Address: 0x007BF4D0 (FUN_007BF4D0, Moho::CDiscoveryService::GetDerivedObjectRef)
 *
 * What it does:
 * Returns reflection reference `{this, GetClass()}`.
 */
gpg::RRef moho::CDiscoveryService::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x007C87E0 (FUN_007C87E0, sub_7C87E0)
 *
 * IDA signature:
 * int __usercall sub_7C87E0@<eax>(int a1@<edx>, _DWORD *a2@<esi>);
 *
 * What it does:
 * Appends `newRecord` to `mGamesBegin..mGamesEnd`. When the backing
 * allocation still has room (`count < capacity`), copies the record in
 * place and bumps `mGamesEnd`. Otherwise grows the allocation by ~1.5x
 * (minimum `count + 1`, matching the capacity math in FUN_007C9CD0's
 * realloc path), copies the existing records into the new buffer, appends
 * `newRecord`, and releases the old buffer.
 */
void moho::CDiscoveryService::AddDiscoveredGame(const DiscoveredGameRecord& newRecord)
{
  const auto count = static_cast<std::size_t>(mGamesEnd - mGamesBegin);
  const auto capacity = static_cast<std::size_t>(mGamesCapacityEnd - mGamesBegin);

  if (mGamesBegin != nullptr && count < capacity) {
    *mGamesEnd = newRecord;
    ++mGamesEnd;
    return;
  }

  std::size_t newCapacity = capacity + capacity / 2;
  if (newCapacity < count + 1) {
    newCapacity = count + 1;
  }

  auto* const newBegin =
    static_cast<DiscoveredGameRecord*>(::operator new(newCapacity * sizeof(DiscoveredGameRecord)));
  DiscoveredGameRecord* newEnd = newBegin;
  for (const DiscoveredGameRecord* src = mGamesBegin; src != mGamesEnd; ++src, ++newEnd) {
    *newEnd = *src;
  }
  *newEnd = newRecord;
  ++newEnd;

  if (mGamesBegin != nullptr) {
    ::operator delete(static_cast<void*>(mGamesBegin));
  }

  mGamesBegin = newBegin;
  mGamesEnd = newEnd;
  mGamesCapacityEnd = newBegin + newCapacity;
}

/**
 * Address: 0x007BFB70 (FUN_007BFB70, ??_7CDiscoveryService@Moho@@6BINetDatagramHandler@Moho@@@ slot 0)
 * Mangled implementer cite: IDA export name `Moho::CDiscoveryService::Pull`
 *
 * IDA signature:
 * void __thiscall Moho::CDiscoveryService::OnDatagram(
 *     Moho::CDiscoveryService *this, Moho::CMessage *msg,
 *     Moho::INetDatagramSocket *socket, u_long address, u_short port);
 *
 * Vtable slot: slot 0 of `INetDatagramHandler`, confirmed constructed by the
 * ctor (FUN_007BF650 writes `??_7CDiscoveryService@Moho@@6BINetDatagramHandler@Moho@@@`
 * at +0x34) and dispatched from `CNetDatagramSocketImpl::Pull()`
 * (`mDatagramHandler->OnDatagram(&msg, this, peerAddress, peerPort)`).
 *
 * What it does:
 * Validates the lobby message kind, the fixed discovery-reply header
 * (magic/protocol-version/SupCom-game flag), decodes the advertised game's
 * protocol/port and its Lua config payload, then either refreshes an
 * existing `DiscoveredGameRecord` (matched by sender address + advertised
 * port) or appends a new one via `AddDiscoveredGame`, firing the
 * `GameUpdated`/`GameFound` script callback either way.
 */
void moho::CDiscoveryService::OnDatagram(
  CMessage* const msg,
  INetDatagramSocket* /*socket*/,
  const u_long address,
  const u_short port
)
{
  if (msg->GetType() != ELobbyMsg::LOBMSG_DiscoveryResponse) {
    gpg::Logf(
      "LOBBY: Ignoring unknown kind of discovery reply (type=%d) from %s:%d",
      static_cast<int>(msg->GetType().raw()),
      NET_GetHostName(address).c_str(),
      static_cast<unsigned>(port)
    );
    return;
  }

  CMessageStream stream(msg);
  const gpg::BinaryReader reader(&stream);

  std::uint8_t replyMagic = 0;
  reader.ReadExact(replyMagic);
  if (replyMagic != kDiscoveryReplyMagic) {
    gpg::Logf(
      "LOBBY: Ignoring different version of discovery reply from %s:%d, got %d but expected %d",
      NET_GetHostName(address).c_str(),
      static_cast<unsigned>(port),
      static_cast<int>(replyMagic),
      static_cast<int>(kDiscoveryReplyMagic)
    );
    return;
  }

  std::uint8_t protocolVersion = 0;
  reader.ReadExact(protocolVersion);
  if (protocolVersion != kDiscoveryLobbyProtocolVersion) {
    gpg::Logf(
      "LOBBY: Ignoring discovery reply for different version of lobby protocol from %s:%d; got %d but expected %d",
      NET_GetHostName(address).c_str(),
      static_cast<unsigned>(port),
      static_cast<int>(protocolVersion),
      static_cast<int>(kDiscoveryLobbyProtocolVersion)
    );
    return;
  }

  std::uint8_t gameTypeFlag = 0;
  reader.ReadExact(gameTypeFlag);
  if (gameTypeFlag != kDiscoverySupComGameTypeFlag) {
    gpg::Logf("LOBBY: Ignoring discovery reply for non-SupCom game.");
    return;
  }

  auto protocol = static_cast<ENetProtocolType>(reader.ReadExact<std::uint8_t>());
  std::uint16_t hostPort = 0;
  reader.ReadExact(hostPort);

  LuaPlus::LuaObject configObject;
  mLuaObj.SCR_FromByteStream(configObject, mLuaObj.m_state, &reader);

  configObject.SetString("Hostname", NET_GetHostName(address).c_str());
  configObject.SetString(
    "Address",
    gpg::STR_Printf("%s:%i", NET_GetDottedOctetFromUInt32(address).c_str(), hostPort).c_str()
  );

  gpg::RRef protocolRef{};
  gpg::RRef_ENetProtocol(&protocolRef, &protocol);
  configObject.SetString("Protocol", protocolRef.GetLexical().c_str());

  gpg::Logf(
    "LOBBY: Received discovery reply for %s:%s:%d.",
    NET_GetProtocolName(protocol).c_str(),
    NET_GetHostName(address).c_str(),
    hostPort
  );

  DiscoveredGameRecord* record = nullptr;
  for (DiscoveredGameRecord* candidate = mGamesBegin; candidate != mGamesEnd; ++candidate) {
    if (candidate->mHostAddress == address && candidate->mHostPort == hostPort) {
      record = candidate;
      break;
    }
  }

  const bool isNewGame = record == nullptr;
  if (isNewGame) {
    DiscoveredGameRecord newRecord{};
    newRecord.mProtocol = protocol;
    newRecord.mHostAddress = address;
    newRecord.mHostPort = hostPort;
    newRecord.mLastReplyTimeSeconds = 0.0f;
    AddDiscoveredGame(newRecord);
    record = mGamesEnd - 1;
  }

  record->mLastReplyTimeSeconds = mTimer.ElapsedSeconds();
  RunScriptIntObject(isNewGame ? "GameFound" : "GameUpdated", 0, configObject);
}

int moho::CDiscoveryService::GetGameCount() const noexcept
{
  const DiscoveredGameRecord* const gamesBegin = mGamesBegin;
  if (gamesBegin == nullptr) {
    return 0;
  }

  return static_cast<int>(mGamesEnd - gamesBegin);
}

/**
 * Address: 0x007C01C0 (FUN_007C01C0, cfunc_CDiscoveryServiceGetGameCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CDiscoveryServiceGetGameCountL`.
 */
int moho::cfunc_CDiscoveryServiceGetGameCount(lua_State* const luaContext)
{
  return cfunc_CDiscoveryServiceGetGameCountL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C0240 (FUN_007C0240, cfunc_CDiscoveryServiceGetGameCountL)
 *
 * What it does:
 * Validates one Lua `self` arg, resolves `CDiscoveryService`, and returns
 * current discovered-game count.
 */
int moho::cfunc_CDiscoveryServiceGetGameCountL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCDiscoveryServiceGetGameCountHelp, 1, argumentCount);
  }

  const LuaPlus::LuaObject serviceObject(LuaPlus::LuaStackObject(state, 1));
  CDiscoveryService* const discoveryService = SCR_FromLua_CDiscoveryService(serviceObject, state);

  const float gameCount = static_cast<float>(discoveryService ? discoveryService->GetGameCount() : 0);
  lua_pushnumber(state->m_state, gameCount);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007C01E0 (FUN_007C01E0, func_CDiscoveryServiceGetGameCount_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CDiscoveryService:GetGameCount`.
 */
moho::CScrLuaInitForm* moho::func_CDiscoveryServiceGetGameCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameCount",
    &moho::cfunc_CDiscoveryServiceGetGameCount,
    &CScrLuaMetatableFactory<CDiscoveryService>::Instance(),
    "CDiscoveryService",
    kCDiscoveryServiceGetGameCountHelp
  );
  return &binder;
}

/**
 * Address: 0x007C0310 (FUN_007C0310, cfunc_CDiscoveryServiceReset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CDiscoveryServiceResetL`.
 */
int moho::cfunc_CDiscoveryServiceReset(lua_State* const luaContext)
{
  return cfunc_CDiscoveryServiceResetL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C0390 (FUN_007C0390, cfunc_CDiscoveryServiceResetL)
 *
 * What it does:
 * Validates one Lua `self` arg, resolves `CDiscoveryService`, and removes all
 * tracked discovery-game entries through callback lane.
 */
int moho::cfunc_CDiscoveryServiceResetL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCDiscoveryServiceResetHelp, 1, argumentCount);
  }

  const LuaPlus::LuaObject serviceObject(LuaPlus::LuaStackObject(state, 1));
  CDiscoveryService* const discoveryService = SCR_FromLua_CDiscoveryService(serviceObject, state);
  RemoveTrackedDiscoveryGames(discoveryService);
  return 0;
}

/**
 * Address: 0x007C0330 (FUN_007C0330, func_CDiscoveryServiceReset_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CDiscoveryService:Reset`.
 */
moho::CScrLuaInitForm* moho::func_CDiscoveryServiceReset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Reset",
    &moho::cfunc_CDiscoveryServiceReset,
    &CScrLuaMetatableFactory<CDiscoveryService>::Instance(),
    "CDiscoveryService",
    kCDiscoveryServiceResetHelp
  );
  return &binder;
}

/**
 * Address: 0x007C0430 (FUN_007C0430, cfunc_CDiscoveryServiceDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CDiscoveryServiceDestroyL`.
 */
int moho::cfunc_CDiscoveryServiceDestroy(lua_State* const luaContext)
{
  return cfunc_CDiscoveryServiceDestroyL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C04B0 (FUN_007C04B0, cfunc_CDiscoveryServiceDestroyL)
 *
 * What it does:
 * Validates one Lua `self` arg, resolves optional `CDiscoveryService`, and
 * destroys it when present.
 */
int moho::cfunc_CDiscoveryServiceDestroyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCDiscoveryServiceDestroyHelp, 1, argumentCount);
  }

  const LuaPlus::LuaObject serviceObject(LuaPlus::LuaStackObject(state, 1));
  CDiscoveryService* const discoveryService = SCR_FromLua_CDiscoveryServiceOpt(serviceObject, state);
  if (discoveryService != nullptr) {
    delete discoveryService;
  }
  return 0;
}

/**
 * Address: 0x007C0450 (FUN_007C0450, func_CDiscoveryServiceDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CDiscoveryService:Destroy`.
 */
moho::CScrLuaInitForm* moho::func_CDiscoveryServiceDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CDiscoveryServiceDestroy,
    &CScrLuaMetatableFactory<CDiscoveryService>::Instance(),
    "CDiscoveryService",
    kCDiscoveryServiceDestroyHelp
  );
  return &binder;
}

/**
 * Address: 0x00BDFDE0 (FUN_00BDFDE0, register_CDiscoveryServiceGetGameCount_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_CDiscoveryServiceGetGameCount_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_CDiscoveryServiceGetGameCount_LuaFuncDef()
{
  return func_CDiscoveryServiceGetGameCount_LuaFuncDef();
}

/**
 * Address: 0x00BDFDF0 (FUN_00BDFDF0, register_CDiscoveryServiceReset_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_CDiscoveryServiceReset_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_CDiscoveryServiceReset_LuaFuncDef()
{
  return func_CDiscoveryServiceReset_LuaFuncDef();
}

/**
 * Address: 0x00BDFE00 (FUN_00BDFE00, register_CDiscoveryServiceDestroy_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_CDiscoveryServiceDestroy_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_CDiscoveryServiceDestroy_LuaFuncDef()
{
  return func_CDiscoveryServiceDestroy_LuaFuncDef();
}

namespace
{
  /**
   * Address: 0x00BDFDB0 (FUN_00BDFDB0) -- record at 0x00F5A780
   *
   * What it does:
   * Publishes CDiscoveryService's method table as `moho.discovery_service_methods`;
   * the front end reaches discovery-service objects through this table.
   */
  moho::CScrLuaInitForm* register_moho_discovery_service_methods()
  {
    static moho::CScrLuaClassBinder binder(
      UserLuaInitSet(), "moho.discovery_service_methods", &moho::CScrLuaMetatableFactory<moho::CDiscoveryService>::Instance(), "CDiscoveryService", ""
    );
    return &binder;
  }

  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct CDiscoveryServiceLuaBinderBootstrap
  {
    CDiscoveryServiceLuaBinderBootstrap()
    {
      (void)::moho::register_CDiscoveryServiceGetGameCount_LuaFuncDef();
      (void)::moho::register_CDiscoveryServiceReset_LuaFuncDef();
      (void)::moho::register_CDiscoveryServiceDestroy_LuaFuncDef();
      (void)register_moho_discovery_service_methods();
    }
  };

  const CDiscoveryServiceLuaBinderBootstrap gCDiscoveryServiceLuaBinderBootstrap{};
} // namespace
