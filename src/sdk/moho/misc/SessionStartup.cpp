#include "moho/misc/SessionStartup.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "moho/client/Localization.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StringUtils.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/Common.h"
#include "moho/net/INetTCPSocket.h"
#include "moho/serialization/SaveGameFileHeader.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "lua/LuaTableIterator.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] bool MatchesSavedGameIdentity(const moho::SSaveGameFileHeader& header)
  {
    return header.mGameIdPart1 == moho::APP_GetGameIdPart(0) &&
           header.mGameIdPart2 == moho::APP_GetGameIdPart(1) &&
           header.mGameIdPart3 == moho::APP_GetGameIdPart(2) &&
           header.mGameIdPart4 == moho::APP_GetGameIdPart(3);
  }

  enum class EGpgNetOpenMode : int
  {
    Read = 1,
    Write = 2,
  };

  constexpr std::uint8_t kInvalidSourceIndex = 255u;
  constexpr const char* kSessionSendChatMessageHelpText = "SessionSendChatMessage([client-or-clients,] message)";
  constexpr const char* kLaunchReplaySessionHelpText =
    "bool LaunchReplaySession(filename) - starts a replay of a given file, returns false if unable to launch";
  constexpr const char* kLaunchSinglePlayerSessionHelpText = "LaunchSinglePlayerSession(launchData)";
  constexpr const char* kLaunchSinglePlayerSessionBusyMessage =
    "Can't launch a session while one is already launching or running.";
  constexpr const char* kNoActiveGameMessage = "GameSendChatMessage(): No active game.";
  constexpr const char* kInvalidClientIndexMessage = "Invalid client index.  Must be between 1 and %d inclusive, not %d.";
  constexpr const char* kInvalidClientSelectorMessage =
    "Invalid value for client-or-clients.  Must be either a single integer or a table of integers.";
  constexpr const char* kChatEncodeFailureMessage = "Can't encode message.";
  constexpr const char* kChatMessageTooLongMessage = "Message too long.";
  constexpr const char* kInternalSaveGameHelpText = "InternalSaveGame";
  constexpr const char* kSessionGetCommandSourceNamesHelpText = "Return a table of  command sources.";

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingLuaState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    static moho::CScrLuaInitFormSet set("user");
    return set;
  }

  void EnsureDirectoryExistsOrThrow(const msvc8::string& directoryPath)
  {
    const std::wstring widePath = gpg::STR_Utf8ToWide(directoryPath.c_str());
    if (::CreateDirectoryW(widePath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
      throw std::runtime_error(gpg::STR_Printf("Unable to create directory %s", directoryPath.c_str()).c_str());
    }
  }

  [[nodiscard]] gpg::RType* CachedSessionSaveDataType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SSessionSaveData));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeSessionSaveDataRef(moho::SSessionSaveData* const saveData)
  {
    gpg::RRef out{};
    out.mObj = saveData;
    out.mType = CachedSessionSaveDataType();
    return out;
  }

  /**
   * Address: 0x007CB8E0 (FUN_007CB8E0, func_CopyLaunchInfoBasePtr)
   *
   * What it does:
   * Copies one `shared_ptr<LaunchInfoNew>` lane into a
   * `shared_ptr<LaunchInfoBase>` output slot through swap-based temporary
   * ownership transfer.
   */
  boost::shared_ptr<moho::LaunchInfoBase>* CopyLaunchInfoBasePtr(
    boost::shared_ptr<moho::LaunchInfoBase>* const outBase,
    const boost::shared_ptr<moho::LaunchInfoNew>& source
  )
  {
    if (outBase == nullptr) {
      return nullptr;
    }

    boost::shared_ptr<moho::LaunchInfoBase> temp(source);
    temp.swap(*outBase);
    return outBase;
  }

  /**
   * Address: 0x0088BBB0 (FUN_0088BBB0, sub_88BBB0)
   *
   * What it does:
   * Seeds one local command source, applies it to all army launch source sets,
   * and binds a one-client local client-manager lane for single-player startup.
   */
  void SetupSinglePlayerCommandSourceLane(moho::SWldSessionInfo& sessionInfo, const char* playerName)
  {
    auto* const launchInfo = sessionInfo.mLaunchInfo.get();
    if (launchInfo == nullptr) {
      return;
    }

    const char* const localPlayerName = playerName != nullptr ? playerName : "";

    moho::SSTICommandSource localCommandSource{};
    localCommandSource.mIndex = 0u;
    localCommandSource.mName = localPlayerName;
    localCommandSource.mTimeouts = -1;
    moho::AppendSSTICommandSource(launchInfo->mCommandSources.mSrcs, localCommandSource);

    sessionInfo.mSourceId = 0u;

    moho::BVIntSet localSourceSet{};
    (void)localSourceSet.Add(0u);
    for (moho::ArmyLaunchInfo& armySourceInfo : launchInfo->mArmyLaunchInfo) {
      armySourceInfo.mUnitSources = localSourceSet;
    }

    moho::IClientManager* const createdManager = moho::CLIENT_CreateClientManager(1u, nullptr, 0, true);
    if (createdManager != sessionInfo.mClientManager && sessionInfo.mClientManager != nullptr) {
      delete sessionInfo.mClientManager;
    }
    sessionInfo.mClientManager = createdManager;

    if (sessionInfo.mClientManager != nullptr) {
      sessionInfo.mClientManager->CreateLocalClient(localPlayerName, 0, 0, sessionInfo.mSourceId);
    }
  }

  /**
   * Address: 0x00875690 (FUN_00875690, func_OpenGPGNet)
   *
   * What it does:
   * Opens one local file stream for replay/network URI fallback according to
   * recovered GPGNet mode semantics.
   */
  [[nodiscard]] std::unique_ptr<gpg::Stream> OpenGPGNet(const gpg::StrArg filename, const EGpgNetOpenMode mode)
  {
    switch (mode) {
    case EGpgNetOpenMode::Read: {
      msvc8::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileRead(filename);
      return std::unique_ptr<gpg::Stream>(openedStream.release());
    }
    case EGpgNetOpenMode::Write: {
      msvc8::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileWrite(filename);
      return std::unique_ptr<gpg::Stream>(openedStream.release());
    }
    default:
      throw std::runtime_error("unexpected mode in OpenGPGNet.");
    }
  }

  /**
   * Address: 0x008754D0 (FUN_008754D0, sub_8754D0)
   *
   * What it does:
   * Connects to GPGNet host endpoint, emits one mode byte plus replay request
   * path payload, and returns the live TCP stream lane.
   */
  [[nodiscard]]
  std::unique_ptr<gpg::Stream> OpenGPGNetSocket(
    const gpg::StrArg host, const msvc8::string& requestPath, const EGpgNetOpenMode mode
  )
  {
    constexpr u_short kDefaultGpgNetPort = 15000;

    u_long address = 0;
    u_short port = 0;
    if (!moho::NET_GetAddrInfo(host, kDefaultGpgNetPort, true, address, port)) {
      gpg::Logf("NET_GetAddrInfo(%s) failed: %s", host, moho::NET_GetWinsockErrorString());
      return {};
    }

    moho::INetTCPSocket* socket = moho::NET_TCPConnect(address, port);
    if (socket == nullptr) {
      const msvc8::string hostName = moho::NET_GetHostName(address);
      gpg::Logf("NET_TCPConnect(%s:%d) failed.", hostName.c_str(), static_cast<int>(port));
      return {};
    }

    std::unique_ptr<gpg::Stream> socketStream(socket);

    const char modeByte = [&]() -> char {
      switch (mode) {
      case EGpgNetOpenMode::Read:
        return 'G';
      case EGpgNetOpenMode::Write:
        return 'P';
      default:
        throw std::runtime_error("unexpected mode in OpenGPGNet.");
      }
    }();

    socketStream->Write(&modeByte, 1u);
    socketStream->Write(requestPath);
    socketStream->VirtFlush();
    return socketStream;
  }

  /**
   * Address: 0x00875770 (FUN_00875770, func_GPGNetOpenURI)
   *
   * What it does:
   * Resolves `gpgnet://` URI streams or falls back to local file open policy
   * for plain/drive-letter paths.
   */
  [[nodiscard]]
  std::unique_ptr<gpg::Stream> OpenGPGNetURI(const gpg::StrArg uri, const EGpgNetOpenMode mode)
  {
    msvc8::string scheme{};
    msvc8::string authority{};
    msvc8::string uriPath{};
    msvc8::string uriQuery{};
    msvc8::string uriFragment{};
    if (!moho::URI_Split(uri, &scheme, &authority, &uriPath, &uriQuery, &uriFragment)) {
      return OpenGPGNet(uri, mode);
    }

    if (gpg::STR_CompareNoCase(scheme.c_str(), "gpgnet:") == 0 && gpg::STR_StartsWith(authority.c_str(), "//")) {
      const msvc8::string requestPath = uriPath + uriQuery + uriFragment;
      return OpenGPGNetSocket(authority.c_str() + 2, requestPath, mode);
    }

    if (scheme.size() == 2u) {
      return OpenGPGNet(uri, mode);
    }

    return {};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008765E0 (FUN_008765E0)
   * Mangled:
   * ?VCR_SetupReplaySession@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Loads replay file payload, reconstructs `LaunchInfoNew`, and creates
   * one replay `SWldSessionInfo` bootstrap object.
   */
  msvc8::auto_ptr<SWldSessionInfo> VCR_SetupReplaySession(const gpg::StrArg filename)
  {
    if (filename == nullptr || filename[0] == '\0') {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    std::unique_ptr<gpg::Stream> replayStream{};
    try {
      replayStream = OpenGPGNetURI(filename, EGpgNetOpenMode::Read);
    } catch (...) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    if (replayStream == nullptr) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    gpg::BinaryReader replayReader(replayStream.get());
    const msvc8::string expectedVersion = gpg::STR_Printf("Supreme Commander v%1.2f.%4i", 1.5, 3764);
    msvc8::string replayVersion{};
    replayReader.ReadString(&replayVersion);
    if (replayVersion.view() != expectedVersion.view()) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    msvc8::string ignoredString{};
    replayReader.ReadString(&ignoredString);

    std::array<char, 14> replaySignature{};
    replayReader.Read(replaySignature.data(), 13);

    msvc8::string replayMapName{};
    replayReader.ReadString(&replayMapName);
    replayReader.ReadString(&ignoredString);

    if (std::strcmp(replaySignature.data(), "Replay v1.9\r\n") != 0) {
      return msvc8::auto_ptr<SWldSessionInfo>();
    }

    boost::shared_ptr<LaunchInfoNew> launchInfo(new LaunchInfoNew());
    replayReader.ReadLengthPrefixedString(&launchInfo->mGameMods);
    replayReader.ReadLengthPrefixedString(&launchInfo->mScenarioInfo);

    std::uint8_t commandSourceCount = 0;
    replayReader.ReadExact(commandSourceCount);

    launchInfo->mCommandSources.mSrcs.clear();
    launchInfo->mCommandSources.mSrcs.reserve(commandSourceCount);

    BVIntSet replayCommandSources{};
    for (std::uint32_t sourceIndex = 0; sourceIndex < commandSourceCount; ++sourceIndex) {
      SSTICommandSource source{};
      source.mIndex = sourceIndex;
      replayReader.ReadString(&source.mName);
      replayReader.ReadExact(source.mTimeouts);
      moho::AppendSSTICommandSource(launchInfo->mCommandSources.mSrcs, source);
      (void)replayCommandSources.Add(sourceIndex);
    }

    std::uint8_t cheatsEnabled = 0;
    replayReader.ReadExact(cheatsEnabled);
    launchInfo->mCheatsEnabled = cheatsEnabled != 0;

    std::uint8_t armyCount = 0;
    replayReader.ReadExact(armyCount);

    launchInfo->mArmyLaunchInfo.clear();
    launchInfo->mArmyLaunchInfo.resize(armyCount);
    launchInfo->mStrVec.clear();
    launchInfo->mStrVec.reserve(armyCount);

    for (std::uint32_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
      msvc8::string armyLabel{};
      replayReader.ReadLengthPrefixedString(&armyLabel);
      launchInfo->mStrVec.push_back(armyLabel);

      while (true) {
        std::uint8_t sourceIndex = kInvalidSourceIndex;
        replayReader.ReadExact(sourceIndex);
        if (sourceIndex == kInvalidSourceIndex) {
          break;
        }
        (void)launchInfo->mArmyLaunchInfo[armyIndex].mUnitSources.Add(sourceIndex);
      }
    }

    replayReader.ReadExact(launchInfo->mInitSeed);
    launchInfo->mCommandSources.mOriginalSource = -1;

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = replayMapName;
    (void)CopyLaunchInfoBasePtr(&sessionInfo->mLaunchInfo, launchInfo);
    sessionInfo->mIsBeingRecorded = false;
    sessionInfo->mIsReplay = true;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mClientManager = CLIENT_CreateClientManager(2u, nullptr, 0, true);
    sessionInfo->mSourceId = kInvalidSourceIndex;

    if (sessionInfo->mClientManager != nullptr) {
      gpg::Stream* replayStreamOwnership = replayStream.release();
      sessionInfo->mClientManager->CreateReplayClient(&replayStreamOwnership, &replayCommandSources);
      if (replayStreamOwnership != nullptr) {
        delete replayStreamOwnership;
      }

      const msvc8::string localName = Loc(USER_GetLuaState(), "<LOC Engine0031>Local");
      sessionInfo->mClientManager->CreateLocalClient(localName.c_str(), 1, 1, kInvalidSourceIndex);
    }

    return sessionInfo;
  }

  /**
   * Address: 0x0088CBC0 (FUN_0088CBC0)
   * Mangled:
   * ?WLD_SetupSessionInfo@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@ABVLuaObject@LuaPlus@@@Z
   *
   * What it does:
   * Builds one single-player session bootstrap payload from Lua launch data.
   */
  msvc8::auto_ptr<SWldSessionInfo> WLD_SetupSessionInfo(const LuaPlus::LuaObject& launchData)
  {
    boost::shared_ptr<LaunchInfoNew> launchInfo(new LaunchInfoNew());
    launchInfo->mCommandSources.mOriginalSource = 0;
    launchInfo->mCheatsEnabled = USER_DebugFacilitiesEnabled();

    const LuaPlus::LuaObject scenarioInfo = launchData["scenarioInfo"];
    launchInfo->mScenarioInfo = SCR_ToString(scenarioInfo);
    launchInfo->mGameMods = SCR_ToString(launchData["scenarioMods"]);

    {
      LuaPlus::LuaObject teamInfo = launchData["teamInfo"];
      LuaPlus::LuaTableIterator teamIterator(&teamInfo, 1);
      while (!teamIterator.m_isDone) {
        launchInfo->mArmyLaunchInfo.push_back(ArmyLaunchInfo{});
        launchInfo->mStrVec.push_back(SCR_ToString(teamIterator.GetValue()));
        teamIterator.Next();
      }
    }

    {
      const LuaPlus::LuaObject randomSeed = launchData["RandomSeed"];
      if (randomSeed.IsNil()) {
        launchInfo->mInitSeed = static_cast<std::int32_t>(gpg::time::GetSystemTimer().ElapsedCycles());
      } else {
        launchInfo->mInitSeed = randomSeed.GetInteger();
      }
    }

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    const char* const mapName = scenarioInfo["map"].GetString();
    sessionInfo->mMapName = mapName != nullptr ? mapName : "";
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(launchInfo);
    sessionInfo->mIsBeingRecorded = launchData["createReplay"].GetBoolean();
    sessionInfo->mIsReplay = false;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mClientManager = nullptr;
    sessionInfo->mSourceId = kInvalidSourceIndex;

    const char* const playerName = launchData["playerName"].GetString();
    SetupSinglePlayerCommandSourceLane(*sessionInfo, playerName);
    return sessionInfo;
  }

  /**
   * Address: 0x00876DD0 (FUN_00876DD0, cfunc_LaunchReplaySession)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_LaunchReplaySessionL`.
   */
  int cfunc_LaunchReplaySession(lua_State* const luaContext)
  {
    return cfunc_LaunchReplaySessionL(ResolveBindingLuaState(luaContext));
  }

  /**
   * Address: 0x00876DF0 (FUN_00876DF0, func_LaunchReplaySession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `LaunchReplaySession`.
   */
  CScrLuaInitForm* func_LaunchReplaySession_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "LaunchReplaySession",
      &moho::cfunc_LaunchReplaySession,
      nullptr,
      "<global>",
      kLaunchReplaySessionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00876E50 (FUN_00876E50, cfunc_LaunchReplaySessionL)
   *
   * What it does:
   * Validates one replay filename arg, builds replay session info, starts
   * world-session begin flow on success, and returns one boolean status.
   */
  int cfunc_LaunchReplaySessionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kLaunchReplaySessionHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject filenameArg(state, 1);
    const char* replayFilename = lua_tostring(state->m_state, 1);
    if (replayFilename == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&filenameArg, "string");
      replayFilename = "";
    }

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo = VCR_SetupReplaySession(replayFilename);
    const bool launchStarted = sessionInfo.get() != nullptr;
    if (launchStarted) {
      WLD_BeginSession(sessionInfo);
    }

    lua_pushboolean(state->m_state, launchStarted ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0088D340 (FUN_0088D340, cfunc_LaunchSinglePlayerSession)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_LaunchSinglePlayerSessionL`.
   */
  int cfunc_LaunchSinglePlayerSession(lua_State* const luaContext)
  {
    return cfunc_LaunchSinglePlayerSessionL(ResolveBindingLuaState(luaContext));
  }

  /**
   * Address: 0x0088D360 (FUN_0088D360, func_LaunchSinglePlayerSession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `LaunchSinglePlayerSession`.
   */
  CScrLuaInitForm* func_LaunchSinglePlayerSession_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "LaunchSinglePlayerSession",
      &moho::cfunc_LaunchSinglePlayerSession,
      nullptr,
      "<global>",
      "LaunchSinglePlayerSession(sessionInfo) -- launch a new single player session."
    );
    return &binder;
  }

  /**
   * Address: 0x0088D3C0 (FUN_0088D3C0, cfunc_LaunchSinglePlayerSessionL)
   *
   * What it does:
   * Validates one launch payload from Lua, rejects launches while world-frame
   * startup/runtime is active, builds single-player session info, and starts
   * world-session begin flow.
   */
  int cfunc_LaunchSinglePlayerSessionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kLaunchSinglePlayerSessionHelpText, 1, argumentCount);
    }

    if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
      LuaPlus::LuaState::Error(state, kLaunchSinglePlayerSessionBusyMessage);
    }

    const LuaPlus::LuaObject launchData(LuaPlus::LuaStackObject(state, 1));
    msvc8::auto_ptr<SWldSessionInfo> sessionInfo = WLD_SetupSessionInfo(launchData);
    WLD_BeginSession(sessionInfo);
    return 0;
  }

  /**
   * Address: 0x0088DA80 (FUN_0088DA80, cfunc_SessionSendChatMessage)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SessionSendChatMessageL`.
   */
  int cfunc_SessionSendChatMessage(lua_State* const luaContext)
  {
    return cfunc_SessionSendChatMessageL(ResolveBindingLuaState(luaContext));
  }

  /**
   * Address: 0x0088DAA0 (FUN_0088DAA0, func_SessionSendChatMessage_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionSendChatMessage`.
   */
  CScrLuaInitForm* func_SessionSendChatMessage_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "SessionSendChatMessage",
      &moho::cfunc_SessionSendChatMessage,
      nullptr,
      "<global>",
      kSessionSendChatMessageHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0088DB00 (FUN_0088DB00, cfunc_SessionSendChatMessageL)
   *
   * What it does:
   * Validates optional chat recipient selector(s), serializes one Lua message
   * payload to byte-stream form, enforces length cap, and broadcasts to the
   * selected network clients.
   */
  int cfunc_SessionSendChatMessageL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kSessionSendChatMessageHelpText, 1, 2, argumentCount
      );
    }

    ISTIDriver* const activeDriver = SIM_GetActiveDriver();
    if (activeDriver == nullptr) {
      LuaPlus::LuaState::Error(state, kNoActiveGameMessage);
      return 0;
    }

    CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
    if (clientManager == nullptr) {
      LuaPlus::LuaState::Error(state, kNoActiveGameMessage);
      return 0;
    }

    const int clientCount = static_cast<int>(clientManager->NumberOfClients());
    int selectedClientMask = 0;

    if (argumentCount <= 1) {
      selectedClientMask = (1 << clientCount) - 1;
    } else {
      const int clientSelectorType = lua_type(rawState, 1);
      if (clientSelectorType == LUA_TNUMBER) {
        const LuaPlus::LuaStackObject selectorArg(state, 1);
        const int clientIndex = selectorArg.GetInteger();
        if (clientIndex < 1 || clientIndex > clientCount) {
          LuaPlus::LuaState::Error(state, kInvalidClientIndexMessage, clientCount, clientIndex);
        }
        selectedClientMask = (1 << (clientIndex - 1));
      } else if (clientSelectorType == LUA_TTABLE) {
        const LuaPlus::LuaStackObject selectorArg(state, 1);
        LuaPlus::LuaObject selectorObject(selectorArg);
        LuaPlus::LuaTableIterator selectorIt(&selectorObject, 1);
        while (!selectorIt.m_isDone) {
          LuaPlus::LuaObject& selectorValue = selectorIt.GetValue();
          if (!selectorValue.IsNumber()) {
            LuaPlus::LuaState::Error(state, kInvalidClientSelectorMessage);
          }

          const int clientIndex = selectorValue.GetInteger();
          if (clientIndex < 1 || clientIndex > clientCount) {
            LuaPlus::LuaState::Error(state, kInvalidClientIndexMessage, clientCount, clientIndex);
          }

          selectedClientMask |= (1 << (clientIndex - 1));
          selectorIt.Next();
        }
      } else {
        LuaPlus::LuaState::Error(state, kInvalidClientSelectorMessage);
      }
    }

    gpg::MemBufferStream messageStream(256u);
    const LuaPlus::LuaStackObject messageArg(state, lua_gettop(rawState));
    LuaPlus::LuaObject messageObject(messageArg);
    if (!const_cast<LuaPlus::LuaObject&>(messageObject).ToByteStream(messageStream)) {
      LuaPlus::LuaState::Error(state, kChatEncodeFailureMessage);
    }

    const std::size_t encodedSize = messageStream.BytesWritten();
    if (encodedSize > 0x400u) {
      LuaPlus::LuaState::Error(state, kChatMessageTooLongMessage);
    }

    const gpg::MemBuffer<const char> encodedMessage = gpg::CopyMemBuffer(messageStream.mWriteStart, encodedSize);
    for (int clientIndex = 0; clientIndex < clientCount; ++clientIndex) {
      if ((selectedClientMask & (1 << clientIndex)) == 0) {
        continue;
      }

      IClient* const client = clientManager->GetClient(clientIndex);
      if (client != nullptr) {
        client->ReceiveChat(encodedMessage);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00897AF0 (FUN_00897AF0, cfunc_SessionGetCommandSourceNames)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SessionGetCommandSourceNamesL`.
   */
  int cfunc_SessionGetCommandSourceNames(lua_State* const luaContext)
  {
    return cfunc_SessionGetCommandSourceNamesL(ResolveBindingLuaState(luaContext));
  }

  /**
   * Address: 0x00897B10 (FUN_00897B10, func_SessionGetCommandSourceNames_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `SessionGetCommandSourceNames`.
   */
  CScrLuaInitForm* func_SessionGetCommandSourceNames_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "SessionGetCommandSourceNames",
      &moho::cfunc_SessionGetCommandSourceNames,
      nullptr,
      "<global>",
      kSessionGetCommandSourceNamesHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00897B70 (FUN_00897B70, cfunc_SessionGetCommandSourceNamesL)
   *
   * What it does:
   * Builds and returns a Lua table of active session command-source names.
   */
  int cfunc_SessionGetCommandSourceNamesL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSessionGetCommandSourceNamesHelpText, 0, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      LuaPlus::LuaState::Error(state, "SessionGetCommandSourceNames(): no active session.");
    }

    LuaPlus::LuaObject commandSources{};
    commandSources.AssignNewTable(state, 0, 0);
    for (std::size_t sourceIndex = 0; sourceIndex < session->cmdSources.size(); ++sourceIndex) {
      const int luaIndex = static_cast<int>(sourceIndex + 1u);
      commandSources.SetString(luaIndex, session->cmdSources[sourceIndex].mName.c_str());
    }

    commandSources.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00881AB0 (FUN_00881AB0, cfunc_InternalSaveGame)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_InternalSaveGameL`.
   */
  int cfunc_InternalSaveGame(lua_State* const luaContext)
  {
    return cfunc_InternalSaveGameL(ResolveBindingLuaState(luaContext));
  }

  /**
   * Address: 0x00881AD0 (FUN_00881AD0, func_InternalSaveGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `InternalSaveGame`.
   */
  CScrLuaInitForm* func_InternalSaveGame_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "InternalSaveGame",
      &moho::cfunc_InternalSaveGame,
      nullptr,
      "<global>",
      "InternalSaveGame(filename, friendlyname, oncompletion) -- save the current session."
    );
    return &binder;
  }

  /**
   * Address: 0x00881B30 (FUN_00881B30, cfunc_InternalSaveGameL)
   *
   * What it does:
   * Validates one save request payload from Lua, seeds `CSaveGameRequestImpl`
   * archive lanes with shared `SSessionSaveData`, and queues request dispatch
   * on the active sim driver.
   */
  int cfunc_InternalSaveGameL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kInternalSaveGameHelpText, 3, argumentCount);
    }

    const msvc8::string saveGameDirectory = USER_GetSaveGameDir();
    EnsureDirectoryExistsOrThrow(saveGameDirectory);

    const LuaPlus::LuaStackObject savePathArg(state, 1);
    const char* const savePath = lua_tostring(rawState, 1);
    if (savePath == nullptr) {
      savePathArg.TypeError("string");
    }

    const msvc8::string saveTargetDirectory = FILE_Dir(savePath);
    EnsureDirectoryExistsOrThrow(saveTargetDirectory);

    ISTIDriver* const driver = SIM_GetActiveDriver();
    if (driver == nullptr) {
      LuaPlus::LuaState::Error(state, "No session to save!");
    }

    const LuaPlus::LuaStackObject sessionNameArg(state, 2);
    const char* const sessionName = lua_tostring(rawState, 2);
    if (sessionName == nullptr) {
      sessionNameArg.TypeError("string");
    }

    const LuaPlus::LuaStackObject completionArg(state, 3);
    const LuaPlus::LuaObject completionCallback(completionArg);

    auto* const request = new CSaveGameRequestImpl(savePath, sessionName, completionCallback);

    CWldSession* const session = WLD_GetActiveSession();
    const boost::shared_ptr<SSessionSaveData> saveData =
      session != nullptr ? session->GetSaveData() : boost::shared_ptr<SSessionSaveData>{};

    gpg::WriteArchive* const archive = request->GetArchive();
    gpg::WriteRawPointer(archive, MakeSessionSaveDataRef(saveData.get()), gpg::TrackedPointerState::Shared, NullOwnerRef());
    archive->EndSection(false);

    driver->RequestSaveGame(request);
    return 0;
  }

  /**
   * Address: 0x00880330 (FUN_00880330)
   *
   * What it does:
   * Opens and validates one saved-game file and loads its header archive lane.
   */
  CSavedGame::CSavedGame(const gpg::StrArg filename)
    : mFilename(filename != nullptr ? filename : "")
    , mReader(nullptr)
    , mHeader()
  {
    const std::wstring widePath = gpg::STR_Utf8ToWide(mFilename.c_str());
    std::FILE* rawFile = nullptr;
    if (_wfopen_s(&rawFile, widePath.c_str(), L"rb") != 0) {
      rawFile = nullptr;
    }
    boost::shared_ptr<std::FILE> file(rawFile, moho::SFileStarCloser{});
    if (!file.get()) {
      throw std::runtime_error("CantOpen");
    }

    SSaveGameFileHeader fileHeader{};
    if (std::fread(&fileHeader, sizeof(fileHeader), 1, file.get()) != 1 ||
        fileHeader.mMagic != kSaveGameFileHeaderMagic || fileHeader.mVersion != kSaveGameFileHeaderVersion ||
        !MatchesSavedGameIdentity(fileHeader)) {
      throw std::runtime_error("InvalidFormat");
    }

    mReader = gpg::CreateBinaryReadArchive(file);
    mReader->Read(SSavedGameHeader::StaticGetClass(), &mHeader, NullOwnerRef());
    mReader->EndSection(false);
    if (mHeader.mVersion != 20) {
      throw std::runtime_error("WrongVersion");
    }
  }

  /**
   * Address: 0x00880770 (FUN_00880770)
   *
   * What it does:
   * Releases the loaded read-archive lane and header-owned fields.
   */
  CSavedGame::~CSavedGame()
  {
    delete mReader;
    mReader = nullptr;
  }

  /**
   * Address: 0x008807F0 (FUN_008807F0)
   *
   * What it does:
   * Builds one single-player `SWldSessionInfo` from loaded save payload.
   */
  msvc8::auto_ptr<SWldSessionInfo> CSavedGame::CreateSinglePlayerSessionInfo()
  {
    boost::shared_ptr<LaunchInfoLoad> launchInfo(new LaunchInfoLoad());
    gpg::ReadPointerShared_SSessionSaveData(launchInfo->mLoadSessionData, mReader, NullOwnerRef());
    mReader->EndSection(false);

    std::int32_t focusArmyIndex = mHeader.mFocusArmy;
    if (focusArmyIndex < 0) {
      focusArmyIndex = 0;
    }

    const msvc8::string localArmyName = mHeader.mArmyInfo[static_cast<std::size_t>(focusArmyIndex)].mPlayerName;

    launchInfo->mCommandSources.mSrcs.clear();
    SSTICommandSource source{};
    source.mIndex = 0;
    source.mName = localArmyName;
    source.mTimeouts = -1;
    moho::AppendSSTICommandSource(launchInfo->mCommandSources.mSrcs, source);

    launchInfo->mArmyLaunchInfo.clear();
    launchInfo->mArmyLaunchInfo.reserve(mHeader.mArmyInfo.size());
    for (std::size_t armyIndex = 0; armyIndex < mHeader.mArmyInfo.size(); ++armyIndex) {
      ArmyLaunchInfo armySourceInfo{};
      (void)armySourceInfo.mUnitSources.Add(0);
      launchInfo->mArmyLaunchInfo.push_back(armySourceInfo);
    }

    launchInfo->mCommandSources.mOriginalSource = mHeader.mFocusArmy;

    gpg::ReadArchive* const loadedArchive = mReader;
    mReader = nullptr;
    delete launchInfo->mReadArchive;
    launchInfo->mReadArchive = loadedArchive;

    launchInfo->mSharedLaunchInfo.assign_retain(mHeader.mLaunchInfo);
    launchInfo->mGameMods = launchInfo->mSharedLaunchInfo.px->mGameMods;
    launchInfo->mScenarioInfo = mHeader.mScenarioInfoText;
    launchInfo->mCheatsEnabled = USER_DebugFacilitiesEnabled();

    msvc8::auto_ptr<SWldSessionInfo> sessionInfo(new SWldSessionInfo());
    sessionInfo->mMapName = mHeader.mMapName;
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(launchInfo);
    sessionInfo->mIsBeingRecorded = false;
    sessionInfo->mIsReplay = false;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mClientManager = CLIENT_CreateClientManager(1u, nullptr, 0, true);
    sessionInfo->mSourceId = kInvalidSourceIndex;

    if (sessionInfo->mClientManager != nullptr) {
      sessionInfo->mClientManager->CreateLocalClient(localArmyName.c_str(), 0, 0, 0u);
    }
    sessionInfo->mSourceId = 0u;

    return sessionInfo;
  }
} // namespace moho
