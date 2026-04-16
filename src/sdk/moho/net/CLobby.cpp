#include "CLobby.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <vector>

#include "CClientManagerImpl.h"
#include "CDiscoveryService.h"
#include "CMessageStream.h"
#include "CNetNullConnector.h"
#include "CNetUDPConnection.h"
#include "ELobbyMsg.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "INetDatagramSocket.h"
#include "INetNATTraversalProviderWeakPtrReflection.h"
#include "lua/LuaTableIterator.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StringUtils.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/ui/UiRuntimeTypes.h"
using namespace moho;

namespace moho
{
  /**
   * Address: 0x00F5A758 (Moho__lob_IgnoreNames)
   *
   * What it does:
   * Stores comma-separated player names that should be ignored by lobby peer-connect flow.
   */
  msvc8::string lob_IgnoreNames{};

  /**
   * Address: 0x00F5A770 (ConVar_lob_IgnoreNames)
   *
   * What it does:
   * Console command definition that exposes `lob_IgnoreNames` for runtime tuning.
   */
  TConVar<msvc8::string> ConVar_lob_IgnoreNames{
    "lob_IgnoreNames",
    "Comma seperated list of player names to ignore.",
    &lob_IgnoreNames
  };

  int cfunc_CLobbySendDataL(LuaPlus::LuaState* state);
  int cfunc_CLobbyMakeValidPlayerNameL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateDiscoveryServiceL(LuaPlus::LuaState* state);
  /**
   * Address: 0x007CB690 (FUN_007CB690, func_GetCObj_NatTraversalProvider)
   *
   * What it does:
   * Unwraps Lua boxed userdata payload and returns the typed
   * `boost::weak_ptr<INetNATTraversalProvider>` slot.
   */
  [[nodiscard]] boost::weak_ptr<INetNATTraversalProvider>* func_GetCObj_NatTraversalProvider(LuaPlus::LuaObject valueObject);
  int cfunc_InternalCreateLobbyL(LuaPlus::LuaState* state);
  int cfunc_CLobbyHostGameL(LuaPlus::LuaState* state);
  int cfunc_CLobbyJoinGameL(LuaPlus::LuaState* state);
  int cfunc_CLobbyBroadcastDataL(LuaPlus::LuaState* state);
  int cfunc_CLobbyGetPeersL(LuaPlus::LuaState* state);
  int cfunc_CLobbyGetPeerL(LuaPlus::LuaState* state);
  int cfunc_CLobbyGetLocalPlayerNameL(LuaPlus::LuaState* state);
  int cfunc_CLobbyGetLocalPlayerIDL(LuaPlus::LuaState* state);
  int cfunc_CLobbyIsHostL(LuaPlus::LuaState* state);
  int cfunc_CLobbyGetLocalPortL(LuaPlus::LuaState* state);
  int cfunc_CLobbyConnectToPeerL(LuaPlus::LuaState* state);
  int cfunc_CLobbyLaunchGameL(LuaPlus::LuaState* state);
  int cfunc_CLobbyDebugDumpL(LuaPlus::LuaState* state);
  int cfunc_CLobbyEjectPeerL(LuaPlus::LuaState* state);
  int cfunc_CLobbyDisconnectFromPeerL(LuaPlus::LuaState* state);
  int cfunc_ValidateIPAddressL(LuaPlus::LuaState* state);
  int cfunc_ValidateIPAddress(lua_State* luaContext);
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kInternalCreateDiscoveryServiceHelp = "InternalCreateDiscoveryService(class)";
  constexpr const char* kInternalCreateLobbyHelp =
    "InternalCreateLobby(class, string protocol, int localPort, int maxConnections, string playerName, string playerUID, "
    "Boxed<weak_ptr<INetNATTraversalProvider> > natTraversalProvider)";
  constexpr const char* kCLobbyDestroyHelp = "CLobby.Destroy(self)";
  constexpr const char* kCLobbyMakeValidGameNameHelp = "string CLobby.MakeValidGameName(self,origName)";
  constexpr const char* kCLobbyMakeValidPlayerNameHelp = "string CLobby.MakeValidPlayerName(self,uid,origName)";
  constexpr const char* kCLobbyHostGameHelp = "void CLobby.HostGame(self)";
  constexpr const char* kCLobbyJoinGameHelp =
    "void CLobby.JoinGame(self, string-or-boxedInt32 address, string-or-nil remotePlayerName, string remotePlayerUID)";
  constexpr const char* kCLobbyBroadcastDataHelp = "void CLobby.BradcastData(self,table)";
  constexpr const char* kCLobbyGetPeersHelp = "table CLobby.GetPeers(self)";
  constexpr const char* kCLobbyGetPeerHelp = "table CLobby.GetPeer(self,uid)";
  constexpr const char* kCLobbyGetLocalPlayerNameHelp = "string CLobby.GetLocalPlayerName(self)";
  constexpr const char* kCLobbyGetLocalPlayerIdHelp = "int CLobby.GetLocalPlayerID(self)";
  constexpr const char* kCLobbyIsHostHelp = "bool CLobby.IsHost(self)";
  constexpr const char* kCLobbyGetLocalPortHelp = "int-or-nil CLobby.GetLocalPort(self)";
  constexpr const char* kCLobbyConnectToPeerHelp = "void CLobby.ConnectToPeer(self,address,name,uid";
  constexpr const char* kCLobbyLaunchGameHelp = "void CLobby.LaunchGame(self,gameConfig)";
  constexpr const char* kCLobbyDebugDumpHelp = "void CLobby.DebugDump()";
  constexpr const char* kCLobbySendDataHelp = "void CLobby.SendData(self,targetID,table)";
  constexpr const char* kCLobbyEjectPeerHelp = "void CLobby.EjectPeer(self,targetID,reason)";
  constexpr const char* kCLobbyDisconnectFromPeerHelp = "void CLobby.DisconnectFromPeer(self,uid";
  constexpr const char* kValidateIPAddressHelp = "str = ValidateIPAddress(ipaddr)";

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (rawState == nullptr) {
      return out;
    }

    const int stackTop = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);
    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(rawState, stackTop);
    return out;
  }

  /**
   * Address: 0x007C8D70 (FUN_007C8D70)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CLobby`.
   */
  [[nodiscard]] gpg::RType* CachedCLobbyRuntimeTypeBridge()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CLobby));
    }
    return cached;
  }

  struct LaunchPlayerOptionEntry
  {
    int32_t mSlotIndex{-1};
    LuaPlus::LuaObject mOptions;
  };
  static_assert(sizeof(LaunchPlayerOptionEntry) == 0x18, "LaunchPlayerOptionEntry size must be 0x18");

  /**
   * Address: 0x007CED70 (FUN_007CED70)
   *
   * What it does:
   * Copy-constructs one half-open launch-player-option range into destination
   * storage and returns the destination end pointer.
   */
  [[maybe_unused]] LaunchPlayerOptionEntry* CopyConstructLaunchPlayerOptionEntryRange(
    const LaunchPlayerOptionEntry* sourceBegin,
    LaunchPlayerOptionEntry* destinationBegin,
    const LaunchPlayerOptionEntry* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      if (destinationBegin != nullptr) {
        destinationBegin->mSlotIndex = sourceBegin->mSlotIndex;
        ::new (static_cast<void*>(&destinationBegin->mOptions)) LuaPlus::LuaObject(sourceBegin->mOptions);
      }
      ++sourceBegin;
      ++destinationBegin;
    }

    return destinationBegin;
  }

  /**
   * Address: 0x007CD090 (FUN_007CD090)
   *
   * What it does:
   * Register-shape adapter that forwards one launch-player-option
   * copy-construction range into the canonical lane.
   */
  [[maybe_unused]] LaunchPlayerOptionEntry* CopyConstructLaunchPlayerOptionEntryRangeAdapterA(
    const LaunchPlayerOptionEntry* const sourceBegin,
    LaunchPlayerOptionEntry* const destinationBegin,
    const LaunchPlayerOptionEntry* const sourceEnd
  )
  {
    return CopyConstructLaunchPlayerOptionEntryRange(sourceBegin, destinationBegin, sourceEnd);
  }

  /**
   * Address: 0x007CDD50 (FUN_007CDD50)
   *
   * What it does:
   * Secondary register-shape adapter for launch-player-option range
   * copy-construction.
   */
  [[maybe_unused]] LaunchPlayerOptionEntry* CopyConstructLaunchPlayerOptionEntryRangeAdapterB(
    const LaunchPlayerOptionEntry* const sourceBegin,
    LaunchPlayerOptionEntry* const destinationBegin,
    const LaunchPlayerOptionEntry* const sourceEnd
  )
  {
    return CopyConstructLaunchPlayerOptionEntryRange(sourceBegin, destinationBegin, sourceEnd);
  }

  /**
   * Address: 0x007CE890 (FUN_007CE890)
   *
   * What it does:
   * Third adapter lane for launch-player-option half-open range
   * copy-construction.
   */
  [[maybe_unused]] LaunchPlayerOptionEntry* CopyConstructLaunchPlayerOptionEntryRangeAdapterC(
    const LaunchPlayerOptionEntry* const sourceBegin,
    LaunchPlayerOptionEntry* const destinationBegin,
    const LaunchPlayerOptionEntry* const sourceEnd
  )
  {
    return CopyConstructLaunchPlayerOptionEntryRange(sourceBegin, destinationBegin, sourceEnd);
  }

  /**
   * Address: 0x007CC0E0 (FUN_007CC0E0)
   *
   * What it does:
   * Copy-assigns one half-open launch-player-option range from one prototype
   * record and returns the Lua-object lane pointer from the final assignment.
   */
  [[maybe_unused]] LuaPlus::LuaObject* CopyAssignLaunchPlayerOptionEntryRange(
    LaunchPlayerOptionEntry* destinationBegin,
    LaunchPlayerOptionEntry* destinationEnd,
    const LaunchPlayerOptionEntry& source
  )
  {
    LuaPlus::LuaObject* assignmentResult = reinterpret_cast<LuaPlus::LuaObject*>(destinationBegin);
    for (LaunchPlayerOptionEntry* destination = destinationBegin; destination != destinationEnd; ++destination) {
      destination->mSlotIndex = source.mSlotIndex;
      assignmentResult = &(destination->mOptions = source.mOptions);
    }
    return assignmentResult;
  }

  /**
   * Address: 0x007CD0B0 (FUN_007CD0B0)
   *
   * What it does:
   * Copies one launch-player-option prototype record from pointer form across
   * destination range and returns the final LuaObject assignment lane.
   */
  [[maybe_unused]] LuaPlus::LuaObject* CopyAssignLaunchPlayerOptionEntryRangeFromPointer(
    LaunchPlayerOptionEntry* const destinationBegin,
    const LaunchPlayerOptionEntry* const source,
    LaunchPlayerOptionEntry* const destinationEnd
  )
  {
    return CopyAssignLaunchPlayerOptionEntryRange(destinationBegin, destinationEnd, *source);
  }

  /**
   * Address: 0x007C0CA0 (FUN_007C0CA0)
   *
   * What it does:
   * Unlinks one intrusive peer-list head node from its current ring and
   * restores self-linked sentinel lanes.
   */
  [[maybe_unused]] moho::TDatListItem<moho::SPeer, void>* UnlinkPeerListHead(
    moho::TDatListItem<moho::SPeer, void>* const head
  ) noexcept
  {
    head->mPrev->mNext = head->mNext;
    head->mNext->mPrev = head->mPrev;
    head->mPrev = head;
    head->mNext = head;
    return head;
  }

  bool sLobbyIgnoreNamesConVarRegistered = false;

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "User") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  [[nodiscard]] bool TryRemoveReceiverLinkage(
    CMessageDispatcher& dispatcher,
    const unsigned int lower,
    const unsigned int upper,
    const IMessageReceiver* const receiver
  )
  {
    using LinkNode = TDatListItem<SMsgReceiverLinkage, void>;
    auto* const head = static_cast<LinkNode*>(&dispatcher);
    for (LinkNode* node = head->mNext; node != head; node = node->mNext) {
      auto* const linkage = static_cast<SMsgReceiverLinkage*>(node);
      if (
        linkage->mLower == lower && linkage->mUpper == upper &&
        linkage->mReceiver == const_cast<IMessageReceiver*>(receiver)
      ) {
        dispatcher.RemoveLinkage(linkage);
        return true;
      }
    }
    return false;
  }

  void DetachLobbyReceiverRanges(
    INetConnection* const connection,
    const IMessageReceiver* const receiver
  )
  {
    GPG_ASSERT(connection != nullptr);
    auto& dispatcher = *static_cast<CMessageDispatcher*>(connection);

    const bool removedLobbyBase = TryRemoveReceiverLinkage(dispatcher, MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, receiver);
    if (!removedLobbyBase) {
      GPG_UNREACHABLE("Reached the supposably unreachable.");
    }

    const bool removedLobbyJoin =
      TryRemoveReceiverLinkage(dispatcher, MSGTYPE_LobbyMsgStart, MSGTYPE_LobbyMsgEnd, receiver);
    if (!removedLobbyJoin) {
      GPG_UNREACHABLE("Reached the supposably unreachable.");
    }
  }

  [[nodiscard]] int32_t ParseOwnerId(
    const LuaPlus::LuaObject& ownerIdObject
  )
  {
    const char* const ownerIdStr = ownerIdObject.GetString();
    return std::atoi(ownerIdStr ? ownerIdStr : "");
  }

  /**
   * Address: 0x007CBC80 (FUN_007CBC80, func_GetIgnoreNames)
   *
   * std::vector<std::string> &,std::set<char> const &
   *
   * What it does:
   * Splits global `lob_IgnoreNames` CSV text into trimmed ignore-name tokens
   * used by `CLobby::ConnectToPeer`.
   */
  [[nodiscard]] msvc8::vector<msvc8::string> BuildLobbyIgnoreNameList()
  {
    msvc8::vector<msvc8::string> ignoreNames{};
    if (moho::lob_IgnoreNames.empty()) {
      return ignoreNames;
    }

    ignoreNames.reserve(8);
    SplitByComma(moho::lob_IgnoreNames, ignoreNames);
    return ignoreNames;
  }

  [[nodiscard]] bool IsPeerNameInIgnoreList(
    const msvc8::vector<msvc8::string>& ignoreNames,
    const msvc8::string& peerName
  ) noexcept
  {
    const std::size_t peerNameLength = peerName.size();
    const char* const peerNameText = peerName.c_str();

    for (const msvc8::string& ignoredName : ignoreNames) {
      if (ignoredName.size() != peerNameLength) {
        continue;
      }

      if (std::memcmp(ignoredName.c_str(), peerNameText, peerNameLength) == 0) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00C03930 (sub_C03930)
   *
   * What it does:
   * Unregisters `lob_IgnoreNames` from the global console registry at process shutdown.
   */
  void UnregisterLobbyIgnoreNamesConVarDefinition()
  {
    if (!sLobbyIgnoreNamesConVarRegistered) {
      return;
    }

    UnregisterConCommand(moho::ConVar_lob_IgnoreNames);
    sLobbyIgnoreNamesConVarRegistered = false;
  }

  /**
   * Address: 0x00BDFD50 (register_lob_IgnoreNames_ConVarDef)
   *
   * What it does:
   * Registers `lob_IgnoreNames` convar once and wires shutdown teardown.
   */
  void RegisterLobbyIgnoreNamesConVarDefinition()
  {
    if (sLobbyIgnoreNamesConVarRegistered) {
      return;
    }

    RegisterConCommand(moho::ConVar_lob_IgnoreNames);
    sLobbyIgnoreNamesConVarRegistered = true;
    std::atexit(&UnregisterLobbyIgnoreNamesConVarDefinition);
  }

  // Binary uses static initializer hooks for this convar; mirror that once-per-process registration.
  [[maybe_unused]] const bool sLobbyIgnoreNamesConVarInit = []() {
    RegisterLobbyIgnoreNamesConVarDefinition();
    return true;
  }();
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CLobby> CScrLuaMetatableFactory<CLobby>::sInstance{};

  CScrLuaMetatableFactory<CLobby>& CScrLuaMetatableFactory<CLobby>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CLobby>::Create(
    LuaPlus::LuaState* const state
  )
  {
    return SCR_CreateSimpleMetatable(state);
  }
} // namespace moho

/**
 * Address: 0x007C0780 (FUN_007C0780)
 *
 * What it does:
 * Returns cached reflection type for `CLobby`.
 */
gpg::RType* CLobby::GetClass() const
{
  return CachedCLobbyRuntimeTypeBridge();
}

/**
 * Address: 0x007C07A0 (FUN_007C07A0)
 *
 * What it does:
 * Returns reflection reference `{this, GetClass()}`.
 */
gpg::RRef CLobby::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x007C0970 (FUN_007C0970)
 * Mangled: ??0CLobby@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVINetConnector@1@H_NVStrArg@gpg@@H@Z
 *
 * LuaPlus::LuaObject const &,Moho::INetConnector *,int,bool,gpg::StrArg,int
 *
 * What it does:
 * Initializes Lua lobby object state, seeds local lobby identity fields, then
 * wires one manual-reset event to connector select + wait-handle dispatch.
 */
CLobby::CLobby(
  const LuaPlus::LuaObject& clazz,
  INetConnector* const connectorArg,
  const int32_t maxConnectionsArg,
  const bool hasNAT,
  const gpg::StrArg playerName,
  const int32_t localUidArg
)
  : CScriptObject(clazz, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
  , connector(connectorArg)
  , maxConnections(maxConnectionsArg)
  , mHasNAT(hasNAT)
  , localUid(localUidArg)
{
  if (localUidArg != -1) {
    gpg::Logf("LOBBY: starting with local uid of %d [%s]", localUidArg, playerName);
  }

  const gpg::StrArg requestedPlayerName = playerName ? playerName : "";
  this->playerName = MakeValidPlayerName(msvc8::string(requestedPlayerName), localUidArg);

  event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (event == nullptr) {
    const msvc8::string errorText = WIN_GetLastError();
    throw std::runtime_error(gpg::STR_Printf("CreateEvent() call failed: %s", errorText.c_str()).c_str());
  }

  this->connector->SelectEvent(event);
  WIN_GetWaitHandleSet()->AddHandle(event);
  (void)UnlinkPeerListHead(&peers);
}

/**
 * Address: 0x007C0C60 (FUN_007C0C60 deleting wrapper)
 * Address: 0x007C1180 (FUN_007C1180, ?1CLobby@Moho@@UAE@XZ non-deleting body)
 *
 * What it does:
 * Releases connector/socket wait handles and destroys all peer/session links.
 */
CLobby::~CLobby()
{
  if (mSocket != nullptr) {
    WIN_GetWaitHandleSet()->RemoveHandle(mSocket->CreateEvent());
  }

  if (connector != nullptr) {
    for (SPeer* peer : peers.owners()) {
      if (peer->peerConnection != nullptr) {
        peer->peerConnection->ScheduleDestroy();
        peer->peerConnection = nullptr;
      }
    }
    connector->Push();
    connector->Destroy();
    connector = nullptr;
  }

  if (event != nullptr) {
    WIN_GetWaitHandleSet()->RemoveHandle(event);
    CloseHandle(event);
    event = nullptr;
  }

  while (!peers.empty()) {
    delete static_cast<SPeer*>(peers.mNext);
  }

  (void)UnlinkPeerListHead(&peers);
  mSocket.reset();
}

msvc8::string CLobby::GetErrorDescription()
{
  return CScriptObject::GetErrorDescription();
}

SPeer* CLobby::FindPeerByConnection(
  const INetConnection* connection
)
{
  for (SPeer* peer : peers.owners()) {
    if (peer->peerConnection == connection) {
      return peer;
    }
  }
  return nullptr;
}

SPeer* CLobby::FindPeerByUid(
  const int32_t uid
)
{
  for (SPeer* peer : peers.owners()) {
    if (peer->uid == uid) {
      return peer;
    }
  }
  return nullptr;
}

/**
 * Address: 0x007C62F0 (FUN_007C62F0)
 *
 * Callsite: 0x00487885
 */
void CLobby::ReceiveMessage(
  CMessage* message,
  CMessageDispatcher* dispatcher
)
{
  // CNetUDPConnection is caller, which have INetConnection `[dispatcher - 4].mReceivers[255]`.
  const auto connection = static_cast<INetConnection*>(dispatcher);

  switch (const ELobbyMsg type = message->GetType()) { // NOLINT(clang-diagnostic-switch-enum)
  case ELobbyMsg::LOBMSG_Join:
    OnJoin(message, connection);
    break;
  case ELobbyMsg::LOBMSG_Rejected:
    if (connection == peerConnection) {
      OnRejected(message, connection);
    }
    break;
  case ELobbyMsg::LOBMSG_Welcome:
    OnWelcome(message, connection);
    break;
  case ELobbyMsg::LOBMSG_NewPeer:
    OnNewPeer(message, connection);
    break;
  case ELobbyMsg::LOBMSG_DeletePeer:
    OnDeletePeer(message, connection);
    break;
  case ELobbyMsg::LOBMSG_EstablishedPeers:
    OnEstablishedPeers(message, connection);
    break;
  case ELobbyMsg::LOBMSG_BroadcastScriptData:
  case ELobbyMsg::LOBMSG_DirectScriptData:
    OnScriptData(message, connection);
    break;
  case ELobbyMsg::LOBMSG_ConnFailed:
    OnConnectionFailed(message, connection);
    break;
  case ELobbyMsg::LOBMSG_ConnMade:
    OnConnectionMade(message, connection);
    break;
  case ELobbyMsg::LOBMSG_ConnLostErrored:
  case ELobbyMsg::LOBMSG_ConnLostEof:
    OnConnectionLost(message, connection);
    break;
  default:
    gpg::Logf("LOBBY: Ignoring unrecognized lobby message w/ type %d", static_cast<int32_t>(type));
    break;
  }
}

/**
 * Address: 0x007C5840 (?HandleMessage@CLobby@@...)
 * Address: 0x1038DA40 (?OnDatagram@CLobby@Moho@@...)
 *
 * What it does:
 * Handles incoming lobby datagrams and replies to discovery requests.
 */
void CLobby::OnDatagram(
  CMessage* msg,
  INetDatagramSocket* sock,
  const u_long address,
  const u_short port
)
{
  if (!msg || !sock) {
    return;
  }

  const auto data = reinterpret_cast<const uint8_t*>(msg->mBuff.start_);
  const size_t size = msg->mBuff.Size();
  if (!data || size == 0) {
    return;
  }

  const msvc8::string hostName = NET_GetHostName(address);

  if (msg->GetType() != ELobbyMsg::LOBMSG_DiscoveryRequest) {
    gpg::Logf(
      "LOBBY: ignoring unexpected message type (%d) from %s:%d",
      static_cast<int>(data[0]),
      hostName.c_str(),
      static_cast<unsigned>(port)
    );
    return;
  }

  gpg::Logf("LOBBY: received discovery request from %s:%d", hostName.c_str(), static_cast<unsigned>(port));

  LuaPlus::LuaObject cfg;
  RunScriptObj(cfg, "GameConfigRequested");

  CMessage reply(ELobbyMsg::LOBMSG_DiscoveryResponse);
  CMessageStream s(reply);

  // Fixed header observed in the binary: 0x0B, 0x01, 0x00
  s.Write(static_cast<uint8_t>(0x0B));
  s.Write(static_cast<uint8_t>(0x01));
  s.Write(static_cast<uint8_t>(0x00));

  s.Write(static_cast<uint8_t>(connector->GetProtocol()));
  s.Write(connector->GetLocalPort());

  if (cfg.ToByteStream(s)) {
    sock->Send(&reply, address, port);
  } else {
    gpg::Warnf("Error serializing lua game config.");
  }
}

/**
 * Address: 0x007C64C0 (FUN_007C64C0)
 */
void CLobby::OnJoin(
  CMessage* message,
  INetConnection* connection
)
{
  CMessageStream stream{message};
  const gpg::BinaryReader br{&stream};

  msvc8::string joiningName;
  br.ReadString(&joiningName);

  std::uint32_t requestedUid = 0;
  br.ReadExact(requestedUid);

  SPeer* player = FindPeerByConnection(connection);

  if (player == nullptr) {
    gpg::Logf("LOBBY: ignoring unexpected join (no player for conn=%p)", connection);
    return;
  }

  if (player->state != ENetworkPlayerState::kWaitingJoin) {
    const msvc8::string who = player->ToString();
    gpg::Logf(
      "LOBBY: ignoring unexpected join (name=\"%s\", uid=%d) from %s", joiningName.c_str(), requestedUid, who.c_str()
    );
    return;
  }

  const auto fromStr = connection->ToString();
  gpg::Logf("LOBBY: Got join (name=\"%s\", uid=%u) from %s", joiningName.c_str(), requestedUid, fromStr.c_str());

  bool canAccept = true;
  // host
  if (peerConnection == nullptr) {
    int32_t connectedPlayersCount = 0;
    for (SPeer* it : peers.owners()) {
      if (it->state == ENetworkPlayerState::kEstablished) {
        connectedPlayersCount++;
      }
    }

    if (connectedPlayersCount >= maxConnections) {
      canAccept = false;
    }
  }

  if (!canAccept) {
    CMessage lobbyFull(ELobbyMsg::LOBMSG_Rejected);
    CMessageStream lobbyFullStream{&lobbyFull};
    lobbyFullStream.Write("LobbyFull");

    connection->Write(lobbyFullStream);
    connection->ScheduleDestroy();
    return;
  }

  player->state = ENetworkPlayerState::kEstablished;
  peersDirty = true; // meaning "changed/dirty" ?

  if (player->uid == -1) {
    player->uid = mNextId++;
    gpg::Logf("LOBBY: assigning uid %d", player->uid);
  }

  CMessage accept(ELobbyMsg::LOBMSG_Welcome);
  CMessageStream acceptStream{&accept};
  if (peerConnection == nullptr) {
    const auto normalized = MakeValidPlayerName(joiningName, player->uid);
    player->playerName.assign(normalized, 0, msvc8::string::npos);

    // Payload from the dump: hostName, hostUid, assignedUid, joiningNameConfirmed, hostedTime.
    acceptStream.Write(playerName);
    acceptStream.Write(localUid);
    acceptStream.Write(player->uid);
    acceptStream.Write(player->playerName);
    acceptStream.Write(hostedTime);
  }
  connection->Write(acceptStream);

  LuaPlus::LuaState* l = mLuaObj.GetActiveState();
  const msvc8::string locMsg = Loc(l, "<LOC Engine0004>Connection to %s established.");
  Msgf(locMsg.c_str(), player->playerName.c_str());

  if (peerConnection == nullptr && mHasNAT) {
    for (SPeer* it : peers.owners()) {
      if (it->state == ENetworkPlayerState::kEstablished && it != player) {
        it->SendInfoTo(connection);
        player->SendInfoTo(it->peerConnection);
      }
    }
  }
}

/**
 * Address: 0x007C6AD0 (FUN_007C6AD0)
 */
void CLobby::OnRejected(
  CMessage* message,
  [[maybe_unused]] INetConnection* connection
)
{
  CMessageStream s(message, CMessageStream::Access::kReadOnly);
  const gpg::BinaryReader br{&s};
  msvc8::string reason;
  br.ReadString(&reason);

  const char* str = reason.c_str();
  CallbackStr("Ejected", &str);
}

/**
 * Address: 0x007C6BD0 (FUN_007C6BD0)
 */
void CLobby::OnWelcome(
  CMessage* message,
  const INetConnection* connection
)
{
  SPeer* peer = FindPeerByConnection(connection);

  if (peer == nullptr || peer->state != ENetworkPlayerState::kConnected) {
    gpg::Logf("LOBBY: ignoring unexpected welcome message.");
    return;
  }

  peer->state = ENetworkPlayerState::kEstablished;
  peersDirty = true;

  if (connection == peerConnection) {
    // If this is a host.
    CMessageStream s(message, CMessageStream::Access::kReadOnly);
    const gpg::BinaryReader br{&s};

    msvc8::string hostDisplayName; // v20
    int32_t hostUid = 0;           // v17 (read as 4 bytes)
    int32_t assignedUid = 0;       // v16 (read as 4 bytes)
    msvc8::string renameSelfTo;    // v19
    int32_t sessionOrSeq = 0;      // v18 -> hostedTime

    br.ReadString(&hostDisplayName);
    br.ReadExact(hostUid);
    br.ReadExact(assignedUid);
    br.ReadString(&renameSelfTo);
    br.ReadExact(sessionOrSeq);

    hostedTime = sessionOrSeq;

    // If host peer doesn't yet have uid, adopt and copy its display name
    if (peer->uid == -1) {
      peer->uid = hostUid;
      peer->playerName = hostDisplayName;
      gpg::Logf("LOBBY: welcomed by host \"%s\" (uid=%u)", hostDisplayName.c_str(), hostUid);
    }

    // Adopt our own local UID if not set; otherwise warn on mismatch
    if (localUid == -1) {
      localUid = assignedUid;
      gpg::Logf("LOBBY: assigned uid of %u by host", assignedUid);
    } else if (localUid != assignedUid) {
      gpg::Logf("LOBBY: host thinks our uid is %u, but we think it is %u", assignedUid, localUid);
    }

    // If host wants to rename us, apply
    if (!renameSelfTo.empty()) {
      gpg::Logf("LOBBY: host renamed us to %s", renameSelfTo.c_str());
      playerName = renameSelfTo;
    }

    // IDs in decimal text (original: base=10, buf size ~10)
    char hostPeerUidBuf[kPlayerUidBufSize]{};
    char localPeerUidBuf[kPlayerUidBufSize]{};
    std::to_chars(hostPeerUidBuf, hostPeerUidBuf + kPlayerUidBufSize, peer->uid);
    std::to_chars(localPeerUidBuf, localPeerUidBuf + kPlayerUidBufSize, localUid);

    const char* pHost = hostPeerUidBuf;
    const char* pLocal = localPeerUidBuf;
    const char* pName = const_cast<char*>(playerName.c_str());

    ProcessConnectionToHostEstablished(&pLocal, &pName, &pHost);
  }

  LuaPlus::LuaState* l = mLuaObj.GetActiveState();
  const msvc8::string locMsg = Loc(l, "<LOC Engine0004>Connection to %s established.");
  Msgf(locMsg.c_str(), peer->playerName.c_str());
}

/**
 * Address: 0x007C7010 (FUN_007C7010)
 */
void CLobby::OnNewPeer(
  CMessage* message,
  INetConnection* connection
)
{
  if (connection != peerConnection) {
    // If this is not a host.
    const auto connStr = connection->ToString();
    gpg::Logf("LOBBY: ignoring NewPeer msg from %s.", connStr.c_str());
    return;
  }

  CMessageStream s(message, CMessageStream::Access::kReadOnly);
  const gpg::BinaryReader br{&s};

  msvc8::string name{};
  u_long host{0};
  u_short port{0};
  int32_t uid{0};

  br.ReadString(&name);
  br.ReadExact(host);
  br.ReadExact(port);
  br.ReadExact(uid);

  ConnectToPeer(host, port, name, uid);
}

/**
 * Address: 0x007C76A0 (FUN_007C76A0)
 */
void CLobby::OnDeletePeer(
  CMessage* message,
  INetConnection* connection
)
{
  if (connection != peerConnection) {
    // If this is not a host.
    const auto connStr = connection->ToString();
    gpg::Logf("LOBBY: ignoring DeletePeer msg from %s.", connStr.c_str());
    return;
  }

  CMessageStream s(message, CMessageStream::Access::kReadOnly);
  const gpg::BinaryReader br{&s};

  int32_t uid{0};
  br.ReadExact(uid);

  DisconnectFromPeer(uid);
}

/**
 * Address: 0x007C7C10 (FUN_007C7C10)
 */
void CLobby::OnEstablishedPeers(
  CMessage* message,
  INetConnection* connection
)
{
  SPeer* peer = FindPeerByConnection(connection);

  if (peer == nullptr) {
    const msvc8::string connStr = connection->ToString();
    gpg::Logf("LOBBY: ignoring EstablishedPeers message from unknown connection %s.", connStr.c_str());
    return;
  }

  peer->establishedUids.clear();

  CMessageStream s(message, CMessageStream::Access::kReadOnly);
  const gpg::BinaryReader br{&s};

  while (true) {
    int32_t uid = 0;
    br.ReadExact(uid);
    if (uid == -1) {
      break;
    }
    peer->establishedUids.insert(uid);
  }

  msvc8::string joined;
  for (const int32_t uid : peer->establishedUids) {
    if (!joined.empty()) {
      joined.append(", ", 2);
    }

    joined.append(gpg::STR_Printf("%d", uid).c_str());
  }

  gpg::Logf("LOBBY: %s has established connections to: %s", peer->ToString().c_str(), joined.c_str());

  LuaPlus::LuaObject obj;
  obj.AssignNewTable(mLuaObj.GetActiveState(), 0, 0);

  int idx = 1;
  char idBuf[kPlayerUidBufSize]{};
  for (const auto uid : peer->establishedUids) {
    std::to_chars(idBuf, idBuf + kPlayerUidBufSize, uid);
    obj.SetString(idx++, idBuf);
  }

  char selfId[kPlayerUidBufSize]{};
  std::to_chars(selfId, selfId + kPlayerUidBufSize, peer->uid);

  RunScript("EstablishedPeers", selfId, &obj);
}

/**
 * Address: 0x007C6EE0 (FUN_007C6EE0)
 */
void CLobby::OnScriptData(
  CMessage* message,
  INetConnection* connection
)
{
  CMessageStream s(message, CMessageStream::Access::kReadOnly);
  const gpg::BinaryReader br{&s};

  LuaPlus::LuaObject script;
  mLuaObj.SCR_FromByteStream(script, mLuaObj.m_state, &br);

  const SPeer* peer = FindPeerByConnection(connection);

  char idBuf[kPlayerUidBufSize]{};
  if (peer != nullptr) {
    std::to_chars(idBuf, idBuf + kPlayerUidBufSize, peer->uid);
    script.SetString("SenderID", idBuf);
    script.SetString("SenderName", peer->playerName.c_str());
  } else {
    std::to_chars(idBuf, idBuf + kPlayerUidBufSize, 0);
    script.SetString("SenderID", idBuf);

    const msvc8::string connStr = connection ? connection->ToString() : msvc8::string{};
    script.SetString("SenderName", connStr.c_str());
  }

  LuaCall("DataReceived", &script);
}

/**
 * Address: 0x007C5B60 (FUN_007C5B60)
 */
void CLobby::OnConnectionFailed(
  [[maybe_unused]] CMessage* message,
  INetConnection* connection
)
{
  if (connection == peerConnection) {
    // If this is not a host.
    gpg::Logf("LOBBY: connection to master failed -- giving up.");
    auto reason = "HostLeft";
    CallbackStr("ConnectionFailed", &reason);
    return;
  }

  SPeer* peer = FindPeerByConnection(connection);

  const auto peerStr = peer->ToString();
  gpg::Logf("LOBBY: connection to %s failed, retrying...", peerStr.c_str());

  INetConnection* newConn = connector->Connect(peer->address, peer->port);
  peer->peerConnection = newConn;

  // Subscribe lobby as receiver for a message range [0xC8..0xD2]
  newConn->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);

  connection->ScheduleDestroy();
}

/**
 * Address: 0x007C5CA0 (FUN_007C5CA0)
 */
void CLobby::OnConnectionMade(
  [[maybe_unused]] const CMessage* message,
  INetConnection* connection
)
{
  SPeer* peer = FindPeerByConnection(connection);

  msvc8::string peerStateStr;
  ENetworkPlayerStateToStr(peer->state, peerStateStr);
  const msvc8::string who = peer->ToString();
  gpg::Logf("LOBBY: connection to %s made, status=%s.", who.c_str(), peerStateStr.c_str());

  if (peer->state == ENetworkPlayerState::kConnecting) {
    peer->state = ENetworkPlayerState::kConnected;
    connection->PushReceiver(MSGTYPE_LobbyMsgStart, MSGTYPE_LobbyMsgEnd, this);

    CMessage msg(ELobbyMsg::LOBMSG_Join);
    CMessageStream s(msg, CMessageStream::Access::kReadWrite);

    s.Write(playerName);
    s.Write(localUid);

    connection->Write(s);
  } else {
    if (peer->state != ENetworkPlayerState::kPending) {
      GPG_UNREACHABLE("unreachable")
    }

    peer->state = ENetworkPlayerState::kWaitingJoin;
    connection->PushReceiver(MSGTYPE_LobbyMsgStart, MSGTYPE_LobbyMsgEnd, this);
  }
}

/**
 * Address: 0x007C5ED0 (FUN_007C5ED0)
 *
 * What it does:
 * Handles connection-loss state transitions and reconnect/eject behavior.
 */
void CLobby::Reconnect(INetConnection* connection)
{
  if (connection == peerConnection) {
    // If this is not a host.
    gpg::Logf("LOBBY: host disconnected.");
    auto reason = "HostLeft";
    CallbackStr("ConnectionFailed", &reason);
    return;
  }

  SPeer* peer = FindPeerByConnection(connection);

  switch (peer->state) {
  case ENetworkPlayerState::kConnecting:
  case ENetworkPlayerState::kConnected: {
    const auto peerStr = peer->ToString();
    gpg::Logf("LOBBY: connection to %s lost, retrying", peerStr.c_str());
    const auto newConn = connector->Connect(peer->address, peer->port);
    peer->peerConnection = newConn;
    newConn->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
    peer->state = ENetworkPlayerState::kConnecting;
    connection->ScheduleDestroy();
    break;
  }
  case ENetworkPlayerState::kPending:
    GPG_UNREACHABLE("unreachable")
    break;
  case ENetworkPlayerState::kWaitingJoin: {
    const auto peerStr = peer->ToString();
    gpg::Logf("LOBBY: lost connection to %s, waiting for them to reconnect.", peerStr.c_str());
    peer->state = ENetworkPlayerState::kPending;
    const auto newConn = connector->Accept(peer->address, peer->port);
    peer->peerConnection = newConn;
    newConn->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
    connection->ScheduleDestroy();
    break;
  }
  case ENetworkPlayerState::kEstablished: {
    peersDirty = true;
    const auto peerStr = peer->ToString();
    if (peerConnection != nullptr || !mHasNAT) {
      gpg::Logf("LOBBY: lost connection to %s, waiting for them to reconnect.", peerStr.c_str());

      LuaPlus::LuaState* l = mLuaObj.GetActiveState();
      const msvc8::string locMsg = Loc(l, "<LOC Engine0003>Lost connection to %s.");
      Msgf(locMsg.c_str(), peer->playerName.c_str());

      INetConnection* newConn;
      if (peer->uid < localUid && peerConnection != nullptr) {
        newConn = connector->Connect(peer->address, peer->port);
        peer->state = ENetworkPlayerState::kConnecting;
      } else {
        newConn = connector->Accept(peer->address, peer->port);
        peer->state = ENetworkPlayerState::kPending;
      }

      peer->peerConnection = newConn;
      newConn->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
      connection->ScheduleDestroy();
    } else {
      gpg::Logf("LOBBY: lost connection to %s, ejecting 'em.", peerStr.c_str());

      LuaPlus::LuaState* l = mLuaObj.GetActiveState();
      const msvc8::string locMsg = Loc(l, "<LOC Engine0002>%s disconnected.");
      Msgf(locMsg.c_str(), peer->playerName.c_str());

      peer->state = ENetworkPlayerState::kDisconnected;
      peersDirty = true;

      KickPeer(peer, "Disconnected");
    }
    break;
  }
  default:
    GPG_UNREACHABLE("unreachable")
    break;
  }
}

/**
 * Address: 0x007C62E0 (FUN_007C62E0)
 *
 * What it does:
 * Adapts one message-receiver callback lane into `CLobby::Reconnect`.
 */
void CLobby::OnConnectionLost(
  [[maybe_unused]] CMessage* message,
  INetConnection* connection
)
{
  Reconnect(connection);
}

/**
 * Address: 0x007C77F0 (FUN_007C77F0)
 */
void CLobby::PeerDisconnected(
  SPeer* peer
)
{
  peer->peerConnection->ScheduleDestroy();
  peer->ListUnlink();

  char idBuf[kPlayerUidBufSize]{};
  std::to_chars(idBuf, idBuf + kPlayerUidBufSize, peer->uid);

  const char* uidStr = idBuf;
  const char* nameStr = peer->playerName.c_str();
  CallbackStr("PeerDisconnected", &uidStr, &nameStr);

  if (peer->state == ENetworkPlayerState::kEstablished || peer->state == ENetworkPlayerState::kDisconnected) {
    peersDirty = true;
  }

  if (peerConnection == nullptr && mHasNAT) {
    CMessage msg(ELobbyMsg::LOBMSG_DeletePeer);
    CMessageStream s(msg, CMessageStream::Access::kReadWrite);

    s.Write(localUid);

    BroadcastStream(s);
  }

  delete peer;
}

/**
 * Address: 0x007C8040 (FUN_007C8040)
 */
void CLobby::BroadcastStream(
  const CMessageStream& s
)
{
  for (SPeer* it : peers.owners()) {
    if (it->state == ENetworkPlayerState::kEstablished) {
      it->peerConnection->Write(s);
    }
  }
}

/**
 * Address: 0x007C1720 (FUN_007C1720)
 */
msvc8::string CLobby::MakeValidPlayerName(
  msvc8::string joiningName,
  const int32_t uid
)
{
  static constexpr std::size_t maxLen = 24;

  const msvc8::string desired = joiningName;
  if (joiningName.size() > maxLen) {
    joiningName = desired.substr(0, maxLen);
  }

  int suffix = 1;
  while (true) {
    if (uid == localUid) {
      break;
    }

    if (gpg::STR_CompareNoCase(playerName.c_str(), joiningName.c_str()) == 0) {
      msvc8::string num = gpg::STR_Printf("%d", suffix++);
      const std::size_t keep = (num.size() < maxLen) ? (maxLen - num.size()) : 0;
      joiningName = desired.substr(0, keep) + num;
      continue;
    }

    bool conflict = false;
    for (SPeer* it : peers.owners()) {
      if (it->uid == uid) {
        continue;
      }

      if (gpg::STR_CompareNoCase(it->playerName.c_str(), joiningName.c_str()) == 0) {
        msvc8::string num = gpg::STR_Printf("%d", suffix++);
        const std::size_t keep = (num.size() < maxLen) ? (maxLen - num.size()) : 0;
        joiningName = desired.substr(0, keep) + num;
        conflict = true;
        break;
      }
    }

    if (conflict) {
      continue;
    }

    break;
  }

  return joiningName;
}

/**
 * Address: 0x007C0060 (FUN_007C0060, cfunc_InternalCreateDiscoveryService)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateDiscoveryServiceL`.
 */
int moho::cfunc_InternalCreateDiscoveryService(lua_State* const luaContext)
{
  return cfunc_InternalCreateDiscoveryServiceL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C00E0 (FUN_007C00E0, cfunc_InternalCreateDiscoveryServiceL)
 *
 * What it does:
 * Validates one class argument, constructs one `CDiscoveryService`, and pushes
 * its script object back to Lua.
 */
int moho::cfunc_InternalCreateDiscoveryServiceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateDiscoveryServiceHelp, 1, argumentCount);
  }

  const LuaPlus::LuaObject classObject(LuaPlus::LuaStackObject(state, 1));
  CDiscoveryService* const discoveryService = new CDiscoveryService(classObject);
  discoveryService->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007C0080 (FUN_007C0080, func_InternalCreateDiscoveryService_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateDiscoveryService(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateDiscoveryService_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateDiscoveryService",
    &moho::cfunc_InternalCreateDiscoveryService,
    nullptr,
    "<global>",
    kInternalCreateDiscoveryServiceHelp
  );
  return &binder;
}

/**
 * Address: 0x007C0CC0 (FUN_007C0CC0, cfunc_InternalCreateLobby)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InternalCreateLobbyL`.
 */
int moho::cfunc_InternalCreateLobby(lua_State* const luaContext)
{
  return cfunc_InternalCreateLobbyL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007CB690 (FUN_007CB690, func_GetCObj_NatTraversalProvider)
 *
 * What it does:
 * Unwraps Lua boxed userdata payload and returns the typed
 * `boost::weak_ptr<INetNATTraversalProvider>` slot.
 */
boost::weak_ptr<moho::INetNATTraversalProvider>* moho::func_GetCObj_NatTraversalProvider(
  LuaPlus::LuaObject valueObject
)
{
  if (valueObject.IsTable()) {
    valueObject = valueObject.GetByName("_c_object");
  }

  const gpg::RRef userDataRef = ExtractLuaUserDataRef(valueObject);
  const gpg::RRef upcastRef = gpg::REF_UpcastPtr(userDataRef, gpg::ResolveWeakPtrINetNATTraversalProviderType());
  auto* const providerSlot = static_cast<boost::weak_ptr<INetNATTraversalProvider>*>(upcastRef.mObj);
  if (providerSlot == nullptr) {
    throw std::bad_cast{};
  }
  return providerSlot;
}

/**
 * Address: 0x007C0D40 (FUN_007C0D40, cfunc_InternalCreateLobbyL)
 *
 * What it does:
 * Validates and decodes one `InternalCreateLobby(...)` Lua call, resolves
 * connector/NAT lanes, constructs `CLobby`, and pushes the lobby Lua object.
 */
int moho::cfunc_InternalCreateLobbyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 7) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateLobbyHelp, 7, argumentCount);
  }

  const LuaPlus::LuaObject clazz(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject protocolArg(state, 2);
  const char* const protocolText = lua_tostring(state->m_state, 2);
  if (protocolText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&protocolArg, "string");
  }
  const ENetProtocolType protocol = NET_ProtocolFromString(protocolText ? protocolText : "");

  LuaPlus::LuaStackObject localPortArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&localPortArg, "integer");
  }
  const int localPort = static_cast<int>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject maxConnectionsArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxConnectionsArg, "integer");
  }
  const int maxConnections = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject playerNameArg(state, 5);
  const char* const playerName = lua_tostring(state->m_state, 5);
  if (playerName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&playerNameArg, "string");
  }

  int uid = -1;
  if (lua_type(state->m_state, 6) != LUA_TNIL) {
    LuaPlus::LuaStackObject uidArg(state, 6);
    const char* const uidText = lua_tostring(state->m_state, 6);
    if (uidText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&uidArg, "string");
    }
    uid = std::atoi(uidText ? uidText : "");
  }

  boost::weak_ptr<INetNATTraversalProvider> natTraversalProvider{};
  if (lua_type(state->m_state, 7) != LUA_TNIL) {
    const LuaPlus::LuaObject natTraversalProviderObject(LuaPlus::LuaStackObject(state, 7));
    natTraversalProvider = *func_GetCObj_NatTraversalProvider(natTraversalProviderObject);
  }

  boost::weak_ptr<INetNATTraversalProvider> liveNatTraversalProvider{};
  if (!natTraversalProvider.expired()) {
    liveNatTraversalProvider = natTraversalProvider;
  }
  const bool noNatTraversalProvider = (liveNatTraversalProvider.use_count() == 0);

  INetConnector* connector = nullptr;
  if (protocol == ENetProtocolType::kTcp) {
    connector = NET_MakeTCPConnector(static_cast<u_short>(localPort));
  } else if (protocol == ENetProtocolType::kUdp) {
    connector = NET_MakeUDPConnector(static_cast<u_short>(localPort), liveNatTraversalProvider);
  } else {
    connector = new (std::nothrow) CNetNullConnector();
  }

  if (connector == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const msvc8::string protocolName = NET_GetProtocolName(protocol);
  const u_short gamePort = connector->GetLocalPort();
  gpg::Logf("LOBBY: Game port %d[%s] opened.", gamePort, protocolName.c_str());

  CLobby* const lobby = new CLobby(clazz, connector, maxConnections, noNatTraversalProvider, playerName, uid);
  lobby->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007C0CE0 (FUN_007C0CE0, func_InternalCreateLobby_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateLobby(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateLobby_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateLobby",
    &moho::cfunc_InternalCreateLobby,
    nullptr,
    "<global>",
    kInternalCreateLobbyHelp
  );
  return &binder;
}

/**
 * Address: 0x00BDFDD0 (FUN_00BDFDD0, register_InternalCreateDiscoveryService_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_InternalCreateDiscoveryService_LuaFuncDef()
{
  return func_InternalCreateDiscoveryService_LuaFuncDef();
}

/**
 * Address: 0x00BDFE50 (FUN_00BDFE50, register_InternalCreateLobby_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_InternalCreateLobby_LuaFuncDef()
{
  return func_InternalCreateLobby_LuaFuncDef();
}

/**
 * Address: 0x007C13E0 (FUN_007C13E0, cfunc_CLobbyDestroy)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyDestroyL`.
 */
int moho::cfunc_CLobbyDestroy(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyDestroyL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C1400 (FUN_007C1400, func_CLobbyDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:Destroy`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CLobbyDestroy,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyDestroyHelp
  );
  return &binder;
}

/**
 * Address: 0x007C1460 (FUN_007C1460, cfunc_CLobbyDestroyL)
 *
 * What it does:
 * Validates one Lua `self` arg, resolves optional `CLobby*`, and deletes it
 * when present.
 */
int moho::cfunc_CLobbyDestroyL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyDestroyHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobbyOpt(lobbyObject, state);
  if (lobby) {
    delete lobby;
  }

  return 0;
}

/**
 * Address: 0x007C1510 (FUN_007C1510, func_MakeValidGameName)
 *
 * What it does:
 * Returns one copy of `sourceName` truncated to at most 32 bytes.
 */
[[nodiscard]] msvc8::string MakeValidGameName(
  const msvc8::string& sourceName
)
{
  return sourceName.substr(0, 32u);
}

/**
 * Address: 0x007C15B0 (FUN_007C15B0, cfunc_CLobbyMakeValidGameNameL)
 *
 * What it does:
 * Validates `(self, origName)` Lua args, normalizes game name length to 32
 * bytes, and pushes the sanitized result.
 */
int moho::cfunc_CLobbyMakeValidGameNameL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kCLobbyMakeValidGameNameHelp, 2, argumentCount
    );
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CLobbyOpt(lobbyObject, state);

  LuaPlus::LuaStackObject originalNameArg(state, 2);
  const char* const originalNameText = lua_tostring(state->m_state, 2);
  if (originalNameText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&originalNameArg, "string");
  }

  const msvc8::string validName = MakeValidGameName(msvc8::string(originalNameText ? originalNameText : ""));
  lua_pushstring(state->m_state, validName.c_str());
  return 1;
}

/**
 * Address: 0x007C1530 (FUN_007C1530, cfunc_CLobbyMakeValidGameName)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyMakeValidGameNameL`.
 */
int moho::cfunc_CLobbyMakeValidGameName(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyMakeValidGameNameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C1550 (FUN_007C1550, func_CLobbyMakeValidGameName_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:MakeValidGameName`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyMakeValidGameName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "MakeValidGameName",
    &moho::cfunc_CLobbyMakeValidGameName,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyMakeValidGameNameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C18D0 (FUN_007C18D0, cfunc_CLobbyMakeValidPlayerName)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyMakeValidPlayerNameL`.
 */
int moho::cfunc_CLobbyMakeValidPlayerName(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyMakeValidPlayerNameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C1950 (FUN_007C1950, cfunc_CLobbyMakeValidPlayerNameL)
 *
 * What it does:
 * Validates `(self, uid, name)` Lua args, normalizes the requested name via
 * `CLobby::MakeValidPlayerName`, and pushes the sanitized result.
 */
int moho::cfunc_CLobbyMakeValidPlayerNameL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kCLobbyMakeValidPlayerNameHelp, 3, argumentCount
    );
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobbyOpt(lobbyObject, state);

  LuaPlus::LuaStackObject uidArg(state, 2);
  const char* const uidText = lua_tostring(state->m_state, 2);
  if (uidText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&uidArg, "string");
  }
  const int32_t uid = std::atoi(uidText ? uidText : "");

  LuaPlus::LuaStackObject nameArg(state, 3);
  const char* const nameText = lua_tostring(state->m_state, 3);
  if (nameText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&nameArg, "string");
  }

  const msvc8::string requestedName{nameText ? nameText : ""};
  const msvc8::string validName = lobby->MakeValidPlayerName(requestedName, uid);
  lua_pushstring(state->m_state, validName.c_str());
  return 1;
}

/**
 * Address: 0x007C18F0 (FUN_007C18F0, func_CLobbyMakeValidPlayerName_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:MakeValidPlayerName`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyMakeValidPlayerName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "MakeValidPlayerName",
    &moho::cfunc_CLobbyMakeValidPlayerName,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyMakeValidPlayerNameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C1C80 (FUN_007C1C80, cfunc_CLobbyHostGame)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyHostGameL`.
 */
int moho::cfunc_CLobbyHostGame(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyHostGameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C1D00 (FUN_007C1D00, cfunc_CLobbyHostGameL)
 *
 * What it does:
 * Validates one Lua `self` arg and dispatches `CLobby::HostGame`.
 */
int moho::cfunc_CLobbyHostGameL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyHostGameHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);
  lobby->HostGame();
  return 0;
}

/**
 * Address: 0x007C1CA0 (FUN_007C1CA0, func_CLobbyHostGame_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:HostGame`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyHostGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HostGame",
    &moho::cfunc_CLobbyHostGame,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyHostGameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C1FA0 (FUN_007C1FA0, cfunc_CLobbyJoinGame)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyJoinGameL`.
 */
int moho::cfunc_CLobbyJoinGame(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyJoinGameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C2020 (FUN_007C2020, cfunc_CLobbyJoinGameL)
 *
 * What it does:
 * Validates `(self,address,nameOrNil,uidOrNil)`, resolves host endpoint,
 * and dispatches `CLobby::JoinGame`.
 */
int moho::cfunc_CLobbyJoinGameL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyJoinGameHelp, 4, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  const char* remotePlayerName = nullptr;
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    LuaPlus::LuaStackObject remoteNameArg(state, 3);
    remotePlayerName = lua_tostring(state->m_state, 3);
    if (remotePlayerName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&remoteNameArg, "string");
    }
  }

  int remotePlayerUid = -1;
  if (lua_type(state->m_state, 4) != LUA_TNIL) {
    LuaPlus::LuaStackObject remoteUidArg(state, 4);
    const char* const remoteUidText = lua_tostring(state->m_state, 4);
    if (remoteUidText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&remoteUidArg, "string");
    }
    remotePlayerUid = std::atoi(remoteUidText ? remoteUidText : "");
  }

  LuaPlus::LuaStackObject addressArg(state, 2);
  const char* const addressText = lua_tostring(state->m_state, 2);
  if (addressText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&addressArg, "string");
  }

  u_long hostAddress = 0;
  u_short hostPort = 0;
  if (!NET_GetAddrInfo(addressText, 0, false, hostAddress, hostPort) || hostPort == 0) {
    LuaPlus::LuaState::Error(state, "Unable to resolve %s", addressText ? addressText : "");
  }

  lobby->JoinGame(hostAddress, hostPort, remotePlayerName, remotePlayerUid);
  return 0;
}

/**
 * Address: 0x007C1FC0 (FUN_007C1FC0, func_CLobbyJoinGame_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:JoinGame`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyJoinGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "JoinGame",
    &moho::cfunc_CLobbyJoinGame,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyJoinGameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2350 (FUN_007C2350, cfunc_CLobbyBroadcastData)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyBroadcastDataL`.
 */
int moho::cfunc_CLobbyBroadcastData(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyBroadcastDataL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C23D0 (FUN_007C23D0, cfunc_CLobbyBroadcastDataL)
 *
 * What it does:
 * Validates `(self,table)` and dispatches `CLobby::BroadcastScriptData`.
 */
int moho::cfunc_CLobbyBroadcastDataL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyBroadcastDataHelp, 2, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaObject scriptDataObject(LuaPlus::LuaStackObject(state, 2));
    lobby->BroadcastScriptData(scriptDataObject);
  }

  return 0;
}

/**
 * Address: 0x007C2370 (FUN_007C2370, func_CLobbyBroadcastData_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:BroadcastData`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyBroadcastData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "BroadcastData",
    &moho::cfunc_CLobbyBroadcastData,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyBroadcastDataHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2650 (FUN_007C2650, cfunc_CLobbySendData)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbySendDataL`.
 */
int moho::cfunc_CLobbySendData(
  lua_State* const luaContext
)
{
  return cfunc_CLobbySendDataL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C26D0 (FUN_007C26D0, cfunc_CLobbySendDataL)
 *
 * What it does:
 * Validates `(self, targetId, table)` Lua args and dispatches one direct lobby
 * script-data message.
 */
int moho::cfunc_CLobbySendDataL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbySendDataHelp, 3, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaObject scriptDataObject(LuaPlus::LuaStackObject(state, 3));

  LuaPlus::LuaStackObject targetIdArg(state, 2);
  const char* const targetIdText = lua_tostring(state->m_state, 2);
  if (targetIdText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&targetIdArg, "string");
  }
  const int32_t targetId = std::atoi(targetIdText ? targetIdText : "");

  lobby->SendScriptData(targetId, scriptDataObject);
  return 0;
}

/**
 * Address: 0x007C2670 (FUN_007C2670, func_CLobbySendData_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:SendData`.
 */
moho::CScrLuaInitForm* moho::func_CLobbySendData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SendData",
    &moho::cfunc_CLobbySendData,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbySendDataHelp
  );
  return &binder;
}

/**
 * Address: 0x007C28A0 (FUN_007C28A0, sub_7C28A0)
 *
 * What it does:
 * Returns one Lua peer table for matching uid, or `nil` when no peer matches.
 */
[[nodiscard]] static LuaPlus::LuaObject LookupPeerByUidAsLua(
  const int32_t uid,
  CLobby* const lobby,
  LuaPlus::LuaState* const state
)
{
  for (SPeer* peer : lobby->peers.owners()) {
    if (peer->uid == uid) {
      return SPeer::ToLua(state, peer);
    }
  }

  LuaPlus::LuaObject nilObject;
  nilObject.AssignNil(state);
  return nilObject;
}

/**
 * Address: 0x007C2B00 (FUN_007C2B00, cfunc_CLobbyGetPeers)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyGetPeersL`.
 */
int moho::cfunc_CLobbyGetPeers(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyGetPeersL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C2B20 (FUN_007C2B20, func_CLobbyGetPeers_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:GetPeers`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyGetPeers_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetPeers",
    &moho::cfunc_CLobbyGetPeers,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyGetPeersHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2B80 (FUN_007C2B80, cfunc_CLobbyGetPeersL)
 *
 * What it does:
 * Validates one Lua `self` arg and returns one table containing all peers.
 */
int moho::cfunc_CLobbyGetPeersL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyGetPeersHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaObject peersTable = lobby->GetPeers(state);
  peersTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x007C2C60 (FUN_007C2C60, cfunc_CLobbyGetPeer)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyGetPeerL`.
 */
int moho::cfunc_CLobbyGetPeer(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyGetPeerL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C2C80 (FUN_007C2C80, func_CLobbyGetPeer_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:GetPeer`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyGetPeer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetPeer",
    &moho::cfunc_CLobbyGetPeer,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyGetPeerHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2CE0 (FUN_007C2CE0, cfunc_CLobbyGetPeerL)
 *
 * What it does:
 * Validates `(self, uid)` and returns one peer table or `nil`.
 */
int moho::cfunc_CLobbyGetPeerL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyGetPeerHelp, 2, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaStackObject uidArg(state, 2);
  const char* const uidText = lua_tostring(state->m_state, 2);
  if (uidText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&uidArg, "string");
  }
  const int32_t uid = std::atoi(uidText ? uidText : "");

  LuaPlus::LuaObject peerObject = LookupPeerByUidAsLua(uid, lobby, state);
  peerObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x007C2DF0 (FUN_007C2DF0, cfunc_CLobbyGetLocalPlayerName)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyGetLocalPlayerNameL`.
 */
int moho::cfunc_CLobbyGetLocalPlayerName(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyGetLocalPlayerNameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C2E10 (FUN_007C2E10, func_CLobbyGetLocalPlayerName_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:GetLocalPlayerName`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyGetLocalPlayerName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetLocalPlayerName",
    &moho::cfunc_CLobbyGetLocalPlayerName,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyGetLocalPlayerNameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2E70 (FUN_007C2E70, cfunc_CLobbyGetLocalPlayerNameL)
 *
 * What it does:
 * Validates one Lua `self` arg and returns local player name text.
 */
int moho::cfunc_CLobbyGetLocalPlayerNameL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyGetLocalPlayerNameHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  const CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);
  lua_pushstring(state->m_state, lobby->playerName.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007C2F40 (FUN_007C2F40, cfunc_CLobbyGetLocalPlayerID)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyGetLocalPlayerIDL`.
 */
int moho::cfunc_CLobbyGetLocalPlayerID(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyGetLocalPlayerIDL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C2F60 (FUN_007C2F60, func_CLobbyGetLocalPlayerID_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:GetLocalPlayerID`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyGetLocalPlayerID_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetLocalPlayerID",
    &moho::cfunc_CLobbyGetLocalPlayerID,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyGetLocalPlayerIdHelp
  );
  return &binder;
}

/**
 * Address: 0x007C2FC0 (FUN_007C2FC0, cfunc_CLobbyGetLocalPlayerIDL)
 *
 * What it does:
 * Validates one Lua `self` arg and returns local uid as text.
 */
int moho::cfunc_CLobbyGetLocalPlayerIDL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyGetLocalPlayerIdHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  const CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  char uidBuffer[kPlayerUidBufSize]{};
  const auto toCharsResult = std::to_chars(uidBuffer, uidBuffer + kPlayerUidBufSize - 1, lobby->localUid);
  *toCharsResult.ptr = '\0';
  lua_pushstring(state->m_state, uidBuffer);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007C3090 (FUN_007C3090, cfunc_CLobbyIsHost)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyIsHostL`.
 */
int moho::cfunc_CLobbyIsHost(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyIsHostL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C30B0 (FUN_007C30B0, func_CLobbyIsHost_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:IsHost`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyIsHost_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsHost",
    &moho::cfunc_CLobbyIsHost,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyIsHostHelp
  );
  return &binder;
}

/**
 * Address: 0x007C3110 (FUN_007C3110, cfunc_CLobbyIsHostL)
 *
 * What it does:
 * Validates one Lua `self` arg and returns whether no host connection is bound.
 */
int moho::cfunc_CLobbyIsHostL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyIsHostHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  const CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);
  lua_pushboolean(state->m_state, lobby->peerConnection == nullptr);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007C31D0 (FUN_007C31D0, cfunc_CLobbyGetLocalPort)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyGetLocalPortL`.
 */
int moho::cfunc_CLobbyGetLocalPort(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyGetLocalPortL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C31F0 (FUN_007C31F0, func_CLobbyGetLocalPort_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:GetLocalPort`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyGetLocalPort_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetLocalPort",
    &moho::cfunc_CLobbyGetLocalPort,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyGetLocalPortHelp
  );
  return &binder;
}

/**
 * Address: 0x007C3250 (FUN_007C3250, cfunc_CLobbyGetLocalPortL)
 *
 * What it does:
 * Validates one Lua `self` arg and returns local connector port or `nil`.
 */
int moho::cfunc_CLobbyGetLocalPortL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyGetLocalPortHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  const CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);
  if (lobby->connector == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const u_short localPort = lobby->connector->GetLocalPort();
  if (localPort == static_cast<u_short>(-1)) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  lua_pushnumber(state->m_state, static_cast<float>(localPort));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007C3340 (FUN_007C3340, cfunc_CLobbyEjectPeer)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyEjectPeerL`.
 */
int moho::cfunc_CLobbyEjectPeer(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyEjectPeerL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C33C0 (FUN_007C33C0, cfunc_CLobbyEjectPeerL)
 *
 * What it does:
 * Validates `(self, targetId, reason)` Lua args and ejects one peer by uid.
 */
int moho::cfunc_CLobbyEjectPeerL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyEjectPeerHelp, 3, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaStackObject reasonArg(state, 3);
  const char* const reasonText = lua_tostring(state->m_state, 3);
  if (reasonText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&reasonArg, "string");
  }

  LuaPlus::LuaStackObject targetIdArg(state, 2);
  const char* const targetIdText = lua_tostring(state->m_state, 2);
  if (targetIdText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&targetIdArg, "string");
  }
  const int32_t targetId = std::atoi(targetIdText ? targetIdText : "");

  lobby->EjectPeer(targetId, reasonText ? reasonText : "");
  return 0;
}

/**
 * Address: 0x007C3360 (FUN_007C3360, func_CLobbyEjectPeer_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:EjectPeer`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyEjectPeer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EjectPeer",
    &moho::cfunc_CLobbyEjectPeer,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyEjectPeerHelp
  );
  return &binder;
}

/**
 * Address: 0x007C34D0 (FUN_007C34D0, cfunc_CLobbyConnectToPeer)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyConnectToPeerL`.
 */
int moho::cfunc_CLobbyConnectToPeer(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyConnectToPeerL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C34F0 (FUN_007C34F0, func_CLobbyConnectToPeer_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:ConnectToPeer`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyConnectToPeer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ConnectToPeer",
    &moho::cfunc_CLobbyConnectToPeer,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyConnectToPeerHelp
  );
  return &binder;
}

/**
 * Address: 0x007C3550 (FUN_007C3550, cfunc_CLobbyConnectToPeerL)
 *
 * What it does:
 * Validates `(self,address,name,uid)`, resolves endpoint, and dispatches
 * `CLobby::ConnectToPeer`.
 */
int moho::cfunc_CLobbyConnectToPeerL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyConnectToPeerHelp, 4, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaStackObject addressArg(state, 2);
  const char* const addressText = lua_tostring(state->m_state, 2);
  if (addressText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&addressArg, "string");
  }

  u_long address = 0;
  u_short port = 0;
  if (!NET_GetAddrInfo(addressText, 0, false, address, port) || port == 0) {
    LuaPlus::LuaState::Error(state, "Invalid peer address \"%s\"", addressText ? addressText : "");
  }

  LuaPlus::LuaStackObject nameArg(state, 3);
  const char* const nameText = lua_tostring(state->m_state, 3);
  if (nameText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&nameArg, "string");
  }

  LuaPlus::LuaStackObject uidArg(state, 4);
  const char* const uidText = lua_tostring(state->m_state, 4);
  if (uidText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&uidArg, "string");
  }
  const int32_t uid = std::atoi(uidText ? uidText : "");

  lobby->ConnectToPeer(address, port, msvc8::string(nameText ? nameText : ""), uid);
  return 0;
}

/**
 * Address: 0x007C3760 (FUN_007C3760, cfunc_CLobbyDisconnectFromPeer)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyDisconnectFromPeerL`.
 */
int moho::cfunc_CLobbyDisconnectFromPeer(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyDisconnectFromPeerL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C37E0 (FUN_007C37E0, cfunc_CLobbyDisconnectFromPeerL)
 *
 * What it does:
 * Validates `(self, uid)` Lua args and disconnects one peer by uid.
 */
int moho::cfunc_CLobbyDisconnectFromPeerL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyDisconnectFromPeerHelp, 2, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaStackObject peerUidArg(state, 2);
  const char* const peerUidText = lua_tostring(state->m_state, 2);
  if (peerUidText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&peerUidArg, "string");
  }
  const int32_t peerUid = std::atoi(peerUidText ? peerUidText : "");

  lobby->DisconnectFromPeer(peerUid);
  return 0;
}

/**
 * Address: 0x007C3780 (FUN_007C3780, func_CLobbyDisconnectFromPeer_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:DisconnectFromPeer`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyDisconnectFromPeer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DisconnectFromPeer",
    &moho::cfunc_CLobbyDisconnectFromPeer,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyDisconnectFromPeerHelp
  );
  return &binder;
}

/**
 * Address: 0x007C50E0 (FUN_007C50E0, cfunc_CLobbyLaunchGame)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyLaunchGameL`.
 */
int moho::cfunc_CLobbyLaunchGame(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyLaunchGameL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C5160 (FUN_007C5160, cfunc_CLobbyLaunchGameL)
 *
 * What it does:
 * Validates `(self,gameConfig)` and dispatches one launch-game request.
 */
int moho::cfunc_CLobbyLaunchGameL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyLaunchGameHelp, 2, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);

  LuaPlus::LuaObject gameConfigObject(LuaPlus::LuaStackObject(state, 2));
  lobby->LaunchGame(gameConfigObject);
  return 1;
}

/**
 * Address: 0x007C5100 (FUN_007C5100, func_CLobbyLaunchGame_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:LaunchGame`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyLaunchGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "LaunchGame",
    &moho::cfunc_CLobbyLaunchGame,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyLaunchGameHelp
  );
  return &binder;
}

/**
 * Address: 0x007C5360 (FUN_007C5360, cfunc_CLobbyDebugDump)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards to
 * `cfunc_CLobbyDebugDumpL`.
 */
int moho::cfunc_CLobbyDebugDump(
  lua_State* const luaContext
)
{
  return cfunc_CLobbyDebugDumpL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C53E0 (FUN_007C53E0, cfunc_CLobbyDebugDumpL)
 *
 * What it does:
 * Validates one Lua `self` arg and dispatches `CLobby::DebugDump`.
 */
int moho::cfunc_CLobbyDebugDumpL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLobbyDebugDumpHelp, 1, argumentCount);
  }

  LuaPlus::LuaObject lobbyObject(LuaPlus::LuaStackObject(state, 1));
  CLobby* const lobby = SCR_FromLua_CLobby(lobbyObject, state);
  lobby->DebugDump();
  return 0;
}

/**
 * Address: 0x007C5380 (FUN_007C5380, func_CLobbyDebugDump_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CLobby:DebugDump`.
 */
moho::CScrLuaInitForm* moho::func_CLobbyDebugDump_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DebugDump",
    &moho::cfunc_CLobbyDebugDump,
    &CScrLuaMetatableFactory<CLobby>::Instance(),
    "CLobby",
    kCLobbyDebugDumpHelp
  );
  return &binder;
}

/**
 * Address: 0x007C8360 (FUN_007C8360, cfunc_ValidateIPAddressL)
 *
 * What it does:
 * Validates one Lua `ipaddr` string, resolves host:port through `NET_GetAddrInfo`,
 * and returns either `"A.B.C.D:port"` or `nil`.
 */
int moho::cfunc_ValidateIPAddressL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kValidateIPAddressHelp, 1, argumentCount);
  }

  LuaPlus::LuaStackObject ipAddressArg(state, 1);
  const char* const ipAddressText = lua_tostring(state->m_state, 1);
  if (ipAddressText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&ipAddressArg, "string");
  }

  u_long address = 0;
  u_short port = 0;
  if (NET_GetAddrInfo(ipAddressText, 0, false, address, port)) {
    const msvc8::string host = NET_GetDottedOctetFromUInt32(address);
    const msvc8::string hostAndPort = gpg::STR_Printf("%s:%d", host.c_str(), static_cast<int>(port));
    lua_pushstring(state->m_state, hostAndPort.c_str());
    (void)lua_gettop(state->m_state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  return 1;
}

/**
 * Address: 0x007C82E0 (FUN_007C82E0, cfunc_ValidateIPAddress)
 *
 * What it does:
 * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
 * to `cfunc_ValidateIPAddressL`.
 */
int moho::cfunc_ValidateIPAddress(
  lua_State* const luaContext
)
{
  return cfunc_ValidateIPAddressL(luaContext ? luaContext->stateUserData : nullptr);
}

/**
 * Address: 0x007C8300 (FUN_007C8300, func_ValidateIPAddress_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ValidateIPAddress`.
 */
moho::CScrLuaInitForm* moho::func_ValidateIPAddress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(), "ValidateIPAddress", &moho::cfunc_ValidateIPAddress, nullptr, "<global>", kValidateIPAddressHelp
  );
  return &binder;
}

/**
 * Address: 0x007C7FA0 (FUN_007C7FA0)
 */
void CLobby::Msg(
  gpg::StrArg msg
)
{
  CallbackStr("SystemMessage", &msg);
}

/**
 * Address: 0x007C7FC0 (FUN_007C7FC0)
 */
void CLobby::Msgf(
  const char* fmt,
  ...
)
{
  va_list va;
  va_start(va, fmt);
  const msvc8::string msg = gpg::STR_Va(fmt, va);
  va_end(va);

  const char* str = msg.c_str();
  CallbackStr("SystemMessage", &str);
}

/**
 * Address: 0x007CBAD0 (FUN_007CBAD0)
 */
void CLobby::ProcessConnectionToHostEstablished(
  const char** localPeerUidBuf,
  const char** newLocalNameBuf,
  const char** hostPeerUidBuf
)
{
  LuaPlus::LuaObject dest;
  FindScript(&dest, "ConnectionToHostEstablished");

  if (dest) {
    const char* localPeerUid = (localPeerUidBuf && *localPeerUidBuf) ? *localPeerUidBuf : "";
    const char* newLocalName = (newLocalNameBuf && *newLocalNameBuf) ? *newLocalNameBuf : "";
    const char* postPeerUid = (hostPeerUidBuf && *hostPeerUidBuf) ? *hostPeerUidBuf : "";

    const LuaPlus::LuaObject self(mLuaObj);
    const LuaPlus::LuaFunction<void> fn(dest);
    fn(self, localPeerUid, newLocalName, postPeerUid);
  }
}

/**
 * Address: 0x007CBD20 (FUN_007CBD20)
 */
void CLobby::ProcessEjected()
{
  LuaPlus::LuaObject dest;
  FindScript(&dest, "Ejected");
  if (dest) {
    LuaPlus::LuaObject self(mLuaObj);
    LuaPlus::LuaFunction<void> fn(dest);
    fn.Call(self, "KickedByHost");
  }
}

/**
 * Address: 0x007C7190 (FUN_007C7190)
 */
void CLobby::ConnectToPeer(
  const u_long address,
  const u_short port,
  const msvc8::string& name,
  const int32_t uid
)
{
  for (SPeer* it : peers.owners()) {
    if (it->uid == uid) {
      const msvc8::string msg = gpg::STR_Printf("Attempting to redundently add peer uid=%d", uid);
      throw std::runtime_error(msg.c_str());
    }
  }

  if (uid == localUid) {
    const msvc8::string msg = gpg::STR_Printf("Attempting to add peer uid=%d, but that is us.", uid);
    throw std::runtime_error(msg.c_str());
  }

  const msvc8::vector<msvc8::string> ignoreNames = BuildLobbyIgnoreNameList();
  if (!ignoreNames.empty() && IsPeerNameInIgnoreList(ignoreNames, name)) {
    return;
  }

  INetConnection* connection;
  ENetworkPlayerState initial;
  if (uid < localUid && peerConnection) {
    connection = connector->Connect(address, port);
    initial = ENetworkPlayerState::kConnecting;
  } else {
    connection = connector->Accept(address, port);
    initial = ENetworkPlayerState::kPending;
  }

  connection->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);

  const auto validName = MakeValidPlayerName(name, uid);
  SPeer* peer = new SPeer(validName, uid, address, port, connection, initial);
  peers.push_back(peer);

  const auto connStr = peer->ToString();
  gpg::Logf("LOBBY: Adding peer %s", connStr.c_str());

  LuaPlus::LuaState* l = mLuaObj.GetActiveState();
  const msvc8::string locMsg = Loc(l, "<LOC Engine0005>Connecting to %s...");
  Msgf(locMsg.c_str(), peer->playerName.c_str());
}

/**
 * Address: 0x007C7790 (FUN_007C7790)
 */
void CLobby::DisconnectFromPeer(
  const int32_t uid
)
{
  if (localUid == uid) {
    gpg::Logf("LOBBY: we've been ejected.");
    ProcessEjected();
    return;
  }

  SPeer* peer = FindPeerByUid(uid);
  if (peer != nullptr) {
    PeerDisconnected(peer);
    return;
  }

  gpg::Logf("LOBBY: deleting unknown peer uid %d.", uid);
}

/**
 * Address: 0x007C7990 (FUN_007C7990, Moho::CLobby::EjectPeer)
 *
 * What it does:
 * Enforces host-only eject preconditions, scans the intrusive peer list for
 * one target uid, then dispatches `KickPeer`.
 */
void CLobby::EjectPeer(
  const int32_t id,
  const char* const reason
)
{
  if (peerConnection != nullptr) {
    throw std::runtime_error("Only the host can eject players.");
  }

  if (id == localUid) {
    throw std::runtime_error("We can't eject ourselves!");
  }

  using PeerNode = TDatListItem<SPeer, void>;
  PeerNode* const peersHead = static_cast<PeerNode*>(&peers);
  for (PeerNode* node = peers.mNext; node != peersHead; node = node->mNext) {
    auto* const peer = static_cast<SPeer*>(node);
    if (peer->uid == id) {
      KickPeer(peer, reason);
      return;
    }
  }

  throw std::runtime_error("Attempting to eject an unknown peer.");
}

/**
 * Address: 0x007C7AC0 (FUN_007C7AC0)
 */
void CLobby::KickPeer(
  SPeer* peer,
  const char* reason
)
{
  if (peerConnection != nullptr) {
    throw std::runtime_error("Only the host can eject players.");
  }

  if (peer->state != ENetworkPlayerState::kDisconnected) {
    CMessage msg(ELobbyMsg::LOBMSG_Rejected);
    CMessageStream s(msg, CMessageStream::Access::kReadWrite);

    s.Write(reason);
    peer->peerConnection->Write(s);
  }

  PeerDisconnected(peer);
}

/**
 * Address: 0x007C5490 (FUN_007C5490, Moho::CLobby::PushTask)
 *
 * What it does:
 * Runs lobby push-phase polling for pending connector/socket events.
 */
void CLobby::PushTask()
{
  if (mSocket != nullptr) {
    mSocket->Pull();
  }

  ResetEvent(event);
  if (connector == nullptr) {
    return;
  }

  u_long address;
  u_short port;
  while (connector->FindNextAddress(address, port)) {
    if (!mHasNAT || peerConnection != nullptr) {
      connector->Reject(address, port);
      gpg::Logf("LOBBY: rejecting unexpected connection from %s:%d", NET_GetHostName(address).c_str(), port);
    } else {
      INetConnection* acceptedConnection = connector->Accept(address, port);
      gpg::Logf("LOBBY: lan game connection from %s.", acceptedConnection->ToString().c_str());
      acceptedConnection->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);

      SPeer* peer = new SPeer(msvc8::string{}, -1, address, port, acceptedConnection, ENetworkPlayerState::kPending);
      peer->ListLinkBefore(&peers);
    }
  }

  connector->Pull();
}

int CLobby::Execute()
{
  PushTask();
  PullTask();
  return 1;
}

/**
 * Address: 0x007C8CB0 (FUN_007C8CB0, `CPushTask_CLobby::PushTask` wrapper)
 *
 * What it does:
 * Thin wrapper that forwards task-stage execution into `PushTask()`.
 */
void CLobby::Push()
{
  PushTask();
}

/**
 * Address: 0x007C56B0 (FUN_007C56B0, Moho::CLobby::PullTask)
 *
 * What it does:
 * When peer replication is dirty, serializes established peer UIDs into one
 * `LOBMSG_EstablishedPeers` packet and broadcasts it to established peers.
 */
void CLobby::PullTask()
{
  if (!peersDirty) {
    return;
  }
  peersDirty = false;

  CMessage msg(ELobbyMsg::LOBMSG_EstablishedPeers);
  CMessageStream s(msg, CMessageStream::Access::kReadWrite);
  for (SPeer* peer : peers.owners()) {
    s.Write(peer->uid);
  }

  s.Write<int32_t>(-1);
  BroadcastStream(s);
}

/**
 * Address: 0x007C8BF0 (FUN_007C8BF0, `CPullTask_CLobby::PullTask` wrapper)
 *
 * What it does:
 * Wrapper that forwards into `PullTask()`.
 */
void CLobby::Pull()
{
  PullTask();
}

/**
 * Address: 0x007C1B20 (FUN_007C1B20)
 *
 * What it does:
 * Transitions lobby into host mode and opens LAN discovery socket when allowed.
 */
void CLobby::HostGame()
{
  if (joinedLobby) {
    throw std::runtime_error{std::string{"Attempting to host or join after already having done so."}};
  }

  joinedLobby = true;
  if (mHasNAT && connector->GetProtocol() != ENetProtocolType::kNone) {
    INetDatagramSocket* sock = NET_OpenDatagramSocket(15000, this);
    mSocket = sock;

    if (mSocket != nullptr) {
      gpg::Logf("LOBBY: Listening for discovery requests on port %d", 15000);
      WIN_GetWaitHandleSet()->AddHandle(mSocket->CreateEvent());
    } else {
      gpg::Logf("LOBBY: Creating discovery listener failed -- someone else must be hosting a game on this machine.");
    }
  }

  if (localUid == -1) {
    localUid = mNextId++;
    gpg::Logf("LOBBY: assigning ourselves the uid of %d", localUid);
  }

  hostedTime = gpg::time::GetSystemTimer().ElapsedCycles();
  RunScript("Hosting");
}

/**
 * Address: 0x007C1DA0 (FUN_007C1DA0)
 *
 * What it does:
 * Connects to host endpoint and seeds host peer state.
 */
void CLobby::JoinGame(
  const u_long address,
  const u_short port,
  const char* remPlayerName,
  int remPlayerUid
)
{
  if (joinedLobby) {
    throw std::runtime_error("Attempting to host or join after already having done so.");
  }

  joinedLobby = true;
  peerConnection = connector->Connect(address, port);
  peerConnection->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
  const u_long remoteAddress = peerConnection->GetAddr();
  const u_short remotePort = peerConnection->GetPort();
  SPeer* peer = new SPeer(
    msvc8::string(remPlayerName),
    remPlayerUid,
    remoteAddress,
    remotePort,
    peerConnection,
    ENetworkPlayerState::kConnecting
  );
  peer->ListLinkBefore(&peers);
  gpg::Logf("LOBBY: Connecting to host %s", peer->ToString().c_str());
  LuaPlus::LuaState* l = mLuaObj.GetActiveState();
  const msvc8::string locMsg = Loc(l, "<LOC Engine0001>Connecting to game host...");
  Msg(locMsg.c_str());
}

/**
 * Address: 0x007C2210 (FUN_007C2210)
 */
void CLobby::BroadcastScriptData(
  LuaPlus::LuaObject& dat
)
{
  CMessage msg(ELobbyMsg::LOBMSG_BroadcastScriptData);
  CMessageStream s(msg, CMessageStream::Access::kReadWrite);

  if (!dat.ToByteStream(s)) {
    throw std::runtime_error("CLobby::BroadcastScriptData(): failed to encode message.");
  }
  BroadcastStream(s);
}

/**
 * Address: 0x007C24C0 (FUN_007C24C0)
 *
 * What it does:
 * Sends a Lua script payload to a specific established peer uid.
 */
void CLobby::SendScriptData(
  int32_t id,
  LuaPlus::LuaObject& dat
)
{
  CMessage msg(ELobbyMsg::LOBMSG_DirectScriptData);
  CMessageStream s(msg, CMessageStream::Access::kReadWrite);

  if (!dat.ToByteStream(s)) {
    throw std::runtime_error(std::format("CLobby::SendScriptData(): failed to encode message to UID {}", id));
  }

  SPeer* peer = FindPeerByUid(id);
  if (peer != nullptr) {
    peer->peerConnection->Write(s);
    return;
  }

  throw std::runtime_error(std::format("CLobby::SendScriptData(): sending to unknown UID {}?", id));
}

/**
 * Address: 0x007C27E0 (FUN_007C27E0)
 */
LuaPlus::LuaObject CLobby::GetPeers(
  LuaPlus::LuaState* state
)
{
  LuaPlus::LuaObject ret;
  ret.AssignNewTable(state, 0, 0);
  int32_t index = 1;
  for (SPeer* it : peers.owners()) {
    auto info = it->ToLua(state, it);
    ret.SetObject(index++, &info);
  }
  return ret;
}

/**
 * Address: 0x007C38C0 (FUN_007C38C0)
 */
void CLobby::LaunchGame(
  const LuaPlus::LuaObject& dat
)
{
  LuaPlus::LuaObject gameOptions = dat["GameOptions"];

  const LuaPlus::LuaObject scenarioFileObject = gameOptions["ScenarioFile"];
  const char* const scenarioFileText = scenarioFileObject.GetString();
  const msvc8::string scenarioFile{scenarioFileText ? scenarioFileText : ""};

  LuaPlus::LuaObject scenarioInfo = WLD_LoadScenarioInfo(scenarioFile, USER_GetLuaState());
  if (scenarioInfo.IsNil()) {
    const char* reason = "";
    CallbackStr("LaunchFailed", &reason);
    return;
  }
  scenarioInfo.SetObject("Options", gameOptions);

  boost::shared_ptr<LaunchInfoNew> launchInfo(new LaunchInfoNew());
  launchInfo->mGameMods = SCR_ToString(dat["GameMods"]);
  launchInfo->mScenarioInfo = SCR_ToString(scenarioInfo);
  launchInfo->mInitSeed = hostedTime;

  const LuaPlus::LuaObject cheatsEnabled = gameOptions["CheatsEnabled"];
  if (cheatsEnabled && cheatsEnabled.IsString()) {
    const char* const enabledStr = cheatsEnabled.GetString();
    if (enabledStr != nullptr && std::strcmp(enabledStr, "true") == 0) {
      launchInfo->mCheatsEnabled = true;
    }
  }

  LuaPlus::LuaObject teamsConfig = scenarioInfo.Lookup("Configurations.standard.teams");
  if (teamsConfig.IsNil()) {
    const char* reason = "NoConfig";
    CallbackStr("LaunchFailed", &reason);
    return;
  }

  msvc8::vector<msvc8::string> ffaArmies;
  {
    LuaPlus::LuaTableIterator teamIt(&teamsConfig, 1);
    while (!teamIt.m_isDone) {
      LuaPlus::LuaObject teamObject = teamIt.GetValue();
      const LuaPlus::LuaObject teamNameObject = teamObject["name"];
      const char* const teamName = teamNameObject.GetString();
      if (teamName != nullptr && _stricmp(teamName, "FFA") == 0) {
        LuaPlus::LuaObject teamArmies = teamObject["armies"];
        LuaPlus::LuaTableIterator armyIt(&teamArmies, 1);
        while (!armyIt.m_isDone) {
          LuaPlus::LuaObject armyNameObject = armyIt.GetValue();
          const char* const armyName = armyNameObject.GetString();
          if (armyName != nullptr) {
            ffaArmies.push_back(msvc8::string(armyName));
          }
          armyIt.Next();
        }
        break;
      }
      teamIt.Next();
    }
  }

  msvc8::vector<LaunchPlayerOptionEntry> playerOptions;
  LuaPlus::LuaObject playerOptionsTable = dat["PlayerOptions"];
  if (!playerOptionsTable.IsNil()) {
    LuaPlus::LuaTableIterator optionIt(&playerOptionsTable, 1);
    while (!optionIt.m_isDone) {
      LuaPlus::LuaObject keyObject = optionIt.GetKey();
      LuaPlus::LuaObject optionObject = optionIt.GetValue();
      const int32_t slotIndex = keyObject.GetInteger() - 1;
      if (slotIndex >= 0 && static_cast<std::size_t>(slotIndex) < ffaArmies.size()) {
        optionObject.SetString("ArmyName", ffaArmies[static_cast<std::size_t>(slotIndex)].c_str());
      }

      LaunchPlayerOptionEntry entry{};
      entry.mSlotIndex = slotIndex;
      entry.mOptions = optionObject;
      playerOptions.push_back(entry);
      optionIt.Next();
    }
  }

  if (playerOptions.size() > ffaArmies.size()) {
    const char* reason = "StartSpots";
    CallbackStr("LaunchFailed", &reason);
    return;
  }

  if (!playerOptions.empty()) {
    std::sort(
      playerOptions.begin(),
      playerOptions.end(),
      [](const LaunchPlayerOptionEntry& lhs, const LaunchPlayerOptionEntry& rhs) {
      return lhs.mSlotIndex < rhs.mSlotIndex;
    }
    );
  }

  auto sessionInfo = msvc8::auto_ptr<SWldSessionInfo>(new SWldSessionInfo());
  sessionInfo->mIsBeingRecorded = true;
  sessionInfo->mIsReplay = false;
  sessionInfo->mIsMultiplayer = connector->GetProtocol() != ENetProtocolType::kNone;
  sessionInfo->mSourceId = 0xFFu;
  launchInfo->mCommandSources.mOriginalSource = -1;

  int32_t timeouts = -1;
  if (sessionInfo->mIsMultiplayer) {
    const LuaPlus::LuaObject timeoutObj = gameOptions["Timeouts"];
    if (timeoutObj.IsString()) {
      const char* const timeoutStr = timeoutObj.GetString();
      timeouts = std::atoi(timeoutStr ? timeoutStr : "");
    }
  }

  if (playerOptions.empty()) {
    LuaPlus::LuaObject defaultOptions = RULE_GetDefaultPlayerOptions(USER_GetLuaState());
    defaultOptions.SetString("PlayerName", "default");
    defaultOptions.SetString("ArmyName", "default");
    defaultOptions.SetBoolean("Human", false);

    LaunchPlayerOptionEntry entry{};
    entry.mSlotIndex = 0;
    entry.mOptions = defaultOptions;
    playerOptions.push_back(entry);
  }

  LuaPlus::LuaObject civilianAlliance = gameOptions["CivilianAlliance"];
  if (civilianAlliance && civilianAlliance.IsString()) {
    const char* const civilianText = civilianAlliance.GetString();
    if (civilianText != nullptr && _stricmp(civilianText, "none") != 0) {
      LuaPlus::LuaObject extraArmiesObject = scenarioInfo.Lookup("Configurations.standard.customprops.ExtraArmies");
      if (extraArmiesObject.IsString()) {
        const char* const extraArmiesText = extraArmiesObject.GetString();
        msvc8::vector<msvc8::string> extraArmies;
        gpg::STR_GetTokens(extraArmiesText ? extraArmiesText : "", " ", extraArmies);
        for (const msvc8::string& extraArmyName : extraArmies) {
          LuaPlus::LuaObject civilianOptions = RULE_GetDefaultPlayerOptions(USER_GetLuaState());
          civilianOptions.SetString("PlayerName", "civilian");
          civilianOptions.SetString("ArmyName", extraArmyName.c_str());
          civilianOptions.SetBoolean("Civilian", true);
          civilianOptions.SetBoolean("Human", false);

          LaunchPlayerOptionEntry entry{};
          entry.mSlotIndex = -1;
          entry.mOptions = civilianOptions;
          playerOptions.push_back(entry);
        }
      }
    }
  }

  int32_t clientIndex = 0;
  int32_t localClientIndex = -1;
  for (std::size_t playerIndex = 0; playerIndex < playerOptions.size(); ++playerIndex) {
    const LuaPlus::LuaObject& option = playerOptions[playerIndex].mOptions;
    BVIntSet commandSourceSet{};

    const LuaPlus::LuaObject isHumanObject = option["Human"];
    if (isHumanObject.GetBoolean()) {
      const LuaPlus::LuaObject ownerIdObject = option["OwnerID"];
      const int32_t ownerId = ParseOwnerId(ownerIdObject);
      if (ownerId == localUid) {
        launchInfo->mCommandSources.mOriginalSource = static_cast<int32_t>(playerIndex);
      }

      const LuaPlus::LuaObject playerNameObject = option["PlayerName"];
      const char* const optionPlayerName = playerNameObject.GetString();
      AssignClientIndex(clientIndex, ownerId, optionPlayerName ? optionPlayerName : "", localClientIndex);

      const uint32_t sourceId =
        AssignCommandSource(timeouts, ownerId, launchInfo->mCommandSources.mSrcs, sessionInfo->mSourceId);
      if (sourceId != 0xFFu) {
        (void)commandSourceSet.Add(sourceId);
      }
    }

    launchInfo->mStrVec.push_back(SCR_ToString(option));
    moho::ArmyLaunchInfo armySourceInfo{};
    armySourceInfo.mUnitSources = commandSourceSet;
    launchInfo->mArmyLaunchInfo.push_back(armySourceInfo);
  }

  LuaPlus::LuaObject observersTable = dat["Observers"];
  LuaPlus::LuaTableIterator observerIt(&observersTable, 1);
  while (!observerIt.m_isDone) {
    LuaPlus::LuaObject observer = observerIt.GetValue();
    const int32_t ownerId = ParseOwnerId(observer["OwnerID"]);
    const LuaPlus::LuaObject observerNameObject = observer["PlayerName"];
    const char* const observerName = observerNameObject.GetString();
    AssignClientIndex(clientIndex, ownerId, observerName ? observerName : "", localClientIndex);

    const int32_t observerTimeouts = sessionInfo->mIsMultiplayer ? 0 : -1;
    (void)AssignCommandSource(observerTimeouts, ownerId, launchInfo->mCommandSources.mSrcs, sessionInfo->mSourceId);
    observerIt.Next();
  }

  int gameSpeed = 0;
  bool adjustableGameSpeed = false;
  const LuaPlus::LuaObject gameSpeedObject = gameOptions["GameSpeed"];
  if (gameSpeedObject.IsString()) {
    const char* const gameSpeedName = gameSpeedObject.GetString();
    if (gameSpeedName != nullptr) {
      if (_stricmp(gameSpeedName, "fast") == 0) {
        gameSpeed = 4;
      } else if (_stricmp(gameSpeedName, "adjustable") == 0) {
        adjustableGameSpeed = true;
      }
    }
  }

  connector->SelectEvent(nullptr);
  sessionInfo->mClientManager =
    CLIENT_CreateClientManager(static_cast<std::size_t>(clientIndex), connector, gameSpeed, adjustableGameSpeed);
  connector = nullptr;

  sessionInfo->mClientManager->CreateLocalClient(
    playerName.c_str(), localClientIndex, localUid, sessionInfo->mSourceId
  );

  for (SPeer* peer : peers.owners()) {
    if (peer->mClientInd == -1) {
      continue;
    }

    if (peer->state == ENetworkPlayerState::kEstablished) {
      DetachLobbyReceiverRanges(peer->peerConnection, this);
      sessionInfo->mClientManager->CreateNetClient(
        peer->playerName.c_str(), peer->mClientInd, peer->uid, peer->mCmdSource, peer->peerConnection
      );
      peer->peerConnection = nullptr;
    } else {
      sessionInfo->mClientManager->CreateNullClient(
        peer->playerName.c_str(), peer->mClientInd, peer->uid, peer->mCmdSource
      );
    }
  }

  while (!peers.empty()) {
    SPeer* const peer = static_cast<SPeer*>(peers.mNext);
    if (peer->mClientInd != -1 && peer->state != ENetworkPlayerState::kEstablished) {
      IClient* const client = sessionInfo->mClientManager->GetClient(peer->mClientInd);
      if (client != nullptr) {
        client->Eject();
      }
    }

    if (peer->peerConnection != nullptr) {
      peer->peerConnection->ScheduleDestroy();
    }
    delete peer;
  }

  const LuaPlus::LuaObject mapObject = scenarioInfo["map"];
  const char* const mapName = mapObject.GetString();
  sessionInfo->mMapName = mapName ? mapName : "";
  sessionInfo->mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(launchInfo);

  RunScript("GameLaunched");
  WLD_BeginSession(sessionInfo);
}

/**
 * Address: 0x007C5240 (FUN_007C5240, Moho::CLobby::DebugDump)
 *
 * What it does:
 * Logs all current peers with connection-state labels, then calls connector
 * debug hook.
 */
void CLobby::DebugDump()
{
  gpg::Logf("Peers:");
  for (SPeer* peer : peers.owners()) {
    msvc8::string peerState;
    ENetworkPlayerStateToStr(peer->state, peerState);
    const msvc8::string peerLabel = peer->ToString();
    gpg::Logf("  0x%08x: %s: %s", peer, peerLabel.c_str(), peerState.c_str());
  }

  connector->Debug();
}

/**
 * Address: 0x007C4E80 (FUN_007C4E80)
 *
 * What it does:
 * Resolves/creates a peer owner record and assigns a stable per-owner client index.
 */
void CLobby::AssignClientIndex(
  int32_t& clientIndex,
  const int32_t ownerId,
  const char* plyName,
  int32_t& tmpUid
)
{
  if (ownerId == localUid) {
    if (tmpUid == -1) {
      tmpUid = clientIndex++;
    }
    return;
  }

  SPeer* peer = FindPeerByUid(ownerId);
  if (peer == nullptr) {
    peer = new SPeer(msvc8::string(plyName), ownerId, 0, 0, nullptr, ENetworkPlayerState::kDisconnected);
    peer->ListLinkBefore(&peers);
  }
  if (peer->mClientInd == -1) {
    peer->mClientInd = clientIndex++;
  }
}

/**
 * Address: 0x007C4F60 (FUN_007C4F60)
 *
 * What it does:
 * Returns an owner-specific command-source id, creating source entries lazily.
 */
uint32_t CLobby::AssignCommandSource(
  int timeouts,
  int32_t ownerId,
  msvc8::vector<SSTICommandSource>& commandSources,
  uint32_t& sourceId
)
{
  static constexpr uint32_t kInvalidCommandSourceId = 0xFF;

  if (localUid == ownerId) {
    if (sourceId == kInvalidCommandSourceId) {
      const uint32_t newId = static_cast<uint32_t>(commandSources.size());
      sourceId = newId;

      const SSTICommandSource entry{static_cast<std::uint32_t>(sourceId), playerName.c_str(), timeouts};
      AppendSSTICommandSource(commandSources, entry);
    }

    return sourceId;
  }

  SPeer* peer = FindPeerByUid(ownerId);

  if (peer == nullptr) {
    // Binary path assumes ownership uid resolves to an existing SPeer.
    GPG_UNREACHABLE("unreachable")
    return kInvalidCommandSourceId;
  }

  if (peer->mCmdSource == kInvalidCommandSourceId) {
    peer->mCmdSource = static_cast<uint32_t>(commandSources.size());

    const SSTICommandSource entry{static_cast<std::uint32_t>(peer->mCmdSource), peer->playerName.c_str(), timeouts};
    AppendSSTICommandSource(commandSources, entry);
  }

  return peer->mCmdSource;
}
