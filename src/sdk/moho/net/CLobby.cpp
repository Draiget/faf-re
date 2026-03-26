#include "CLobby.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <vector>
#include <typeinfo>

#include "CClientManagerImpl.h"
#include "CMessageStream.h"
#include "CNetUDPConnection.h"
#include "ELobbyMsg.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "INetDatagramSocket.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StringUtils.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "lua/LuaTableIterator.h"
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
    "lob_IgnoreNames", "Comma seperated list of player names to ignore.", &lob_IgnoreNames
  };
} // namespace moho

namespace
{
  struct LaunchPlayerOptionEntry
  {
    int32_t mSlotIndex{-1};
    LuaPlus::LuaObject mOptions;
  };

  bool sLobbyIgnoreNamesConVarRegistered = false;

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
      if (linkage->mLower == lower && linkage->mUpper == upper &&
          linkage->mReceiver == const_cast<IMessageReceiver*>(receiver)) {
        dispatcher.RemoveLinkage(linkage);
        return true;
      }
    }
    return false;
  }

  void DetachLobbyReceiverRanges(INetConnection* const connection, const IMessageReceiver* const receiver)
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

  [[nodiscard]] int32_t ParseOwnerId(const LuaPlus::LuaObject& ownerIdObject)
  {
    const char* const ownerIdStr = ownerIdObject.GetString();
    return std::atoi(ownerIdStr ? ownerIdStr : "");
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

/**
 * Address: 0x007C0780 (FUN_007C0780)
 *
 * What it does:
 * Returns cached reflection type for `CLobby`.
 */
gpg::RType* CLobby::GetClass() const
{
  static gpg::RType* sLobbyType = nullptr;
  if (sLobbyType == nullptr) {
    sLobbyType = gpg::LookupRType(typeid(CLobby));
  }
  return sLobbyType;
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
}

/**
 * Address: 0x007C0C60 (FUN_007C0C60 deleting wrapper)
 * Address: ?1CLobby@Moho@@UAE@XZ (non-deleting body)
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

  mSocket.reset();
}

msvc8::string CLobby::GetErrorDescription()
{
  return CScriptObject::GetErrorDescription();
}

SPeer* CLobby::FindPeerByConnection(const INetConnection* connection)
{
  for (SPeer* peer : peers.owners()) {
    if (peer->peerConnection == connection) {
      return peer;
    }
  }
  return nullptr;
}

SPeer* CLobby::FindPeerByUid(const int32_t uid)
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
void CLobby::ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher)
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
void CLobby::OnDatagram(CMessage* msg, INetDatagramSocket* sock, const u_long address, const u_short port)
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
void CLobby::OnJoin(CMessage* message, INetConnection* connection)
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
void CLobby::OnRejected(CMessage* message, [[maybe_unused]] INetConnection* connection)
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
void CLobby::OnWelcome(CMessage* message, const INetConnection* connection)
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
void CLobby::OnNewPeer(CMessage* message, INetConnection* connection)
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
void CLobby::OnDeletePeer(CMessage* message, INetConnection* connection)
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
void CLobby::OnEstablishedPeers(CMessage* message, INetConnection* connection)
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
void CLobby::OnScriptData(CMessage* message, INetConnection* connection)
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
void CLobby::OnConnectionFailed([[maybe_unused]] CMessage* message, INetConnection* connection)
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
void CLobby::OnConnectionMade([[maybe_unused]] const CMessage* message, INetConnection* connection)
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
void CLobby::OnConnectionLost(CMessage* message, INetConnection* connection)
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
 * Address: 0x007C77F0 (FUN_007C77F0)
 */
void CLobby::PeerDisconnected(SPeer* peer)
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
void CLobby::BroadcastStream(const CMessageStream& s)
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
msvc8::string CLobby::MakeValidPlayerName(msvc8::string joiningName, const int32_t uid)
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
 * Address: 0x007C7FA0 (FUN_007C7FA0)
 */
void CLobby::Msg(gpg::StrArg msg)
{
  CallbackStr("SystemMessage", &msg);
}

/**
 * Address: 0x007C7FC0 (FUN_007C7FC0)
 */
void CLobby::Msgf(const char* fmt, ...)
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
  const char** localPeerUidBuf, const char** newLocalNameBuf, const char** hostPeerUidBuf
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
void CLobby::ConnectToPeer(const u_long address, const u_short port, const msvc8::string& name, const int32_t uid)
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

  if (!lob_IgnoreNames.empty() && IsNameIgnored(lob_IgnoreNames, name.c_str())) {
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
void CLobby::DisconnectFromPeer(const int32_t uid)
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
 * Address: 0x007C7AC0 (FUN_007C7AC0)
 */
void CLobby::KickPeer(SPeer* peer, const char* reason)
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
 * Address: 0x007C8CB0 (FUN_007C8CB0, `CPushTask_CLobby::PushTask` wrapper)
 *
 * What it does:
 * Runs lobby push-phase polling for pending connector/socket events.
 */
void CLobby::Push()
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

/**
 * Address: 0x007C8BF0 (FUN_007C8BF0, `CPullTask_CLobby::PullTask` wrapper)
 *
 * What it does:
 * Broadcasts established-peer snapshots when dirty flag is set.
 */
void CLobby::Pull()
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
void CLobby::JoinGame(const u_long address, const u_short port, const char* remPlayerName, int remPlayerUid)
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
void CLobby::BroadcastScriptData(LuaPlus::LuaObject& dat)
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
void CLobby::SendScriptData(int32_t id, LuaPlus::LuaObject& dat)
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
LuaPlus::LuaObject CLobby::GetPeers(LuaPlus::LuaState* state)
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
void CLobby::LaunchGame(const LuaPlus::LuaObject& dat)
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
    std::sort(playerOptions.begin(), playerOptions.end(), [](const LaunchPlayerOptionEntry& lhs, const LaunchPlayerOptionEntry& rhs) {
      return lhs.mSlotIndex < rhs.mSlotIndex;
    });
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

      const uint32_t sourceId = AssignCommandSource(timeouts, ownerId, launchInfo->mCommandSources.mSrcs, sessionInfo->mSourceId);
      if (sourceId != 0xFFu) {
        (void)commandSourceSet.Add(sourceId);
      }
    }

    launchInfo->mStrVec.push_back(SCR_ToString(option));
    launchInfo->mArmyLaunchInfo.push_back(commandSourceSet);
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

  sessionInfo->mClientManager->CreateLocalClient(playerName.c_str(), localClientIndex, localUid, sessionInfo->mSourceId);

  for (SPeer* peer : peers.owners()) {
    if (peer->mClientInd == -1) {
      continue;
    }

    if (peer->state == ENetworkPlayerState::kEstablished) {
      DetachLobbyReceiverRanges(peer->peerConnection, this);
      sessionInfo->mClientManager->CreateNetClient(
        peer->playerName.c_str(),
        peer->mClientInd,
        peer->uid,
        peer->mCmdSource,
        peer->peerConnection
      );
      peer->peerConnection = nullptr;
    } else {
      sessionInfo->mClientManager->CreateNullClient(peer->playerName.c_str(), peer->mClientInd, peer->uid, peer->mCmdSource);
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
 * Address: 0x007C4E80 (FUN_007C4E80)
 *
 * What it does:
 * Resolves/creates a peer owner record and assigns a stable per-owner client index.
 */
void CLobby::AssignClientIndex(int32_t& clientIndex, const int32_t ownerId, const char* plyName, int32_t& tmpUid)
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
  int timeouts, int32_t ownerId, msvc8::vector<SSTICommandSource>& commandSources, uint32_t& sourceId
)
{
  static constexpr uint32_t kInvalidCommandSourceId = 0xFF;

  if (localUid == ownerId) {
    if (sourceId == kInvalidCommandSourceId) {
      const uint32_t newId = static_cast<uint32_t>(commandSources.size());
      sourceId = newId;

      const SSTICommandSource entry{static_cast<std::uint32_t>(sourceId), playerName, timeouts};
      commandSources.push_back(entry);
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

    const SSTICommandSource entry{static_cast<std::uint32_t>(peer->mCmdSource), peer->playerName, timeouts};
    commandSources.push_back(entry);
  }

  return peer->mCmdSource;
}
