#include "CLobby.h"

#include "CMessageStream.h"
#include "CNetUDPConnection.h"
#include "ELobbyMsg.h"
#include "INetConnection.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "moho/client/Localization.h"
#include "moho/misc/StringUtils.h"
using namespace moho;

void moho::ENetworkPlayerStateToStr(const ENetworkPlayerState state, msvc8::string& out) {
	if (state >= ENetworkPlayerState::_Last) {
		out = gpg::STR_Printf("%d", static_cast<int32_t>(state));
		return;
	}

	switch (state) {
	case ENetworkPlayerState::kUnknown:      
		out = "Unknown";
		return;
	case ENetworkPlayerState::kConnecting:   
		out = "Connecting";
		return;
	case ENetworkPlayerState::kConnected:    
		out = "Connected";
		return;
	case ENetworkPlayerState::kPending:      
		out = "Pending";
		return;
	case ENetworkPlayerState::kWaitingJoin:  
		out = "WaitingJoin";
		return;
	case ENetworkPlayerState::kEstablished:  
		out = "Established";
		return;
	case ENetworkPlayerState::kDisconnected: 
		out = "Disconnected";
	default: ;
	}
}

msvc8::string SPeer::ToString() const {
	const auto hostname = NET_GetHostName(address);
	return gpg::STR_Printf("\"%s\" [%s:%d, uid=%d]", playerName.c_str(), hostname.c_str(), port, uid);
}

SPeer* SPeer::Cleanup() {
	establishedUids.clear();
	playerName.clear();
	return static_cast<SPeer*>(ListUnlink());
}

gpg::RType* CLobby::GetClass() const {
	return nullptr;
}

gpg::RRef CLobby::GetDerivedObjectRef() {
	return gpg::RRef{};
}

CLobby::~CLobby() {
}

msvc8::string CLobby::GetErrorDescription() {
	return CScriptObject::GetErrorDescription();
}

// 0x007C62F0
// Called by 00487885:
void CLobby::Receive(CMessage* message, CMessageDispatcher* dispatcher) {
	const auto udpConnection = static_cast<CNetUDPConnection*>(dispatcher);
	const auto sender = static_cast<INetConnection*>(udpConnection);

	switch (const ELobbyMsg type = message->GetType()) {
	case ELobbyMsg::LOBMSG_Join:
		OnJoin(message, sender);
		break;
	case ELobbyMsg::LOBMSG_Rejected:
		if (sender == peerConnection) {
			OnRejected(message, sender);
		}
		break;
	case ELobbyMsg::LOBMSG_Welcome:
		OnWelcome(message, sender);
		break;
	case ELobbyMsg::LOBMSG_NewPeer:
		OnNewPeer(message, sender);
		break;
	case ELobbyMsg::LOBMSG_DeletePeer:
		OnDeletePeer(message, sender);
		break;
	case ELobbyMsg::LOBMSG_EstablishedPeers:
		OnEstablishedPeers(message, sender);
		break;
	case ELobbyMsg::LOBMSG_BroadcastScriptData:
	case ELobbyMsg::LOBMSG_DirectScriptData:
		OnScriptData(message, sender);
		break;
	case ELobbyMsg::LOBMSG_ConnFailed:
		OnConnectionFailed(message, sender);
		break;
	case ELobbyMsg::LOBMSG_ConnMade:
		OnConnectionMade(message, sender);
		break;
	case ELobbyMsg::LOBMSG_ConnLostErrored:
	case ELobbyMsg::LOBMSG_ConnLostEof:
		OnConnectionLost(message, sender);
		break;
	default:
		gpg::Logf("LOBBY: Ignoring unrecognized lobby message w/ type %d",
			static_cast<int32_t>(type));
		break;
	}
}

// 0x007C64C0
void CLobby::OnJoin(CMessage* message, INetConnection* connection) {
	CMessageStream stream{ message };
	const gpg::BinaryReader br{ &stream };

	msvc8::string joiningName;
	br.ReadString(&joiningName);

	std::uint32_t requestedUid = 0;
	br.ReadExact(requestedUid);

	SPeer* player = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			player = it;
			break;
		}
	}

	if (player == nullptr) {
		gpg::Logf("LOBBY: ignoring unexpected join (no player for conn=%p)", connection);
		return;
	}

	if (player->state != ENetworkPlayerState::kWaitingJoin) {
		const msvc8::string who = player->ToString();
		gpg::Logf("LOBBY: ignoring unexpected join (name=\"%s\", uid=%d) from %s",
			joiningName.c_str(), requestedUid, who.c_str());
		return;
	}

	const auto fromStr = connection->ToString();
	gpg::Logf("LOBBY: Got join (name=\"%s\", uid=%u) from %s",
		joiningName.c_str(), requestedUid, fromStr.c_str());

	bool canAccept = true;
	// host
	if (peerConnection == nullptr) {
		int32_t connectedPlayersCount = 0;
		for (const auto* it : peers.owners()) {
			if (it->state == ENetworkPlayerState::kEstablished) {
				connectedPlayersCount++;
			}
		}

		if (connectedPlayersCount >= maxConnections) {
			canAccept = false;
		}
	}

	if (!canAccept) {
		CMessage lobbyFull{ ELobbyMsg::LOBMSG_Rejected };
		CMessageStream lobbyFullStream{ &lobbyFull };
		lobbyFullStream.Write("LobbyFull");

		connection->Write(lobbyFullStream);
		connection->ScheduleDestroy();
		return;
	}

	player->state = ENetworkPlayerState::kEstablished;
	peersDirty = true; // meaning "changed/dirty" ?

	if (player->uid == -1) {
		player->uid = static_cast<int32_t>(lastUid++);
		gpg::Logf("LOBBY: assigning uid %d", player->uid);
	}

	CMessage accept{ ELobbyMsg::LOBMSG_Welcome };
	CMessageStream acceptStream{ &accept };
	if (peerConnection == nullptr) {
		const auto normalized = MakeValidPlayerName(joiningName, player->uid);
		player->playerName.assign(normalized, 0, msvc8::string::npos);

		// Payload from the dump: hostName, hostUid, assignedUid, joiningNameConfirmed, lobbyFlags(v39).
		acceptStream.Write(playerName);
		acceptStream.Write(localUid);
		acceptStream.Write(player->uid);
		acceptStream.Write(player->playerName);
		acceptStream.Write(v39);
	}
	connection->Write(acceptStream);

	LuaPlus::LuaState* l = mLuaObj.GetActiveState();
	const msvc8::string locMsg = Loc(l, "<LOC Engine0004>Connection to %s established.");
	Msgf(locMsg.c_str(), player->playerName.c_str());

	if (peerConnection == nullptr && mHasNAT) {
		for (const auto* it : peers.owners()) {
			if (it->state == ENetworkPlayerState::kEstablished && it != player) {
				SendPeerInfo(it, connection);
				SendPeerInfo(player, it->peerConnection);
			}
		}
	}
}

// 0x007C6AD0
void CLobby::OnRejected(CMessage* message, [[maybe_unused]] INetConnection* connection) {
	CMessageStream s(message, CMessageStream::Access::kReadOnly);
	const gpg::BinaryReader br{ &s };
	msvc8::string reason;
	br.ReadString(&reason);

	const char* str = reason.c_str();
	CallbackStr("Ejected", &str);
}

// 0x007C6BD0
void CLobby::OnWelcome(CMessage* message, const INetConnection* connection) {
	SPeer* peer = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	if (peer == nullptr || peer->state != ENetworkPlayerState::kConnected) {
		gpg::Logf("LOBBY: ignoring unexpected welcome message.");
		return;
	}

	peer->state = ENetworkPlayerState::kEstablished;
	peersDirty = true;

	if (connection == peerConnection) {
		// If this is a host.
		CMessageStream s(message, CMessageStream::Access::kReadOnly);
		const gpg::BinaryReader br{ &s };

		msvc8::string hostDisplayName;  // v20
		int32_t       hostUid = 0;      // v17 (read as 4 bytes)
		int32_t       assignedUid = 0;  // v16 (read as 4 bytes)
		msvc8::string renameSelfTo;     // v19
		int32_t       sessionOrSeq = 0; // v18 -> a2->v39

		br.ReadString(&hostDisplayName);
		br.ReadExact(hostUid);
		br.ReadExact(assignedUid);
		br.ReadString(&renameSelfTo);
		br.ReadExact(sessionOrSeq);

		v39 = sessionOrSeq;

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
		GetLocalPlayerId(peer->uid, hostPeerUidBuf, sizeof(hostPeerUidBuf));
		GetLocalPlayerId(localUid, localPeerUidBuf, sizeof(localPeerUidBuf));

		const char* pHost = hostPeerUidBuf;
		const char* pLocal = localPeerUidBuf;
		const char* pName = const_cast<char*>(playerName.c_str());

		ProcessConnectionToHostEstablished(&pLocal, &pName, &pHost);
	}

	LuaPlus::LuaState* l = mLuaObj.GetActiveState();
	const msvc8::string locMsg = Loc(l, "<LOC Engine0004>Connection to %s established.");
	Msgf(locMsg.c_str(), peer->playerName.c_str());
}

// 0x007C7010
void CLobby::OnNewPeer(CMessage* message, INetConnection* connection) {
	if (connection != peerConnection) {
		// If this is not a host.
		const auto connStr = connection->ToString();
		gpg::Logf("LOBBY: ignoring NewPeer msg from %s.", connStr.c_str());
		return;
	}

	CMessageStream s(message, CMessageStream::Access::kReadOnly);
	const gpg::BinaryReader br{ &s };

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

// 0x007C76A0
void CLobby::OnDeletePeer(CMessage* message, INetConnection* connection) {
	if (connection != peerConnection) {
		// If this is not a host.
		const auto connStr = connection->ToString();
		gpg::Logf("LOBBY: ignoring DeletePeer msg from %s.", connStr.c_str());
		return;
	}

	CMessageStream s(message, CMessageStream::Access::kReadOnly);
	const gpg::BinaryReader br{ &s };

	int32_t uid{ 0 };
	br.ReadExact(uid);

	DisconnectFromPeer(uid);
}

// 0x007C7C10
void CLobby::OnEstablishedPeers(CMessage* message, INetConnection* connection) {
	SPeer* peer = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	if (peer == nullptr) {
		const msvc8::string connStr = connection->ToString();
		gpg::Logf("LOBBY: ignoring EstablishedPeers message from unknown connection %s.", connStr.c_str());
		return;
	}

	peer->establishedUids.clear();

	CMessageStream s(message, CMessageStream::Access::kReadOnly);
	const gpg::BinaryReader br{ &s };

	while(true) {
		int32_t uid = 0;
		br.ReadExact(uid);
		if (uid == -1) {
			// end marker
			break;
		}
		peer->establishedUids.insert(uid);
	}

	msvc8::string joined;
	bool first = true;
	for (const int32_t uid : peer->establishedUids) {
		if (!first) {
			joined.append(", ", 2);
		}
		first = false;

		msvc8::string one = gpg::STR_Printf("%u", uid);
		joined.append(one.c_str());
	}

	const msvc8::string who = peer->ToString();
	gpg::Logf("LOBBY: %s has established connections to: %s", who.c_str(), joined.c_str());

	LuaPlus::LuaObject arr;
	LuaPlus::LuaState* l = mLuaObj.GetActiveState();
	arr.AssignNewTable(l, 0, 0);

	int idx = 1;
	char idBuf[kPlayerUidBufSize]{};
	for (const auto uid : peer->establishedUids) {
		GetLocalPlayerId(uid, idBuf, sizeof(idBuf));
		arr.SetString(idx++, idBuf);
	}

	char selfId[kPlayerUidBufSize]{};
	GetLocalPlayerId(peer->uid, selfId, sizeof(selfId));

	const char* pSelfId = selfId;
	LuaPCall("EstablishedPeers", &pSelfId, &arr);
}

// 0x007C6EE0
void CLobby::OnScriptData(CMessage* message, INetConnection* connection) {
	CMessageStream s(message, CMessageStream::Access::kReadOnly);
	const gpg::BinaryReader br{ &s };

	LuaPlus::LuaObject script;
	mLuaObj.SCR_FromByteStream(script, mLuaObj.m_state, &br);

	const SPeer* peer = nullptr;
	for (const auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	char idBuf[kPlayerUidBufSize]{};
	if (peer != nullptr) {
		GetLocalPlayerId(peer->uid, idBuf, sizeof(idBuf));
		script.SetString("SenderID", reinterpret_cast<const char*>(&idBuf));
		script.SetString("SenderName", peer->playerName.c_str());
	} else {
		GetLocalPlayerId(0, idBuf, sizeof(idBuf));
		script.SetString("SenderID", idBuf);

		const msvc8::string connStr = connection ? connection->ToString() : msvc8::string{};
		script.SetString("SenderName", connStr.c_str());
	}

	LuaCall("DataReceived", &script);
}

// 0x007C5B60
void CLobby::OnConnectionFailed([[maybe_unused]] CMessage* message, INetConnection* connection) {
	if (connection == peerConnection) {
		// If this is not a host.
		gpg::Logf("LOBBY: connection to master failed -- giving up.");
		auto reason = "HostLeft";
		CallbackStr("ConnectionFailed", &reason);
		return;
	}

	SPeer* peer = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	const auto connStr = connection->ToString();
	gpg::Logf("LOBBY: connection to %s failed, retrying...", connStr.c_str());

	INetConnection* newConn = connector->Connect(peer->address, peer->port);
	peer->peerConnection = newConn;

	// Subscribe lobby as receiver for a message range [0xC8..0xD2]
	constexpr uint8_t msgMin = static_cast<uint8_t>(ELobbyMsg::LOBMSG_ConnFailed); // 200
	constexpr uint8_t msgMax = static_cast<uint8_t>(ELobbyMsg::LOBMSG_Unknown6); // 210

	newConn->PushReceiver(msgMin, msgMax, this);

	connection->ScheduleDestroy();
}

// 0x007C5CA0
void CLobby::OnConnectionMade([[maybe_unused]] const CMessage* message, INetConnection* connection) {
	SPeer* peer = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	msvc8::string peerStateStr;
	ENetworkPlayerStateToStr(peer->state, peerStateStr);
	const msvc8::string who = peer->ToString();
	gpg::Logf("LOBBY: connection to %s made, status=%s.", who.c_str(), peerStateStr.c_str());

	constexpr uint8_t msgMin = static_cast<uint8_t>(ELobbyMsg::LOBMSG_Join); // 100
	constexpr uint8_t msgMax = static_cast<uint8_t>(ELobbyMsg::LOBMSG_HandshakeLast); // 120

	if (peer->state == ENetworkPlayerState::kConnecting) {
		peer->state = ENetworkPlayerState::kConnected;
		connection->PushReceiver(msgMin, msgMax, this);

		CMessage msg{ ELobbyMsg::LOBMSG_Join };
		CMessageStream s(msg, CMessageStream::Access::kReadWrite);

		s.Write(playerName);
		s.Write(localUid);

		connection->Write(s);
	} else {
		if (peer->state != ENetworkPlayerState::kPending) {
			GPG_UNREACHABLE()
		}

		peer->state = ENetworkPlayerState::kWaitingJoin;
		connection->PushReceiver(msgMin, msgMax, this);
	}
}

// 0x007C5ED0
void CLobby::OnConnectionLost(CMessage* message, INetConnection* connection) {
	if (connection == peerConnection) {
		// If this is not a host.
		gpg::Logf("LOBBY: host disconnected.");
		auto reason = "HostLeft";
		CallbackStr("ConnectionFailed", &reason);
		return;
	}

	SPeer* peer = nullptr;
	for (auto* it : peers.owners()) {
		if (it->peerConnection == connection) {
			peer = it;
			break;
		}
	}

	constexpr uint8_t msgMin = static_cast<uint8_t>(ELobbyMsg::LOBMSG_ConnFailed); // 200
	constexpr uint8_t msgMax = static_cast<uint8_t>(ELobbyMsg::LOBMSG_Unknown6); // 210

	switch(peer->state) {
		case ENetworkPlayerState::kConnecting:
		case ENetworkPlayerState::kConnected: {
			const auto peerStr = peer->ToString();
			gpg::Logf("LOBBY: connection to %s lost, retrying", peerStr.c_str());
			v39 = -1;
			const auto newConn = connector->Connect(peer->address, peer->port);
			peer->peerConnection = newConn;
			newConn->PushReceiver(msgMin, msgMax, this);
			peer->state = ENetworkPlayerState::kConnecting;
			connection->ScheduleDestroy();
			break;
		}
		case ENetworkPlayerState::kPending:
			GPG_UNREACHABLE()
				break;
		case ENetworkPlayerState::kWaitingJoin: {
			const auto peerStr = peer->ToString();
			gpg::Logf("LOBBY: lost connection to %s, waiting for them to reconnect.", peerStr.c_str());
			peer->state = ENetworkPlayerState::kPending;
			const auto newConn = connector->Accept(peer->address, peer->port);
			peer->peerConnection = newConn;
			newConn->PushReceiver(msgMin, msgMax, this);
			connection->ScheduleDestroy();
			break;
		}
		case ENetworkPlayerState::kEstablished: {
			peersDirty = true;
			const auto peerStr = peer->ToString();
			if (peerConnection != nullptr && !mHasNAT) {
				gpg::Logf("LOBBY: lost connection to %s, waiting for them to reconnect.", peerStr.c_str());

				LuaPlus::LuaState* l = mLuaObj.GetActiveState();
				const msvc8::string locMsg = Loc(l, "<LOC Engine0004>Connection to %s established.");
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
				newConn->PushReceiver(msgMin, msgMax, this);
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
			GPG_UNREACHABLE()
			break;
	}
}

// 0x007C77F0
void CLobby::PeerDisconnected(SPeer* peer) {
	peer->peerConnection->ScheduleDestroy();
	peer->ListUnlink();

	char idBuf[kPlayerUidBufSize]{};
	GetLocalPlayerId(peer->uid, idBuf, sizeof(idBuf));

	const char* uidStr = idBuf;
	const char* nameStr = peer->playerName.c_str();
	CallbackStr("PeerDisconnected", &uidStr, &nameStr);

	if (peer->state == ENetworkPlayerState::kEstablished || 
		peer->state == ENetworkPlayerState::kDisconnected) 
	{
		peersDirty = true;
	}

	if (peerConnection == nullptr && mHasNAT) {
		CMessage msg{ ELobbyMsg::LOBMSG_DeletePeer };
		CMessageStream s(msg, CMessageStream::Access::kReadWrite);

		s.Write(localUid);

		BroadcastStream(s);
	}

	peer->Cleanup();
	delete peer;
}

// 0x007C8040
void CLobby::BroadcastStream(const CMessageStream& s) {
	for (const auto* it : peers.owners()) {
		if (it->state == ENetworkPlayerState::kEstablished) {
			it->peerConnection->Write(s);
		}
	}
}

// 0x007C1720
msvc8::string CLobby::MakeValidPlayerName(msvc8::string joiningName, const int32_t uid) {
	static constexpr std::size_t maxLen = 24;

	const msvc8::string desired = joiningName;
	if (joiningName.size() > maxLen) {
		joiningName = desired.substr(0, maxLen);
	}

	int suffix = 1;
	while(true) {
		if (uid == localUid) {
			break;
		}

		if (_stricmp(playerName.c_str(), joiningName.c_str()) == 0) {
			msvc8::string num = gpg::STR_Printf("%d", suffix++);
			const std::size_t keep = (num.size() < maxLen) ? (maxLen - num.size()) : 0;
			joiningName = desired.substr(0, keep) + num;
			continue;
		}

		bool conflict = false;
		for (const auto* it : peers.owners()) {
			if (it->uid == uid) {
				continue;
			}

			if (_stricmp(it->playerName.c_str(), joiningName.c_str()) == 0) {
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

// 0x007C7FA0
void CLobby::Msg(gpg::StrArg msg) {
	CallbackStr("SystemMessage", &msg);
}

// 0x007C7FC0
void CLobby::Msgf(const char* fmt, ...) {
	va_list va;
	va_start(va, fmt);
	const msvc8::string msg = gpg::STR_Va(fmt, va);
	va_end(va);

	const char* str = msg.c_str();
	CallbackStr("SystemMessage", &str);
}

// 0x007C8070
void CLobby::SendPeerInfo(const SPeer* peer, INetConnection* connection) const {
	if (connection == nullptr) {
		return;
	}

	const auto connectionStr = connection->ToString();
	const auto peerStr = peer->ToString();
	gpg::Logf("LOBBY: sending info on peer %s to %s", peerStr.c_str(), connectionStr.c_str());

	CMessage msg{ ELobbyMsg::LOBMSG_NewPeer };
	CMessageStream s(msg, CMessageStream::Access::kReadWrite);

	s.Write(playerName);
	s.Write(peer->address);
	s.Write(peer->port);
	s.Write(peer->uid);
	connection->Write(s);
}

// 0x007CBAD0
void CLobby::ProcessConnectionToHostEstablished(
	const char** localPeerUidBuf, 
	const char** newLocalNameBuf, 
	const char** hostPeerUidBuf)
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

// 0x007CBD20
void CLobby::ProcessEjected() {
	LuaPlus::LuaObject dest;
	FindScript(&dest, "Ejected");
	if (dest) {
		LuaPlus::LuaObject self(this->mLuaObj);
		LuaPlus::LuaFunction<void> fn(dest);
		fn.Call(self, "KickedByHost");
	}

	// TODO: Some magic/replace node to mPrev happens here, but we do not have TDatList<> according to RTTI.
}

// 0x007C7190
void CLobby::ConnectToPeer(const u_long address, const u_short port, const msvc8::string& name, const int32_t uid) {
	for (const auto* it : peers.owners()) {
		if (it->uid == uid) {
			const msvc8::string msg = gpg::STR_Printf("Attempting to redundently add peer uid=%d", uid);
			throw std::runtime_error(msg.c_str());
		}
	}

	if (uid == localUid) {
		const msvc8::string msg = gpg::STR_Printf("Attempting to add peer uid=%d, but that is us.", uid);
		throw std::runtime_error(msg.c_str());
	}

	// TODO: lob_IgnoreNames should be TConVar<std::string>
	static msvc8::string lob_IgnoreNames{};
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

	constexpr uint8_t msgMin = static_cast<uint8_t>(ELobbyMsg::LOBMSG_ConnFailed); // 200
	constexpr uint8_t msgMax = static_cast<uint8_t>(ELobbyMsg::LOBMSG_Unknown6); // 210

	connection->PushReceiver(msgMin, msgMax, this);

	const auto validName = MakeValidPlayerName(name, uid);
	const auto peer = new SPeer(validName, uid, address, port, connection, initial);
	peers.push_back(peer);

	const auto connStr = peer->ToString();
	gpg::Logf("LOBBY: Adding peer %s", connStr.c_str());

	LuaPlus::LuaState* l = mLuaObj.GetActiveState();
	const msvc8::string locMsg = Loc(l, "<LOC Engine0005>Connecting to %s...");
	Msgf(locMsg.c_str(), peer->playerName.c_str());
}

// 0x007C7790
void CLobby::DisconnectFromPeer(const int32_t uid) {
	if (localUid == uid) {
		gpg::Logf("LOBBY: we've been ejected.");
		ProcessEjected();
		return;
	}

	for (auto* it : peers.owners()) {
		if (it->uid == uid) {
			PeerDisconnected(it);
			return;
		}
	}

	gpg::Logf("LOBBY: deleting unknown peer uid %d.", uid);
}

// 0x007C7AC0
void CLobby::KickPeer(SPeer* peer, const char* reason) {
	if (peerConnection != nullptr) {
		throw std::runtime_error("Only the host can eject players.");
	}

	if (peer->state != ENetworkPlayerState::kDisconnected) {
		CMessage msg{ ELobbyMsg::LOBMSG_Rejected };
		CMessageStream s(msg, CMessageStream::Access::kReadWrite);

		s.Write(reason);
		peer->peerConnection->Write(s);
	}

	PeerDisconnected(peer);
}

/**
 * Address: 0x00B57C4C
 *
 * Convert integer uid to string using given base (2..36).
 * If base == 10 and uid < 0, a leading '-' is emitted and magnitude is printed.
 * Digits above 9 are lowercase 'a' - 'z', matching original sub_B57C4C.
 * Caller must provide a sufficiently large buffer (>= 33 bytes for 32-bit ints).
 * Returns out for chaining.
 */
inline char* FormatPlayerId(const uint32_t uid, char* out, unsigned base) noexcept {
	if (!out) {
		return out;
	}

	// Clamp base to sane range; original code assumes valid input.
	if (base < 2 || base > 36) {
		base = 10;
	}

	char* p = out;

	// Emit sign only for base-10 negative values (matches func_GetLocalPlayerID).
	const bool emitMinus = (base == 10 && uid < 0);
	// Work in unsigned to mirror wraparound behavior for INT_MIN in original.
	uint32_t v = uid;
	if (emitMinus) {
		*p++ = '-';
		v = static_cast<uint32_t>(-static_cast<int32_t>(v));
	}

	// Generate digits in reverse order.
	char* firstDigit = p;
	do {
		const uint32_t d = v % base;
		v /= base;
		*p++ = static_cast<char>(d < 10 ? ('0' + d) : ('a' + (d - 10)));
	} while (v);

	// NUL-terminate.
	*p = '\0';

	// Reverse the digits range [firstDigit, p).
	for (char* l = firstDigit, *r = p - 1; l < r; ++l, --r) {
		const char tmp = *l; *l = *r; *r = tmp;
	}

	return out;
}

char* CLobby::GetLocalPlayerId(const uint32_t uid, char* out, const unsigned base) noexcept {
	return FormatPlayerId(uid, out, base);
}
