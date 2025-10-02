#pragma once

#include "IMessageReceiver.h"
#include "INetDatagramHandler.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTask.h"
#pragma pack(push, 4)
namespace moho
{
	constexpr auto kPlayerUidBufSize = 0xAu;

	class INetConnector;
	class INetConnection;

	/**
	 * String versions is on 0x00DFEB14
	 */
	enum class ENetworkPlayerState : int32_t
	{
		kUnknown = 0,
		kConnecting = 1,
		kConnected = 2,
		kPending = 3,
		kWaitingJoin = 4,
		kEstablished = 5,
		kDisconnected = 6,
		_Last
	};

	/**
	 * Address: 0x007C0560
	 *
	 * @param state 
	 * @return 
	 */
	void ENetworkPlayerStateToStr(ENetworkPlayerState state, msvc8::string& out);

	class SPeer :
		public TDatListItem<SPeer, void>
	{
	public:
		msvc8::string playerName;
		int32_t uid;
		u_long address;
		u_short port;
		ENetworkPlayerState state;
		int32_t v2;
		INetConnection* peerConnection;
		msvc8::set<int32_t> establishedUids;
		int32_t ctr;

		/**
		 * Address: 0x007C05C0
		 */
		SPeer(
			const msvc8::string& playerName,
			const int32_t uid,
			const u_long address,
			const u_short port, 
			INetConnection* connection,
			const ENetworkPlayerState state
		) :
			playerName(playerName),
			uid(uid),
			address(address),
			port(port),
			state(state),
			v2(0),
			peerConnection(connection),
			ctr(-1)
		{
		}

		/**
		 * Address: 0x007C0690
		 * @return 
		 */
		msvc8::string ToString() const;

		/**
		 * Address: 0x007C77F0
		 * @return
		 */
		SPeer* Cleanup();
	};
	static_assert(sizeof(SPeer) == 0x50, "SPeer must be 0x50");

	class MOHO_EMPTY_BASES CLobby :
		public CScriptObject,
		public IMessageReceiver,
		public INetDatagramHandler,
		public CPushTask<CLobby>,
		public CPullTask<CLobby>
	{
	public:
		/**
		 * Address: 0x007C0780
		 */
		gpg::RType* GetClass() const override;

		/**
		 * Address: 0x007C07A0
		 */
		gpg::RRef GetDerivedObjectRef() override;

		/**
		 * Address: 0x007C0C60
		 */
		~CLobby() override;

		/**
		 * Address: 0x004C70A0
		 */
		msvc8::string GetErrorDescription() override;

		/**
		 * Address: 0x007C62F0
		 */
		void Receive(CMessage* message, CMessageDispatcher* dispatcher) override;

		/**
		 * Address: 0x007C64C0
		 */
		void OnJoin(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C6AD0
		 */
		void OnRejected(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C6BD0
		 */
		void OnWelcome(CMessage* message, const INetConnection* connection);

		/**
		 * Address: 0x007C7010
		 */
		void OnNewPeer(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C76A0
		 */
		void OnDeletePeer(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C7C10
		 */
		void OnEstablishedPeers(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C6EE0
		 */
		void OnScriptData(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C5B60
		 */
		void OnConnectionFailed(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C5CA0
		 */
		void OnConnectionMade(const CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C5ED0
		 */
		void OnConnectionLost(CMessage* message, INetConnection* connection);

		/**
		 * Address: 0x007C77F0
		 */
		void PeerDisconnected(SPeer* peer);

		/**
		 * Address: 0x007C8040
		 */
		void BroadcastStream(const CMessageStream& s);

		/**
		 * Address: 0x007C1720
		 *
		 *  Make a lobby-unique player name (case-insensitive), max length 24.
		 * Algorithm (from IDA):
		 *  - Truncate desired to 24.
		 *  - If uid != localUID and name equals host's name (stricmp == 0), append "1","2",...
		 *    (trim base to keep total <= 24) and retry.
		 *  - Scan all peers (uid differs). If any equals (stricmp == 0), append suffix and retry.
		 *  - Return final unique name.
		 *
		 * @param joiningName 
		 * @param uid 
		 * @return 
		 */
		msvc8::string MakeValidPlayerName(msvc8::string joiningName, int32_t uid);

		/**
		 * Address: 0x007C7FA0
		 * In MohoEngine.dll it's called `Msg`.
		 */
		void Msg(gpg::StrArg msg);

		/**
		 * Address: 0x007C7FC0
		 * In MohoEngine.dll it's called `Msgf`.
		 */
		void Msgf(const char* fmt, ...);

		/**
		 * Address: 0x007C8070
		 *
		 * @param peer 
		 * @param connection 
		 */
		void SendPeerInfo(const SPeer* peer, INetConnection* connection) const;

		/**
		 * Address: 0x007CBAD0
		 *
		 * @param localPeerUidBuf 
		 * @param newLocalNameBuf 
		 * @param hostPeerUidBuf 
		 */
		void ProcessConnectionToHostEstablished(
			const char** localPeerUidBuf, 
			const char** newLocalNameBuf, 
			const char** hostPeerUidBuf
		);

		/**
		 * Address: 0x007CBD20
		 */
		void ProcessEjected();

		/**
		 * Address: 0x007C7190
		 *
		 * @param address 
		 * @param port 
		 * @param name 
		 * @param uid 
		 */
		void ConnectToPeer(u_long address, u_short port, const msvc8::string& name, int32_t uid);

		/**
		 * Address: 0x007C7790
		 *
		 * @param uid 
		 */
		void DisconnectFromPeer(int32_t uid);

		/**
		 * Address: 0x007C7AC0
		 *
		 * @param peer 
		 * @param reason 
		 */
		void KickPeer(SPeer* peer, const char* reason);

		/**
		 * Address: 0x00B57C8C
		 *
		 * Convenience wrapper that mimics func_GetLocalPlayerID exactly.
		 * `base` is passed in the third parameter; typical call is base=10 (0xA).
		 */
		static char* GetLocalPlayerId(uint32_t uid, char* out, unsigned base) noexcept;

	public:
		INetConnector* connector;
		int32_t maxConnections;
		HANDLE event;
		bool joinedLobby;
		INetConnection* peerConnection;
		bool mHasNAT;
		msvc8::string playerName;
		int32_t localUid;
		TDatList<SPeer, void> peers;
		bool peersDirty;
		uint32_t lastUid;
		int32_t v38;
		int32_t v39;
	};
	static_assert(sizeof(CLobby) == 0xC8, "CLobby size must be 0xC8");
	static_assert(offsetof(CLobby, connector) == 0x78, "connector offset");
}

#pragma pack(pop)
