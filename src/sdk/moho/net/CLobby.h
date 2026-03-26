#pragma once

#include <cstddef>
#include <cstdint>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "IMessageReceiver.h"
#include "INetDatagramHandler.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/Map.h"
#include "lua/LuaObject.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTask.h"
#include "SPeer.h"
namespace moho
{
  class SSTICommandSource;

  class INetConnector;
  class INetConnection;

  class MOHO_EMPTY_BASES CLobby : public CScriptObject,
                                  public IMessageReceiver,
                                  public INetDatagramHandler,
                                  public CPushTask<CLobby>,
                                  public CPullTask<CLobby>
  {
  public:
    /**
     * Address: 0x007C0780 (FUN_007C0780)
     *
     * What it does:
     * Returns cached reflection type for `CLobby`.
     */
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x007C07A0 (FUN_007C07A0)
     *
     * What it does:
     * Packs `{this, GetClass()}` into an `RRef`.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x007C0970 (FUN_007C0970)
     * Mangled: ??0CLobby@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVINetConnector@1@H_NVStrArg@gpg@@H@Z
     *
     * LuaPlus::LuaObject const &,Moho::INetConnector *,int,bool,gpg::StrArg,int
     *
     * What it does:
     * Binds Lua lobby object state, initializes connector/session fields, and
     * registers lobby event handles with connector + wait-handle set.
     */
    CLobby(
      const LuaPlus::LuaObject& clazz,
      INetConnector* connector,
      int32_t maxConnections,
      bool hasNAT,
      gpg::StrArg playerName,
      int32_t localUid
    );

    /**
     * Address: 0x007C0C60 (FUN_007C0C60 deleting wrapper, body via ?1CLobby@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down lobby connector/socket/wait-handle wiring and destroys peer list.
     */
    ~CLobby() override;

    /**
     * Address: 0x004C70A0
     */
    msvc8::string GetErrorDescription() override;

    /**
     * Address: 0x007C62F0
     */
    void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) override;

    /**
     * Address: 0x007C5840 (?HandleMessage@CLobby@@...)
     * Address: 0x1038DA40 (?OnDatagram@CLobby@Moho@@...)
     *
     * What it does:
     * Handles discovery request datagrams and replies with discovery metadata.
     */
    void OnDatagram(CMessage* msg, INetDatagramSocket* sock, u_long address, u_short port) override;

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
     * Address: 0x007CBAD0
     *
     * @param localPeerUidBuf
     * @param newLocalNameBuf
     * @param hostPeerUidBuf
     */
    void ProcessConnectionToHostEstablished(
      const char** localPeerUidBuf, const char** newLocalNameBuf, const char** hostPeerUidBuf
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
     * Address: 0x007C8CB0 (FUN_007C8CB0, `CPushTask_CLobby::PushTask` wrapper)
     *
     * What it does:
     * Called by push-task wrapper to execute lobby push-phase network processing.
     */
    void Push();

    /**
     * Address: 0x007C8BF0 (FUN_007C8BF0, `CPullTask_CLobby::PullTask` wrapper)
     *
     * What it does:
     * Called by pull-task wrapper to execute lobby pull-phase replication.
     */
    void Pull();

    /**
     * Address: 0x007C1B20 (FUN_007C1B20)
     */
    void HostGame();

    /**
     * Address: 0x007C1DA0 (FUN_007C1DA0)
     */
    void JoinGame(u_long address, u_short port, const char* remPlayerName, int remPlayerUid);

    /**
     * Address: 0x007C2210
     *
     * @param dat
     */
    void BroadcastScriptData(LuaPlus::LuaObject& dat);

    /**
     * Address: 0x007C24C0 (FUN_007C24C0)
     *
     * @param id
     * @param dat
     */
    void SendScriptData(int32_t id, LuaPlus::LuaObject& dat);

    /**
     * Address: 0x007C27E0
     *
     * @param state
     * @return
     */
    LuaPlus::LuaObject GetPeers(LuaPlus::LuaState* state);

    /**
     * Address: 0x007C38C0
     *
     * @param dat
     */
    void LaunchGame(const LuaPlus::LuaObject& dat);

    /**
     * Address: 0x007C4E80 (FUN_007C4E80)
     *
     * What it does:
     * Resolves/creates owner peers and assigns deterministic client indices.
     */
    void AssignClientIndex(int32_t& clientIndex, int32_t ownerId, const char* plyName, int32_t& tmpUid);

    /**
     * Address: 0x007C4F60 (FUN_007C4F60)
     *
     * What it does:
     * Resolves or creates the per-owner command source id entry.
     */
    uint32_t AssignCommandSource(
      int timeouts, int32_t ownerId, msvc8::vector<SSTICommandSource>& commandSources, uint32_t& sourceId
    );

  private:
    SPeer* FindPeerByConnection(const INetConnection* connection);
    SPeer* FindPeerByUid(int32_t uid);

  public:
    INetConnector* connector{nullptr};           // 0x78
    int32_t maxConnections{0};                   // 0x7C
    HANDLE event{nullptr};                       // 0x80
    bool joinedLobby{false};                     // 0x84
    INetConnection* peerConnection{nullptr};     // 0x88
    bool mHasNAT{false};                         // 0x8C
    msvc8::string playerName;                    // 0x90
    int32_t localUid{-1};                        // 0xAC
    TDatList<SPeer, void> peers;                 // 0xB0
    bool peersDirty{false};                      // 0xB8
    int32_t mNextId{0};                          // 0xBC
    msvc8::auto_ptr<INetDatagramSocket> mSocket; // 0xC0
    int32_t hostedTime{0};                       // 0xC4
  };
  static_assert(sizeof(CLobby) == 0xC8, "CLobby size must be 0xC8");
  static_assert(offsetof(CLobby, connector) == 0x78, "connector offset");
  static_assert(offsetof(CLobby, maxConnections) == 0x7C, "maxConnections offset");
  static_assert(offsetof(CLobby, event) == 0x80, "event offset");
  static_assert(offsetof(CLobby, joinedLobby) == 0x84, "joinedLobby offset");
  static_assert(offsetof(CLobby, peerConnection) == 0x88, "peerConnection offset");
  static_assert(offsetof(CLobby, mHasNAT) == 0x8C, "mHasNAT offset");
  static_assert(offsetof(CLobby, playerName) == 0x90, "playerName offset");
  static_assert(offsetof(CLobby, localUid) == 0xAC, "localUid offset");
  static_assert(offsetof(CLobby, peers) == 0xB0, "peers offset");
  static_assert(offsetof(CLobby, peersDirty) == 0xB8, "peersDirty offset");
  static_assert(offsetof(CLobby, mNextId) == 0xBC, "mNextId offset");
  static_assert(offsetof(CLobby, mSocket) == 0xC0, "mSocket offset");
  static_assert(offsetof(CLobby, hostedTime) == 0xC4, "hostedTime offset");
} // namespace moho
