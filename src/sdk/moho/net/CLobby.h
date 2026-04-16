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
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTask.h"
#include "SPeer.h"

struct lua_State;

namespace moho
{
  class CScrLuaInitForm;
  struct SSTICommandSource;

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
     * Address: 0x007C0C60 (FUN_007C0C60 deleting wrapper)
     * Address: 0x007C1180 (FUN_007C1180, ?1CLobby@Moho@@UAE@XZ non-deleting body)
     *
     * What it does:
     * Tears down lobby connector/socket/wait-handle wiring and destroys peer list.
     */
    ~CLobby() override;

    /**
     * Task-execution bridge for legacy `CTask` ABI.
     */
    int Execute() override;

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
     * Address: 0x007C5ED0 (FUN_007C5ED0)
     *
     * What it does:
     * Handles connection-loss state transitions and reconnect/eject behavior.
     */
    void Reconnect(INetConnection* connection);

    /**
     * Address: 0x007C62E0 (FUN_007C62E0)
     *
     * What it does:
     * Message-dispatch adapter that forwards one lost-link callback into
     * `Reconnect`.
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
     * Address: 0x007C7990 (FUN_007C7990, Moho::CLobby::EjectPeer)
     *
     * What it does:
     * Host-only eject helper that rejects self-eject and unknown uid targets,
     * then dispatches `KickPeer(peer, reason)` for the matched peer.
     */
    void EjectPeer(int32_t id, const char* reason);

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
     * Address: 0x007C5490 (FUN_007C5490, Moho::CLobby::PushTask)
     *
     * What it does:
     * Runs lobby push-phase network processing for pending connector/socket events.
     */
    void PushTask();

    /**
     * Address: 0x007C8CB0 (FUN_007C8CB0, `CPushTask_CLobby::PushTask` wrapper)
     *
     * What it does:
     * Wrapper that forwards into `PushTask()`.
     */
    void Push();

    /**
     * Address: 0x007C56B0 (FUN_007C56B0, Moho::CLobby::PullTask)
     *
     * What it does:
     * When peer replication is dirty, builds one `LOBMSG_EstablishedPeers`
     * payload, appends all established peer UIDs plus `-1` terminator, and
     * broadcasts the packet to established peers.
     */
    void PullTask();

    /**
     * Address: 0x007C8BF0 (FUN_007C8BF0, `CPullTask_CLobby::PullTask` wrapper)
     *
     * What it does:
     * Wrapper that forwards into `PullTask()`.
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
     * Address: 0x007C5240 (FUN_007C5240, Moho::CLobby::DebugDump)
     *
     * What it does:
     * Logs one summary line for each lobby peer and forwards to connector
     * debug hook.
     */
    void DebugDump();

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

  template <>
  class CScrLuaMetatableFactory<CLobby> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<CLobby>) == 0x08, "CScrLuaMetatableFactory<CLobby> size must be 0x08");

  /**
   * Address: 0x007C0060 (FUN_007C0060, cfunc_InternalCreateDiscoveryService)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_InternalCreateDiscoveryServiceL`.
   */
  int cfunc_InternalCreateDiscoveryService(lua_State* luaContext);

  /**
   * Address: 0x007C0080 (FUN_007C0080, func_InternalCreateDiscoveryService_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateDiscoveryService(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateDiscoveryService_LuaFuncDef();

  /**
   * Address: 0x007C00E0 (FUN_007C00E0, cfunc_InternalCreateDiscoveryServiceL)
   */
  int cfunc_InternalCreateDiscoveryServiceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C0CC0 (FUN_007C0CC0, cfunc_InternalCreateLobby)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to `cfunc_InternalCreateLobbyL`.
   */
  int cfunc_InternalCreateLobby(lua_State* luaContext);

  /**
   * Address: 0x007C0CE0 (FUN_007C0CE0, func_InternalCreateLobby_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateLobby(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateLobby_LuaFuncDef();

  /**
   * Address: 0x007C0D40 (FUN_007C0D40, cfunc_InternalCreateLobbyL)
   *
   * What it does:
   * Validates and decodes one `InternalCreateLobby(...)` Lua call, resolves
   * connector/NAT lanes, constructs `CLobby`, and pushes the lobby Lua object.
   */
  int cfunc_InternalCreateLobbyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BDFDD0 (FUN_00BDFDD0, register_InternalCreateDiscoveryService_LuaFuncDef)
   */
  CScrLuaInitForm* register_InternalCreateDiscoveryService_LuaFuncDef();

  /**
   * Address: 0x00BDFE50 (FUN_00BDFE50, register_InternalCreateLobby_LuaFuncDef)
   */
  CScrLuaInitForm* register_InternalCreateLobby_LuaFuncDef();

  /**
   * Address: 0x007C13E0 (FUN_007C13E0, cfunc_CLobbyDestroy)
   */
  int cfunc_CLobbyDestroy(lua_State* luaContext);

  /**
   * Address: 0x007C1460 (FUN_007C1460, cfunc_CLobbyDestroyL)
   */
  int cfunc_CLobbyDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C1400 (FUN_007C1400, func_CLobbyDestroy_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyDestroy_LuaFuncDef();

  /**
   * Address: 0x007C1530 (FUN_007C1530, cfunc_CLobbyMakeValidGameName)
   */
  int cfunc_CLobbyMakeValidGameName(lua_State* luaContext);

  /**
   * Address: 0x007C15B0 (FUN_007C15B0, cfunc_CLobbyMakeValidGameNameL)
   */
  int cfunc_CLobbyMakeValidGameNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C1550 (FUN_007C1550, func_CLobbyMakeValidGameName_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyMakeValidGameName_LuaFuncDef();

  /**
   * Address: 0x007C18D0 (FUN_007C18D0, cfunc_CLobbyMakeValidPlayerName)
   */
  int cfunc_CLobbyMakeValidPlayerName(lua_State* luaContext);

  /**
   * Address: 0x007C1950 (FUN_007C1950, cfunc_CLobbyMakeValidPlayerNameL)
   */
  int cfunc_CLobbyMakeValidPlayerNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C18F0 (FUN_007C18F0, func_CLobbyMakeValidPlayerName_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyMakeValidPlayerName_LuaFuncDef();

  /**
   * Address: 0x007C1C80 (FUN_007C1C80, cfunc_CLobbyHostGame)
   */
  int cfunc_CLobbyHostGame(lua_State* luaContext);

  /**
   * Address: 0x007C1CA0 (FUN_007C1CA0, func_CLobbyHostGame_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyHostGame_LuaFuncDef();

  /**
   * Address: 0x007C1D00 (FUN_007C1D00, cfunc_CLobbyHostGameL)
   */
  int cfunc_CLobbyHostGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C1FA0 (FUN_007C1FA0, cfunc_CLobbyJoinGame)
   */
  int cfunc_CLobbyJoinGame(lua_State* luaContext);

  /**
   * Address: 0x007C1FC0 (FUN_007C1FC0, func_CLobbyJoinGame_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyJoinGame_LuaFuncDef();

  /**
   * Address: 0x007C2020 (FUN_007C2020, cfunc_CLobbyJoinGameL)
   */
  int cfunc_CLobbyJoinGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2350 (FUN_007C2350, cfunc_CLobbyBroadcastData)
   */
  int cfunc_CLobbyBroadcastData(lua_State* luaContext);

  /**
   * Address: 0x007C2370 (FUN_007C2370, func_CLobbyBroadcastData_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyBroadcastData_LuaFuncDef();

  /**
   * Address: 0x007C23D0 (FUN_007C23D0, cfunc_CLobbyBroadcastDataL)
   */
  int cfunc_CLobbyBroadcastDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2650 (FUN_007C2650, cfunc_CLobbySendData)
   */
  int cfunc_CLobbySendData(lua_State* luaContext);

  /**
   * Address: 0x007C26D0 (FUN_007C26D0, cfunc_CLobbySendDataL)
   */
  int cfunc_CLobbySendDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2670 (FUN_007C2670, func_CLobbySendData_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbySendData_LuaFuncDef();

  /**
   * Address: 0x007C2B00 (FUN_007C2B00, cfunc_CLobbyGetPeers)
   */
  int cfunc_CLobbyGetPeers(lua_State* luaContext);

  /**
   * Address: 0x007C2B20 (FUN_007C2B20, func_CLobbyGetPeers_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyGetPeers_LuaFuncDef();

  /**
   * Address: 0x007C2B80 (FUN_007C2B80, cfunc_CLobbyGetPeersL)
   */
  int cfunc_CLobbyGetPeersL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2C60 (FUN_007C2C60, cfunc_CLobbyGetPeer)
   */
  int cfunc_CLobbyGetPeer(lua_State* luaContext);

  /**
   * Address: 0x007C2C80 (FUN_007C2C80, func_CLobbyGetPeer_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyGetPeer_LuaFuncDef();

  /**
   * Address: 0x007C2CE0 (FUN_007C2CE0, cfunc_CLobbyGetPeerL)
   */
  int cfunc_CLobbyGetPeerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2DF0 (FUN_007C2DF0, cfunc_CLobbyGetLocalPlayerName)
   */
  int cfunc_CLobbyGetLocalPlayerName(lua_State* luaContext);

  /**
   * Address: 0x007C2E10 (FUN_007C2E10, func_CLobbyGetLocalPlayerName_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyGetLocalPlayerName_LuaFuncDef();

  /**
   * Address: 0x007C2E70 (FUN_007C2E70, cfunc_CLobbyGetLocalPlayerNameL)
   */
  int cfunc_CLobbyGetLocalPlayerNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C2F40 (FUN_007C2F40, cfunc_CLobbyGetLocalPlayerID)
   */
  int cfunc_CLobbyGetLocalPlayerID(lua_State* luaContext);

  /**
   * Address: 0x007C2F60 (FUN_007C2F60, func_CLobbyGetLocalPlayerID_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyGetLocalPlayerID_LuaFuncDef();

  /**
   * Address: 0x007C2FC0 (FUN_007C2FC0, cfunc_CLobbyGetLocalPlayerIDL)
   */
  int cfunc_CLobbyGetLocalPlayerIDL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C3090 (FUN_007C3090, cfunc_CLobbyIsHost)
   */
  int cfunc_CLobbyIsHost(lua_State* luaContext);

  /**
   * Address: 0x007C30B0 (FUN_007C30B0, func_CLobbyIsHost_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyIsHost_LuaFuncDef();

  /**
   * Address: 0x007C3110 (FUN_007C3110, cfunc_CLobbyIsHostL)
   */
  int cfunc_CLobbyIsHostL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C31D0 (FUN_007C31D0, cfunc_CLobbyGetLocalPort)
   */
  int cfunc_CLobbyGetLocalPort(lua_State* luaContext);

  /**
   * Address: 0x007C31F0 (FUN_007C31F0, func_CLobbyGetLocalPort_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyGetLocalPort_LuaFuncDef();

  /**
   * Address: 0x007C3250 (FUN_007C3250, cfunc_CLobbyGetLocalPortL)
   */
  int cfunc_CLobbyGetLocalPortL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C3340 (FUN_007C3340, cfunc_CLobbyEjectPeer)
   */
  int cfunc_CLobbyEjectPeer(lua_State* luaContext);

  /**
   * Address: 0x007C33C0 (FUN_007C33C0, cfunc_CLobbyEjectPeerL)
   */
  int cfunc_CLobbyEjectPeerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C3360 (FUN_007C3360, func_CLobbyEjectPeer_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyEjectPeer_LuaFuncDef();

  /**
   * Address: 0x007C34D0 (FUN_007C34D0, cfunc_CLobbyConnectToPeer)
   */
  int cfunc_CLobbyConnectToPeer(lua_State* luaContext);

  /**
   * Address: 0x007C34F0 (FUN_007C34F0, func_CLobbyConnectToPeer_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyConnectToPeer_LuaFuncDef();

  /**
   * Address: 0x007C3550 (FUN_007C3550, cfunc_CLobbyConnectToPeerL)
   */
  int cfunc_CLobbyConnectToPeerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C3760 (FUN_007C3760, cfunc_CLobbyDisconnectFromPeer)
   */
  int cfunc_CLobbyDisconnectFromPeer(lua_State* luaContext);

  /**
   * Address: 0x007C3780 (FUN_007C3780, func_CLobbyDisconnectFromPeer_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyDisconnectFromPeer_LuaFuncDef();

  /**
   * Address: 0x007C37E0 (FUN_007C37E0, cfunc_CLobbyDisconnectFromPeerL)
   */
  int cfunc_CLobbyDisconnectFromPeerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C50E0 (FUN_007C50E0, cfunc_CLobbyLaunchGame)
   */
  int cfunc_CLobbyLaunchGame(lua_State* luaContext);

  /**
   * Address: 0x007C5100 (FUN_007C5100, func_CLobbyLaunchGame_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyLaunchGame_LuaFuncDef();

  /**
   * Address: 0x007C5160 (FUN_007C5160, cfunc_CLobbyLaunchGameL)
   */
  int cfunc_CLobbyLaunchGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C5360 (FUN_007C5360, cfunc_CLobbyDebugDump)
   */
  int cfunc_CLobbyDebugDump(lua_State* luaContext);

  /**
   * Address: 0x007C5380 (FUN_007C5380, func_CLobbyDebugDump_LuaFuncDef)
   */
  CScrLuaInitForm* func_CLobbyDebugDump_LuaFuncDef();

  /**
   * Address: 0x007C53E0 (FUN_007C53E0, cfunc_CLobbyDebugDumpL)
   */
  int cfunc_CLobbyDebugDumpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007C8300 (FUN_007C8300, func_ValidateIPAddress_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ValidateIPAddress`.
   */
  CScrLuaInitForm* func_ValidateIPAddress_LuaFuncDef();
} // namespace moho
