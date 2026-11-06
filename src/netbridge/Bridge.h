#pragma once

// faf-netbridge: does the whole job of FAF's Java ICE adapter for the FAF
// client (docs/LAUNCHER_ADAPTER_CONTRACT.md), with peer links from netlink.
// Issue #230. Engine addition, not recovered code.
//
//   * JSON-RPC server on --rpc-port: the client's 10 methods, the 5 callbacks
//     as notifications.
//   * GPGNet server on --gpgnet-port for the game: CreateLobby on Idle,
//     HostGame / JoinGame / ConnectToPeer / DisconnectFromPeer, every game
//     message passed to the client.
//   * One netlink::Link and one UDP port per peer on the game's address
//     (default 127.0.0.1); the game sends to <that address>:<that port>, as
//     with the Java adapter.
//   * Issue #233: a game that sends NetlinkHello runs the links itself. For
//     its peers the bridge only passes the signalling over GPGNet
//     (netlink/EngineLinks.h) and relays no datagrams.

#include "netbridge/GpgNet.h"
#include "netbridge/Socket.h"
#include "netlink/GameCounters.h"
#include "netlink/Json.h"
#include "netlink/Link.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace faf::netbridge
{
  struct BridgeOptions
  {
    std::int64_t id = 0;
    std::int64_t gameId = 0;
    std::string login;
    std::uint16_t rpcPort = 0;
    std::uint16_t gpgnetPort = 0;
    std::uint16_t lobbyPort = 0; // 0: a free UDP port from 20000 up, as the Java adapter
    bool forceRelay = false;
    // Ours, not the launcher's: local address for ICE host candidates
    // (empty: every interface), for test hosts that drop inbound UDP to
    // sockets bound to 0.0.0.0.
    std::string bindAddress;
    // Ours: where the game's lobby port is reached (default 127.0.0.1, as the
    // Java adapter); tests on hosts that drop loopback UDP to sockets bound
    // to 0.0.0.0 pass the machine's LAN address.
    std::string gameAddress = "127.0.0.1";
    std::string logPath;
    // Issue #235: send each game datagram twice, the copy this many ms later
    // (-1 off, the default).
    int duplicateGapMs = -1;
    // Issue #239: offer WebRTC data channels to our peers (--webrtc).
    bool webrtc = false;
    // Issue #240: the redundant lane with our peers, each game datagram
    // repeated up to this many times until acked (--redundancy N); 0 is off.
    int redundancy = 0;
    // Issue #289: encrypt that lane with peers that offer it too; off with
    // --no-encrypt or FAF_NETBRIDGE_ENCRYPT=0.
    bool encrypt = true;
    // Tests only: drop this share of game datagrams before sending (0-100).
    int testDropPercent = 0;
    // Seconds between per-peer statistics lines (issue #241); 0 only at close.
    int statsIntervalSec = 10;
  };

  // The game protocol's counts per peer (netlink/GameCounters.h, issue #241).
  using netlink::GameCounters;

  // Parses the launcher's command line (IceOptions). Unknown options are
  // skipped, as picocli's unmatched-arguments mode does.
  BridgeOptions ParseBridgeArgs(int argc, char** argv);

  class Logger
  {
  public:
    explicit Logger(const std::string& path);
    ~Logger();
    void Write(const std::string& line);

  private:
    std::mutex mMutex;
    std::FILE* mFile = nullptr;
  };

  class Bridge
  {
  public:
    Bridge(BridgeOptions options, Logger& log);
    ~Bridge();
    // Runs until quit, or the client goes away outside a running game.
    int Run();

  private:
    struct Peer
    {
      std::int64_t id = 0;
      std::string login;
      bool offerer = false;
      SocketHandle udp = kInvalidSocket;
      std::uint16_t port = 0;
      std::unique_ptr<netlink::Link> link;
      std::uint64_t fromGame = 0;
      std::uint64_t toGame = 0;
      std::mutex countersMutex; // OnReceived runs on libjuice's thread
      GameCounters counters;
    };

    // A peer whose link runs in the game (issue #233).
    struct EnginePeer
    {
      std::string login;
      bool offerer = false;
      std::string state = "new";
      bool connected = false;
    };

    bool Listen();
    void Poll();
    void AcceptRpc();
    void ReadRpc();
    void AcceptGpg();
    void ReadGpg();
    void ReadPeer(Peer& peer);
    void OnGpgLost();
    void OnRpcLost();

    void HandleRpc(const netlink::JsonValue& msg);
    void Respond(std::int64_t id, const netlink::JsonValue& result);
    void RespondError(std::int64_t id, int code, const std::string& message);
    void Notify(const std::string& method, netlink::JsonValue params);
    void WriteRpc(const netlink::JsonValue& msg);

    void HandleGame(const GpgMessage& m);
    void SendToGame(GpgMessage m, bool waitForLobby = true);
    void WriteGame(const GpgMessage& m);

    void NewGameSession();
    // The address the game sends to for this peer: our loopback port, or with
    // in-engine links the peer's engine address.
    std::string ConnectPeer(std::int64_t id, const std::string& login, bool offerer);
    std::uint16_t AddPeer(std::int64_t id, const std::string& login, bool offerer);
    void SendEngineConfig();
    bool HandleEngineMessage(const GpgMessage& m);
    void RemovePeer(std::int64_t id);
    void OnIceMsg(std::int64_t remoteId, const netlink::JsonValue& msg);
    netlink::JsonValue Status() const;
    std::uint16_t PickLobbyPort() const;
    void Log(const std::string& line) { mLog.Write(line); }
    void LogStats(Peer& peer, const char* when);

    BridgeOptions mOptions;
    Logger& mLog;

    SocketHandle mRpcListen = kInvalidSocket;
    SocketHandle mRpcClient = kInvalidSocket;
    SocketHandle mGpgListen = kInvalidSocket;
    SocketHandle mGpgClient = kInvalidSocket;
    std::string mRpcIn;
    GpgDecoder mGpgIn;

    std::string mGameState;
    bool mGameInLobby = false;
    bool mGameEnded = false;
    std::vector<GpgMessage> mForGame; // waits for GameState Lobby
    int mInitMode = 0;
    std::vector<netlink::IceServer> mIceServers;
    netlink::JsonValue mIceServersJson = netlink::JsonValue::Array(); // as setIceServers gave them
    std::uint16_t mLobbyPort = 0;
    std::map<std::int64_t, std::unique_ptr<Peer>> mPeers;
    bool mEngineLinks = false; // the game sent NetlinkHello
    std::map<std::int64_t, EnginePeer> mEnginePeers;

    std::chrono::steady_clock::time_point mNextStats{};
    bool mQuit = false;
    int mExitCode = 0;
  };
} // namespace faf::netbridge
