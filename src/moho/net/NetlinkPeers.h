#pragma once

// Engine addition (issue #233), not in the binary: the peer links in the game
// itself. With net_InEngineLinks 1 the game announces itself to faf-netbridge
// after GameState Idle (NetlinkHello); the bridge then sends each peer's ICE
// signalling over GPGNet instead of linking for the game, and this module
// runs one netlink::Link per peer behind a peer transport (#232) at the
// address netlink::EngineAddressFor gives that peer. The lobby, the
// connection and the packets are the game's own; only the path of each
// datagram changes. Messages: src/netlink/EngineLinks.h.

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "netlink/PathChoice.h"

#include <cstdint>
#include <string>
#include <vector>

namespace moho
{
  // Issue #322: one peer link as the network panel shows it.
  struct SNetlinkPeerInfo
  {
    std::int64_t id = 0;
    std::string login;
    std::string state;      // netlink::LinkStateName
    bool connected = false;
    std::string localType;  // the selected pair's candidate types ("host", "srflx", "prflx", "relay")
    std::string remoteType;
    double rttMs = -1;      // the offerer's echo, else the lane's RTT; -1 when neither has a sample
    bool onLane = false;    // the redundant lane (#240)
    bool laneEncrypted = false; // #289
    std::uint32_t attempts = 0;
    faf::netlink::PathChoice choice; // the path picked in the panel (#322)
    // The game protocol's own counts on this link (netlink/GameCounters.h).
    std::uint64_t sent = 0;
    std::uint64_t resends = 0;
    std::uint64_t received = 0;
    std::uint64_t lost = 0;
    double lossPercent = 0;
  };

  struct SNetlinkSnapshot
  {
    // "native" (no adapter, #274), "in-engine" (behind faf-netbridge, #233), or
    // empty: the links belong to the launcher's ICE adapter, not to this game.
    std::string mode;
    std::vector<SNetlinkPeerInfo> peers;
    // The latest network log lines (NETLINK: and NET:), oldest first.
    std::vector<std::string> log;
    // The ICE servers new links use, "host:port" (IceServerName).
    std::vector<std::string> turnServers;
    std::vector<std::string> stunServers;
    bool forceRelay = false; // /nativenetrelay: relayed candidates only, whatever the choice
  };

  // A copy of the game's peer links and recent network log lines. Any thread.
  [[nodiscard]] SNetlinkSnapshot NETLINK_GetSnapshot();

  // Starts keeping network log lines for NETLINK_GetSnapshot. Called by the
  // modes that run links and by the panel; idempotent. Any thread.
  void NETLINK_KeepLogLines();

  // Issue #321: drops the link to that peer and connects again (Link::Reconnect);
  // issue #322: with a choice, on that path from now on. False when no link to it
  // exists. Any thread.
  bool NETLINK_ReconnectPeer(std::int64_t id, const faf::netlink::PathChoice* choice = nullptr);

  class CGpgNetInterface;
  struct SNetCommandArg;

  // After GameState Idle: announces in-engine links when net_InEngineLinks
  // is on. Main thread.
  void NETLINK_SayHello(CGpgNetInterface& gpgnet);

  // A Netlink* command from the bridge. False for any other command. Main
  // thread (CGpgNetInterface::PullTask).
  bool NETLINK_HandleCommand(const fa::string& name, const fa::vector<SNetCommandArg>& args);

  // Closes every link (GPGNet shut down).
  void NETLINK_Shutdown();

  // Issue #274, native mode (net_NativeNet, or /nativenet): no ICE adapter;
  // the launcher talks to the game directly and the game links every peer
  // itself (docs/LAUNCHER_NATIVE_NETWORK.md). Off, nothing below does
  // anything and the game talks to an adapter as the shipped game does.
  [[nodiscard]] bool NATIVENET_Enabled();

  // After GameState Idle (CGpgNetInterface::Connected). Main thread.
  void NATIVENET_Start();

  // A command from the launcher, before PullTask dispatches it. In native mode
  // IceServers and IceMsg are taken here (true); the server's JoinGame and
  // ConnectToPeer start a link and are rewritten to the shipped form with the
  // peer's engine address; DisconnectFromPeer and HostGame close links. False
  // leaves the command to PullTask. Main thread.
  bool NATIVENET_HandleCommand(const fa::string& name, fa::vector<SNetCommandArg>& args);

  // A command the game sends to the launcher (CGpgNetInterface::WriteCommand*):
  // GameEnded stops link restarts. Any thread.
  void NATIVENET_OnGameMessage(const char* name);
} // namespace moho
