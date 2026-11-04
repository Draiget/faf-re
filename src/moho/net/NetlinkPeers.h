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

namespace moho
{
  class CGpgNetInterface;
  struct SNetCommandArg;

  // After GameState Idle: announces in-engine links when net_InEngineLinks
  // is on. Main thread.
  void NETLINK_SayHello(CGpgNetInterface& gpgnet);

  // A Netlink* command from the bridge. False for any other command. Main
  // thread (CGpgNetInterface::PullTask).
  bool NETLINK_HandleCommand(const msvc8::string& name, const msvc8::vector<SNetCommandArg>& args);

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
  bool NATIVENET_HandleCommand(const msvc8::string& name, msvc8::vector<SNetCommandArg>& args);

  // A command the game sends to the launcher (CGpgNetInterface::WriteCommand*):
  // GameEnded stops link restarts. Any thread.
  void NATIVENET_OnGameMessage(const char* name);
} // namespace moho
