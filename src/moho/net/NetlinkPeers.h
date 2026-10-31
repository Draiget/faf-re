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
} // namespace moho
