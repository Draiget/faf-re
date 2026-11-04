#pragma once

// Issue #233: links inside the engine. The GPGNet messages between the game
// and faf-netbridge when the game runs the peer links itself, and the address
// the game reaches each peer at. docs/LAUNCHER_ADAPTER_CONTRACT.md §9.
// Engine addition, not recovered code.
//
//   game   -> bridge  NetlinkHello      [int version]
//   bridge -> game    NetlinkConfig     [string json]  local id, ICE servers, link options
//   bridge -> game    NetlinkPeer       [int remote id, string login, int offerer]
//   bridge -> game    NetlinkIceMsg     [int remote id, string json]  the client's iceMsg
//   bridge -> game    NetlinkClose      [int remote id]
//   bridge -> game    NetlinkGameEnded  []
//   game   -> bridge  NetlinkIceMsg     [int remote id, string json]  for the client's onIceMsg
//   game   -> bridge  NetlinkState      [int remote id, string state, int connected]
//
// A game that never sends NetlinkHello (the retail exe, or ours with
// net_InEngineLinks 0) gets none of these, and the bridge relays its
// datagrams as before.

#include <cstdint>
#include <string>

namespace faf::netlink
{
  inline constexpr int kEngineLinksVersion = 1;

  inline constexpr const char* kCmdHello = "NetlinkHello";
  inline constexpr const char* kCmdConfig = "NetlinkConfig";
  inline constexpr const char* kCmdPeer = "NetlinkPeer";
  inline constexpr const char* kCmdIceMsg = "NetlinkIceMsg";
  inline constexpr const char* kCmdClose = "NetlinkClose";
  inline constexpr const char* kCmdGameEnded = "NetlinkGameEnded";
  inline constexpr const char* kCmdState = "NetlinkState";

  // Issue #274, native mode: no adapter; the launcher talks to the game
  // directly (docs/LAUNCHER_NATIVE_NETWORK.md). The lobby server's own game
  // messages arrive as it sends them, plus one of the launcher's:
  //
  //   launcher -> game  IceServers      [string json]  the TURN/STUN list
  //   launcher -> game  JoinGame        [string login, int id]            (server's form)
  //   launcher -> game  ConnectToPeer   [string login, int id, int offer] (server's form)
  //   launcher -> game  IceMsg          [int sender id, string text]
  //   game -> launcher  IceMsg          [int receiver id, string text]    the server routes it
  inline constexpr const char* kCmdIceServers = "IceServers";
  inline constexpr const char* kCmdNativeIceMsg = "IceMsg";

  // Where the game reaches the player `remoteId` when its link runs in the
  // engine: 240.x.y.z (240.0.0.0/4 is reserved and never routed) with the
  // id's low 24 bits, the port from the bits above. Every player derives the
  // same address for the same player, so an address the host's lobby passes
  // on names the same peer everywhere.
  struct EngineAddress
  {
    std::uint32_t addrHost = 0; // host byte order
    std::uint16_t portHost = 0;
  };

  inline EngineAddress EngineAddressFor(const std::int64_t remoteId)
  {
    const auto id = static_cast<std::uint32_t>(remoteId);
    EngineAddress a;
    a.addrHost = 0xF0000000u | (id & 0x00FFFFFFu);
    a.portHost = static_cast<std::uint16_t>(1000u + (id >> 24));
    return a;
  }

  inline std::string EngineAddressText(const std::int64_t remoteId)
  {
    const EngineAddress a = EngineAddressFor(remoteId);
    return std::to_string(a.addrHost >> 24) + "." + std::to_string((a.addrHost >> 16) & 0xFF) + "." +
           std::to_string((a.addrHost >> 8) & 0xFF) + "." + std::to_string(a.addrHost & 0xFF) + ":" +
           std::to_string(a.portHost);
  }
} // namespace faf::netlink
