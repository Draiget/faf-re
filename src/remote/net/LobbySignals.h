#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

// Engine addition, server mode (plan WP2.12, WP2.13; design research/WP2.13-lobby-relay-design.md): what the server
// tells a participant's game about the lobby, as FAF's lobby server tells it over GPGNet today (`HostGame`, `JoinGame`,
// `ConnectToPeer`, `DisconnectFromPeer`, moho/net/CGpgNetInterface.cpp). They travel as `ESeatMessage::Lobby` frames
// from uid 0, the server. One participant, the logical host, gets `Host`: its unchanged FAF lobby runs the host's
// logic and its `CLobby` is the lobby's network host. Every other gets `Join` with the logical host's uid, and
// `ConnectToPeer` for each other participant; every connection is a virtual one over the channel to the server.
//
// Wire form: kind byte, flags byte, varint uid, then two strings (varint length, bytes): `name`, `text`.

namespace faf::remote::net
{
  enum class ELobbySignal : std::uint8_t
  {
    /** Make the lobby as its host: `name` is this player's, `text` the map's scenario file (may be empty). */
    Host = 1,
    /** Make the lobby and join the host: `name` is this player's, `uid` the host's, `text` the host's name. */
    Join = 2,
    /** Connect to another participant: `uid` and `name` are theirs. */
    ConnectToPeer = 3,
    /** A participant left: `uid` is theirs. */
    DisconnectFromPeer = 4,
    /** To the host (plan WP2.14): the server won't launch what it asked for; `text` says why. */
    LaunchRefused = 5,
    /** To everyone in the lobby (plan WP2.14): the server is starting the match. */
    Launching = 6,
  };

  /**
   * Player to server (plan WP2.14): a `Lobby` frame to uid 0 whose message is this byte, then the game configuration
   * `CLobby::LaunchGame` was given, in the lobby's own Lua byte form (`LuaObject::ToByteStream`).
   */
  constexpr std::uint8_t kLobbyLaunchRequest = 16;

  enum ELobbySignalFlags : std::uint8_t
  {
    kLobbySignalAutoLobby = 1u, // `Host`, `Join`: FAF's automatch lobby (autolobby.lua) instead of the custom game lobby
  };

  struct SLobbySignal
  {
    ELobbySignal kind = ELobbySignal::Host;
    std::uint8_t flags = 0;
    std::int32_t uid = 0;
    std::string name;
    std::string text;
  };

  constexpr std::size_t kLobbySignalMaxName = 256;
  constexpr std::size_t kLobbySignalMaxText = 1024;

  /** The message (after the frame's kind and uid). */
  [[nodiscard]] std::vector<std::uint8_t> EncodeLobbySignal(const SLobbySignal& signal);
  /** False for an unknown kind, a negative uid, a string over its limit, or bytes left over. */
  [[nodiscard]] bool DecodeLobbySignal(std::span<const std::uint8_t> message, SLobbySignal& out);

  /** The message of a launch request: `kLobbyLaunchRequest`, then the configuration's bytes. */
  [[nodiscard]] std::vector<std::uint8_t> EncodeLaunchRequest(std::span<const std::uint8_t> configuration);
  /** True for a launch request; `configuration` is then its bytes. */
  [[nodiscard]] bool IsLaunchRequest(std::span<const std::uint8_t> message, std::span<const std::uint8_t>& configuration);
} // namespace faf::remote::net
