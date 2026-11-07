#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "remote/net/LobbySignals.h"

namespace moho
{
  class INetConnector;
}

// Engine addition, server mode (docs/SWITCHES.md, "Server mode"): the client's entry into a
// server-authoritative session. Built only with FAF_SERVER_MODE; without `/connectserver` on
// the command line, the client takes every lockstep startup path exactly as before.

namespace faf::remote
{
  /** What `/connectserver <host:port> /servertoken <token>` asks for. */
  struct SServerConnectRequest
  {
    std::string endpoint;    // as given on the command line, for messages
    std::uint32_t address{}; // IPv4, as NET_GetAddrInfo returns it
    std::uint16_t port{};
    std::string token;
    std::int32_t uid{}; // `/serveruid`: the player the token was made for (the handshake names both)
  };

  enum class EServerConnectArgs
  {
    Absent,  // no `/connectserver`: a lockstep session
    Valid,
    Invalid, // the error text says why
  };

  /**
   * Reads `/connectserver` and `/servertoken` from the command line. `/servertoken` without
   * `/connectserver` counts as absent. `/connectserver` together with a lockstep startup flag
   * (`/hostgame`, `/joingame`, `/gpgnet`, `/replay`, `/load`, `/scenario`, `/map`, `/perf`) is
   * invalid.
   */
  [[nodiscard]] EServerConnectArgs ReadServerConnectArgs(SServerConnectRequest& request, std::string& error);

  enum class EServerSessionStart
  {
    NotRequested, // no `/connectserver`: the caller continues with the lockstep paths
    Started,
    Failed,       // the player has been told why; the caller exits
  };

  /**
   * Called first by the startup session selection (`InitializeSessionFromCommandLine`). Once
   * `/connectserver` is given, startup never falls back to a lockstep path. With the channel up it calls
   * `startLobbyUi`: the client shows its waiting front end and starts the task that takes the server's lobby signals
   * (this file stays out of the UI, which headless lacks).
   */
  [[nodiscard]] EServerSessionStart StartServerSessionFromCommandLine(bool (*startLobbyUi)());

  /**
   * Plan WP2.12: the server's next lobby signal (remote/net/LobbySignals.h), if it is next in line: the lobby's own
   * frames after it wait until it has been taken. False outside a server session.
   */
  [[nodiscard]] bool TakeServerLobbySignal(net::SLobbySignal& signal);
  /** The lobby's connection to `uid` ends (`ConnLostEof`): the server said that participant left. */
  void EndServerLobbyPeer(std::int32_t uid);
  /**
   * Plan WP2.14: the lobby's host asks the server to launch this configuration (its Lua bytes, as
   * `LuaObject::ToByteStream` writes them). False outside a server session.
   */
  bool SendServerLaunchRequest(std::span<const std::uint8_t> configuration);
  /**
   * Plan WP11: the next message from the server for the game's session (`LaunchInfo`, `GameInfo`, `View`, `Beat`,
   * `CommandAnswer`, `ViewCheck`; not a lobby frame), in arrival order. False when none is waiting or outside a session.
   */
  [[nodiscard]] bool TakeServerGameMessage(std::vector<std::uint8_t>& message);
  /**
   * The link to the server moves without taking anything from it (keepalives, acknowledgements): every frame while
   * the map loads, when neither the lobby nor the session's driver reads the channel. Its 10 s timeout would end it.
   */
  void KeepServerSessionAlive();
  /** Plan WP11: one message from the game's session to the server (a `Command`, `Loaded`, `Leaving`...), reliably. */
  bool SendServerGameMessage(std::span<const std::uint8_t> message);
  /** This player's uid in the server session, or 0 outside one. */
  [[nodiscard]] std::int32_t ServerSessionUid();
  /** The channel to the server is connected or reconnecting. */
  [[nodiscard]] bool ServerSessionUp();

  /**
   * Plan WP2.13, WP12.1: once a server session has its channel, the connector the lobby is made with
   * (`InternalCreateLobby`): every participant a virtual connection over that channel
   * (ServerRelayConnector.h). Null outside a server session, and after the first call: one lobby per session.
   */
  [[nodiscard]] moho::INetConnector* TakeServerLobbyConnector();
} // namespace faf::remote
