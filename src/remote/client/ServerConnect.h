#pragma once

#include <cstdint>
#include <string>

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
   * `startLobby` with the server's address (the client starts its join-lobby UI; this file stays out of the UI,
   * which headless lacks).
   */
  [[nodiscard]] EServerSessionStart StartServerSessionFromCommandLine(bool (*startLobby)(const char* endpoint));

  /**
   * Plan WP2.13, WP12.1: once a server session has its channel, the connector the lobby is made with
   * (`InternalCreateLobby`): every participant a virtual connection over that channel
   * (ServerRelayConnector.h). Null outside a server session, and after the first call: one lobby per session.
   */
  [[nodiscard]] moho::INetConnector* TakeServerLobbyConnector();
} // namespace faf::remote
