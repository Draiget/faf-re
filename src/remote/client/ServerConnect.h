#pragma once

#include <cstdint>
#include <string>

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
   * `/connectserver` is given, startup never falls back to a lockstep path.
   */
  [[nodiscard]] EServerSessionStart StartServerSessionFromCommandLine();
} // namespace faf::remote
