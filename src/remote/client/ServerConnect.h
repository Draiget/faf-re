#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "remote/net/LobbySignals.h"

namespace moho
{
  class INetConnector;
  class RRuleGameRules;
} // namespace moho

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
    Absent, // no `/connectserver`: a lockstep session
    Valid,
    Invalid, // the error text says why
  };

  /**
   * Reads `/connectserver` and `/servertoken` from the command line. `/servertoken` without
   * `/connectserver` counts as absent. `/connectserver` together with a lockstep startup flag
   * (`/hostgame`, `/joingame`, `/replay`, `/load`, `/scenario`, `/map`, `/perf`) is invalid. `/gpgnet` is allowed:
   * it is the launcher's channel (states, results), and its lobby commands are ignored (`IsPeerLinkCommand`).
   */
  [[nodiscard]] EServerConnectArgs ReadServerConnectArgs(SServerConnectRequest& request, std::string& error);

  /**
   * Plan WP12.2: one connection string's parts, as a launcher hands them over (the switches, or GPGNet's
   * `JoinServer address token uid`), checked as the switches are: an IPv4 `host:port`, a token of 1 to 1024 printable
   * characters without spaces, a uid above 0. False with `error` saying what is wrong; the token never appears in it.
   */
  [[nodiscard]] bool MakeServerConnectRequest(
    std::string_view endpoint,
    std::string_view token,
    std::int32_t uid,
    SServerConnectRequest& request,
    std::string& error
  );

  /**
   * Plan WP12.2: a launcher command that makes, joins or links a peer-to-peer lobby (`CreateLobby`, `HostGame`,
   * `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer`, `SendNatPacket`, `EjectPlayer`, the adapter's and the native
   * links' own). A game on a game server has no such lobby or links: it ignores them, so an unchanged ICE adapter
   * (which answers the game's `Idle` with `CreateLobby`) does no harm.
   */
  [[nodiscard]] bool IsPeerLinkCommand(std::string_view command);

  /** The GPGNet command a launcher sends in place of `CreateLobby` to put this game on a game server (plan WP12.2). */
  inline constexpr const char* kJoinServerCommand = "JoinServer";
  /** The game's answer to it: `ServerSession <"connected" | "failed" | "refused"> <why>`, never the token. */
  inline constexpr const char* kServerSessionCommand = "ServerSession";

  enum class EServerSessionStart
  {
    NotRequested, // no `/connectserver`: the caller continues with the lockstep paths
    Started,
    Failed, // the player has been told why; the caller exits
  };

  /**
   * Called first by the startup session selection (`InitializeSessionFromCommandLine`). Once
   * `/connectserver` is given, startup never falls back to a lockstep path. With the channel up it calls
   * `startLobbyUi`: the client shows its waiting front end and starts the task that takes the server's lobby signals
   * (this file stays out of the UI, which headless lacks).
   */
  [[nodiscard]] EServerSessionStart StartServerSessionFromCommandLine(bool (*startLobbyUi)());

  /**
   * Plan WP12.2: the same from a checked request (`MakeServerConnectRequest`), for a launcher's `JoinServer`: the
   * channel to the server (waiting up to 15 s for its answer), then `startLobbyUi`. On a failure the player is told
   * why and `error` says it for the launcher.
   */
  [[nodiscard]] EServerSessionStart
  StartServerSession(const SServerConnectRequest& request, bool (*startLobbyUi)(), std::string& error);

  /** A server session was started in this process (from the command line or a launcher's `JoinServer`). */
  [[nodiscard]] bool ServerSessionStarted();

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
   * `CommandAnswer`, `ViewCheck`; not a lobby frame), in arrival order. False when none is waiting or outside a
   * session.
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
   * (ServerRelayConnector.h). Null outside a server session, and while the last one handed out is alive: one lobby
   * at a time, which may be started again once the last is destroyed (a new logical host, plan WPR.50).
   */
  [[nodiscard]] moho::INetConnector* TakeServerLobbyConnector();

  /**
   * Plan WP2.6: the session's game has loaded its rules: what they hold goes to the server (remote/ContentCheck.h),
   * ahead of `Loaded`. `gameMods`: the launch's `GameMods` in its byte form (`LaunchInfoBase::mGameMods`).
   */
  void ReportServerContent(moho::RRuleGameRules& rules, const std::string& gameMods);
} // namespace faf::remote
