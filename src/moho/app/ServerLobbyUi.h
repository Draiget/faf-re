#pragma once

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

// Engine addition, server mode (plan WP2.12, WP12.1; docs/SWITCHES.md, "Server mode"): the client's lobby in a
// server session. The server signals the lobby as FAF's lobby server does over GPGNet (remote/net/LobbySignals.h);
// this side turns each signal into the call `CGpgNetInterface` makes for the GPGNet command of the same name
// (`CreateLobby` + `HostGame` / `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer`), so FAF's lobby Lua runs unchanged
// and the logical host's `CLobby` hosts. Built only with FAF_SERVER_MODE, in the game client (not headless).
// A `Host` or `Join` while a lobby is up means a new logical host (plan WPR.50): the lobby closes and starts again.
//
// Plan WP12.2, the FAF client's launch path: a game the launcher started with `/gpgnet` joins a game server when the
// launcher sends `JoinServer address token uid` in place of `CreateLobby`, or when it was started with
// `/connectserver` too. Either way GPGNet stays the launcher's channel (states, results) and its lobby and link
// commands are ignored (docs/LAUNCHER_ADAPTER_CONTRACT.md, "Games on a game server").

namespace moho
{
  class CGpgNetInterface;
  struct SNetCommandArg;

  /**
   * With the channel to the server up: the front end GPGNet shows while it waits (`gpgnet.lua` `CreateUI`), and the
   * task that takes the server's lobby signals each frame. False when the UI can't start.
   */
  bool SERVERLOBBY_Start();

  /**
   * Engine addition (in-game launcher): the server session is over (no world session runs): the lobby task and its
   * lobby go, and the channel closes (`faf::remote::EndServerSession`), so the next game may be any. Called on the
   * main thread outside the task's run. Does nothing without a server session.
   */
  void SERVERLOBBY_End();

  /**
   * Engine addition (in-game launcher): `SERVERLOBBY_Start` for a game the launcher started: a channel lost before the
   * lobby is the launcher's to tell (no message box).
   */
  bool SERVERLOBBY_StartForLauncher();

  /**
   * Engine addition: `net_ServerGames` (1 by default). 0: a launcher's games on our servers are refused (the in-game
   * launcher's and GPGNet's `JoinServer`); `/connectserver` on the command line still joins, as the player asked.
   */
  [[nodiscard]] bool SERVERLOBBY_GamesOn();

  /**
   * Plan WP12.2: one launcher command, before `CGpgNetInterface` handles it. Takes `JoinServer` (starts the server
   * session and answers `ServerSession`), and in a server session every peer lobby or link command, which it ignores.
   * False for the rest, which go on as before.
   */
  bool SERVERLOBBY_HandleGpgNetCommand(
    CGpgNetInterface& gpgnet,
    const fa::string& name,
    const fa::vector<SNetCommandArg>& args
  );
} // namespace moho
