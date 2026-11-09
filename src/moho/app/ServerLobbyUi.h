#pragma once

// Engine addition, server mode (plan WP2.12, WP12.1; docs/SWITCHES.md, "Server mode"): the client's lobby in a
// server session. The server signals the lobby as FAF's lobby server does over GPGNet (remote/net/LobbySignals.h);
// this side turns each signal into the call `CGpgNetInterface` makes for the GPGNet command of the same name
// (`CreateLobby` + `HostGame` / `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer`), so FAF's lobby Lua runs unchanged
// and the logical host's `CLobby` hosts. Built only with FAF_SERVER_MODE, in the game client (not headless).
// A `Host` or `Join` while a lobby is up means a new logical host (plan WPR.50): the lobby closes and starts again.

namespace moho
{
  /**
   * With the channel to the server up: the front end GPGNet shows while it waits (`gpgnet.lua` `CreateUI`), and the
   * task that takes the server's lobby signals each frame. False when the UI can't start.
   */
  bool SERVERLOBBY_Start();
} // namespace moho
