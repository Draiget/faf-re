#pragma once

// Engine addition (in-game launcher plan, .plans/ingame-launcher, WP4-WP5): the in-game launcher's online service in
// the game client. FAF's sign-in and lobby (faf_online) and a match the launcher starts inside the running game: its
// switches as runtime launch values (CFG_SetLaunchArgs), the GPGNet side (GameLink), the replay relay, and the way
// back to the launcher when the match ends. Nothing here runs, and nothing goes to the network, until the launcher's
// Lua calls one of its functions (FafOnline_*), so a game another launcher started behaves as it always did.

namespace moho
{
  /** The service's step on the main thread, each frame: the lobby's messages, a match's start and end. */
  void ONLINE_Frame();

  /**
   * For ExitApplication. While a match the in-game launcher started runs, quitting ends that match and brings the
   * player back to the launcher instead: in launcher mode a finished game never quits. True when it did, and the
   * caller doesn't quit.
   */
  [[nodiscard]] bool ONLINE_ReturnToLauncherInsteadOfQuitting();

  /** Ends the service (its threads, the lobby connection), before GPGNet goes at the program's end. */
  void ONLINE_Shutdown();
} // namespace moho
