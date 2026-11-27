#pragma once

// Engine addition (in-game launcher plan, .plans/ingame-launcher, WP4-WP5): the in-game launcher's online service in
// the game client. FAF's sign-in and lobby (faf_online) and a match the launcher starts inside the running game: its
// switches as runtime launch values (CFG_SetLaunchArgs), the GPGNet side (GameLink), the replay relay, and the way
// back to the launcher when the match ends. Nothing here runs, and nothing goes to the network, until the launcher's
// Lua calls one of its functions (FafOnline_*), so a game another launcher started behaves as it always did.

#include <expected>
#include <filesystem>
#include <string>

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

  // For the launcher's replays and mods (LauncherLibrary.cpp).

  /** Where the launcher keeps its files: %LOCALAPPDATA%, $XDG_DATA_HOME or ~/.local/share, then faf-re/online. */
  [[nodiscard]] std::filesystem::path ONLINE_DataFolder();
  /** FAF's API (https://api.faforever.com, or a test stack's). */
  [[nodiscard]] std::string ONLINE_ApiBase();
  /** The player's FAF access token, refreshed when near its end; for a worker thread. The error when not signed in. */
  [[nodiscard]] std::expected<std::string, std::string> ONLINE_AccessToken();
  /** The FAF init file the game runs on (its folder is FAF's bin folder); empty when it isn't on FAF's files. */
  [[nodiscard]] std::filesystem::path ONLINE_InitFile();

  /** Stops the library's downloads and searches (LauncherLibrary.cpp), before the service they sign in with goes. */
  void LIBRARY_Shutdown();
} // namespace moho
