#pragma once

// Engine addition (issue #321), not in the binary: a tray icon for the game's own
// peer links (native mode #274, or in-engine links #233). FAF's ICE adapter had
// one; with no adapter the game shows it. The tooltip counts links up, relayed
// and lost; the menu lists the peers and can show the network panel (#322),
// reconnect a peer, open the log folder and copy diagnostics for a bug report.
// The icon runs on its own thread with its own window, so it works while the
// game window is minimised out of fullscreen. Switch: net_TrayIcon (default 1).
// Windows only; elsewhere these do nothing.

#include <string>

namespace moho
{
  extern bool net_TrayIcon;

  // Shared by the tray menu and the network panel (#322). `owner` is a window of
  // the calling thread (an HWND): the clipboard needs one. Windows only.
  // Opens the log folder, or puts the log file's path on the clipboard when the
  // shell refuses; returns what happened.
  [[nodiscard]] std::string NETDIAG_OpenLogFolder(void* owner);
  [[nodiscard]] std::string NETDIAG_LogFilePath(); // the game's /log file, empty without one
  [[nodiscard]] std::string NETDIAG_Text(); // the build, every link, the log file, the network log lines
  [[nodiscard]] bool NETDIAG_CopyText(void* owner, const std::string& text);

  // Shows the icon from now until NETTRAY_Stop or the end of the process.
  // Idempotent. Any thread.
  void NETTRAY_Start();

  // Removes the icon. Any thread but the icon's own.
  void NETTRAY_Stop();
} // namespace moho
