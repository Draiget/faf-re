#pragma once

// Engine addition (issue #322), not in the binary: the network panel. It shows the
// game's own peer links (native mode #274, or in-engine links #233) and lets the
// player act on them: reconnect a peer, pick its path (relay only, no relay, one
// TURN server), read and copy the network log, copy diagnostics, open the log
// folder. The renderer draws it in the same pass as the debug overlays, so it
// shows in the lobby, in a game and in fullscreen; the viewport hands it the mouse
// clicks that land on it. Switch: net_ShowPanel (console), or Ctrl+Shift+F11. The
// ICE adapter's debug window used to show this; with no adapter the game does.

#include <string>

namespace moho
{
  class CD3DPrimBatcher;
  struct SNetlinkPeerInfo;

  extern bool net_ShowPanel;

  // "relayed (relay/host)", "direct (host/srflx)", or "-" while not connected: the
  // panel's path column, also used by the tray icon (#321).
  [[nodiscard]] std::string NETPANEL_PathText(const SNetlinkPeerInfo& peer);

  // Draws the panel when net_ShowPanel is on. The batcher's projection is the
  // head's screen space (REN_DebugStuff sets it). Render thread.
  void NETPANEL_Draw(CD3DPrimBatcher* batcher, float headWidth, float headHeight);

  // Plan WP10.10: a server-mode game's bytes from the server by lane, right-aligned to `right` from `top`, where
  // the lockstep driver draws its network stats (ren_ShowNetworkStats). Nothing before the game's first view.
  // Render thread.
  void NETPANEL_DrawServerLanes(CD3DPrimBatcher* batcher, float right, float top);

  // Flips net_ShowPanel (the key). Any thread.
  void NETPANEL_Toggle();

  // A mouse message for the game window (WD3DViewport::MSWWindowProc): `x`, `y`
  // in client pixels of a `clientWidth` x `clientHeight` client area, `wheel` the
  // WM_MOUSEWHEEL delta. True when the panel took it: a press on the panel, and
  // the release that ends that press. Moves are never taken. `window` is the
  // HWND, for the clipboard. Main thread.
  [[nodiscard]] bool NETPANEL_OnMouse(
    void* window, unsigned message, int x, int y, int clientWidth, int clientHeight, int wheel
  );
} // namespace moho
