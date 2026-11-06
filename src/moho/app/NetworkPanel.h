#pragma once

// Engine addition (issue #322), not in the binary: the network panel. It shows the
// game's own peer links (native mode #274, or in-engine links #233) and the latest
// network log lines, drawn by the renderer in the same pass as the debug overlays,
// so it shows in the lobby, in a game and in fullscreen. Switch: net_ShowPanel
// (console), or Ctrl+Shift+F11. The ICE adapter's debug window used to show this;
// with no adapter the game does.

namespace moho
{
  class CD3DPrimBatcher;

  extern bool net_ShowPanel;

  // Draws the panel when net_ShowPanel is on. The batcher's projection is the
  // head's screen space (REN_DebugStuff sets it). Render thread.
  void NETPANEL_Draw(CD3DPrimBatcher* batcher, float headWidth, float headHeight);

  // Flips net_ShowPanel (the key). Any thread.
  void NETPANEL_Toggle();
} // namespace moho
