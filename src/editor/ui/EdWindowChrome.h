#pragma once

#include <vector>

namespace faf::editor
{
  /**
   * The editor draws its own title bar, as Discord and VS Code do (design §3, Title bar): the row at the top of the
   * window is the panels' (ImGui), and Windows draws no caption. The window's message handler asks TitleHit where a
   * point is; the title bar's drawing fills this each frame and reads back which caption button the mouse is on.
   * Coordinates are the frame's client area in pixels (the panels' window covers it from 0,0).
   */
  struct EdChromeRect
  {
    float x = 0.0f;
    float y = 0.0f;
    float w = 0.0f;
    float h = 0.0f;

    [[nodiscard]] bool Contains(
      const float px,
      const float py
    ) const noexcept
    {
      return px >= x && py >= y && px < x + w && py < y + h;
    }
  };

  /** What a point of the window is, for WM_NCHITTEST. */
  enum class EdHit
  {
    Client,  // the panels' (ImGui's)
    Caption, // drags the window, double-click maximises, right-click is the window menu
    Minimize,
    Maximize, // Windows 11 shows its snap layouts over it
    Close,
    Top, // resizes from the top edge (the caption row has no frame above it)
    TopLeft,
    TopRight,
  };

  struct EdWindowChrome
  {
    /** False: Windows draws its caption (`/nativecaption`, or Settings); the row then only carries the menus. */
    bool own = true;
    /** The title row's height in pixels (0 until the first frame). */
    float height = 0.0f;
    /** Where ImGui takes the mouse in the row: the menus, the search box, the workspace tabs. */
    std::vector<EdChromeRect> controls;
    EdChromeRect minimize;
    EdChromeRect maximize;
    EdChromeRect close;
    /** The caption button the mouse is on (Windows sends the mouse there as non-client moves) and the one held. */
    EdHit hot = EdHit::Client;
    EdHit pressed = EdHit::Client;
    bool maximised = false;
    bool active = true;
    /** Alt or F10 asked to open a menu: its index, or -1. */
    int openMenu = -1;
  };

  /** The window's chrome (one window per editor). */
  EdWindowChrome& WindowChrome();

  /**
   * What the point (client pixels) is. `border` is the resize band's height along the top edge; a maximised window
   * has none. Only the title row is caption: below it, and over its controls, the point is the panels'.
   */
  [[nodiscard]] EdHit TitleHit(const EdWindowChrome& chrome, float x, float y, float clientWidth, float border);
} // namespace faf::editor
