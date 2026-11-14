#pragma once

#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdCommands;
  struct EdMenu;
  struct EdMenuItem;

  /** What the title row says besides its menus. */
  struct EdTitleInfo
  {
    std::string document;  // the open map's name, or what the editor is doing
    bool modified = false; // a dot after the name
    std::string state;     // "Playing", or empty
    /** Tabs after the menus (the workspaces): the command each runs and its label; `activeTab` is filled. */
    struct Tab
    {
      std::string command;
      std::string label;
      std::string icon;        // ui/EdIconFont.h, or empty
      std::string keys;        // "Alt+4", for the tooltip
      std::string about;       // what it is for, for the tooltip
      bool groupStart = false; // a thin rule before it
    };
    std::vector<Tab> tabs;
    int activeTab = -1;
  };

  /**
   * The editor's own title row (design §3, Title bar), as Discord's: the app mark, the map's name with a dot while
   * unsaved, the menus from the command registry, a search box that opens the command palette, and Windows 11's
   * minimise, maximise and close at the right end. Drawn at the top of the panels' window; fills WindowChrome() with
   * where its controls are, so the window's message handler can make the rest of the row drag the window. Returns the
   * row's height.
   */
  float DrawTitleBar(
    EdCommands& commands,
    const std::vector<EdMenu>& menus,
    const EdTitleInfo& info,
    const std::function<void()>& openPalette
  );

  /** One menu's entries as ImGui menu items (also used by right-click menus). */
  void DrawMenuItems(EdCommands& commands, const std::vector<EdMenuItem>& items);
} // namespace faf::editor
