#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /**
   * A workspace (design §4): a set of panels in a dock layout of its own, for one kind of work. Each keeps its own
   * layout and which of its panels are shown; Alt+1 to Alt+0 and the title row's tabs switch between them.
   */
  struct EdWorkspace
  {
    const char* key;   // "terrain": its name in layout.ini and window ids
    const char* name;  // "Terrain"
    const char* keys;  // "Alt+1"
    const char* about; // what it's for, for its tab's tooltip
    // Its first layout: panels by where they dock (comma-separated names as the panels' windows have them); the
    // panels it shows at first are these.
    const char* left;
    const char* leftBottom;
    const char* right;
    const char* rightBottom;
    const char* bottom;
    float leftWidth;  // of the window, 0 to 1
    float rightWidth; // of what the left leaves
    bool readOnly;    // Review: only looking (tools other than Select are off)
  };

  /** The ten workspaces, in their keys' order (Alt+1 is the first, Alt+0 the last). */
  [[nodiscard]] const std::vector<EdWorkspace>& Workspaces();
  /** The workspace with this key, or -1. */
  [[nodiscard]] int WorkspaceByKey(std::string_view key);

  /** The workspace shown now (0 until one is picked or read from layout.ini). */
  [[nodiscard]] int ActiveWorkspace();
  void SetActiveWorkspace(int workspace);

  /**
   * A panel's id: what follows `###` in its window name, else the name ("Script Editor###ScriptEditor" gives
   * "ScriptEditor", "Tools" gives "Tools"). Lists of shown panels in layout.ini use it.
   */
  [[nodiscard]] std::string PanelId(std::string_view panel);
  /**
   * The window a panel is in a workspace: the first (Terrain) keeps the panel's own name, so layouts saved before
   * workspaces stay; the others add the workspace's key to its id ("Tools###Tools@objects"), so each has its own
   * window with its own place in its own layout, and the title stays the panel's.
   */
  [[nodiscard]] std::string PanelWindowName(std::string_view panel, int workspace);
  /**
   * The same before the panels' titles had icons (the first workspace's windows were named by the bare title, which
   * was their id): a saved layout's places are under these.
   */
  [[nodiscard]] std::string PanelWindowNameBeforeIcons(std::string_view panel, int workspace);
  /** A panel's icon (ui/EdIconFont.h) by its id, or nullptr. */
  [[nodiscard]] const char* PanelIcon(std::string_view id);
  /** A workspace's icon by its key, or nullptr. */
  [[nodiscard]] const char* WorkspaceIcon(std::string_view key);
  /** The same for the active workspace, kept until the program ends (ImGui takes the name as a C string). */
  [[nodiscard]] const char* Panel(const char* panel);
  /** The dock space a workspace lays its panels out in: "EditorDockSpace", "EditorDockSpace@objects", ... */
  [[nodiscard]] std::string DockSpaceName(int workspace);

  /** "Tools,Properties,Log" into its names, blanks around them dropped; and back. */
  [[nodiscard]] std::vector<std::string> SplitPanelList(std::string_view list);
  [[nodiscard]] std::string JoinPanelList(const std::vector<std::string>& panels);
  /** The panels a workspace shows at first: those its layout places, in its order, by id. */
  [[nodiscard]] std::vector<std::string> DefaultPanels(int workspace);

  /**
   * Which panels each workspace showed last, by workspace key and panel id: read from layout.ini
   * (`Panels.<key>=<ids>`) and written there; the shell keeps the active workspace's current.
   */
  [[nodiscard]] std::map<std::string, std::vector<std::string>>& ShownPanels();
} // namespace faf::editor
