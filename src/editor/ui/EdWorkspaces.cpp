#include "editor/ui/EdWorkspaces.h"

#include "editor/ui/EdIconFont.h"

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace faf::editor
{
  namespace
  {
    int gActive = 0;

    [[nodiscard]] std::string_view Trim(
      std::string_view text
    )
    {
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
      }
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
      }
      return text;
    }
  } // namespace

  const std::vector<EdWorkspace>& Workspaces()
  {
    // The panels each one starts with are the ones there are now; the design's others (Layers, Outliner,
    // the node editors) join their workspaces as they are made.
    static const std::vector<EdWorkspace> kWorkspaces = {
      {"terrain",
       "Terrain",
       "Alt+1",
       "Heights, textures and water: the sculpt and paint tools",
       "Tools",
       "",
       "Layers,Info",
       "Properties",
       "Problems,Log,History,Markers,Check,Map",
       0.21f,
       0.22f,
       false},
      {"objects",
       "Objects",
       "Alt+2",
       "Props, decals, markers and units: placing and arranging them",
       "Tools",
       "Properties,Assets###AssetBrowser",
       "Markers,Armies,Info",
       "",
       "Problems,Log,History",
       0.21f,
       0.22f,
       false},
      {"environment",
       "Environment",
       "Alt+3",
       "Lighting, sky and water's look",
       "Lighting",
       "Tools",
       "Map,Info",
       "",
       "Problems,Log,History",
       0.24f,
       0.22f,
       false},
      {"layout",
       "Layout",
       "Alt+4",
       "The map's layout: its drawing in layers, the terrain made from it, start positions and resources",
       "Layout layers###LayoutLayers,Markers",
       "Starts and resources###LayoutStarts",
       "Layout canvas###LayoutCanvas",
       "Properties,Armies",
       "Check,Log,Map",
       0.24f,
       0.24f,
       false},
      {"generate",
       "Generate",
       "Alt+5",
       "Making terrain from rules: the terrain graph's nodes, its canvas and the selected node's settings",
       "Nodes###GenerateNodes",
       "",
       "Inspector###GenerateInspector",
       "",
       "Graph###GenerateGraph,Log",
       0.21f,
       0.22f,
       false},
      {"mission",
       "Mission",
       "Alt+6",
       "The map's mission (stages, dialogues), scripts, lobby options and armies",
       "Stages###MissionStages,Armies",
       "Strings###MissionStrings,Bases###MissionBases,Platoons###MissionPlatoons",
       "Script Editor###ScriptEditor,Adaptive Map###AdaptiveMap",
       "Properties",
       "Run###MissionRun,Problems,Check,Log,Debugger",
       0.20f,
       0.42f,
       false},
      {"effects",
       "Effects",
       "Alt+7",
       "Particle effects: the browser and the emitter editor",
       "Particle Browser",
       "",
       "Particle Editor",
       "",
       "Log",
       0.22f,
       0.48f,
       false},
      {"units",
       "Units",
       "Alt+8",
       "Units on the map and in mods: armies, groups, mod projects, the unit lab",
       "Unit lab###UnitLab,Tools",
       "Mod project###ModProject,Properties,Assets###AssetBrowser",
       "Unit viewer###UnitViewer,Armies,Info,Editor mods###EditorMods",
       "",
       "Log",
       0.21f,
       0.24f,
       false},
      {"materials",
       "Materials",
       "Alt+9",
       "Terrain materials and their graphs",
       "Info",
       "",
       "Material Editor",
       "",
       "Log",
       0.18f,
       0.50f,
       false},
      {"review",
       "Review",
       "Alt+0",
       "Looking the map over before release: nothing changes here",
       "",
       "",
       "Problems,Check,Info",
       "Map",
       "Log",
       0.0f,
       0.28f,
       true},
    };
    return kWorkspaces;
  }

  int WorkspaceByKey(
    std::string_view key
  )
  {
    const std::vector<EdWorkspace>& all = Workspaces();
    for (std::size_t i = 0; i < all.size(); ++i) {
      if (key == all[i].key) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  int ActiveWorkspace()
  {
    return gActive;
  }

  void SetActiveWorkspace(
    const int workspace
  )
  {
    if (workspace >= 0 && workspace < static_cast<int>(Workspaces().size())) {
      gActive = workspace;
    }
  }

  std::string PanelId(
    std::string_view panel
  )
  {
    const std::size_t hashes = panel.find("###");
    return std::string(hashes == std::string_view::npos ? panel : panel.substr(hashes + 3));
  }

  const char* PanelIcon(
    const std::string_view id
  )
  {
    // The mockup's icons for its panels (data_panels.ts), by our panels' ids.
    static constexpr std::pair<std::string_view, const char*> kIcons[] = {
      {"Tools", ICON_WAND},
      {"Properties", ICON_INFO},
      {"Map", ICON_VAULT},
      {"Info", ICON_INFO},
      {"Layers", ICON_LAYERS},
      {"Markers", ICON_MARKER},
      {"Check", ICON_CHECK},
      {"Log", ICON_CONSOLE},
      {"History", ICON_HISTORY},
      {"Problems", ICON_WARN},
      {"Lighting", ICON_LIGHT},
      {"Debugger", ICON_PLAY},
      {"Armies", ICON_FLAG},
      {"Material Editor", ICON_MATERIAL},
      {"Particle Browser", ICON_IMAGE},
      {"Particle Editor", ICON_PARTICLES},
      {"ScriptEditor", ICON_SCRIPT},
      {"AdaptiveMap", ICON_GENERATE},
      {"GenerateNodes", ICON_GENERATE},
      {"GenerateGraph", ICON_GRAPH},
      {"GenerateInspector", ICON_INFO},
      {"LayoutLayers", ICON_LAYERS},
      {"LayoutCanvas", ICON_LAYOUT},
      {"LayoutStarts", ICON_FLAG},
      {"MissionStages", ICON_MISSION},
      {"MissionStrings", ICON_SCRIPT},
      {"MissionRun", ICON_PLAY},
      {"MissionBases", ICON_FLAG},
      {"MissionPlatoons", ICON_UNIT},
      {"ModProject", ICON_MOD},
      {"UnitLab", ICON_UNIT},
      {"AssetBrowser", ICON_IMAGE},
      {"EditorMods", ICON_MOD},
      {"UnitViewer", ICON_UNIT},
    };
    for (const auto& [panel, icon] : kIcons) {
      if (panel == id) {
        return icon;
      }
    }
    return nullptr;
  }

  int LayoutVersionOf(
    const std::string_view key
  )
  {
    // Raised when a workspace's first layout changes, so a layout saved before is laid out again once.
    // 2: Terrain's right dock as the mockup's (Layers and Info, Properties under them).
    // 2: Generate's terrain graph panels (Nodes, Inspector, Graph).
    // 2: Layout's drawing panels (Layout layers, Layout canvas).
    // 3: Layout's Starts and resources under its layers.
    // 2: Mission's Stages and Strings.
    // 3: Mission's Run beside Problems.
    // 4: Mission's Bases beside Strings.
    // 5: Mission's Platoons beside Bases.
    // 2: Units' Mod project beside Properties.
    // 3: Units' Unit lab before Tools.
    // 4: Units' Assets beside Properties; 2: Objects' Assets beside Properties.
    if (key == "mission") {
      return 5;
    }
    if (key == "units") {
      return 6; // 5: Editor mods beside Armies and Info; 6: Unit viewer before them
    }
    if (key == "layout") {
      return 3;
    }
    return key == "terrain" || key == "generate" || key == "objects" ? 2 : 1;
  }

  std::map<std::string, int>& LayoutVersions()
  {
    static std::map<std::string, int> versions;
    return versions;
  }

  const char* WorkspaceIcon(
    const std::string_view key
  )
  {
    static constexpr std::pair<std::string_view, const char*> kIcons[] = {
      {"terrain", ICON_TERRAIN},
      {"objects", ICON_OBJECTS},
      {"environment", ICON_ENV},
      {"layout", ICON_LAYOUT},
      {"generate", ICON_GENERATE},
      {"mission", ICON_MISSION},
      {"effects", ICON_PARTICLES},
      {"units", ICON_MOD},
      {"materials", ICON_MATERIAL},
      {"review", ICON_REVIEW},
    };
    for (const auto& [workspace, icon] : kIcons) {
      if (workspace == key) {
        return icon;
      }
    }
    return nullptr;
  }

  std::string PanelWindowNameBeforeIcons(
    std::string_view panel,
    const int workspace
  )
  {
    if (workspace <= 0 || workspace >= static_cast<int>(Workspaces().size())) {
      return std::string(panel);
    }
    const std::string key = Workspaces()[static_cast<std::size_t>(workspace)].key;
    if (panel.find("###") != std::string_view::npos) {
      return std::string(panel) + "@" + key;
    }
    return std::string(panel) + "###" + std::string(panel) + "@" + key;
  }

  std::string PanelWindowName(
    std::string_view panel,
    const int workspace
  )
  {
    const char* const icon = PanelIcon(PanelId(panel));
    if (icon == nullptr) {
      return PanelWindowNameBeforeIcons(panel, workspace);
    }
    // The title with its icon in front; the id after ### stays what it was, so the window keeps its place.
    const std::size_t hashes = panel.find("###");
    const std::string_view title = hashes == std::string_view::npos ? panel : panel.substr(0, hashes);
    const std::string before = PanelWindowNameBeforeIcons(panel, workspace);
    const std::size_t idAt = before.find("###");
    const std::string id = idAt == std::string::npos ? "###" + before : before.substr(idAt);
    return std::string(icon) + "  " + std::string(title) + id;
  }

  const char* Panel(
    const char* const panel
  )
  {
    // Node-based, so the strings stay where they are as more are added.
    static std::unordered_map<std::string, std::string> names;
    std::string at = std::to_string(gActive) + "|" + panel;
    auto found = names.find(at);
    if (found == names.end()) {
      found = names.emplace(std::move(at), PanelWindowName(panel, gActive)).first;
    }
    return found->second.c_str();
  }

  std::string DockSpaceName(
    const int workspace
  )
  {
    if (workspace <= 0 || workspace >= static_cast<int>(Workspaces().size())) {
      return "EditorDockSpace";
    }
    return std::string("EditorDockSpace@") + Workspaces()[static_cast<std::size_t>(workspace)].key;
  }

  std::vector<std::string> SplitPanelList(
    std::string_view list
  )
  {
    std::vector<std::string> out;
    while (!list.empty()) {
      const std::size_t comma = list.find(',');
      const std::string_view part = Trim(list.substr(0, comma));
      if (!part.empty()) {
        out.emplace_back(part);
      }
      list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
    }
    return out;
  }

  std::string JoinPanelList(
    const std::vector<std::string>& panels
  )
  {
    std::string out;
    for (const std::string& panel : panels) {
      out += (out.empty() ? "" : ",") + panel;
    }
    return out;
  }

  std::vector<std::string> DefaultPanels(
    const int workspace
  )
  {
    std::vector<std::string> out;
    if (workspace < 0 || workspace >= static_cast<int>(Workspaces().size())) {
      return out;
    }
    const EdWorkspace& w = Workspaces()[static_cast<std::size_t>(workspace)];
    for (const char* const place : {w.left, w.leftBottom, w.right, w.rightBottom, w.bottom}) {
      for (const std::string& panel : SplitPanelList(place)) {
        const std::string id = PanelId(panel);
        if (std::find(out.begin(), out.end(), id) == out.end()) {
          out.push_back(id);
        }
      }
    }
    return out;
  }

  std::map<std::string, std::vector<std::string>>& ShownPanels()
  {
    static std::map<std::string, std::vector<std::string>> shown;
    return shown;
  }
} // namespace faf::editor
