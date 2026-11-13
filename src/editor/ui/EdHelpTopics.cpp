#include "editor/ui/EdHelpTopics.h"

#include <algorithm>
#include <cctype>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return out;
    }

    constexpr const char* kToolTopics[] = {
      "tool.select",
      "tool.terrain",
      "tool.texture",
      "tool.water",
      "tool.props",
      "tool.decals",
      "tool.markers",
      "tool.units",
    };
  } // namespace

  const std::vector<EdHelpTopic>& HelpTopics()
  {
    static const std::vector<EdHelpTopic> kTopics = {
      {"start",
       "Start screen",
       "The start screen opens when the editor starts without a map, and from File > Start screen. Its pages: Home, "
       "On this computer (every map the game lists here) and FAF vault.\n\n"
       "Home has one search over your maps and the vault (Enter opens the vault page with the words), New for each "
       "kind of project, your recent maps as cards, and, once signed in to FAF, your uploads and the most played "
       "maps. A map opening, a workspace tab or Continue put the screen away.",
       "file.home,file.open,file.new"},
      {"view",
       "The map view",
       "The middle of the window is the map. The camera: W A S D or the arrows move it (Shift for faster), the wheel "
       "zooms to the cursor, the middle button drags to turn it, Home frames the whole map.\n\n"
       "What a left click does is the tool's (the strip at the left of the Tools panel, keys 1 to 8); the right "
       "button does the opposite of a brush (Raise lowers). F5 plays the map; during a play F6 switches between the "
       "game's view and the editor's.",
       "view.frame,play.toggle,play.editorview,edit.undo,edit.redo"},
      {"tool.select",
       "Select tool",
       "Picks markers, units, props and decals in the view: a click selects what is under the cursor (its outline "
       "shows before you click), the Properties panel shows it. Delete removes the selection; Ctrl+C, Ctrl+V and "
       "Ctrl+D copy, paste at the cursor and make a copy beside it. Q and E turn selected props.",
       "tool.0,edit.delete,edit.copy,edit.paste,edit.duplicate"},
      {"tool.terrain",
       "Terrain tool",
       "Sculpts the heights with a brush: Raise, Lower, Smooth, Flatten, Set height, Noise, Terrace, Plane, Stamp, "
       "Erode and Water erode. Radius, strength and falloff shape the brush; the right button does the opposite.\n\n"
       "Symmetry writes every stroke to all the map's copies (half turn, mirrors, quarter turns, ...); the check "
       "compares each point with its copies and marks the differences. Limit keeps a stroke between heights or "
       "below a slope. The height field can be imported and exported as an image.",
       "tool.1,edit.undo,edit.redo"},
      {"tool.texture",
       "Texture tool",
       "Paints the terrain's texture layers: pick a layer, then paint its mask in the view (the right button "
       "erases). The layers' textures and their scale are set here too; symmetry applies as for heights.",
       "tool.2"},
      {"tool.water",
       "Water tool",
       "The sea (on or off, its level, the deep and abyss levels) and water bodies: lakes and pools at their own "
       "levels, outlined or seeded in the view. Its look (colours, refraction, Fresnel, sun on the water) and the "
       "waves are here too.",
       "tool.3"},
      {"tool.props",
       "Props tool",
       "Places props (trees, rocks, wrecks of scenery) from the game's prop blueprints: pick one in the list, then "
       "click or paint in the view. Their reclaim is added to the map's totals.",
       "tool.4"},
      {"tool.decals",
       "Decals tool",
       "Places decals (the ground's painted details) from the game's decal textures, singly or along a path (Enter "
       "places the path, Backspace drops its last point, Escape cancels). Delete removes the selected decals.",
       "tool.5"},
      {"tool.markers",
       "Markers tool",
       "Places and edits markers: start positions, mass and hydrocarbon resources, AI markers and path nodes. The "
       "Markers panel lists them; the Properties panel edits the selected one.",
       "tool.6"},
      {"tool.units",
       "Units tool",
       "Places units on the map for an army (or as wrecks) and edits their groups: the army, the group tree and "
       "what a unit is when a game starts. Copies go to the mirrored army with symmetry.",
       "tool.7"},
      {"Properties",
       "Properties",
       "What the Select tool (or the tool in use) has selected: a marker's values, a unit's army and group, a prop's "
       "blueprint, a decal's size and turn. Each change is one undo step.",
       "edit.undo"},
      {"Map",
       "Map panel",
       "The open map and playing it: open another map, the play setup (solo, against AI, custom; the start, the "
       "faction, mods, fog of war, victory) and the map's own settings (name, folder, size, players).",
       "file.open,play.toggle"},
      {"Info",
       "Info",
       "What the map is: its size, players, water, symmetry; its props, decals, markers and armies; the terrain's "
       "shader and layers; and its files.",
       ""},
      {"Markers",
       "Markers panel",
       "Every marker of the map by kind, with how many: start positions, resources, AI markers, path nodes. A click "
       "selects one and frames it in the view.",
       "tool.6"},
      {"Check",
       "Check",
       "Run the check: the scripts' syntax, then start positions and mass and hydrocarbon points (off the playable "
       "area, under water, without a partner at their symmetric copies, overlapping), then what each start reaches "
       "by land. Test run plays the map for a few seconds and lists its Lua errors. A click on a finding goes to it.",
       ""},
      {"Armies",
       "Armies",
       "The lobby's player slots and their teams, and the extra armies (civilians and others): each one's starting "
       "resources, faction and colour, its units (Go to start, Select its units), and the alliances.",
       ""},
      {"Lighting",
       "Lighting",
       "The map's sun (colour, direction, light multiplier), ambience, shadow fill, specular, bloom and fog, and its "
       "sky dome; import and export .scmlighting and .scmskybox files, or take them from another map. Each change "
       "shows in the view at once.",
       ""},
      {"ScriptEditor",
       "Script editor",
       "The map's script and the adaptive map's tables and options as text, coloured as Lua, with line numbers. "
       "Apply makes the text the map's (one undo step), Revert drops the edits, Check compiles it.",
       ""},
      {"AdaptiveMap",
       "Adaptive map",
       "An adaptive map's lobby options by what the player picks in the lobby: each option's choices and what they "
       "put on the map, and Preview a game, which shows only what a game with those choices starts with.",
       ""},
      {"Material Editor",
       "Material editor",
       "A texture layer's node graph: nodes make the layer's textures from noise, images and the terrain; Apply puts "
       "them on the map's layer. Graphs are kept in the map's folder.",
       "new.material"},
      {"Particle Editor",
       "Particle editor",
       "An effect's emitters as a graph: each Emitter node takes its curves from the nodes linked to its pins, its "
       "texture and colour ramp from Texture nodes. The effect plays in its own view (Pause, Restart, Loop, the "
       "ground and background). Place on the map puts it there.",
       "new.effect"},
      {"Particle Browser",
       "Particle browser",
       "The game's effects, searchable by faction and kind; a click plays one in the preview, Edit opens it in the "
       "particle editor.",
       ""},
      {"Log",
       "Log",
       "What the editor and the game say: info, warnings (amber) and errors. The filter finds lines; Times shows "
       "when each came. The status bar's warning count opens it.",
       "view.log"},
      {"Debugger",
       "Debugger",
       "Stops a play's map scripts at their breakpoints: tick Stop at breakpoints in plays, click a line's number in "
       "the Script Editor to set one, then play (F5 or Check's test run). Paused, the sim waits: the Script Editor "
       "shows the line, this panel the locals, your watched expressions and the stack; Continue, Step into, Step over "
       "or Step out go on. Stopping the play lets the sim go.",
       "view.debugger,play.toggle"},
      {"Problems",
       "Problems",
       "One list of the check's findings and the log's warnings (each different warning once, with how many times "
       "it came). Filter by errors, warnings and notes, or by Check and Log. A click goes to a finding (its script "
       "line, its marker, a prop's place) or shows the Log filtered to a warning. The status bar's count opens it.",
       "view.problems"},
      {"History",
       "History",
       "The map's edits, newest at the top: a click goes back (or forward) to that step, as many Undos or Redos as "
       "it takes.",
       "edit.undo,edit.redo,view.history"},
      {"Settings",
       "Settings",
       "General (help text, autosave, backups, the start screen), Appearance (theme, the panels' scale, the title "
       "row), Keys (every command's keys), Viewport (renderer, frame rate behind other windows) and Performance.",
       "settings.open,settings.keys"},
      {"palette",
       "Commands and the palette",
       "Everything the editor does is a command with a name and keys: the menus, the toolbar and the keys run "
       "them. Ctrl+K (or the search box in the title row) finds any command by a few of its letters.",
       "view.palette"},
      {"workspaces",
       "Workspaces",
       "Ten sets of panels, each with its own layout, for one kind of work: the title row's tabs or Alt+1 to Alt+0 "
       "switch them. Review only looks.",
       "workspace.0,workspace.1,workspace.9"},
    };
    return kTopics;
  }

  const EdHelpTopic* FindHelpTopic(
    std::string_view id
  )
  {
    for (const EdHelpTopic& topic : HelpTopics()) {
      if (id == topic.id) {
        return &topic;
      }
    }
    return nullptr;
  }

  std::string HelpTopicForWindow(
    std::string_view windowName,
    const int tool
  )
  {
    if (windowName.empty()) {
      return "view";
    }
    // The panel's id: after "###" when there is one, before a workspace's "@key"; a child window's root part.
    std::string_view id = windowName;
    if (const std::size_t hashes = id.find("###"); hashes != std::string_view::npos) {
      id = id.substr(hashes + 3);
    }
    if (const std::size_t at = id.find('@'); at != std::string_view::npos) {
      id = id.substr(0, at);
    }
    if (const std::size_t slash = id.find('/'); slash != std::string_view::npos) {
      id = id.substr(0, slash);
    }
    if (id == "Tools") {
      return tool >= 0 && tool < static_cast<int>(std::size(kToolTopics)) ? kToolTopics[tool] : "tool.terrain";
    }
    if (id == "Home") {
      return "start";
    }
    if (id == "##CommandPalette") {
      return "palette";
    }
    if (FindHelpTopic(id) != nullptr) {
      return std::string(id);
    }
    return "view";
  }

  std::vector<const EdHelpTopic*> SearchHelp(
    std::string_view query
  )
  {
    std::vector<std::string> words;
    std::string word;
    for (const char c : Lower(query)) {
      if (std::isspace(static_cast<unsigned char>(c)) != 0) {
        if (!word.empty()) {
          words.push_back(std::move(word));
          word.clear();
        }
      } else {
        word += c;
      }
    }
    if (!word.empty()) {
      words.push_back(std::move(word));
    }
    std::vector<const EdHelpTopic*> out;
    for (const EdHelpTopic& topic : HelpTopics()) {
      const std::string text = Lower(std::string(topic.title) + " " + topic.text);
      if (std::all_of(words.begin(), words.end(), [&text](const std::string& w) {
        return text.find(w) != std::string::npos;
      })) {
        out.push_back(&topic);
      }
    }
    return out;
  }

  const std::vector<EdTourStep>& TourSteps()
  {
    static const std::vector<EdTourStep> kSteps = {
      {"##TitleBar",
       "The title row",
       "The menus, the workspaces (Alt+1 to Alt+0) and the search box, which finds any command (Ctrl+K)."},
      {"##Toolbar",
       "The toolbar",
       "Play (F5), New, Open, Save, Undo and Redo, and the view's switches: grid, snap, "
       "keep on the ground, slope."},
      {"Tools",
       "Tools",
       "The tools at the left (1 to 8) and the settings of the one in use. F1 over any panel opens "
       "its help."},
      {"view", "The map", "W A S D move the camera, the wheel zooms, the middle button turns it, Home frames the map."},
      {"Info",
       "Panels",
       "What the map is (Info), its markers, the check, and more in View. Drag a tab to move a "
       "panel; each workspace keeps its own layout."},
      {"##StatusBar",
       "The status bar",
       "The mode, warnings (a click shows the log), the cursor, the selection, the last undo step and the last "
       "message, such as an autosave."},
    };
    return kSteps;
  }
} // namespace faf::editor
