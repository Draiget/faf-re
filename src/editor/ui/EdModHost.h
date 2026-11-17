#pragma once

#include "editor/doc/EdEditorMods.h"

#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace LuaPlus
{
  class LuaState;
}

namespace faf::editor
{
  class EdCommands;
  class EdDocument;

  /**
   * Runs the turned-on editor mods: each one's `editor/commands.lua` in a Lua state of its own (Lua's base library
   * without its file loading, and the `Editor` table), whose `Editor.Command(id, title, fn [, keys])` adds a command to
   * the editor (palette, keys; id `mod.<mod>.<id>`). The `Editor` table also has `Log(text)`, `Run(commandId)` (one of
   * the editor's commands; false when it can't run), `Map()` (the open map: path, name, size, water, counts; or nil),
   * `HeightAt(x, z)`, `Markers()`, `AddMarker(type, x, z)` (one undo step), `Panel(id, title, draw)` (a panel drawn
   * each frame by `draw(ui)`, `ui` holding Text, Note, Button, Checkbox, Slider, Input, Separator, SameLine, Tooltip),
   * `Menu(commandId [, label])` (an entry under Window > From editor mods), `Tool(id, title, click)` (a tool its
   * command turns on: a left click on the view calls `click(x, z, shift, ctrl)`), `SetHeights(x0, z0, w, h, list)`
   * (one undo step), `LayerAt(layer, x, z)`, `MissionNode(id, title, params, code)` (a node type for the mission
   * graph), `On(event, fn)` (fn(arg) on "map", "save" or "edit"), `Has(point [, version])`, `Capabilities` and
   * `ApiVersion` (FAF Studio's extension points, on this editor). The map's paint, props, decals and units:
   * `SetLayer(layer, x0, z0, w, h, list)`, `PaintSize()`, `Props()`, `AddProp(bp, x, z [, scale])`,
   * `RemoveProp(index)`, `Decals()`, `AddDecal(texture, x, z, size [, heading])`, `Units()`, `AddUnit(type, army, x,
   * z)` (each change one undo step); a store kept with the map, `MapData(key)` / `SetMapData(key, value)`. A command
   * that raises an error is reported with its mod's name and turns that mod off until the editor starts again; a panel
   * that raises stops drawing and says why.
   */
  class EdModHost
  {
  public:
    struct Mod;

    EdModHost(EdDocument& document);
    ~EdModHost();

    void Attach(
      EdCommands* commands
    ) noexcept
    {
      mCommands = commands;
    }
    /** Where the turned-on mods are kept (empty: not kept, as in test runs); read when set. */
    void SetEnabledFile(const std::filesystem::path& file);
    /**
     * Looks for editor mods in a mods folder and runs the turned-on ones. With an enabled file, under a start-up trial
     * (Studio's): the mods about to run are noted, EndTrial takes the note away once the editor is up; a note left from
     * the last start turns its mods off (TrialOff). A mod seen for the first time starts turned on.
     */
    void Scan(const std::filesystem::path& mods);
    void EndTrial();
    /** A mod's Editor.On listener; Notify calls the running mods' listeners of an event ("map", "save", "edit"). */
    void AddListener(Mod& mod, const std::string& event, int ref);
    void Notify(const std::string& event, const std::string& arg);
    /** The turned-on mods with sim hooks (`ui_only = false` and a hook folder): plays add them as sim mods. */
    [[nodiscard]] std::vector<std::string> SimHookMods() const;
    /** The mods the start-up trial turned off (the editor didn't come up with them last time). */
    [[nodiscard]] const std::set<std::string>& TrialOff() const noexcept
    {
      return mTrialOff;
    }
    /** Turns a mod on (runs it) or off (its commands say so); kept in the enabled file. */
    bool SetEnabled(const std::string& uid, bool on);
    void Draw(bool& open);

    struct Mod
    {
      EditorModInfo info;
      std::unique_ptr<LuaPlus::LuaState> lua;
      std::vector<std::string> commands; // the ids it added
      std::vector<int> refs;             // their functions in its registry
      std::string error;                 // why it isn't running ("" while it is)
      bool running = false;
      int uiRef = -1; // the `ui` table its panels draw with, in its registry
    };
    /** A mod's panel: its draw function, shown or not (its command toggles it), why it stopped. */
    struct ModPanel
    {
      Mod* mod = nullptr;
      std::string id;
      std::string title;
      int ref = -1;
      bool shown = false;
      std::string error;
    };
    /** A mod's tool: its click function; on while its command has it on. */
    struct ModTool
    {
      Mod* mod = nullptr;
      std::string id;
      std::string title;
      int ref = -1;
    };
    /** A mod's menu entry: a command id and its label ("" for the command's title). */
    struct ModMenu
    {
      Mod* mod = nullptr;
      std::string command;
      std::string label;
    };
    [[nodiscard]] const std::vector<std::unique_ptr<Mod>>& Mods() const noexcept
    {
      return mMods;
    }

    // The Lua side (static functions find their mod through an upvalue).
    void AddCommand(Mod& mod, const std::string& id, const std::string& title, const std::string& keys, int ref);
    void AddPanel(Mod& mod, const std::string& id, const std::string& title, int ref);
    void AddMenu(Mod& mod, const std::string& command, const std::string& label);
    void AddTool(Mod& mod, const std::string& id, const std::string& title, int ref);
    /** A left click on the view at a ground point: the active mod tool's, true when one took it. */
    bool ClickTool(float x, float z, bool shift, bool ctrl);
    /** The mod tool that is on (null: none). */
    [[nodiscard]] const ModTool* ActiveTool() const;
    void StopTool()
    {
      mActiveTool.clear();
    }
    /** What the mods' map writes and reads go through (the view's; set by the app). */
    std::function<std::expected<void, std::string>(int x0, int z0, int w, int h, const std::vector<float>& heights)>
      writeHeights;
    std::function<float(int layer, float x, float z)> layerAt;
    std::function<
      std::expected<void, std::string>(int layer, int x0, int z0, int w, int h, const std::vector<float>& weights)>
      writeLayer;
    std::function<bool(int& width, int& height)> paintSize;
    /** A prop, decal or unit as the mods see it. */
    struct MapObject
    {
      std::string what; // blueprint path / texture / unit blueprint id
      std::string name; // a unit's name
      std::string army; // a unit's army
      float x = 0.0f, y = 0.0f, z = 0.0f;
      float size = 0.0f; // a decal's size
    };
    /** "props", "decals" or "units". */
    std::function<std::vector<MapObject>(const std::string& kind)> listObjects;
    /** Each returns an error text, empty when done (one undo step). */
    std::function<std::string(const std::string& blueprint, float x, float z, float scale)> addProp;
    std::function<std::string(int index)> removeProp;
    std::function<std::string(const std::string& texture, float x, float z, float size, float heading)> addDecal;
    std::function<std::string(const std::string& type, const std::string& army, float x, float z, std::string& name)>
      addUnit;
    /**
     * A mod's own data kept with the open map (FAF Studio's sidecar): `<map>_moddata.editor` beside the map's file, a
     * `uid<TAB>key<TAB>value` line each; written at once (not part of the map's undo). Empty: none.
     */
    [[nodiscard]] std::string MapData(const std::string& uid, const std::string& key) const;
    [[nodiscard]] std::expected<void, std::string>
    SetMapData(const std::string& uid, const std::string& key, const std::string& value, bool remove);
    /** Each frame: the shown panels of the running mods. */
    void DrawPanels();
    /** The menu entries the running mods asked for, and their panels' show commands. */
    [[nodiscard]] std::vector<ModMenu> MenuEntries() const;
    [[nodiscard]] const std::vector<ModPanel>& Panels() const noexcept
    {
      return mPanels;
    }
    bool RunCommand(const std::string& id);
    void Fail(Mod& mod, const std::string& what);
    [[nodiscard]] EdDocument& Document() noexcept
    {
      return mDocument;
    }
    /** The mod whose commands.lua is running now (panels and menu entries are added only then). */
    [[nodiscard]] const Mod* Loading() const noexcept
    {
      return mLoading;
    }

  private:
    void Start(Mod& mod);
    void Stop(Mod& mod, const std::string& why);
    void SaveEnabled();
    void DropRetired();

    EdDocument& mDocument;
    EdCommands* mCommands = nullptr;
    std::vector<std::unique_ptr<Mod>> mMods;
    std::vector<ModPanel> mPanels;
    std::vector<ModMenu> mMenus;
    std::vector<ModTool> mTools;
    std::string mActiveTool; // "<uid>/<id>" of the tool that is on
    std::set<std::string> mEnabled;
    std::filesystem::path mEnabledFile;
    struct Listener
    {
      Mod* mod = nullptr;
      std::string event;
      int ref = 0;
    };
    std::vector<Listener> mListeners;
    std::filesystem::path mTrialFile;
    bool mTrialOpen = false;
    std::set<std::string> mTrialOff;
    bool mNewModsOn = true;
    std::filesystem::path mFolder;
    int mRunDepth = 0;
    /** Lua states of mods that stopped while their own code was running, freed once it has returned. */
    std::vector<std::unique_ptr<LuaPlus::LuaState>> mRetired;
    Mod* mLoading = nullptr;
  };
} // namespace faf::editor
