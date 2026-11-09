#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "editor/undo/EdHeightHistory.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CWldMap;
} // namespace moho

namespace faf::editor
{
  /** What an opened map holds, read once when it opens (the Map info panel, the log). */
  struct MapFacts
  {
    std::string scenarioPath;
    std::string mapPath;
    std::string savePath;
    std::string scriptPath;
    std::string name;
    std::string description;
    std::string type;
    int mapVersion = 0;
    /** `size` in `_scenario.lua`, in game units. */
    int sizeX = 0;
    int sizeZ = 0;
    /** The height field's size in samples (a 1024-cell map has 1025 each way). */
    int fieldWidth = 0;
    int fieldHeight = 0;
    bool water = false;
    float waterElevation = 0.0f;
    std::string terrainShader;
    /** The albedo texture of each layer: lower, strata 1 to 8, upper ("" when the slot is empty). */
    std::vector<std::string> layers;
    int props = 0;
    int decals = 0;
    /** The army names of the first configuration's first team (`Configurations.standard`). */
    std::vector<std::string> armies;
    /** `_save.lua`'s markers by type. */
    std::map<std::string, int> markers;
    int markerCount = 0;
    double loadSeconds = 0.0;
  };

  /**
   * One map opened for editing (board task WPE.4): its `.scmap` as the game loads it (`CWldMap::MapLoad`),
   * its `_scenario.lua` (`WLD_LoadScenarioInfo`) and its `_save.lua` (`Scenario`, run the same way), in a
   * Lua state of its own. Opening runs on a thread of its own, as the session loader's early map load does;
   * the main thread takes the result in `Poll`. Nothing here touches a running session.
   */
  class EdDocument
  {
  public:
    enum class State
    {
      Empty,
      Loading,
      Open,
      Failed,
    };

    EdDocument();
    ~EdDocument();
    EdDocument(const EdDocument&) = delete;
    EdDocument& operator=(const EdDocument&) = delete;

    /** Starts opening the map of `scenarioPath` (a VFS path to `*_scenario.lua`). False while one is opening. */
    bool Open(const std::string& scenarioPath);

    /** The main thread's turn, each frame: takes a finished open. Returns true on the frame it finished. */
    bool Poll();

    /** Waits for an open in progress to finish (the command-line checks). */
    void Wait();

    /** Drops the map. */
    void Close();

    /** Called just before the map is deleted (the viewport stops drawing it first). */
    void SetBeforeDrop(std::function<void()> beforeDrop) { mBeforeDrop = std::move(beforeDrop); }

    [[nodiscard]] State GetState() const noexcept { return mState; }
    [[nodiscard]] const MapFacts& Facts() const noexcept { return mFacts; }
    [[nodiscard]] const std::string& Error() const noexcept { return mError; }
    /** The opening or open map's scenario path, "" when none. */
    [[nodiscard]] const std::string& Path() const noexcept { return mPath; }
    /** The loaded map, null unless open. */
    [[nodiscard]] moho::CWldMap* Map() const noexcept { return mMap.get(); }
    /** The height field's undo history, reset when a map opens. */
    [[nodiscard]] HeightHistory& Heights() noexcept { return mHeights; }
    /** Whether the map changed since it was opened (or last saved). */
    [[nodiscard]] bool Modified() const noexcept { return mModified; }
    void SetModified(bool modified) noexcept { mModified = modified; }

    /** The document's Lua state (scripts and objects made for the open map), null unless open. */
    [[nodiscard]] LuaPlus::LuaState* Lua() const noexcept { return mLua.get(); }

  private:
    struct Load;
    static void Run(Load& load);
    static void RunSteps(Load& load);

    State mState = State::Empty;
    std::string mPath;
    MapFacts mFacts;
    std::string mError;
    std::unique_ptr<LuaPlus::LuaState> mLua;
    std::unique_ptr<moho::CWldMap> mMap;
    std::unique_ptr<Load> mLoad;
    std::thread mThread;
    std::function<void()> mBeforeDrop;
    HeightHistory mHeights;
    bool mModified = false;
  };
} // namespace faf::editor
