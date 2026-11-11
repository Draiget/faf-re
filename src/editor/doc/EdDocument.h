#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "editor/doc/EdPackage.h"
#include "editor/doc/EdLighting.h"
#include "editor/doc/EdSkybox.h"
#include "editor/tools/EdWaves.h"
#include "editor/doc/EdWater.h"
#include "editor/doc/EdWaterBodies.h"
#include "editor/tools/EdChecks.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdSymmetryCheck.h"
#include "editor/doc/EdMapFile.h"
#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/undo/EdHeightHistory.h"
#include "moho/sim/CWldMap.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CWldMap;
  class IWldTerrainRes;
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
    /** An adaptive map's `_tables.lua` (the script's import), or empty. */
    std::string tablesPath;
    /** The map's `_options.lua` (its lobby options), beside the scenario; empty until it has one. */
    std::string optionsPath;
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
    /** The symmetry the heights were made with (DetectSymmetry), found while the map loads. */
    DetectedSymmetry symmetry;
    bool water = false;
    float waterElevation = 0.0f;
    float waterDeep = 0.0f;
    float waterAbyss = 0.0f;
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

    /**
     * Starts making a new map folder `<vault>/maps/<settings.folder>` on the worker thread: the engine's empty
     * map of that size (CWldMap::MapNew, 0x00890D40) at the settings' height and sea, a preview, and the
     * scenario, save and script files with the start positions. Poll finishes it; the app then mounts the
     * folder and opens it (TakeCreated). False, with `message`, when it can't start.
     */
    bool CreateNew(const NewMapSettings& settings, std::string& message);

    /** After Poll finished a CreateNew: the folder it wrote and its scenario's game path (once). */
    bool TakeCreated(std::filesystem::path& folder, std::string& scenarioPath);

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
    /**
     * Saves the map's `.scmap` over its own file, when it has one on disk (a map in the game's archives has
     * none; it is saved as a new folder instead). Before the first overwrite of a session the old file is
     * copied to `<map folder>/.editor_backup/<time>/`. The scenario, save and script files are left as they
     * are: nothing edits them yet. `message` says what happened, for the log and the status bar.
     */
    bool Save(std::string& message);

    /**
     * The FAF vault (its `maps` folder holds the mapper's maps). Save writes over a map only there: the
     * game's own maps (its install folder) are saved as a new map folder instead.
     */
    void SetVaultFolder(std::filesystem::path folder) { mVault = std::move(folder); }
    [[nodiscard]] const std::filesystem::path& VaultFolder() const noexcept { return mVault; }

    /**
     * Saves the map as a new map folder `<vault>/maps/<folder>` (FAF names them `name.vNNNN`): every file
     * of the map's folder copied, renamed to the new base name (the folder name without its version) where
     * they started with the old one, `/maps/<old folder>/...` paths rewritten in its Lua files (scenario,
     * save, script), and the edited `.scmap` written there. Later saves go to the new folder. The game sees
     * the new folder from its next start (its file system is mounted at startup).
     */
    bool SaveAsNewFolder(const std::string& folder, std::string& message);

    /** The map's folder name (`scmp_009`, `seton.v0003`) and the suggestion for a new version of it. */
    [[nodiscard]] std::string FolderName() const;
    [[nodiscard]] std::string NextVersionFolder() const;

    /** The `.scmap` on disk that Save writes over, or empty when there is none. */
    [[nodiscard]] std::filesystem::path MapDiskFile() const;
    /** The vault package of the map's folder as saved on disk (no folder: an error in the plan). */
    [[nodiscard]] PackagePlan PlanPackage() const;
    /** Writes the plan's files as `<vault>/packages/<folder>.zip`, the folder at the zip's top; false with `message`. */
    bool WritePackage(const PackagePlan& plan, std::filesystem::path& written, std::string& message) const;

    /** What the map file stored that a save writes back as it was (the preview, unchanged props). */
    [[nodiscard]] const MapFileRecords& FileRecords() const noexcept { return mFileRecords; }
    /** Marks which of the file's images a save keeps: those whose sources are as they were at load. */
    void MarkKeptImages();
    /** The masks were read from the terrain (once): what they were then, to tell an edit from none. */
    void MasksRead();

    /** The height field's undo history, reset when a map opens. */
    [[nodiscard]] HeightHistory& Heights() noexcept { return mHeights; }

    /** The stratum masks as the editor paints them (read from the map's textures when the view first shows it). */
    struct MaskGrid
    {
      int width = 0;
      int height = 0;
      std::vector<std::uint64_t> texels;
    };
    [[nodiscard]] MaskGrid& Masks() noexcept { return mMasks; }
    [[nodiscard]] MaskHistory& MaskUndo() noexcept { return mMaskHistory; }

    /** One undo order over every kind of edit: Ctrl+Z takes back the newest edit, whatever it changed. */
    enum class EditKind
    {
      Heights,
      Masks,
      Layers,
      Props,
      SaveData,
      Decals,
      Water,
      Lighting,
      Skybox,
      Waves,
      TerrainTypes,
    };
    /** The map's terrain type grid (a byte a cell, STIMap::mTerrainType, saved with the terrain): its cells, or null. */
    [[nodiscard]] std::uint8_t* TerrainTypeCells(int& width, int& height) const;
    [[nodiscard]] std::vector<std::uint8_t> TerrainTypesNow() const;
    void ApplyTerrainTypes(const std::vector<std::uint8_t>& cells);
    void TerrainTypesEdited(std::vector<std::uint8_t> before);
    /** Counts each change to the grid, for the overlay. */
    [[nodiscard]] int TerrainTypeRevision() const noexcept { return mTerrainTypeRevision; }
    void TerrainTypesChanged() noexcept { ++mTerrainTypeRevision; }
    [[nodiscard]] std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>& TerrainTypesUndo() noexcept { return mTerrainTypesUndo; }
    [[nodiscard]] std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>& TerrainTypesRedo() noexcept { return mTerrainTypesRedo; }
    /** The map's wave generators (through the wave system's own Save, WaveSystem::Save 0x00889AD0). */
    [[nodiscard]] std::vector<WaveRecord> WavesNow() const;
    /** The map's prop reclaim, by blueprint (RPropBlueprint::Economy's ReclaimMassMax and ReclaimEnergyMax). */
    struct ReclaimRow
    {
      std::string blueprint;
      int count = 0;
      float mass = 0.0f;
      float energy = 0.0f;
    };
    struct ReclaimTotals
    {
      int props = 0;
      double mass = 0.0;
      double energy = 0.0;
      /** Props whose blueprint gives none, and props whose blueprint the rules haven't got. */
      int none = 0;
      int unknown = 0;
      /** Each blueprint's props, the most mass first. */
      std::vector<ReclaimRow> rows;
    };
    /** Needs the game's rules; empty until they are built. */
    [[nodiscard]] ReclaimTotals PropReclaim() const;
    /** How many wave generators the map has. */
    [[nodiscard]] int WaveCount() const;
    /** Puts these generators on the map in place of its own (WaveSystem::Load 0x008899E0); no undo step. */
    void ApplyWaves(const std::vector<WaveRecord>& waves);
    void WavesEdited(std::vector<WaveRecord> before);
    [[nodiscard]] std::vector<std::pair<std::vector<WaveRecord>, std::vector<WaveRecord>>>& WavesUndo() noexcept { return mWavesUndo; }
    [[nodiscard]] std::vector<std::pair<std::vector<WaveRecord>, std::vector<WaveRecord>>>& WavesRedo() noexcept { return mWavesRedo; }
    /** The map's sky now (SkyDome: the dome, horizon, planets, cirrus). */
    [[nodiscard]] SkyboxState SkyboxNow() const;
    /** Puts a sky on the map (its dome is rebuilt on the next frame); no undo step, SkyboxEdited records one. */
    void ApplySkybox(const SkyboxState& sky);
    void SkyboxEdited(SkyboxState before);
    [[nodiscard]] std::vector<std::pair<SkyboxState, SkyboxState>>& SkyboxUndo() noexcept { return mSkyboxUndo; }
    [[nodiscard]] std::vector<std::pair<SkyboxState, SkyboxState>>& SkyboxRedo() noexcept { return mSkyboxRedo; }
    /** The map's lighting now (sun, ambience, shadow, specular, bloom, fog). */
    [[nodiscard]] LightingState LightingNow() const;
    /** Puts a lighting state on the map at once (no undo step; LightingEdited records one). */
    void ApplyLighting(const LightingState& lighting);
    void LightingEdited(LightingState before);
    [[nodiscard]] std::vector<std::pair<LightingState, LightingState>>& LightingUndo() noexcept { return mLightingUndo; }
    [[nodiscard]] std::vector<std::pair<LightingState, LightingState>>& LightingRedo() noexcept { return mLightingRedo; }
    /** The map's sea now (on or off, its levels, the water shader's numbers). */
    [[nodiscard]] WaterState WaterNow() const;
    /** Puts a water state on the map at once (no undo step: a drag applies it many times, then WaterEdited records it). */
    void ApplyWater(const WaterState& water);
    /**
     * While the editor's view is in front of a play: that play's map (the session's), which lighting and water edits
     * go into as well (WPE.41); null otherwise.
     */
    void SetLiveMap(moho::CWldMap* map) noexcept { mLiveMap = map; }
    /** A water edit ended: its before and the water now become the newest undo step. */
    void WaterEdited(WaterState before);
    [[nodiscard]] std::vector<std::pair<WaterState, WaterState>>& WaterUndo() noexcept { return mWaterUndo; }
    [[nodiscard]] std::vector<std::pair<WaterState, WaterState>>& WaterRedo() noexcept { return mWaterRedo; }
    /** The map's decals as a snapshot (every decal's saved fields), for undo. */
    using DecalSnapshot = std::vector<DecalState>;
    [[nodiscard]] DecalSnapshot DecalsNow() const;
    /** Puts a snapshot back as the map's decals. */
    void RestoreDecals(const DecalSnapshot& decals);
    /** A decal edit ended: its before and the decals now become the newest undo step. */
    void DecalsEdited(DecalSnapshot before);
    [[nodiscard]] std::vector<std::pair<DecalSnapshot, DecalSnapshot>>& DecalUndo() noexcept { return mDecalUndo; }
    [[nodiscard]] std::vector<std::pair<DecalSnapshot, DecalSnapshot>>& DecalRedo() noexcept { return mDecalRedo; }
    /** The terrain's decal manager, or null. */
    [[nodiscard]] moho::IDecalManager* Decals() const;
    /** The map's `_save.lua` (markers, areas) and `_script.lua` as the editor keeps them. */
    [[nodiscard]] SaveFile& SaveData() noexcept { return mSave; }
    [[nodiscard]] const SaveFile& SaveData() const noexcept { return mSave; }
    [[nodiscard]] std::string& Script() noexcept { return mScript; }
    [[nodiscard]] const std::string& Script() const noexcept { return mScript; }
    /** An adaptive map's `_tables.lua` as the editor keeps it (empty when the map has none yet). */
    [[nodiscard]] const std::string& TablesText() const noexcept { return mTables; }
    [[nodiscard]] bool Adaptive() const noexcept { return !mFacts.tablesPath.empty(); }
    /**
     * Sets the tables' text as one undo step; on a map without tables, the map becomes adaptive: its tables file is
     * `<base>_tables.lua` beside the scenario and the scenario gets `AdaptiveMap = true`.
     */
    void SetTablesText(const std::string& text);
    /** The map's `_options.lua` as the editor keeps it (empty when it has none). */
    [[nodiscard]] const std::string& OptionsText() const noexcept { return mOptions; }
    /** Sets it as one undo step; a map without one gets `<base>_options.lua` beside the scenario. */
    void SetOptionsText(const std::string& text);
    /**
     * Sets the scenario's water bodies (`ScenarioInfo.WaterBodies`, its text rewritten in place). No undo step of its
     * own: the caller takes SaveDataNow before and gives it to SaveDataEdited after.
     */
    void ApplyWaterBodies(const std::vector<WaterBody>& bodies);
    /** The maps opened last, newest first (their scenario paths), kept in `file`; each map that opens goes first. */
    void SetRecentMapsFile(std::string file);
    [[nodiscard]] const std::vector<std::string>& RecentMaps() const noexcept { return mRecentMaps; }
    /** File > Open Recent > Clear: the list emptied, and its file with it. */
    void ClearRecentMaps();
    /**
     * Compiles the scenario, save and script texts as they are now (edits included) and returns their syntax errors,
     * each with its file and line.
     */
    [[nodiscard]] std::vector<CheckIssue> CheckScripts() const;
    /** One text compiled as the file `name` (`x_options.lua`): its syntax error, or an issue with an empty text. */
    [[nodiscard]] CheckIssue CheckLuaText(const std::string& text, const std::string& name) const;
    [[nodiscard]] const std::string& Scenario() const noexcept { return mScenario; }
    /** The armies of the scenario's team list, in order (its extra armies are ExtraArmies). */
    [[nodiscard]] std::vector<std::string> Armies() const { return ScenarioArmies(mScenario); }
    /**
     * Every army name taken, which a new start position can't have: the team list's, the extra armies (SCMP_009's
     * ARMY_9) and `_save.lua`'s Armies table.
     */
    [[nodiscard]] std::vector<std::string> ArmyNamesInUse() const;
    /** The scenario's teams; setting them rewrites its `teams` block. */
    [[nodiscard]] std::vector<ScenarioTeam> Teams() const { return ScenarioTeams(mScenario); }
    void SetTeams(const std::vector<ScenarioTeam>& teams);
    [[nodiscard]] std::vector<std::string> ExtraArmies() const { return ScenarioExtraArmies(mScenario); }
    void SetExtraArmies(const std::vector<std::string>& armies);
    /** An army added to the scenario's list and to `_save.lua`'s Armies (when it isn't there), removed, renamed. */
    void AddArmy(const std::string& name);
    void RemoveArmy(const std::string& name);
    void RenameArmy(const std::string& from, const std::string& to);
    /** A playable area: the rectangle FAF's SetPlayableArea makes of it (each edge down to a multiple of 4). */
    struct PlayableRect
    {
      int x0 = 0;
      int z0 = 0;
      int x1 = 0;
      int z1 = 0;
      bool operator==(const PlayableRect& other) const { return x0 == other.x0 && z0 == other.z0 && x1 == other.x1 && z1 == other.z1; }
    };
    /** The playable area the map's script sets (its area's rectangle, rounded as the game rounds it), or none. */
    [[nodiscard]] std::optional<PlayableRect> PlayableArea() const;
    /** Sets or clears it (the area `AREA_1`, or the one the script names, and the script's call). */
    void SetPlayableArea(const std::optional<PlayableRect>& area);
    /** The markers, areas and script as a whole, for undo. */
    struct SaveSnapshot
    {
      std::vector<SaveEntry> markers;
      std::vector<SaveEntry> areas;
      std::string script;
      std::vector<SaveEntry> armies;
      std::string tables;
      std::string tablesPath;
      std::string scenario;
      std::vector<MarkerChain> chains;
      std::string options;
      std::string optionsPath;
    };
    [[nodiscard]] SaveSnapshot SaveDataNow() const;
    void RestoreSaveData(const SaveSnapshot& snapshot);
    /** A markers/areas/script edit ended: its before and now become the newest undo step. */
    void SaveDataEdited(SaveSnapshot before);
    [[nodiscard]] std::vector<std::pair<SaveSnapshot, SaveSnapshot>>& SaveDataUndo() noexcept { return mSaveUndo; }
    [[nodiscard]] std::vector<std::pair<SaveSnapshot, SaveSnapshot>>& SaveDataRedo() noexcept { return mSaveRedo; }
    /** The map's props as a whole, for undo: the entries and the records they were read with (same order). */
    struct PropSnapshot
    {
      std::vector<moho::CWldPropEntry> entries;
      std::vector<PropRecord> records;
    };
    [[nodiscard]] PropSnapshot PropsNow() const;
    /** Puts a snapshot back as the map's props (the view rebuilds their meshes). */
    void RestoreProps(const PropSnapshot& props);
    /** A prop edit ended: its before and the props now become the newest undo step. */
    void PropsEdited(PropSnapshot before);
    [[nodiscard]] std::vector<std::pair<PropSnapshot, PropSnapshot>>& PropUndo() noexcept { return mPropUndo; }
    [[nodiscard]] std::vector<std::pair<PropSnapshot, PropSnapshot>>& PropRedo() noexcept { return mPropRedo; }
    /** A prop added at the end (with an empty record: it is saved from its transform) or removed at `index`. */
    void AddProp(const moho::CWldPropEntry& entry, const PropRecord& record);
    void SetPropRecord(std::size_t index, const PropRecord& record);
    void DeletePropAt(std::size_t index);
    /** A texture slot's change (path or size), for undo: its values before and after, as the terrain has them. */
    struct LayerEdit
    {
      int slot = 0;
      std::string albedoBefore, normalsBefore, albedoAfter, normalsAfter;
      float albedoSizeBefore = 1.0f, normalsSizeBefore = 1.0f, albedoSizeAfter = 1.0f, normalsSizeAfter = 1.0f;
      /** Edits made together (a layer set imported) share a non-zero batch and are one undo step. */
      int batch = 0;
    };
    [[nodiscard]] std::vector<LayerEdit>& LayerUndo() noexcept { return mLayerUndo; }
    [[nodiscard]] std::vector<LayerEdit>& LayerRedo() noexcept { return mLayerRedo; }
    /** The slot's albedo path in the facts the Info panel shows. */
    void SetLayerFact(int slot, const std::string& albedo)
    {
      if (slot >= 0 && static_cast<std::size_t>(slot) < mFacts.layers.size()) {
        mFacts.layers[static_cast<std::size_t>(slot)] = albedo;
      }
    }
    /** An edit of `kind` was recorded in its history: it is the newest; what was undone can't be redone. */
    void EditEnded(EditKind kind);
    /** The kind of the edit Undo (Redo) takes back (gives back) next; false when there is none. */
    bool PopUndo(EditKind& kind);
    bool PopRedo(EditKind& kind);
    void PushRedo(EditKind kind) { mRedoOrder.push_back(kind); }
    void PushUndo(EditKind kind) { mUndoOrder.push_back(kind); }
    /** Whether there is an edit to undo (redo), for the toolbar. */
    [[nodiscard]] bool CanUndo() const noexcept { return !mUndoOrder.empty(); }
    [[nodiscard]] bool CanRedo() const noexcept { return !mRedoOrder.empty(); }
    /** Whether the map changed since it was opened (or last saved). */
    [[nodiscard]] bool Modified() const noexcept { return mModified; }
    void SetModified(bool modified) noexcept { mModified = modified; }

    /** The document's Lua state (scripts and objects made for the open map), null unless open. */
    [[nodiscard]] LuaPlus::LuaState* Lua() const noexcept { return mLua.get(); }

  private:
    struct Load;
    static void Run(Load& load);
    static void RunSteps(Load& load);
    static void RunCreate(Load& load);
    std::filesystem::path mCreatedFolder;
    std::string mCreatedScenario;

    State mState = State::Empty;
    moho::CWldMap* mLiveMap = nullptr;
    /** The lighting / water written into one map's terrain (the document's, or a play's). */
    static void LightingInto(moho::IWldTerrainRes& terrain, const LightingState& lighting);
    static void WaterInto(moho::IWldTerrainRes& terrain, const WaterState& water, bool warnTextures);
    std::string mPath;
    MapFacts mFacts;
    std::string mError;
    std::unique_ptr<LuaPlus::LuaState> mLua;
    std::unique_ptr<moho::CWldMap> mMap;
    std::unique_ptr<Load> mLoad;
    std::thread mThread;
    std::function<void()> mBeforeDrop;
    HeightHistory mHeights;
    MaskGrid mMasks;
    MaskHistory mMaskHistory;
    SaveFile mSave;
    std::string mScript;
    std::string mScriptRead;
    std::string mTables;
    std::string mTablesRead;
    std::string mOptions;
    std::string mOptionsRead;
    std::string mScenario;
    std::string mRecentMapsFile;
    std::vector<std::string> mRecentMaps;
    std::string mScenarioRead;
    std::vector<std::pair<SaveSnapshot, SaveSnapshot>> mSaveUndo;
    std::vector<std::pair<SaveSnapshot, SaveSnapshot>> mSaveRedo;
    /** Writes `_save.lua` and `_script.lua` beside the map file when they changed (Save). */
    bool WriteLuaFiles(const std::filesystem::path& folder, std::string& error);
    /** The script's effect decorations block on when the save has Effect markers, off when it has none (both saves). */
    void SyncEffectScript();
    std::vector<std::pair<PropSnapshot, PropSnapshot>> mPropUndo;
    std::vector<std::pair<PropSnapshot, PropSnapshot>> mPropRedo;
    std::vector<LayerEdit> mLayerUndo;
    std::vector<LayerEdit> mLayerRedo;
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> mTerrainTypesUndo;
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> mTerrainTypesRedo;
    int mTerrainTypeRevision = 0;
    std::vector<std::pair<std::vector<WaveRecord>, std::vector<WaveRecord>>> mWavesUndo;
    std::vector<std::pair<std::vector<WaveRecord>, std::vector<WaveRecord>>> mWavesRedo;
    std::vector<std::pair<SkyboxState, SkyboxState>> mSkyboxUndo;
    std::vector<std::pair<SkyboxState, SkyboxState>> mSkyboxRedo;
    std::vector<std::pair<LightingState, LightingState>> mLightingUndo;
    std::vector<std::pair<LightingState, LightingState>> mLightingRedo;
    std::vector<std::pair<WaterState, WaterState>> mWaterUndo;
    std::vector<std::pair<WaterState, WaterState>> mWaterRedo;
    std::vector<std::pair<DecalSnapshot, DecalSnapshot>> mDecalUndo;
    std::vector<std::pair<DecalSnapshot, DecalSnapshot>> mDecalRedo;
    std::vector<EditKind> mUndoOrder;
    std::vector<EditKind> mRedoOrder;
    MapFileRecords mFileRecords;
    std::uint64_t mHeightsAtLoad = 0;
    std::uint64_t mMasksAtRead = 0;
    bool mMasksReadSet = false;
    WaterState mWaterAtLoad;
    [[nodiscard]] std::uint64_t HeightsHash() const;
    [[nodiscard]] std::uint64_t MasksHash() const;
    bool mModified = false;
    bool mBackedUp = false;
    std::filesystem::path mVault;
    /** Set by SaveAsNewFolder: where Save writes from then on (else the map's own file). */
    std::filesystem::path mSaveTarget;
  };
} // namespace faf::editor
