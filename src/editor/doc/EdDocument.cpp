#include "editor/doc/EdDocument.h"
#include "editor/doc/EdAutosave.h"
#include "editor/doc/EdRecentMaps.h"
#include "editor/doc/EdAdaptiveTables.h"
#include "editor/view/EdLiveTerrain.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <chrono>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iterator>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <exception>
#include <system_error>

#include "editor/doc/EdMapFile.h"

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/luaplus/include/lauxlib.h"
#include "lua/LuaTableIterator.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/terrain/water/WaveSystem.h"
#include "moho/render/SkyDome.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "gpg/core/streams/Stream.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace faf::editor
{
  /** One open on the worker thread: what it was given and what it made. */
  struct EdDocument::Load
  {
    std::string scenarioPath;
    std::unique_ptr<LuaPlus::LuaState> lua;
    std::unique_ptr<moho::CWldMap> map;
    MapFacts facts;
    std::string error;
    MapFileRecords records;
    SaveFile save;
    std::string script;
    std::string tables;
    std::string options;
    std::string scenario;
    /** CreateNew: what to make and where; the scenario's game path once made. */
    bool create = false;
    NewMapSettings settings;
    std::filesystem::path createFolder;
    std::string createdScenario;
    /** Set last by the worker; the main thread reads the rest only after seeing it. */
    std::atomic<bool> done{false};
  };

  namespace
  {
    [[nodiscard]] std::string StringOf(
      const LuaPlus::LuaObject& object
    )
    {
      if (!object.IsString()) {
        return {};
      }
      const char* const text = object.GetString();
      return text != nullptr ? text : "";
    }

    /** The text without a leading localization tag (`<LOC key>`), which the game swaps for a translation. */
    [[nodiscard]] std::string WithoutLocTag(
      std::string text
    )
    {
      if (text.rfind("<LOC", 0) == 0) {
        if (const std::size_t end = text.find('>'); end != std::string::npos) {
          text.erase(0, end + 1);
        }
      }
      return text;
    }

    [[nodiscard]] int IntOf(
      const LuaPlus::LuaObject& object
    )
    {
      return object.IsNumber() ? static_cast<int>(object.GetNumber()) : 0;
    }

    /** Runs `path` with a fresh table as its globals (after the game's data helpers) and returns the table. */
    [[nodiscard]] LuaPlus::LuaObject RunInTable(
      LuaPlus::LuaState* const state,
      const std::string& path
    )
    {
      LuaPlus::LuaObject env(state);
      env.AssignNewTable(state, 0, 0);
      (void)moho::SCR_LuaDoScript(state, "/lua/dataInit.lua", &env);
      if (!moho::SCR_LuaDoScript(state, path.c_str(), &env)) {
        return {};
      }
      return env;
    }

    void ReadScenario(
      const LuaPlus::LuaObject& scenario,
      MapFacts& facts
    )
    {
      facts.name = WithoutLocTag(StringOf(scenario["name"]));
      facts.description = WithoutLocTag(StringOf(scenario["description"]));
      facts.type = StringOf(scenario["type"]);
      facts.mapPath = StringOf(scenario["map"]);
      facts.savePath = StringOf(scenario["save"]);
      facts.scriptPath = StringOf(scenario["script"]);
      facts.mapVersion = IntOf(scenario["map_version"]);
      if (const LuaPlus::LuaObject size = scenario["size"]; size.IsTable()) {
        facts.sizeX = IntOf(size[1]);
        facts.sizeZ = IntOf(size[2]);
      }
      const LuaPlus::LuaObject teams = scenario["Configurations"]["standard"]["teams"];
      if (teams.IsTable()) {
        const LuaPlus::LuaObject armies = teams[1]["armies"];
        if (armies.IsTable()) {
          for (LuaPlus::LuaTableIterator army(armies, 1); army.IsValid(); army.Next()) {
            facts.armies.push_back(StringOf(army.GetValue()));
          }
        }
      }
    }

    void ReadSave(
      const LuaPlus::LuaObject& save,
      MapFacts& facts
    )
    {
      const LuaPlus::LuaObject markers = save["MasterChain"]["_MASTERCHAIN_"]["Markers"];
      if (!markers.IsTable()) {
        return;
      }
      for (LuaPlus::LuaTableIterator marker(markers, 1); marker.IsValid(); marker.Next()) {
        std::string type = StringOf(marker.GetValue()["type"]);
        ++facts.markers[type.empty() ? "(no type)" : type];
        ++facts.markerCount;
      }
    }

    void ReadMap(
      moho::CWldMap& map,
      MapFacts& facts
    )
    {
      moho::IWldTerrainRes* const terrain = map.mTerrainRes;
      if (terrain == nullptr) {
        return;
      }
      if (const moho::CHeightField* const field = terrain->GetHeightField(); field != nullptr) {
        facts.fieldWidth = field->width;
        facts.fieldHeight = field->height;
      }
      facts.water = terrain->IsWaterEnabled();
      facts.waterElevation = terrain->GetWaterElevation();
      if (terrain->mMap != nullptr) {
        facts.waterDeep = terrain->mMap->mWaterElevationDeep;
        facts.waterAbyss = terrain->mMap->mWaterElevationAbyss;
      }
      moho::StratumMaterial& strata = terrain->GetStratumMaterial();
      facts.terrainShader = strata.mShaderName.c_str();
      const moho::CStratumMaterial* const albedo[] = {
        &strata.mLowerAlbedoTexture,
        &strata.mStratum0AlbedoTexture,
        &strata.mStratum1AlbedoTexture,
        &strata.mStratum2AlbedoTexture,
        &strata.mStratum3AlbedoTexture,
        &strata.mStratum4AlbedoTexture,
        &strata.mStratum5AlbedoTexture,
        &strata.mStratum6AlbedoTexture,
        &strata.mStratum7AlbedoTexture,
        &strata.mUpperAlbedoTexture,
      };
      for (const moho::CStratumMaterial* const layer : albedo) {
        facts.layers.emplace_back(layer->mPath.c_str());
      }
      if (moho::IDecalManager* const decals = terrain->GetDecalManager(); decals != nullptr) {
        facts.decals = decals->GetDecalCount();
        // By type, and one of them as the file holds it, in the log: what new decals are measured against.
        std::map<int, int> types;
        for (std::int32_t i = 0; i < facts.decals; ++i) {
          if (const moho::CWldTerrainDecal* const decal = decals->GetDecal(i); decal != nullptr) {
            ++types[static_cast<int>(decal->mType)];
          }
        }
        std::string counts;
        for (const auto& [type, count] : types) {
          counts += (counts.empty() ? "" : ", ") + std::to_string(count) + " " + DecalTypeName(type);
        }
        if (facts.decals > 0) {
          const DecalState first = CaptureDecal(*decals->GetDecal(0));
          gpg::Logf(
            "editor: decals: %s; the first: %s, scale %.1f %.1f %.1f, turn %.2f, cutoff %.0f, near %.0f",
            counts.c_str(),
            first.names[0].c_str(),
            first.scale[0],
            first.scale[1],
            first.scale[2],
            first.orientation[1],
            first.cutoff,
            first.nearCutoff
          );
        }
      }
      if (map.mProps != nullptr) {
        facts.props = static_cast<int>(map.mProps->mEntries.size());
      }
    }
  } // namespace

  EdDocument::EdDocument() = default;

  EdDocument::~EdDocument()
  {
    Close();
  }

  void EdDocument::Run(
    Load& load
  )
  {
    const auto start = std::chrono::steady_clock::now();
    if (load.create) {
      RunCreate(load);
    } else {
      RunSteps(load);
    }
    load.facts.loadSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    load.done.store(true, std::memory_order_release);
  }

  namespace
  {
    /** A state of its own with the engine's bindings, as a session's (CWldSessionLoaderImpl.cpp). */
    std::unique_ptr<LuaPlus::LuaState> NewDocumentState()
    {
      auto lua = std::make_unique<LuaPlus::LuaState>(LuaPlus::LuaState::LIB_BASE);
      for (const char* const set : {"Core", "User"}) {
        if (moho::CScrLuaInitFormSet* const forms = moho::SCR_FindLuaInitFormSet(set); forms != nullptr) {
          forms->RunInits(lua.get());
        }
      }
      return lua;
    }

    bool WriteText(
      const std::filesystem::path& file,
      const std::string& text,
      std::string& error
    )
    {
      std::ofstream out(file, std::ios::binary);
      out.write(text.data(), static_cast<std::streamsize>(text.size()));
      if (!out) {
        error = "can't write " + file.string();
        return false;
      }
      return true;
    }

    /** The folder name without FAF's version suffix (`seton.v0003` -> `seton`). */
    [[nodiscard]] std::string BaseOfFolder(const std::string& folder);
  } // namespace

  void EdDocument::RunCreate(
    Load& load
  )
  {
    try {
      load.lua = NewDocumentState();
      LuaPlus::LuaState* const state = load.lua.get();
      const NewMapSettings& settings = load.settings;
      const int units = kNewMapSizes[std::clamp(settings.size, 0, kNewMapSizeCount - 1)].units;

      // The engine's empty map: terrain (default layers, cleared masks, water off), no props.
      auto map = std::make_unique<moho::CWldMap>();
      (void)map->MapNew(units, units, state);
      moho::CHeightField* const field = map->mTerrainRes != nullptr ? map->mTerrainRes->GetHeightField() : nullptr;
      if (field == nullptr) {
        load.error = "the engine made no terrain";
        return;
      }
      const auto word = static_cast<std::uint16_t>(std::clamp(std::lround(settings.height * 128.0f), 0L, 65535L));
      std::fill(
        field->data,
        field->data + static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height),
        word
      );
      field->SetElevationRectRaw(gpg::Rect2i{0, 0, field->width - 1, field->height - 1}, field->data, field->width);
      moho::STIMap& terrain = *map->mTerrainRes->mMap;
      terrain.mWaterEnabled = settings.sea ? 1u : 0u;
      terrain.mWaterElevation = settings.seaLevel;
      terrain.mWaterElevationDeep = settings.seaLevel - 2.5f;
      terrain.mWaterElevationAbyss = settings.seaLevel - 15.0f;
      // The water map (shore and depth shading) is built from the heights and the sea's levels when the
      // terrain enters edit mode, as Reset does once for the empty map.
      {
        moho::CBackgroundTaskControl control{nullptr};
        map->mTerrainRes->EnterEditMode(control);
        map->mTerrainRes->ExitEditMode();
      }
      // The preview is written from its record; the chunk object only has to be there.
      map->mMapPreviewChunk = new moho::RWldMapPreviewChunk();
      MapFileRecords records;
      records.preview = NewMapPreviewRecord(settings);

      const std::string base = BaseOfFolder(settings.folder);
      std::string error;
      if (
        !WriteMapFile(*map, records, load.createFolder / (base + ".scmap"), error) ||
        !WriteText(load.createFolder / (base + "_scenario.lua"), NewMapScenarioText(settings, base), error) ||
        !WriteText(load.createFolder / (base + "_save.lua"), NewMapSaveText(settings), error) ||
        !WriteText(load.createFolder / (base + "_script.lua"), NewMapScriptText(), error)
      ) {
        load.error = error;
        return;
      }
      load.createdScenario = "/maps/" + settings.folder + "/" + base + "_scenario.lua";
    } catch (const std::exception& error) {
      load.error = error.what();
    } catch (...) {
      load.error = "an unknown error";
    }
  }

  void EdDocument::RunSteps(
    Load& load
  )
  {
    try {
      load.lua = NewDocumentState();
      LuaPlus::LuaState* const state = load.lua.get();

      MapFacts& facts = load.facts;
      facts.scenarioPath = load.scenarioPath;
      const LuaPlus::LuaObject scenario = moho::WLD_LoadScenarioInfo(fa::string(load.scenarioPath.c_str()), state);
      if (!scenario.IsTable()) {
        load.error = "its _scenario.lua sets no ScenarioInfo";
        return;
      }
      ReadScenario(scenario, facts);
      if (facts.mapPath.empty()) {
        load.error = "its _scenario.lua names no map file";
        return;
      }

      load.map = std::make_unique<moho::CWldMap>();
      moho::CBackgroundTaskControl control{nullptr};
      if (!load.map->MapLoad(facts.mapPath.c_str(), state, false, control)) {
        load.error = "the map file " + facts.mapPath + " did not load";
        load.map.reset();
        return;
      }
      ReadMap(*load.map, facts);
      // Each prop as the file stores it (the game keeps only a quaternion of its rotation).
      load.records.preview = ReadPreviewRecord(facts.mapPath);
      load.records.props = ReadPropRecords(facts.mapPath, *load.map);
      load.records.images = ReadImageRecords(facts.mapPath, load.records.preview.size());

      // The save's and script's text, for the markers, areas and playable area the editor changes.
      if (std::string text; !facts.savePath.empty() && ReadGameFile(facts.savePath, text)) {
        std::string error;
        if (!load.save.Parse(std::move(text), error)) {
          gpg::Warnf("editor: %s: %s", facts.savePath.c_str(), error.c_str());
        }
      }
      if (!facts.scriptPath.empty()) {
        (void)ReadGameFile(facts.scriptPath, load.script);
        // An adaptive map's tables: the file its script imports.
        if (
          const std::string tables = AdaptiveTablesPath(load.script);
          !tables.empty() && ReadGameFile(tables, load.tables)
        ) {
          facts.tablesPath = tables;
        }
      }
      // Else the tables beside the scenario (made in the editor before the adaptive script was put in).
      if (facts.tablesPath.empty() && load.scenarioPath.size() > std::string("_scenario.lua").size()) {
        const std::string beside =
          load.scenarioPath.substr(0, load.scenarioPath.size() - std::string("_scenario.lua").size()) + "_tables.lua";
        if (ReadGameFile(beside, load.tables)) {
          facts.tablesPath = beside;
        }
      }
      // The lobby options beside the scenario (the game reads `<base>_options.lua` there).
      if (load.scenarioPath.size() > std::string("_scenario.lua").size()) {
        const std::string beside =
          load.scenarioPath.substr(0, load.scenarioPath.size() - std::string("_scenario.lua").size()) + "_options.lua";
        if (ReadGameFile(beside, load.options)) {
          facts.optionsPath = beside;
        }
      }
      // The symmetry the map was made with: its heights, start positions and resource markers.
      if (
        const moho::CHeightField* const field =
          load.map->mTerrainRes != nullptr ? load.map->mTerrainRes->GetHeightField() : nullptr;
        field != nullptr
      ) {
        std::vector<SymmetryMarker> markers;
        for (const SaveEntry& marker : load.save.Markers()) {
          const std::vector<double> at = ValueNumbers(marker.Get("position"));
          if (at.size() < 3) {
            continue;
          }
          const std::string type = ValueString(marker.Get("type"));
          SymmetryMarker m;
          m.x = static_cast<float>(at[0]);
          m.z = static_cast<float>(at[2]);
          if (marker.name.rfind("ARMY_", 0) == 0) {
            m.kind = SymmetryMarker::Kind::Start;
          } else if (type == "Mass") {
            m.kind = SymmetryMarker::Kind::Mass;
          } else if (type == "Hydrocarbon") {
            m.kind = SymmetryMarker::Kind::Hydrocarbon;
          } else {
            continue;
          }
          markers.push_back(m);
        }
        facts.symmetry = DetectSymmetry(field->data, field->width, field->height, markers);
      }
      (void)ReadGameFile(load.scenarioPath, load.scenario);
      if (!facts.savePath.empty()) {
        const LuaPlus::LuaObject save = RunInTable(state, facts.savePath);
        if (save.IsTable() && save["Scenario"].IsTable()) {
          ReadSave(save["Scenario"], facts);
        } else {
          load.error = "the save file " + facts.savePath + " sets no Scenario";
        }
      }
    } catch (const std::exception& error) {
      load.error = error.what();
    } catch (...) {
      load.error = "an unknown error";
    }
  }

  bool EdDocument::Guarded(
    std::function<void()> proceed
  )
  {
    if (mGuardPassed || !mModified || mState != State::Open || !mUnsavedGuard) {
      return false;
    }
    return mUnsavedGuard([this, proceed = std::move(proceed)] {
      mGuardPassed = true;
      proceed();
      mGuardPassed = false;
    });
  }

  bool EdDocument::WriteSnapshot(
    const std::filesystem::path& folder,
    std::string& error
  )
  {
    if (mState != State::Open || mMap == nullptr) {
      error = "no map is open";
      return false;
    }
    if (mMap->mTerrainRes == nullptr || !mMap->mTerrainRes->GetBool()) {
      error = "the terrain is still being prepared";
      return false;
    }
    std::error_code code;
    std::filesystem::create_directories(folder, code);
    if (code) {
      error = "can't make " + folder.string() + ": " + code.message();
      return false;
    }
    const std::filesystem::path disk = MapDiskFile();
    const std::string scmapName = disk.empty() ? FolderName() + ".scmap" : disk.filename().string();
    MarkKeptImages();
    if (!WriteMapFile(*mMap, mFileRecords, folder / scmapName, error)) {
      return false;
    }
    // Every Lua file as Save would write it, the "as saved" texts untouched.
    SyncEffectScript();
    std::string scenario = mScenario;
    if (const ReclaimTotals reclaim = PropReclaim(); reclaim.props > 0) {
      scenario = WithScenarioReclaim(scenario, reclaim.mass, reclaim.energy);
    }
    const std::pair<const std::string*, std::string> files[] = {
      {&mFacts.scenarioPath, scenario},
      {&mFacts.savePath, mSave.Loaded() ? mSave.Text() : std::string()},
      {&mFacts.scriptPath, mScript},
      {&mFacts.tablesPath, mTables},
      {&mFacts.optionsPath, mOptions},
    };
    for (const auto& [gamePath, text] : files) {
      if (gamePath->empty() || text.empty()) {
        continue;
      }
      const std::filesystem::path file = folder / gamePath->substr(gamePath->find_last_of('/') + 1);
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      out.write(text.data(), static_cast<std::streamsize>(text.size()));
      if (!out) {
        error = "can't write " + file.string();
        return false;
      }
    }
    return true;
  }

  bool EdDocument::Open(
    const std::string& scenarioPath
  )
  {
    if (mState == State::Loading) {
      return false;
    }
    if (Guarded([this, scenarioPath] {
      (void)Open(scenarioPath);
    })) {
      return false;
    }
    Close();
    mPath = scenarioPath;
    mState = State::Loading;
    mLoad = std::make_unique<Load>();
    mLoad->scenarioPath = scenarioPath;
    mThread = std::thread([load = mLoad.get()] {
      Run(*load);
    });
    return true;
  }

  bool EdDocument::CreateNew(
    const NewMapSettings& settings,
    std::string& message
  )
  {
    if (mState == State::Loading) {
      message = "A map is still opening.";
      return false;
    }
    if (Guarded([this, settings] {
      std::string ignored;
      (void)CreateNew(settings, ignored);
    })) {
      message = "The open map has unsaved changes: answer the question first.";
      return false;
    }
    if (
      settings.folder.empty() || settings.folder.find_first_of("\\/:*?\"<>|") != std::string::npos ||
      settings.folder[0] == '.'
    ) {
      message = "\"" + settings.folder + "\" can't be a folder name.";
      return false;
    }
    if (mVault.empty()) {
      message = "There is no vault folder to make the map in.";
      return false;
    }
    const std::filesystem::path target = mVault / "maps" / settings.folder;
    std::error_code error;
    if (std::filesystem::exists(target, error)) {
      message = target.string() + " already exists; pick another name.";
      return false;
    }
    std::filesystem::create_directories(target, error);
    if (error) {
      message = "Can't make " + target.string() + ": " + error.message();
      return false;
    }
    Close();
    mPath.clear();
    mState = State::Loading;
    mLoad = std::make_unique<Load>();
    mLoad->create = true;
    mLoad->settings = settings;
    mLoad->createFolder = target;
    mThread = std::thread([load = mLoad.get()] {
      Run(*load);
    });
    message = "Making " + target.string();
    return true;
  }

  std::optional<EdDocument::PlayableRect> EdDocument::PlayableArea() const
  {
    const std::optional<std::string> name = ScriptPlayableArea(mScript);
    if (!name) {
      return std::nullopt;
    }
    for (const SaveEntry& area : mSave.Areas()) {
      if (area.name != *name) {
        continue;
      }
      const std::vector<double> numbers = ValueNumbers(area.Get("rectangle"));
      if (numbers.size() < 4) {
        return std::nullopt;
      }
      // FAF's SetPlayableArea: each edge less its remainder of 4.
      const auto round = [](const double value) {
        const int whole = static_cast<int>(value);
        return whole - whole % 4;
      };
      return PlayableRect{round(numbers[0]), round(numbers[1]), round(numbers[2]), round(numbers[3])};
    }
    return std::nullopt;
  }

  void EdDocument::SetPlayableArea(
    const std::optional<PlayableRect>& area
  )
  {
    if (!area) {
      mScript = WithScriptPlayableArea(mScript, "");
      mModified = true;
      return;
    }
    const std::string name = ScriptPlayableArea(mScript).value_or("AREA_1");
    SaveEntry* entry = nullptr;
    for (SaveEntry& existing : mSave.Areas()) {
      entry = existing.name == name ? &existing : entry;
    }
    if (entry == nullptr) {
      mSave.Areas().push_back({name, {}});
      entry = &mSave.Areas().back();
    }
    entry->Set("rectangle", RectangleValue(area->x0, area->z0, area->x1, area->z1));
    mScript = WithScriptPlayableArea(mScript, name);
    mModified = true;
  }

  void EdDocument::SetExtraArmies(
    const std::vector<std::string>& armies
  )
  {
    mScenario = WithScenarioExtraArmies(mScenario, armies);
    for (const std::string& army : armies) {
      bool known = false;
      for (const SaveEntry& entry : mSave.Armies()) {
        known = known || entry.name == army;
      }
      if (!known) {
        mSave.Armies().push_back(NewArmyEntry(army));
      }
    }
    mModified = true;
  }

  void EdDocument::SetTeams(
    const std::vector<ScenarioTeam>& teams
  )
  {
    mScenario = WithScenarioTeams(mScenario, teams);
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::AddArmy(
    const std::string& name
  )
  {
    // A new army joins the first team (a map's one FFA team).
    std::vector<ScenarioTeam> teams = Teams();
    const std::vector<std::string> armies = Armies();
    if (std::find(armies.begin(), armies.end(), name) == armies.end()) {
      if (teams.empty()) {
        mScenario = WithScenarioArmies(mScenario, {name});
      } else {
        teams.front().armies.push_back(name);
        mScenario = WithScenarioTeams(mScenario, teams);
      }
    }
    bool known = false;
    for (const SaveEntry& entry : mSave.Armies()) {
      known = known || entry.name == name;
    }
    if (!known) {
      mSave.Armies().push_back(NewArmyEntry(name));
    }
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::RemoveArmy(
    const std::string& name
  )
  {
    // From whichever team has it.
    std::vector<ScenarioTeam> teams = Teams();
    for (ScenarioTeam& team : teams) {
      team.armies.erase(std::remove(team.armies.begin(), team.armies.end(), name), team.armies.end());
    }
    mScenario = WithScenarioTeams(mScenario, teams);
    const std::vector<std::string> extra = ExtraArmies();
    if (std::find(extra.begin(), extra.end(), name) == extra.end()) {
      auto& entries = mSave.Armies();
      entries.erase(
        std::remove_if(
          entries.begin(),
          entries.end(),
          [&](const SaveEntry& entry) {
        return entry.name == name;
      }
        ),
        entries.end()
      );
    }
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::RenameArmy(
    const std::string& from,
    const std::string& to
  )
  {
    std::vector<ScenarioTeam> teams = Teams();
    for (ScenarioTeam& team : teams) {
      std::replace(team.armies.begin(), team.armies.end(), from, to);
    }
    mScenario = WithScenarioTeams(mScenario, teams);
    for (SaveEntry& entry : mSave.Armies()) {
      if (entry.name == from) {
        entry.name = to;
      }
    }
    mFacts.armies = Armies();
    mModified = true;
  }

  EdDocument::SaveSnapshot EdDocument::SaveDataNow() const
  {
    return {
      mSave.Markers(),
      mSave.Areas(),
      mScript,
      mSave.Armies(),
      mTables,
      mFacts.tablesPath,
      mScenario,
      mSave.Chains(),
      mOptions,
      mFacts.optionsPath
    };
  }

  void EdDocument::RestoreSaveData(
    const SaveSnapshot& snapshot
  )
  {
    mSave.Markers() = snapshot.markers;
    mSave.Areas() = snapshot.areas;
    mScript = snapshot.script;
    mSave.Armies() = snapshot.armies;
    mTables = snapshot.tables;
    mFacts.tablesPath = snapshot.tablesPath;
    mScenario = snapshot.scenario;
    mSave.Chains() = snapshot.chains;
    mOptions = snapshot.options;
    mFacts.optionsPath = snapshot.optionsPath;
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::SetRecentMapsFile(
    std::string file
  )
  {
    mRecentMapsFile = std::move(file);
    mRecentMaps = ReadRecentMaps(mRecentMapsFile);
  }

  void EdDocument::ClearRecentMaps()
  {
    mRecentMaps.clear();
    if (!mRecentMapsFile.empty() && !WriteRecentMaps(mRecentMapsFile, mRecentMaps)) {
      gpg::Warnf("editor: the recent maps list %s could not be written", mRecentMapsFile.c_str());
    }
  }

  void EdDocument::ApplyWaterBodies(
    const std::vector<WaterBody>& bodies
  )
  {
    const std::string scenario = WithWaterBodies(mScenario, bodies);
    if (scenario != mScenario) {
      mScenario = scenario;
      mModified = true;
    }
  }

  void EdDocument::SetTablesText(
    const std::string& text
  )
  {
    SaveSnapshot before = SaveDataNow();
    if (mFacts.tablesPath.empty()) {
      // The map becomes adaptive: the tables beside the scenario, and the scenario's flag.
      const std::size_t cut =
        mFacts.scenarioPath.size() - std::min(mFacts.scenarioPath.size(), std::string("_scenario.lua").size());
      mFacts.tablesPath = mFacts.scenarioPath.substr(0, cut) + "_tables.lua";
      mScenario = WithScenarioAdaptive(mScenario);
    }
    mTables = text;
    SaveDataEdited(std::move(before));
  }

  void EdDocument::SetOptionsText(
    const std::string& text
  )
  {
    SaveSnapshot before = SaveDataNow();
    if (mFacts.optionsPath.empty()) {
      const std::size_t cut =
        mFacts.scenarioPath.size() - std::min(mFacts.scenarioPath.size(), std::string("_scenario.lua").size());
      mFacts.optionsPath = mFacts.scenarioPath.substr(0, cut) + "_options.lua";
    }
    mOptions = text;
    SaveDataEdited(std::move(before));
  }

  void EdDocument::SaveDataEdited(
    SaveSnapshot before
  )
  {
    mSaveUndo.emplace_back(std::move(before), SaveDataNow());
    EditEnded(EditKind::SaveData);
    mModified = true;
  }

  void EdDocument::SyncEffectScript()
  {
    // The effect decorations' script block follows the Effect markers (on with any, off without).
    if (!mSave.Loaded() || mFacts.scriptPath.empty()) {
      return;
    }
    bool effects = false;
    for (const SaveEntry& marker : mSave.Markers()) {
      effects = effects || ValueString(marker.Get("type")) == "Effect";
    }
    mScript = WithScriptEffects(mScript, effects);
  }

  bool EdDocument::WriteLuaFiles(
    const std::filesystem::path& folder,
    std::string& error
  )
  {
    const auto write = [&](const std::string& gamePath, const std::string& text) {
      const std::filesystem::path file = folder / gamePath.substr(gamePath.find_last_of('/') + 1);
      std::ofstream out(file, std::ios::binary);
      out.write(text.data(), static_cast<std::streamsize>(text.size()));
      if (!out) {
        error = "can't write " + file.string();
        return false;
      }
      return true;
    };
    SyncEffectScript();
    if (mSave.Loaded() && mSave.Changed()) {
      if (!write(mFacts.savePath, mSave.Text())) {
        return false;
      }
      mSave.MarkSaved();
    }
    if (mScript != mScriptRead && !mFacts.scriptPath.empty()) {
      if (!write(mFacts.scriptPath, mScript)) {
        return false;
      }
      mScriptRead = mScript;
    }
    if (mTables != mTablesRead && !mFacts.tablesPath.empty()) {
      if (!write(mFacts.tablesPath, mTables)) {
        return false;
      }
      mTablesRead = mTables;
    }
    if (mOptions != mOptionsRead && !mFacts.optionsPath.empty()) {
      if (!write(mFacts.optionsPath, mOptions)) {
        return false;
      }
      mOptionsRead = mOptions;
    }
    // A scenario that keeps the map's reclaim (FAForeverMapEditor's `reclaim`) gets the props' totals.
    if (const ReclaimTotals reclaim = PropReclaim(); reclaim.props > 0) {
      mScenario = WithScenarioReclaim(mScenario, reclaim.mass, reclaim.energy);
    }
    if (mScenario != mScenarioRead && !mFacts.scenarioPath.empty()) {
      if (!write(mFacts.scenarioPath, mScenario)) {
        return false;
      }
      mScenarioRead = mScenario;
    }
    return true;
  }

  EdDocument::PropSnapshot EdDocument::PropsNow() const
  {
    PropSnapshot snapshot;
    if (mMap != nullptr && mMap->mProps != nullptr) {
      snapshot.entries.assign(mMap->mProps->mEntries.begin(), mMap->mProps->mEntries.end());
    }
    snapshot.records = mFileRecords.props;
    return snapshot;
  }

  void EdDocument::RestoreProps(
    const PropSnapshot& props
  )
  {
    if (mMap == nullptr || mMap->mProps == nullptr) {
      return;
    }
    mMap->mProps->mEntries.clear();
    for (const moho::CWldPropEntry& entry : props.entries) {
      mMap->mProps->mEntries.push_back(entry);
    }
    mFileRecords.props = props.records;
    mModified = true;
  }

  void EdDocument::PropsEdited(
    PropSnapshot before
  )
  {
    mPropUndo.emplace_back(std::move(before), PropsNow());
    // A long session keeps the newest 200 prop edits (a 5000-prop map is about 0.3 MB a step, twice).
    if (mPropUndo.size() > 200) {
      mPropUndo.erase(mPropUndo.begin());
    }
    EditEnded(EditKind::Props);
    mModified = true;
  }

  std::vector<CheckIssue> EdDocument::CheckScripts() const
  {
    std::vector<CheckIssue> issues;
    if (mLua == nullptr) {
      return issues;
    }
    lua_State* const L = mLua->GetCState();
    const auto name = [](const std::string& path, const char* const fallback) {
      const std::size_t slash = path.find_last_of('/');
      return path.empty() ? std::string(fallback) : path.substr(slash == std::string::npos ? 0 : slash + 1);
    };
    const std::pair<std::string, const std::string*> files[] = {
      {name(mPath, "_scenario.lua"), &mScenario},
      {name(mFacts.savePath, "_save.lua"), nullptr},
      {name(mFacts.scriptPath, "_script.lua"), &mScript},
      // An adaptive map's lobby options and tables (empty when it has none: skipped).
      {name(mFacts.optionsPath, "_options.lua"), &mOptions},
      {name(mFacts.tablesPath, "_tables.lua"), &mTables},
    };
    const std::string save = mSave.Text();
    for (const auto& [file, text] : files) {
      const std::string& source = text != nullptr ? *text : save;
      if (source.empty()) {
        continue;
      }
      const int top = lua_gettop(L);
      const std::string chunk = "=" + file;
      if (luaL_loadbuffer(L, source.data(), source.size(), chunk.c_str()) != 0) {
        const char* const message = lua_tostring(L, -1);
        CheckIssue issue;
        issue.level = CheckIssue::Level::Error;
        issue.file = file;
        int line = 0;
        std::string text2;
        if (message != nullptr && ParseLuaError(message, line, text2)) {
          issue.line = line;
          issue.text = text2;
        } else {
          issue.text = message != nullptr ? message : "does not compile";
        }
        issue.marker = file;
        issues.push_back(std::move(issue));
      }
      lua_settop(L, top);
    }
    return issues;
  }

  CheckIssue EdDocument::CheckLuaText(
    const std::string& text,
    const std::string& name
  ) const
  {
    CheckIssue issue;
    issue.file = name;
    if (mLua == nullptr || text.empty()) {
      return issue;
    }
    lua_State* const L = mLua->GetCState();
    const int top = lua_gettop(L);
    const std::string chunk = "=" + name;
    if (luaL_loadbuffer(L, text.data(), text.size(), chunk.c_str()) != 0) {
      const char* const message = lua_tostring(L, -1);
      issue.level = CheckIssue::Level::Error;
      int line = 0;
      std::string what;
      if (message != nullptr && ParseLuaError(message, line, what)) {
        issue.line = line;
        issue.text = what;
      } else {
        issue.text = message != nullptr ? message : "does not compile";
      }
    }
    lua_settop(L, top);
    return issue;
  }

  std::vector<std::string> EdDocument::ArmyNamesInUse() const
  {
    std::vector<std::string> names = Armies();
    const auto add = [&names](const std::string& name) {
      if (std::find(names.begin(), names.end(), name) == names.end()) {
        names.push_back(name);
      }
    };
    for (const std::string& army : ExtraArmies()) {
      add(army);
    }
    for (const SaveEntry& army : mSave.Armies()) {
      add(army.name);
    }
    return names;
  }

  std::vector<WaveRecord> EdDocument::WavesNow() const
  {
    std::vector<WaveRecord> waves;
    moho::WaveSystem* const system =
      mMap != nullptr && mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetWaveSystem() : nullptr;
    if (system == nullptr) {
      return waves;
    }
    gpg::PipeStream pipe;
    {
      gpg::BinaryWriter writer(&pipe);
      system->Save(writer);
    }
    pipe.VirtFlush();
    // Drained in chunks: GetLength (0x009566C0) counts the first block only from where a read left it, so before any
    // read it comes up short on a stream of several blocks.
    std::string bytes;
    char chunk[65536];
    for (;;) {
      const std::size_t got = pipe.VirtReadNonBlocking(chunk, sizeof(chunk));
      if (got == 0) {
        break;
      }
      bytes.append(chunk, got);
    }
    if (!WaveRecordsFromBytes(bytes, waves)) {
      gpg::Warnf("editor: the wave generators didn't read back (%zu bytes)", bytes.size());
    }
    return waves;
  }

  EdDocument::ReclaimTotals EdDocument::PropReclaim() const
  {
    ReclaimTotals totals;
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (rules == nullptr || mMap == nullptr || mMap->mProps == nullptr) {
      return totals;
    }
    std::map<std::string, std::size_t> rowOf;
    for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
      const std::string path = entry.mBlueprintPath.c_str();
      auto found = rowOf.find(path);
      if (found == rowOf.end()) {
        ReclaimRow row;
        row.blueprint = path;
        moho::RResId id{};
        gpg::STR_CopyFilename(&id.name, &entry.mBlueprintPath);
        if (const moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id); blueprint != nullptr) {
          row.mass = blueprint->Economy.ReclaimMassMax;
          row.energy = blueprint->Economy.ReclaimEnergyMax;
        } else {
          row.mass = -1.0f;
        }
        found = rowOf.emplace(path, totals.rows.size()).first;
        totals.rows.push_back(row);
      }
      ReclaimRow& row = totals.rows[found->second];
      ++row.count;
      ++totals.props;
      if (row.mass < 0.0f) {
        ++totals.unknown;
      } else if (row.mass == 0.0f && row.energy == 0.0f) {
        ++totals.none;
      } else {
        totals.mass += row.mass;
        totals.energy += row.energy;
      }
    }
    std::sort(totals.rows.begin(), totals.rows.end(), [](const ReclaimRow& a, const ReclaimRow& b) {
      return a.mass * static_cast<float>(a.count) > b.mass * static_cast<float>(b.count);
    });
    return totals;
  }

  std::uint8_t* EdDocument::TerrainTypeCells(
    int& width,
    int& height
  ) const
  {
    width = 0;
    height = 0;
    if (mMap == nullptr || mMap->mTerrainRes == nullptr || mMap->mTerrainRes->mMap == nullptr) {
      return nullptr;
    }
    moho::TerrainTypeGrid& grid = mMap->mTerrainRes->mMap->mTerrainType;
    width = grid.width;
    height = grid.height;
    return grid.data;
  }

  std::vector<std::uint8_t> EdDocument::TerrainTypesNow() const
  {
    int width = 0;
    int height = 0;
    const std::uint8_t* const cells = TerrainTypeCells(width, height);
    return cells != nullptr
      ? std::vector<std::uint8_t>(cells, cells + static_cast<std::size_t>(width) * static_cast<std::size_t>(height))
      : std::vector<std::uint8_t>();
  }

  void EdDocument::ApplyTerrainTypes(
    const std::vector<std::uint8_t>& cells
  )
  {
    int width = 0;
    int height = 0;
    std::uint8_t* const grid = TerrainTypeCells(width, height);
    if (grid == nullptr || cells.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height)) {
      return;
    }
    std::memcpy(grid, cells.data(), cells.size());
    ++mTerrainTypeRevision;
    mModified = true;
  }

  void EdDocument::TerrainTypesEdited(
    std::vector<std::uint8_t> before
  )
  {
    mTerrainTypesUndo.emplace_back(std::move(before), TerrainTypesNow());
    // A megabyte a side on a 20 km map: a few steps.
    if (mTerrainTypesUndo.size() > 20) {
      mTerrainTypesUndo.erase(mTerrainTypesUndo.begin());
    }
    EditEnded(EditKind::TerrainTypes);
    mModified = true;
  }

  namespace
  {
    std::uint64_t Fnv(
      const void* const data,
      const std::size_t size,
      std::uint64_t hash = 1469598103934665603ULL
    )
    {
      const auto* const bytes = static_cast<const unsigned char*>(data);
      for (std::size_t i = 0; i < size; ++i) {
        hash = (hash ^ bytes[i]) * 1099511628211ULL;
      }
      return hash;
    }
  } // namespace

  std::uint64_t EdDocument::HeightsHash() const
  {
    const moho::CHeightField* const field =
      mMap != nullptr && mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    return field != nullptr && field->data != nullptr
      ? Fnv(
          field->data,
          static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height) * sizeof(field->data[0])
        )
      : 0U;
  }

  std::uint64_t EdDocument::MasksHash() const
  {
    return mMasks.texels.empty() ? 0U : Fnv(mMasks.texels.data(), mMasks.texels.size() * sizeof(mMasks.texels[0]));
  }

  void EdDocument::MasksRead()
  {
    if (!mMasksReadSet) {
      mMasksAtRead = MasksHash();
      mMasksReadSet = true;
    }
  }

  void EdDocument::MarkKeptImages()
  {
    // The images in the file's order: the normal maps, then the two stratum masks, then the water map.
    const std::size_t count = mFileRecords.images.size();
    mFileRecords.keepImages.assign(count, false);
    if (count < 3) {
      return;
    }
    const bool heights = HeightsHash() == mHeightsAtLoad;
    const WaterState water = WaterNow();
    const bool levels = water.enabled == mWaterAtLoad.enabled && water.elevation == mWaterAtLoad.elevation &&
      water.deep == mWaterAtLoad.deep && water.abyss == mWaterAtLoad.abyss;
    const bool masks = !mMasksReadSet || MasksHash() == mMasksAtRead;
    for (std::size_t i = 0; i < count; ++i) {
      mFileRecords.keepImages[i] = i + 1 == count ? heights && levels : i + 3 >= count ? masks : heights;
    }
  }

  int EdDocument::WaveCount() const
  {
    moho::WaveSystem* const system =
      mMap != nullptr && mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetWaveSystem() : nullptr;
    return system != nullptr ? static_cast<int>(system->mWaveGenerators.end_ - system->mWaveGenerators.start_) : 0;
  }

  void EdDocument::ApplyWaves(
    const std::vector<WaveRecord>& waves
  )
  {
    moho::WaveSystem* const system =
      mMap != nullptr && mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetWaveSystem() : nullptr;
    const moho::CHeightField* const field = system != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    const std::string bytes = WaveRecordsToBytes(waves);
    gpg::PipeStream pipe;
    pipe.VirtWrite(bytes.data(), bytes.size());
    pipe.VirtFlush();
    gpg::BinaryReader reader(&pipe);
    // The map's current format (above 51: every float of a generator is read, WaveGenerator::LoadSerializedState).
    system->Load(60, field->height - 1, field->width - 1, reader);
    mModified = true;
  }

  void EdDocument::WavesEdited(
    std::vector<WaveRecord> before
  )
  {
    mWavesUndo.emplace_back(std::move(before), WavesNow());
    // A retail map has thousands; a few steps are enough.
    if (mWavesUndo.size() > 20) {
      mWavesUndo.erase(mWavesUndo.begin());
    }
    EditEnded(EditKind::Waves);
    mModified = true;
  }

  SkyboxState EdDocument::SkyboxNow() const
  {
    SkyboxState sky;
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return sky;
    }
    const moho::SkyDome& dome = static_cast<const moho::IWldTerrainRes&>(*mMap->mTerrainRes).GetSkyDome();
    const auto three = [](const Wm3::Vector3f& v, float (&out)[3]) {
      out[0] = v.x;
      out[1] = v.y;
      out[2] = v.z;
    };
    three(dome.mDomeOrigin, sky.position);
    // SkyDome::Load's order (0x00815FA0), FAFME's names.
    sky.horizonHeight = dome.mDomeShapeParams.x;
    sky.scale = dome.mDomeShapeParams.y;
    sky.subtractHeight = dome.mDomeShapeParams.z;
    sky.subdivisionsAxis = dome.mWidth;
    sky.subdivisionsHeight = dome.mHeight;
    sky.zenithHeight = dome.mHorizonSize;
    three(dome.mHorizonColor, sky.horizonColor);
    three(dome.mSkyColor, sky.zenithColor);
    sky.decalGlow = dome.mHorizonBlend;
    sky.albedo = dome.mAtmosphereTexPath.c_str();
    sky.glow = dome.mAtmosphereTexPath2.c_str();
    for (const moho::SkyDomeDecalVertices& record : dome.mDecalUploads) {
      SkyboxPlanet planet;
      std::memcpy(&planet, record.mBytes, sizeof(planet));
      sky.planets.push_back(planet);
    }
    sky.cirrusMultiplier = dome.mCirrusMultiplier;
    sky.cirrusColor[0] = dome.mCirrusColor_R;
    sky.cirrusColor[1] = dome.mCirrusColor_G;
    sky.cirrusColor[2] = dome.mCirrusColor_B;
    sky.cirrusTexture = dome.mCirrusTexPath.c_str();
    static_assert(sizeof(sky.cirrus) == sizeof(dome.mCirrusData), "four 20-byte cirrus layers");
    std::memcpy(sky.cirrus, dome.mCirrusData, sizeof(sky.cirrus));
    return sky;
  }

  void EdDocument::ApplySkybox(
    const SkyboxState& sky
  )
  {
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return;
    }
    moho::SkyDome& dome = mMap->mTerrainRes->GetSkyDome();
    // As SkyDome::Load: its GPU resources dropped first, so the next frame builds the dome from these.
    dome.Reset();
    dome.mDomeOrigin = Wm3::Vector3f(sky.position[0], sky.position[1], sky.position[2]);
    dome.mDomeShapeParams = Wm3::Vector3f(sky.horizonHeight, sky.scale, sky.subtractHeight);
    dome.mWidth = sky.subdivisionsAxis;
    dome.mHeight = sky.subdivisionsHeight;
    dome.mHorizonSize = sky.zenithHeight;
    dome.mHorizonColor = Wm3::Vector3f(sky.horizonColor[0], sky.horizonColor[1], sky.horizonColor[2]);
    dome.mSkyColor = Wm3::Vector3f(sky.zenithColor[0], sky.zenithColor[1], sky.zenithColor[2]);
    dome.mHorizonBlend = sky.decalGlow;
    dome.mAtmosphereTexPath.assign(sky.albedo.c_str());
    dome.mAtmosphereTexPath2.assign(sky.glow.c_str());
    dome.mDecalUploads.clear();
    for (const SkyboxPlanet& planet : sky.planets) {
      moho::SkyDomeDecalVertices record{};
      std::memcpy(record.mBytes, &planet, sizeof(planet));
      dome.mDecalUploads.push_back(record);
    }
    dome.mCirrusMultiplier = sky.cirrusMultiplier;
    dome.mCirrusColor_R = sky.cirrusColor[0];
    dome.mCirrusColor_G = sky.cirrusColor[1];
    dome.mCirrusColor_B = sky.cirrusColor[2];
    dome.mCirrusTexPath.assign(sky.cirrusTexture.c_str());
    std::memcpy(dome.mCirrusData, sky.cirrus, sizeof(sky.cirrus));
    mModified = true;
  }

  void EdDocument::SkyboxEdited(
    SkyboxState before
  )
  {
    mSkyboxUndo.emplace_back(std::move(before), SkyboxNow());
    if (mSkyboxUndo.size() > 50) {
      mSkyboxUndo.erase(mSkyboxUndo.begin());
    }
    EditEnded(EditKind::Skybox);
    mModified = true;
  }

  LightingState EdDocument::LightingNow() const
  {
    LightingState lighting;
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return lighting;
    }
    const moho::IWldTerrainRes& terrain = *mMap->mTerrainRes;
    const auto three = [](const Wm3::Vector3f& v, float (&out)[3]) {
      out[0] = v.x;
      out[1] = v.y;
      out[2] = v.z;
    };
    lighting.multiplier = terrain.GetLightingMultiplier();
    three(terrain.GetSunDirection(), lighting.sunDirection);
    three(terrain.GetSunAmbience(), lighting.sunAmbience);
    three(terrain.GetSunColor(), lighting.sunColor);
    three(terrain.GetShadowFillColor(), lighting.shadowFill);
    const moho::Vector4f specular = terrain.GetSpecularColor();
    lighting.specular[0] = specular.x;
    lighting.specular[1] = specular.y;
    lighting.specular[2] = specular.z;
    lighting.specular[3] = specular.w;
    lighting.bloom = terrain.GetBloom();
    // The fog as WRenViewport::FogOn reads it: the colour from the first three floats, start and end from the next two.
    const moho::SFogInfo& fog = terrain.GetFogInfo();
    lighting.fogColor[0] = fog.mStartDistance;
    lighting.fogColor[1] = fog.mCutoffDistance;
    lighting.fogColor[2] = fog.mMinClamp;
    lighting.fogStart = fog.mMaxClamp;
    lighting.fogEnd = fog.mCurveExponent;
    return lighting;
  }

  void EdDocument::ApplyLighting(
    const LightingState& lighting
  )
  {
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return;
    }
    LightingInto(*mMap->mTerrainRes, lighting);
    // In front of a play: its map takes the same (WPE.41).
    if (mLiveMap != nullptr && mLiveMap->mTerrainRes != nullptr) {
      LightingInto(*mLiveMap->mTerrainRes, lighting);
    }
    mModified = true;
  }

  void EdDocument::LightingInto(
    moho::IWldTerrainRes& terrain,
    const LightingState& lighting
  )
  {
    const auto vec = [](const float (&v)[3]) {
      return Wm3::Vector3f(v[0], v[1], v[2]);
    };
    terrain.SetLightingMultiplier(lighting.multiplier);
    terrain.SetSunDirection(vec(lighting.sunDirection));
    terrain.SetSunAmbience(vec(lighting.sunAmbience));
    terrain.SetSunColor(vec(lighting.sunColor));
    terrain.SetShadowFillColor(vec(lighting.shadowFill));
    moho::Vector4f specular = terrain.GetSpecularColor();
    specular.x = lighting.specular[0];
    specular.y = lighting.specular[1];
    specular.z = lighting.specular[2];
    specular.w = lighting.specular[3];
    terrain.SetSpecularColor(specular);
    terrain.SetBloom(lighting.bloom);
    moho::SFogInfo fog = terrain.GetFogInfo();
    fog.mStartDistance = lighting.fogColor[0];
    fog.mCutoffDistance = lighting.fogColor[1];
    fog.mMinClamp = lighting.fogColor[2];
    fog.mMaxClamp = lighting.fogStart;
    fog.mCurveExponent = lighting.fogEnd;
    terrain.SetFogInfo(fog);
  }

  void EdDocument::LightingEdited(
    LightingState before
  )
  {
    mLightingUndo.emplace_back(before, LightingNow());
    if (mLightingUndo.size() > 200) {
      mLightingUndo.erase(mLightingUndo.begin());
    }
    EditEnded(EditKind::Lighting);
    mModified = true;
  }

  std::vector<std::pair<std::string, std::string>> EdDocument::CubesNow() const
  {
    std::vector<std::pair<std::string, std::string>> cubes;
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return cubes;
    }
    moho::TerrainEnvironmentLookupPairs pairs;
    static_cast<const moho::IWldTerrainRes&>(*mMap->mTerrainRes).EnumerateEnvLookup(pairs);
    for (const auto& [name, cube] : pairs) {
      cubes.emplace_back(name.c_str(), cube.c_str());
    }
    return cubes;
  }

  void EdDocument::ApplyCubes(
    const std::vector<std::pair<std::string, std::string>>& cubes
  )
  {
    if (mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return;
    }
    moho::IWldTerrainRes& terrain = *mMap->mTerrainRes;
    terrain.ClearEnvLookup();
    for (const auto& [name, cube] : cubes) {
      terrain.AddEnvLookup(fa::string(name.c_str()), fa::string(cube.c_str()));
    }
    mModified = true;
  }

  void EdDocument::LookApplied(
    LookEnvironment before
  )
  {
    mLookUndo.emplace_back(std::move(before), LookEnvironmentNow());
    if (mLookUndo.size() > 100) {
      mLookUndo.erase(mLookUndo.begin());
    }
    EditEnded(EditKind::Look);
    mModified = true;
  }

  WaterState EdDocument::WaterNow() const
  {
    WaterState water;
    if (mMap == nullptr || mMap->mTerrainRes == nullptr || mMap->mTerrainRes->mMap == nullptr) {
      return water;
    }
    const moho::STIMap& map = *mMap->mTerrainRes->mMap;
    water.enabled = map.mWaterEnabled != 0u;
    water.elevation = map.mWaterElevation;
    water.deep = map.mWaterElevationDeep;
    water.abyss = map.mWaterElevationAbyss;
    if (
      const moho::CWaterShaderProperties* const shader = mMap->mTerrainRes->GetWaterShaderProperties();
      shader != nullptr
    ) {
      static_assert(
        sizeof(WaterNumbers) == sizeof(moho::WaterShaderNumericState), "WaterNumbers mirrors WaterShaderNumericState"
      );
      std::memcpy(&water.shader, &shader->mNumericState, sizeof(water.shader));
      water.textures[0] = shader->mWaterCubemap.c_str();
      water.textures[1] = shader->mWaterRamp.c_str();
      for (int i = 0; i < 4; ++i) {
        water.textures[2 + i] = shader->mShaderNames[i].c_str();
      }
    }
    return water;
  }

  void EdDocument::ApplyWater(
    const WaterState& water
  )
  {
    if (mMap == nullptr || mMap->mTerrainRes == nullptr || mMap->mTerrainRes->mMap == nullptr) {
      return;
    }
    WaterInto(*mMap->mTerrainRes, water, true);
    // In front of a play: its map's water the same, and its sim's levels at its next beat (WPE.41).
    if (mLiveMap != nullptr && mLiveMap->mTerrainRes != nullptr && mLiveMap->mTerrainRes->mMap != nullptr) {
      WaterInto(*mLiveMap->mTerrainRes, water, false);
      LiveWaterLevels(water.enabled, water.elevation, water.deep, water.abyss);
    }
    mFacts.water = water.enabled;
    mFacts.waterElevation = water.elevation;
    mFacts.waterDeep = water.deep;
    mFacts.waterAbyss = water.abyss;
    mModified = true;
  }

  void EdDocument::WaterInto(
    moho::IWldTerrainRes& terrainRes,
    const WaterState& water,
    const bool warnTextures
  )
  {
    moho::IWldTerrainRes* const terrain = &terrainRes;
    const moho::STIMap& map = *terrain->mMap;
    const bool levelsChanged = (map.mWaterEnabled != 0u) != water.enabled || map.mWaterElevation != water.elevation ||
      map.mWaterElevationDeep != water.deep || map.mWaterElevationAbyss != water.abyss;
    terrain->WaterEnabled(water.enabled);
    terrain->SetWaterElevation(water.elevation);
    terrain->SetWaterElevationDeep(water.deep);
    terrain->SetWaterElevationAbyss(water.abyss);
    if (moho::CWaterShaderProperties* const shader = terrain->GetWaterShaderProperties(); shader != nullptr) {
      std::memcpy(&shader->mNumericState, &water.shader, sizeof(water.shader));
      // The textures: new names, and the loaded ones dropped; the water's draw loads each again the next time it binds
      // it (GetCubeMap 0x0089FC40, GetWaterRamp 0x0089FD70, GetNormalMap 0x0089FB00 load a slot that is empty).
      fa::string* const paths[6] = {
        &shader->mWaterCubemap,
        &shader->mWaterRamp,
        &shader->mShaderNames[0],
        &shader->mShaderNames[1],
        &shader->mShaderNames[2],
        &shader->mShaderNames[3]
      };
      bool texturesChanged = false;
      for (int i = 0; i < 6; ++i) {
        if (water.textures[i] != paths[i]->c_str()) {
          paths[i]->assign(water.textures[i].c_str());
          texturesChanged = true;
          if (
            std::string probe; warnTextures && !water.textures[i].empty() && !ReadGameFile(water.textures[i], probe)
          ) {
            gpg::Warnf(
              "editor: water texture %s isn't in the game's files; the game draws a stand-in", water.textures[i].c_str()
            );
          }
        }
      }
      if (texturesChanged) {
        shader->releaseTextures();
      }
    }
    // The water map (depth below the sea, for the shore and the water's colour) follows the levels.
    if (levelsChanged) {
      terrain->UpdateWaterMap();
    }
  }

  void EdDocument::WaterEdited(
    WaterState before
  )
  {
    mWaterUndo.emplace_back(std::move(before), WaterNow());
    if (mWaterUndo.size() > 200) {
      mWaterUndo.erase(mWaterUndo.begin());
    }
    EditEnded(EditKind::Water);
    mModified = true;
  }

  moho::IDecalManager* EdDocument::Decals() const
  {
    return mMap != nullptr && mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetDecalManager() : nullptr;
  }

  EdDocument::DecalSnapshot EdDocument::DecalsNow() const
  {
    moho::IDecalManager* const decals = Decals();
    return decals != nullptr ? CaptureDecals(*decals) : DecalSnapshot{};
  }

  void EdDocument::RestoreDecals(
    const DecalSnapshot& decals
  )
  {
    if (moho::IDecalManager* const manager = Decals(); manager != nullptr) {
      const DecalSnapshot before = LiveDecals() != nullptr ? DecalsNow() : DecalSnapshot{};
      faf::editor::RestoreDecals(*manager, decals);
      MirrorDecalsLive(before, decals);
      mModified = true;
    }
  }

  moho::IDecalManager* EdDocument::LiveDecals() const
  {
    return mLiveMap != nullptr && mLiveMap->mTerrainRes != nullptr ? mLiveMap->mTerrainRes->GetDecalManager() : nullptr;
  }

  void EdDocument::MirrorDecalsLive(
    const DecalSnapshot& before,
    const DecalSnapshot& after
  )
  {
    moho::IDecalManager* const live = LiveDecals();
    if (live == nullptr) {
      return;
    }
    const DecalMirror done = MirrorDecals(*live, before, after);
    if (done.removed + done.added + done.missing > 0) {
      gpg::Logf(
        "editor: decals into the play: %d removed, %d added%s (%d there now)",
        done.removed,
        done.added,
        done.missing > 0 ? (", " + std::to_string(done.missing) + " to remove weren't in it").c_str() : "",
        live->GetDecalCount()
      );
    }
  }

  void EdDocument::DecalsEdited(
    DecalSnapshot before
  )
  {
    DecalSnapshot now = DecalsNow();
    MirrorDecalsLive(before, now);
    mDecalUndo.emplace_back(std::move(before), std::move(now));
    // About 120 bytes a decal: a 2,000-decal map is about half a megabyte a step, twice.
    if (mDecalUndo.size() > 100) {
      mDecalUndo.erase(mDecalUndo.begin());
    }
    EditEnded(EditKind::Decals);
    mModified = true;
  }

  void EdDocument::SetPropRecord(
    const std::size_t index,
    const PropRecord& record
  )
  {
    if (mMap == nullptr || mMap->mProps == nullptr || index >= mMap->mProps->mEntries.size()) {
      return;
    }
    mFileRecords.props.resize(mMap->mProps->mEntries.size());
    mFileRecords.props[index] = record;
  }

  void EdDocument::AddProp(
    const moho::CWldPropEntry& entry,
    const PropRecord& record
  )
  {
    if (mMap == nullptr || mMap->mProps == nullptr) {
      return;
    }
    // The records follow the entries index for index; a new prop's record is empty, so it is written from
    // its transform.
    mFileRecords.props.resize(mMap->mProps->mEntries.size());
    mMap->mProps->mEntries.push_back(entry);
    mFileRecords.props.push_back(record);
  }

  void EdDocument::DeletePropAt(
    const std::size_t index
  )
  {
    if (mMap == nullptr || mMap->mProps == nullptr || index >= mMap->mProps->mEntries.size()) {
      return;
    }
    mMap->mProps->mEntries.erase(mMap->mProps->mEntries.begin() + static_cast<std::ptrdiff_t>(index));
    if (index < mFileRecords.props.size()) {
      mFileRecords.props.erase(mFileRecords.props.begin() + static_cast<std::ptrdiff_t>(index));
    }
  }

  void EdDocument::EditEnded(
    const EditKind kind
  )
  {
    mUndoOrder.push_back(kind);
    mRedoOrder.clear();
    mHeights.ClearRedo();
    mMaskHistory.ClearRedo();
    mLayerRedo.clear();
    mPropRedo.clear();
    mSaveRedo.clear();
    mDecalRedo.clear();
    mWaterRedo.clear();
    mLightingRedo.clear();
    mLookRedo.clear();
    mSkyboxRedo.clear();
    mWavesRedo.clear();
    mTerrainTypesRedo.clear();
  }

  bool EdDocument::PopUndo(
    EditKind& kind
  )
  {
    if (mUndoOrder.empty()) {
      return false;
    }
    kind = mUndoOrder.back();
    mUndoOrder.pop_back();
    return true;
  }

  bool EdDocument::PopRedo(
    EditKind& kind
  )
  {
    if (mRedoOrder.empty()) {
      return false;
    }
    kind = mRedoOrder.back();
    mRedoOrder.pop_back();
    return true;
  }

  bool EdDocument::TakeCreated(
    std::filesystem::path& folder,
    std::string& scenarioPath
  )
  {
    if (mCreatedScenario.empty()) {
      return false;
    }
    folder = std::move(mCreatedFolder);
    scenarioPath = std::move(mCreatedScenario);
    mCreatedFolder.clear();
    mCreatedScenario.clear();
    return true;
  }

  void EdDocument::Wait()
  {
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  bool EdDocument::Poll()
  {
    if (mState != State::Loading || mLoad == nullptr || !mThread.joinable()) {
      return false;
    }
    if (!mLoad->done.load(std::memory_order_acquire)) {
      return false;
    }
    mThread.join();
    std::unique_ptr<Load> load = std::move(mLoad);
    if (load->create) {
      // The new folder is on disk; the app mounts it and opens it like any map.
      mState = load->error.empty() ? State::Empty : State::Failed;
      mError = std::move(load->error);
      if (mState == State::Empty) {
        mCreatedFolder = load->createFolder;
        mCreatedScenario = load->createdScenario;
        gpg::Logf("editor: made the new map %s in %.2f s", mCreatedFolder.string().c_str(), load->facts.loadSeconds);
      } else {
        gpg::Warnf("editor: the new map %s was not made: %s", load->createFolder.string().c_str(), mError.c_str());
      }
      return true;
    }
    mFacts = std::move(load->facts);
    mError = std::move(load->error);
    mMap = std::move(load->map);
    mFileRecords = std::move(load->records);
    mHeightsAtLoad = HeightsHash();
    mWaterAtLoad = WaterNow();
    mMasksReadSet = false;
    mSave = std::move(load->save);
    mScript = std::move(load->script);
    mScriptRead = mScript;
    mTables = std::move(load->tables);
    mTablesRead = mTables;
    mOptions = std::move(load->options);
    mOptionsRead = mOptions;
    mScenario = std::move(load->scenario);
    mScenarioRead = mScenario;
    // The markers the save's text gives, against those its Lua gave (every map should agree).
    if (mSave.Loaded() && static_cast<int>(mSave.Markers().size()) != load->facts.markerCount) {
      gpg::Warnf(
        "editor: %s: %zu markers in the save's text, %d in its Lua",
        load->facts.savePath.c_str(),
        mSave.Markers().size(),
        load->facts.markerCount
      );
    }
    mLua = std::move(load->lua);
    // A missing save keeps the map open: the editor still has its terrain, props and decals.
    mState = mMap != nullptr ? State::Open : State::Failed;
    mModified = false;
    if (mState == State::Open) {
      if (
        const moho::CHeightField* const field =
          mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr
      ) {
        mHeights.Reset(field->width, field->height);
      }
      gpg::Logf(
        "editor: opened %s in %.2f s: %d x %d, %zu layers named, %d props, %d decals, %d markers, %zu armies%s%s",
        mPath.c_str(),
        mFacts.loadSeconds,
        mFacts.fieldWidth,
        mFacts.fieldHeight,
        static_cast<std::size_t>(std::count_if(
          mFacts.layers.begin(),
          mFacts.layers.end(),
          [](const std::string& layer) {
        return !layer.empty();
      }
        )),
        mFacts.props,
        mFacts.decals,
        mFacts.markerCount,
        mFacts.armies.size(),
        mError.empty() ? "" : "; ",
        mError.c_str()
      );
      gpg::Logf(
        "editor: water: %s, level %.2f, deep %.2f, abyss %.2f",
        mFacts.water ? "on" : "off",
        static_cast<double>(mFacts.waterElevation),
        static_cast<double>(mFacts.waterDeep),
        static_cast<double>(mFacts.waterAbyss)
      );
      gpg::Logf(
        "editor: symmetry from the heights: mode %d, %d turns (%.1f%% of points match)",
        static_cast<int>(mFacts.symmetry.symmetry),
        mFacts.symmetry.turns,
        static_cast<double>(mFacts.symmetry.matched) * 100.0
      );
      mRecentMaps = WithRecentMap(mRecentMaps, mPath);
      if (!mRecentMapsFile.empty() && !WriteRecentMaps(mRecentMapsFile, mRecentMaps)) {
        gpg::Warnf("editor: the recent maps list %s could not be written", mRecentMapsFile.c_str());
      }
    } else {
      gpg::Warnf("editor: %s did not open: %s", mPath.c_str(), mError.c_str());
    }
    return true;
  }

  namespace
  {
    [[nodiscard]] std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    /** `text` with every `from` replaced by `to`, ignoring case. */
    [[nodiscard]] std::string ReplaceNoCase(
      const std::string& text,
      const std::string& from,
      const std::string& to
    )
    {
      if (from.empty()) {
        return text;
      }
      const std::string lowerText = Lower(text);
      const std::string lowerFrom = Lower(from);
      std::string out;
      std::size_t at = 0;
      for (std::size_t found = lowerText.find(lowerFrom); found != std::string::npos;
           found = lowerText.find(lowerFrom, at)) {
        out.append(text, at, found - at);
        out += to;
        at = found + from.size();
      }
      out.append(text, at, std::string::npos);
      return out;
    }

    /** The folder name without FAF's version suffix (`seton.v0003` -> `seton`). */
    [[nodiscard]] std::string WithoutVersion(
      const std::string& folder
    )
    {
      const std::size_t dot = Lower(folder).rfind(".v");
      if (
        dot != std::string::npos && dot + 2 < folder.size() &&
        std::all_of(folder.begin() + static_cast<std::ptrdiff_t>(dot + 2), folder.end(), [](const unsigned char c) {
        return std::isdigit(c) != 0;
      })
      ) {
        return folder.substr(0, dot);
      }
      return folder;
    }

  } // namespace

  namespace
  {
    std::string BaseOfFolder(
      const std::string& folder
    )
    {
      return WithoutVersion(folder);
    }
  } // namespace

  std::string EdDocument::FolderName() const
  {
    const std::string& path = mFacts.scenarioPath;
    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) {
      return {};
    }
    const std::size_t parent = path.find_last_of('/', slash - 1);
    return parent == std::string::npos ? std::string{} : path.substr(parent + 1, slash - parent - 1);
  }

  std::string EdDocument::NextVersionFolder() const
  {
    const std::string folder = FolderName();
    const std::string base = WithoutVersion(folder);
    int version = 0;
    if (base.size() < folder.size()) {
      version = std::atoi(folder.c_str() + base.size() + 2);
    }
    char suffix[16];
    (void)std::snprintf(suffix, sizeof(suffix), ".v%04d", version + 1);
    return base + suffix;
  }

  bool EdDocument::SaveAsNewFolder(
    const std::string& folder,
    std::string& message
  )
  {
    if (mState != State::Open || mMap == nullptr) {
      message = "No map is open.";
      return false;
    }
    SyncEffectScript();
    if (mMap->mTerrainRes == nullptr || !mMap->mTerrainRes->GetBool()) {
      message = "The map isn't ready yet (its terrain is still being prepared); save again in a moment.";
      return false;
    }
    if (folder.empty() || folder.find_first_of("\\/:*?\"<>|") != std::string::npos) {
      message = "\"" + folder + "\" can't be a folder name.";
      return false;
    }
    if (mVault.empty()) {
      message = "There is no vault folder to save into.";
      return false;
    }
    const std::filesystem::path target = mVault / "maps" / folder;
    std::error_code error;
    if (std::filesystem::exists(target, error)) {
      message = target.string() + " already exists; pick another name.";
      return false;
    }

    const std::string oldFolder = FolderName();
    std::string oldBase = mFacts.scenarioPath.substr(mFacts.scenarioPath.find_last_of('/') + 1);
    oldBase = oldBase.substr(0, oldBase.size() - std::min(oldBase.size(), std::string("_scenario.lua").size()));
    const std::string newBase = WithoutVersion(folder);
    const std::string oldPrefix = "/maps/" + oldFolder + "/";
    const std::string newPrefix = "/maps/" + folder + "/";

    moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
    fa::vector<fa::string> files;
    if (vfs != nullptr) {
      // By file type: the engine's wildcard match never matches a pattern that ends in '*' ("*", "*.*";
      // gpg::STR_MatchWildcard's case-sensitive lane, which the file system uses).
      static constexpr const char* kTypes[] = {
        "*.lua",
        "*.scmap",
        "*.dds",
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.txt",
        "*.md",
        "*.bp",
        "*.scm",
        "*.sca",
        "*.json",
        "*.xwb",
        "*.xsb",
        "*.sfx"
      };
      for (const char* const type : kTypes) {
        fa::vector<fa::string> found;
        vfs->EnumerateFiles(("/maps/" + oldFolder).c_str(), type, true, &found);
        for (fa::string& path : found) {
          files.push_back(std::move(path));
        }
      }
    }
    if (files.empty()) {
      message = "The map's folder " + oldPrefix + " lists no files.";
      return false;
    }
    // Tables made in the editor and not saved yet are copied too.
    if (
      !mFacts.tablesPath.empty() && !mTables.empty() &&
      std::none_of(files.begin(), files.end(), [&](const fa::string& file) {
      return Lower(file.c_str()) == Lower(mFacts.tablesPath);
    })
    ) {
      files.push_back(fa::string(mFacts.tablesPath.c_str()));
    }
    if (
      !mFacts.optionsPath.empty() && !mOptions.empty() &&
      std::none_of(files.begin(), files.end(), [&](const fa::string& file) {
      return Lower(file.c_str()) == Lower(mFacts.optionsPath);
    })
    ) {
      files.push_back(fa::string(mFacts.optionsPath.c_str()));
    }
    std::filesystem::create_directories(target, error);
    if (error) {
      message = "Can't make " + target.string() + ": " + error.message();
      return false;
    }

    std::filesystem::path newMapFile;
    int copied = 0;
    for (const fa::string& file : files) {
      const std::string source = file.c_str();
      if (Lower(source).rfind(Lower(oldPrefix), 0) != 0) {
        continue;
      }
      std::string relative = source.substr(oldPrefix.size());
      // The file's own name takes the new base name where it had the old one.
      const std::size_t lastSlash = relative.find_last_of('/');
      const std::size_t nameAt = lastSlash == std::string::npos ? 0 : lastSlash + 1;
      if (Lower(relative.substr(nameAt)).rfind(Lower(oldBase), 0) == 0) {
        relative = relative.substr(0, nameAt) + newBase + relative.substr(nameAt + oldBase.size());
      }
      const std::filesystem::path destination = target / std::filesystem::path(relative).make_preferred();
      std::filesystem::create_directories(destination.parent_path(), error);
      if (Lower(source) == Lower(mFacts.mapPath)) {
        newMapFile = destination; // written below, edits included
        continue;
      }
      std::string bytes;
      if (Lower(source) == Lower(mFacts.savePath) && mSave.Loaded() && mSave.Changed()) {
        bytes = mSave.Text(); // the edited markers and areas
      } else if (Lower(source) == Lower(mFacts.scriptPath) && mScript != mScriptRead) {
        bytes = mScript; // the edited script (its playable area)
      } else if (Lower(source) == Lower(mFacts.tablesPath) && !mTables.empty()) {
        bytes = mTables; // the adaptive tables as edited (maybe not on disk yet)
      } else if (Lower(source) == Lower(mFacts.optionsPath) && !mOptions.empty()) {
        bytes = mOptions; // the lobby options as edited
      } else if (Lower(source) == Lower(mFacts.scenarioPath) && mScenario != mScenarioRead) {
        bytes = mScenario; // the edited army list (its paths are moved below, as the copy's)
      } else if (!ReadGameFile(source, bytes)) {
        message = "Can't read " + source;
        return false;
      }
      if (Lower(destination.extension().string()) == ".lua") {
        // Paths into the old folder point into the new one, with the new base name.
        bytes = ReplaceNoCase(bytes, oldPrefix + oldBase, newPrefix + newBase);
        bytes = ReplaceNoCase(bytes, oldPrefix, newPrefix);
      }
      // The scenario's map_version is the new folder's version (the vault checks they match).
      if (Lower(source) == Lower(mFacts.scenarioPath) && FolderVersion(folder) > 0) {
        bytes = WithMapVersion(bytes, FolderVersion(folder));
      }
      // A scenario that keeps the map's reclaim gets the props' totals, as a save in place does.
      if (Lower(source) == Lower(mFacts.scenarioPath)) {
        if (const ReclaimTotals reclaim = PropReclaim(); reclaim.props > 0) {
          bytes = WithScenarioReclaim(bytes, reclaim.mass, reclaim.energy);
        }
      }
      std::ofstream out(destination, std::ios::binary);
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
      if (!out) {
        message = "Can't write " + destination.string();
        return false;
      }
      ++copied;
    }
    if (newMapFile.empty()) {
      message = "The map file " + mFacts.mapPath + " isn't in its folder " + oldPrefix;
      return false;
    }
    std::string failure;
    MarkKeptImages();
    if (!WriteMapFile(*mMap, mFileRecords, newMapFile, failure)) {
      message = "Saving " + newMapFile.string() + " failed: " + failure;
      return false;
    }
    mSaveTarget = newMapFile;
    mBackedUp = true; // a new folder has nothing to back up
    mModified = false;
    // From now on the map's files are the new folder's: a later Save writes there, under the new names.
    mSave.MarkSaved();
    mScriptRead = mScript;
    mScenarioRead = mScenario;
    mTablesRead = mTables;
    mOptionsRead = mOptions;
    for (std::string* const path :
         {&mFacts.mapPath,
          &mFacts.savePath,
          &mFacts.scriptPath,
          &mFacts.scenarioPath,
          &mFacts.tablesPath,
          &mFacts.optionsPath}) {
      *path = ReplaceNoCase(ReplaceNoCase(*path, oldPrefix + oldBase, newPrefix + newBase), oldPrefix, newPrefix);
    }
    message = "Saved as " + target.string() + " (" + std::to_string(copied + 1) +
      " files); the game lists it from its next start";
    return true;
  }

  std::filesystem::path EdDocument::MapDiskFile() const
  {
    if (mState != State::Open) {
      return {};
    }
    return mSaveTarget.empty() ? DiskFileOf(mFacts.mapPath) : mSaveTarget;
  }

  PackagePlan EdDocument::PlanPackage() const
  {
    const std::filesystem::path file = MapDiskFile();
    if (file.empty()) {
      PackagePlan plan;
      plan.errors.push_back("this map is inside the game's archives: save it as a new map folder in your vault first");
      return plan;
    }
    const std::filesystem::path folder = file.parent_path();
    std::string scenario;
    for (const std::string& name : FilesUnder(folder)) {
      if (
        name.find('/') == std::string::npos && name.size() > 13 &&
        name.compare(name.size() - 13, 13, "_scenario.lua") == 0
      ) {
        std::ifstream in(folder / name, std::ios::binary);
        scenario.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
      }
    }
    PackagePlan plan = faf::editor::PlanPackage(folder.filename().string(), scenario, FilesUnder(folder));
    if (mModified) {
      plan.warnings.insert(plan.warnings.begin(), "the map has unsaved edits: the package is the folder as saved");
    }
    return plan;
  }

  bool EdDocument::WritePackage(
    const PackagePlan& plan,
    std::filesystem::path& written,
    std::string& message
  ) const
  {
    const std::filesystem::path file = MapDiskFile();
    if (file.empty() || !plan.errors.empty()) {
      message = plan.errors.empty() ? "no folder to package" : plan.errors.front();
      return false;
    }
    const std::filesystem::path folder = file.parent_path();
    std::vector<ZipEntry> entries;
    for (const std::string& name : plan.files) {
      std::ifstream in(folder / name, std::ios::binary);
      if (!in) {
        message = "can't read " + (folder / name).string();
        return false;
      }
      entries.push_back(
        {plan.folder + "/" + name, std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>())}
      );
    }
    const std::string zip = WriteZip(entries);
    std::error_code error;
    const std::filesystem::path packages = mVault / "packages";
    std::filesystem::create_directories(packages, error);
    written = packages / (plan.folder + ".zip");
    std::ofstream out(written, std::ios::binary | std::ios::trunc);
    out.write(zip.data(), static_cast<std::streamsize>(zip.size()));
    if (!out) {
      message = "can't write " + written.string();
      return false;
    }
    message = "packaged " + std::to_string(entries.size()) + " files, " + std::to_string(zip.size()) + " bytes, as " +
      written.string();
    return true;
  }

  bool EdDocument::Save(
    std::string& message
  )
  {
    if (mState != State::Open || mMap == nullptr) {
      message = "No map is open.";
      return false;
    }
    const std::filesystem::path file = MapDiskFile();
    if (file.empty()) {
      message =
        "This map is inside the game's archives and has no file of its own to save over; save it as a new map folder.";
      return false;
    }
    // Only a map in the vault's maps folder is written over; the game's own maps stay as installed.
    std::error_code ignored;
    const std::filesystem::path vaultMaps = std::filesystem::weakly_canonical(mVault / "maps", ignored);
    const std::filesystem::path relative =
      std::filesystem::relative(std::filesystem::weakly_canonical(file, ignored), vaultMaps, ignored);
    if (mVault.empty() || relative.empty() || relative.native().rfind(L"..", 0) == 0) {
      message = "This map isn't in your vault (" + (mVault / "maps").string() + "); save it as a new map folder there.";
      return false;
    }
    // Until the terrain is ready for drawing (Finalize builds its normal map, which the file carries) the
    // writer would write leftover memory there.
    if (mMap->mTerrainRes == nullptr || !mMap->mTerrainRes->GetBool()) {
      message = "The map isn't ready yet (its terrain is still being prepared); save again in a moment.";
      return false;
    }
    // Before the session's first save: the map's files (all five) backed up outside the maps folder.
    if (!mBackedUp && !mBackupRoot.empty() && mBackupKeep > 0) {
      std::filesystem::path made;
      std::string failure;
      if (!BackupMapFolder(file.parent_path(), mBackupRoot, mBackupKeep, made, failure)) {
        message = "The backup failed (" + failure + "); nothing was saved.";
        return false;
      }
      gpg::Logf("editor: the map's files backed up to %s", made.string().c_str());
      mBackedUp = true;
    }
    std::string failure;
    MarkKeptImages();
    if (!WriteMapFile(*mMap, mFileRecords, file, failure)) {
      message = "Saving " + file.string() + " failed: " + failure;
      return false;
    }
    if (!WriteLuaFiles(file.parent_path(), failure)) {
      message = "Saved " + file.string() + ", but " + failure;
      return false;
    }
    mModified = false;
    message = "Saved " + file.string();
    return true;
  }

  void EdDocument::Close()
  {
    Wait();
    mLoad.reset();
    if (mMap != nullptr && mBeforeDrop) {
      mBeforeDrop();
    }
    mMap.reset();
    mLua.reset();
    mHeights.Reset(0, 0);
    mMasks = {};
    mMaskHistory.Reset(0, 0);
    mUndoOrder.clear();
    mRedoOrder.clear();
    mLayerUndo.clear();
    mLayerRedo.clear();
    mConversionUndo.clear();
    mConversionRedo.clear();
    mPropUndo.clear();
    mPropRedo.clear();
    mSave = {};
    mScript.clear();
    mScriptRead.clear();
    mTables.clear();
    mTablesRead.clear();
    mOptions.clear();
    mOptionsRead.clear();
    mScenario.clear();
    mScenarioRead.clear();
    mSaveUndo.clear();
    mSaveRedo.clear();
    mFileRecords = {};
    mSaveTarget.clear();
    mModified = false;
    mBackedUp = false;
    mFacts = {};
    mError.clear();
    mPath.clear();
    mState = State::Empty;
  }
} // namespace faf::editor
