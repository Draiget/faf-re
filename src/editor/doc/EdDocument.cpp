#include "editor/doc/EdDocument.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <chrono>
#include <ctime>
#include <cstring>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <exception>
#include <system_error>

#include "editor/doc/EdMapFile.h"

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
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
    [[nodiscard]] std::string StringOf(const LuaPlus::LuaObject& object)
    {
      if (!object.IsString()) {
        return {};
      }
      const char* const text = object.GetString();
      return text != nullptr ? text : "";
    }

    /** The text without a leading localization tag (`<LOC key>`), which the game swaps for a translation. */
    [[nodiscard]] std::string WithoutLocTag(std::string text)
    {
      if (text.rfind("<LOC", 0) == 0) {
        if (const std::size_t end = text.find('>'); end != std::string::npos) {
          text.erase(0, end + 1);
        }
      }
      return text;
    }

    [[nodiscard]] int IntOf(const LuaPlus::LuaObject& object)
    {
      return object.IsNumber() ? static_cast<int>(object.GetNumber()) : 0;
    }

    /** Runs `path` with a fresh table as its globals (after the game's data helpers) and returns the table. */
    [[nodiscard]] LuaPlus::LuaObject RunInTable(LuaPlus::LuaState* const state, const std::string& path)
    {
      LuaPlus::LuaObject env(state);
      env.AssignNewTable(state, 0, 0);
      (void)moho::SCR_LuaDoScript(state, "/lua/dataInit.lua", &env);
      if (!moho::SCR_LuaDoScript(state, path.c_str(), &env)) {
        return {};
      }
      return env;
    }

    void ReadScenario(const LuaPlus::LuaObject& scenario, MapFacts& facts)
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

    void ReadSave(const LuaPlus::LuaObject& save, MapFacts& facts)
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

    void ReadMap(moho::CWldMap& map, MapFacts& facts)
    {
      moho::IWldTerrainRes* const terrain = map.mTerrainRes;
      if (terrain == nullptr) {
        return;
      }
      if (const moho::CHeightField* const field = terrain->GetHeightField(); field != nullptr) {
        facts.fieldWidth = field->width;
        facts.fieldHeight = field->height;
        facts.symmetry = DetectSymmetry(field->data, field->width, field->height);
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
        &strata.mLowerAlbedoTexture,    &strata.mStratum0AlbedoTexture, &strata.mStratum1AlbedoTexture,
        &strata.mStratum2AlbedoTexture, &strata.mStratum3AlbedoTexture, &strata.mStratum4AlbedoTexture,
        &strata.mStratum5AlbedoTexture, &strata.mStratum6AlbedoTexture, &strata.mStratum7AlbedoTexture,
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
          gpg::Logf("editor: decals: %s; the first: %s, scale %.1f %.1f %.1f, turn %.2f, cutoff %.0f, near %.0f", counts.c_str(),
                    first.names[0].c_str(), first.scale[0], first.scale[1], first.scale[2], first.orientation[1], first.cutoff,
                    first.nearCutoff);
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

  void EdDocument::Run(Load& load)
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

    bool WriteText(const std::filesystem::path& file, const std::string& text, std::string& error)
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

  void EdDocument::RunCreate(Load& load)
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
      std::fill(field->data, field->data + static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height), word);
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
      if (!WriteMapFile(*map, records, load.createFolder / (base + ".scmap"), error) ||
          !WriteText(load.createFolder / (base + "_scenario.lua"), NewMapScenarioText(settings, base), error) ||
          !WriteText(load.createFolder / (base + "_save.lua"), NewMapSaveText(settings), error) ||
          !WriteText(load.createFolder / (base + "_script.lua"), NewMapScriptText(), error)) {
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

  void EdDocument::RunSteps(Load& load)
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

      // The save's and script's text, for the markers, areas and playable area the editor changes.
      if (std::string text; !facts.savePath.empty() && ReadGameFile(facts.savePath, text)) {
        std::string error;
        if (!load.save.Parse(std::move(text), error)) {
          gpg::Warnf("editor: %s: %s", facts.savePath.c_str(), error.c_str());
        }
      }
      if (!facts.scriptPath.empty()) {
        (void)ReadGameFile(facts.scriptPath, load.script);
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

  bool EdDocument::Open(const std::string& scenarioPath)
  {
    if (mState == State::Loading) {
      return false;
    }
    Close();
    mPath = scenarioPath;
    mState = State::Loading;
    mLoad = std::make_unique<Load>();
    mLoad->scenarioPath = scenarioPath;
    mThread = std::thread([load = mLoad.get()] { Run(*load); });
    return true;
  }

  bool EdDocument::CreateNew(const NewMapSettings& settings, std::string& message)
  {
    if (mState == State::Loading) {
      message = "A map is still opening.";
      return false;
    }
    if (settings.folder.empty() || settings.folder.find_first_of("\\/:*?\"<>|") != std::string::npos || settings.folder[0] == '.') {
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
    mThread = std::thread([load = mLoad.get()] { Run(*load); });
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

  void EdDocument::SetPlayableArea(const std::optional<PlayableRect>& area)
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

  void EdDocument::SetExtraArmies(const std::vector<std::string>& armies)
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

  void EdDocument::SetTeams(const std::vector<ScenarioTeam>& teams)
  {
    mScenario = WithScenarioTeams(mScenario, teams);
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::AddArmy(const std::string& name)
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

  void EdDocument::RemoveArmy(const std::string& name)
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
      entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const SaveEntry& entry) { return entry.name == name; }), entries.end());
    }
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::RenameArmy(const std::string& from, const std::string& to)
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
    return {mSave.Markers(), mSave.Areas(), mScript, mSave.Armies(), mScenario};
  }

  void EdDocument::RestoreSaveData(const SaveSnapshot& snapshot)
  {
    mSave.Markers() = snapshot.markers;
    mSave.Areas() = snapshot.areas;
    mScript = snapshot.script;
    mSave.Armies() = snapshot.armies;
    mScenario = snapshot.scenario;
    mFacts.armies = Armies();
    mModified = true;
  }

  void EdDocument::SaveDataEdited(SaveSnapshot before)
  {
    mSaveUndo.emplace_back(std::move(before), SaveDataNow());
    EditEnded(EditKind::SaveData);
    mModified = true;
  }

  bool EdDocument::WriteLuaFiles(const std::filesystem::path& folder, std::string& error)
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

  void EdDocument::RestoreProps(const PropSnapshot& props)
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

  void EdDocument::PropsEdited(PropSnapshot before)
  {
    mPropUndo.emplace_back(std::move(before), PropsNow());
    // A long session keeps the newest 200 prop edits (a 5000-prop map is about 0.3 MB a step, twice).
    if (mPropUndo.size() > 200) {
      mPropUndo.erase(mPropUndo.begin());
    }
    EditEnded(EditKind::Props);
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
    if (const moho::CWaterShaderProperties* const shader = mMap->mTerrainRes->GetWaterShaderProperties(); shader != nullptr) {
      water.shader = shader->mNumericState;
      water.textures[0] = shader->mWaterCubemap.c_str();
      water.textures[1] = shader->mWaterRamp.c_str();
      for (int i = 0; i < 4; ++i) {
        water.textures[2 + i] = shader->mShaderNames[i].c_str();
      }
    }
    return water;
  }

  void EdDocument::ApplyWater(const WaterState& water)
  {
    if (mMap == nullptr || mMap->mTerrainRes == nullptr || mMap->mTerrainRes->mMap == nullptr) {
      return;
    }
    moho::IWldTerrainRes* const terrain = mMap->mTerrainRes;
    const WaterState now = WaterNow();
    terrain->WaterEnabled(water.enabled);
    terrain->SetWaterElevation(water.elevation);
    terrain->SetWaterElevationDeep(water.deep);
    terrain->SetWaterElevationAbyss(water.abyss);
    if (moho::CWaterShaderProperties* const shader = terrain->GetWaterShaderProperties(); shader != nullptr) {
      shader->mNumericState = water.shader;
    }
    // The water map (depth below the sea, for the shore and the water's colour) follows the levels.
    if (now.enabled != water.enabled || now.elevation != water.elevation || now.deep != water.deep || now.abyss != water.abyss) {
      terrain->UpdateWaterMap();
    }
    mFacts.water = water.enabled;
    mFacts.waterElevation = water.elevation;
    mFacts.waterDeep = water.deep;
    mFacts.waterAbyss = water.abyss;
    mModified = true;
  }

  void EdDocument::WaterEdited(WaterState before)
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

  void EdDocument::RestoreDecals(const DecalSnapshot& decals)
  {
    if (moho::IDecalManager* const manager = Decals(); manager != nullptr) {
      faf::editor::RestoreDecals(*manager, decals);
      mModified = true;
    }
  }

  void EdDocument::DecalsEdited(DecalSnapshot before)
  {
    mDecalUndo.emplace_back(std::move(before), DecalsNow());
    // About 120 bytes a decal: a 2,000-decal map is about half a megabyte a step, twice.
    if (mDecalUndo.size() > 100) {
      mDecalUndo.erase(mDecalUndo.begin());
    }
    EditEnded(EditKind::Decals);
    mModified = true;
  }

  void EdDocument::SetPropRecord(const std::size_t index, const PropRecord& record)
  {
    if (mMap == nullptr || mMap->mProps == nullptr || index >= mMap->mProps->mEntries.size()) {
      return;
    }
    mFileRecords.props.resize(mMap->mProps->mEntries.size());
    mFileRecords.props[index] = record;
  }

  void EdDocument::AddProp(const moho::CWldPropEntry& entry, const PropRecord& record)
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

  void EdDocument::DeletePropAt(const std::size_t index)
  {
    if (mMap == nullptr || mMap->mProps == nullptr || index >= mMap->mProps->mEntries.size()) {
      return;
    }
    mMap->mProps->mEntries.erase(mMap->mProps->mEntries.begin() + static_cast<std::ptrdiff_t>(index));
    if (index < mFileRecords.props.size()) {
      mFileRecords.props.erase(mFileRecords.props.begin() + static_cast<std::ptrdiff_t>(index));
    }
  }

  void EdDocument::EditEnded(const EditKind kind)
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
  }

  bool EdDocument::PopUndo(EditKind& kind)
  {
    if (mUndoOrder.empty()) {
      return false;
    }
    kind = mUndoOrder.back();
    mUndoOrder.pop_back();
    return true;
  }

  bool EdDocument::PopRedo(EditKind& kind)
  {
    if (mRedoOrder.empty()) {
      return false;
    }
    kind = mRedoOrder.back();
    mRedoOrder.pop_back();
    return true;
  }

  bool EdDocument::TakeCreated(std::filesystem::path& folder, std::string& scenarioPath)
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
    mSave = std::move(load->save);
    mScript = std::move(load->script);
    mScriptRead = mScript;
    mScenario = std::move(load->scenario);
    mScenarioRead = mScenario;
    // The markers the save's text gives, against those its Lua gave (every map should agree).
    if (mSave.Loaded() && static_cast<int>(mSave.Markers().size()) != load->facts.markerCount) {
      gpg::Warnf("editor: %s: %zu markers in the save's text, %d in its Lua", load->facts.savePath.c_str(), mSave.Markers().size(),
                 load->facts.markerCount);
    }
    mLua = std::move(load->lua);
    // A missing save keeps the map open: the editor still has its terrain, props and decals.
    mState = mMap != nullptr ? State::Open : State::Failed;
    mModified = false;
    if (mState == State::Open) {
      if (const moho::CHeightField* const field = mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr) {
        mHeights.Reset(field->width, field->height);
      }
      gpg::Logf("editor: opened %s in %.2f s: %d x %d, %zu layers named, %d props, %d decals, %d markers, %zu armies%s%s",
                mPath.c_str(), mFacts.loadSeconds, mFacts.fieldWidth, mFacts.fieldHeight,
                static_cast<std::size_t>(std::count_if(mFacts.layers.begin(), mFacts.layers.end(),
                                                       [](const std::string& layer) { return !layer.empty(); })),
                mFacts.props, mFacts.decals, mFacts.markerCount, mFacts.armies.size(), mError.empty() ? "" : "; ",
                mError.c_str());
      gpg::Logf("editor: water: %s, level %.2f, deep %.2f, abyss %.2f", mFacts.water ? "on" : "off",
                static_cast<double>(mFacts.waterElevation), static_cast<double>(mFacts.waterDeep), static_cast<double>(mFacts.waterAbyss));
      gpg::Logf("editor: symmetry from the heights: mode %d, %d turns (%.1f%% of points match)", static_cast<int>(mFacts.symmetry.symmetry),
                mFacts.symmetry.turns, static_cast<double>(mFacts.symmetry.matched) * 100.0);
    } else {
      gpg::Warnf("editor: %s did not open: %s", mPath.c_str(), mError.c_str());
    }
    return true;
  }


  namespace
  {
    [[nodiscard]] std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    }

    /** `text` with every `from` replaced by `to`, ignoring case. */
    [[nodiscard]] std::string ReplaceNoCase(const std::string& text, const std::string& from, const std::string& to)
    {
      if (from.empty()) {
        return text;
      }
      const std::string lowerText = Lower(text);
      const std::string lowerFrom = Lower(from);
      std::string out;
      std::size_t at = 0;
      for (std::size_t found = lowerText.find(lowerFrom); found != std::string::npos; found = lowerText.find(lowerFrom, at)) {
        out.append(text, at, found - at);
        out += to;
        at = found + from.size();
      }
      out.append(text, at, std::string::npos);
      return out;
    }

    /** The folder name without FAF's version suffix (`seton.v0003` -> `seton`). */
    [[nodiscard]] std::string WithoutVersion(const std::string& folder)
    {
      const std::size_t dot = Lower(folder).rfind(".v");
      if (dot != std::string::npos && dot + 2 < folder.size() &&
          std::all_of(folder.begin() + static_cast<std::ptrdiff_t>(dot + 2), folder.end(), [](const unsigned char c) { return std::isdigit(c) != 0; })) {
        return folder.substr(0, dot);
      }
      return folder;
    }

  } // namespace

  namespace
  {
    std::string BaseOfFolder(const std::string& folder)
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

  bool EdDocument::SaveAsNewFolder(const std::string& folder, std::string& message)
  {
    if (mState != State::Open || mMap == nullptr) {
      message = "No map is open.";
      return false;
    }
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
      static constexpr const char* kTypes[] = {"*.lua", "*.scmap", "*.dds", "*.png", "*.jpg", "*.jpeg", "*.txt", "*.md",
                                               "*.bp", "*.scm", "*.sca", "*.json", "*.xwb", "*.xsb", "*.sfx"};
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
    for (std::string* const path : {&mFacts.mapPath, &mFacts.savePath, &mFacts.scriptPath, &mFacts.scenarioPath}) {
      *path = ReplaceNoCase(ReplaceNoCase(*path, oldPrefix + oldBase, newPrefix + newBase), oldPrefix, newPrefix);
    }
    message = "Saved as " + target.string() + " (" + std::to_string(copied + 1) + " files); the game lists it from its next start";
    return true;
  }

  std::filesystem::path EdDocument::MapDiskFile() const
  {
    if (mState != State::Open) {
      return {};
    }
    return mSaveTarget.empty() ? DiskFileOf(mFacts.mapPath) : mSaveTarget;
  }

  bool EdDocument::Save(std::string& message)
  {
    if (mState != State::Open || mMap == nullptr) {
      message = "No map is open.";
      return false;
    }
    const std::filesystem::path file = MapDiskFile();
    if (file.empty()) {
      message = "This map is inside the game's archives and has no file of its own to save over; save it as a new map folder.";
      return false;
    }
    // Only a map in the vault's maps folder is written over; the game's own maps stay as installed.
    std::error_code ignored;
    const std::filesystem::path vaultMaps = std::filesystem::weakly_canonical(mVault / "maps", ignored);
    const std::filesystem::path relative = std::filesystem::relative(std::filesystem::weakly_canonical(file, ignored), vaultMaps, ignored);
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
    std::error_code error;
    if (!mBackedUp) {
      char stamp[32];
      const std::time_t now = std::time(nullptr);
      std::tm local{};
      (void)localtime_s(&local, &now);
      (void)std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &local);
      const std::filesystem::path backup = file.parent_path() / ".editor_backup" / stamp;
      std::filesystem::create_directories(backup, error);
      if (!error) {
        std::filesystem::copy_file(file, backup / file.filename(), std::filesystem::copy_options::overwrite_existing, error);
      }
      if (error) {
        message = "The backup of " + file.string() + " failed (" + error.message() + "); nothing was saved.";
        return false;
      }
      mBackedUp = true;
    }
    std::string failure;
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
    mPropUndo.clear();
    mPropRedo.clear();
    mSave = {};
    mScript.clear();
    mScriptRead.clear();
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
