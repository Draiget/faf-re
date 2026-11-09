#include "editor/doc/EdDocument.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"
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
      }
      facts.water = terrain->IsWaterEnabled();
      facts.waterElevation = terrain->GetWaterElevation();
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
    RunSteps(load);
    load.facts.loadSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    load.done.store(true, std::memory_order_release);
  }

  void EdDocument::RunSteps(Load& load)
  {
    try {
      // A state of its own with the engine's bindings, as a session's (CWldSessionLoaderImpl.cpp).
      load.lua = std::make_unique<LuaPlus::LuaState>(LuaPlus::LuaState::LIB_BASE);
      LuaPlus::LuaState* const state = load.lua.get();
      for (const char* const set : {"Core", "User"}) {
        if (moho::CScrLuaInitFormSet* const forms = moho::SCR_FindLuaInitFormSet(set); forms != nullptr) {
          forms->RunInits(state);
        }
      }

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
    mFacts = std::move(load->facts);
    mError = std::move(load->error);
    mMap = std::move(load->map);
    mLua = std::move(load->lua);
    // A missing save keeps the map open: the editor still has its terrain, props and decals.
    mState = mMap != nullptr ? State::Open : State::Failed;
    if (mState == State::Open) {
      gpg::Logf("editor: opened %s in %.2f s: %d x %d, %zu layers named, %d props, %d decals, %d markers, %zu armies%s%s",
                mPath.c_str(), mFacts.loadSeconds, mFacts.fieldWidth, mFacts.fieldHeight,
                static_cast<std::size_t>(std::count_if(mFacts.layers.begin(), mFacts.layers.end(),
                                                       [](const std::string& layer) { return !layer.empty(); })),
                mFacts.props, mFacts.decals, mFacts.markerCount, mFacts.armies.size(), mError.empty() ? "" : "; ",
                mError.c_str());
    } else {
      gpg::Warnf("editor: %s did not open: %s", mPath.c_str(), mError.c_str());
    }
    return true;
  }

  void EdDocument::Close()
  {
    Wait();
    mLoad.reset();
    mMap.reset();
    mLua.reset();
    mFacts = {};
    mError.clear();
    mPath.clear();
    mState = State::Empty;
  }
} // namespace faf::editor
