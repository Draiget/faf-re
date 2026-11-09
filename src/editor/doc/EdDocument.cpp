#include "editor/doc/EdDocument.h"

#include <algorithm>
#include <atomic>
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
      // Each prop as the file stores it (the game keeps only a quaternion of its rotation).
      load.records.preview = ReadPreviewRecord(facts.mapPath);
      load.records.props = ReadPropRecords(facts.mapPath, *load.map);

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
    mFileRecords = std::move(load->records);
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
      if (!ReadGameFile(source, bytes)) {
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
