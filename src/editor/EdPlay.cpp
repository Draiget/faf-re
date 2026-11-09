#include "editor/EdPlay.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CWldSession.h"

namespace faf::editor
{
  std::string MapDisplayName(const std::string& scenarioPath)
  {
    std::string name = scenarioPath;
    const std::size_t slash = name.find_last_of('/');
    if (slash != std::string::npos) {
      name.erase(0, slash + 1);
    }
    constexpr char kSuffix[] = "_scenario.lua";
    constexpr std::size_t kSuffixLength = sizeof(kSuffix) - 1U;
    if (name.size() > kSuffixLength) {
      name.erase(name.size() - kSuffixLength);
    }
    return name;
  }

  void EdPlay::FindMaps()
  {
    mMaps.clear();
    moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
    if (vfs == nullptr) {
      return;
    }
    fa::vector<fa::string> found;
    vfs->EnumerateFiles("/maps", "*_scenario.lua", true, &found);

    // Each scenario's title, read the way FAF's map list reads it.
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    LuaPlus::LuaObject loadScenario;
    if (state != nullptr) {
      try {
        loadScenario = moho::SCR_Import(state, "/lua/ui/maputil.lua")["LoadScenario"];
      } catch (const std::exception& error) {
        gpg::Warnf("editor: /lua/ui/maputil.lua: %s", error.what());
      }
    }
    struct Entry
    {
      std::string path;
      std::string title;
    };
    std::vector<Entry> entries;
    int untitled = 0;
    for (const fa::string& path : found) {
      Entry entry{path.c_str(), {}};
      if (!loadScenario.IsNil()) {
        try {
          LuaPlus::LuaFunction<LuaPlus::LuaObject> load(loadScenario);
          const LuaPlus::LuaObject scenario = load(path.c_str());
          if (scenario.IsTable()) {
            const LuaPlus::LuaObject name = scenario["name"];
            if (name.IsString()) {
              entry.title = name.GetString();
            }
          }
        } catch (const std::exception&) {
        }
      }
      if (entry.title.empty()) {
        entry.title = MapDisplayName(entry.path);
        ++untitled;
      }
      entries.push_back(std::move(entry));
    }
    const auto lower = [](std::string text) {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    };
    std::sort(entries.begin(), entries.end(), [&](const Entry& a, const Entry& b) {
      const std::string titleA = lower(a.title);
      const std::string titleB = lower(b.title);
      return titleA != titleB ? titleA < titleB : lower(MapDisplayName(a.path)) < lower(MapDisplayName(b.path));
    });
    mTitles.clear();
    for (Entry& entry : entries) {
      mMaps.push_back(std::move(entry.path));
      mTitles.push_back(std::move(entry.title));
    }
    mSelected = 0;
    gpg::Logf("editor: %zu maps in /maps (%d without a title in their scenario)", mMaps.size(), untitled);
  }

  bool EdPlay::CanPlay() const
  {
    return moho::WLD_GetFrameAction() == moho::EWldFrameAction::Inactive && !mMaps.empty();
  }

  bool EdPlay::Active() const
  {
    return moho::WLD_GetFrameAction() != moho::EWldFrameAction::Inactive;
  }

  const char* EdPlay::StateText() const
  {
    switch (moho::WLD_GetFrameAction()) {
    case moho::EWldFrameAction::Inactive:
      return "Editing";
    case moho::EWldFrameAction::Preload:
    case moho::EWldFrameAction::Loading:
    case moho::EWldFrameAction::Initialize:
    case moho::EWldFrameAction::PostInitialize:
    case moho::EWldFrameAction::Waiting:
    case moho::EWldFrameAction::CreateSession:
      return "Loading";
    case moho::EWldFrameAction::Playing:
      return "Playing";
    case moho::EWldFrameAction::Exit:
      return "Ending";
    default:
      return "";
    }
  }

  void EdPlay::ReadCommandLine()
  {
    fa::vector<fa::string> args;
    if (!moho::CFG_GetArgOption("/play", 1, &args) || args.empty()) {
      return;
    }
    const auto lower = [](std::string text) {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    };
    // One map, or several separated by commas: the runs take them in turn.
    const std::string list = args[0].c_str();
    std::size_t at = 0U;
    while (at <= list.size()) {
      const std::size_t comma = list.find(',', at);
      const std::string wanted = lower(list.substr(at, comma == std::string::npos ? std::string::npos : comma - at));
      at = comma == std::string::npos ? list.size() + 1U : comma + 1U;
      if (wanted.empty()) {
        continue;
      }
      int found = -1;
      for (int i = 0; i < static_cast<int>(mMaps.size()); ++i) {
        if (lower(MapDisplayName(mMaps[static_cast<std::size_t>(i)])) == wanted) {
          found = i;
          break;
        }
      }
      if (found < 0) {
        gpg::Warnf("editor: /play %s: no such map in /maps", wanted.c_str());
        continue;
      }
      mAutoMaps.push_back(found);
    }
    if (mAutoMaps.empty()) {
      return;
    }
    const int found = mAutoMaps.front();
    mSelected = found;
    mAutoRun = true;
    mAutoCyclesLeft = 1;
    if (moho::CFG_GetArgOption("/playcycles", 1, &args) && !args.empty()) {
      mAutoCyclesLeft = std::max(1, std::atoi(args[0].c_str()));
    }
    if (moho::CFG_GetArgOption("/playseconds", 1, &args) && !args.empty()) {
      mAutoSeconds = static_cast<float>(std::atof(args[0].c_str()));
    }
    mAutoQuit = moho::CFG_GetArgOption("/playquit", 0, nullptr);
    mAutoExitApp = moho::CFG_GetArgOption("/playexitapp", 0, nullptr);
    gpg::Logf("editor: command-line play of %s, %d cycle(s), %.1f s each", MapDisplayName(mMaps[static_cast<std::size_t>(found)]).c_str(),
              mAutoCyclesLeft, static_cast<double>(mAutoSeconds));
  }

  void EdPlay::DriveCommandLineRuns()
  {
    if (!mAutoRun) {
      return;
    }
    const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    const moho::EWldFrameAction action = moho::WLD_GetFrameAction();
    if (action == moho::EWldFrameAction::Inactive) {
      mPlayingSince = -1.0;
      mExitAppSent = false;
      if (mAutoCyclesLeft > 0) {
        --mAutoCyclesLeft;
        mSelected = mAutoMaps[mAutoRunIndex++ % mAutoMaps.size()];
        mPlayRequested = true;
      } else {
        mAutoRun = false;
        mQuitRequested = mAutoQuit;
        gpg::Logf("editor: command-line play done");
      }
      return;
    }
    if (action == moho::EWldFrameAction::Playing && mAutoSeconds > 0.0f) {
      if (mPlayingSince < 0.0) {
        mPlayingSince = now;
        gpg::Logf("editor: playing");
      } else if (now - mPlayingSince >= static_cast<double>(mAutoSeconds)) {
        if (mAutoExitApp) {
          // As the game's own "Exit to Windows" does; the editor turns it into a Stop (EdApp.cpp).
          if (!mExitAppSent) {
            mExitAppSent = true;
            gpg::Logf("editor: the game asks to quit (ExitApplication)");
            moho::CON_Execute("UI_Lua ExitApplication()");
          }
        } else {
          mStopRequested = true;
        }
      }
    }
  }

  void EdPlay::LogPhases()
  {
    const moho::EWldFrameAction action = moho::WLD_GetFrameAction();
    if (action == mLastAction) {
      return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (mLastAction != moho::EWldFrameAction::Inactive) {
      const double ms = std::chrono::duration<double, std::milli>(now - mPhaseStart).count();
      gpg::Logf("editor: phase %d took %.0f ms (session start to now %.0f ms)", static_cast<int>(mLastAction), ms,
                std::chrono::duration<double, std::milli>(now - mSessionStart).count());
    } else {
      mSessionStart = now;
    }
    mLastAction = action;
    mPhaseStart = now;
  }

  void EdPlay::BeforeGameFrame()
  {
    LogPhases();
    DriveCommandLineRuns();
    const moho::EWldFrameAction action = moho::WLD_GetFrameAction();
    if ((mStopRequested && action != moho::EWldFrameAction::Inactive) || action == moho::EWldFrameAction::Exit) {
      gpg::Logf("editor: play ended (%s)", action == moho::EWldFrameAction::Exit ? "the session's exit" : "Stop");
      moho::WLD_Teardown();
    }
    mStopRequested = false;

    if (mPlayRequested) {
      mPlayRequested = false;
      if (CanPlay() && mSelected >= 0 && mSelected < static_cast<int>(mMaps.size())) {
        const std::string& scenario = mMaps[static_cast<std::size_t>(mSelected)];
        gpg::Logf("editor: play %s", scenario.c_str());
        if (!moho::StartCommandLineSession(scenario.c_str(), false)) {
          gpg::Warnf("editor: the session for %s did not start", scenario.c_str());
        }
      }
    }
  }
} // namespace faf::editor
