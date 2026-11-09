#include "editor/EdPlay.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>

#include "gpg/core/utils/Logging.h"
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
    for (const fa::string& path : found) {
      mMaps.emplace_back(path.c_str());
    }
    const auto lower = [](std::string text) {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    };
    std::sort(mMaps.begin(), mMaps.end(), [&](const std::string& a, const std::string& b) {
      return lower(MapDisplayName(a)) < lower(MapDisplayName(b));
    });
    mSelected = 0;
    gpg::Logf("editor: %zu maps in /maps", mMaps.size());
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
    std::string wanted = args[0].c_str();
    std::transform(wanted.begin(), wanted.end(), wanted.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    int found = -1;
    for (int i = 0; i < static_cast<int>(mMaps.size()); ++i) {
      std::string name = MapDisplayName(mMaps[static_cast<std::size_t>(i)]);
      std::transform(name.begin(), name.end(), name.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (name == wanted) {
        found = i;
        break;
      }
    }
    if (found < 0) {
      gpg::Warnf("editor: /play %s: no such map in /maps", args[0].c_str());
      return;
    }
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
      if (mAutoCyclesLeft > 0) {
        --mAutoCyclesLeft;
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
        mStopRequested = true;
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
