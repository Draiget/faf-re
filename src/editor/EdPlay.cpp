#include "editor/EdPlay.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <stdexcept>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"

namespace faf::editor
{
  namespace
  {
    /**
     * The editor's session launcher, run once in the UI's Lua state. It follows FAF's quick start
     * (SinglePlayerLaunch.lua: SetupCommandLineSkirmish and its default options) with three changes: the
     * AI armies are optional (aiKey ''), the fog and faction come from the Play setup, and no replay is
     * written. Campaign scenarios keep FAF's own path, which sets up their objectives.
     */
    constexpr const char kLauncher[] = R"lua(
function EditorStartPlay(mapPath, aiKey, faction, fog)
    local SPL = import('/lua/singleplayerlaunch.lua')
    local Prefs = import('/lua/user/prefs.lua')
    local scenario = import('/lua/ui/maputil.lua').LoadScenario(mapPath)
    if not scenario then
        error('Unable to load map ' .. mapPath)
    end
    if scenario.type == 'campaign' then
        SPL.StartCommandLineSession(mapPath, false)
        return
    end
    SPL.VerifyScenarioConfiguration(scenario)
    scenario.Options = {
        FogOfWar = fog, NoRushOption = 'Off', PrebuiltUnits = 'Off', Difficulty = 2,
        DoNotShareUnitCap = true, Timeouts = -1, GameSpeed = 'normal', UnitCap = '500',
        Victory = 'sandbox', CheatsEnabled = 'true', CivilianAlliance = 'enemy',
        TeamShareOverflow = 'enabled', Share = 'ShareUntilDeath',
    }
    if faction < 1 then
        faction = SPL.GetRandomFaction()
    end
    rawset(_G, '__EditorLoadingTitle', scenario.name or mapPath)

    local info = {}
    info.playerName = Prefs.GetFromCurrentProfile('Name') or 'Player'
    info.createReplay = false
    info.scenarioInfo = scenario
    info.teamInfo = {}
    info.scenarioMods = import('/lua/mods.lua').GetCampaignMods(scenario)

    local GetDefaultPlayerOptions = import('/lua/ui/lobby/lobbycomm.lua').GetDefaultPlayerOptions
    local armies = scenario.Configurations.standard.teams[1].armies
    local numColors = table.getn(import('/lua/gamecolors.lua').GameColors.PlayerColors)

    local player = GetDefaultPlayerOptions(info.playerName)
    player.PlayerName = info.playerName
    player.Faction = faction
    player.Human = true
    player.ArmyName = armies[1]
    player.PlayerColor = math.mod(1, numColors)
    player.ArmyColor = math.mod(1, numColors)
    info.teamInfo[1] = player

    if aiKey ~= '' then
        for index = 2, table.getn(armies) do
            local ai = GetDefaultPlayerOptions(info.playerName)
            ai.AIPersonality = aiKey
            ai.Faction = SPL.GetRandomFaction()
            ai.PlayerName = SPL.GetRandomName(ai.Faction, aiKey)
            ai.Human = false
            ai.ArmyName = armies[index]
            ai.PlayerColor = math.mod(index, numColors)
            ai.ArmyColor = math.mod(index, numColors)
            info.teamInfo[index] = ai
        end
    end

    local extras = import('/lua/ui/maputil.lua').GetExtraArmies(scenario)
    if extras then
        for _, armyName in extras do
            local index = table.getn(info.teamInfo) + 1
            info.teamInfo[index] = GetDefaultPlayerOptions('civilian')
            info.teamInfo[index].PlayerName = 'civilian'
            info.teamInfo[index].Civilian = true
            info.teamInfo[index].ArmyName = armyName
            info.teamInfo[index].Human = false
        end
    end
    for _, armyName in { 'ARMY_17', 'NEUTRAL_CIVILIAN' } do
        local index = table.getn(info.teamInfo) + 1
        info.teamInfo[index] = GetDefaultPlayerOptions('Civilian')
        info.teamInfo[index].Civilian = true
        info.teamInfo[index].ArmyName = armyName
        info.teamInfo[index].Human = false
    end

    Prefs.SetToCurrentProfile('LoadingFaction', faction)
    LaunchSinglePlayerSession(info)
end
)lua";

    /**
     * The editor's loading view, installed in each state the game UI starts in (moho::gUIBeforeStartGameUI):
     * FAF's gamemain.lua makes a provider whose StartLoadingDialog plays a faction movie with "IN TRANSIT"
     * and loading tips, and whose StopLoadingDialog covers the view with an "IN TRANSIT" picture that
     * fades over about 3.5 s before the panels slide in. The provider FAF creates is caught as it registers
     * (InternalCreateWldUIProvider) and gets a line of text while loading instead, and the panels at once.
     * The tips thread is what failed on the next play ("Game object has been destroyed"): it outlives a
     * play shorter than its 7 s wait in the editor's UI state, which the game would have rebuilt.
     */
    constexpr const char kLoadingView[] = R"lua(
if not rawget(_G, '__EditorLoadingView') then
    rawset(_G, '__EditorLoadingView', true)
    local gm = import('/lua/ui/game/gamemain.lua')
    local createProvider = gm.CreateWldUIProvider
    gm.CreateWldUIProvider = function()
        local created = false
        local internal = rawget(_G, 'InternalCreateWldUIProvider')
        rawset(_G, 'InternalCreateWldUIProvider', function(object)
            created = object
            return internal(object)
        end)
        local ok, err = pcall(createProvider)
        rawset(_G, 'InternalCreateWldUIProvider', internal)
        if not ok then
            error(err)
        end
        if not created then
            return
        end
        local loadingText = false
        created.StartLoadingDialog = function(self)
            gm.supressExitDialog = true
            local UIUtil = import('/lua/ui/uiutil.lua')
            local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
            local title = rawget(_G, '__EditorLoadingTitle') or 'the map'
            loadingText = UIUtil.CreateText(GetFrame(0), 'Loading ' .. title .. ' ...', 20, UIUtil.bodyFont)
            loadingText:SetDropShadow(true)
            LayoutHelpers.AtCenterIn(loadingText, GetFrame(0))
        end
        created.UpdateLoadingDialog = function(self, elapsedTime)
        end
        created.StopLoadingDialog = function(self)
            if loadingText then
                loadingText:Destroy()
                loadingText = false
            end
            GetCursor():Show()
            if not import('/lua/ui/campaign/campaignmanager.lua').campaignMode then
                ForkThread(function()
                    import('/lua/ui/game/tabs.lua').InitialAnimation()
                    if not SessionIsReplay() then
                        import('/lua/ui/game/economy.lua').InitialAnimation()
                    end
                    import('/lua/ui/game/score.lua').InitialAnimation()
                    import('/lua/ui/game/multifunction.lua').InitialAnimation()
                    if not SessionIsReplay() then
                        import('/lua/ui/game/avatars.lua').InitialAnimation()
                    end
                    import('/lua/ui/game/controlgroups.lua').InitialAnimation()
                    gm.HideGameUI('off')
                end)
            end
            FlushEvents()
        end
    end
end
)lua";

    /** "AI: Easy" for "<LOC lobui_0347>AI: Easy". */
    std::string WithoutLocTag(std::string text)
    {
      if (text.rfind("<LOC", 0) == 0) {
        const std::size_t end = text.find('>');
        if (end != std::string::npos) {
          text.erase(0, end + 1);
        }
      }
      return text;
    }
  } // namespace

  void InstallLoadingView(LuaPlus::LuaState* const state)
  {
    if (state != nullptr && !moho::SCR_LuaDoString(kLoadingView, state)) {
      gpg::Warnf("editor: the loading view did not install; the game's loading screen shows");
    }
  }

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
    FindChoices();
  }

  void EdPlay::FindChoices()
  {
    mAiTypes.clear();
    mFactions.clear();
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    if (state == nullptr) {
      return;
    }
    // Each list is a Lua array of tables; `keyField` and `nameField` name the two strings taken.
    const auto read = [&](const char* module, const char* table, const char* keyField, const char* nameField,
                          std::vector<PlayChoice>& out) {
      try {
        const LuaPlus::LuaObject list = moho::SCR_Import(state, module)[table];
        if (!list.IsTable()) {
          gpg::Warnf("editor: %s has no %s list", module, table);
          return;
        }
        for (int32_t i = 1; i <= list.GetN(); ++i) {
          const LuaPlus::LuaObject entry = list[i];
          if (!entry.IsTable()) {
            continue;
          }
          const LuaPlus::LuaObject key = entry[keyField];
          const LuaPlus::LuaObject name = entry[nameField];
          if (key.IsString()) {
            out.push_back({key.GetString(), WithoutLocTag(name.IsString() ? name.GetString() : key.GetString())});
          }
        }
      } catch (const std::exception& error) {
        gpg::Warnf("editor: %s: %s", module, error.what());
      }
    };
    read("/lua/ui/lobby/aitypes.lua", "aitypes", "key", "name", mAiTypes);
    read("/lua/factions.lua", "Factions", "Key", "DisplayName", mFactions);
    // FAF's quick start plays against "rush".
    mSetup.ai = 0;
    for (std::size_t i = 0; i < mAiTypes.size(); ++i) {
      if (mAiTypes[i].key == "rush") {
        mSetup.ai = static_cast<int>(i);
      }
    }
    gpg::Logf("editor: %zu AI types, %zu factions", mAiTypes.size(), mFactions.size());

    // The game rules for the mods a skirmish play uses (FAF's GetCampaignMods: GetGameMods for any
    // non-campaign map), built now on a thread so that the first Play takes them too. The session
    // receives the same table as scenarioMods and the loader keys the rules by its SCR_ToString.
    try {
      const LuaPlus::LuaObject getGameMods = moho::SCR_Import(state, "/lua/mods.lua")["GetGameMods"];
      if (getGameMods.IsFunction()) {
        LuaPlus::LuaFunction<LuaPlus::LuaObject> call(getGameMods);
        moho::RULE_PrepareKept(moho::SCR_ToString(call()));
      }
    } catch (const std::exception& error) {
      gpg::Warnf("editor: the game's mods for the rules built ahead: %s", error.what());
    }
  }

  bool EdPlay::SeesWholeMap() const
  {
    return mWholeMap && moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing;
  }

  void EdPlay::SetSeesWholeMap(const bool wholeMap)
  {
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr || moho::WLD_GetFrameAction() != moho::EWldFrameAction::Playing || wholeMap == mWholeMap) {
      return;
    }
    // The request goes through the sim driver and lands a frame or more later, so the switch's state is
    // kept here rather than read back from the session.
    if (wholeMap) {
      mPlayerArmy = session->FocusArmy;
      session->RequestFocusArmy(-1);
    } else {
      session->RequestFocusArmy(mPlayerArmy >= 0 ? mPlayerArmy : 0);
    }
    mWholeMap = wholeMap;
    gpg::Logf("editor: the view shows %s", wholeMap ? "the whole map" : "the player's army");
  }

  bool EdPlay::StartSession(const std::string& scenario)
  {
    mPlayerArmy = 0;
    mWholeMap = false;
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    if (state == nullptr) {
      return false;
    }
    // Defined again whenever the state lacks it (a new UI Lua state has none).
    if (state->GetGlobal("EditorStartPlay").IsNil() && !moho::SCR_LuaDoString(kLauncher, state)) {
      gpg::Warnf("editor: the session launcher did not load; playing with FAF's quick start");
      return moho::StartCommandLineSession(scenario.c_str(), false);
    }
    const bool withAi = mSetup.withAi && mSetup.ai >= 0 && mSetup.ai < static_cast<int>(mAiTypes.size());
    const std::string aiKey = withAi ? mAiTypes[static_cast<std::size_t>(mSetup.ai)].key : std::string{};
    const int faction = mSetup.faction >= 1 && mSetup.faction <= static_cast<int>(mFactions.size()) ? mSetup.faction : 0;
    const char* const fog = mSetup.fog ? "explored" : "none";
    gpg::Logf("editor: play %s (%s, faction %s, fog %s)", scenario.c_str(), withAi ? aiKey.c_str() : "solo",
              faction > 0 ? mFactions[static_cast<std::size_t>(faction - 1)].key.c_str() : "random", fog);
    try {
      const LuaPlus::LuaObject start = state->GetGlobal("EditorStartPlay");
      if (start.IsNil()) {
        throw std::runtime_error("EditorStartPlay is not defined");
      }
      LuaPlus::LuaFunction<void> call(start);
      call(scenario.c_str(), aiKey.c_str(), faction, fog);
      return true;
    } catch (const std::exception& error) {
      gpg::Warnf("editor: the session for %s did not start: %s", scenario.c_str(), error.what());
    } catch (...) {
      gpg::Warnf("editor: the session for %s did not start", scenario.c_str());
    }
    return false;
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
    // `/playai <key>`: every other army is that AI ("rush", "easy", ...); solo without it.
    if (moho::CFG_GetArgOption("/playai", 1, &args) && !args.empty()) {
      for (std::size_t i = 0; i < mAiTypes.size(); ++i) {
        if (mAiTypes[i].key == args[0].c_str()) {
          mSetup.withAi = true;
          mSetup.ai = static_cast<int>(i);
        }
      }
      if (!mSetup.withAi) {
        gpg::Warnf("editor: /playai %s: no such AI type", args[0].c_str());
      }
    }
    mAutoWholeMap = moho::CFG_GetArgOption("/playwholemap", 0, nullptr);
    if (moho::CFG_GetArgOption("/playafter", 1, &args) && !args.empty()) {
      mAutoDelay = static_cast<float>(std::atof(args[0].c_str()));
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
      if (mAutoStartAt < 0.0) {
        mAutoStartAt = now + static_cast<double>(mAutoDelay);
      }
      if (now < mAutoStartAt) {
        return;
      }
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
        if (mAutoWholeMap) {
          SetSeesWholeMap(true);
        }
      } else if (mAutoWholeMap && mWholeMap && now - mPlayingSince >= static_cast<double>(mAutoSeconds) * 0.5) {
        if (const moho::CWldSession* const session = moho::WLD_GetActiveSession()) {
          gpg::Logf("editor: the session's focus army is %d", session->FocusArmy);
        }
        SetSeesWholeMap(false);
      } else if (now - mPlayingSince >= static_cast<double>(mAutoSeconds)) {
        if (mAutoWholeMap && !mExitAppSent) {
          if (const moho::CWldSession* const session = moho::WLD_GetActiveSession()) {
            gpg::Logf("editor: the session's focus army is %d", session->FocusArmy);
          }
        }
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
        (void)StartSession(mMaps[static_cast<std::size_t>(mSelected)]);
      }
    }
  }
} // namespace faf::editor
