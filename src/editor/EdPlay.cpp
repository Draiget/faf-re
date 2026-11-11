#include "editor/EdPlay.h"
#include "editor/EdMemTrace.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "lua/LuaArena.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/WeakPtr.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"


namespace moho
{
  extern bool ren_FogOfWarHidden;
}

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
    -- The setup's other choices, set by the editor just before the call.
    local extra = rawget(_G, '__EditorPlayExtra') or {}
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
        FogOfWar = fog, NoRushOption = 'Off', PrebuiltUnits = extra.prebuilt and 'On' or 'Off', Difficulty = 2,
        DoNotShareUnitCap = true, Timeouts = -1, GameSpeed = 'normal', UnitCap = tostring(extra.unitCap or 500),
        Victory = extra.victory or 'sandbox', CheatsEnabled = 'true', CivilianAlliance = 'enemy',
        TeamShareOverflow = 'enabled', Share = 'ShareUntilDeath',
        -- As FAF's lobby has them (lobbyOptions.lua defaults, lobby.lua fills Ratings and ClanTags): AI mods
        -- read them (M28AI writes its AIs' ratings into Ratings, cheating AIs read the multipliers).
        CheatMult = extra.cheatMult or '1.5', BuildMult = extra.cheatMult or '1.5', Ratings = {}, ClanTags = {},
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
    -- The setup's mods (a uid set), as a lobby game passes the chosen ones; a campaign map keeps FAF's own.
    if scenario.type == 'campaign' then
        info.scenarioMods = import('/lua/mods.lua').GetCampaignMods(scenario)
    else
        info.scenarioMods = import('/lua/mods.lua').GetGameMods(extra.mods or {})
    end

    local GetDefaultPlayerOptions = import('/lua/ui/lobby/lobbycomm.lua').GetDefaultPlayerOptions
    local armies = scenario.Configurations.standard.teams[1].armies
    local numColors = table.getn(import('/lua/gamecolors.lua').GameColors.PlayerColors)

    local function newAi(index, key, team, aiFaction)
        local ai = GetDefaultPlayerOptions(info.playerName)
        ai.AIPersonality = key
        ai.Faction = (aiFaction and aiFaction > 0) and aiFaction or SPL.GetRandomFaction()
        ai.PlayerName = SPL.GetRandomName(ai.Faction, key)
        ai.Human = false
        ai.ArmyName = armies[index]
        ai.PlayerColor = math.mod(index, numColors)
        ai.ArmyColor = math.mod(index, numColors)
        ai.Team = team or 1
        return ai
    end
    local function newPlayer(index, team)
        local player = GetDefaultPlayerOptions(info.playerName)
        player.PlayerName = info.playerName
        player.Faction = faction
        player.Human = true
        player.ArmyName = armies[index]
        player.PlayerColor = math.mod(index, numColors)
        player.ArmyColor = math.mod(index, numColors)
        player.Team = team or 1
        return player
    end

    if extra.slots and table.getn(extra.slots) > 0 then
        -- A custom setup, slot by slot: you first (army 1 is the player's), then the AIs in slot order. No You
        -- row: you watch, as an observer (the session's focus army stays -1).
        local you = nil
        for index, s in extra.slots do
            if s.role == 'you' and armies[index] and not you then
                you = index
                info.teamInfo[1] = newPlayer(index, s.team + 1)
            end
        end
        for index, s in extra.slots do
            if s.role == 'ai' and armies[index] and index ~= you then
                info.teamInfo[table.getn(info.teamInfo) + 1] = newAi(index, s.ai, s.team + 1, s.faction)
            end
        end
    else
        local slot = extra.slot or 1
        if slot < 1 or slot > table.getn(armies) then
            slot = 1
        end
        info.teamInfo[1] = newPlayer(slot, 1)
        if aiKey ~= '' then
            local wanted = extra.aiCount or 0
            local placed = 0
            for index = 1, table.getn(armies) do
                if index ~= slot and (wanted < 1 or placed < wanted) then
                    placed = placed + 1
                    info.teamInfo[table.getn(info.teamInfo) + 1] = newAi(index, aiKey, 1)
                end
            end
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

    for _, player in info.teamInfo do
        if player.PlayerName then
            scenario.Options.Ratings[player.PlayerName] = 0
        end
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
            out.push_back({key.GetString(), WithoutLocTag(name.IsString() ? name.GetString() : key.GetString()), std::string()});
          }
        }
      } catch (const std::exception& error) {
        gpg::Warnf("editor: %s: %s", module, error.what());
      }
    };
    read("/lua/ui/lobby/aitypes.lua", "aitypes", "key", "name", mAiTypes);
    read("/lua/factions.lua", "Factions", "Key", "DisplayName", mFactions);
    // The sim mods, as FAF's lobby lists them (AllSelectableMods, not ui_only), and the AI types of the AI
    // mods: the files of a mod's lua/AI/CustomAIs_v2 folder, their AI.AIList and AI.CheatAIList (FAF's
    // aitypes.lua GetAItypes reads the same for the mods a lobby selected).
    mMods.clear();
    static constexpr char kListMods[] = R"lua(
function EditorListMods()
    local out = {}
    for uid, mod in import('/lua/mods.lua').AllSelectableMods() do
        if not mod.ui_only then
            local entry = { uid = uid, name = mod.name or uid, ai = {} }
            local folder = mod.location .. '/lua/AI/CustomAIs_v2'
            if exists(folder) then
                for _, file in DiskFindFiles(folder, '*.lua') do
                    local ok, data = pcall(import, file)
                    if ok and data.AI then
                        for _, list in { data.AI.AIList or {}, data.AI.CheatAIList or {} } do
                            for _, t in list do
                                table.insert(entry.ai, { key = t.key, name = t.name })
                            end
                        end
                    end
                end
            end
            table.insert(out, entry)
        end
    end
    return out
end
)lua";
    try {
      if (moho::SCR_LuaDoString(kListMods, state)) {
        LuaPlus::LuaFunction<LuaPlus::LuaObject> listMods(state->GetGlobal("EditorListMods"));
        const LuaPlus::LuaObject list = listMods();
        for (int32_t i = 1; list.IsTable() && i <= list.GetN(); ++i) {
          const LuaPlus::LuaObject entry = list[i];
          if (!entry.IsTable() || !entry["uid"].IsString()) {
            continue;
          }
          PlayMod mod;
          mod.uid = entry["uid"].GetString();
          mod.name = entry["name"].IsString() ? WithoutLocTag(entry["name"].GetString()) : mod.uid;
          const LuaPlus::LuaObject ai = entry["ai"];
          for (int32_t k = 1; ai.IsTable() && k <= ai.GetN(); ++k) {
            const LuaPlus::LuaObject type = ai[k];
            if (type.IsTable() && type["key"].IsString()) {
              mod.aiTypes.push_back({type["key"].GetString(),
                                     WithoutLocTag(type["name"].IsString() ? type["name"].GetString() : type["key"].GetString()), mod.uid});
            }
          }
          mMods.push_back(std::move(mod));
        }
      }
    } catch (const std::exception& error) {
      gpg::Warnf("editor: the mod list: %s", error.what());
    }
    std::sort(mMods.begin(), mMods.end(), [](const PlayMod& a, const PlayMod& b) { return a.name < b.name; });
    // The AI mods' types after the game's, named with their mod.
    for (const PlayMod& mod : mMods) {
      for (PlayChoice type : mod.aiTypes) {
        // An AI mod may also list the game's own types: those stay the game's.
        if (std::any_of(mAiTypes.begin(), mAiTypes.end(), [&](const PlayChoice& known) { return known.key == type.key; })) {
          continue;
        }
        type.name = mod.name + ": " + type.name;
        mAiTypes.push_back(std::move(type));
      }
    }
    gpg::Logf("editor: %zu sim mods, %zu of them with AI types", mMods.size(),
              static_cast<std::size_t>(std::count_if(mMods.begin(), mMods.end(), [](const PlayMod& mod) { return !mod.aiTypes.empty(); })));
    // FAF's quick start plays against "rush".
    mSetup.ai = 0;
    for (std::size_t i = 0; i < mAiTypes.size(); ++i) {
      if (mAiTypes[i].key == "rush") {
        mSetup.ai = static_cast<int>(i);
      }
    }
    gpg::Logf("editor: %zu AI types, %zu factions", mAiTypes.size(), mFactions.size());
    ReadSetups();
    Select(mSelected);

    PrepareRules();
  }

  std::vector<std::string> EdPlay::PlayedMods() const
  {
    std::vector<std::string> mods = mSetup.mods;
    const auto addAiMod = [&](const int ai) {
      if (ai >= 0 && ai < static_cast<int>(mAiTypes.size())) {
        const std::string& aiMod = mAiTypes[static_cast<std::size_t>(ai)].mod;
        if (!aiMod.empty() && std::find(mods.begin(), mods.end(), aiMod) == mods.end()) {
          mods.push_back(aiMod);
        }
      }
    };
    if (mSetup.slots.empty() && mSetup.withAi) {
      addAiMod(mSetup.ai);
    }
    for (const PlaySlot& slot : mSetup.slots) {
      if (slot.role == PlaySlot::Role::Ai) {
        addAiMod(slot.ai);
      }
    }
    // Only mods the game data still has.
    mods.erase(std::remove_if(mods.begin(), mods.end(),
                              [&](const std::string& uid) {
                                return std::none_of(mMods.begin(), mMods.end(), [&](const PlayMod& mod) { return mod.uid == uid; });
                              }),
               mods.end());
    std::sort(mods.begin(), mods.end());
    return mods;
  }

  void EdPlay::PrepareRules()
  {
    // The game rules for the mods a skirmish play uses (GetGameMods of the setup's set), built now on a
    // thread so that the next Play takes them. The session receives the same table as scenarioMods and
    // the loader keys the rules by its SCR_ToString.
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    const std::vector<std::string> mods = PlayedMods();
    if (state == nullptr || (mods == mPreparedMods && !mPreparedMods.empty())) {
      return;
    }
    mPreparedMods = mods;
    std::string set = "__EditorPlayMods = {";
    for (const std::string& uid : mods) {
      set += "['" + uid + "'] = true, ";
    }
    (void)moho::SCR_LuaDoString((set + "}").c_str(), state);
    try {
      const LuaPlus::LuaObject getGameMods = moho::SCR_Import(state, "/lua/mods.lua")["GetGameMods"];
      if (getGameMods.IsFunction()) {
        LuaPlus::LuaFunction<LuaPlus::LuaObject> call(getGameMods);
        moho::RULE_PrepareKept(moho::SCR_ToString(call(state->GetGlobal("__EditorPlayMods"))));
        gpg::Logf("editor: rules built ahead for %zu mod%s", mods.size(), mods.size() == 1 ? "" : "s");
      }
    } catch (const std::exception& error) {
      gpg::Warnf("editor: the game's mods for the rules built ahead: %s", error.what());
    }
  }

  void EdPlay::Select(const int index)
  {
    mSelected = index;
    const auto own = mMapSetups.find(SelectedKey());
    mKeepOwnSetup = own != mMapSetups.end();
    if (mKeepOwnSetup) {
      mSetup = Restore(own->second);
    } else if (mHaveLastSetup) {
      mSetup = Restore(mLastSetup);
    }
  }

  void EdPlay::SetKeepsOwnSetup(const bool keep)
  {
    mKeepOwnSetup = keep;
    if (keep) {
      mMapSetups[SelectedKey()] = Store(mSetup);
    } else {
      mMapSetups.erase(SelectedKey());
    }
    WriteSetups();
  }

  void EdPlay::SetSetupsFile(std::string path)
  {
    mSetupsFile = std::move(path);
  }

  std::string EdPlay::SelectedKey() const
  {
    if (mSelected < 0 || mSelected >= static_cast<int>(mMaps.size())) {
      return {};
    }
    std::string key = MapDisplayName(mMaps[static_cast<std::size_t>(mSelected)]);
    std::transform(key.begin(), key.end(), key.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // FAF vault folders carry a version (scmp_009.v0003); every version shares one setup.
    if (key.size() > 6 && key[key.size() - 6] == '.' && key[key.size() - 5] == 'v' &&
        std::all_of(key.end() - 4, key.end(), [](const unsigned char c) { return std::isdigit(c) != 0; })) {
      key.erase(key.size() - 6);
    }
    return key;
  }

  EdPlay::StoredSetup EdPlay::Store(const PlaySetup& setup) const
  {
    StoredSetup stored;
    stored.withAi = setup.withAi;
    if (setup.ai >= 0 && setup.ai < static_cast<int>(mAiTypes.size())) {
      stored.ai = mAiTypes[static_cast<std::size_t>(setup.ai)].key;
    }
    if (setup.faction >= 1 && setup.faction <= static_cast<int>(mFactions.size())) {
      stored.faction = mFactions[static_cast<std::size_t>(setup.faction - 1)].key;
    }
    stored.fog = setup.fog;
    stored.slot = setup.slot;
    stored.aiCount = setup.aiCount;
    stored.prebuilt = setup.prebuilt;
    stored.quickStart = setup.quickStart;
    stored.mods = setup.mods;
    stored.slots.clear();
    for (const PlaySlot& slot : setup.slots) {
      const std::string role = slot.role == PlaySlot::Role::You ? "you" : slot.role == PlaySlot::Role::Ai ? "ai" : "empty";
      const std::string key =
        slot.role == PlaySlot::Role::Ai && slot.ai >= 0 && slot.ai < static_cast<int>(mAiTypes.size()) ? mAiTypes[static_cast<std::size_t>(slot.ai)].key : "";
      stored.slots += (stored.slots.empty() ? "" : ",") + role + ":" + key + ":" + std::to_string(slot.team) + ":" + std::to_string(slot.faction);
    }
    stored.victory = setup.victory;
    stored.unitCap = setup.unitCap;
    stored.cheatMult = setup.cheatMult;
    return stored;
  }

  PlaySetup EdPlay::Restore(const StoredSetup& stored) const
  {
    PlaySetup setup = mSetup; // an AI the game no longer has keeps the current choice
    setup.withAi = stored.withAi;
    for (std::size_t i = 0; i < mAiTypes.size(); ++i) {
      if (mAiTypes[i].key == stored.ai) {
        setup.ai = static_cast<int>(i);
      }
    }
    setup.faction = 0;
    for (std::size_t i = 0; i < mFactions.size(); ++i) {
      if (mFactions[i].key == stored.faction) {
        setup.faction = static_cast<int>(i) + 1;
      }
    }
    setup.fog = stored.fog;
    setup.slot = stored.slot;
    setup.aiCount = stored.aiCount;
    setup.prebuilt = stored.prebuilt;
    setup.quickStart = stored.quickStart;
    setup.mods = stored.mods;
    setup.slots.clear();
    for (std::size_t at = 0; at < stored.slots.size();) {
      const std::size_t comma = std::min(stored.slots.find(',', at), stored.slots.size());
      const std::string item = stored.slots.substr(at, comma - at);
      at = comma + 1;
      const std::size_t first = item.find(':');
      const std::size_t second = first == std::string::npos ? std::string::npos : item.find(':', first + 1);
      if (second == std::string::npos) {
        continue;
      }
      PlaySlot slot;
      const std::string role = item.substr(0, first);
      slot.role = role == "you" ? PlaySlot::Role::You : role == "ai" ? PlaySlot::Role::Ai : PlaySlot::Role::Empty;
      const std::string key = item.substr(first + 1, second - first - 1);
      slot.ai = setup.ai;
      for (std::size_t i = 0; i < mAiTypes.size(); ++i) {
        if (mAiTypes[i].key == key) {
          slot.ai = static_cast<int>(i);
        }
      }
      slot.team = std::max(0, std::atoi(item.c_str() + second + 1));
      if (const std::size_t third = item.find(':', second + 1); third != std::string::npos) {
        slot.faction = std::max(0, std::atoi(item.c_str() + third + 1));
      }
      setup.slots.push_back(slot);
    }
    setup.victory = stored.victory.empty() ? "sandbox" : stored.victory;
    setup.unitCap = stored.unitCap;
    setup.cheatMult = stored.cheatMult;
    return setup;
  }

  void EdPlay::RememberSetup()
  {
    mLastSetup = Store(mSetup);
    mHaveLastSetup = true;
    if (mKeepOwnSetup) {
      mMapSetups[SelectedKey()] = mLastSetup;
    }
    WriteSetups();
  }

  // play_setups.ini: a [last] section and a [map <key>] section per map that keeps its own setup,
  // each with opponents=solo|ai, ai=<key>, faction=<key>|random, fog=0|1, slot=<n from 1>, aicount=<n, 0 all>, prebuilt=0|1,
  // quickstart=0|1 (missing: on).
  void EdPlay::ReadSetups()
  {
    mMapSetups.clear();
    mProfiles.clear();
    mHaveLastSetup = false;
    std::ifstream in(mSetupsFile);
    if (!in) {
      return;
    }
    StoredSetup* current = nullptr;
    std::string line;
    while (std::getline(in, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
        line.pop_back();
      }
      if (line.empty() || line[0] == ';') {
        continue;
      }
      if (line.front() == '[' && line.back() == ']') {
        const std::string section = line.substr(1, line.size() - 2);
        if (section == "last") {
          current = &mLastSetup;
          mHaveLastSetup = true;
        } else if (section.rfind("map ", 0) == 0 && section.size() > 4) {
          current = &mMapSetups[section.substr(4)];
        } else if (section.rfind("profile ", 0) == 0 && section.size() > 8) {
          current = &mProfiles[section.substr(8)];
        } else {
          current = nullptr;
        }
        continue;
      }
      const std::size_t equals = line.find('=');
      if (current == nullptr || equals == std::string::npos) {
        continue;
      }
      const std::string key = line.substr(0, equals);
      const std::string value = line.substr(equals + 1);
      if (key == "opponents") {
        current->withAi = value == "ai";
      } else if (key == "ai") {
        current->ai = value;
      } else if (key == "faction") {
        current->faction = value == "random" ? std::string{} : value;
      } else if (key == "fog") {
        current->fog = value != "0";
      } else if (key == "slot") {
        current->slot = std::max(0, std::atoi(value.c_str()) - 1);
      } else if (key == "aicount") {
        current->aiCount = std::max(0, std::atoi(value.c_str()));
      } else if (key == "prebuilt") {
        current->prebuilt = value == "1";
      } else if (key == "quickstart") {
        current->quickStart = value != "0";
      } else if (key == "slots") {
        current->slots = value;
      } else if (key == "victory") {
        current->victory = value;
      } else if (key == "unitcap") {
        current->unitCap = std::clamp(std::atoi(value.c_str()), 100, 10000);
      } else if (key == "cheatmult") {
        current->cheatMult = static_cast<float>(std::atof(value.c_str()));
      } else if (key == "mods") {
        current->mods.clear();
        for (std::size_t at = 0; at < value.size();) {
          const std::size_t comma = std::min(value.find(',', at), value.size());
          if (comma > at) {
            current->mods.push_back(value.substr(at, comma - at));
          }
          at = comma + 1;
        }
      }
    }
    gpg::Logf("editor: play setups from %s (%s last, %zu maps of their own)", mSetupsFile.c_str(),
              mHaveLastSetup ? "a" : "no", mMapSetups.size());
  }

  void EdPlay::WriteSetups() const
  {
    if (mSetupsFile.empty()) {
      return;
    }
    std::ofstream out(mSetupsFile, std::ios::trunc);
    if (!out) {
      gpg::Warnf("editor: %s could not be written", mSetupsFile.c_str());
      return;
    }
    const auto write = [&out](const char* header, const std::string& name, const StoredSetup& setup) {
      out << '[' << header << name << "]\n"
          << "opponents=" << (setup.withAi ? "ai" : "solo") << '\n'
          << "ai=" << setup.ai << '\n'
          << "faction=" << (setup.faction.empty() ? "random" : setup.faction) << '\n'
          << "fog=" << (setup.fog ? 1 : 0) << '\n'
          << "slot=" << setup.slot + 1 << '\n'
          << "aicount=" << setup.aiCount << '\n'
          << "prebuilt=" << (setup.prebuilt ? 1 : 0) << '\n'
          << "quickstart=" << (setup.quickStart ? 1 : 0) << '\n'
          << "mods=";
      for (std::size_t i = 0; i < setup.mods.size(); ++i) {
        out << (i > 0 ? "," : "") << setup.mods[i];
      }
      out << '\n'
          << "slots=" << setup.slots << '\n'
          << "victory=" << setup.victory << '\n'
          << "unitcap=" << setup.unitCap << '\n'
          << "cheatmult=" << setup.cheatMult << "\n\n";
    };
    out << "; FAF Map Editor: the last play setup, and the maps that keep their own (written by the editor)\n\n";
    if (mHaveLastSetup) {
      write("last", "", mLastSetup);
    }
    for (const auto& [key, setup] : mMapSetups) {
      write("map ", key, setup);
    }
    for (const auto& [name, setup] : mProfiles) {
      write("profile ", name, setup);
    }
  }

  namespace
  {
    /** The built-in profiles, in the menu's order. */
    const char* const kBuiltInProfiles[] = {"Solo sandbox", "You vs 1 AI", "2 v 2 with AI", "Free for all with AI", "Watch 4 AI"};
  } // namespace

  std::vector<PlayProfile> EdPlay::Profiles() const
  {
    std::vector<PlayProfile> profiles;
    for (const char* const name : kBuiltInProfiles) {
      profiles.push_back({name, true});
    }
    for (const auto& [name, setup] : mProfiles) {
      profiles.push_back({name, false});
    }
    return profiles;
  }

  void EdPlay::ApplyProfile(const std::string& name, const int slots)
  {
    if (const auto saved = mProfiles.find(name); saved != mProfiles.end()) {
      mSetup = Restore(saved->second);
      gpg::Logf("editor: play profile %s", name.c_str());
      return;
    }
    // The built-in ones keep the faction, fog and mods; the AI is the chosen one.
    PlaySetup& setup = mSetup;
    setup.slots.clear();
    setup.slot = 0;
    setup.aiCount = 0;
    setup.prebuilt = false;
    if (name == kBuiltInProfiles[0]) {
      setup.withAi = false;
      setup.victory = "sandbox";
    } else if (name == kBuiltInProfiles[1]) {
      setup.withAi = true;
      setup.aiCount = 1;
      setup.victory = "demoralization";
    } else if (name == kBuiltInProfiles[4]) {
      // Four AIs on slots 1-4, two teams by odd and even slots, and you watching.
      setup.withAi = true;
      setup.victory = "demoralization";
      for (int i = 0; i < std::min(4, std::max(slots, 2)); ++i) {
        PlaySlot slot;
        slot.role = PlaySlot::Role::Ai;
        slot.ai = setup.ai;
        slot.team = 1 + (i % 2);
        setup.slots.push_back(slot);
      }
    } else if (name == kBuiltInProfiles[2] || name == kBuiltInProfiles[3]) {
      // Slots 1 and 2, 3 and 4 face each other on maps whose starts are paired (the Armies panel pairs them):
      // two v two puts the odd slots on one team and the even on the other.
      const int count = name == kBuiltInProfiles[2] ? std::min(4, std::max(slots, 2)) : std::max(slots, 2);
      setup.withAi = true;
      setup.victory = "demoralization";
      for (int i = 0; i < count; ++i) {
        PlaySlot slot;
        slot.role = i == 0 ? PlaySlot::Role::You : PlaySlot::Role::Ai;
        slot.ai = setup.ai;
        slot.team = name == kBuiltInProfiles[2] ? 1 + (i % 2) : 0;
        setup.slots.push_back(slot);
      }
    } else {
      return;
    }
    gpg::Logf("editor: play profile %s (%zu slots)", name.c_str(), setup.slots.size());
    PrepareRules();
  }

  void EdPlay::SaveProfile(const std::string& name)
  {
    if (name.empty()) {
      return;
    }
    mProfiles[name] = Store(mSetup);
    WriteSetups();
    gpg::Logf("editor: play profile %s saved", name.c_str());
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

  bool EdPlay::FogHidden() const
  {
    return mFogHidden && moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing;
  }

  void EdPlay::SetFogHidden(const bool hidden)
  {
    if (hidden == mFogHidden) {
      return;
    }
    mFogHidden = hidden;
    // Not `ren_FogOfWar`: each beat sets that one from the sim (CWldSession::DoBeat).
    moho::ren_FogOfWarHidden = hidden;
    gpg::Logf("editor: the view %s the fog", hidden ? "leaves out" : "shows");
  }

  bool EdPlay::StartSession(const std::string& scenario)
  {
    mPlayerArmy = 0;
    mWholeMap = false;
    SetFogHidden(false);
    // `/playnoquickstart` (test runs): FAF's own start, to compare against.
    mQuickStartPending = mSetup.quickStart && !moho::CFG_GetArgOption("/playnoquickstart", 0, nullptr);
    mQuickStartSimSent = false;
    mQuickStartUntil = 0.0;
    if (memtrace::Running()) {
      mTracePlay = memtrace::NextPlay();
    }
    if (!mAutoRun) {
      RememberSetup(); // test runs from the command line leave the remembered setups alone
    }
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    if (state == nullptr) {
      return false;
    }
    // A map's water bodies (ScenarioInfo.WaterBodies) are in no game release yet: the switch puts them in this session,
    // as the editor's view shows them. A map without any is played as before.
    moho::CON_Execute("sim_FixWaterBodies 1");
    // Defined again whenever the state lacks it (a new UI Lua state has none).
    if (state->GetGlobal("EditorStartPlay").IsNil() && !moho::SCR_LuaDoString(kLauncher, state)) {
      gpg::Warnf("editor: the session launcher did not load; playing with FAF's quick start");
      return moho::StartCommandLineSession(scenario.c_str(), false);
    }
    const bool withAi = (mSetup.withAi || std::any_of(mSetup.slots.begin(), mSetup.slots.end(),
                                                      [](const PlaySlot& slot) { return slot.role == PlaySlot::Role::Ai; })) &&
                        mSetup.ai >= 0 && mSetup.ai < static_cast<int>(mAiTypes.size());
    const std::string aiKey = withAi ? mAiTypes[static_cast<std::size_t>(mSetup.ai)].key : std::string{};
    const int faction = mSetup.faction >= 1 && mSetup.faction <= static_cast<int>(mFactions.size()) ? mSetup.faction : 0;
    const char* const fog = mSetup.fog ? "explored" : "none";
    gpg::Logf("editor: play %s (%s, faction %s, fog %s, slot %d, %d AI, prebuilt %s)", scenario.c_str(), withAi ? aiKey.c_str() : "solo",
              faction > 0 ? mFactions[static_cast<std::size_t>(faction - 1)].key.c_str() : "random", fog, mSetup.slot + 1,
              mSetup.aiCount, mSetup.prebuilt ? "on" : "off");
    char extra[160];
    (void)std::snprintf(extra, sizeof(extra), "__EditorPlayExtra = { slot = %d, aiCount = %d, prebuilt = %s, mods = {", mSetup.slot + 1,
                        mSetup.aiCount, mSetup.prebuilt ? "true" : "false");
    std::string extraText = extra;
    const std::vector<std::string> playedMods = PlayedMods();
    for (const std::string& uid : playedMods) {
      extraText += "['" + uid + "'] = true, ";
    }
    extraText += "}, slots = {";
    for (const PlaySlot& slot : mSetup.slots) {
      const std::string role = slot.role == PlaySlot::Role::You ? "you" : slot.role == PlaySlot::Role::Ai ? "ai" : "empty";
      const std::string key = slot.ai >= 0 && slot.ai < static_cast<int>(mAiTypes.size()) ? mAiTypes[static_cast<std::size_t>(slot.ai)].key : "rush";
      extraText += "{ role = '" + role + "', ai = '" + key + "', team = " + std::to_string(slot.team) +
                   ", faction = " + std::to_string(slot.faction) + " }, ";
    }
    char options[160];
    (void)std::snprintf(options, sizeof(options), "}, victory = '%s', unitCap = %d, cheatMult = '%.1f' }", mSetup.victory.c_str(), mSetup.unitCap,
                        static_cast<double>(mSetup.cheatMult));
    (void)moho::SCR_LuaDoString((extraText + options).c_str(), state);
    if (!playedMods.empty()) {
      gpg::Logf("editor: play with %zu mod%s", playedMods.size(), playedMods.size() == 1 ? "" : "s");
    }
    if (!mSetup.slots.empty()) {
      std::string list;
      for (const PlaySlot& slot : mSetup.slots) {
        list += slot.role == PlaySlot::Role::You ? " you" : slot.role == PlaySlot::Role::Ai ? " ai" : " -";
        list += slot.team > 0 ? "/t" + std::to_string(slot.team) : std::string();
        list += slot.faction > 0 ? "/f" + std::to_string(slot.faction) : std::string();
      }
      gpg::Logf("editor: play slots:%s; victory %s, unit cap %d, AI cheat %.1f", list.c_str(), mSetup.victory.c_str(), mSetup.unitCap,
                static_cast<double>(mSetup.cheatMult));
    }
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
      // Nothing to play: a test run that asked to quit after its plays quits now instead of waiting forever.
      mQuitRequested = moho::CFG_GetArgOption("/playquit", 0, nullptr);
      return;
    }
    const int found = mAutoMaps.front();
    Select(found);
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
          mAutoAi = static_cast<int>(i);
        }
      }
      if (mAutoAi < 0) {
        gpg::Warnf("editor: /playai %s: no such AI type", args[0].c_str());
      }
    }
    // `/playprofile <n>`: the n-th profile (1 the first built-in one) applied before each test play.
    if (moho::CFG_GetArgOption("/playprofile", 1, &args) && !args.empty()) {
      mAutoProfile = std::atoi(args[0].c_str());
    }
    mAutoWholeMap = moho::CFG_GetArgOption("/playwholemap", 0, nullptr);
    mAutoNoFog = moho::CFG_GetArgOption("/playnofog", 0, nullptr);
    mAutoLogArmies = moho::CFG_GetArgOption("/playlogarmies", 0, nullptr);
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
      if (now < mAutoStartAt || mMemoryCheckAt != std::chrono::steady_clock::time_point{}) {
        return; // the delay before the first play, or the memory reading after the last one
      }
      if (mAutoCyclesLeft > 0) {
        --mAutoCyclesLeft;
        Select(mAutoMaps[mAutoRunIndex++ % mAutoMaps.size()]); // with the map's remembered setup
        if (mAutoAi >= 0) {
          mSetup.withAi = true;
          mSetup.ai = mAutoAi;
        }
        if (const std::vector<PlayProfile> profiles = Profiles(); mAutoProfile >= 1 && mAutoProfile <= static_cast<int>(profiles.size())) {
          ApplyProfile(profiles[static_cast<std::size_t>(mAutoProfile - 1)].name, 8);
        }
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
        if (mAutoNoFog) {
          SetFogHidden(true);
        }
        // `/playlogarmies`: each army's name and its stance to the others, as the UI sees them (IsAlly).
        if (mAutoLogArmies) {
          if (LuaPlus::LuaState* const state = moho::USER_GetLuaState(); state != nullptr) {
            (void)moho::SCR_LuaDoString(R"lua(
local armies = GetArmiesTable().armiesTable
for i, a in armies do
    local line = 'editor: army ' .. i .. ' ' .. tostring(a.nickname) .. (a.human and ' (you)' or '') .. ':'
    for j, b in armies do
        if j ~= i and not b.civilian and not a.civilian then
            line = line .. ' ' .. j .. (IsAlly(i, j) and '=ally' or '=enemy')
        end
    end
    LOG(line)
end
)lua", state);
          }
        }
      } else if (fa::vector<fa::string> poke; !mPokeDone && now - mPlayingSince >= 1.5 && moho::CFG_GetArgOption("/playterrainpoke", 1, &poke) &&
                                                !poke.empty()) {
        // `/playterrainpoke x,z,size,height` (WPE.39, editing while the map plays): the rendered terrain's height at
        // (x, z), the sim told to flatten a square there (SimLua FlattenMapRect, the sim's own Lua), and the rendered
        // height again two seconds on: the sim's beat sync (SSyncData::mTerrainUpdate -> SyncTerrain) carries it over.
        mPokeDone = true;
        float x = 0.0f, z = 0.0f, size = 0.0f, height = 0.0f;
        if (std::sscanf(poke[0].c_str(), "%f,%f,%f,%f", &x, &z, &size, &height) == 4) {
          mPokeX = x;
          mPokeZ = z;
          mPokeAt = now + 2.0;
          if (const moho::CWldSession* const session = moho::WLD_GetActiveSession(); session != nullptr && session->GetSTIMap() != nullptr) {
            gpg::Logf("editor: terrain poke: rendered height at %.1f,%.1f before: %.2f", static_cast<double>(x), static_cast<double>(z),
                      static_cast<double>(session->GetSTIMap()->mHeightField->GetElevation(x, z)));
          }
          char command[200];
          (void)std::snprintf(command, sizeof(command), "SimLua FlattenMapRect(%g, %g, %g, %g, %g)", static_cast<double>(x - size * 0.5f),
                              static_cast<double>(z - size * 0.5f), static_cast<double>(size), static_cast<double>(size), static_cast<double>(height));
          moho::CON_Execute(command);
          gpg::Logf("editor: terrain poke: %s", command);
          // The sim's own height there, as the sim logs it (the rendered terrain follows only what the camera sees).
          (void)std::snprintf(command, sizeof(command), "SimLua LOG('editor: terrain poke: the sim height now ', GetTerrainHeight(%g, %g))",
                              static_cast<double>(x), static_cast<double>(z));
          moho::CON_Execute(command);
        }
      } else if (mPokeAt > 0.0 && now >= mPokeAt) {
        mPokeAt = 0.0;
        if (const moho::CWldSession* const session = moho::WLD_GetActiveSession(); session != nullptr && session->GetSTIMap() != nullptr) {
          gpg::Logf("editor: terrain poke: rendered height at %.1f,%.1f after: %.2f", static_cast<double>(mPokeX), static_cast<double>(mPokeZ),
                    static_cast<double>(session->GetSTIMap()->mHeightField->GetElevation(mPokeX, mPokeZ)));
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

  void EdPlay::DriveQuickStart()
  {
    if (!mQuickStartPending) {
      return;
    }
    const moho::EWldFrameAction action = moho::WLD_GetFrameAction();
    if (action == moho::EWldFrameAction::Inactive || action == moho::EWldFrameAction::Exit) {
      mQuickStartPending = false;
      return;
    }
    if (action != moho::EWldFrameAction::Playing) {
      return;
    }
    // The sim: FAF starts each commander hidden and calls its PlayCommanderWarpInEffect 3 s on (ScenarioUtilities'
    // CommanderWarpDelay; then 2.1 s of effect before it shows and takes orders). That call is looked up on the unit
    // when it comes, so a commander given its own does nothing then; it is shown now, as the effect's end leaves it
    // (its WarpInEffect.HideBones hidden again), and takes orders. The sim's own Lua (SimLua, the editor's plays have
    // cheats on), in short lines: the console's command line is cut past a few hundred characters.
    if (!mQuickStartSimSent) {
      mQuickStartSimSent = true;
      if (!mSetup.prebuilt) { // with prebuilt units FAF has no warp-in
        moho::CON_Execute("SimLua function __EdQuick(u) u.PlayCommanderWarpInEffect = function(s) s:SetBlockCommandQueue(false) end "
                          "u:ShowBone(0, true) u:SetBlockCommandQueue(false) end");
        moho::CON_Execute("SimLua function __EdQuickBones(u) local w = u.Blueprint.Display.WarpInEffect if w and w.HideBones then "
                          "for _, b in pairs(w.HideBones) do u:HideBone(b, true) end end end");
        moho::CON_Execute("SimLua local n = 0 for _, a in pairs(ArmyBrains) do for _, u in pairs(a:GetListOfUnits(categories.COMMAND, false)) do "
                          "__EdQuick(u) __EdQuickBones(u) n = n + 1 end end LOG('editor: quick start: ' .. n .. ' commanders at tick ' .. GetGameTick())");
      }
    }
    // The camera: over your commander now, not FAF's zoom to it a second in (its own zoom then stays where it is). The
    // world camera framed on it as UIZoomTo (0x00867240) frames its units, from here: the game's own GetArmyAvatars
    // called from the editor's Lua fails LuaPlus's same-state check when it fills its table. Tried each frame until
    // your army has its commander, for up to 5 s (an observer has none).
    const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (mQuickStartUntil <= 0.0) {
      mQuickStartUntil = now + 5.0;
    }
    if (now >= mQuickStartUntil) {
      mQuickStartPending = false;
      return;
    }
    const moho::CWldSession* const session = moho::WLD_GetActiveSession();
    moho::UserArmy* const army = session != nullptr ? session->GetFocusArmy() : nullptr;
    moho::CameraImpl* const camera = moho::CAM_GetManager() != nullptr ? moho::CAM_GetManager()->GetCamera("WorldCamera") : nullptr;
    if (army == nullptr || camera == nullptr) {
      return;
    }
    for (const moho::WeakPtr<moho::UserUnit>& avatar : army->GetAvatars()) {
      if (moho::UserUnit* const unit = avatar.GetObjectPtr(); unit != nullptr) {
        const Wm3::Vec3f at = static_cast<moho::UserEntity*>(unit)->GetInterpolatedPosition(1.0f);
        constexpr float kMargin = 20.0f; // UIZoomTo's
        Wm3::AxisAlignedBox3f box{};
        box.Min.x = at.x - kMargin;
        box.Min.y = at.y - kMargin;
        box.Min.z = at.z - kMargin;
        box.Max.x = at.x + kMargin;
        box.Max.y = at.y + kMargin;
        box.Max.z = at.z + kMargin;
        camera->TargetBox(box, 0.0f);
        camera->TargetNothing();
        mQuickStartPending = false;
        gpg::Logf("editor: quick start: the camera over your commander at %.0f,%.0f", static_cast<double>(at.x), static_cast<double>(at.z));
        return;
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
    DriveQuickStart();
    const moho::EWldFrameAction action = moho::WLD_GetFrameAction();
    if ((mStopRequested && action != moho::EWldFrameAction::Inactive) || action == moho::EWldFrameAction::Exit) {
      gpg::Logf("editor: play ended (%s)", action == moho::EWldFrameAction::Exit ? "the session's exit" : "Stop");
      moho::WLD_Teardown();
      SetFogHidden(false);
      mMemoryCheckAt = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    }
    mStopRequested = false;

    // Two seconds after a play ends: what the process keeps (WPE.16, memory given back after a play).
    if (mMemoryCheckAt != std::chrono::steady_clock::time_point{} && std::chrono::steady_clock::now() >= mMemoryCheckAt &&
        action == moho::EWldFrameAction::Inactive) {
      mMemoryCheckAt = {};
      // The editor's UI Lua state holds the play's garbage until its own next collection (0.4 MB a play on
      // SCMP_009), and the Lua range keeps its highest size: collected now, so each play starts from the same
      // floor (WPE.16). The state is this thread's.
      if (LuaPlus::LuaState* const ui = moho::USER_GetLuaState(); ui != nullptr) {
        lua_setgcthreshold(ui->m_state, 0);
      }
      PROCESS_MEMORY_COUNTERS_EX counters{};
      counters.cb = sizeof(counters);
      if (::GetProcessMemoryInfo(::GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
        gpg::Logf("editor: after the play, %.1f MB private, %.1f MB working set", static_cast<double>(counters.PrivateUsage) / 1048576.0,
                  static_cast<double>(counters.WorkingSetSize) / 1048576.0);
      }
      // What the graphics driver holds for the process: video memory, and system memory the GPU reads (DXGI's
      // or Vulkan's own counts), so a play that leaves GPU resources behind shows here.
      if (gpg::gal::DeviceRuntimeInfo info; gpg::gal::Device::IsReady() && gpg::gal::Device::GetInstance()->GetRuntimeInfo(info)) {
        gpg::Logf("editor: after the play, GPU memory: %.1f MB video, %.1f MB system", static_cast<double>(info.localUsage) / 1048576.0,
                  static_cast<double>(info.nonLocalUsage) / 1048576.0);
      }
      // `/memtrace`: what the play before last left (its caches are warm by now, so this is what stays).
      if (memtrace::Running() && mTracePlay >= 2) {
        memtrace::Report(mTracePlay - 1, 12);
      }
      // The engine's live object counts by type (InstanceCounter), and which changed since the last play.
      if (moho::StatItem* const counts = moho::GetEngineStats()->GetItem("Instance Counts", false); counts != nullptr) {
        std::map<std::string, int> now;
        counts->VisitChildren(
          [](moho::StatItem* const child, void* const context) {
            // The primary slot: instance counters never write the realtime one.
            (*static_cast<std::map<std::string, int>*>(context))[child->Name().c_str()] = child->GetInt(false);
          },
          &now
        );
        std::string changed;
        for (const auto& [name, count] : now) {
          const auto before = mInstanceCounts.find(name);
          const int previous = before != mInstanceCounts.end() ? before->second : 0;
          if (count != previous) {
            changed += " " + name + " " + std::to_string(previous) + "->" + std::to_string(count) + ";";
          }
        }
        if (!changed.empty()) {
          gpg::Logf("editor: instance counts changed since the last play:%s", changed.c_str());
        }
        mInstanceCounts = std::move(now);
      }
      // Which heap, stack or direct allocation holds the rest (the engine heap is only one of them).
      memmap::Snapshot map = memmap::Take();
      memmap::LogChanges(mLastMemoryMap, map);
      mLastMemoryMap = std::move(map);
      // Lua's own range (every Lua state's memory): where it is, and what the editor's UI state holds.
      // Other states open and close on other threads (the rules for the next play), so only this one.
#if INTPTR_MAX != INT32_MAX
      const lua::ArenaUsage arena = lua::ArenaReadUsage();
      static lua::ArenaUsage lastArena;
      for (std::size_t c = 0; c < lua::ArenaUsage::kClasses && lastArena.committedBytes != 0; ++c) {
        if (arena.classSpans[c] != lastArena.classSpans[c]) {
          gpg::Logf("editor:   Lua blocks of %u bytes: %u -> %u spans, %u -> %u blocks free on the shared lists", arena.classBytes[c],
                    lastArena.classSpans[c], arena.classSpans[c], lastArena.classFreeBlocks[c], arena.classFreeBlocks[c]);
        }
      }
      lastArena = arena;
      constexpr double kMB = 1048576.0;
      const LuaPlus::LuaState* const ui = moho::USER_GetLuaState();
      // The rules kept between plays (their blueprints' Lua state): what each play adds to it stays.
      if (moho::RRuleGameRules* const kept = moho::RULE_PeekKept(); kept != nullptr) {
        const LuaPlus::LuaState* const rules = static_cast<moho::RRuleGameRulesImpl*>(kept)->mLuaState;
        gpg::Logf("editor: the kept rules' Lua state counts %d KB", rules != nullptr ? lua_getgccount(rules->m_state) : 0);
      }
      gpg::Logf("editor: Lua range: %.1f MB committed, %.1f MB in spans (%.1f MB small-block spans, %.1f MB of them free on "
                "the shared lists; %.1f MB in %zu freed large runs), %zu light cells; the UI state counts %d KB",
                arena.committedBytes / kMB, arena.spanBytes / kMB, arena.smallSpanBytes / kMB, arena.smallFreeBytes / kMB,
                arena.freeRunBytes / kMB, arena.freeRuns, arena.lightCells,
                ui != nullptr ? lua_getgccount(ui->m_state) : 0);
#endif
    }

    if (mPlayRequested) {
      mPlayRequested = false;
      if (CanPlay() && mSelected >= 0 && mSelected < static_cast<int>(mMaps.size())) {
        (void)StartSession(mMaps[static_cast<std::size_t>(mSelected)]);
      }
    }
  }
} // namespace faf::editor
