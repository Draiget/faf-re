#pragma once

#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "editor/EdMemMap.h"
#include "moho/sim/CWldSession.h"

namespace faf::editor
{
  /** One entry of a Play setup list: the key the game's Lua takes ("rush", "uef") and the name shown. */
  struct PlayChoice
  {
    std::string key;
    std::string name;
    /** An AI mod's AI type: the mod's uid (the mod is loaded with it); empty for the game's own. */
    std::string mod;
  };

  /** A sim mod the game data has (FAF's AllSelectableMods, not ui_only), and the AI types it brings. */
  struct PlayMod
  {
    std::string uid;
    std::string name;
    std::vector<PlayChoice> aiTypes;
  };

  /** One lobby slot of a custom setup: empty, you, or an AI; and its team. */
  struct PlaySlot
  {
    enum class Role
    {
      Empty,
      You,
      Ai,
    };
    Role role = Role::Empty;
    /** The AI type (an index into `EdPlay::AiTypes()`) for an AI slot. */
    int ai = 0;
    /** 0 no team, else the team's number: armies of one team start allied (FAF's Team, this plus one). */
    int team = 0;
    /** 0 random, else index + 1 into `EdPlay::Factions()` (an AI's; your own is the setup's faction). */
    int faction = 0;
  };

  /** How Play sets the session up. */
  struct PlaySetup
  {
    /** Solo (false): only the player and the map's civilians, so no AI brain and no AI map analysis. */
    bool withAi = false;
    /** Index into `EdPlay::AiTypes()` for every other army. */
    int ai = 0;
    /** 0 random, else index + 1 into `EdPlay::Factions()`. */
    int faction = 0;
    /** Fog of war as the game's "explored"; off is "none". */
    bool fog = true;
    /** The player's start: an index into the scenario's first team (the lobby's slots); past its end, the first. */
    int slot = 0;
    /** How many of the other slots get an AI (0: all of them), in slot order. */
    int aiCount = 0;
    /** The game's "Prebuilt units" option: each army starts with a base. */
    bool prebuilt = false;
    /** The sim mods played with (uids); the chosen AI's own mod comes along anyway. */
    std::vector<std::string> mods;
    /** A custom setup, slot by slot (empty: the simple one above, your slot and the AI opponents). */
    std::vector<PlaySlot> slots;
    /** The game's Victory option: sandbox, demoralization, domination, eradication, decapitation. */
    std::string victory = "sandbox";
    int unitCap = 500;
    /** The cheating AIs' resource and build multiplier (FAF's CheatMult and BuildMult). */
    float cheatMult = 1.5f;
  };

  /** A named setup: a built-in one or one the mapper saved. */
  struct PlayProfile
  {
    std::string name;
    bool builtIn = false;
  };

  /**
   * Play in the editor: a single-player session on a map, run by the game's own session state machine
   * (moho/sim/WldSessionControl.cpp) in the editor's window, and ended back to editing.
   *
   * Play builds the session the way FAF's `/map` quick start does (SinglePlayerLaunch.lua,
   * SetupCommandLineSkirmish), from the editor's `PlaySetup`: the AI armies are optional, and no replay
   * is written. Campaign maps go through FAF's own `StartCommandLineSession`. Stop, the game's own exit
   * from a session and a Lua request to quit all end it with `WLD_Teardown`, before the game's frame
   * would go on to its main menu.
   */
  class EdPlay
  {
  public:
    /**
     * Lists the maps the game data has (`/maps/<name>/<name>_scenario.lua`, as Lua's DiskFindFiles), each with
     * the title its scenario gives it (FAF's `/lua/ui/maputil.lua` LoadScenario, its `name`), sorted by title.
     */
    void FindMaps();

    /** The scenario paths, in the list's order. */
    [[nodiscard]] const std::vector<std::string>& Maps() const noexcept { return mMaps; }
    /** Each map's title ("Seton's Clutch"), or its folder name when the scenario gives none. */
    [[nodiscard]] const std::vector<std::string>& Titles() const noexcept { return mTitles; }
    [[nodiscard]] int Selected() const noexcept { return mSelected; }
    /** Picks a map and takes the setup remembered for it, or the last one used. */
    void Select(int index);

    /**
     * Where play setups are remembered (`play_setups.ini` in the editor's settings folder): the last
     * one used, and one per map for the maps that keep their own. Read now and written at each Play.
     */
    void SetSetupsFile(std::string path);
    /** The selected map keeps its own setup (else it plays with the last one used). */
    [[nodiscard]] bool KeepsOwnSetup() const noexcept { return mKeepOwnSetup; }
    void SetKeepsOwnSetup(bool keep);

    /** A session can start: none is loading or running. */
    [[nodiscard]] bool CanPlay() const;
    /** A session is loading or running. */
    [[nodiscard]] bool Active() const;
    /** What the session is doing, for the play bar. */
    [[nodiscard]] const char* StateText() const;

    /** The game's AI types (FAF's /lua/ui/lobby/aitypes.lua) and factions (/lua/factions.lua). */
    [[nodiscard]] const std::vector<PlayChoice>& AiTypes() const noexcept { return mAiTypes; }
    /** The sim mods the game data has, AI mods among them (their AI types are in AiTypes, after the game's). */
    [[nodiscard]] const std::vector<PlayMod>& Mods() const noexcept { return mMods; }
    /** The mods the setup plays with: its own and the chosen AI's; a uid set as Lua text (`{ ['uid'] = true }`). */
    [[nodiscard]] std::vector<std::string> PlayedMods() const;
    /** After the setup's mods change: the game's rules for them built ahead on a thread, so the next Play is quick. */
    void PrepareRules();
    /** The profiles: the built-in ones, then the saved ones by name. */
    [[nodiscard]] std::vector<PlayProfile> Profiles() const;
    /** The setup becomes the profile's (`slots` is how many start positions the map has, for the built-in ones). */
    void ApplyProfile(const std::string& name, int slots);
    /** The setup as it is, saved as a profile of that name (written to play_setups.ini). */
    void SaveProfile(const std::string& name);
    [[nodiscard]] const std::vector<PlayChoice>& Factions() const noexcept { return mFactions; }
    [[nodiscard]] PlaySetup& Setup() noexcept { return mSetup; }

    /**
     * During play: the view shows the whole map as an observer does (focus army -1), or the player's army
     * with its fog. The sim's fog itself is fixed at the start (each army's vision grids are made from the
     * FogOfWar option, CArmyImpl), so this is the switch that works mid-game; editor plays have cheats on,
     * which the engine requires for it (CWldSession::ValidateFocusArmyRequest).
     */
    [[nodiscard]] bool SeesWholeMap() const;
    void SetSeesWholeMap(bool wholeMap);
    /**
     * During play: the view leaves out the fog's shading (`ren_FogOfWarHidden`, WRenViewport) while the
     * player keeps their army; units the army has no intel on stay unseen. Put back when the play ends.
     */
    [[nodiscard]] bool FogHidden() const;
    void SetFogHidden(bool hidden);

    /** Starts the selected map on the next frame. */
    void Play() noexcept { mPlayRequested = true; }
    /** Ends the session on the next frame. */
    void Stop() noexcept { mStopRequested = true; }

    /** Applies Play and Stop, and catches the session's own Exit; runs before the game's frame. */
    void BeforeGameFrame();

    /**
     * Test runs from the command line: `/play <map>` plays that map (its folder or scenario name) once the
     * editor is up; `/playseconds <s>` stops it after s seconds of play, `/playcycles <n>` repeats that n
     * times, and `/playquit` closes the editor after the last one. `/playai <key>` plays against that AI
     * (solo without it), and `/playwholemap` switches the view to the whole map once play starts
     * and back to the player's army halfway through. `/playafter <s>` waits s seconds after the editor is
     * up before the first play.
     */
    void ReadCommandLine();

    /** The command line's runs are over and asked for the editor to close. */
    [[nodiscard]] bool QuitRequested() const noexcept { return mQuitRequested; }

  private:
    /** A setup as remembered: AI and faction by key, so they survive a change of the game's lists. */
    struct StoredSetup
    {
      bool withAi = false;
      std::string ai;
      std::string faction; // empty: random
      bool fog = true;
      int slot = 0;
      int aiCount = 0;
      bool prebuilt = false;
      std::vector<std::string> mods;
      /** `you::0,ai:m28ai:2,empty::0`: role, AI key, team per slot. */
      std::string slots;
      std::string victory = "sandbox";
      int unitCap = 500;
      float cheatMult = 1.5f;
    };

    void FindChoices();
    void ReadSetups();
    void WriteSetups() const;
    /** At a Play started by the user: the setup becomes the last one, and the map's own if it keeps one. */
    void RememberSetup();
    [[nodiscard]] StoredSetup Store(const PlaySetup& setup) const;
    [[nodiscard]] PlaySetup Restore(const StoredSetup& stored) const;
    /** "scmp_009" for the selected map (its folder name, lower case, without a .vNNNN version). */
    [[nodiscard]] std::string SelectedKey() const;
    /** Starts the session for one scenario with `mSetup`; false (and a warning) when it did not start. */
    bool StartSession(const std::string& scenario);
    void DriveCommandLineRuns();
    /** Logs how long each phase of a session's start took (Preload, Loading, Initialize, ...). */
    void LogPhases();

    moho::EWldFrameAction mLastAction = moho::EWldFrameAction::Inactive;
    std::chrono::steady_clock::time_point mPhaseStart{};
    std::chrono::steady_clock::time_point mSessionStart{};
    std::chrono::steady_clock::time_point mMemoryCheckAt{};
    std::map<std::string, int> mInstanceCounts;
    /** The memory map after the last play, to diff the next one against. */
    memmap::Snapshot mLastMemoryMap;
    std::uint32_t mTracePlay = 0; // `/memtrace`: the current play's number

    std::vector<std::string> mMaps;
    std::vector<std::string> mTitles;
    std::vector<PlayChoice> mAiTypes;
    std::vector<PlayChoice> mFactions;
    std::vector<PlayMod> mMods;
    std::vector<std::string> mPreparedMods;
    PlaySetup mSetup;
    std::string mSetupsFile;
    StoredSetup mLastSetup;
    bool mHaveLastSetup = false;
    std::map<std::string, StoredSetup> mMapSetups;
    std::map<std::string, StoredSetup> mProfiles;
    bool mKeepOwnSetup = false;
    /** The army the view had before it switched to the whole map. */
    int mPlayerArmy = 0;
    bool mWholeMap = false;
    bool mFogHidden = false;
    int mSelected = 0;
    bool mPlayRequested = false;
    bool mStopRequested = false;

    bool mAutoRun = false;
    std::vector<int> mAutoMaps;
    std::size_t mAutoRunIndex = 0U;
    float mAutoSeconds = 0.0f;
    int mAutoCyclesLeft = 0;
    bool mAutoQuit = false;
    bool mAutoWholeMap = false;
    bool mAutoNoFog = false;
    int mAutoProfile = 0; // `/playprofile <n>`
    bool mAutoLogArmies = false; // `/playlogarmies` // `/playnofog`: Hide the fog once play starts
    float mAutoDelay = 0.0f;
    int mAutoAi = -1; // `/playai`: this AI for every test play, over the map's remembered setup
    double mAutoStartAt = -1.0;
    bool mAutoExitApp = false;
    bool mExitAppSent = false;
    bool mQuitRequested = false;
    double mPlayingSince = -1.0;
  };

  /**
   * Installs the editor's loading view in a state the game UI starts in (no faction movie, no
   * "IN TRANSIT" screen; EdPlay.cpp); the editor sets it as `moho::gUIBeforeStartGameUI`.
   */
  void InstallLoadingView(LuaPlus::LuaState* state);

  /** "SCMP_009" for "/maps/scmp_009/SCMP_009_scenario.lua". */
  [[nodiscard]] std::string MapDisplayName(const std::string& scenarioPath);
} // namespace faf::editor
