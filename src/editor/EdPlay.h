#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "moho/sim/CWldSession.h"

namespace faf::editor
{
  /** One entry of a Play setup list: the key the game's Lua takes ("rush", "uef") and the name shown. */
  struct PlayChoice
  {
    std::string key;
    std::string name;
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
    void Select(int index) noexcept { mSelected = index; }

    /** A session can start: none is loading or running. */
    [[nodiscard]] bool CanPlay() const;
    /** A session is loading or running. */
    [[nodiscard]] bool Active() const;
    /** What the session is doing, for the play bar. */
    [[nodiscard]] const char* StateText() const;

    /** The game's AI types (FAF's /lua/ui/lobby/aitypes.lua) and factions (/lua/factions.lua). */
    [[nodiscard]] const std::vector<PlayChoice>& AiTypes() const noexcept { return mAiTypes; }
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
     * and back to the player's army halfway through.
     */
    void ReadCommandLine();

    /** The command line's runs are over and asked for the editor to close. */
    [[nodiscard]] bool QuitRequested() const noexcept { return mQuitRequested; }

  private:
    void FindChoices();
    /** Starts the session for one scenario with `mSetup`; false (and a warning) when it did not start. */
    bool StartSession(const std::string& scenario);
    void DriveCommandLineRuns();
    /** Logs how long each phase of a session's start took (Preload, Loading, Initialize, ...). */
    void LogPhases();

    moho::EWldFrameAction mLastAction = moho::EWldFrameAction::Inactive;
    std::chrono::steady_clock::time_point mPhaseStart{};
    std::chrono::steady_clock::time_point mSessionStart{};

    std::vector<std::string> mMaps;
    std::vector<std::string> mTitles;
    std::vector<PlayChoice> mAiTypes;
    std::vector<PlayChoice> mFactions;
    PlaySetup mSetup;
    /** The army the view had before it switched to the whole map. */
    int mPlayerArmy = 0;
    bool mWholeMap = false;
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
    bool mAutoExitApp = false;
    bool mExitAppSent = false;
    bool mQuitRequested = false;
    double mPlayingSince = -1.0;
  };

  /** "SCMP_009" for "/maps/scmp_009/SCMP_009_scenario.lua". */
  [[nodiscard]] std::string MapDisplayName(const std::string& scenarioPath);
} // namespace faf::editor
