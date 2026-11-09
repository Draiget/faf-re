#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "moho/sim/CWldSession.h"

namespace faf::editor
{
  /**
   * Play in the editor: a single-player session on a map, run by the game's own session state machine
   * (moho/sim/WldSessionControl.cpp) in the editor's window, and ended back to editing.
   *
   * Play starts it the way the game's `/map` does (`StartCommandLineSession`, FAF's
   * SinglePlayerLaunch.lua). Stop, the game's own exit from a session and a Lua request to quit all end
   * it with `WLD_Teardown`, before the game's frame would go on to its main menu.
   */
  class EdPlay
  {
  public:
    /** Lists the maps the game data has (`/maps/<name>/<name>_scenario.lua`, as Lua's DiskFindFiles). */
    void FindMaps();

    [[nodiscard]] const std::vector<std::string>& Maps() const noexcept { return mMaps; }
    [[nodiscard]] int Selected() const noexcept { return mSelected; }
    void Select(int index) noexcept { mSelected = index; }

    /** A session can start: none is loading or running. */
    [[nodiscard]] bool CanPlay() const;
    /** A session is loading or running. */
    [[nodiscard]] bool Active() const;
    /** What the session is doing, for the play bar. */
    [[nodiscard]] const char* StateText() const;

    /** Starts the selected map on the next frame. */
    void Play() noexcept { mPlayRequested = true; }
    /** Ends the session on the next frame. */
    void Stop() noexcept { mStopRequested = true; }

    /** Applies Play and Stop, and catches the session's own Exit; runs before the game's frame. */
    void BeforeGameFrame();

    /**
     * Test runs from the command line: `/play <map>` plays that map (its folder or scenario name) once the
     * editor is up; `/playseconds <s>` stops it after s seconds of play, `/playcycles <n>` repeats that n
     * times, and `/playquit` closes the editor after the last one.
     */
    void ReadCommandLine();

    /** The command line's runs are over and asked for the editor to close. */
    [[nodiscard]] bool QuitRequested() const noexcept { return mQuitRequested; }

  private:
    void DriveCommandLineRuns();
    /** Logs how long each phase of a session's start took (Preload, Loading, Initialize, ...). */
    void LogPhases();

    moho::EWldFrameAction mLastAction = moho::EWldFrameAction::Inactive;
    std::chrono::steady_clock::time_point mPhaseStart{};
    std::chrono::steady_clock::time_point mSessionStart{};

    std::vector<std::string> mMaps;
    int mSelected = 0;
    bool mPlayRequested = false;
    bool mStopRequested = false;

    bool mAutoRun = false;
    float mAutoSeconds = 0.0f;
    int mAutoCyclesLeft = 0;
    bool mAutoQuit = false;
    bool mQuitRequested = false;
    double mPlayingSince = -1.0;
  };

  /** "SCMP_009" for "/maps/scmp_009/SCMP_009_scenario.lua". */
  [[nodiscard]] std::string MapDisplayName(const std::string& scenarioPath);
} // namespace faf::editor
