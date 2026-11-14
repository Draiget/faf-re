#pragma once

#include <chrono>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"

struct ImGuiInputTextCallbackData;

namespace faf::editor
{
  /**
   * The engine's log (gpg::Logf, Warnf and the rest) as the editor's Log panel shows it: a log
   * target that keeps the last lines, from any thread.
   */
  class EdLog final : public gpg::LogTarget
  {
  public:
    EdLog();
    ~EdLog() override;

    /**
     * Also writes every line from now on to `path`, each with the seconds since the editor started (the
     * `/logtimes <file>` switch, for timing where a play spends its time).
     */
    void WriteTimesTo(const std::string& path);

    void OnMessage(
      gpg::LogSeverity level,
      const fa::string& message,
      const fa::vector<fa::string>& context,
      int previousDepth
    ) override;

    /** Draws the lines into the current ImGui window, with a filter box. */
    void Draw();

    /** How many warnings arrived since the start. */
    [[nodiscard]] int WarningCount() const;
    /** The warnings still kept (the log keeps its newest lines), oldest first: the Problems panel's log rows. */
    [[nodiscard]] std::vector<std::string> Warnings() const;
    /** The filter box's text (the Problems panel shows a warning's lines). */
    void SetFilter(const std::string& text);

    /** From now until EndCapture the warnings (where the game's Lua errors arrive) are also kept apart. */
    void BeginCapture();
    [[nodiscard]] std::vector<std::string> EndCapture();
    /** The mission trace ids (`EDMISSION trace <id>` lines of a test play) that arrived since the last take. */
    [[nodiscard]] std::vector<std::string> TakeMissionTrace();
    /**
     * The console line under the lines (FAF Studio's console): what was typed and Entered, taken once a frame by the
     * app, which runs it (UI Lua; `=expr` prints its value; `sim <code>` in the sim; `con <command>` the engine's).
     */
    [[nodiscard]] bool TakeCommand(
      std::string& out
    )
    {
      if (mCommands.empty()) {
        return false;
      }
      out = std::move(mCommands.front());
      mCommands.pop_front();
      return true;
    }
    /** Test runs: a line as if typed and Entered. */
    void QueueCommand(
      std::string command
    )
    {
      mCommands.push_back(std::move(command));
    }

  private:
    struct Line
    {
      gpg::LogSeverity level;
      std::string text;
      /** Seconds since the editor started. */
      double seconds;
    };

    mutable std::mutex mMutex;
    std::deque<Line> mLines;
    const std::chrono::steady_clock::time_point mStart = std::chrono::steady_clock::now();
    std::FILE* mTimesFile = nullptr;
    int mWarnings = 0;
    bool mCapturing = false;
    std::vector<std::string> mCaptured;
    std::vector<std::string> mMissionTrace;
    bool mAutoScroll = true;
    bool mShowTimes = false;
    /** Whether a line passes the filter and the level toggles. */
    [[nodiscard]] bool Shown(const Line& line) const;
    bool mShowInfo = true;
    bool mShowWarnings = true;
    bool mShowDebug = true;
    char mFilter[128]{};
    char mCommand[512]{};
    std::deque<std::string> mCommands;
    std::vector<std::string> mHistory; // the last 50 lines Entered, oldest first
    int mHistoryAt = -1;               // Up / Down's place in it (-1: the line being typed)
    static int HistoryCallback(::ImGuiInputTextCallbackData* data);
  };
} // namespace faf::editor
