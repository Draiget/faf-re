#pragma once

#include <chrono>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>

#include "gpg/core/utils/Logging.h"

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
    bool mAutoScroll = true;
    bool mShowTimes = false;
    char mFilter[128]{};
  };
} // namespace faf::editor
