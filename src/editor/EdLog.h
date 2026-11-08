#pragma once

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
    };

    mutable std::mutex mMutex;
    std::deque<Line> mLines;
    int mWarnings = 0;
    bool mAutoScroll = true;
    char mFilter[128]{};
  };
} // namespace faf::editor
