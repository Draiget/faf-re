#pragma once

#include <string>
#include <vector>

#include "editor/tools/EdChecks.h"

namespace faf::editor
{
  /** Where a problem came from: the Check panel's run (and test run), or a warning in the log. */
  enum class EdProblemSource
  {
    Check,
    Log,
  };

  /** One row of the Problems panel (design §8: one list from the checks). */
  struct EdProblem
  {
    EdProblemSource source = EdProblemSource::Check;
    CheckIssue::Level level = CheckIssue::Level::Warning;
    std::string title; // the marker, "_script.lua line 12", or "Log"
    std::string text;
    int count = 1;         // the same log warning this many times
    std::size_t index = 0; // into the check's findings (Check), or the first such log line (Log)
  };

  /**
   * The one list: the check's findings in their order, then the log's warnings, each different text once with how
   * many times it came (newest last). `levels` and `sources` filter (bit per Level / Source; all bits: everything).
   */
  [[nodiscard]] std::vector<EdProblem> ProblemRows(
    const std::vector<CheckIssue>& checks,
    const std::vector<std::string>& logWarnings,
    unsigned levels,
    unsigned sources
  );

  /** How many of each level (errors, warnings, notes) a list has, repeats counted once. */
  struct EdProblemCounts
  {
    int errors = 0;
    int warnings = 0;
    int notes = 0;
  };
  [[nodiscard]] EdProblemCounts CountProblems(const std::vector<EdProblem>& rows);
} // namespace faf::editor
