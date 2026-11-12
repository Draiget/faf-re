#include "editor/ui/EdProblems.h"

#include <map>

namespace faf::editor
{
  std::vector<EdProblem> ProblemRows(
    const std::vector<CheckIssue>& checks,
    const std::vector<std::string>& logWarnings,
    const unsigned levels,
    const unsigned sources
  )
  {
    std::vector<EdProblem> rows;
    const auto wanted = [levels](const CheckIssue::Level level) {
      return (levels & (1U << static_cast<unsigned>(level))) != 0;
    };
    if ((sources & (1U << static_cast<unsigned>(EdProblemSource::Check))) != 0) {
      for (std::size_t i = 0; i < checks.size(); ++i) {
        const CheckIssue& issue = checks[i];
        if (!wanted(issue.level)) {
          continue;
        }
        EdProblem row;
        row.source = EdProblemSource::Check;
        row.level = issue.level;
        row.title = issue.file.empty() ? issue.marker : issue.file + " line " + std::to_string(issue.line);
        row.text = issue.text;
        row.index = i;
        rows.push_back(std::move(row));
      }
    }
    if ((sources & (1U << static_cast<unsigned>(EdProblemSource::Log))) != 0 && wanted(CheckIssue::Level::Warning)) {
      std::map<std::string, std::size_t> at; // text -> its row
      for (std::size_t i = 0; i < logWarnings.size(); ++i) {
        const std::string& text = logWarnings[i];
        if (const auto found = at.find(text); found != at.end()) {
          ++rows[found->second].count;
          continue;
        }
        EdProblem row;
        row.source = EdProblemSource::Log;
        row.level = CheckIssue::Level::Warning;
        row.title = "Log";
        row.text = text;
        row.index = i;
        at.emplace(text, rows.size());
        rows.push_back(std::move(row));
      }
    }
    return rows;
  }

  EdProblemCounts CountProblems(
    const std::vector<EdProblem>& rows
  )
  {
    EdProblemCounts counts;
    for (const EdProblem& row : rows) {
      switch (row.level) {
      case CheckIssue::Level::Error:
        ++counts.errors;
        break;
      case CheckIssue::Level::Warning:
        ++counts.warnings;
        break;
      case CheckIssue::Level::Note:
        ++counts.notes;
        break;
      }
    }
    return counts;
  }
} // namespace faf::editor
