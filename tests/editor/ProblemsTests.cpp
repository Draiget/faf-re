// The map editor's Problems panel (src/editor/ui/EdProblems.cpp): the check's findings and the log's warnings in one
// list, repeats of a log warning merged with a count, the filters, and the counts.

#include "editor/ui/EdProblems.h"

#include <gtest/gtest.h>

using faf::editor::CheckIssue;
using faf::editor::CountProblems;
using faf::editor::EdProblemSource;
using faf::editor::ProblemRows;

namespace
{
  std::vector<CheckIssue> Checks()
  {
    CheckIssue error;
    error.level = CheckIssue::Level::Error;
    error.marker = "ARMY_1";
    error.text = "off the playable area";
    CheckIssue script;
    script.level = CheckIssue::Level::Warning;
    script.file = "x_script.lua";
    script.line = 12;
    script.text = "'=' expected near 'end'";
    CheckIssue note;
    note.level = CheckIssue::Level::Note;
    note.marker = "Mass 3";
    note.text = "overlaps Mass 4";
    return {error, script, note};
  }

  TEST(
    Problems,
    OneListChecksThenLogWithRepeatsMerged
  )
  {
    const auto rows = ProblemRows(Checks(), {"SND: no audio", "Lua: x is nil", "SND: no audio"}, 0x7U, 0x3U);
    ASSERT_EQ(rows.size(), 5u);
    EXPECT_EQ(rows[0].title, "ARMY_1");
    EXPECT_EQ(rows[1].title, "x_script.lua line 12") << "a script finding by file and line";
    EXPECT_EQ(rows[2].index, 2u);
    EXPECT_EQ(rows[3].source, EdProblemSource::Log);
    EXPECT_EQ(rows[3].text, "SND: no audio");
    EXPECT_EQ(rows[3].count, 2) << "the same warning twice: one row";
    EXPECT_EQ(rows[4].text, "Lua: x is nil");
    EXPECT_EQ(rows[4].index, 1u);
    const auto counts = CountProblems(rows);
    EXPECT_EQ(counts.errors, 1);
    EXPECT_EQ(counts.warnings, 3) << "the script finding and the two log rows";
    EXPECT_EQ(counts.notes, 1);
  }

  TEST(
    Problems,
    Filters
  )
  {
    const auto errors = ProblemRows(Checks(), {"w"}, 1U << 0, 0x3U);
    ASSERT_EQ(errors.size(), 1u);
    EXPECT_EQ(errors[0].title, "ARMY_1");
    const auto logOnly = ProblemRows(Checks(), {"w"}, 0x7U, 1U << static_cast<unsigned>(EdProblemSource::Log));
    ASSERT_EQ(logOnly.size(), 1u);
    EXPECT_EQ(logOnly[0].source, EdProblemSource::Log);
    EXPECT_TRUE(ProblemRows(Checks(), {"w"}, 1U << 2, 1U << static_cast<unsigned>(EdProblemSource::Log)).empty())
      << "log rows are warnings: not among the notes";
    EXPECT_TRUE(ProblemRows({}, {}, 0x7U, 0x3U).empty());
  }
} // namespace
