// The Script Editor's Lua colouring (src/editor/doc/EdLuaSyntax.cpp).

#include "editor/doc/EdLuaSyntax.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::LuaSpanKind;

  /** The kind at the start of `piece` in `text`. */
  LuaSpanKind KindAt(
    const std::string& text,
    const std::string& piece
  )
  {
    const std::size_t at = text.find(piece);
    for (const auto& span : faf::editor::LuaSpans(text)) {
      if (span.start <= at && at < span.end) {
        return span.kind;
      }
    }
    return LuaSpanKind::Plain;
  }

  TEST(
    LuaSyntax,
    SpansCoverTheTextInOrder
  )
  {
    const std::string text = "local x = 1 -- one\nfunction OnPopulate()\n  LOG('hi', x)\nend\n";
    const auto spans = faf::editor::LuaSpans(text);
    ASSERT_FALSE(spans.empty());
    std::size_t at = 0;
    for (const auto& span : spans) {
      EXPECT_EQ(span.start, at);
      EXPECT_LT(span.start, span.end);
      at = span.end;
    }
    EXPECT_EQ(at, text.size());
  }

  TEST(
    LuaSyntax,
    Kinds
  )
  {
    const std::string text =
      "local w = ScenarioInfo.Options.optional_wreckage or 1\n"
      "if w > 1 then ScenarioUtils.CreateArmyGroup('ARMY_17', \"Optional_Wreckage_\" .. w, true) end\n"
      "# GPG's comment\n"
      "Foo{ a = nil }\n";
    EXPECT_EQ(KindAt(text, "local"), LuaSpanKind::Keyword);
    EXPECT_EQ(KindAt(text, "ScenarioInfo"), LuaSpanKind::Engine);
    EXPECT_EQ(KindAt(text, "optional_wreckage"), LuaSpanKind::Plain);
    EXPECT_EQ(KindAt(text, "1\n"), LuaSpanKind::Number);
    EXPECT_EQ(KindAt(text, "CreateArmyGroup"), LuaSpanKind::Call);
    EXPECT_EQ(KindAt(text, "'ARMY_17'"), LuaSpanKind::String);
    EXPECT_EQ(KindAt(text, "\"Optional"), LuaSpanKind::String);
    EXPECT_EQ(KindAt(text, "true"), LuaSpanKind::Constant);
    EXPECT_EQ(KindAt(text, "# GPG"), LuaSpanKind::Comment);
    EXPECT_EQ(KindAt(text, "Foo"), LuaSpanKind::Call);
    EXPECT_EQ(KindAt(text, "nil"), LuaSpanKind::Constant);
    EXPECT_EQ(KindAt(text, ".."), LuaSpanKind::Operator);
  }

  TEST(
    LuaSyntax,
    LongCommentsAndStringsRunOverLines
  )
  {
    const std::string text = "--[[ a\nb ]] x = [==[ c\n]] d ]==] y";
    EXPECT_EQ(KindAt(text, "b ]]"), LuaSpanKind::Comment);
    EXPECT_EQ(KindAt(text, "x ="), LuaSpanKind::Plain);
    EXPECT_EQ(KindAt(text, "]] d"), LuaSpanKind::String);
    EXPECT_EQ(KindAt(text, "y"), LuaSpanKind::Plain);
    // A string that doesn't end stops at its line.
    const std::string open = "s = 'abc\nlocal";
    EXPECT_EQ(KindAt(open, "local"), LuaSpanKind::Keyword);
  }
} // namespace
