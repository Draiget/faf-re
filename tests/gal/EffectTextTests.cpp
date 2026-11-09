// gpg/gal/effects/EffectText.h: the scanner the effect parser and the HLSL rewrite share. Inputs are
// written the way the effect preprocessor leaves them (every token spaced); the expected values are
// what the header promises for each helper, worked out by hand.

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "gpg/gal/effects/EffectText.h"

namespace text = gpg::gal::effects::text;

TEST(GalEffectText, LowerTrimAndSqueeze)
{
  EXPECT_EQ(text::Lower("AbC_1 XyZ"), "abc_1 xyz");
  EXPECT_EQ(text::Trim("  \t a b \r\n"), "a b");
  EXPECT_EQ(text::Trim(""), "");
  EXPECT_EQ(text::Trim(" \t\n "), "");
  EXPECT_EQ(text::Squeeze("  a \t b\n\nc  "), "a b c");
  EXPECT_EQ(text::Squeeze("   "), "");
  EXPECT_EQ(text::Squeeze("abc"), "abc");
}

TEST(GalEffectText, IdentifierCharactersAndLeadingWords)
{
  for (const char c : std::string_view("azAZ09_")) {
    EXPECT_TRUE(text::IsIdentifierChar(c)) << c;
  }
  for (const char c : std::string_view(" .(<{;:\"-")) {
    EXPECT_FALSE(text::IsIdentifierChar(c)) << c;
  }
  EXPECT_TRUE(text::StartsWithWord("technique Draw", "technique"));
  EXPECT_TRUE(text::StartsWithWord("technique", "technique"));
  EXPECT_TRUE(text::StartsWithWord("struct{", "struct"));
  EXPECT_FALSE(text::StartsWithWord("technique10 Draw", "technique"));
  EXPECT_FALSE(text::StartsWithWord("tech", "technique"));
  EXPECT_FALSE(text::StartsWithWord(" technique", "technique"));
}

TEST(GalEffectText, MatchingFindsTheCloserAndSkipsStrings)
{
  const std::string braces = "{ a { b } c } d";
  EXPECT_EQ(text::Matching(braces, 0U), 12U);
  EXPECT_EQ(text::Matching(braces, 4U), 8U);

  const std::string quoted = "( \")\" , x )";
  EXPECT_EQ(text::Matching(quoted, 0U), quoted.size() - 1U);

  const std::string annotation = "< string s = \"a>b\"; int n = 1; > = 2";
  EXPECT_EQ(text::Matching(annotation, 0U), annotation.find("; >") + 2U);

  const std::string square = "[ [ 1 ] ]";
  EXPECT_EQ(text::Matching(square, 0U), 8U);

  EXPECT_EQ(text::Matching("{ never closed", 0U), std::string_view::npos);
  EXPECT_EQ(text::Matching("( ( )", 0U), std::string_view::npos);
}

TEST(GalEffectText, SplitTopLevelKeepsBracketsAndStringsWhole)
{
  const std::vector<std::string> parts = text::SplitTopLevel("a, f(b, c), {d, e}, [g, h], \"i, j\"", ',');
  ASSERT_EQ(parts.size(), 5U);
  EXPECT_EQ(parts[0], "a");
  EXPECT_EQ(parts[1], " f(b, c)");
  EXPECT_EQ(parts[2], " {d, e}");
  EXPECT_EQ(parts[3], " [g, h]");
  EXPECT_EQ(parts[4], " \"i, j\"");

  EXPECT_EQ(text::SplitTopLevel("", ';'), std::vector<std::string>{""});
  EXPECT_EQ(text::SplitTopLevel("a;", ';'), (std::vector<std::string>{"a", ""}));
  EXPECT_EQ(text::SplitTopLevel("a;;b", ';'), (std::vector<std::string>{"a", "", "b"}));
}

TEST(GalEffectText, ParseNumbersReadsEveryLiteralForm)
{
  EXPECT_EQ(text::ParseNumbers("float4 ( 1 , 0.5 , - 2 , 1 )"), (std::vector<float>{1.0f, 0.5f, -2.0f, 1.0f}));
  EXPECT_EQ(text::ParseNumbers("{ 1 , 2 }"), (std::vector<float>{1.0f, 2.0f}));
  EXPECT_EQ(text::ParseNumbers("true , false"), (std::vector<float>{1.0f, 0.0f}));
  EXPECT_EQ(text::ParseNumbers("0x10 0X1f 0xFF"), (std::vector<float>{16.0f, 31.0f, 255.0f}));
  EXPECT_EQ(text::ParseNumbers("1.5f 2h 3u 4L"), (std::vector<float>{1.5f, 2.0f, 3.0f, 4.0f}));
  EXPECT_EQ(text::ParseNumbers("1e-3 2.5E+2"), (std::vector<float>{0.001f, 250.0f}));
  EXPECT_EQ(text::ParseNumbers("+ .5 - .25"), (std::vector<float>{0.5f, -0.25f}));
  // Identifiers with digits are names, not numbers; a sign without a digit after it is no number.
  EXPECT_TRUE(text::ParseNumbers("float2x2 TEXCOORD3 x - y truevalue").empty());
  EXPECT_TRUE(text::ParseNumbers("").empty());
}

TEST(GalEffectText, EvaluateConstantFoldsIntegerAndFloatExpressions)
{
  const struct
  {
    const char* text;
    double value;
  } cases[] = {
    {"0x01 + 0x02 + 0x10 + 0x04", 23.0}, // the header's example: renderStage
    {"1 + 2 * 3", 7.0},
    {"( 1 + 2 ) * 3", 9.0},
    {"( 1 << 4 ) | 3", 19.0},
    {"7 & ~2", 5.0},
    {"6 ^ 3", 5.0},
    {"1 | 2 & 3", 3.0},
    {"10 % 4", 2.0},
    {"256 >> 4", 16.0},
    {"-3 * 2", -6.0},
    {"+4 - -1", 5.0},
    {"1.5f * 2", 3.0},
    {"true + true", 2.0},
    {"false", 0.0},
    {"0xFFFFFFFF", 4294967295.0},
    {"7 / 2", 3.5},
    {"1 / 0", 0.0},  // a zero divisor folds to zero instead of failing
    {"5 % 0", 0.0},
  };
  for (const auto& entry : cases) {
    double value = -1.0;
    EXPECT_TRUE(text::EvaluateConstant(entry.text, value)) << entry.text;
    EXPECT_DOUBLE_EQ(value, entry.value) << entry.text;
  }

  for (const char* const refused : {"", "abc", "( 1 + 2", "1 +", "1 2", "1 < 2", "1 || 2", "float4 ( 1 , 2 )"}) {
    double value = 0.0;
    EXPECT_FALSE(text::EvaluateConstant(refused, value)) << refused;
  }
}

TEST(GalEffectText, ReplaceIdentifierSkipsLongerNamesAndMembers)
{
  EXPECT_EQ(text::ReplaceIdentifier("a + ab + a.a + b . a + _a + a", "a", "X"), "X + ab + X.a + b . a + _a + X");
  EXPECT_EQ(text::ReplaceIdentifier("sampler2D s; samplerCUBE c;", "sampler2D", "faf_sampler"), "faf_sampler s; samplerCUBE c;");
  EXPECT_EQ(text::ReplaceIdentifier("", "a", "b"), "");
  EXPECT_EQ(text::ReplaceIdentifier("nothing here", "zz", "y"), "nothing here");
}

TEST(GalEffectText, ContainsIdentifierWantsAWholeWord)
{
  EXPECT_TRUE(text::ContainsIdentifier("row_major float4x4 m", "float4x4"));
  EXPECT_TRUE(text::ContainsIdentifier("column_major", "column_major"));
  EXPECT_FALSE(text::ContainsIdentifier("float4x4", "float4"));
  EXPECT_FALSE(text::ContainsIdentifier("xfloat4", "float4"));
  EXPECT_FALSE(text::ContainsIdentifier("", "a"));
}

TEST(GalEffectText, HasTopLevelAssignmentIgnoresComparisonsAndNestedText)
{
  EXPECT_TRUE(text::HasTopLevelAssignment("float a = 1"));
  EXPECT_TRUE(text::HasTopLevelAssignment("string s = \"=\""));
  EXPECT_FALSE(text::HasTopLevelAssignment("a == b"));
  EXPECT_FALSE(text::HasTopLevelAssignment("a != b"));
  EXPECT_FALSE(text::HasTopLevelAssignment("a <= b"));
  EXPECT_FALSE(text::HasTopLevelAssignment("a >= b"));
  EXPECT_FALSE(text::HasTopLevelAssignment("f ( a = 1 )"));
  EXPECT_FALSE(text::HasTopLevelAssignment("x < string s = \"q\" ; >"));
  EXPECT_FALSE(text::HasTopLevelAssignment("\"a = b\""));
  EXPECT_FALSE(text::HasTopLevelAssignment(""));
}

TEST(GalEffectText, SplitItemsSeparatesDeclarationsBlocksAndDirectives)
{
  const std::string source =
    "float4 a : COLOR < string UIName = \"A;B\"; > = float4(1, 2, 3, 4);\n"
    "#define X 1 \\\n"
    "   + 2\n"
    "struct S { float x; };\n"
    "float f(float v) { return v; }\n"
    "sampler2D s = sampler_state { Texture = <t>; };\n"
    "// a comment ; with { braces\n"
    "/* and ; another */ float k[] = { 1, 2 };\n";
  const std::vector<text::Item> items = text::SplitItems(source);
  ASSERT_EQ(items.size(), 6U);

  EXPECT_EQ(items[0].head, "float4 a : COLOR < string UIName = \"A;B\"; > = float4(1, 2, 3, 4)");
  EXPECT_FALSE(items[0].braced);
  EXPECT_EQ(items[0].begin, 0U);
  EXPECT_EQ(items[0].end, source.find(";\n") + 1U);

  EXPECT_TRUE(items[1].directive);
  EXPECT_EQ(items[1].head, "#define X 1 \\\n   + 2");

  EXPECT_TRUE(items[2].braced);
  EXPECT_EQ(items[2].head, "struct S");
  EXPECT_EQ(items[2].body, " float x; ");
  EXPECT_EQ(source.substr(items[2].begin, items[2].end - items[2].begin), "struct S { float x; };");

  EXPECT_TRUE(items[3].braced);
  EXPECT_EQ(items[3].head, "float f(float v)");
  EXPECT_EQ(items[3].body, " return v; ");
  EXPECT_EQ(source.substr(items[3].begin, items[3].end - items[3].begin), "float f(float v) { return v; }");

  EXPECT_EQ(items[4].head, "sampler2D s = sampler_state");
  EXPECT_EQ(items[4].body, " Texture = <t>; ");

  EXPECT_TRUE(items[5].braced);
  EXPECT_EQ(items[5].head, "float k[] =");
  EXPECT_EQ(items[5].body, " 1, 2 ");
  EXPECT_EQ(items[5].end, source.size() - 1U);
}

TEST(GalEffectText, SplitItemsTreatsAComparisonInAnInitializerAsText)
{
  // The '<' has a '>' in the next statement; it must not swallow the ';' between them.
  const std::vector<text::Item> items = text::SplitItems("static const bool b = 1 < 2; static const bool c = 3 > 1;");
  ASSERT_EQ(items.size(), 2U);
  EXPECT_EQ(items[0].head, "static const bool b = 1 < 2");
  EXPECT_EQ(items[1].head, "static const bool c = 3 > 1");

  const std::vector<text::Item> unmatched = text::SplitItems("bool d = 1 < 2; float e;");
  ASSERT_EQ(unmatched.size(), 2U);
  EXPECT_EQ(unmatched[1].head, "float e");
}

TEST(GalEffectText, SplitItemsRefusesUnbalancedBraces)
{
  EXPECT_THROW(static_cast<void>(text::SplitItems("float f() { return 1;")), std::runtime_error);
  EXPECT_THROW(static_cast<void>(text::SplitItems("}}}{{")), std::runtime_error);
  EXPECT_TRUE(text::SplitItems("").empty());
  EXPECT_TRUE(text::SplitItems(" ;;; ").empty());
}
