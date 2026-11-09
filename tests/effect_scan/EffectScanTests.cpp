// Engine addition: gpg/gal/backends/d3d11/EffectScan.h finds what the std::regex patterns it replaced
// find, on generated text made of the tokens those patterns care about.

#include <cstdio>
#include <gtest/gtest.h>
#include <cstdint>
#include <random>
#include <regex>
#include <string>
#include <vector>

#include "gpg/gal/backends/d3d11/EffectScan.h"

namespace scan = gpg::gal::d3d11::scan;

namespace
{
  const char* const kTokens[] = {
    "struct", "technique10", "technique11", "technique1", "technique12", "BlendState", "DepthStencilState", "RasterizerState",
    "State", "XBlendState", "FixedFuncVS", "FixedFuncPS", "xFixedFuncVS", "FixedFuncVS2", "float4", "foo", "Bar_1", "x", "faf_foo",
    "faf_Bar_1", "faf_foox", "if", "(", ")", "{", "}", ";", ":", "<", ">", "\"", ",", "=", "POSITION0", " ", " ", " ", " ", "  ", "\n",
    "\t", "\r\n", "\f", "\v", "a b", "\"a>b\"", "<string x=\"a>b\";>", "() {", ") : COLOR0 {", "//", "#", "9", "_", "-", ".",
  };

  std::string Generate(std::mt19937& random)
  {
    constexpr std::size_t tokenCount = sizeof(kTokens) / sizeof(kTokens[0]);
    const int length = 1 + static_cast<int>(random() % 60U);
    std::string text;
    for (int index = 0; index < length; ++index) {
      text += kTokens[random() % tokenCount];
      if (random() % 3U == 0U) {
        text += ' ';
      }
    }
    return text;
  }

  using Rows = std::vector<std::string>;

  Rows RegexRows(const std::string& text, const std::regex& pattern)
  {
    Rows rows;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), pattern); it != std::sregex_iterator(); ++it) {
      std::string row = std::to_string(it->position(0) + it->length(0)) + "|";
      for (std::size_t group = 1U; group < it->size(); ++group) {
        row += (*it)[group].matched ? "+" + (*it)[group].str() : std::string("-");
        row += "|";
      }
      rows.push_back(std::move(row));
    }
    return rows;
  }

  // `expected` holds the regex's rows, `actual` the scanner's.
  void Report(const char* const what, const std::string& text, const Rows& expected, const Rows& actual)
  {
    EXPECT_EQ(expected, actual) << what << " differs on: <<" << text << ">>";
  }

  std::string NameOnly(const std::string& row)
  {
    return row.substr(row.find('|') + 1U);
  }

  void CheckAll(const std::string& text)
  {
    static const std::regex techniqueName(R"(\btechnique1[01]\s+(\w+))");
    static const std::regex structName(R"(\bstruct\s+(\w+))");
    static const std::regex structHead(R"(\bstruct\s+(\w+)\s*\{)");
    static const std::regex functionHead(R"((\w+)\s+(\w+)\s*\(([^(){};]*)\)\s*(:\s*(\w+)\s*)?\{)");
    static const std::regex declaration(R"(\b(BlendState|DepthStencilState|RasterizerState)\s+(\w+)\s*\{)");
    static const std::regex techniqueHead(R"(\btechnique1[01]\s+(\w+)\s*(<(?:[^>"]|"[^"]*")*>)?\s*\{)");
    static const std::regex definitionVS(R"(\b\w+\s+FixedFuncVS\s*\([^;{]*\)\s*(:\s*\w+\s*)?\{)");
    static const std::regex renamedFoo("(\\btechnique1[01]\\s+)faf_foo\\b");

    {
      Rows expected;
      for (const std::string& row : RegexRows(text, techniqueName)) {
        expected.push_back(NameOnly(row));
      }
      Rows actual;
      scan::ForEachTechniqueName(text, [&](const std::string_view name) { actual.push_back("+" + std::string(name) + "|"); });
      Report("techniqueName", text, expected, actual);
    }
    {
      Rows expected;
      for (const std::string& row : RegexRows(text, structName)) {
        expected.push_back(NameOnly(row));
      }
      Rows actual;
      scan::ForEachStructName(text, [&](const std::string_view name) { actual.push_back("+" + std::string(name) + "|"); });
      Report("structName", text, expected, actual);
    }
    {
      const Rows expected = RegexRows(text, structHead);
      Rows actual;
      scan::ForEachStructHead(text, [&](const std::string_view name, const std::size_t open) {
        actual.push_back(std::to_string(open + 1U) + "|+" + std::string(name) + "|");
      });
      Report("structHead", text, expected, actual);
    }
    {
      const Rows expected = RegexRows(text, declaration);
      Rows actual;
      scan::ForEachStateDeclaration(text, [&](const std::string_view kind, const std::string_view name, const std::size_t open) {
        actual.push_back(std::to_string(open + 1U) + "|+" + std::string(kind) + "|+" + std::string(name) + "|");
      });
      Report("stateDeclaration", text, expected, actual);
    }
    {
      Rows expected;
      for (auto it = std::sregex_iterator(text.begin(), text.end(), functionHead); it != std::sregex_iterator(); ++it) {
        expected.push_back(
          (*it)[1].str() + "|" + (*it)[2].str() + "|" + (*it)[3].str() + "|" + ((*it)[5].matched ? "+" + (*it)[5].str() : std::string("-"))
        );
      }
      Rows actual;
      scan::ForEachFunctionHead(
        text,
        [&](const std::string_view type, const std::string_view name, const std::string_view parameters, const std::string_view semantic, const bool hasSemantic) {
          actual.push_back(
            std::string(type) + "|" + std::string(name) + "|" + std::string(parameters) + "|" + (hasSemantic ? "+" + std::string(semantic) : std::string("-"))
          );
        }
      );
      Report("functionHead", text, expected, actual);
    }
    {
      Rows expected;
      Rows actual;
      std::size_t from = 0U;
      for (int guard = 0; guard < 100; ++guard) {
        std::smatch match;
        const auto begin = text.cbegin() + static_cast<std::ptrdiff_t>(from);
        const bool regexFound = std::regex_search(begin, text.cend(), match, techniqueHead);
        std::size_t start = 0U;
        std::size_t open = 0U;
        std::string_view name;
        const bool scanFound = scan::FindTechniqueHead(text, from, start, open, name);
        if (regexFound) {
          const std::size_t regexStart = from + static_cast<std::size_t>(match.position(0));
          expected.push_back(std::to_string(regexStart) + "|" + std::to_string(regexStart + static_cast<std::size_t>(match.length(0)) - 1U) + "|" + match[1].str());
        }
        if (scanFound) {
          actual.push_back(std::to_string(start) + "|" + std::to_string(open) + "|" + std::string(name));
        }
        if (!regexFound || !scanFound) {
          break;
        }
        from = open + 1U;
      }
      Report("techniqueHead", text, expected, actual);
    }
    {
      const Rows expected{std::regex_search(text, definitionVS) ? "yes" : "no"};
      const Rows actual{scan::HasFunctionDefinition(text, "FixedFuncVS") ? "yes" : "no"};
      Report("functionDefinition", text, expected, actual);
    }
    {
      const Rows expected{std::regex_replace(text, renamedFoo, "$1foo")};
      const Rows actual{scan::RestoreRenamedTechnique(text, "foo")};
      Report("renamedTechnique", text, expected, actual);
    }
  }
} // namespace

TEST(Existing_EffectScan, MatchesRegexTokens)
{
  std::mt19937 random(0x5EED2007U);
  constexpr int kCases = 60000;
  for (int index = 0; index < kCases; ++index) {
    CheckAll(Generate(random));
    // One differing text names the bug; the rest of the run would repeat it.
    ASSERT_FALSE(HasFailure()) << "generated text " << index << " of " << kCases;
  }
}
