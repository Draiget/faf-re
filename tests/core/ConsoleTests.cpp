// moho/console/CConCommand: parsing and unparsing console lines, the typed console variables' argument forms, the
// command registry (lookup, prefix matches, listing, register and unregister), semicolon chains, the saved-command
// history and a failing command. The engine's own test variables (con_TestVar, con_TestVarBool, con_TestVarUByte,
// con_TestVarFloat, con_TestVarStr) are used and put back after each test.

#include "legacy/exceptions/StdExcept.h"
#include "moho/console/CConCommand.h"

#include "gpg/core/utils/Logging.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
  std::vector<std::string> Parse(
    const char* text,
    std::string* remainder = nullptr
  )
  {
    fa::vector<fa::string> tokens;
    fa::string rest;
    moho::CON_ParseCommand(text, tokens, rest);
    if (remainder != nullptr) {
      *remainder = rest.c_str();
    }
    std::vector<std::string> out;
    for (const fa::string& token : tokens) {
      out.emplace_back(token.data(), token.size());
    }
    return out;
  }

  std::string Unparse(
    const std::vector<std::string>& tokens
  )
  {
    fa::vector<fa::string> in;
    for (const std::string& token : tokens) {
      in.push_back(fa::string(token.data(), token.size()));
    }
    return moho::CON_UnparseCommand(in).c_str();
  }

  /** Keeps every log line, to read what a variable printed. */
  class LogLines final : public gpg::LogTarget
  {
  public:
    LogLines()
      : gpg::LogTarget(true)
    {}

    void OnMessage(
      gpg::LogSeverity,
      const fa::string& message,
      const fa::vector<fa::string>&,
      int
    ) override
    {
      mLines.emplace_back(message.c_str());
    }

    bool Has(
      const std::string& text
    ) const
    {
      for (const std::string& line : mLines) {
        if (line.contains(text)) {
          return true;
        }
      }
      return false;
    }

    std::vector<std::string> mLines;
  };

  /** Saves the test variables and restores them after each test. */
  class Console : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      mInt = moho::con_TestVar;
      mBool = moho::con_TestVarBool;
      mByte = moho::con_TestVarUByte;
      mFloat = moho::con_TestVarFloat;
      mStr = moho::con_TestVarStr.c_str();
    }

    void TearDown() override
    {
      moho::con_TestVar = mInt;
      moho::con_TestVarBool = mBool;
      moho::con_TestVarUByte = mByte;
      moho::con_TestVarFloat = mFloat;
      moho::con_TestVarStr = fa::string(mStr.c_str());
    }

  private:
    int mInt = 0;
    bool mBool = false;
    std::uint8_t mByte = 0;
    float mFloat = 0.0f;
    std::string mStr;
  };

  /** A command that always fails, to see the chain go on after it. */
  class FailingCommand final : public moho::CConCommand
  {
  public:
    FailingCommand()
      : moho::CConCommand("test_ConsoleFails", "always throws")
    {}

    void Handle(
      const fa::vector<fa::string>&
    ) override
    {
      ++mCalls;
      throw fa::runtime_error(fa::string("refused on purpose"));
    }

    int mCalls = 0;
  };

  std::uint32_t gTestU32 = 0;
  moho::TConVar<std::uint32_t> gTestU32Var("test_ConsoleU32", "uint32 console test variable", &gTestU32);
} // namespace

TEST(
  ConsoleParse,
  SplitsTokensQuotesCommentsAndTheRestAfterASemicolon
)
{
  std::string rest;
  EXPECT_EQ(Parse("a  b\t\"c d\" e;next cmd", &rest), (std::vector<std::string>{"a", "b", "c d", "e"}));
  EXPECT_EQ(rest, "next cmd");

  EXPECT_EQ(Parse("x y # comment z"), (std::vector<std::string>{"x", "y"}));
  EXPECT_EQ(Parse("x y// comment"), (std::vector<std::string>{"x", "y"}));
  EXPECT_EQ(Parse("x a/b"), (std::vector<std::string>{"x", "a/b"})) << "one slash is part of a token";
  EXPECT_EQ(Parse(R"(say "a \"q\" b\\c")"), (std::vector<std::string>{"say", R"(a "q" b\c)"}));
  EXPECT_EQ(Parse(R"(say \"word)"), (std::vector<std::string>{"say", "\"word"})) << "an escaped quote outside quotes";
  EXPECT_EQ(Parse("say \"#;// inside\""), (std::vector<std::string>{"say", "#;// inside"}));

  EXPECT_TRUE(Parse("").empty());
  EXPECT_TRUE(Parse(nullptr).empty());
  EXPECT_TRUE(Parse("   ", &rest).empty());
  EXPECT_EQ(Parse("only;", &rest), (std::vector<std::string>{"only"}));
  EXPECT_EQ(rest, "") << "nothing after the semicolon";
}

TEST(
  ConsoleParse,
  UnparseQuotesWhatTheParserWouldSplitAndRoundTrips
)
{
  EXPECT_EQ(Unparse({"set", "x", "1"}), "set x 1");
  EXPECT_EQ(Unparse({"say", "two words", ""}), R"(say "two words" "")");
  EXPECT_EQ(Unparse({"q", R"(a"b\c)"}), R"(q "a\"b\\c")");
  EXPECT_EQ(Unparse({"c", "#x", "a;b", "u//v", "t\tu"}), "c \"#x\" \"a;b\" \"u//v\" \"t\tu\"");
  EXPECT_EQ(Unparse({}), "");

  const std::vector<std::string> tokens{"cmd", "a b", R"(q"x)", R"(back\slash)", "#hash", "semi;colon", "plain"};
  EXPECT_EQ(Parse(Unparse(tokens).c_str()), tokens);
}

TEST_F(
  Console,
  IntVariableTakesValuesOperatorsAndSwitchWords
)
{
  struct Step
  {
    const char* command;
    int expected;
  };
  const Step steps[] = {
    {"con_TestVar 5", 5},
    {"con_TestVar = 7", 7},
    {"con_TestVar += 3", 10},
    {"con_TestVar -= 4", 6},
    {"con_TestVar *= 3", 18},
    {"con_TestVar /= 4", 4},
    {"con_TestVar %= 3", 1},
    {"con_TestVar |= 6", 7},
    {"con_TestVar &= 5", 5},
    {"con_TestVar ^= 1", 4},
    {"con_TestVar off", 0},
    {"con_TestVar on", 1},
    {"con_TestVar tog", 0},
    {"con_TestVar tog", 1},
    {"con_TestVar FALSE", 0},
    {"con_TestVar True", 1},
    {"CON_TESTVAR 42", 42}, // names are case-insensitive
  };
  for (const Step& step : steps) {
    moho::CON_Execute(step.command);
    EXPECT_EQ(moho::con_TestVar, step.expected) << step.command;
  }
  moho::CON_Execute("con_TestVar"); // no argument: unchanged
  EXPECT_EQ(moho::con_TestVar, 42);
  moho::CON_Execute("con_TestVar = "); // "=" without a value is read as a number: 0
  EXPECT_EQ(moho::con_TestVar, 0);
}

TEST_F(
  Console,
  ByteAndUInt32VariablesWrapAndReadHex
)
{
  moho::CON_Execute("con_TestVarUByte = 255");
  EXPECT_EQ(moho::con_TestVarUByte, 255);
  moho::CON_Execute("con_TestVarUByte += 1");
  EXPECT_EQ(moho::con_TestVarUByte, 0) << "uint8 wraps";
  moho::CON_Execute("con_TestVarUByte tog");
  EXPECT_EQ(moho::con_TestVarUByte, 1);

  moho::CON_Execute("test_ConsoleU32 0x10");
  EXPECT_EQ(gTestU32, 16u);
  moho::CON_Execute("test_ConsoleU32 *= 0x10");
  EXPECT_EQ(gTestU32, 256u);
  moho::CON_Execute("test_ConsoleU32 = 2000000000");
  EXPECT_EQ(gTestU32, 2000000000u);
}

TEST_F(
  Console,
  FloatVariableTakesValuesAndOperators
)
{
  moho::CON_Execute("con_TestVarFloat = 1.5");
  moho::CON_Execute("con_TestVarFloat += 0.25");
  moho::CON_Execute("con_TestVarFloat -= 0.75");
  moho::CON_Execute("con_TestVarFloat *= 4");
  moho::CON_Execute("con_TestVarFloat /= 2");
  EXPECT_FLOAT_EQ(moho::con_TestVarFloat, 2.0f);
  moho::CON_Execute("con_TestVarFloat 3.5");
  EXPECT_FLOAT_EQ(moho::con_TestVarFloat, 3.5f);
}

TEST_F(
  Console,
  BoolVariableTogglesShowsAndParses
)
{
  LogLines log;
  moho::con_TestVarBool = false;
  moho::CON_Execute("con_TestVarBool");
  EXPECT_TRUE(moho::con_TestVarBool) << "no argument toggles";
  EXPECT_TRUE(log.Has("toggled con_TestVarBool is now on"));
  moho::CON_Execute("con_TestVarBool show");
  EXPECT_TRUE(log.Has("bool con_TestVarBool is on"));

  moho::CON_Execute("con_TestVarBool = 0");
  EXPECT_FALSE(moho::con_TestVarBool);
  moho::CON_Execute("con_TestVarBool ON");
  EXPECT_TRUE(moho::con_TestVarBool);
  moho::CON_Execute("con_TestVarBool false");
  EXPECT_FALSE(moho::con_TestVarBool);
  moho::CON_Execute("con_TestVarBool tog");
  EXPECT_TRUE(moho::con_TestVarBool);
  moho::CON_Execute("con_TestVarBool 0");
  EXPECT_FALSE(moho::con_TestVarBool);
  moho::CON_Execute("con_TestVarBool 5");
  EXPECT_TRUE(moho::con_TestVarBool);
}

TEST_F(
  Console,
  StringVariableAssignsAndPrints
)
{
  LogLines log;
  moho::CON_Execute("con_TestVarStr hello");
  EXPECT_STREQ(moho::con_TestVarStr.c_str(), "hello");
  moho::CON_Execute("con_TestVarStr = \"two words\"");
  EXPECT_STREQ(moho::con_TestVarStr.c_str(), "two words");
  moho::CON_Execute("con_TestVarStr");
  EXPECT_TRUE(log.Has("string con_TestVarStr == two words"));
}

TEST_F(
  Console,
  ChainsRunInOrderAndSurviveUnknownAndFailingCommands
)
{
  LogLines log;
  FailingCommand failing;
  moho::CON_Execute("con_TestVar 1; no_such_command x ; test_ConsoleFails; con_TestVar += 2;con_TestVar *= 5");
  EXPECT_EQ(moho::con_TestVar, 15);
  EXPECT_EQ(failing.mCalls, 1);
  EXPECT_TRUE(log.Has("Error running console command")) << "a failing command is logged";
  EXPECT_TRUE(log.Has("refused on purpose"));

  moho::CON_Executef("con_TestVar = %d", 9);
  EXPECT_EQ(moho::con_TestVar, 9);
  moho::CON_Execute(";;  ;");
  moho::CON_Execute(nullptr);
  moho::CON_Execute("hockey"); // the old unknown-command joke, which prints instead of failing
  EXPECT_EQ(moho::con_TestVar, 9);
}

TEST_F(
  Console,
  SavedCommandRunsAgainAsTheLastCommand
)
{
  moho::con_TestVar = 0;
  moho::CON_ExecuteSave("con_TestVar += 3");
  EXPECT_EQ(moho::con_TestVar, 3);
  moho::CON_ExecuteLastCommand();
  EXPECT_EQ(moho::con_TestVar, 6);
  moho::CON_ExecuteSave("");
  moho::CON_ExecuteLastCommand();
  EXPECT_EQ(moho::con_TestVar, 9) << "an empty command is not saved";
}

TEST(
  ConsoleRegistry,
  FindsByAnyCaseListsAndMatchesPrefixes
)
{
  moho::CConCommand* const command = moho::CON_FindCommand("con_testvar");
  ASSERT_NE(command, nullptr);
  EXPECT_STREQ(command->mName, "con_TestVar");
  EXPECT_EQ(moho::CON_FindCommand("CON_TESTVAR"), command);
  EXPECT_EQ(moho::CON_FindCommand(nullptr), nullptr);
  EXPECT_EQ(moho::CON_FindCommand("con_TestVa"), nullptr) << "lookup is by the whole name";

  const fa::vector<fa::string> matches = moho::CON_GetFindTextMatches("CON_TESTVAR");
  std::vector<std::string> names;
  for (const fa::string& match : matches) {
    names.emplace_back(match.c_str());
  }
  for (const char* expected :
       {"con_TestVar", "con_TestVarBool", "con_TestVarFloat", "con_TestVarStr", "con_TestVarUByte"}) {
    EXPECT_NE(std::find(names.begin(), names.end(), expected), names.end()) << expected;
  }
  EXPECT_TRUE(moho::CON_GetFindTextMatches("").empty());
  EXPECT_TRUE(moho::CON_GetFindTextMatches(nullptr).empty());
  EXPECT_TRUE(moho::CON_GetFindTextMatches("zzz_no_such_prefix").empty());

  fa::string list("before\n");
  moho::CON_GetCommandList(list, true);
  const std::string withDescriptions = list.c_str();
  EXPECT_EQ(withDescriptions.rfind("before\n", 0), 0u) << "the list is appended";
  EXPECT_NE(withDescriptions.find("console commands available:"), std::string::npos);
  EXPECT_NE(withDescriptions.find("  test_ConsoleU32 - uint32 console test variable\n"), std::string::npos);

  fa::string names2;
  moho::CON_GetCommandList(names2, false);
  EXPECT_NE(std::string(names2.c_str()).find("\ntest_ConsoleU32\n"), std::string::npos);
}

TEST(
  ConsoleRegistry,
  CommandsRegisterForTheirLifetimeAndDuplicatesWarn
)
{
  LogLines log;
  int value = 0;
  {
    moho::TConVar<int> scoped("test_ConsoleScoped", "lives for one block", &value);
    moho::CON_Execute("test_ConsoleScoped 4");
    EXPECT_EQ(value, 4);

    moho::TConVar<int> duplicate("test_ConsoleScoped", "second definition", &value);
    EXPECT_TRUE(log.Has("Duplicate definition of console command \"test_ConsoleScoped\""));
    EXPECT_EQ(moho::CON_FindCommand("test_ConsoleScoped"), &scoped) << "the first definition stays";
  }
  // The duplicate, destroyed first, removes the name both share; the original's destructor then finds no entry and
  // warns.
  EXPECT_EQ(moho::CON_FindCommand("test_ConsoleScoped"), nullptr);
  EXPECT_TRUE(log.Has("Deregistering an unknown console command: \"test_ConsoleScoped\""));
  moho::CON_Execute("test_ConsoleScoped 9");
  EXPECT_EQ(value, 4);
}

TEST(
  ConsoleRegistry,
  EchoAndListRunWithoutAConsoleWindow
)
{
  fa::vector<fa::string> args;
  args.push_back(fa::string("echo"));
  moho::CON_Echo(args); // nothing to say
  args.push_back(fa::string("hello"));
  args.push_back(fa::string("world"));
  moho::CON_Echo(args);
  moho::CON_ListCommands(args);
  SUCCEED();
}
