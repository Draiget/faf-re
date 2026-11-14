// The Script Editor's knowledge of the game's Lua (src/editor/doc/EdLuaApi.cpp, the table generated from FAF's
// annotated engine Lua): signatures, the word and the call at the caret, completions by context, and typos of known
// functions with their fix.

#include "editor/doc/EdLuaApi.h"

#include <gtest/gtest.h>

#include <algorithm>

using faf::editor::EditDistance;
using faf::editor::EdLuaCall;
using faf::editor::LuaApi;
using faf::editor::LuaApiFind;
using faf::editor::LuaApiForCall;
using faf::editor::LuaCallAt;
using faf::editor::LuaCompletions;
using faf::editor::LuaSignature;
using faf::editor::LuaTypos;
using faf::editor::LuaWordBefore;

namespace
{
  TEST(
    LuaApi,
    TheTableHasTheEngineAndTheScenarioLibraries
  )
  {
    EXPECT_GT(LuaApi().size(), 800u);
    const auto* create = LuaApiFind("", "CreateUnitHPR");
    ASSERT_NE(create, nullptr);
    EXPECT_EQ(
      LuaSignature(*create),
      "CreateUnitHPR(blueprint: UnitId, army: Army, x: number, y: number, z: number, heading: number, pitch: number, "
      "roll: number) -> Unit"
    );
    EXPECT_NE(std::string(create->doc), "");
    ASSERT_NE(LuaApiFind("ScenarioUtils", "CreateArmyGroup"), nullptr);
    EXPECT_EQ(
      LuaSignature(*LuaApiFind("ScenarioUtils", "CreateArmyGroup")).rfind("ScenarioUtils.CreateArmyGroup(", 0), 0u
    );
    EXPECT_EQ(LuaApiFind("", "NoSuchThing"), nullptr);
  }

  TEST(
    LuaApi,
    TheWordAtTheCaret
  )
  {
    const std::string text = "local units = ScenarioUtils.CreateAr";
    const auto word = LuaWordBefore(text, text.size());
    EXPECT_EQ(word.qualifier, "ScenarioUtils");
    EXPECT_EQ(word.separator, '.');
    EXPECT_EQ(word.prefix, "CreateAr");
    EXPECT_EQ(word.start, text.size() - 8);
    const auto method = LuaWordBefore("unit:GetPos", 11);
    EXPECT_EQ(method.separator, ':');
    EXPECT_EQ(method.qualifier, "unit");
    EXPECT_EQ(LuaWordBefore("Create", 6).separator, 0);
  }

  TEST(
    LuaApi,
    CompletionsByContext
  )
  {
    // A module's functions after "ScenarioUtils.".
    const auto module = LuaCompletions(LuaWordBefore("ScenarioUtils.CreateAr", 22), 12);
    ASSERT_FALSE(module.empty());
    EXPECT_STREQ(module.front()->name, "CreateArmyGroup");
    // Globals: names starting with the prefix first, case aside.
    const auto globals = LuaCompletions(LuaWordBefore("createunith", 11), 12);
    ASSERT_FALSE(globals.empty());
    EXPECT_STREQ(globals.front()->name, "CreateUnitHPR");
    for (const auto* entry : globals) {
      EXPECT_STREQ(entry->owner, "") << "no methods among the globals";
    }
    // Methods after ':', each name once though several classes have it.
    const auto methods = LuaCompletions(LuaWordBefore("u:GetPosit", 10), 30);
    ASSERT_FALSE(methods.empty());
    int positions = 0;
    for (const auto* entry : methods) {
      positions += std::string(entry->name) == "GetPosition" ? 1 : 0;
    }
    EXPECT_EQ(positions, 1);
    EXPECT_LE(LuaCompletions(LuaWordBefore("Get", 3), 5).size(), 5u);
  }

  TEST(
    LuaApi,
    TheCallAroundTheCaret
  )
  {
    EdLuaCall call;
    const std::string text = "CreateUnitHPR('uel0001', 'ARMY_1', 10, ";
    ASSERT_TRUE(LuaCallAt(text, text.size(), call));
    EXPECT_EQ(call.name, "CreateUnitHPR");
    EXPECT_EQ(call.argument, 3) << "the fourth argument, y";
    // Nested: the inner call's.
    const std::string nested = "Warp(unit, VECTOR3(1, ";
    ASSERT_TRUE(LuaCallAt(nested, nested.size(), call));
    EXPECT_EQ(call.name, "VECTOR3");
    EXPECT_EQ(call.argument, 1);
    // After the call closed: none.
    EXPECT_FALSE(LuaCallAt("Foo(1, 2) ", 10, call));
    ASSERT_TRUE(LuaCallAt("ScenarioUtils.CreateArmyGroup(", 30, call));
    EXPECT_NE(LuaApiForCall(call.qualifier, call.separator, call.name), nullptr);
  }

  TEST(
    LuaApi,
    TyposOfKnownFunctionsWithTheirFix
  )
  {
    const std::string script = "-- CreatUnitHPR in a comment is fine\n"
                               "function OnPopulate()\n"
                               "  local u = CreatUnitHPR('uel0001', 'ARMY_1', 0, 0, 0, 0, 0, 0)\n"
                               "  MyOwnHelper(u)\n"
                               "  print('CreatUnitHPR(')\n"
                               "end\n"
                               "function MyOwnHelper(u) end\n";
    const auto typos = LuaTypos(script);
    ASSERT_EQ(typos.size(), 1u) << "own functions, comments and strings aren't typos";
    EXPECT_EQ(typos[0].written, "CreatUnitHPR");
    EXPECT_EQ(typos[0].suggestion, "CreateUnitHPR");
    EXPECT_EQ(typos[0].line, 3);
    EXPECT_EQ(script.substr(typos[0].at, typos[0].written.size()), "CreatUnitHPR");
    EXPECT_EQ(EditDistance("kitten", "sitting"), 3);
    EXPECT_TRUE(LuaTypos("ForkThread(Main)\nLOG('x')\n").empty()) << "the game's thread and log functions";
  }

  TEST(
    LuaApi,
    DryRunFindsUnknownFunctionsAndTooManyArguments
  )
  {
    // A module function the table has, with a fixed number of parameters.
    const faf::editor::EdLuaApiEntry* chosen = nullptr;
    for (const faf::editor::EdLuaApiEntry& e : faf::editor::LuaApi()) {
      const std::string params = e.params;
      if (std::string(e.owner) == "ScenarioUtils" && params.find("...") == std::string::npos && !params.empty()) {
        chosen = &e;
        break;
      }
    }
    ASSERT_NE(chosen, nullptr) << "the table has ScenarioUtils' functions";
    const std::string params = chosen->params;
    const int takes = 1 + static_cast<int>(std::count(params.begin(), params.end(), ','));
    std::string args;
    for (int i = 0; i <= takes; ++i) {
      args += (i > 0 ? ", " : "") + std::to_string(i);
    }
    const std::string call = std::string("ScenarioUtils.") + chosen->name;
    const std::string script = "-- ScenarioUtils.Nope() in a comment\n"
                               "local s = 'ScenarioUtils.Nope()'\n" +
      call + "(" + args + ")\n" + "ScenarioUtils.NoSuchFunction(1)\n" + call + "({1, 2, 3})\n" +
      "Unknown.Thing(1, 2, 3, 4, 5)\n";
    const auto problems = faf::editor::CheckLuaApiCalls(script);
    ASSERT_EQ(problems.size(), 2U);
    EXPECT_EQ(problems[0].line, 3);
    EXPECT_EQ(problems[0].call, call) << "one argument too many";
    EXPECT_EQ(problems[1].line, 4);
    EXPECT_NE(problems[1].text.find("no function NoSuchFunction"), std::string::npos);
  }
} // namespace
