// The map editor's command registry and window chrome (src/editor/ui/EdCommands.cpp, EdWindowChrome.cpp): chords
// written one way, clashes found, commands that can't run say why and don't run, the palette's fuzzy order, and what
// each point of the own title bar is.

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdWindowChrome.h"

#include <gtest/gtest.h>

using faf::editor::CanonicalChord;
using faf::editor::CanonicalKeys;
using faf::editor::EdChromeRect;
using faf::editor::EdCommand;
using faf::editor::EdCommands;
using faf::editor::EdHit;
using faf::editor::EdWindowChrome;
using faf::editor::FuzzyScore;
using faf::editor::MenuAccessKey;
using faf::editor::MenuLabelText;
using faf::editor::SplitChords;
using faf::editor::TitleHit;

namespace
{
  TEST(
    Commands,
    ChordsAreWrittenOneWay
  )
  {
    EXPECT_EQ(CanonicalChord("ctrl+shift+s"), "Ctrl+Shift+S");
    EXPECT_EQ(CanonicalChord("Shift+Control+s"), "Ctrl+Shift+S");
    EXPECT_EQ(CanonicalChord("alt + 1"), "Alt+1");
    EXPECT_EQ(CanonicalChord("del"), "Delete");
    EXPECT_EQ(CanonicalChord("f5"), "F5");
    EXPECT_EQ(CanonicalChord("Shift+F11"), "Shift+F11");
    EXPECT_EQ(CanonicalChord("Ctrl++"), "Ctrl+=");
    EXPECT_EQ(CanonicalChord("Ctrl+="), "Ctrl+=");
    EXPECT_EQ(CanonicalChord("Ctrl+Space"), "Ctrl+Space");
    EXPECT_EQ(CanonicalChord(""), "");
    EXPECT_EQ(CanonicalChord("Ctrl"), "") << "a modifier alone isn't a chord";
    EXPECT_EQ(CanonicalChord("Ctrl+A+B"), "") << "two keys aren't one chord";
    EXPECT_EQ(CanonicalChord("F25"), "");
  }

  TEST(
    Commands,
    KeysHoldMoreThanOneChord
  )
  {
    const std::vector<std::string> expected = {"Ctrl+Y", "Ctrl+Shift+Z"};
    EXPECT_EQ(SplitChords("ctrl+y, ctrl+shift+z, Ctrl+Y"), expected);
    EXPECT_EQ(CanonicalKeys(" ctrl+y ,ctrl+shift+z"), "Ctrl+Y, Ctrl+Shift+Z");
    EXPECT_EQ(CanonicalKeys("nonsense+key, F1"), "F1");
  }

  TEST(
    Commands,
    RunsOnlyWhenItCan
  )
  {
    EdCommands commands;
    int saved = 0;
    bool open = false;
    commands.Add(EdCommand{"file.save", "Save", "File", "ctrl+s", "", [&] {
      ++saved;
    }, [&] {
      return open ? "" : std::string("no map is open");
    }, {}});
    EXPECT_EQ(commands.Find("file.save")->keys, "Ctrl+S");
    EXPECT_EQ(commands.WhyNot("file.save"), "no map is open");
    EXPECT_FALSE(commands.Run("file.save"));
    EXPECT_EQ(saved, 0);
    open = true;
    EXPECT_EQ(commands.WhyNot("file.save"), "");
    EXPECT_TRUE(commands.Run("file.save"));
    EXPECT_EQ(saved, 1);
    EXPECT_FALSE(commands.Run("file.nothing"));
    EXPECT_EQ(commands.WhyNot("file.nothing"), "no such command");
  }

  TEST(
    Commands,
    AddReplacesTheSameId
  )
  {
    EdCommands commands;
    commands.Add(EdCommand{"view.log", "Log", "View", "", "", [] {}, {}, {}});
    commands.Add(EdCommand{"view.log", "Console", "View", "Ctrl+`", "", [] {}, {}, [] {
      return true;
    }});
    ASSERT_EQ(commands.All().size(), 1u);
    EXPECT_EQ(commands.Find("view.log")->title, "Console");
    EXPECT_TRUE(commands.Checked("view.log"));
  }

  TEST(
    Commands,
    ChordsFindTheirCommandAndClashesAreListed
  )
  {
    EdCommands commands;
    commands.Add(EdCommand{"edit.redo", "Redo", "Edit", "Ctrl+Y, Ctrl+Shift+Z", "", [] {}, {}, {}});
    commands.Add(EdCommand{"file.save", "Save", "File", "Ctrl+S", "", [] {}, {}, {}});
    ASSERT_NE(commands.ForChord("control+shift+z"), nullptr);
    EXPECT_EQ(commands.ForChord("control+shift+z")->id, "edit.redo");
    EXPECT_EQ(commands.ForChord("Ctrl+Q"), nullptr);
    EXPECT_TRUE(commands.Clashes().empty());
    ASSERT_TRUE(commands.SetKeys("file.save", "ctrl+y"));
    const auto clashes = commands.Clashes();
    ASSERT_EQ(clashes.size(), 1u);
    EXPECT_EQ(clashes[0].first, "edit.redo");
    EXPECT_EQ(clashes[0].second, "file.save");
    EXPECT_FALSE(commands.SetKeys("file.none", "F1"));
  }

  TEST(
    Commands,
    FuzzyScoreOrdersPaletteMatches
  )
  {
    EXPECT_EQ(FuzzyScore("xyz", "Save as new map folder"), 0);
    EXPECT_GT(FuzzyScore("sav", "Save"), 0);
    // The text starting with the query beats letters spread over it.
    EXPECT_GT(FuzzyScore("save", "Save as new map folder"), FuzzyScore("save", "Show a valid edge"));
    // Word starts count: "rl" for "Reset layout" beats the same letters inside one word.
    EXPECT_GT(FuzzyScore("rl", "Reset layout"), FuzzyScore("rl", "Roll back"));
    EXPECT_GT(FuzzyScore("me", "Material Editor"), 0) << "case and the space between words don't matter";
    EXPECT_GT(FuzzyScore("mat ed", "Material Editor"), 0);
    EXPECT_EQ(FuzzyScore("", "anything"), 1) << "an empty query lists everything";
  }

  TEST(
    Commands,
    MenuLabelsAndTheirAltLetter
  )
  {
    EXPECT_EQ(MenuLabelText("&File"), "File");
    EXPECT_EQ(MenuLabelText("Save && quit"), "Save & quit");
    EXPECT_EQ(MenuAccessKey("&File"), 'F');
    EXPECT_EQ(MenuAccessKey("Mat&erial"), 'E');
    EXPECT_EQ(MenuAccessKey("Play"), 0);
  }

  [[nodiscard]] EdWindowChrome Chrome()
  {
    EdWindowChrome chrome;
    chrome.height = 34.0f;
    chrome.controls = {EdChromeRect{40.0f, 4.0f, 200.0f, 26.0f}};
    chrome.minimize = EdChromeRect{862.0f, 0.0f, 46.0f, 34.0f};
    chrome.maximize = EdChromeRect{908.0f, 0.0f, 46.0f, 34.0f};
    chrome.close = EdChromeRect{954.0f, 0.0f, 46.0f, 34.0f};
    return chrome;
  }

  TEST(
    WindowChrome,
    EachPointOfTheTitleRow
  )
  {
    EdWindowChrome chrome = Chrome();
    const float border = 5.0f;
    EXPECT_EQ(TitleHit(chrome, 500.0f, 20.0f, 1000.0f, border), EdHit::Caption) << "empty row drags the window";
    EXPECT_EQ(TitleHit(chrome, 100.0f, 20.0f, 1000.0f, border), EdHit::Client) << "the menus are the panels'";
    EXPECT_EQ(TitleHit(chrome, 870.0f, 20.0f, 1000.0f, border), EdHit::Minimize);
    EXPECT_EQ(TitleHit(chrome, 930.0f, 20.0f, 1000.0f, border), EdHit::Maximize);
    EXPECT_EQ(TitleHit(chrome, 990.0f, 20.0f, 1000.0f, border), EdHit::Close);
    EXPECT_EQ(TitleHit(chrome, 990.0f, 1.0f, 1000.0f, border), EdHit::Close) << "the buttons reach the top edge";
    EXPECT_EQ(TitleHit(chrome, 500.0f, 2.0f, 1000.0f, border), EdHit::Top);
    EXPECT_EQ(TitleHit(chrome, 3.0f, 2.0f, 1000.0f, border), EdHit::TopLeft);
    EXPECT_EQ(TitleHit(chrome, 500.0f, 40.0f, 1000.0f, border), EdHit::Client) << "below the row";
  }

  TEST(
    WindowChrome,
    MaximisedHasNoTopBandAndNativeCaptionNoRow
  )
  {
    EdWindowChrome chrome = Chrome();
    chrome.maximised = true;
    EXPECT_EQ(TitleHit(chrome, 500.0f, 2.0f, 1000.0f, 5.0f), EdHit::Caption);
    chrome.own = false;
    EXPECT_EQ(TitleHit(chrome, 500.0f, 20.0f, 1000.0f, 5.0f), EdHit::Client);
    EXPECT_EQ(TitleHit(chrome, 990.0f, 20.0f, 1000.0f, 5.0f), EdHit::Client);
  }
} // namespace
