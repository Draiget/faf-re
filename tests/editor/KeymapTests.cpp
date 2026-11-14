// The map editor's keymap (src/editor/ui/EdKeymap.cpp): keys.ini read and written (only what differs from the
// defaults, problems said and the rest kept), the two key slots of Settings > Keys, Windows key codes named as the
// registry writes keys, which chords the panels keep for text fields and navigation, and a key shared by two commands.

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdKeymap.h"

#include <gtest/gtest.h>

using faf::editor::ChordOf;
using faf::editor::EdCommand;
using faf::editor::EdCommands;
using faf::editor::EdKeyDefaults;
using faf::editor::KeyDefaults;
using faf::editor::KeySlot;
using faf::editor::PanelsKeepChord;
using faf::editor::ReadKeymap;
using faf::editor::RunsOverGame;
using faf::editor::VirtualKeyName;
using faf::editor::WithKeySlot;
using faf::editor::WriteKeymap;

namespace
{
  EdCommands Registry()
  {
    EdCommands commands;
    commands.Add(EdCommand{"file.save", "Save", "File", "Ctrl+S"});
    commands.Add(EdCommand{"edit.redo", "Redo", "Edit", "Ctrl+Y, Ctrl+Shift+Z"});
    commands.Add(EdCommand{"tool.0", "Select tool", "Tools", "1"});
    commands.Add(EdCommand{"view.log", "Log", "View", ""});
    return commands;
  }

  TEST(
    Keymap,
    WritesOnlyWhatDiffersFromTheDefaults
  )
  {
    EdCommands commands = Registry();
    const EdKeyDefaults defaults = KeyDefaults(commands);
    const std::string none = WriteKeymap(commands, defaults);
    EXPECT_EQ(none.substr(none.size() - 7), "[Keys]\n") << "nothing changed, no lines after the header: " << none;

    ASSERT_TRUE(commands.SetKeys("view.log", "ctrl+shift+l"));
    ASSERT_TRUE(commands.SetKeys("tool.0", ""));
    const std::string text = WriteKeymap(commands, defaults);
    EXPECT_NE(text.find("view.log=Ctrl+Shift+L\n"), std::string::npos) << text;
    EXPECT_NE(text.find("tool.0=\n"), std::string::npos) << "a key taken away is written empty: " << text;
    EXPECT_EQ(text.find("file.save"), std::string::npos) << text;

    // Read back over fresh defaults: the same keys.
    EdCommands again = Registry();
    EXPECT_TRUE(ReadKeymap(again, text).empty());
    EXPECT_EQ(again.Find("view.log")->keys, "Ctrl+Shift+L");
    EXPECT_EQ(again.Find("tool.0")->keys, "");
    EXPECT_EQ(again.Find("file.save")->keys, "Ctrl+S");
  }

  TEST(
    Keymap,
    ReadSaysWhatItCantUseAndKeepsTheRest
  )
  {
    EdCommands commands = Registry();
    const std::vector<std::string> problems = ReadKeymap(
      commands, "; comment\r\n[Keys]\r\nno.such=F2\r\nfile.save = ctrl+s, Hyper+Q, F2\r\njust text\r\nview.log=F9\r\n"
    );
    ASSERT_EQ(problems.size(), 3u);
    EXPECT_NE(problems[0].find("no command no.such"), std::string::npos) << problems[0];
    EXPECT_NE(problems[1].find("Hyper+Q"), std::string::npos) << problems[1];
    EXPECT_NE(problems[2].find("no '='"), std::string::npos) << problems[2];
    EXPECT_EQ(commands.Find("file.save")->keys, "Ctrl+S, F2") << "the chord it can't read left out, the others kept";
    EXPECT_EQ(commands.Find("view.log")->keys, "F9") << "lines after a bad one still apply";
  }

  TEST(
    Keymap,
    TwoSlotsPerCommand
  )
  {
    EXPECT_EQ(KeySlot("Ctrl+Y, Ctrl+Shift+Z", 0), "Ctrl+Y");
    EXPECT_EQ(KeySlot("Ctrl+Y, Ctrl+Shift+Z", 1), "Ctrl+Shift+Z");
    EXPECT_EQ(KeySlot("Ctrl+Y", 1), "");
    EXPECT_EQ(KeySlot("", 0), "");

    EXPECT_EQ(WithKeySlot("Ctrl+Y", 1, "f4"), "Ctrl+Y, F4") << "an empty second slot is filled";
    EXPECT_EQ(WithKeySlot("", 1, "F4"), "F4") << "with no first, the key goes first";
    EXPECT_EQ(WithKeySlot("Ctrl+Y, Ctrl+Shift+Z", 0, "F4"), "F4, Ctrl+Shift+Z");
    EXPECT_EQ(WithKeySlot("Ctrl+Y, Ctrl+Shift+Z", 0, ""), "Ctrl+Shift+Z") << "cleared: the second moves up";
    EXPECT_EQ(WithKeySlot("Ctrl+Y, Ctrl+Shift+Z", 1, ""), "Ctrl+Y");
    EXPECT_EQ(WithKeySlot("Ctrl+Y, Ctrl+Shift+Z", 0, "Ctrl+Shift+Z"), "Ctrl+Shift+Z") << "not doubled: it moves";
    EXPECT_EQ(WithKeySlot("A, B, C", 1, "D"), "A, D, C") << "chords past the two slots are kept";
    EXPECT_EQ(WithKeySlot("A", 2, "D"), "A") << "no third slot";
  }

  TEST(
    Keymap,
    WindowsKeyCodesAreNamedAsTheRegistryWritesThem
  )
  {
    EXPECT_EQ(VirtualKeyName('S'), "S");
    EXPECT_EQ(VirtualKeyName('7'), "7");
    EXPECT_EQ(VirtualKeyName(0x74), "F5");  // VK_F5
    EXPECT_EQ(VirtualKeyName(0x87), "F24"); // VK_F24
    EXPECT_EQ(VirtualKeyName(0x2E), "Delete");
    EXPECT_EQ(VirtualKeyName(0x24), "Home");
    EXPECT_EQ(VirtualKeyName(0xBB), "="); // VK_OEM_PLUS
    EXPECT_EQ(VirtualKeyName(0xBD), "-"); // VK_OEM_MINUS
    EXPECT_EQ(VirtualKeyName(0x11), "");  // VK_CONTROL alone
    EXPECT_EQ(VirtualKeyName(0x10), "");  // VK_SHIFT alone
    EXPECT_EQ(VirtualKeyName(0xBC), "");  // VK_OEM_COMMA: keys are split at commas
    EXPECT_EQ(VirtualKeyName(0x61), "");  // VK_NUMPAD1

    EXPECT_EQ(ChordOf(VirtualKeyName('S'), true, false, false), "Ctrl+S");
    EXPECT_EQ(ChordOf(VirtualKeyName('Z'), true, true, false), "Ctrl+Shift+Z");
    EXPECT_EQ(ChordOf(VirtualKeyName(0xBB), true, false, false), "Ctrl+=");
    EXPECT_EQ(ChordOf("", true, false, false), "") << "a modifier alone is no chord";

    // What a key press gives finds its command.
    EdCommands commands = Registry();
    ASSERT_NE(commands.ForChord(ChordOf(VirtualKeyName('Z'), true, true, false)), nullptr);
    EXPECT_EQ(commands.ForChord(ChordOf(VirtualKeyName('Z'), true, true, false))->id, "edit.redo");
    EXPECT_EQ(commands.ForChord(ChordOf(VirtualKeyName('1'), false, false, false))->id, "tool.0");
  }

  TEST(
    Keymap,
    PanelsKeepTheirOwnKeys
  )
  {
    // ImGui's keyboard navigation, always.
    EXPECT_TRUE(PanelsKeepChord("Up", false));
    EXPECT_TRUE(PanelsKeepChord("Enter", false));
    EXPECT_TRUE(PanelsKeepChord("Escape", false));
    EXPECT_FALSE(PanelsKeepChord("1", false)) << "not typing: a digit picks a tool";
    EXPECT_FALSE(PanelsKeepChord("Ctrl+Z", false));
    EXPECT_FALSE(PanelsKeepChord("Delete", false));
    // A text field.
    EXPECT_TRUE(PanelsKeepChord("1", true));
    EXPECT_TRUE(PanelsKeepChord("Shift+A", true));
    EXPECT_TRUE(PanelsKeepChord("Delete", true));
    EXPECT_TRUE(PanelsKeepChord("Ctrl+Z", true));
    EXPECT_TRUE(PanelsKeepChord("Ctrl+Shift+Z", true));
    EXPECT_TRUE(PanelsKeepChord("Ctrl+V", true));
    EXPECT_TRUE(PanelsKeepChord("Ctrl+Left", true));
    EXPECT_FALSE(PanelsKeepChord("Ctrl+S", true)) << "saving works while typing";
    EXPECT_FALSE(PanelsKeepChord("F5", true)) << "function keys work while typing";
    EXPECT_FALSE(PanelsKeepChord("Ctrl+K", true));

    EXPECT_TRUE(RunsOverGame("play.toggle"));
    EXPECT_TRUE(RunsOverGame("play.editorview"));
    EXPECT_FALSE(RunsOverGame("file.save")) << "a play keeps Ctrl+S for the game";
  }

  TEST(
    Keymap,
    AKeySharedByTwoCommandsListsBoth
  )
  {
    EdCommands commands = Registry();
    ASSERT_TRUE(commands.SetKeys("view.log", "Ctrl+S"));
    const auto both = commands.AllForChord("ctrl+s");
    ASSERT_EQ(both.size(), 2u);
    EXPECT_EQ(both[0]->id, "file.save") << "the registry's order";
    EXPECT_EQ(both[1]->id, "view.log");
    const auto clashes = commands.Clashes();
    ASSERT_EQ(clashes.size(), 1u);
    EXPECT_EQ(clashes[0].first, "file.save");
    EXPECT_EQ(clashes[0].second, "view.log");
    EXPECT_TRUE(commands.AllForChord("F12").empty());
  }
} // namespace
