#include "editor/doc/EdEditorMods.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace faf::editor
{
  TEST(
    EditorMods,
    ModInfoFieldsAreTheTopLevelKeys
  )
  {
    const std::string text = "-- a comment\n"
                             "name = \"My Tools\"\r\n"
                             "uid = 'abc-123'\n"
                             "editor_mod = true -- turns it into an editor mod\n"
                             "editor_api = 2\n"
                             "requires = {\n"
                             "    name = 'inside a table',\n"
                             "}\n"
                             "description = [[long text]]\n"
                             "if x == 1 then end\n";
    const auto fields = ModInfoFields(text);
    EXPECT_EQ(fields.at("name"), "My Tools");
    EXPECT_EQ(fields.at("uid"), "abc-123");
    EXPECT_EQ(fields.at("editor_mod"), "true");
    EXPECT_EQ(fields.at("editor_api"), "2");
    EXPECT_EQ(fields.at("description"), "long text");
    EXPECT_EQ(fields.count("x"), 0U);
    const EditorModInfo info = ReadEditorModInfo(text, "C:/mods/mytools");
    EXPECT_TRUE(info.editorMod);
    EXPECT_EQ(info.api, 2);
    EXPECT_EQ(info.name, "My Tools") << "not the table's inner name";
    EXPECT_EQ(EditorModIncompatibility(2), "it needs editor API 2; this editor has 1");
    EXPECT_EQ(EditorModIncompatibility(1), "");
    EXPECT_EQ(ReadEditorModInfo("uid = 'x'", "C:/mods/plain").editorMod, false);
    EXPECT_EQ(ReadEditorModInfo("uid = 'x'", "C:/mods/plain").api, 1) << "missing means 1";
  }

  TEST(
    EditorMods,
    OnlyEditorModsAreFoundAndTheEnabledListReadsBack
  )
  {
    const std::filesystem::path root = std::filesystem::temp_directory_path() / "faf_editor_editormods_tests";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "b_tools", ec);
    std::filesystem::create_directories(root / "a_tools", ec);
    std::filesystem::create_directories(root / "game_mod", ec);
    std::filesystem::create_directories(root / "no_uid", ec);
    std::ofstream(root / "b_tools" / "mod_info.lua", std::ios::binary) << "name = 'B'\nuid = 'b'\neditor_mod = true\n";
    std::ofstream(root / "a_tools" / "mod_info.lua", std::ios::binary) << "name = 'A'\nuid = 'a'\neditor_mod = true\n";
    std::ofstream(root / "game_mod" / "mod_info.lua", std::ios::binary) << "name = 'G'\nuid = 'g'\n";
    std::ofstream(root / "no_uid" / "mod_info.lua", std::ios::binary) << "name = 'N'\neditor_mod = true\n";
    const std::vector<EditorModInfo> mods = FindEditorMods(root);
    ASSERT_EQ(mods.size(), 2U);
    EXPECT_EQ(mods[0].name, "A");
    EXPECT_EQ(mods[1].name, "B");
    EXPECT_EQ(mods[0].folder, root / "a_tools");
    EXPECT_EQ(EditorModCommandId("My Tools!", "do.it now"), "mod.mytools.do.itnow");
    const std::set<std::string> enabled = {"a", "b"};
    EXPECT_EQ(ParseEnabledMods(SaveEnabledMods(enabled)), enabled);
    EXPECT_EQ(ParseEnabledMods("# comment\n  a  \r\n\nb\n"), enabled);
  }
} // namespace faf::editor
