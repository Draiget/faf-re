// The map editor's autosave, recovery and backups (src/editor/doc/EdAutosave.cpp): the note an autosave keeps, when
// one is due, backups of all of a map's files kept to a count, and Recover putting an autosave back after a backup.

#include "editor/doc/EdAutosave.h"

#include <fstream>
#include <random>
#include <sstream>

#include <gtest/gtest.h>

using faf::editor::AutosaveDue;
using faf::editor::AutosaveNote;
using faf::editor::BackupMapFolder;
using faf::editor::BackupsToRemove;
using faf::editor::EdAutosaveEntry;
using faf::editor::ListAutosaves;
using faf::editor::MapFolderFiles;
using faf::editor::ReadAutosaveNote;
using faf::editor::RemoveAutosave;
using faf::editor::RestoreAutosave;

namespace
{
  namespace fs = std::filesystem;

  /** A fresh folder under the system's temp folder, removed afterwards. */
  struct TempFolder
  {
    fs::path path;
    TempFolder()
    {
      std::random_device random;
      path = fs::temp_directory_path() / ("faf_autosave_test_" + std::to_string(random()));
      fs::create_directories(path);
    }
    ~TempFolder()
    {
      std::error_code ignored;
      fs::remove_all(path, ignored);
    }
  };

  void WriteFile(
    const fs::path& file,
    const std::string& text
  )
  {
    fs::create_directories(file.parent_path());
    std::ofstream(file, std::ios::binary) << text;
  }

  std::string ReadFile(
    const fs::path& file
  )
  {
    std::ifstream in(file, std::ios::binary);
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
  }

  TEST(
    Autosave,
    NoteRoundTrip
  )
  {
    EdAutosaveEntry entry;
    entry.scenario = "/maps/zz_test/zz_test_scenario.lua";
    entry.title = "Test map";
    entry.disk = "C:/maps/zz_test";
    entry.time = 1763000000;
    EdAutosaveEntry read;
    ASSERT_TRUE(ReadAutosaveNote(AutosaveNote(entry), read));
    EXPECT_EQ(read.scenario, entry.scenario);
    EXPECT_EQ(read.title, entry.title);
    EXPECT_EQ(read.disk.generic_string(), "C:/maps/zz_test");
    EXPECT_EQ(read.time, entry.time);
    EdAutosaveEntry missing;
    EXPECT_FALSE(ReadAutosaveNote("title=x\r\ntime=5\r\n", missing)) << "no scenario, no disk: not one";
  }

  TEST(
    Autosave,
    DueWhenChangedLongEnoughAndIdle
  )
  {
    EXPECT_TRUE(AutosaveDue(100.0, true, 30.0, 90.0, 60.0, 3.0));
    EXPECT_FALSE(AutosaveDue(100.0, false, 30.0, 90.0, 60.0, 3.0)) << "nothing unsaved";
    EXPECT_FALSE(AutosaveDue(100.0, true, 50.0, 90.0, 60.0, 3.0)) << "a minute hasn't passed";
    EXPECT_FALSE(AutosaveDue(100.0, true, 30.0, 98.5, 60.0, 3.0)) << "something was pressed 1.5 s ago";
    EXPECT_FALSE(AutosaveDue(100.0, true, 30.0, 90.0, 0.0, 3.0)) << "no interval: off";
  }

  TEST(
    Autosave,
    BackupsKeepTheNewest
  )
  {
    const std::vector<fs::path> backups = {"b/20261113-010000", "b/20261111-090000", "b/20261112-120000"};
    EXPECT_EQ(BackupsToRemove(backups, 2), (std::vector<fs::path>{"b/20261111-090000"}));
    EXPECT_TRUE(BackupsToRemove(backups, 3).empty());
    EXPECT_TRUE(BackupsToRemove(backups, 0).empty()) << "0 keeps all";

    TempFolder temp;
    const fs::path map = temp.path / "maps" / "zz_test";
    WriteFile(map / "zz_test.scmap", "map");
    WriteFile(map / "zz_test_scenario.lua", "scenario");
    WriteFile(map / "zz_test_save.lua", "save");
    WriteFile(map / "notes.txt", "not a map file");
    EXPECT_EQ(MapFolderFiles(map).size(), 3u) << "the .scmap and the .lua files";
    fs::path made;
    std::string error;
    ASSERT_TRUE(BackupMapFolder(map, temp.path / "backups", 1, made, error)) << error;
    EXPECT_EQ(made.parent_path(), temp.path / "backups" / "zz_test");
    EXPECT_EQ(ReadFile(made / "zz_test_save.lua"), "save");
    EXPECT_FALSE(fs::exists(made / "notes.txt"));
    // An older backup beside it goes when only one is kept.
    fs::create_directories(temp.path / "backups" / "zz_test" / "20000101-000000");
    ASSERT_TRUE(BackupMapFolder(map, temp.path / "backups", 1, made, error)) << error;
    EXPECT_FALSE(fs::exists(temp.path / "backups" / "zz_test" / "20000101-000000"));
    EXPECT_TRUE(fs::exists(made / "zz_test.scmap"));
    EXPECT_FALSE(BackupMapFolder(temp.path / "nothing", temp.path / "backups", 1, made, error));
  }

  TEST(
    Autosave,
    RecoverBacksUpThenPutsTheAutosaveBack
  )
  {
    TempFolder temp;
    const fs::path map = temp.path / "maps" / "zz_test";
    WriteFile(map / "zz_test.scmap", "old map");
    WriteFile(map / "zz_test_save.lua", "old save");
    const fs::path autosave = temp.path / "autosave" / "zz_test";
    WriteFile(autosave / "zz_test.scmap", "autosaved map");
    WriteFile(autosave / "zz_test_save.lua", "autosaved save");
    EdAutosaveEntry entry;
    entry.scenario = "/maps/zz_test/zz_test_scenario.lua";
    entry.title = "zz_test";
    entry.disk = map;
    entry.time = 7;
    WriteFile(autosave / "autosave.txt", AutosaveNote(entry));

    const auto found = ListAutosaves(temp.path / "autosave");
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].folder, autosave);

    fs::path backup;
    std::string error;
    ASSERT_TRUE(RestoreAutosave(found[0], temp.path / "backups", 3, backup, error)) << error;
    EXPECT_EQ(ReadFile(map / "zz_test.scmap"), "autosaved map");
    EXPECT_EQ(ReadFile(map / "zz_test_save.lua"), "autosaved save");
    EXPECT_EQ(ReadFile(backup / "zz_test.scmap"), "old map") << "the files before are kept";
    EXPECT_FALSE(fs::exists(map / "autosave.txt")) << "the note isn't a map file";

    RemoveAutosave(autosave);
    EXPECT_FALSE(fs::exists(autosave));
    EXPECT_TRUE(ListAutosaves(temp.path / "autosave").empty());
    RemoveAutosave(map); // no autosave.txt: left alone
    EXPECT_TRUE(fs::exists(map / "zz_test.scmap"));
  }
} // namespace
