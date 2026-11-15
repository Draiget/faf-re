// Engine addition (issue #255): the POSIX SHFileOperation deletes as Windows' shell does. The engine
// deletes saves, replays and profiles with it (DISK_Recycle: FO_DELETE with FOF_ALLOWUNDO, the
// recycle bin) and purges its cache (USER_PurgeAppCacheDir: "<cache>\*"). Its paths are joined with
// backslashes below the documents folder, and Windows finds a file whatever the case of its name.

#include <gtest/gtest.h>

#include <Windows.h>

#include "moho/misc/StartupHelpers.h"

#include <sys/stat.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace
{
  namespace fs = std::filesystem;

  /** A fresh folder for the files, and XDG_DATA_HOME (the trash's home) inside it, restored afterwards. */
  class ShellFileOperation : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      char pattern[] = "/tmp/faf-shell-delete-XXXXXX";
      ASSERT_NE(::mkdtemp(pattern), nullptr);
      mRoot = pattern;
      const char* const value = std::getenv("XDG_DATA_HOME");
      mSavedDataHome = value != nullptr ? std::optional<std::string>(value) : std::nullopt;
      ::setenv("XDG_DATA_HOME", (mRoot + "/data").c_str(), 1);
    }

    void TearDown() override
    {
      if (mSavedDataHome) {
        ::setenv("XDG_DATA_HOME", mSavedDataHome->c_str(), 1);
      } else {
        ::unsetenv("XDG_DATA_HOME");
      }
      std::error_code ignored;
      fs::remove_all(mRoot, ignored);
    }

    /** Makes `relative` below the root with `text` in it, and its folders. */
    std::string MakeFile(
      const std::string& relative,
      const std::string& text = "x"
    )
    {
      const fs::path path = fs::path(mRoot) / relative;
      fs::create_directories(path.parent_path());
      std::ofstream(path) << text;
      return path.string();
    }

    [[nodiscard]] std::string Trash() const
    {
      return mRoot + "/data/Trash";
    }

    [[nodiscard]] static std::string ReadAll(
      const std::string& path
    )
    {
      std::ifstream file(path);
      std::stringstream text;
      text << file.rdbuf();
      return text.str();
    }

    /** SHFileOperationW's FO_DELETE of `paths` (one double-null list) with `flags`. */
    static int DeleteW(
      const std::vector<std::wstring>& paths,
      const WORD flags
    )
    {
      std::wstring list;
      for (const std::wstring& path : paths) {
        list += path;
        list.push_back(L'\0');
      }
      list.push_back(L'\0');
      SHFILEOPSTRUCTW operation{};
      operation.wFunc = FO_DELETE;
      operation.pFrom = list.c_str();
      operation.fFlags = flags;
      operation.fAnyOperationsAborted = TRUE;
      const int result = ::SHFileOperationW(&operation);
      EXPECT_EQ(operation.fAnyOperationsAborted, FALSE);
      return result;
    }

    static std::wstring Wide(
      const std::string& text
    )
    {
      return std::wstring(text.begin(), text.end());
    }

    std::string mRoot;
    std::optional<std::string> mSavedDataHome;
  };

  constexpr WORD kQuiet = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI;

  // The save path as the engine builds it: '/' up to the documents folder, '\' below it, and the
  // profile spelled in another case than on disk.
  TEST_F(
    ShellFileOperation,
    DeletesAFileNamedWithBackslashesAndAnotherCase
  )
  {
    const std::string file = MakeFile("Documents/My Games/savegames/Player/My Save.SCFAsave");
    const std::string keep = MakeFile("Documents/My Games/savegames/Player/Other.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(mRoot + "/Documents\\My Games\\savegames\\PLAYER\\my save.SCFAsave")}, kQuiet), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_TRUE(fs::exists(keep));
  }

  // A profile's folders (RemoveProfileDirectories) go with everything in them.
  TEST_F(
    ShellFileOperation,
    DeletesAFolderWithAllItHolds
  )
  {
    MakeFile("Documents/My Games/replays/Player/a.SCFAReplay");
    MakeFile("Documents/My Games/replays/Player/sub/b.SCFAReplay");
    EXPECT_EQ(DeleteW({Wide(mRoot + "/Documents\\My Games\\replays\\Player")}, kQuiet), 0);
    EXPECT_FALSE(fs::exists(mRoot + "/Documents/My Games/replays/Player"));
    EXPECT_TRUE(fs::exists(mRoot + "/Documents/My Games/replays"));
  }

  // FOF_ALLOWUNDO, DISK_Recycle's flag: the file goes to the desktop's trash, with the info file a file
  // manager restores it from, and a second file of the same name takes a free one.
  TEST_F(
    ShellFileOperation,
    AllowUndoMovesToTheHomeTrash
  )
  {
    const std::string first = MakeFile("Documents/savegames/Player/My Save.SCFAsave", "first");
    EXPECT_EQ(DeleteW({Wide(first)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(first));
    EXPECT_EQ(ReadAll(Trash() + "/files/My Save.SCFAsave"), "first");
    const std::string info = ReadAll(Trash() + "/info/My Save.SCFAsave.trashinfo");
    EXPECT_EQ(info.rfind("[Trash Info]\nPath=", 0), 0u) << info;
    EXPECT_NE(info.find("Path=" + mRoot + "/Documents/savegames/Player/My%20Save.SCFAsave\n"), std::string::npos)
      << info;
    EXPECT_NE(info.find("\nDeletionDate="), std::string::npos) << info;

    const std::string second = MakeFile("Documents/savegames/Player/My Save.SCFAsave", "second");
    EXPECT_EQ(DeleteW({Wide(second)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(second));
    EXPECT_EQ(ReadAll(Trash() + "/files/My Save.SCFAsave"), "first");
    EXPECT_EQ(ReadAll(Trash() + "/files/My Save.SCFAsave.2"), "second");
    EXPECT_TRUE(fs::exists(Trash() + "/info/My Save.SCFAsave.2.trashinfo"));
  }

  // DISK_Recycle (0x0045A7A0) with the path RemoveSpecialFile builds: the save is in the trash.
  TEST_F(
    ShellFileOperation,
    DiskRecycleMovesASaveToTheTrash
  )
  {
    const std::string file = MakeFile("Documents/My Games/savegames/Player/My Save.SCFAsave", "save");
    moho::DISK_Recycle((mRoot + "/Documents\\My Games\\savegames\\Player\\My Save.SCFAsave").c_str());
    EXPECT_FALSE(fs::exists(file));
    EXPECT_EQ(ReadAll(Trash() + "/files/My Save.SCFAsave"), "save");
  }

  // A profile or save name in another script, as the engine passes it to DISK_Recycle (UTF-8).
  TEST_F(
    ShellFileOperation,
    DiskRecycleTakesANonAsciiName
  )
  {
    const std::string file = MakeFile(
      "Documents/savegames/\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA/\xD0\xA1\xD0\xB5\xD0\xB9\xD0\xB2.SCFAsave", "save"
    );
    moho::DISK_Recycle(
      (mRoot +
       "/Documents\\savegames\\\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA\\\xD0\xA1\xD0\xB5\xD0\xB9\xD0\xB2.SCFAsave")
        .c_str()
    );
    EXPECT_FALSE(fs::exists(file));
    EXPECT_EQ(ReadAll(Trash() + "/files/\xD0\xA1\xD0\xB5\xD0\xB9\xD0\xB2.SCFAsave"), "save");
  }

  // A trash on another file system than the file can't take it by a rename: the file is deleted, as
  // Windows deletes from a drive with no recycle bin. Runs where /dev/shm and /tmp are two file
  // systems (a container, most desktops).
  TEST_F(
    ShellFileOperation,
    AllowUndoDeletesWhenTheTrashIsOnAnotherFileSystem
  )
  {
    struct stat tmpInfo{};
    struct stat shmInfo{};
    if (::stat(mRoot.c_str(), &tmpInfo) != 0 || ::stat("/dev/shm", &shmInfo) != 0 || tmpInfo.st_dev == shmInfo.st_dev) {
      GTEST_SKIP() << "no second file system at /dev/shm";
    }
    char pattern[] = "/dev/shm/faf-shell-trash-XXXXXX";
    ASSERT_NE(::mkdtemp(pattern), nullptr);
    const std::string dataHome = pattern;
    ::setenv("XDG_DATA_HOME", dataHome.c_str(), 1);
    const std::string file = MakeFile("Documents/savegames/Player/a.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_FALSE(fs::exists(dataHome + "/Trash/files/a.SCFAsave"));
    EXPECT_FALSE(fs::exists(dataHome + "/Trash/info/a.SCFAsave.trashinfo"));
    std::error_code ignored;
    fs::remove_all(dataHome, ignored);
  }

  // USER_PurgeAppCacheDir's "<cache>\*": every name in the folder, the folder itself stays. A pattern
  // matches names whatever their case, "*.*" also names with no dot, and one that matches nothing is
  // no failure.
  TEST_F(
    ShellFileOperation,
    WildcardsDeleteTheMatchingNamesInTheirFolder
  )
  {
    MakeFile("cache/a.fx");
    MakeFile("cache/B.FX");
    MakeFile("cache/keep.txt");
    MakeFile("cache/sub/c.fx");

    std::string list = mRoot + "\\cache\\*.fx";
    list.push_back('\0');
    list.push_back('\0');
    SHFILEOPSTRUCTA operation{};
    operation.wFunc = FO_DELETE;
    operation.pFrom = list.c_str();
    operation.fFlags = kQuiet;
    EXPECT_EQ(::SHFileOperationA(&operation), 0);
    EXPECT_FALSE(fs::exists(mRoot + "/cache/a.fx"));
    EXPECT_FALSE(fs::exists(mRoot + "/cache/B.FX"));
    EXPECT_TRUE(fs::exists(mRoot + "/cache/keep.txt"));
    EXPECT_TRUE(fs::exists(mRoot + "/cache/sub/c.fx"));

    MakeFile("cache/noext");
    EXPECT_EQ(DeleteW({Wide(mRoot + "/cache/*.*")}, kQuiet), 0);
    EXPECT_TRUE(fs::is_directory(mRoot + "/cache"));
    EXPECT_TRUE(fs::is_empty(mRoot + "/cache"));

    EXPECT_EQ(DeleteW({Wide(mRoot + "/cache/*")}, kQuiet), 0);
  }

  // A file that isn't there is an error, and the other sources of the list still go. The codes are
  // what Windows 10's SHFileOperationW answers: 2 for a missing file, 0x7C for a pattern in a folder
  // that isn't there.
  TEST_F(
    ShellFileOperation,
    AMissingSourceIsAnErrorAndTheOthersStillGo
  )
  {
    const std::string file = MakeFile("a.txt");
    EXPECT_EQ(DeleteW({Wide(mRoot + "/missing.txt"), Wide(file)}, kQuiet), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_FALSE(fs::exists(file));
    EXPECT_EQ(DeleteW({Wide(mRoot + "/nofolder/*")}, kQuiet), 0x7C);
  }

  // The operations the engine doesn't use stay unsupported and touch nothing.
  TEST_F(
    ShellFileOperation,
    OtherOperationsStayUnsupported
  )
  {
    const std::string file = MakeFile("a.txt");
    std::wstring list = Wide(file);
    list.push_back(L'\0');
    list.push_back(L'\0');
    std::wstring to = Wide(mRoot + "/b.txt");
    to.push_back(L'\0');
    to.push_back(L'\0');
    for (const UINT function : {FO_MOVE, FO_COPY, FO_RENAME}) {
      SHFILEOPSTRUCTW operation{};
      operation.wFunc = function;
      operation.pFrom = list.c_str();
      operation.pTo = to.c_str();
      EXPECT_EQ(::SHFileOperationW(&operation), static_cast<int>(ERROR_NOT_SUPPORTED));
    }
    EXPECT_TRUE(fs::exists(file));
    EXPECT_FALSE(fs::exists(mRoot + "/b.txt"));
  }
} // namespace
