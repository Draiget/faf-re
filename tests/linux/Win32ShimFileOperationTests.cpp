// Engine addition (issue #255): the POSIX SHFileOperation deletes as Windows' shell does. The engine
// deletes saves, replays and profiles with it (DISK_Recycle: FO_DELETE with FOF_ALLOWUNDO, the
// recycle bin) and purges its cache (USER_PurgeAppCacheDir: "<cache>\*"). Its paths are joined with
// backslashes below the documents folder, and Windows finds a file whatever the case of its name.

#include <gtest/gtest.h>

#include <Windows.h>

#include "moho/misc/StartupHelpers.h"
#include "platform/posix/NativePath.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <ranges>

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
      for (auto& mount : mMounts | std::views::reverse) {
        (void)::umount2(mount.c_str(), MNT_DETACH);
      }
      std::error_code ignored;
      fs::remove_all(mRoot, ignored);
    }

    /** Mounts `source` (a bind) or a tmpfs at `target`; false where this run may not mount. */
    bool Mount(
      const std::string& source,
      const std::string& target
    )
    {
      fs::create_directories(target);
      const bool bind = !source.empty();
      if (
        ::mount(
          bind ? source.c_str() : "none", target.c_str(), bind ? nullptr : "tmpfs", bind ? MS_BIND : 0, nullptr
        ) != 0
      ) {
        return false;
      }
      mMounts.push_back(target);
      return true;
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

    /** The wide (UTF-32) form of UTF-8 text, as the engine's STR_Utf8ToWide gives it. */
    static std::wstring WideUtf8(
      const std::string& text
    )
    {
      std::wstring out;
      for (std::size_t at = 0; at < text.size();) {
        const auto lead = static_cast<unsigned char>(text[at]);
        const std::size_t extra = lead >= 0xF0u ? 3 : lead >= 0xE0u ? 2 : lead >= 0xC0u ? 1 : 0;
        std::uint32_t c = extra == 0 ? lead : (lead & (0x3Fu >> extra));
        for (std::size_t k = 1; k <= extra && at + k < text.size(); ++k) {
          c = (c << 6) | (static_cast<unsigned char>(text[at + k]) & 0x3Fu);
        }
        out.push_back(static_cast<wchar_t>(c));
        at += extra + 1;
      }
      return out;
    }

    std::string mRoot;
    std::optional<std::string> mSavedDataHome;
    std::vector<std::string> mMounts;
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

  // A save, replay or profile on another file system than the home trash (a second disk, a USB
  // stick): FAF_TEST_OTHER_DISK or /dev/shm plays that disk, where it is a file system of its own (a container, most
  // desktops); the home trash stays below the test's root in /tmp.
  class ShellFileOperationOtherDisk : public ShellFileOperation
  {
  protected:
    void SetUp() override
    {
      ShellFileOperation::SetUp();
      struct stat root{};
      struct stat disk{};
      if (::stat(mRoot.c_str(), &root) != 0 || ::stat(Disk(), &disk) != 0 || root.st_dev == disk.st_dev) {
        GTEST_SKIP() << "no second file system at " << Disk();
      }
      std::string pattern = std::string(Disk()) + "/faf-shell-disk-XXXXXX";
      ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
      mDiskFolder = pattern;
      mUid = std::to_string(::getuid());
    }

    void TearDown() override
    {
      std::error_code ignored;
      if (!mDiskFolder.empty()) {
        fs::remove_all(mDiskFolder, ignored);
      }
      for (const std::string& path : mCleanUp) {
        fs::remove_all(path, ignored);
      }
      ShellFileOperation::TearDown();
    }

    /** Makes `name` in the folder on the other disk. */
    std::string MakeDiskFile(
      const std::string& name,
      const std::string& text = "x"
    )
    {
      const std::string path = mDiskFolder + "/" + name;
      std::ofstream(path) << text;
      return path;
    }

    /** The entry of the test's folder `name` would get in the trash folder `trash`, and its info. */
    void ExpectInTrash(
      const std::string& trash,
      const std::string& name,
      const std::string& text
    )
    {
      EXPECT_EQ(ReadAll(trash + "/files/" + name), text);
      const std::string info = ReadAll(trash + "/info/" + name + ".trashinfo");
      // Named relative to the top of its file system, as the specification has it for these trashes.
      const std::string relative = mDiskFolder.substr(std::string(Disk()).size() + 1) + "/" + name;
      EXPECT_NE(info.find("\nPath=" + relative + "\n"), std::string::npos) << info;
      mCleanUp.push_back(trash + "/files/" + name);
      mCleanUp.push_back(trash + "/info/" + name + ".trashinfo");
    }

    /** The other disk's mount point: FAF_TEST_OTHER_DISK (a USB stick, a second drive), else /dev/shm. */
    static const char* Disk()
    {
      const char* const chosen = std::getenv("FAF_TEST_OTHER_DISK");
      return chosen != nullptr && chosen[0] == '/' ? chosen : "/dev/shm";
    }
    std::string mDiskFolder;
    std::string mUid;
    std::vector<std::string> mCleanUp;
  };

  // No shared trash there: the entry goes to <disk>/.Trash-<uid>, made for it.
  TEST_F(
    ShellFileOperationOtherDisk,
    AllowUndoMovesToTheTrashOfItsOwnDisk
  )
  {
    struct stat existing{};
    if (::lstat((std::string(Disk()) + "/.Trash").c_str(), &existing) == 0) {
      GTEST_SKIP() << Disk() << "/.Trash exists here";
    }
    const std::string trash = std::string(Disk()) + "/.Trash-" + mUid;
    const bool hadTrash = ::lstat(trash.c_str(), &existing) == 0;
    const std::string file = MakeDiskFile("a.SCFAsave", "disk");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_FALSE(fs::exists(Trash() + "/files/a.SCFAsave"));
    struct stat info{};
    ASSERT_EQ(::lstat(trash.c_str(), &info), 0);
    // Made with mode 0700; a FAT stick shows the mode its mount options give, so only check that no
    // one else can write to it.
    EXPECT_EQ(info.st_mode & 022, 0u);
    ExpectInTrash(trash, "a.SCFAsave", "disk");
    if (!hadTrash) {
      mCleanUp.push_back(trash);
    }
  }

  // An administrator's shared trash (<disk>/.Trash with the sticky bit): the entry goes to its
  // <uid> folder.
  TEST_F(
    ShellFileOperationOtherDisk,
    AllowUndoUsesTheSharedTrashOfItsDisk
  )
  {
    const std::string shared = std::string(Disk()) + "/.Trash";
    struct stat existing{};
    if (::lstat(shared.c_str(), &existing) == 0) {
      GTEST_SKIP() << shared << " exists here";
    }
    ASSERT_EQ(::mkdir(shared.c_str(), 0777), 0);
    ASSERT_EQ(::chmod(shared.c_str(), 01777), 0);
    mCleanUp.push_back(shared);
    const std::string file = MakeDiskFile("b.SCFAReplay", "shared");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(file));
    ExpectInTrash(shared + "/" + mUid, "b.SCFAReplay", "shared");
  }

  // Neither trash of that disk can be used (here a link planted where the user's would be): the
  // file is deleted, as Windows deletes from a drive with no recycle bin, and nothing goes where the
  // link points.
  TEST_F(
    ShellFileOperationOtherDisk,
    AllowUndoDeletesWhenItsDiskHasNoUsableTrash
  )
  {
    const std::string trash = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    if (::lstat((std::string(Disk()) + "/.Trash").c_str(), &existing) == 0 || ::lstat(trash.c_str(), &existing) == 0) {
      GTEST_SKIP() << "a trash exists at " << Disk();
    }
    const std::string elsewhere = mRoot + "/elsewhere";
    fs::create_directories(elsewhere);
    ASSERT_EQ(::symlink(elsewhere.c_str(), trash.c_str()), 0);
    mCleanUp.push_back(trash);
    const std::string file = MakeDiskFile("c.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_TRUE(fs::is_empty(elsewhere));
    EXPECT_FALSE(fs::exists(Trash() + "/files/c.SCFAsave"));
  }

  // Without FOF_ALLOWUNDO a file on another disk is deleted, and no trash is made there.
  TEST_F(
    ShellFileOperationOtherDisk,
    DeleteWithoutUndoLeavesNoTrash
  )
  {
    const std::string trash = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    const bool hadTrash = ::lstat(trash.c_str(), &existing) == 0;
    const std::string file = MakeDiskFile("d.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_EQ(::lstat(trash.c_str(), &existing) == 0, hadTrash);
  }

  // NTFS finds a name whatever the case of its letters, Latin or not ($UpCase): a Cyrillic profile
  // and save, a Latin-1 letter, and a Greek one, spelled in another case than on disk.
  TEST_F(
    ShellFileOperation,
    FindsNonLatinNamesInAnotherCase
  )
  {
    const std::string save = MakeFile(
      "Documents/savegames/\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA/\xD0\xA1\xD0\xB5\xD0\xB9\xD0\xB2.SCFAsave", "save"
    );
    // "ИГРОК\сейв.SCFAsave" for "Игрок/Сейв.SCFAsave".
    moho::DISK_Recycle((mRoot +
                        "/Documents\\savegames\\\xD0\x98\xD0\x93\xD0\xA0\xD0\x9E\xD0\x9A\\\xD1\x81\xD0\xB5\xD0"
                        "\xB9\xD0\xB2.SCFAsave")
                         .c_str());
    EXPECT_FALSE(fs::exists(save));
    EXPECT_EQ(ReadAll(Trash() + "/files/\xD0\xA1\xD0\xB5\xD0\xB9\xD0\xB2.SCFAsave"), "save");

    // "Ärger/Ωmega.txt" found as "ärger/ωMEGA.TXT".
    const std::string other = MakeFile("\xC3\x84rger/\xCE\xA9mega.txt", "other");
    EXPECT_EQ(platform::posix::NativePath((mRoot + "/\xC3\xA4rger\\\xCF\x89MEGA.TXT").c_str()), other);
    EXPECT_EQ(DeleteW({WideUtf8(mRoot + "/\xC3\xA4rger/\xCF\x89MEGA.TXT")}, kQuiet), 0);
    EXPECT_FALSE(fs::exists(other));

    // A name that differs in more than case stays not found.
    // "Игрок2/x.txt" on disk, "игрок3/x.txt" asked for.
    const std::string kept = MakeFile(
      "\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA"
      "2/x.txt"
    );
    EXPECT_EQ(
      DeleteW(
        {WideUtf8(
          mRoot +
          "/\xD0\xB8\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA"
          "3/x.txt"
        )},
        kQuiet
      ),
      static_cast<int>(ERROR_FILE_NOT_FOUND)
    );
    EXPECT_TRUE(fs::exists(kept));
  }

  // NTFS keeps a letter outside ASCII apart from the ASCII one Unicode upper-cases it to: Windows 11
  // finds no 'file' as 'fıle' (dotless i) and no 'save' as 'ſave' (long s).
  TEST_F(
    ShellFileOperation,
    DotlessIAndLongSStayOtherLetters
  )
  {
    const std::string file = MakeFile("file");
    const std::string save = MakeFile("save");
    EXPECT_EQ(DeleteW({WideUtf8(mRoot + "/f\xC4\xB1le")}, kQuiet), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_EQ(
      DeleteW(
        {WideUtf8(
          mRoot +
          "/\xC5\xBF"
          "ave"
        )},
        kQuiet
      ),
      static_cast<int>(ERROR_FILE_NOT_FOUND)
    );
    EXPECT_EQ(DeleteW({WideUtf8(mRoot + "/f\xC4\xB1*")}, kQuiet), 0);
    EXPECT_TRUE(fs::exists(file));
    EXPECT_TRUE(fs::exists(save));
  }

  // Every pair Windows 11's NTFS was asked about (Test-Path of the upper form finding a file named
  // with the lower one): the ones it folds are found here, the ones it keeps apart are not.
  TEST_F(
    ShellFileOperation,
    LettersFoldAsNtfsFoldsThem
  )
  {
    struct Pair
    {
      const char* lower; // UTF-8
      const char* upper;
      bool oneName;
      const char* what;
    };
    const Pair pairs[] = {
      {"\xC3\xBF", "\xC5\xB8", true, "y diaeresis"},          // U+00FF / U+0178
      {"\xD5\xA1", "\xD4\xB1", true, "Armenian ayb"},         // U+0561 / U+0531
      {"\xD1\x90", "\xD0\x80", true, "Cyrillic ie grave"},    // U+0450 / U+0400
      {"\xE2\xB1\xA5", "\xC8\xBA", true, "a stroke"},         // U+2C65 / U+023A
      {"\xC2\xB5", "\xCE\x9C", false, "micro sign / Mu"},     // U+00B5 / U+039C
      {"\xCF\x82", "\xCE\xA3", false, "final sigma / Sigma"}, // U+03C2 / U+03A3
      {"\xC7\x85", "\xC7\x84", false, "Dz caron title"},      // U+01C5 / U+01C4
      {"\xC3\x9F", "\xE1\xBA\x9E", false, "sharp s"},         // U+00DF / U+1E9E
      {"\xE1\x83\x90", "\xE1\xB2\x90", false, "Georgian an"}, // U+10D0 / U+1C90
      {"\xEA\xAD\xB0", "\xE1\x8E\xA0", false, "Cherokee a"},  // U+AB70 / U+13A0
    };
    for (const Pair& pair : pairs) {
      const std::string name = std::string(pair.lower) + "x";
      const std::string file = MakeFile(name);
      const int result = DeleteW({WideUtf8(mRoot + "/" + pair.upper + "x")}, kQuiet);
      EXPECT_EQ(result, pair.oneName ? 0 : static_cast<int>(ERROR_FILE_NOT_FOUND)) << pair.what;
      EXPECT_EQ(fs::exists(file), !pair.oneName) << pair.what;
      std::error_code ignored;
      fs::remove(file, ignored);
    }
  }

  // A name on disk that isn't UTF-8 (Latin-1 "\xE4rger") is no letter: a UTF-8 request for "Ärger"
  // or "ärger" doesn't find it, only its own bytes do.
  TEST_F(
    ShellFileOperation,
    ANameThatIsNotUtf8MatchesOnlyItself
  )
  {
    const std::string latin1 = MakeFile("\xE4rger");
    // Byte sequences that aren't UTF-8 either and could decode to that byte or a letter: a code point
    // past U+10FFFF (F4 90 83 A4), an overlong '?' (E0 80 BF, no wildcard), an overlong 'A' (E0 81 81).
    const auto deleteBytes = [](const std::string& path) {
      std::string list = path;
      list.push_back('\0');
      list.push_back('\0');
      SHFILEOPSTRUCTA operation{};
      operation.wFunc = FO_DELETE;
      operation.pFrom = list.c_str();
      operation.fFlags = kQuiet;
      return ::SHFileOperationA(&operation);
    };
    EXPECT_EQ(deleteBytes(mRoot + "/\xF4\x90\x83\xA4rger"), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_EQ(deleteBytes(mRoot + "/\xE0\x80\xBFrger"), static_cast<int>(ERROR_FILE_NOT_FOUND));
    const std::string plain = MakeFile("Arger");
    EXPECT_EQ(deleteBytes(mRoot + "/\xE0\x81\x81rger"), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_EQ(deleteBytes(mRoot + "/\xE0\x80\xBF*"), 0);
    EXPECT_TRUE(fs::exists(latin1));
    EXPECT_TRUE(fs::exists(plain));
    EXPECT_EQ(DeleteW({WideUtf8(mRoot + "/\xC3\x84rger")}, kQuiet), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_EQ(DeleteW({WideUtf8(mRoot + "/\xC3\xA4rger")}, kQuiet), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_TRUE(fs::exists(latin1));
    std::string list = mRoot + "/\xC4rger";
    list.push_back('\0');
    list.push_back('\0');
    SHFILEOPSTRUCTA operation{};
    operation.wFunc = FO_DELETE;
    operation.pFrom = list.c_str();
    operation.fFlags = kQuiet;
    EXPECT_EQ(::SHFileOperationA(&operation), static_cast<int>(ERROR_FILE_NOT_FOUND));
    EXPECT_TRUE(fs::exists(latin1));
    list = mRoot + "/\xE4rger";
    list.push_back('\0');
    list.push_back('\0');
    operation.pFrom = list.c_str();
    EXPECT_EQ(::SHFileOperationA(&operation), 0);
    EXPECT_FALSE(fs::exists(latin1));
  }

  // A folder's listing (FindFirstFile, _findfirst64) takes a wildcard as the delete does: letters in
  // any case, Latin or not, and "*.*" for names with no dot too.
  TEST_F(
    ShellFileOperation,
    ListingsMatchNonLatinNamesInAnyCase
  )
  {
    MakeFile("Documents/savegames/\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA/a.SCFAsave");
    MakeFile("Documents/savegames/Other/b.SCFAsave");
    const auto list = [](const std::string& pattern) {
      std::vector<std::string> names;
      WIN32_FIND_DATAA found{};
      const HANDLE search = ::FindFirstFileA(pattern.c_str(), &found);
      if (search == INVALID_HANDLE_VALUE) {
        return names;
      }
      do {
        names.emplace_back(found.cFileName);
      } while (::FindNextFileA(search, &found));
      (void)::FindClose(search);
      return names;
    };
    // "игрок*" lists "Игрок".
    EXPECT_EQ(
      list(mRoot + "/Documents/savegames/\xD0\xB8\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA*"),
      std::vector<std::string>{"\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA"}
    );
    EXPECT_EQ(list(mRoot + "/Documents/savegames/OTH?R"), std::vector<std::string>{"Other"});
    std::vector<std::string> all = list(mRoot + "/Documents/savegames/*.*");
    all.erase(
      std::remove_if(
        all.begin(),
        all.end(),
        [](const std::string& name) {
      return name == "." || name == "..";
    }
      ),
      all.end()
    );
    std::sort(all.begin(), all.end());
    EXPECT_EQ(all, (std::vector<std::string>{"Other", "\xD0\x98\xD0\xB3\xD1\x80\xD0\xBE\xD0\xBA"}));
  }

  // A trash on that disk the user doesn't own (an administrator's or another user's, made before)
  // is not used, and the file is deleted. Needs root to give a folder to another user.
  TEST_F(
    ShellFileOperationOtherDisk,
    AnotherUsersTrashIsNotUsed
  )
  {
    if (::getuid() != 0) {
      GTEST_SKIP() << "needs root to make a folder another user owns";
    }
    const std::string trash = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    if (::lstat((std::string(Disk()) + "/.Trash").c_str(), &existing) == 0 || ::lstat(trash.c_str(), &existing) == 0) {
      GTEST_SKIP() << "a trash exists at " << Disk();
    }
    ASSERT_EQ(::mkdir(trash.c_str(), 0700), 0);
    mCleanUp.push_back(trash);
    ASSERT_EQ(::chown(trash.c_str(), 4242, 4242), 0);
    const std::string file = MakeDiskFile("e.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(file)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(file));
    EXPECT_TRUE(fs::is_empty(trash));
  }

  // A shared .Trash without the sticky bit, or one that is a link, is no shared trash: the entry
  // goes to the user's own .Trash-<uid> of that disk.
  TEST_F(
    ShellFileOperationOtherDisk,
    ASharedTrashNeedsTheStickyBitAndARealFolder
  )
  {
    const std::string shared = std::string(Disk()) + "/.Trash";
    const std::string own = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    if (::lstat(shared.c_str(), &existing) == 0 || ::lstat(own.c_str(), &existing) == 0) {
      GTEST_SKIP() << "a trash exists at " << Disk();
    }
    ASSERT_EQ(::mkdir(shared.c_str(), 0777), 0);
    ASSERT_EQ(::chmod(shared.c_str(), 0777), 0);
    mCleanUp.push_back(shared);
    mCleanUp.push_back(own);
    const std::string first = MakeDiskFile("f.SCFAsave", "no sticky bit");
    EXPECT_EQ(DeleteW({Wide(first)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(shared + "/" + mUid));
    ExpectInTrash(own, "f.SCFAsave", "no sticky bit");

    // Now a link to a real sticky folder in its place.
    std::error_code ignored;
    fs::remove_all(shared, ignored);
    const std::string sticky = mDiskFolder + "/sticky";
    ASSERT_EQ(::mkdir(sticky.c_str(), 0777), 0);
    ASSERT_EQ(::chmod(sticky.c_str(), 01777), 0);
    ASSERT_EQ(::symlink(sticky.c_str(), shared.c_str()), 0);
    const std::string second = MakeDiskFile("g.SCFAsave", "linked");
    EXPECT_EQ(DeleteW({Wide(second)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_TRUE(fs::is_empty(sticky));
    ExpectInTrash(own, "g.SCFAsave", "linked");
  }

  // The documents folder linked to the other disk (a common way to keep saves on a second drive): a
  // whole profile folder deleted through the link goes to that disk's trash, named where it really
  // was.
  TEST_F(
    ShellFileOperationOtherDisk,
    AProfileFolderThroughALinkGoesToItsDisksTrash
  )
  {
    const std::string own = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    if (::lstat((std::string(Disk()) + "/.Trash").c_str(), &existing) == 0 || ::lstat(own.c_str(), &existing) == 0) {
      GTEST_SKIP() << "a trash exists at " << Disk();
    }
    mCleanUp.push_back(own);
    fs::create_directories(mDiskFolder + "/Documents/savegames/Player");
    std::ofstream(mDiskFolder + "/Documents/savegames/Player/a.SCFAsave") << "profile";
    ASSERT_EQ(::symlink((mDiskFolder + "/Documents").c_str(), (mRoot + "/Documents").c_str()), 0);
    moho::DISK_Recycle((mRoot + "/Documents\\savegames\\Player").c_str());
    EXPECT_FALSE(fs::exists(mDiskFolder + "/Documents/savegames/Player"));
    EXPECT_EQ(ReadAll(own + "/files/Player/a.SCFAsave"), "profile");
    const std::string info = ReadAll(own + "/info/Player.trashinfo");
    const std::string relative = mDiskFolder.substr(std::string(Disk()).size() + 1) + "/Documents/savegames/Player";
    EXPECT_NE(info.find("\nPath=" + relative + "\n"), std::string::npos) << info;
  }

  // A home trash that can't take anything (here its folder is a file) doesn't stop a file on the
  // other disk from going to that disk's trash; a file on the home trash's own disk is deleted then.
  TEST_F(
    ShellFileOperationOtherDisk,
    AnUnusableHomeTrashStillLeavesTheDisksTrash
  )
  {
    const std::string own = std::string(Disk()) + "/.Trash-" + mUid;
    struct stat existing{};
    if (::lstat((std::string(Disk()) + "/.Trash").c_str(), &existing) == 0 || ::lstat(own.c_str(), &existing) == 0) {
      GTEST_SKIP() << "a trash exists at " << Disk();
    }
    mCleanUp.push_back(own);
    std::ofstream(mRoot + "/data") << "not a folder";
    const std::string onDisk = MakeDiskFile("h.SCFAsave", "disk");
    EXPECT_EQ(DeleteW({Wide(onDisk)}, kQuiet | FOF_ALLOWUNDO), 0);
    ExpectInTrash(own, "h.SCFAsave", "disk");

    const std::string onHome = MakeFile("home.SCFAsave");
    EXPECT_EQ(DeleteW({Wide(onHome)}, kQuiet | FOF_ALLOWUNDO), 0);
    EXPECT_FALSE(fs::exists(onHome));
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
  // what Windows 11's SHFileOperationW answers: 2 for a missing file, 0x7C for a pattern in a folder
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

  // A documents folder that is a bind mount of the home trash's own file system (a sandbox or a
  // container gives the game its folders so): a rename can't cross the mount, so the save is copied
  // into the home trash, the one the desktop shows, and removed. Needs the right to mount.
  TEST_F(
    ShellFileOperation,
    ABindMountedSaveGoesToTheHomeTrashByCopy
  )
  {
    const std::string save = MakeFile("real/savegames/Player/a.SCFAsave", "bound");
    // A save from last year: the copy keeps its time, as a rename would.
    const auto saved = fs::last_write_time(save) - std::chrono::hours(24 * 365);
    fs::last_write_time(save, saved);
    if (!Mount(mRoot + "/real", mRoot + "/Documents")) {
      GTEST_SKIP() << "no right to mount here";
    }
    moho::DISK_Recycle((mRoot + "/Documents\\savegames\\Player\\a.SCFAsave").c_str());
    EXPECT_FALSE(fs::exists(mRoot + "/real/savegames/Player/a.SCFAsave"));
    EXPECT_EQ(ReadAll(Trash() + "/files/a.SCFAsave"), "bound");
    EXPECT_EQ(fs::last_write_time(Trash() + "/files/a.SCFAsave"), saved);
    const std::string info = ReadAll(Trash() + "/info/a.SCFAsave.trashinfo");
    EXPECT_NE(info.find("\nPath=" + mRoot + "/Documents/savegames/Player/a.SCFAsave\n"), std::string::npos) << info;
    EXPECT_FALSE(fs::exists(mRoot + "/Documents/.Trash-" + std::to_string(::getuid())));
  }

  // A folder that is itself a mount point (another disk mounted at a profile's folder) is refused,
  // with or without undo, and what is mounted there stays. Needs the right to mount.
  TEST_F(
    ShellFileOperation,
    AMountPointFolderIsNotDeleted
  )
  {
    if (!Mount("", mRoot + "/Documents/savegames/Player")) {
      GTEST_SKIP() << "no right to mount here";
    }
    std::ofstream(mRoot + "/Documents/savegames/Player/a.SCFAsave") << "mounted";
    EXPECT_EQ(
      DeleteW({Wide(mRoot + "/Documents\\savegames\\Player")}, kQuiet | FOF_ALLOWUNDO),
      static_cast<int>(ERROR_ACCESS_DENIED)
    );
    EXPECT_EQ(DeleteW({Wide(mRoot + "/Documents/savegames/Player/")}, kQuiet), static_cast<int>(ERROR_ACCESS_DENIED));
    EXPECT_EQ(ReadAll(mRoot + "/Documents/savegames/Player/a.SCFAsave"), "mounted");
  }

  // Nor a folder with a file system mounted anywhere below it: deleting it, to the trash or not,
  // would walk into that one and empty it. The folder and what is mounted stay.
  TEST_F(
    ShellFileOperation,
    AFolderWithAMountBelowIsNotDeleted
  )
  {
    MakeFile("Documents/savegames/Player/own.SCFAsave", "own");
    if (!Mount("", mRoot + "/Documents/savegames/Player/linked/disk")) {
      GTEST_SKIP() << "no right to mount here";
    }
    std::ofstream(mRoot + "/Documents/savegames/Player/linked/disk/other.SCFAsave") << "other disk";
    EXPECT_EQ(
      DeleteW({Wide(mRoot + "/Documents\\savegames\\Player")}, kQuiet | FOF_ALLOWUNDO),
      static_cast<int>(ERROR_ACCESS_DENIED)
    );
    EXPECT_EQ(DeleteW({Wide(mRoot + "/Documents/savegames/*")}, kQuiet), static_cast<int>(ERROR_ACCESS_DENIED));
    EXPECT_EQ(ReadAll(mRoot + "/Documents/savegames/Player/linked/disk/other.SCFAsave"), "other disk");
    EXPECT_EQ(ReadAll(mRoot + "/Documents/savegames/Player/own.SCFAsave"), "own");
    EXPECT_FALSE(fs::exists(Trash() + "/files/Player"));
  }
} // namespace
