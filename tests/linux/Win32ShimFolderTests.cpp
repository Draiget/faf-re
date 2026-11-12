// Engine addition (issue #389): the POSIX SHGetFolderPathW answers the folders Windows would, and
// they exist when the engine writes below them. Windows' known folders always exist, and the engine
// creates only its own subfolders, one level at a time (USER_EnsureDocumentDirectories,
// VCR_CreateReplay); a desktop in another language names its documents folder in user-dirs.dirs.

#include <gtest/gtest.h>

#include <Windows.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{
  /** A fresh home folder with HOME and the XDG variables pointing into it, restored afterwards. */
  class ShellFolders : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      char pattern[] = "/tmp/faf-shell-folders-XXXXXX";
      ASSERT_NE(::mkdtemp(pattern), nullptr);
      mHome = pattern;
      for (const char* const name :
           {"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_DOCUMENTS_DIR", "XDG_DESKTOP_DIR"}) {
        const char* const value = std::getenv(name);
        mSaved.emplace_back(name, value != nullptr ? std::optional<std::string>(value) : std::nullopt);
        ::unsetenv(name);
      }
      ::setenv("HOME", mHome.c_str(), 1);
    }

    void TearDown() override
    {
      for (const auto& [name, value] : mSaved) {
        if (value) {
          ::setenv(name.c_str(), value->c_str(), 1);
        } else {
          ::unsetenv(name.c_str());
        }
      }
      std::error_code ignored;
      std::filesystem::remove_all(mHome, ignored);
    }

    void WriteUserDirs(
      const std::string& text
    )
    {
      std::filesystem::create_directories(mHome + "/.config");
      std::ofstream(mHome + "/.config/user-dirs.dirs") << text;
    }

    std::string Folder(
      const int csidl
    )
    {
      wchar_t path[MAX_PATH]{};
      EXPECT_EQ(SHGetFolderPathW(nullptr, csidl, nullptr, 0, path), S_OK);
      return std::filesystem::path(path).string();
    }

    std::string mHome;
    std::vector<std::pair<std::string, std::optional<std::string>>> mSaved;
  };
} // namespace

TEST_F(
  ShellFolders,
  DocumentsAndDataFoldersExistInAnEmptyHome
)
{
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/Documents");
  EXPECT_TRUE(std::filesystem::is_directory(mHome + "/Documents"));
  EXPECT_EQ(Folder(CSIDL_LOCAL_APPDATA), mHome + "/.local/share");
  EXPECT_TRUE(std::filesystem::is_directory(mHome + "/.local/share"));
  EXPECT_EQ(Folder(CSIDL_APPDATA), mHome + "/.config");
  EXPECT_TRUE(std::filesystem::is_directory(mHome + "/.config"));
}

TEST_F(
  ShellFolders,
  TheDesktopIsMadeOnlyWhenAskedTo
)
{
  EXPECT_EQ(Folder(CSIDL_DESKTOP), mHome + "/Desktop");
  EXPECT_FALSE(std::filesystem::exists(mHome + "/Desktop"));
  EXPECT_EQ(Folder(CSIDL_DESKTOPDIRECTORY | CSIDL_FLAG_CREATE), mHome + "/Desktop");
  EXPECT_TRUE(std::filesystem::is_directory(mHome + "/Desktop"));
}

TEST_F(
  ShellFolders,
  UserDirsNameTheTranslatedFolders
)
{
  WriteUserDirs(
    "# written by xdg-user-dirs-update\n"
    "XDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\n"
    "XDG_DOCUMENTS_DIR=\"$HOME/Dokumente\"\n"
  );
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/Dokumente");
  EXPECT_TRUE(std::filesystem::is_directory(mHome + "/Dokumente"));
  EXPECT_FALSE(std::filesystem::exists(mHome + "/Documents"));
  EXPECT_EQ(Folder(CSIDL_DESKTOP), mHome + "/Schreibtisch");
}

TEST_F(
  ShellFolders,
  UserDirsTakeAbsolutePathsAndTheLastLine
)
{
  const std::string elsewhere = mHome + "/elsewhere/docs";
  WriteUserDirs(
    "XDG_DOCUMENTS_DIR=\"$HOME/First\"\n"
    "  XDG_DOCUMENTS_DIR=\"" +
    elsewhere + "/\"\r\n"
  );
  EXPECT_EQ(Folder(CSIDL_PERSONAL), elsewhere);
}

TEST_F(
  ShellFolders,
  TheEnvironmentComesAfterUserDirs
)
{
  ::setenv("XDG_DOCUMENTS_DIR", (mHome + "/FromEnvironment").c_str(), 1);
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/FromEnvironment");
  WriteUserDirs("XDG_DOCUMENTS_DIR=\"$HOME/FromFile\"\n");
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/FromFile");
}

TEST_F(
  ShellFolders,
  UserDirsFollowXdgConfigHome
)
{
  const std::string config = mHome + "/cfg";
  std::filesystem::create_directories(config);
  std::ofstream(config + "/user-dirs.dirs") << "XDG_DOCUMENTS_DIR=\"$HOME/Docs\"\n";
  ::setenv("XDG_CONFIG_HOME", config.c_str(), 1);
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/Docs");
}

TEST_F(
  ShellFolders,
  RelativeOrMalformedEntriesAreIgnored
)
{
  WriteUserDirs(
    "XDG_DOCUMENTS_DIR=\"Documents2\"\nXDG_DOCUMENTS_DIRX=\"$HOME/Wrong\"\nXDG_DOCUMENTS_DIR=\"$HOMEX/Wrong\"\n"
  );
  EXPECT_EQ(Folder(CSIDL_PERSONAL), mHome + "/Documents");
}
