// faf-re-lua.nx2 (moho/misc/FafLuaOverrides.h): a replacement is used only when FAF's mounted file
// is the one its manifest line names by SHA-256, only for UI Lua, and the file system then serves
// the replacement for the game path and maps its archive path back.
//
// Each FafLuaOverrides test writes a stand-in FAF archive and a faf-re-lua.nx2 (stored zip entries)
// to a folder of its own, mounts the first like an init file does and applies the second.
// FafLuaArchive reads the archive the build made (FAF_FA_LUA_ARCHIVE) with the engine's zip reader,
// which skips entries it can't read, so a packer the engine can't read fails here, not in a game.
//
// usage: faf_fa_lua_tests

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <gtest/gtest.h>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "moho/misc/CZipFile.h"
#include "moho/misc/FafLuaOverrides.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"

namespace
{
  void Put16(
    std::string& out,
    const std::uint16_t value
  )
  {
    out.push_back(static_cast<char>(value & 0xFFu));
    out.push_back(static_cast<char>(value >> 8));
  }

  void Put32(
    std::string& out,
    const std::uint32_t value
  )
  {
    Put16(out, static_cast<std::uint16_t>(value & 0xFFFFu));
    Put16(out, static_cast<std::uint16_t>(value >> 16));
  }

  [[nodiscard]] std::uint32_t Crc32(
    const std::string& bytes
  )
  {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const char byte : bytes) {
      crc ^= static_cast<unsigned char>(byte);
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
      }
    }
    return ~crc;
  }

  /** A zip of stored (uncompressed) entries. */
  void WriteZip(
    const std::filesystem::path& path,
    const std::vector<std::pair<std::string, std::string>>& entries
  )
  {
    std::string body;
    std::string directory;
    for (const auto& [name, payload] : entries) {
      const auto offset = static_cast<std::uint32_t>(body.size());
      const std::uint32_t crc = Crc32(payload);
      const auto size = static_cast<std::uint32_t>(payload.size());
      Put32(body, 0x04034B50u);
      Put16(body, 20u);
      Put16(body, 0u);
      Put16(body, 0u); // stored
      Put16(body, 0u);
      Put16(body, 0x0021u);
      Put32(body, crc);
      Put32(body, size);
      Put32(body, size);
      Put16(body, static_cast<std::uint16_t>(name.size()));
      Put16(body, 0u);
      body += name;
      body += payload;

      Put32(directory, 0x02014B50u);
      Put16(directory, 20u);
      Put16(directory, 20u);
      Put16(directory, 0u);
      Put16(directory, 0u);
      Put16(directory, 0u);
      Put16(directory, 0x0021u);
      Put32(directory, crc);
      Put32(directory, size);
      Put32(directory, size);
      Put16(directory, static_cast<std::uint16_t>(name.size()));
      Put16(directory, 0u);
      Put16(directory, 0u);
      Put16(directory, 0u);
      Put16(directory, 0u);
      Put32(directory, 0u);
      Put32(directory, offset);
      directory += name;
    }
    std::string out = body + directory;
    Put32(out, 0x06054B50u);
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, static_cast<std::uint16_t>(entries.size()));
    Put16(out, static_cast<std::uint16_t>(entries.size()));
    Put32(out, static_cast<std::uint32_t>(directory.size()));
    Put32(out, static_cast<std::uint32_t>(body.size()));
    Put16(out, 0u);
    std::ofstream(path, std::ios::binary).write(out.data(), static_cast<std::streamsize>(out.size()));
  }

  [[nodiscard]] std::string Digest(
    const std::string& bytes
  )
  {
    return moho::FAFLUA_DigestHex(bytes.data(), bytes.size());
  }

  [[nodiscard]] std::string ReadMounted(
    moho::CVFSImpl& vfs,
    const char* const path,
    std::string* diskPath = nullptr
  )
  {
    fa::string disk{};
    (void)vfs.FindFile(&disk, path, nullptr);
    if (diskPath != nullptr) {
      *diskPath = std::string(disk.view());
    }
    if (disk.empty()) {
      return {};
    }
    const gpg::MemBuffer<char> file = moho::DISK_ReadFile(disk.c_str());
    return file.mBegin == nullptr ? std::string{} : std::string(file.mBegin, file.mEnd);
  }

  class FafLuaOverrides : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      const auto* const info = ::testing::UnitTest::GetInstance()->current_test_info();
      mRoot = std::filesystem::temp_directory_path() / (std::string("faf_fa_lua_") + info->name());
      std::error_code error;
      std::filesystem::remove_all(mRoot, error);
      std::filesystem::create_directories(mRoot / "bin");
      WriteZip(
        mRoot / "lua.nx2",
        {
          {"lua/ui/uimain.lua", kFafUiMain},
          {"lua/ui/game/unitview.lua", kFafUnitView},
          {"lua/sim/unit.lua", kFafSimUnit},
        }
      );
    }

    void TearDown() override
    {
      mVfs.reset();
      std::error_code error;
      std::filesystem::remove_all(mRoot, error);
    }

    moho::CVFSImpl& MountAndApply(
      const std::string& manifest,
      std::vector<std::pair<std::string, std::string>> files
    )
    {
      files.emplace_back("manifest.txt", manifest);
      WriteZip(mRoot / "bin" / moho::kFafLuaArchiveName, files);
      fa::vector<moho::SVFSMountPoint> mounts;
      mounts.push_back(moho::SVFSMountPoint((mRoot / "lua.nx2").string().c_str(), "/"));
      mVfs = std::make_unique<moho::CVFSImpl>(mounts, mRoot);
      moho::FAFLUA_Apply(*mVfs, mRoot / "bin");
      return *mVfs;
    }

    static constexpr const char* kFafUiMain = "-- FAF uimain\n";
    static constexpr const char* kFafUnitView = "-- FAF unitview\n";
    static constexpr const char* kFafSimUnit = "-- FAF sim unit\n";
    std::filesystem::path mRoot;
    std::unique_ptr<moho::CVFSImpl> mVfs;
  };
} // namespace

TEST(
  FafLuaManifest,
  ParsesLinesAndReportsBadOnes
)
{
  const std::string digest(64, 'a');
  std::vector<std::string> problems;
  const auto entries = moho::FAFLUA_ParseManifest(
    "# comment\n\n" + digest + " /Lua/UI/UiMain.lua files/x/lua/ui/uimain.lua FAForever/fa#1 develop\r\n" +
      "nothex /lua/ui/a.lua files/a\n" + std::string(64, 'B') + " /lua/ui/b.lua files/b\n" + digest +
      " /lua/ui/c.lua\n",
    &problems
  );
  ASSERT_EQ(entries.size(), 2u);
  EXPECT_EQ(entries[0].mBaseDigest, digest);
  EXPECT_EQ(entries[0].mMountedPath, "/lua/ui/uimain.lua"); // lowercased like every VFS lookup
  EXPECT_EQ(entries[0].mEntry, "files/x/lua/ui/uimain.lua");
  EXPECT_EQ(entries[0].mNotes, "FAForever/fa#1 develop");
  EXPECT_EQ(entries[1].mBaseDigest, std::string(64, 'b'));
  EXPECT_EQ(problems.size(), 2u); // "nothex" and the line with no entry
}

TEST(
  FafLuaManifest,
  OnlyUiLuaIsReplaceable
)
{
  EXPECT_TRUE(moho::FAFLUA_IsReplaceablePath("/lua/ui/uimain.lua"));
  EXPECT_TRUE(moho::FAFLUA_IsReplaceablePath("/lua/keymap/hotbuild.lua"));
  EXPECT_FALSE(moho::FAFLUA_IsReplaceablePath("/lua/sim/unit.lua"));
  EXPECT_FALSE(moho::FAFLUA_IsReplaceablePath("/lua/simutils.lua"));
  EXPECT_FALSE(moho::FAFLUA_IsReplaceablePath("/units/uel0001/uel0001_script.lua"));
  EXPECT_FALSE(moho::FAFLUA_IsReplaceablePath("/lua/ui/../sim/unit.lua"));
  EXPECT_FALSE(moho::FAFLUA_IsReplaceablePath("/lua/ui/game/unitview.bp"));
}

TEST(
  FafLuaManifest,
  DigestIsSha256
)
{
  EXPECT_EQ(Digest("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(
  FafLuaOverrides,
  ReplacesOnlyFilesWhoseFafFileMatches
)
{
  const std::string manifest = Digest(kFafUiMain) + " /lua/ui/uimain.lua files/1/lua/ui/uimain.lua FAForever/fa#1\n" +
    Digest("-- an older FAF unitview\n") +
    " /lua/ui/game/unitview.lua files/2/lua/ui/game/unitview.lua FAForever/fa#2\n" + Digest(kFafSimUnit) +
    " /lua/sim/unit.lua files/3/lua/sim/unit.lua FAForever/fa#3\n";
  moho::CVFSImpl& vfs = MountAndApply(
    manifest,
    {
      {"files/1/lua/ui/uimain.lua", "-- ours uimain\n"},
      {"files/2/lua/ui/game/unitview.lua", "-- ours unitview\n"},
      {"files/3/lua/sim/unit.lua", "-- ours sim unit\n"},
    }
  );

  std::string diskPath;
  EXPECT_EQ(ReadMounted(vfs, "/lua/ui/uimain.lua", &diskPath), "-- ours uimain\n");
  EXPECT_NE(diskPath.find("faf-re-lua.nx2"), std::string::npos) << diskPath;
  EXPECT_EQ(ReadMounted(vfs, "/LUA/UI/UIMAIN.LUA"), "-- ours uimain\n");  // lookups are case-blind
  EXPECT_EQ(ReadMounted(vfs, "/lua/ui/game/unitview.lua"), kFafUnitView); // FAF's file moved on
  EXPECT_EQ(ReadMounted(vfs, "/lua/sim/unit.lua"), kFafSimUnit);          // not UI Lua: refused

  fa::string mounted{};
  (void)vfs.ToMountedPath(&mounted, diskPath.c_str());
  EXPECT_EQ(std::string(mounted.view()), "/lua/ui/uimain.lua");
  moho::SDiskFileInfo info{};
  ASSERT_TRUE(vfs.GetFileInfo("/lua/ui/uimain.lua", &info));
  EXPECT_EQ(info.mFileSize, std::string("-- ours uimain\n").size());
}

TEST_F(
  FafLuaOverrides,
  PicksTheEntryMadeForTheMountedFafFile
)
{
  const std::string manifest = Digest("-- another FAF version\n") + " /lua/ui/uimain.lua files/a/lua/ui/uimain.lua\n" +
    Digest(kFafUiMain) + " /lua/ui/uimain.lua files/b/lua/ui/uimain.lua\n";
  moho::CVFSImpl& vfs = MountAndApply(
    manifest,
    {
      {"files/a/lua/ui/uimain.lua", "-- for the other version\n"},
      {"files/b/lua/ui/uimain.lua", "-- for this version\n"},
    }
  );
  EXPECT_EQ(ReadMounted(vfs, "/lua/ui/uimain.lua"), "-- for this version\n");
}

TEST_F(
  FafLuaOverrides,
  MissingEntryKeepsFafFile
)
{
  moho::CVFSImpl& vfs = MountAndApply(Digest(kFafUiMain) + " /lua/ui/uimain.lua files/none/lua/ui/uimain.lua\n", {});
  EXPECT_EQ(ReadMounted(vfs, "/lua/ui/uimain.lua"), kFafUiMain);
}

TEST(
  FafLuaArchive,
  BuiltArchiveHoldsEveryManifestEntryAsInTheRepository
)
{
  // The engine opens archives by their canonical path (FWaitHandleSet: lowercase, backslashes).
  fa::string archivePath{};
  gpg::STR_CanonizeFilename(&archivePath, FAF_FA_LUA_ARCHIVE);
  const moho::CZipFile zip(archivePath.c_str());
  ASSERT_FALSE(zip.mEntries.empty()) << archivePath.c_str() << " has no entries the engine can read";
  const auto readSource = [](const std::string& entry) {
    std::ifstream in(std::filesystem::path(FAF_FA_LUA_SOURCE) / entry, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  };
  const auto readEntry = [&zip](const std::string& entry) -> std::string {
    for (std::uint32_t index = 0; index < zip.mEntries.size(); ++index) {
      if (std::string(zip.GetEntryName(index).view()) == entry) {
        const gpg::MemBuffer<const char> data = zip.ReadEntry(index);
        return data.mBegin == nullptr ? std::string{} : std::string(data.mBegin, data.mEnd);
      }
    }
    return "<missing>";
  };

  const std::string manifest = readEntry("manifest.txt");
  ASSERT_EQ(manifest, readSource("manifest.txt"));
  std::vector<std::string> problems;
  const auto entries = moho::FAFLUA_ParseManifest(manifest, &problems);
  EXPECT_TRUE(problems.empty());
  ASSERT_FALSE(entries.empty());
  EXPECT_EQ(zip.mEntries.size(), entries.size() + 1u); // the replacements and manifest.txt
  for (const moho::SFafLuaManifestEntry& entry : entries) {
    EXPECT_TRUE(moho::FAFLUA_IsReplaceablePath(entry.mMountedPath)) << entry.mMountedPath;
    EXPECT_EQ(readEntry(entry.mEntry), readSource(entry.mEntry)) << entry.mEntry;
  }
}

TEST_F(
  FafLuaOverrides,
  NoArchiveChangesNothing
)
{
  fa::vector<moho::SVFSMountPoint> mounts;
  mounts.push_back(moho::SVFSMountPoint((mRoot / "lua.nx2").string().c_str(), "/"));
  mVfs = std::make_unique<moho::CVFSImpl>(mounts, mRoot);
  moho::FAFLUA_Apply(*mVfs, mRoot / "bin"); // bin holds no faf-re-lua.nx2
  EXPECT_EQ(ReadMounted(*mVfs, "/lua/ui/uimain.lua"), kFafUiMain);
  EXPECT_TRUE(mVfs->mReplacements.empty());
}
