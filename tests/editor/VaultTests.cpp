// The map editor's vault downloads (src/editor/doc/EdVault.cpp): names and links, zip reading, installing a map's
// archive into the maps folder (and refusing archives that would write elsewhere).

#include "editor/doc/EdVault.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>

namespace
{
  using faf::editor::VaultMapName;
  using faf::editor::ZipEntry;

  std::filesystem::path FreshFolder(const char* const name)
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / name;
    std::error_code code;
    std::filesystem::remove_all(folder, code);
    std::filesystem::create_directories(folder, code);
    return folder;
  }

  TEST(Vault, NamesAndLinks)
  {
    VaultMapName map;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseVaultMapName("dualgap_adaptive.v0012", map, error)) << error;
    EXPECT_EQ(map.folder, "dualgap_adaptive.v0012");
    EXPECT_EQ(map.url, "https://content.faforever.com/maps/dualgap_adaptive.v0012.zip");
    ASSERT_TRUE(faf::editor::ParseVaultMapName("  https://content.faforever.com/maps/DualGap_Adaptive.v0012.zip?x=1 ", map, error));
    EXPECT_EQ(map.folder, "dualgap_adaptive.v0012");
    ASSERT_TRUE(faf::editor::ParseVaultMapName("seton's%20clutch.v0003.zip", map, error));
    EXPECT_EQ(map.folder, "seton's clutch.v0003");
    EXPECT_EQ(map.url, "https://content.faforever.com/maps/seton%27s%20clutch.v0003.zip");
    EXPECT_FALSE(faf::editor::ParseVaultMapName("", map, error));
    EXPECT_FALSE(faf::editor::ParseVaultMapName("no_version", map, error));
    EXPECT_FALSE(faf::editor::ParseVaultMapName("..", map, error));
    EXPECT_FALSE(faf::editor::ParseVaultMapName("c:evil.v1", map, error));
  }

  TEST(Vault, EntriesStayInTheMapsFolder)
  {
    EXPECT_EQ(faf::editor::MapEntryPath("lake.v0001/lake_scenario.lua", "lake.v0001"), "lake_scenario.lua");
    EXPECT_EQ(faf::editor::MapEntryPath("Lake.V0001/env/decal.dds", "lake.v0001"), "env/decal.dds");
    EXPECT_EQ(faf::editor::MapEntryPath("lake.v0001/", "lake.v0001"), "");
    EXPECT_EQ(faf::editor::MapEntryPath("other.v0001/x.lua", "lake.v0001"), "");
    EXPECT_EQ(faf::editor::MapEntryPath("lake.v0001/../../x.lua", "lake.v0001"), "");
    EXPECT_EQ(faf::editor::MapEntryPath("lake.v0001//x.lua", "lake.v0001"), "");
    EXPECT_EQ(faf::editor::MapEntryPath("lake.v0001/c:/x.lua", "lake.v0001"), "");
    EXPECT_EQ(faf::editor::MapEntryPath("x.lua", "lake.v0001"), "");
  }

  TEST(Vault, ZipReadsBackWhatWasWritten)
  {
    const std::vector<ZipEntry> written = {{"lake.v0001/", ""},
                                           {"lake.v0001/lake_scenario.lua", "ScenarioInfo = { name = 'Lake' }\n"},
                                           {"lake.v0001/lake_save.lua", std::string(20000, 'a')},
                                           {"lake.v0001/lake.scmap", std::string("\x01\x02\x03\x00\xff", 5)}};
    std::vector<ZipEntry> read;
    std::string error;
    ASSERT_TRUE(faf::editor::ReadZip(faf::editor::WriteZip(written), read, error)) << error;
    ASSERT_EQ(read.size(), written.size());
    for (std::size_t i = 0; i < read.size(); ++i) {
      EXPECT_EQ(read[i].name, written[i].name);
      EXPECT_EQ(read[i].data, written[i].data) << read[i].name;
    }
    EXPECT_FALSE(faf::editor::ReadZip("not a zip at all, not even close to one", read, error));
  }

  TEST(Vault, InstallsAMapAndRefusesOthers)
  {
    const std::filesystem::path maps = FreshFolder("faf_editor_vault_test");
    std::string error;
    const std::string good = faf::editor::WriteZip({{"lake.v0001/lake_scenario.lua", "s"}, {"lake.v0001/lake_save.lua", "v"}});
    ASSERT_TRUE(faf::editor::InstallMapZip(good, "lake.v0001", maps, error)) << error;
    EXPECT_TRUE(std::filesystem::exists(maps / "lake.v0001" / "lake_scenario.lua"));
    EXPECT_TRUE(std::filesystem::exists(maps / "lake.v0001" / "lake_save.lua"));

    const std::string escaping = faf::editor::WriteZip({{"pond.v0001/pond_scenario.lua", "s"}, {"pond.v0001/../../evil.lua", "x"}});
    EXPECT_FALSE(faf::editor::InstallMapZip(escaping, "pond.v0001", maps, error));
    EXPECT_FALSE(std::filesystem::exists(maps.parent_path() / "evil.lua"));
    EXPECT_FALSE(std::filesystem::exists(maps / "pond.v0001"));

    const std::string noScenario = faf::editor::WriteZip({{"pool.v0001/pool_save.lua", "v"}});
    EXPECT_FALSE(faf::editor::InstallMapZip(noScenario, "pool.v0001", maps, error));
    std::error_code code;
    std::filesystem::remove_all(maps, code);
  }

  // A real vault archive (FAF's are written with data descriptors): FAF_VAULT_ZIP names one, its folder the file name.
  TEST(Vault, RealVaultArchiveInstalls)
  {
    const char* const file = std::getenv("FAF_VAULT_ZIP");
    if (file == nullptr) {
      GTEST_SKIP() << "FAF_VAULT_ZIP is not set";
    }
    std::ifstream in(file, std::ios::binary);
    std::stringstream bytes;
    bytes << in.rdbuf();
    const std::string folder = std::filesystem::path(file).stem().string();
    const std::filesystem::path maps = FreshFolder("faf_editor_vault_real");
    std::string error;
    ASSERT_TRUE(faf::editor::InstallMapZip(bytes.str(), folder, maps, error)) << error;
    int files = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(maps / folder)) {
      files += entry.is_regular_file() ? 1 : 0;
    }
    EXPECT_GT(files, 3);
    std::error_code code;
    std::filesystem::remove_all(maps, code);
  }
} // namespace
