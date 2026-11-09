// The map editor's packaging (src/editor/doc/EdPackage.cpp): the vault's rules for a map folder, and a zip whose
// entries read back through zlib as written.

#include "editor/doc/EdPackage.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "zlib.h"

namespace
{
  const char* const kScenario = R"(version = 3
ScenarioInfo = {
    name = 'Test Map',
    description = 'A map.',
    type = 'skirmish',
    map = '/maps/test_map.v0002/test_map.scmap',
    save = '/maps/test_map.v0002/test_map_save.lua',
    script = '/maps/test_map.v0002/test_map_script.lua',
    map_version = 2,
}
)";

  const std::vector<std::string> kFiles = {"test_map.scmap",          "test_map_save.lua", "test_map_scenario.lua", "test_map_script.lua",
                                           ".editor_backup/1/x.scmap", "Thumbs.db",         "test_map.scmap.bak"};

  TEST(Package, AGoodFolderPacksItsMapFilesOnly)
  {
    const faf::editor::PackagePlan plan = faf::editor::PlanPackage("test_map.v0002", kScenario, kFiles);
    EXPECT_TRUE(plan.errors.empty()) << plan.errors.front();
    EXPECT_TRUE(plan.warnings.empty());
    EXPECT_EQ(plan.version, 2);
    EXPECT_EQ(plan.files, (std::vector<std::string>{"test_map.scmap", "test_map_save.lua", "test_map_scenario.lua", "test_map_script.lua"}));
  }

  TEST(Package, WrongNamesAndVersionsAreErrors)
  {
    // The folder's version and the scenario's differ; a capital letter; a path elsewhere; a missing file.
    std::string scenario = kScenario;
    scenario.replace(scenario.find("map_version = 2"), 15, "map_version = 3");
    EXPECT_FALSE(faf::editor::PlanPackage("test_map.v0002", scenario, kFiles).errors.empty());
    EXPECT_FALSE(faf::editor::PlanPackage("Test_Map.v0002", kScenario, kFiles).errors.empty());
    EXPECT_FALSE(faf::editor::PlanPackage("test_map.v0003", kScenario, kFiles).errors.empty());
    const faf::editor::PackagePlan missing = faf::editor::PlanPackage("test_map.v0002", kScenario, {"test_map_scenario.lua", "test_map.scmap"});
    EXPECT_EQ(missing.errors.size(), 2u); // save and script aren't there
  }

  TEST(Package, MapVersionIsSetOrAdded)
  {
    EXPECT_EQ(faf::editor::FolderVersion("test_map.v0012"), 12);
    EXPECT_EQ(faf::editor::FolderVersion("scmp_009"), 0);
    // Replaced where it is.
    const std::string replaced = faf::editor::WithMapVersion(kScenario, 7);
    EXPECT_NE(replaced.find("map_version = 7,"), std::string::npos);
    EXPECT_EQ(replaced.find("map_version = 2"), std::string::npos);
    // Added where it isn't (the game's own maps), in the file's line ends.
    const std::string retail = "version = 3\r\nScenarioInfo = {\r\n    name = 'Seton',\r\n}\r\n";
    EXPECT_EQ(faf::editor::WithMapVersion(retail, 1), "version = 3\r\nScenarioInfo = {\r\n    map_version = 1,\r\n    name = 'Seton',\r\n}\r\n");
  }

  // Reads a stored or deflated entry back by its local header.
  std::string ReadEntry(const std::string& zip, std::size_t at, std::string& name)
  {
    const auto u16 = [&](const std::size_t i) { return static_cast<std::uint32_t>(static_cast<unsigned char>(zip[i]) | (static_cast<unsigned char>(zip[i + 1]) << 8)); };
    const auto u32 = [&](const std::size_t i) { return u16(i) | (u16(i + 2) << 16); };
    EXPECT_EQ(u32(at), 0x04034B50u);
    const std::uint32_t method = u16(at + 8);
    const std::uint32_t crc = u32(at + 14);
    const std::uint32_t packed = u32(at + 18);
    const std::uint32_t size = u32(at + 22);
    const std::uint32_t nameLength = u16(at + 26);
    name = zip.substr(at + 30, nameLength);
    const std::string body = zip.substr(at + 30 + nameLength, packed);
    std::string data(size, '\0');
    if (method == 0) {
      data = body;
    } else {
      z_stream stream{};
      inflateInit2(&stream, -MAX_WBITS);
      stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(body.data()));
      stream.avail_in = static_cast<uInt>(body.size());
      stream.next_out = reinterpret_cast<Bytef*>(data.data());
      stream.avail_out = static_cast<uInt>(data.size());
      EXPECT_EQ(inflate(&stream, Z_FINISH), Z_STREAM_END);
      inflateEnd(&stream);
    }
    EXPECT_EQ(static_cast<std::uint32_t>(crc32(crc32(0L, Z_NULL, 0), reinterpret_cast<const Bytef*>(data.data()), static_cast<uInt>(data.size()))), crc);
    return data;
  }

  TEST(Package, TheZipReadsBack)
  {
    const std::string big(5000, 'a');
    const std::string small = "xy";
    const std::string zip = faf::editor::WriteZip({{"m.v0001/big.txt", big}, {"m.v0001/small.txt", small}});
    std::string name;
    EXPECT_EQ(ReadEntry(zip, 0, name), big);
    EXPECT_EQ(name, "m.v0001/big.txt");
    // The second local header follows the first's body.
    const std::size_t second = zip.find("PK\x03\x04", 4);
    ASSERT_NE(second, std::string::npos);
    EXPECT_EQ(ReadEntry(zip, second, name), small);
    // The end record counts two entries.
    const std::size_t end = zip.rfind("PK\x05\x06");
    ASSERT_NE(end, std::string::npos);
    EXPECT_EQ(static_cast<unsigned char>(zip[end + 10]), 2);
    EXPECT_LT(zip.size(), big.size()); // the big one deflated
  }
} // namespace
