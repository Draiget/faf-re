// The map editor's FAF API reading (src/editor/doc/EdFafApi.cpp): JSON, the vault search's link and its answer.

#include "editor/doc/EdFafApi.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::JsonNode;

  TEST(FafApi, JsonReadsWhatTheApiWrites)
  {
    JsonNode root;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseJson(R"({"a": [1, 2.5, -3e2], "b": {"c": "x \"y\" {z}", "d": true, "e": null},
      "u": "Café 😀", "n": "line\nnext"})", root, error)) << error;
    ASSERT_NE(root.Get("a"), nullptr);
    ASSERT_EQ(root.Get("a")->items.size(), 3u);
    EXPECT_EQ(root.Get("a")->items[1].number, 2.5);
    EXPECT_EQ(root.Get("a")->items[2].number, -300.0);
    EXPECT_EQ(root.Get("b")->String("c"), "x \"y\" {z}");
    EXPECT_TRUE(root.Get("b")->Bool("d"));
    EXPECT_EQ(root.Get("b")->Get("e")->kind, JsonNode::Kind::Null);
    EXPECT_EQ(root.String("u"), "Caf\xC3\xA9 \xF0\x9F\x98\x80");
    EXPECT_EQ(root.String("n"), "line\nnext");
    EXPECT_FALSE(faf::editor::ParseJson(R"({"a": [1, 2)", root, error));
    EXPECT_FALSE(faf::editor::ParseJson(R"({"a": 1} x)", root, error));
  }

  TEST(FafApi, SearchLink)
  {
    faf::editor::VaultQuery query;
    query.text = "seton \"clutch\"";
    const std::string url = faf::editor::VaultSearchUrl(query, 2);
    EXPECT_EQ(url.rfind("https://api.faforever.com/data/map?filter=", 0), 0u);
    // displayName=="*seton clutch*";latestVersion.hidden==false, quotes in the text left out.
    EXPECT_NE(url.find("displayName%3D%3D%22%2Aseton%20clutch%2A%22%3BlatestVersion.hidden%3D%3Dfalse"), std::string::npos) << url;
    EXPECT_NE(url.find("&include=latestVersion,author"), std::string::npos);
    EXPECT_NE(url.find("page%5Bnumber%5D=2"), std::string::npos);
    EXPECT_NE(url.find("&sort=-gamesPlayed"), std::string::npos);
    EXPECT_EQ(faf::editor::VaultSearchUrl(faf::editor::VaultQuery{}, 1).find("displayName"), std::string::npos);
    // Filters and orders: 8 to 12 players, 20 km, ranked; newest first, best rated, by name.
    faf::editor::VaultQuery filtered;
    filtered.minPlayers = 8;
    filtered.maxPlayers = 12;
    filtered.width = 1024;
    filtered.rankedOnly = true;
    filtered.sort = faf::editor::VaultQuery::Sort::Newest;
    const std::string f = faf::editor::VaultSearchUrl(filtered, 1);
    EXPECT_NE(f.find("latestVersion.hidden%3D%3Dfalse%3BlatestVersion.maxPlayers%3Dge%3D8%3BlatestVersion.maxPlayers%3Dle%3D12%3B"
                     "latestVersion.width%3D%3D1024%3BlatestVersion.ranked%3D%3Dtrue"),
              std::string::npos)
      << f;
    EXPECT_NE(f.find("&sort=-updateTime"), std::string::npos);
    filtered.sort = faf::editor::VaultQuery::Sort::BestRated;
    EXPECT_NE(faf::editor::VaultSearchUrl(filtered, 1).find("&sort=-reviewsSummary.lowerBound"), std::string::npos);
    filtered.sort = faf::editor::VaultQuery::Sort::Name;
    EXPECT_NE(faf::editor::VaultSearchUrl(filtered, 1).find("&sort=displayName&"), std::string::npos);
  }

  TEST(FafApi, SearchAnswerToMaps)
  {
    // The JSON:API shape: maps in data, their latest versions and authors in included.
    const char* const answer = R"({
      "data": [
        {"type": "map", "id": "101", "attributes": {"displayName": "Dual Gap Adaptive", "gamesPlayed": 54321},
         "relationships": {"latestVersion": {"data": {"type": "mapVersion", "id": "9001"}},
                           "author": {"data": {"type": "player", "id": "77"}}}},
        {"type": "map", "id": "102", "attributes": {"displayName": "No Version", "gamesPlayed": 3},
         "relationships": {"latestVersion": {"data": null}}}
      ],
      "included": [
        {"type": "mapVersion", "id": "9001", "attributes": {"folderName": "dualgap_adaptive.v0012", "version": 12, "maxPlayers": 12,
          "width": 1024, "height": 1024, "ranked": true, "description": "Two {gaps}", "thumbnailUrlSmall": "https://content.faforever.com/maps/previews/small/dualgap_adaptive.v0012.png"}},
        {"type": "player", "id": "77", "attributes": {"login": "CookieNoob"}}
      ],
      "meta": {"page": {"number": 1, "totalRecords": 2, "totalPages": 4}}
    })";
    std::vector<faf::editor::VaultMap> maps;
    int pages = 0;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseVaultSearch(answer, maps, pages, error)) << error;
    ASSERT_EQ(maps.size(), 1u) << "the map without a version can't be downloaded";
    EXPECT_EQ(maps[0].name, "Dual Gap Adaptive");
    EXPECT_EQ(maps[0].folder, "dualgap_adaptive.v0012");
    EXPECT_EQ(maps[0].version, "12");
    EXPECT_EQ(maps[0].players, 12);
    EXPECT_EQ(maps[0].width, 1024);
    EXPECT_TRUE(maps[0].ranked);
    EXPECT_EQ(maps[0].author, "CookieNoob");
    EXPECT_EQ(maps[0].gamesPlayed, 54321);
    EXPECT_EQ(maps[0].description, "Two {gaps}");
    EXPECT_EQ(pages, 4);

    EXPECT_FALSE(faf::editor::ParseVaultSearch(R"({"errors": [{"detail": "Invalid filter"}]})", maps, pages, error));
    EXPECT_EQ(error, "Invalid filter");
  }
} // namespace
