#include "editor/tools/EdAssetCatalog.h"

#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/ui/EdUnitCatalog.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

namespace faf::editor
{
  namespace
  {
    std::vector<AssetEntry> Props()
    {
      return {
        PropAsset("/env/evergreen/props/trees/pine06_prop.bp"),
        PropAsset("/env/Evergreen/Props/Rocks/rock01_prop.bp"),
        PropAsset("/env/desert/props/trees/palm01_prop.bp"),
        PropAsset("/env/common/props/wrecks/ship_wreck_prop.bp"),
      };
    }
  } // namespace

  TEST(
    AssetCatalog,
    EntriesCarryTheirFacets
  )
  {
    const AssetEntry pine = PropAsset("/env/evergreen/props/trees/pine06_prop.bp");
    EXPECT_EQ(pine.kind, AssetKind::Props);
    EXPECT_EQ(pine.name, "pine06");
    EXPECT_EQ(pine.tags.at("group"), "Evergreen");
    EXPECT_EQ(pine.tags.at("type"), "Trees");
    EXPECT_EQ(PropAsset("/env/common/props/wrecks/ship_wreck_prop.bp").tags.at("type"), "Wrecks");
    EXPECT_EQ(PropAsset("/props/odd_prop.bp").tags.at("group"), "Other");
    EdUnitInfo tank{"uel0201", "Medium Tank", 2, 0, 0};
    const AssetEntry unit = UnitAsset(tank);
    EXPECT_EQ(unit.tags.at("faction"), kUnitFactions[2]);
    EXPECT_EQ(unit.tags.at("tech"), kUnitTechs[0]);
    EXPECT_EQ(unit.tags.at("type"), kUnitKinds[0]);
    EXPECT_NE(unit.search.find("medium tank"), std::string::npos);
    DecalTexture decal;
    decal.path = "/env/common/decals/crater01_normals.dds";
    decal.biome = "common";
    decal.name = "crater01_normals";
    decal.type = 2;
    EXPECT_EQ(DecalAsset(decal).tags.at("type"), "Normals");
    const MarkerType mass{"Mass", "Resources", "Mass ", "ff808080", "/env/common/props/markers/m_mass_prop.bp", {}};
    EXPECT_EQ(MarkerAsset(mass).tags.at("type"), mass.group);
    LayerTexture grass{"/env/evergreen/layers/grass001_albedo.dds", "", "evergreen", "grass001"};
    EXPECT_EQ(TextureAsset(grass).tags.at("group"), "Evergreen");
    const AssetEntry beam = EffectAsset("/effects/emitters/aeon_laser_beam_01_beam.bp");
    EXPECT_EQ(beam.tags.at("file"), "Beam");
    EXPECT_EQ(beam.tags.at("faction"), "Aeon");
    EXPECT_EQ(beam.name, "aeon_laser_beam_01_beam");
    EXPECT_EQ(AssetFacetValues(Props(), "group"), (std::vector<std::string>{"Common", "Desert", "Evergreen"}));
    EXPECT_EQ(AssetFacets(AssetKind::Units).size(), 3U);
  }

  TEST(
    AssetCatalog,
    FindingTakesWordsFiltersFavouritesAndRecent
  )
  {
    const std::vector<AssetEntry> props = Props();
    AssetMarks marks;
    AssetQuery q;
    q.text = "TREES";
    EXPECT_EQ(FindAssets(props, q, marks), (std::vector<std::size_t>{0, 2})) << "words match any case";
    q.text = "trees evergreen";
    EXPECT_EQ(FindAssets(props, q, marks), (std::vector<std::size_t>{0}));
    q.text.clear();
    q.filters["group"] = "Desert";
    EXPECT_EQ(FindAssets(props, q, marks), (std::vector<std::size_t>{2}));
    q.filters["group"].clear();
    // Favourites first.
    marks.ToggleFavourite(props[3]);
    EXPECT_EQ(FindAssets(props, q, marks).front(), 3U);
    q.onlyFavourites = true;
    EXPECT_EQ(FindAssets(props, q, marks), (std::vector<std::size_t>{3}));
    q.onlyFavourites = false;
    // Recent: the latest first, once each.
    marks.Used(props[1]);
    marks.Used(props[2]);
    marks.Used(props[1]);
    q.recent = true;
    EXPECT_EQ(FindAssets(props, q, marks), (std::vector<std::size_t>{1, 2}));
    for (int i = 0; i < 60; ++i) {
      marks.Used(PropAsset("/env/x/props/p" + std::to_string(i) + "_prop.bp"));
    }
    EXPECT_EQ(marks.RecentRank(props[1]), -1) << "only the last 40";
    // Kept as text.
    AssetMarks back;
    back.Load(marks.Save());
    EXPECT_TRUE(back.Favourite(props[3]));
    EXPECT_EQ(back.RecentRank(PropAsset("/env/x/props/p59_prop.bp")), 0);
    EXPECT_EQ(back.Save(), marks.Save());
  }

  TEST(
    AssetCatalog,
    PicturesReadBackFromTheCache
  )
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_thumb_tests";
    const std::filesystem::path a = ThumbCacheFile(folder, "/env/evergreen/props/trees/pine06_prop.bp");
    EXPECT_EQ(a, ThumbCacheFile(folder, "/env/evergreen/props/trees/pine06_prop.bp"));
    EXPECT_NE(a, ThumbCacheFile(folder, "/env/evergreen/props/trees/pine07_prop.bp"));
    EXPECT_EQ(a.parent_path(), folder);
    std::vector<std::uint32_t> pixels(4 * 3);
    for (std::size_t i = 0; i < pixels.size(); ++i) {
      pixels[i] = 0xFF000000u | static_cast<std::uint32_t>(i * 1000);
    }
    ASSERT_TRUE(WriteThumbFile(a, 4, 3, pixels.data()));
    int w = 0;
    int h = 0;
    std::vector<std::uint32_t> back;
    ASSERT_TRUE(ReadThumbFile(a, w, h, back));
    EXPECT_EQ(w, 4);
    EXPECT_EQ(h, 3);
    EXPECT_EQ(back, pixels);
    EXPECT_FALSE(ReadThumbFile(folder / "missing.thumb", w, h, back));
    EXPECT_FALSE(WriteThumbFile(a, 0, 3, pixels.data()));
  }

  TEST(
    AssetCatalog,
    AnEffectsPictureIsTheTextureItDrawsWith
  )
  {
    EXPECT_EQ(
      faf::editor::EffectPictureTexture(
        "TrailEmitterBlueprint {\n    RepeatTexture = true,\n    TextureName = "
        "'/textures/particles/beam_white_01.dds',\n}"
      ),
      "/textures/particles/beam_white_01.dds"
    );
    EXPECT_EQ(faf::editor::EffectPictureTexture("SomethingBlueprint { Lifetime = 1 }"), "");
  }
} // namespace faf::editor
