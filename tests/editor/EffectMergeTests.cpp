#include "editor/doc/EdEffectMerge.h"
#include "editor/doc/EdModProject.h"

#include <gtest/gtest.h>

#include <string>

namespace faf::editor
{
  namespace
  {
    bool Has(
      const std::string& text,
      const std::string& part
    )
    {
      return text.find(part) != std::string::npos;
    }

    EmitterBlueprint Game()
    {
      EmitterBlueprint e = NewEmitter();
      e.blueprintId = "/effects/emitters/test_emit.bp";
      e.lifetime = 5.0f;
      e.texture = "/textures/particles/glow_02.dds";
      e.curves[0].keys = {{0.0f, 1.0f, 0.0f}, {50.0f, 2.0f, 0.0f}, {100.0f, 3.0f, 0.0f}};
      return e;
    }
  } // namespace

  TEST(
    EffectMerge,
    AChangedFieldIsOneLineAndAChangedCurveItsWholeBlock
  )
  {
    const EmitterBlueprint game = Game();
    EXPECT_TRUE(EmitterModBlueprint(game, game, "/effects/emitters/test_emit.bp").text.empty()) << "nothing changed";
    EmitterBlueprint edited = game;
    edited.lifetime = 12.0f;
    edited.curves[0].keys[1].y = 4.0f;
    edited.curves[0].keys.push_back({120.0f, 1.0f, 0.0f});
    edited.blueprintId = "something else"; // the id comes from Source
    const EffectModBlueprint bp = EmitterModBlueprint(game, edited, "/effects/emitters/test_emit.bp");
    EXPECT_FALSE(bp.replaced);
    EXPECT_EQ(bp.changed, 2);
    EXPECT_EQ(bp.text.rfind(kModProjectMark, 0), 0U);
    EXPECT_TRUE(
      Has(bp.text, "EmitterBlueprint {\n    Merge = true,\n    Source = '/effects/emitters/test_emit.bp',\n")
    );
    EXPECT_TRUE(Has(bp.text, "\tLifetime = 12.00,\n"));
    const std::string curve = CurveInfo(0).name;
    EXPECT_TRUE(Has(bp.text, "\t" + curve + " = {\n"));
    EXPECT_TRUE(Has(bp.text, "{ x=50.000,y=4.000,z=0.000 },\n\t\t\t{ x=100.000,y=3.000,z=0.000 },\n\t\t\t{ x=120.000"));
    EXPECT_FALSE(Has(bp.text, "BlueprintId"));
    EXPECT_FALSE(Has(bp.text, "Texture =")) << "unchanged";
    EXPECT_FALSE(Has(bp.text, std::string("\t") + CurveInfo(1).name + " = {")) << "unchanged curve";
  }

  TEST(
    EffectMerge,
    ACurveWithFewerKeysReplacesTheGamesBlueprint
  )
  {
    const EmitterBlueprint game = Game();
    EmitterBlueprint edited = game;
    edited.curves[0].keys.resize(1);
    const EffectModBlueprint bp = EmitterModBlueprint(game, edited, "/effects/emitters/test_emit.bp");
    EXPECT_TRUE(bp.replaced);
    EXPECT_TRUE(Has(bp.why, "1 keys, the game's 3"));
    EXPECT_TRUE(Has(bp.text, "EmitterBlueprint {\n    Source = '/effects/emitters/test_emit.bp',\n"));
    EXPECT_FALSE(Has(bp.text, "Merge = true"));
    EXPECT_TRUE(Has(bp.text, "\tTexture = [[/textures/particles/glow_02.dds]],\n")) << "the whole blueprint";
  }

  TEST(
    EffectMerge,
    BeamsMergeTheirChangedKeysAndPathsStayInEffects
  )
  {
    FlatBlueprint game;
    game.kind = "BeamBlueprint";
    FlatValue length;
    length.number = 10.0f;
    game.Set("Length", length);
    FlatValue texture;
    texture.kind = FlatValue::Kind::Text;
    texture.text = "/textures/beam.dds";
    game.Set("TextureName", texture);
    FlatBlueprint edited = game;
    length.number = 25.0f;
    edited.Set("Length", length);
    FlatValue width;
    width.number = 2.0f;
    edited.Set("Thickness", width);
    EffectModBlueprint bp = FlatModBlueprint(game, edited, "/effects/emitters/x_beam.bp");
    EXPECT_FALSE(bp.replaced);
    EXPECT_EQ(bp.changed, 2);
    EXPECT_TRUE(Has(bp.text, "BeamBlueprint {\n    Merge = true,\n    Source = '/effects/emitters/x_beam.bp',\n"));
    EXPECT_TRUE(Has(bp.text, "    Length = 25"));
    EXPECT_TRUE(Has(bp.text, "    Thickness = 2"));
    EXPECT_FALSE(Has(bp.text, "TextureName"));
    // A key taken out: a replacement.
    FlatBlueprint dropped;
    dropped.kind = "BeamBlueprint";
    dropped.Set("Length", length);
    bp = FlatModBlueprint(game, dropped, "/effects/emitters/x_beam.bp");
    EXPECT_TRUE(bp.replaced);
    EXPECT_TRUE(Has(bp.why, "TextureName was taken out"));
    EXPECT_EQ(EffectModFile("/effects/Emitters/x_emit.bp"), "effects/Emitters/x_emit.bp");
    EXPECT_EQ(EffectModFile("/maps/m/../../x_emit.bp"), "effects/emitters/x_emit.bp");
  }
} // namespace faf::editor
