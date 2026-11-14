#include "editor/tools/EdMapLayout.h"

#include <gtest/gtest.h>

#include <cmath>

namespace faf::editor
{
  namespace
  {
    /** A half turn about the middle of a 256-unit map. */
    std::vector<std::pair<float, float>> HalfTurn(
      const float x,
      const float z
    )
    {
      return {{x, z}, {256.0f - x, 256.0f - z}};
    }

    int Index(
      const MapLayout& layout,
      const LayoutKind kind
    )
    {
      for (std::size_t i = 0; i < layout.Layers().size(); ++i) {
        if (layout.Layers()[i].kind == kind) {
          return static_cast<int>(i);
        }
      }
      return -1;
    }
  } // namespace

  TEST(
    MapLayout,
    TheDrawingCoversThePlayableAreaInSquareCells
  )
  {
    MapLayout layout;
    layout.New(128, 0.0f, 0.0f, 512.0f, 256.0f);
    EXPECT_EQ(layout.Frame().rw, 128);
    EXPECT_EQ(layout.Frame().rh, 64);
    EXPECT_FLOAT_EQ(layout.Frame().cell, 4.0f);
    EXPECT_EQ(layout.Layers().size(), 6U);
    EXPECT_FALSE(layout.Drawn());
    EXPECT_FALSE(layout.Stale(0.0f, 0.0f, 512.0f, 256.0f));
    EXPECT_TRUE(layout.Stale(0.0f, 0.0f, 256.0f, 256.0f));
    float x = 0.0f, z = 0.0f;
    layout.ToWorld(10.0f, 5.0f, x, z);
    EXPECT_FLOAT_EQ(x, 40.0f);
    EXPECT_FLOAT_EQ(z, 20.0f);
    // A second layer of a kind is numbered; the list holds 16 at most.
    EXPECT_EQ(layout.AddLayer(LayoutKind::Hills), 6);
    EXPECT_EQ(layout.Layers()[6].name, "Hills 2");
    while (layout.Layers().size() < static_cast<std::size_t>(MapLayout::kMaxLayers)) {
      (void)layout.AddLayer(LayoutKind::Mask);
    }
    EXPECT_EQ(layout.AddLayer(LayoutKind::Mask), -1);
    EXPECT_TRUE(layout.MoveLayer(0, 1));
    EXPECT_EQ(layout.Layers()[1].kind, LayoutKind::Hills);
  }

  TEST(
    MapLayout,
    StrokesPaintTheSymmetrysCopiesAndUndo
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f); // cells of 4 units
    layout.SetImages(&HalfTurn);
    const int hills = Index(layout, LayoutKind::Hills);
    ASSERT_TRUE(layout.BeginStroke(hills));
    layout.Dab(hills, 10.0f, 12.0f, 3.0f, 0.5f, 1.0f, false);
    LayoutStroke stroke;
    ASSERT_TRUE(layout.EndStroke(stroke));
    const auto& data = layout.Layers()[static_cast<std::size_t>(hills)].data;
    EXPECT_FLOAT_EQ(data[12 * 64 + 10], 1.0f) << "the dab";
    EXPECT_FLOAT_EQ(data[(63 - 12) * 64 + (63 - 10)], 1.0f) << "its half-turn copy";
    EXPECT_FLOAT_EQ(data[30 * 64 + 30], 0.0f);
    // An empty stroke keeps no undo step; the stroke's record puts the cells back.
    ASSERT_TRUE(layout.BeginStroke(hills));
    LayoutStroke none;
    EXPECT_FALSE(layout.EndStroke(none));
    ASSERT_TRUE(layout.SetCells(stroke.layerId, stroke.before));
    EXPECT_FALSE(layout.Drawn());
    ASSERT_TRUE(layout.SetCells(stroke.layerId, stroke.after));
    EXPECT_TRUE(layout.Drawn());
    // Shapes: a rectangle of 4 x 4 cells and its copy, an ellipse, a triangle; erase takes them away.
    layout.SetImages({});
    const int water = Index(layout, LayoutKind::Water);
    EXPECT_EQ(layout.FillRect(water, 2.0f, 2.0f, 5.9f, 5.9f, 1.0f, false), 16);
    EXPECT_GT(layout.FillEllipse(water, 20.0f, 20.0f, 30.0f, 30.0f, 1.0f, false), 60);
    EXPECT_GT(layout.FillPolygon(water, {{40.0f, 40.0f}, {60.0f, 40.0f}, {40.0f, 60.0f}}, 0.5f, false), 150);
    EXPECT_EQ(layout.FillRect(water, 2.0f, 2.0f, 5.9f, 5.9f, 1.0f, true), 16);
  }

  TEST(
    MapLayout,
    BaseBlobsAreStartPositions
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    const int base = Index(layout, LayoutKind::Base);
    layout.Dab(base, 16.0f, 16.0f, 4.0f, 1.0f, 1.0f, false);
    layout.Dab(base, 48.0f, 40.0f, 3.0f, 1.0f, 1.0f, false);
    layout.Dab(base, 60.0f, 4.0f, 0.6f, 1.0f, 1.0f, false); // too small
    const std::vector<LayoutBase> bases = layout.BaseCentres();
    ASSERT_EQ(bases.size(), 2U);
    EXPECT_NEAR(bases[0].x, 64.0f, 0.5f) << "the bigger first, in world units";
    EXPECT_NEAR(bases[0].z, 64.0f, 0.5f);
    EXPECT_NEAR(bases[1].x, 192.0f, 0.5f);
    EXPECT_NEAR(bases[1].z, 160.0f, 0.5f);
  }

  TEST(
    MapLayout,
    SavedDrawingReadsBack
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    EXPECT_EQ(layout.Save(), "") << "nothing drawn: nothing saved";
    layout.Dab(0, 20.0f, 20.0f, 6.0f, 0.3f, 0.8f, false);
    layout.Layers()[0].p["height"] = 30.0f;
    layout.Layers()[2].visible = false;
    layout.base = 40.0f;
    layout.seed = 7;
    const std::string text = layout.Save();
    MapLayout back;
    std::string error;
    ASSERT_TRUE(back.Load(text, error)) << error;
    ASSERT_EQ(back.Layers().size(), layout.Layers().size());
    EXPECT_EQ(back.Frame().rw, 64);
    EXPECT_FLOAT_EQ(back.base, 40.0f);
    EXPECT_EQ(back.seed, 7);
    EXPECT_FLOAT_EQ(back.Layers()[0].P("height"), 30.0f);
    EXPECT_FALSE(back.Layers()[2].visible);
    EXPECT_EQ(back.Layers()[3].name, "Water");
    for (std::size_t k = 0; k < layout.Layers()[0].data.size(); ++k) {
      ASSERT_NEAR(back.Layers()[0].data[k], layout.Layers()[0].data[k], 0.5f / 255.0f) << k;
    }
    EXPECT_FALSE(back.Load("{\"layers\": []}", error));
    // The generator's markers are kept with it (also when nothing is drawn).
    MapLayout markers;
    markers.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    markers.generated = {{"Mass 07", 12.5f, 40.5f}, {"Hydrocarbon 01", 30.5f, 60.5f}};
    MapLayout markersBack;
    ASSERT_TRUE(markersBack.Load(markers.Save(), error)) << error;
    ASSERT_EQ(markersBack.generated.size(), 2U);
    EXPECT_EQ(markersBack.generated[0].name, "Mass 07");
    EXPECT_FLOAT_EQ(markersBack.generated[1].z, 60.5f);
  }

  TEST(
    MapLayout,
    RefitKeepsWhatWasDrawnInItsPlace
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    layout.FillRect(0, 30.0f, 30.0f, 33.9f, 33.9f, 1.0f, false); // world 120..136
    ASSERT_TRUE(layout.Refit(128, 0.0f, 0.0f, 256.0f, 256.0f));
    EXPECT_EQ(layout.Frame().rw, 128);
    const auto& data = layout.Layers()[0].data;
    EXPECT_GT(data[64 * 128 + 64], 0.9f) << "world 128, 128";
    EXPECT_FLOAT_EQ(data[20 * 128 + 20], 0.0f);
    EXPECT_FALSE(layout.Refit(128, 0.0f, 0.0f, 256.0f, 256.0f));
  }

  TEST(
    MapLayout,
    GeneratorRaisesDigsAndLevels
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    const int hills = Index(layout, LayoutKind::Hills);
    const int water = Index(layout, LayoutKind::Water);
    const int base = Index(layout, LayoutKind::Base);
    layout.FillEllipse(hills, 4.0f, 4.0f, 28.0f, 28.0f, 1.0f, false);   // around (64, 64)
    layout.FillEllipse(water, 36.0f, 36.0f, 60.0f, 60.0f, 1.0f, false); // around (192, 192)
    layout.FillEllipse(hills, 36.0f, 4.0f, 60.0f, 28.0f, 1.0f, false);  // around (192, 64) ...
    layout.FillEllipse(base, 44.0f, 12.0f, 52.0f, 20.0f, 1.0f, false);  // ... with a base in its middle
    const field::Grid like(257, 257, 1.0f, 0.0f, 0.0f);
    field::Grid h;
    std::vector<field::Grid> masks;
    std::string error;
    ASSERT_TRUE(BuildLayout(layout, like, LayoutBuildOptions{}, h, &masks, error)) << error;
    EXPECT_EQ(masks.size(), layout.Layers().size());
    EXPECT_EQ(h.w, 257);
    EXPECT_NEAR(h.At(10, 240), layout.base, 0.01f) << "nothing drawn: the ground height";
    EXPECT_GT(h.At(64, 64), layout.base + 5.0f) << "hills";
    EXPECT_LT(h.At(192, 192), layout.water - 5.0f) << "under the water";
    EXPECT_NEAR(h.At(192, 64), layout.base, 1.0f) << "the base levels its hill";
    EXPECT_GT(masks[static_cast<std::size_t>(water)].At(192, 192), 0.95f);
    EXPECT_LT(masks[static_cast<std::size_t>(water)].At(64, 64), 0.01f);
    // A hidden layer doesn't build; the symmetry option copies one half onto the other.
    layout.Layers()[static_cast<std::size_t>(water)].visible = false;
    LayoutBuildOptions turned;
    turned.symmetry = "rot2";
    turned.cx = 128.0f;
    turned.cz = 128.0f;
    ASSERT_TRUE(BuildLayout(layout, like, turned, h, nullptr, error)) << error;
    EXPECT_NEAR(h.At(64, 64), h.At(192, 192), 0.01f);
    // The plain mask of a layer.
    field::Grid mask;
    ASSERT_TRUE(LayoutLayerMask(layout, like, base, false, mask, error)) << error;
    EXPECT_GT(mask.At(192, 64), 0.99f);
    EXPECT_FALSE(LayoutLayerMask(layout, like, 40, false, mask, error));
  }

  TEST(
    MapLayout,
    TemplatesDrawTheirMasterPartUnderTheirSymmetry
  )
  {
    MapLayout layout;
    layout.New(64, 0.0f, 0.0f, 256.0f, 256.0f);
    std::string symmetry;
    EXPECT_FALSE(layout.ApplyTemplate("nope", symmetry));
    layout.SetImages(&HalfTurn);
    ASSERT_TRUE(layout.ApplyTemplate("duel", symmetry));
    EXPECT_EQ(symmetry, "rot2");
    EXPECT_EQ(layout.BaseCentres().size(), 2U) << "a base and its copy";
    ASSERT_TRUE(layout.ApplyTemplate("islands", symmetry));
    EXPECT_EQ(layout.Layers()[0].kind, LayoutKind::Water) << "the sea goes first";
    EXPECT_EQ(MapLayout::Templates().size(), 4U);
  }
} // namespace faf::editor
