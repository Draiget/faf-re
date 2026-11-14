#include "editor/doc/EdSaveFile.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdResize.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  namespace
  {
    const char* const kSave = R"(Scenario = {
    next_area_id = '2',
    Props = {
    },
    Areas = {
        ['AREA_1'] = {
            ['rectangle'] = RECTANGLE( 0, 0, 1024, 1024 ),
        },
        ['AREA_2'] = {
            ['rectangle'] = RECTANGLE( 600, 600, 700, 700 ),
        },
    },
    MasterChain = {
        ['_MASTERCHAIN_'] = {
            Markers = {
                ['ARMY_1'] = {
                    ['type'] = STRING( 'Blank Marker' ),
                    ['orientation'] = VECTOR3( 0, 0, 0 ),
                    ['position'] = VECTOR3( 100.5, 18, 200.5 ),
                },
                ['Far'] = {
                    ['type'] = STRING( 'Path Node' ),
                    ['orientation'] = VECTOR3( 0, 0, 0 ),
                    ['position'] = VECTOR3( 700, 20, 300 ),
                },
            },
        },
    },
    Chains = {
        ['Gone'] = {
            Markers = {
                "Far",
            },
        },
        ['Kept'] = {
            Markers = {
                "ARMY_1",
                "Far",
            },
        },
    },
    Armies =
    {
        ['ARMY_1'] =
        {
            personality = '',
            ['Units'] = GROUP {
                orders = '',
                platoon = '',
                Units = {
                    ['UNIT_1'] = {
                        type = 'ueb2101',
                        orders = '',
                        platoon = '',
                        Position = { 100.000000, 20.000000, 100.000000 },
                        Orientation = { 0.000000, 0.000000, 0.000000 },
                    },
                    ['UNIT_2'] = {
                        type = 'ueb2101',
                        orders = '',
                        platoon = '',
                        Position = { 900.000000, 20.000000, 900.000000 },
                        Orientation = { 0.000000, 0.000000, 0.000000 },
                    },
                },
            },
        },
    },
}
)";

    HeightImage Columns()
    {
      // A 4 x 4 map's 5 x 5 samples, each its column times 100.
      HeightImage image;
      image.width = 5;
      image.height = 5;
      for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
          image.words.push_back(static_cast<std::uint16_t>(x * 100));
        }
      }
      return image;
    }
  } // namespace

  TEST(
    Resize,
    CanvasCutDropsWhatFallsOutsideAndMovesTheRest
  )
  {
    ResizeOptions o;
    o.oldWidth = 1024;
    o.oldDepth = 1024;
    o.newWidth = 512;
    o.newDepth = 512;
    o.anchor = 0; // the top left kept
    const ResizeGeometry g = MakeResizeGeometry(o);
    ResizeReport report;
    std::string error;
    const std::string text = ResizeSaveText(kSave, g, report, error);
    ASSERT_FALSE(text.empty()) << error;
    SaveFile save;
    ASSERT_TRUE(save.Parse(text, error)) << error;
    ASSERT_EQ(save.Markers().size(), 1U);
    EXPECT_EQ(save.Markers()[0].name, "ARMY_1");
    float x = 0, y = 0, z = 0;
    ASSERT_TRUE(MarkerPosition(save.Markers()[0], x, y, z));
    EXPECT_FLOAT_EQ(x, 100.5f);
    EXPECT_FLOAT_EQ(z, 200.5f);
    ASSERT_EQ(save.Chains().size(), 1U) << "a chain left with none goes";
    EXPECT_EQ(save.Chains()[0].markers, (std::vector<std::string>{"ARMY_1"}));
    ASSERT_EQ(save.Areas().size(), 1U);
    EXPECT_EQ(ValueNumbers(save.Areas()[0].Get("rectangle")), (std::vector<double>{0, 0, 512, 512})) << "clipped";
    UnitGroup root;
    ASSERT_TRUE(ParseUnitGroup(save.Armies()[0].Get("Units"), root, error)) << error;
    ASSERT_EQ(root.units.size(), 1U);
    EXPECT_EQ(root.units[0].name, "UNIT_1");
    EXPECT_EQ(report.markersDropped, 1);
    EXPECT_EQ(report.chainsDropped, 1);
    EXPECT_EQ(report.areasDropped, 1);
    EXPECT_EQ(report.unitsDropped, 1);
    EXPECT_EQ(report.unitsKept, 1);
  }

  TEST(
    Resize,
    CanvasAnchorMovesByTheOffset
  )
  {
    ResizeOptions o;
    o.oldWidth = 512;
    o.oldDepth = 512;
    o.newWidth = 1024;
    o.newDepth = 1024;
    o.anchor = 4; // the old map in the middle
    const ResizeGeometry g = MakeResizeGeometry(o);
    float nx = 0, nz = 0;
    ASSERT_TRUE(ResizePoint(g, 0.0f, 512.0f, nx, nz));
    EXPECT_FLOAT_EQ(nx, 256.0f);
    EXPECT_FLOAT_EQ(nz, 768.0f);
    o.anchor = 8; // bottom right
    ASSERT_TRUE(ResizePoint(MakeResizeGeometry(o), 10.0f, 10.0f, nx, nz));
    EXPECT_FLOAT_EQ(nx, 522.0f);
    EXPECT_FLOAT_EQ(nz, 522.0f);
  }

  TEST(
    Resize,
    ScaleMultipliesEveryPosition
  )
  {
    ResizeOptions o;
    o.oldWidth = 1024;
    o.oldDepth = 1024;
    o.newWidth = 512;
    o.newDepth = 256;
    o.mode = ResizeMode::Scale;
    const ResizeGeometry g = MakeResizeGeometry(o);
    ResizeReport report;
    std::string error;
    const std::string text = ResizeSaveText(kSave, g, report, error);
    SaveFile save;
    ASSERT_TRUE(save.Parse(text, error)) << error;
    EXPECT_EQ(save.Markers().size(), 2U) << "nothing dropped";
    EXPECT_EQ(report.unitsKept, 2);
    float x = 0, y = 0, z = 0;
    ASSERT_TRUE(MarkerPosition(save.Markers()[1], x, y, z));
    EXPECT_FLOAT_EQ(x, 350.0f);
    EXPECT_FLOAT_EQ(z, 75.0f);
    EXPECT_FLOAT_EQ(y, 20.0f) << "heights stay";
  }

  TEST(
    Resize,
    ImagesPadAndScale
  )
  {
    ResizeOptions o;
    o.oldWidth = 4;
    o.oldDepth = 4;
    o.newWidth = 8;
    o.newDepth = 4;
    o.anchor = 0;
    const HeightImage edge = ResizeImage(Columns(), MakeResizeGeometry(o), 9, 5, true, 7);
    ASSERT_EQ(edge.words.size(), 45U);
    EXPECT_EQ(edge.words[3], 300);
    EXPECT_EQ(edge.words[4], 400);
    EXPECT_EQ(edge.words[8], 400) << "the edge repeated";
    const HeightImage level = ResizeImage(Columns(), MakeResizeGeometry(o), 9, 5, false, 7);
    EXPECT_EQ(level.words[4], 400);
    EXPECT_EQ(level.words[5], 7) << "the pad level";
    o.mode = ResizeMode::Scale;
    const HeightImage scaled = ResizeImage(Columns(), MakeResizeGeometry(o), 9, 5, true, 7);
    EXPECT_EQ(scaled.words[1], 50);
    EXPECT_EQ(scaled.words[8], 400);
    EXPECT_EQ(scaled.words[9 * 4 + 6], 300) << "rows alike";
  }

  TEST(
    Resize,
    ScenarioSize
  )
  {
    EXPECT_EQ(
      WithScenarioSize("    size = {512, 512},\r\n    map = 'x',", 1024, 256),
      "    size = {1024, 256},\r\n    map = 'x',"
    );
    EXPECT_EQ(WithScenarioSize("no size", 1, 1), "no size");
  }
} // namespace faf::editor
