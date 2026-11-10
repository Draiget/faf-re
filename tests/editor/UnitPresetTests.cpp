// The map editor's units files (src/editor/doc/EdUnitPreset.cpp): FAForeverMapEditor's `.scunits`, read and written.

#include "editor/doc/EdUnitPreset.h"

#include <cmath>

#include <gtest/gtest.h>

namespace
{
  using faf::editor::SaveUnit;

  // As FAFME's ExportUnits writes it (JsonUtility, pretty): a factory turned a quarter (Orientation y = pi/2: Unity's
  // y is -90 degrees, w = cos(-45), y = sin(-45)) and a tank.
  const char* const kFafme = R"({
    "Units": [
        {
            "ID": "ueb0101",
            "pos": {
                "x": 25.0,
                "y": 1.5,
                "z": -30.0
            },
            "rot": {
                "x": 0.0,
                "y": -0.7071067690849304,
                "z": 0.0,
                "w": 0.7071067690849304
            },
            "orders": "",
            "platoon": ""
        },
        {
            "ID": "uel0201",
            "pos": {
                "x": 27.0,
                "y": 1.5,
                "z": -32.0
            },
            "rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "orders": "",
            "platoon": "Attack"
        }
    ],
    "Center": {
        "x": 26.0,
        "y": 1.5,
        "z": -31.0
    }
})";

  TEST(UnitPreset, ReadsFafmesFile)
  {
    std::vector<SaveUnit> units;
    float centre[3];
    std::string error;
    ASSERT_TRUE(faf::editor::UnitsFromScunits(kFafme, units, centre, error)) << error;
    ASSERT_EQ(units.size(), 2u);
    EXPECT_EQ(units[0].type, "ueb0101");
    EXPECT_FLOAT_EQ(units[0].position[0], 250.0f);
    EXPECT_FLOAT_EQ(units[0].position[1], 15.0f);
    EXPECT_FLOAT_EQ(units[0].position[2], 300.0f);
    // The quarter turn comes back as the same direction (eulerAngles gives 270 degrees for -90).
    EXPECT_NEAR(std::remainder(units[0].orientation[1] - 3.14159265f / 2.0f, 2.0 * 3.14159265), 0.0, 1e-4);
    EXPECT_EQ(units[1].platoon, "Attack");
    EXPECT_FLOAT_EQ(centre[0], 260.0f);
    EXPECT_FLOAT_EQ(centre[2], 310.0f);
  }

  TEST(UnitPreset, WritesWhatItReads)
  {
    std::vector<SaveUnit> units;
    float centre[3];
    std::string error;
    ASSERT_TRUE(faf::editor::UnitsFromScunits(kFafme, units, centre, error)) << error;
    units[1].orders = "it's \"quoted\"";
    std::vector<SaveUnit> again;
    float centreAgain[3];
    ASSERT_TRUE(faf::editor::UnitsFromScunits(faf::editor::UnitsToScunits(units), again, centreAgain, error)) << error;
    ASSERT_EQ(again.size(), units.size());
    for (std::size_t i = 0; i < units.size(); ++i) {
      EXPECT_EQ(again[i].type, units[i].type);
      EXPECT_EQ(again[i].orders, units[i].orders);
      EXPECT_EQ(again[i].platoon, units[i].platoon);
      for (int a = 0; a < 3; ++a) {
        EXPECT_NEAR(again[i].position[a], units[i].position[a], 1e-3f);
        EXPECT_NEAR(std::remainder(again[i].orientation[a] - units[i].orientation[a], 2.0 * 3.14159265), 0.0, 1e-4);
      }
    }
    EXPECT_NEAR(centreAgain[0], 260.0f, 1e-3f);
    EXPECT_FALSE(faf::editor::UnitsFromScunits("{ \"Markers\": [] }", again, centreAgain, error));
  }

  TEST(UnitPreset, UnitsOffTheMapMoveTogether)
  {
    std::vector<SaveUnit> units;
    float centre[3];
    std::string error;
    ASSERT_TRUE(faf::editor::UnitsFromScunits(kFafme, units, centre, error)) << error;
    // On a 1024 map they fit and stay.
    EXPECT_FALSE(faf::editor::FitUnitsOnMap(units, centre, 1024.0f, 1024.0f));
    // On a 256 map the factory (250, 300) is off: both move by the same offset, their centre to the map's.
    ASSERT_TRUE(faf::editor::FitUnitsOnMap(units, centre, 256.0f, 256.0f));
    EXPECT_FLOAT_EQ(units[0].position[0], 250.0f - 132.0f);
    EXPECT_FLOAT_EQ(units[0].position[2], 300.0f - 182.0f);
    EXPECT_FLOAT_EQ(units[1].position[0] - units[0].position[0], 20.0f);
  }
} // namespace
