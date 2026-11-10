// The map editor's marker files (src/editor/doc/EdMarkerPreset.cpp): FAForeverMapEditor's `.fafmapmarkers`, read and
// written, with Unity's Euler angles and FAFME's world units.

#include "editor/doc/EdMarkerPreset.h"

#include <cmath>

#include <gtest/gtest.h>

#include "editor/doc/EdJson.h"
#include "editor/tools/EdMarkers.h"

namespace
{
  using faf::editor::SaveEntry;

  // As FAFME's ExportSelectedMarkers writes it (JsonUtility, pretty): a mass point, two linked land path nodes, a weather
  // generator (a type the editor doesn't place) and a camera.
  const char* const kFafme = R"({
    "Markers": [
        {
            "MarkerType": 1,
            "Pos": {
                "x": 12.5,
                "y": 1.75,
                "z": -30.0
            },
            "Rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "Connected": []
        },
        {
            "MarkerType": 14,
            "Pos": {
                "x": 20.0,
                "y": 2.0,
                "z": -20.0
            },
            "Rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "Connected": [
                2
            ]
        },
        {
            "MarkerType": 14,
            "Pos": {
                "x": 25.0,
                "y": 2.0,
                "z": -20.0
            },
            "Rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "Connected": [
                1
            ]
        },
        {
            "MarkerType": 22,
            "Pos": {
                "x": 1.0,
                "y": 1.0,
                "z": -1.0
            },
            "Rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "Connected": []
        },
        {
            "MarkerType": 4,
            "Pos": {
                "x": 51.2,
                "y": 3.0,
                "z": -51.2
            },
            "Rot": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0,
                "w": 1.0
            },
            "Connected": []
        }
    ],
    "MapWidth": 1024,
    "MapHeight": 1024
})";

  TEST(MarkerPreset, ReadsFafmesFile)
  {
    std::vector<SaveEntry> markers = {faf::editor::NewMarker(*faf::editor::FindMarkerType("Mass"), "Mass 00", 1.0f, 2.0f, 3.0f)};
    faf::editor::MarkerImport result;
    std::string error;
    ASSERT_TRUE(faf::editor::MarkersFromFafmapmarkers(kFafme, markers, result, error)) << error;
    ASSERT_EQ(result.names.size(), 4u);
    EXPECT_EQ(result.skipped, 1);
    EXPECT_EQ(result.links, 1);
    ASSERT_EQ(markers.size(), 5u);
    // The new mass point takes the next free name; FAFME's units are a tenth of the game's, z flipped.
    EXPECT_EQ(markers[1].name, "Mass 01");
    float x = 0.0f, y = 0.0f, z = 0.0f;
    ASSERT_TRUE(faf::editor::MarkerPosition(markers[1], x, y, z));
    EXPECT_FLOAT_EQ(x, 125.0f);
    EXPECT_FLOAT_EQ(y, 17.5f);
    EXPECT_FLOAT_EQ(z, 300.0f);
    EXPECT_EQ(faf::editor::MarkerTypeOf(markers[2]), "Land Path Node");
    EXPECT_TRUE(faf::editor::MarkersLinked(markers, markers[2].name, markers[3].name));
    EXPECT_EQ(faf::editor::MarkerTypeOf(markers[4]), "Camera Info");
  }

  TEST(MarkerPreset, WritesWhatItReads)
  {
    std::vector<SaveEntry> markers;
    faf::editor::MarkerImport result;
    std::string error;
    ASSERT_TRUE(faf::editor::MarkersFromFafmapmarkers(kFafme, markers, result, error)) << error;
    // A path node outside the export keeps its link out of the file.
    markers.push_back(faf::editor::NewMarker(*faf::editor::FindMarkerType("Land Path Node"), "Outside", 0.0f, 0.0f, 0.0f));
    ASSERT_TRUE(faf::editor::SetMarkerLink(markers, result.names[1], "Outside", true));
    const std::string text = faf::editor::MarkersToFafmapmarkers(markers, result.names, 1024, 1024);
    std::vector<SaveEntry> again;
    faf::editor::MarkerImport second;
    ASSERT_TRUE(faf::editor::MarkersFromFafmapmarkers(text, again, second, error)) << error;
    ASSERT_EQ(again.size(), markers.size() - 1);
    EXPECT_EQ(second.links, 1);
    EXPECT_EQ(second.skipped, 0);
    for (std::size_t i = 0; i < again.size(); ++i) {
      EXPECT_EQ(again[i].name, markers[i].name);
      EXPECT_EQ(faf::editor::MarkerTypeOf(again[i]), faf::editor::MarkerTypeOf(markers[i]));
      float ax = 0, ay = 0, az = 0, bx = 0, by = 0, bz = 0;
      ASSERT_TRUE(faf::editor::MarkerPosition(again[i], ax, ay, az));
      ASSERT_TRUE(faf::editor::MarkerPosition(markers[i], bx, by, bz));
      EXPECT_NEAR(ax, bx, 1e-3f);
      EXPECT_NEAR(ay, by, 1e-3f);
      EXPECT_NEAR(az, bz, 1e-3f);
    }
    EXPECT_EQ(faf::editor::MarkerLinks(again[1]).size(), 1u);
    EXPECT_FALSE(faf::editor::MarkersFromFafmapmarkers("{ \"LightingMultiplier\": 1 }", again, second, error));
  }

  TEST(MarkerPreset, AStartPositionSkipsTheArmiesNames)
  {
    const char* const start = R"({ "Markers": [ { "MarkerType": 3, "Pos": { "x": 1.0, "y": 1.0, "z": -1.0 }, "Rot": { "x": 0.0, "y": 0.0, "z": 0.0, "w": 1.0 }, "Connected": [] } ] })";
    std::vector<SaveEntry> markers = {faf::editor::NewMarker(*faf::editor::FindMarkerType("Blank Marker"), "ARMY_1", 0.0f, 0.0f, 0.0f)};
    faf::editor::MarkerImport result;
    std::string error;
    ASSERT_TRUE(faf::editor::MarkersFromFafmapmarkers(start, markers, result, error, {"ARMY_1", "ARMY_2", "ARMY_9"})) << error;
    ASSERT_EQ(result.names.size(), 1u);
    EXPECT_EQ(result.names[0], "ARMY_3");
  }

  TEST(MarkerPreset, UnityEulerAnglesRoundTrip)
  {
    float q[4];
    faf::editor::UnityEulerToQuaternion({0.0f, 90.0f, 0.0f}, q);
    EXPECT_NEAR(q[1], std::sqrt(0.5f), 1e-6f);
    EXPECT_NEAR(q[3], std::sqrt(0.5f), 1e-6f);
    faf::editor::UnityEulerToQuaternion({90.0f, 0.0f, 0.0f}, q);
    EXPECT_NEAR(q[0], std::sqrt(0.5f), 1e-6f);
    // Unity applies z, then x, then y: (30, 45, 60) is Qy(45) * Qx(30) * Qz(60).
    faf::editor::UnityEulerToQuaternion({30.0f, 45.0f, 60.0f}, q);
    float e[3];
    faf::editor::UnityQuaternionToEuler(q, e);
    EXPECT_NEAR(e[0], 30.0f, 1e-3f);
    EXPECT_NEAR(e[1], 45.0f, 1e-3f);
    EXPECT_NEAR(e[2], 60.0f, 1e-3f);
    faf::editor::UnityEulerToQuaternion({-20.0f, 0.0f, 0.0f}, q);
    faf::editor::UnityQuaternionToEuler(q, e);
    EXPECT_NEAR(e[0], 340.0f, 1e-3f);
  }

  TEST(MarkerPreset, ACamerasHeadingAndPitchComeBack)
  {
    std::vector<SaveEntry> markers = {faf::editor::NewMarker(*faf::editor::FindMarkerType("Camera Info"), "Camera Info 00", 100.0f, 10.0f, 200.0f)};
    markers[0].Set("orientation", faf::editor::Vector3Value(0.5, 1.2, 0.0));
    const std::string text = faf::editor::MarkersToFafmapmarkers(markers, {}, 512, 512);
    std::vector<SaveEntry> again;
    faf::editor::MarkerImport result;
    std::string error;
    ASSERT_TRUE(faf::editor::MarkersFromFafmapmarkers(text, again, result, error)) << error;
    ASSERT_EQ(again.size(), 1u);
    const std::vector<double> orientation = faf::editor::ValueNumbers(again[0].Get("orientation"));
    ASSERT_EQ(orientation.size(), 3u);
    // FAFME gives the heading back as eulerAngles' y negated: the same direction, a whole turn away.
    EXPECT_NEAR(std::remainder(orientation[0] - 0.5, 2.0 * 3.14159265358979), 0.0, 1e-4);
    EXPECT_NEAR(orientation[1], 1.2, 1e-4);
  }
} // namespace
