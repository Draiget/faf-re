// The view frame of a Camera Info marker (src/editor/tools/EdCameraFrame.cpp, after FAF Studio's camframe.lua): the
// field of view over the zoom, the frustum from the marker's focus, heading, pitch and zoom, and where its corner
// rays meet the ground.

#include "editor/tools/EdCameraFrame.h"

#include <cmath>

#include <gtest/gtest.h>

namespace
{
  using faf::editor::CameraHit;

  constexpr float kPi = 3.14159265358979f;

  TEST(
    CameraFrame,
    FieldOfViewGoesFromNearToFarOverTheZoom
  )
  {
    EXPECT_NEAR(faf::editor::CameraFovFor(5.0f, 500.0f), 65.0f * kPi / 180.0f, 1e-5f);
    EXPECT_NEAR(faf::editor::CameraFovFor(500.0f, 500.0f), 60.0f * kPi / 180.0f, 1e-5f);
    EXPECT_NEAR(faf::editor::CameraFovFor(1.0f, 500.0f), 65.0f * kPi / 180.0f, 1e-5f); // under the near zoom
    const float middle = faf::editor::CameraFovFor(50.0f, 500.0f);                     // half way in log
    EXPECT_NEAR(middle, 62.5f * kPi / 180.0f, 1e-4f);
    EXPECT_NEAR(faf::editor::CameraFovFor(50.0f, 0.0f), 60.0f * kPi / 180.0f, 1e-5f); // no largest zoom
  }

  TEST(
    CameraFrame,
    StraightDownOnFlatGroundSeesTheZoomsWidth
  )
  {
    const float fov = 60.0f * kPi / 180.0f;
    const auto frustum = faf::editor::CameraFrustumOf({100.0f, 10.0f, 100.0f}, 0.0f, kPi * 0.5f, 40.0f, fov, 1.0f);
    // The eye above the focus, zoom / tan(fov / 2) / 2 up.
    EXPECT_NEAR(frustum.eye[0], 100.0f, 1e-3f);
    EXPECT_NEAR(frustum.eye[1], 10.0f + 20.0f / std::tan(fov * 0.5f), 1e-3f);
    EXPECT_NEAR(frustum.eye[2], 100.0f, 1e-3f);
    const faf::editor::CameraGround flat = [](float x, float z) -> std::optional<float> {
      if (x < 0.0f || z < 0.0f || x > 512.0f || z > 512.0f) {
        return std::nullopt;
      }
      return 10.0f;
    };
    const auto corners = faf::editor::CameraCorners(frustum, flat, 2000.0f, 400);
    for (const CameraHit& corner : corners) {
      EXPECT_EQ(corner.kind, CameraHit::Kind::Ground);
      EXPECT_NEAR(std::fabs(corner.point[0] - 100.0f), 20.0f, 0.05f);
      EXPECT_NEAR(std::fabs(corner.point[2] - 100.0f), 20.0f, 0.05f);
      EXPECT_NEAR(corner.point[1], 10.0f, 1e-3f);
    }
    // Top left and bottom right are opposite corners.
    EXPECT_NEAR(corners[0].point[0] + corners[2].point[0], 200.0f, 0.1f);
    EXPECT_NEAR(corners[0].point[2] + corners[2].point[2], 200.0f, 0.1f);
  }

  TEST(
    CameraFrame,
    ALevelCameraSeesTheSkyAtTheTop
  )
  {
    const float fov = 60.0f * kPi / 180.0f;
    // Heading 0 looks along +z; a level camera's upper rays never come down.
    const auto frustum = faf::editor::CameraFrustumOf({256.0f, 30.0f, 50.0f}, 0.0f, 0.0f, 60.0f, fov, 16.0f / 9.0f);
    EXPECT_NEAR(frustum.forward[2], 1.0f, 1e-6f);
    const faf::editor::CameraGround flat = [](float, float) -> std::optional<float> {
      return 0.0f;
    };
    const auto corners = faf::editor::CameraCorners(frustum, flat, 3000.0f, 300);
    EXPECT_EQ(corners[0].kind, CameraHit::Kind::Far);
    EXPECT_EQ(corners[1].kind, CameraHit::Kind::Far);
    EXPECT_EQ(corners[2].kind, CameraHit::Kind::Ground);
    EXPECT_EQ(corners[3].kind, CameraHit::Kind::Ground);
    EXPECT_GT(corners[2].point[2], 50.0f);
  }

  TEST(
    CameraFrame,
    ARayLeavingTheTerrainEndsAtItsEdge
  )
  {
    const faf::editor::CameraGround island = [](float x, float z) -> std::optional<float> {
      if (x < 0.0f || z < 0.0f || x > 100.0f || z > 100.0f) {
        return std::nullopt;
      }
      return 0.0f;
    };
    // From above the middle, shallow towards +x: it leaves the terrain at x 100 before reaching the ground.
    const float d = std::sqrt(1.0f + 0.01f * 0.01f);
    const auto hit =
      faf::editor::CameraRayGround({50.0f, 50.0f, 50.0f}, {1.0f / d, -0.01f / d, 0.0f}, island, 400.0f, 400);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->kind, CameraHit::Kind::Edge);
    EXPECT_NEAR(hit->point[0], 100.0f, 0.05f);
  }
} // namespace
