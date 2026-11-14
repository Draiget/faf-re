#pragma once

#include <array>
#include <functional>
#include <optional>

/**
 * The view of a Camera Info marker (after FAF Studio's camframe.lua): a marker keeps the camera's FOCUS point
 * (`position`), `orientation` = { heading, pitch, 0 } in radians and `zoom`, the world width of the view at the focus
 * point. The look direction is (sin h cos p, -sin p, cos h cos p): heading 0 looks along +z, pitch pi/2 straight down.
 * The eye sits zoom / tan(fov / 2) / 2 back from the focus. The field of view is for the longer side of the view, and
 * goes from 65 degrees at zoom 5 to 60 degrees at the camera's largest zoom over the log of the zoom (the engine's
 * cam_NearFOV, cam_NearZoom and cam_FarFOV defaults).
 */
namespace faf::editor
{
  using CameraVec = std::array<float, 3>;

  /** The field of view (radians) at `zoom` for a camera whose largest zoom is `maxZoom`. */
  [[nodiscard]] float CameraFovFor(float zoom, float maxZoom);

  struct CameraFrustum
  {
    CameraVec eye{};
    CameraVec focus{};
    float distance = 0.0f;
    CameraVec forward{};
    CameraVec right{};
    CameraVec up{};
    float halfWidth = 0.0f;  // at distance 1
    float halfHeight = 0.0f; // at distance 1
    /** The corner rays (unit), as the screen shows them: top left, top right, bottom right, bottom left. */
    std::array<CameraVec, 4> rays{};
  };

  [[nodiscard]] CameraFrustum
  CameraFrustumOf(const CameraVec& focus, float heading, float pitch, float zoom, float fov, float aspect);

  /** A point where a ray meets the ground; `edge` when the ray leaves the terrain first, `far` when it meets nothing.
   */
  struct CameraHit
  {
    CameraVec point{};
    float t = 0.0f;
    enum class Kind
    {
      Ground,
      Edge,
      Far,
    } kind = Kind::Far;
  };

  /** The ground's height at (x, z), or nothing outside the terrain. */
  using CameraGround = std::function<std::optional<float>(float x, float z)>;

  /** The first point where the ray from `eye` along the unit `direction` meets the ground, marched then bisected. */
  [[nodiscard]] std::optional<CameraHit> CameraRayGround(
    const CameraVec& eye,
    const CameraVec& direction,
    const CameraGround& ground,
    float maxDistance,
    int steps
  );

  /** Where the four corner rays meet the ground; one that meets nothing is laid far out at the eye's height. */
  [[nodiscard]] std::array<CameraHit, 4>
  CameraCorners(const CameraFrustum& frustum, const CameraGround& ground, float maxDistance, int steps);
} // namespace faf::editor
