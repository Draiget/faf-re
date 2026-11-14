#include "editor/tools/EdCameraFrame.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    constexpr float kNearZoom = 5.0f;
    constexpr float kNearFov = 65.0f;
    constexpr float kFarFov = 60.0f;
    constexpr float kDegree = 0.017453292519943295f;

    CameraVec Normalized(
      const float x,
      const float y,
      const float z
    )
    {
      const float length = std::sqrt(x * x + y * y + z * z);
      if (length < 1e-12f) {
        return {0.0f, 1.0f, 0.0f};
      }
      return {x / length, y / length, z / length};
    }

    // 0: outside the terrain; 1: above the ground; 2: on or under it.
    int Probe(
      const CameraVec& eye,
      const CameraVec& d,
      const CameraGround& ground,
      const float t,
      CameraVec& at,
      float& height
    )
    {
      at = {eye[0] + d[0] * t, eye[1] + d[1] * t, eye[2] + d[2] * t};
      const std::optional<float> g = ground(at[0], at[2]);
      if (!g) {
        return 0;
      }
      height = *g;
      return at[1] <= *g ? 2 : 1;
    }
  } // namespace

  float CameraFovFor(
    const float zoom,
    const float maxZoom
  )
  {
    if (maxZoom <= kNearZoom) {
      return kFarFov * kDegree;
    }
    const float z = std::clamp(zoom, kNearZoom, maxZoom);
    const float f = (std::log(z) - std::log(kNearZoom)) / (std::log(maxZoom) - std::log(kNearZoom));
    return (f * (kFarFov - kNearFov) + kNearFov) * kDegree;
  }

  CameraFrustum CameraFrustumOf(
    const CameraVec& focus,
    const float heading,
    const float pitch,
    const float zoom,
    const float fov,
    const float aspect
  )
  {
    const float sh = std::sin(heading);
    const float ch = std::cos(heading);
    const float sp = std::sin(pitch);
    const float cp = std::cos(pitch);
    CameraFrustum out;
    out.forward = {sh * cp, -sp, ch * cp};
    out.right = {-ch, 0.0f, sh};
    out.up = {sh * sp, cp, ch * sp};
    const float t = std::tan(fov * 0.5f);
    if (aspect >= 1.0f) {
      out.halfWidth = t;
      out.halfHeight = t / aspect;
    } else {
      out.halfHeight = t;
      out.halfWidth = t * aspect;
    }
    out.distance = zoom / t / 2.0f;
    out.focus = focus;
    for (int i = 0; i < 3; ++i) {
      out.eye[static_cast<std::size_t>(i)] =
        focus[static_cast<std::size_t>(i)] - out.forward[static_cast<std::size_t>(i)] * out.distance;
    }
    constexpr float kSigns[4][2] = {{-1.0f, 1.0f}, {1.0f, 1.0f}, {1.0f, -1.0f}, {-1.0f, -1.0f}};
    for (std::size_t i = 0; i < 4; ++i) {
      const float sx = kSigns[i][0] * out.halfWidth;
      const float sy = kSigns[i][1] * out.halfHeight;
      out.rays[i] = Normalized(
        out.forward[0] + sx * out.right[0] + sy * out.up[0],
        out.forward[1] + sx * out.right[1] + sy * out.up[1],
        out.forward[2] + sx * out.right[2] + sy * out.up[2]
      );
    }
    return out;
  }

  std::optional<CameraHit> CameraRayGround(
    const CameraVec& eye,
    const CameraVec& direction,
    const CameraGround& ground,
    const float maxDistance,
    const int steps
  )
  {
    // A ray that doesn't go down meets no ground.
    if (direction[1] >= -1e-6f || steps <= 0 || !ground) {
      return std::nullopt;
    }
    const float dt = maxDistance / static_cast<float>(steps);
    CameraVec at{};
    float height = 0.0f;
    int previous = Probe(eye, direction, ground, 0.0f, at, height);
    float previousT = 0.0f;
    for (int i = 1; i <= steps; ++i) {
      const float t = static_cast<float>(i) * dt;
      const int state = Probe(eye, direction, ground, t, at, height);
      if (state != previous) {
        if (previous == 1) {
          float a = previousT;
          float b = t;
          for (int k = 0; k < 18; ++k) {
            const float middle = (a + b) * 0.5f;
            CameraVec m{};
            float mh = 0.0f;
            if (Probe(eye, direction, ground, middle, m, mh) == state) {
              b = middle;
            } else {
              a = middle;
            }
          }
          CameraVec p{};
          float ph = p[1];
          const int last = Probe(eye, direction, ground, a, p, ph);
          CameraHit hit;
          hit.point = {p[0], last == 0 ? p[1] : ph, p[2]};
          hit.t = a;
          hit.kind = state == 2 ? CameraHit::Kind::Ground : CameraHit::Kind::Edge;
          return hit;
        }
        if (previous == 0 && state == 2) {
          // It entered the terrain already under the ground (a steep rim).
          CameraHit hit;
          hit.point = {at[0], height, at[2]};
          hit.t = t;
          hit.kind = CameraHit::Kind::Ground;
          return hit;
        }
      }
      previous = state;
      previousT = t;
    }
    return std::nullopt;
  }

  std::array<CameraHit, 4> CameraCorners(
    const CameraFrustum& frustum,
    const CameraGround& ground,
    const float maxDistance,
    const int steps
  )
  {
    std::array<CameraHit, 4> out{};
    const float far = std::min(maxDistance, frustum.distance * 4.0f + 300.0f);
    for (std::size_t i = 0; i < 4; ++i) {
      const CameraVec& d = frustum.rays[i];
      if (const std::optional<CameraHit> hit = CameraRayGround(frustum.eye, d, ground, maxDistance, steps)) {
        out[i] = *hit;
        continue;
      }
      float hx = d[0];
      float hz = d[2];
      float length = std::sqrt(hx * hx + hz * hz);
      if (length < 1e-6f) {
        hx = frustum.forward[0];
        hz = frustum.forward[2];
        length = std::sqrt(hx * hx + hz * hz);
      }
      if (length < 1e-6f) {
        hx = 0.0f;
        hz = 1.0f;
        length = 1.0f;
      }
      out[i].point = {frustum.eye[0] + hx / length * far, frustum.eye[1], frustum.eye[2] + hz / length * far};
      out[i].t = far;
      out[i].kind = CameraHit::Kind::Far;
    }
    return out;
  }
} // namespace faf::editor
