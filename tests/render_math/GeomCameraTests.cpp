// moho::GeomCamera3: the projection, view and frustum maths every picking ray and every culling test of the
// client uses. Expected values come from the geometry: a projected point unprojects to a ray through it,
// the centre ray is the view direction, the frustum planes keep what the projection keeps.

#include "moho/math/QuaternionMath.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/STIMap.h"

#include <gtest/gtest.h>

#include <cmath>
#include <random>

namespace
{
  constexpr float kFov = 1.2f;
  constexpr float kNear = 1.0f;
  constexpr float kFar = 1000.0f;

  float Dot(const Wm3::Vector3f& a, const Wm3::Vector3f& b)
  {
    return (a.x * b.x) + (a.y * b.y) + (a.z * b.z);
  }

  Wm3::Vector3f Sub(const Wm3::Vector3f& a, const Wm3::Vector3f& b)
  {
    return {a.x - b.x, a.y - b.y, a.z - b.z};
  }

  Wm3::Vector3f Add(const Wm3::Vector3f& a, const Wm3::Vector3f& b)
  {
    return {a.x + b.x, a.y + b.y, a.z + b.z};
  }

  Wm3::Vector3f Scale(const Wm3::Vector3f& a, const float s)
  {
    return {a.x * s, a.y * s, a.z * s};
  }

  float Length(const Wm3::Vector3f& v)
  {
    return std::sqrt(Dot(v, v));
  }

  Wm3::Vector3f Rotated(const Wm3::Quaternionf& q, const Wm3::Vector3f& v)
  {
    Wm3::Vector3f out{};
    moho::MultQuadVec(&out, &v, &q);
    return out;
  }

  Wm3::Quaternionf AxisAngle(const Wm3::Vector3f& axis, const float angle)
  {
    const float s = std::sin(angle * 0.5f);
    return Wm3::Quaternionf{std::cos(angle * 0.5f), axis.x * s, axis.y * s, axis.z * s};
  }

  // Distance from `p` to the infinite line through `line.pos` along the unit `line.dir`.
  float DistanceToLine(const moho::GeomLine3& line, const Wm3::Vector3f& p)
  {
    const Wm3::Vector3f offset = Sub(p, line.pos);
    const Wm3::Vector3f along = Scale(line.dir, Dot(offset, line.dir));
    return Length(Sub(offset, along));
  }

  bool Inside(const moho::CGeomSolid3& solid, const Wm3::Vector3f& p, const float slack = 0.0f)
  {
    for (const Wm3::Plane3f& plane : solid.planes_) {
      if (Dot(plane.Normal, p) - plane.Constant > slack) {
        return false;
      }
    }
    return true;
  }

  // A camera at `eye` turned by `orient`, looking down its own -z (the D3D projection's w = -z).
  moho::GeomCamera3 MakeCamera(const Wm3::Vector3f& eye, const Wm3::Quaternionf& orient, const float aspect = 1.0f)
  {
    moho::VTransform transform{};
    transform.orient_ = orient;
    transform.pos_ = eye;
    const moho::VMatrix4 projection = moho::VEC_D3DProjectionMatrixFOV(kFov, kFov, -kNear, -kFar, aspect);
    moho::GeomCamera3 camera(transform, projection);
    camera.viewport.r[3] = moho::Vector4f{0.0f, 0.0f, 800.0f, 800.0f / aspect};
    return camera;
  }

  void ExpectNear3(const Wm3::Vector3f& actual, const Wm3::Vector3f& expected, const float tolerance)
  {
    EXPECT_NEAR(actual.x, expected.x, tolerance);
    EXPECT_NEAR(actual.y, expected.y, tolerance);
    EXPECT_NEAR(actual.z, expected.z, tolerance);
  }
} // namespace

TEST(RenderGeomCamera, ProjectionMatrixMapsNearAndFarToDepthZeroAndOne)
{
  const moho::VMatrix4 m = moho::VEC_D3DProjectionMatrixFOV(kFov, kFov, -kNear, -kFar, 1.0f);
  const float t = std::tan(kFov * 0.5f);
  EXPECT_NEAR(m.r[0].x, 1.0f / t, 1.0e-5f);
  EXPECT_NEAR(m.r[1].y, 1.0f / t, 1.0e-5f);
  EXPECT_EQ(m.r[2].w, -1.0f);
  EXPECT_EQ(m.r[3].w, 0.0f);

  const auto ndcDepth = [&m](const float viewZ) { return ((viewZ * m.r[2].z) + m.r[3].z) / (-viewZ); };
  EXPECT_NEAR(ndcDepth(-kNear), 0.0f, 1.0e-5f);
  EXPECT_NEAR(ndcDepth(-kFar), 1.0f, 1.0e-5f);
  EXPECT_GT(ndcDepth(-10.0f), ndcDepth(-5.0f));

  // Wider than tall: the horizontal field is the given one and the vertical shrinks by the aspect.
  const moho::VMatrix4 wide = moho::VEC_D3DProjectionMatrixFOV(kFov, kFov, -kNear, -kFar, 2.0f);
  EXPECT_NEAR(wide.r[0].x, 1.0f / t, 1.0e-5f);
  EXPECT_NEAR(wide.r[1].y, 2.0f / t, 1.0e-4f);
}

TEST(RenderGeomCamera, ProjectHitsTheFrustumEdgesAndCentre)
{
  const moho::GeomCamera3 camera = MakeCamera({0.0f, 0.0f, 0.0f}, Wm3::Quaternionf{1.0f, 0.0f, 0.0f, 0.0f});
  const float t = std::tan(kFov * 0.5f);
  const float d = 50.0f;

  const Wm3::Vector2f centre = camera.Project({0.0f, 0.0f, -d});
  EXPECT_NEAR(centre.x, 400.0f, 1.0e-3f);
  EXPECT_NEAR(centre.y, 400.0f, 1.0e-3f);

  // The one-argument form flips y: up in the world is up on the screen (smaller y).
  const Wm3::Vector2f rightEdge = camera.Project({d * t, 0.0f, -d});
  const Wm3::Vector2f topEdge = camera.Project({0.0f, d * t, -d});
  EXPECT_NEAR(rightEdge.x, 800.0f, 1.0e-2f);
  EXPECT_NEAR(topEdge.y, 0.0f, 1.0e-2f);

  // The bounds form maps NDC onto any rectangle.
  const Wm3::Vector2f unit = camera.Project({d * t * 0.5f, -d * t * 0.5f, -d}, 0.0f, 1.0f, 0.0f, 1.0f);
  EXPECT_NEAR(unit.x, 0.75f, 1.0e-5f);
  EXPECT_NEAR(unit.y, 0.25f, 1.0e-5f);
}

TEST(RenderGeomCamera, UnprojectGivesARayThroughTheProjectedPoint)
{
  std::mt19937 rng(2024);
  std::uniform_real_distribution<float> lane(-1.0f, 1.0f);
  std::uniform_real_distribution<float> angle(-3.0f, 3.0f);
  std::uniform_real_distribution<float> depth(5.0f, 500.0f);

  for (int i = 0; i < 100; ++i) {
    Wm3::Vector3f axis{lane(rng), lane(rng), lane(rng)};
    const float axisLength = Length(axis);
    if (axisLength < 0.1f) {
      continue;
    }
    axis = Scale(axis, 1.0f / axisLength);
    const Wm3::Quaternionf orient = AxisAngle(axis, angle(rng));
    const Wm3::Vector3f eye{lane(rng) * 300.0f, lane(rng) * 300.0f, lane(rng) * 300.0f};
    const moho::GeomCamera3 camera = MakeCamera(eye, orient);

    // A point inside the frustum, built in view space and moved to the world.
    const float d = depth(rng);
    const float t = std::tan(kFov * 0.5f) * 0.9f;
    const Wm3::Vector3f local{lane(rng) * d * t, lane(rng) * d * t, -d};
    const Wm3::Vector3f world = Add(eye, Rotated(orient, local));
    SCOPED_TRACE(testing::Message() << "i=" << i << " depth " << d);

    const Wm3::Vector2f screen = camera.Project(world);
    EXPECT_GE(screen.x, 0.0f);
    EXPECT_LE(screen.x, 800.0f);
    EXPECT_GE(screen.y, 0.0f);
    EXPECT_LE(screen.y, 800.0f);

    const moho::GeomLine3 ray = camera.Unproject(screen);
    EXPECT_NEAR(Length(ray.dir), 1.0f, 1.0e-4f);
    EXPECT_EQ(ray.closest, 0.0f);
    // The ray runs from the near plane to the far plane along the point's view direction.
    const float expectedLength = Length(local) * (kFar - kNear) / d;
    EXPECT_NEAR(ray.farthest, expectedLength, expectedLength * 2.0e-3f);
    EXPECT_LT(DistanceToLine(ray, world), 2.0e-3f * d);
    EXPECT_LT(DistanceToLine(ray, eye), 2.0e-3f * d);
    EXPECT_GT(Dot(ray.dir, Sub(world, eye)), 0.0f);
    // The ray starts on the near plane.
    const Wm3::Vector3f forward = Rotated(orient, {0.0f, 0.0f, -1.0f});
    EXPECT_NEAR(Dot(Sub(ray.pos, eye), forward), kNear, 1.0e-2f);

    // Both frustum solids agree with the projection: the point is in, a point behind the eye is out.
    EXPECT_TRUE(Inside(camera.solid2, world, 1.0e-2f * d));
    EXPECT_FALSE(Inside(camera.solid2, Sub(eye, Scale(forward, 10.0f))));
    EXPECT_TRUE(Inside(camera.solid1, local, 1.0e-2f * d));
  }
}

TEST(RenderGeomCamera, CentreRayIsTheViewDirection)
{
  const Wm3::Quaternionf orient = AxisAngle({0.0f, 1.0f, 0.0f}, 0.8f);
  const Wm3::Vector3f eye{100.0f, 40.0f, -20.0f};
  const moho::GeomCamera3 camera = MakeCamera(eye, orient);
  const moho::GeomLine3 centre = camera.Unproject(Wm3::Vector2f{400.0f, 400.0f});
  ExpectNear3(centre.dir, Rotated(orient, {0.0f, 0.0f, -1.0f}), 1.0e-4f);

  // The inverse view's rows are the camera's axes and position (row-vector convention).
  const Wm3::Vector3f xAxis = Rotated(orient, {1.0f, 0.0f, 0.0f});
  ExpectNear3({camera.inverseView.r[0].x, camera.inverseView.r[0].y, camera.inverseView.r[0].z}, xAxis, 1.0e-5f);
  ExpectNear3({camera.inverseView.r[3].x, camera.inverseView.r[3].y, camera.inverseView.r[3].z}, eye, 1.0e-4f);

  // view * inverseView is the identity.
  const moho::VMatrix4 identity = moho::VMatrix4::Multiply(camera.view, camera.inverseView);
  for (int r = 0; r < 4; ++r) {
    const float* row = &identity.r[r].x;
    for (int c = 0; c < 4; ++c) {
      EXPECT_NEAR(row[c], r == c ? 1.0f : 0.0f, 1.0e-4f) << "r=" << r << " c=" << c;
    }
  }
}

TEST(RenderGeomCamera, FrustumPlanesBoundTheView)
{
  const moho::GeomCamera3 camera = MakeCamera({0.0f, 0.0f, 0.0f}, Wm3::Quaternionf{1.0f, 0.0f, 0.0f, 0.0f});
  ASSERT_EQ(camera.solid2.planes_.Size(), 6u);
  for (const Wm3::Plane3f& plane : camera.solid2.planes_) {
    EXPECT_NEAR(Length(plane.Normal), 1.0f, 1.0e-5f);
  }

  const float t = std::tan(kFov * 0.5f);
  EXPECT_TRUE(Inside(camera.solid2, {0.0f, 0.0f, -10.0f}));
  EXPECT_TRUE(Inside(camera.solid2, {0.0f, 0.0f, -999.0f}));
  EXPECT_FALSE(Inside(camera.solid2, {0.0f, 0.0f, -1001.0f}));   // past the far plane
  EXPECT_FALSE(Inside(camera.solid2, {0.0f, 0.0f, -0.5f}));      // before the near plane
  EXPECT_FALSE(Inside(camera.solid2, {0.0f, 0.0f, 10.0f}));      // behind
  EXPECT_FALSE(Inside(camera.solid2, {20.0f * t * 1.05f, 0.0f, -20.0f}));
  EXPECT_TRUE(Inside(camera.solid2, {20.0f * t * 0.95f, 0.0f, -20.0f}));
  EXPECT_FALSE(Inside(camera.solid2, {0.0f, -20.0f * t * 1.05f, -20.0f}));

  // The solid's box tests use the same planes.
  EXPECT_TRUE(camera.solid2.Intersects(Wm3::AxisAlignedBox3f({-1.0f, -1.0f, -12.0f}, {1.0f, 1.0f, -10.0f})));
  EXPECT_FALSE(camera.solid2.Intersects(Wm3::AxisAlignedBox3f({-1.0f, -1.0f, 5.0f}, {1.0f, 1.0f, 8.0f})));
  EXPECT_TRUE(camera.solid2.Intersects(Wm3::Sphere3f({0.0f, 0.0f, -50.0f}, 2.0f)));
  EXPECT_FALSE(camera.solid2.Intersects(Wm3::Sphere3f({500.0f, 0.0f, -50.0f}, 2.0f)));
}

TEST(RenderGeomCamera, ScreenRectangleUnprojectsToASubFrustum)
{
  const moho::GeomCamera3 camera = MakeCamera({10.0f, 20.0f, 30.0f}, AxisAngle({1.0f, 0.0f, 0.0f}, -0.4f));
  gpg::Rect2f rect{};
  rect.x0 = 200.0f;
  rect.x1 = 500.0f;
  rect.z0 = 100.0f;
  rect.z1 = 300.0f;
  const moho::CGeomSolid3 solid = camera.Unproject(rect);
  ASSERT_EQ(solid.planes_.Size(), 6u);

  // Points whose screen projection (the one-argument form, y down) lands inside the rectangle are inside the
  // solid: Unproject's y planes keep clip y between -ndcY1 and -ndcY0, the same flip.
  std::mt19937 rng(5);
  std::uniform_real_distribution<float> lane(-1.0f, 1.0f);
  int inside = 0;
  int outside = 0;
  const Wm3::Quaternionf orient = AxisAngle({1.0f, 0.0f, 0.0f}, -0.4f);
  for (int i = 0; i < 400; ++i) {
    const float d = 20.0f + (lane(rng) + 1.0f) * 200.0f;
    const float t = std::tan(kFov * 0.5f);
    const Wm3::Vector3f world =
      Add({10.0f, 20.0f, 30.0f}, Rotated(orient, {lane(rng) * d * t, lane(rng) * d * t, -d}));
    const Wm3::Vector2f s = camera.Project(world);
    const bool margin = std::fabs(s.x - rect.x0) < 2.0f || std::fabs(s.x - rect.x1) < 2.0f
                     || std::fabs(s.y - rect.z0) < 2.0f || std::fabs(s.y - rect.z1) < 2.0f;
    if (margin) {
      continue;
    }
    const bool expected = s.x > rect.x0 && s.x < rect.x1 && s.y > rect.z0 && s.y < rect.z1;
    EXPECT_EQ(Inside(solid, world), expected) << "screen " << s.x << ", " << s.y;
    (expected ? inside : outside) += 1;
  }
  EXPECT_GT(inside, 10);
  EXPECT_GT(outside, 10);
}

TEST(RenderGeomCamera, LodRowIsTheViewWidthAtThePointsDepth)
{
  moho::GeomCamera3 camera = MakeCamera({0.0f, 50.0f, 0.0f}, AxisAngle({0.0f, 1.0f, 0.0f}, 1.0f));
  const Wm3::Quaternionf orient = AxisAngle({0.0f, 1.0f, 0.0f}, 1.0f);
  const float t = std::tan(kFov * 0.5f);
  for (const float d : {5.0f, 50.0f, 400.0f}) {
    const Wm3::Vector3f p = Add({0.0f, 50.0f, 0.0f}, Rotated(orient, {3.0f, -2.0f, -d}));
    const moho::Vector4f& row = camera.viewport.r[0];
    const float width = (row.x * p.x) + (row.y * p.y) + (row.z * p.z) + row.w;
    EXPECT_NEAR(width, 2.0f * d * t, 2.0e-3f * d) << "depth " << d;
  }

  camera.SetLODScale(0.5f);
  EXPECT_FLOAT_EQ(camera.lodScale, 0.5f);
  EXPECT_FLOAT_EQ(camera.viewport.r[1].z, camera.viewport.r[0].z * 0.5f);
  EXPECT_FLOAT_EQ(camera.viewport.r[1].w, camera.viewport.r[0].w * 0.5f);
  // 0x00470B90 folds the scale into r[2] too, then divides by the viewport width.
  EXPECT_NEAR(camera.viewport.r[2].w, camera.viewport.r[0].w * 0.5f / camera.viewport.r[3].z, 1.0e-6f);
}

TEST(RenderGeomCamera, MoveAndSetProjectionKeepTheOtherHalf)
{
  moho::GeomCamera3 camera = MakeCamera({0.0f, 0.0f, 0.0f}, Wm3::Quaternionf{1.0f, 0.0f, 0.0f, 0.0f});
  moho::VTransform moved{};
  moved.pos_ = {5.0f, 6.0f, 7.0f};
  camera.Move(moved);
  EXPECT_NEAR(camera.inverseView.r[3].x, 5.0f, 1.0e-6f);
  EXPECT_NEAR(camera.projection.r[2].w, -1.0f, 0.0f);

  const moho::VMatrix4 other = moho::VEC_D3DProjectionMatrixFOV(0.5f, 0.5f, -2.0f, -20.0f, 1.0f);
  camera.SetProjection(other);
  EXPECT_FLOAT_EQ(camera.projection.r[0].x, other.r[0].x);
  EXPECT_NEAR(camera.inverseView.r[3].z, 7.0f, 1.0e-6f);

  // 0x00471770 ignores its arguments and always builds a 90-degree, near -10 / far -10000 projection.
  camera.ViewInitPerspective(0.1f, 0.2f, -3.0f, -4.0f);
  const moho::VMatrix4 fixed = moho::VEC_D3DProjectionMatrixFOV(1.5707964f, 1.5707964f, -10.0f, -10000.0f, 1.0f);
  for (int r = 0; r < 4; ++r) {
    EXPECT_FLOAT_EQ(camera.projection.r[r].x, fixed.r[r].x);
    EXPECT_FLOAT_EQ(camera.projection.r[r].z, fixed.r[r].z);
  }

  // A default camera is the identity view with the unit viewport.
  const moho::GeomCamera3 defaults;
  EXPECT_EQ(defaults.viewport.r[3].z, 1.0f);
  EXPECT_EQ(defaults.view.r[0].x, 1.0f);
  EXPECT_EQ(defaults.solid1.planes_.Size(), 6u);
}

TEST(RenderGeomCamera, OrthographicProjectionIsPixelLinear)
{
  moho::GeomCamera3 camera{};
  camera.ViewInitOrtho(600, 800, -1.0f, -100.0f);
  camera.viewport.r[3] = moho::Vector4f{0.0f, 0.0f, 800.0f, 600.0f};
  // 0x00471610: the view spans the viewport in world units, shifted by half a pixel.
  const Wm3::Vector2f origin = camera.Project({0.0f, 0.0f, -10.0f});
  EXPECT_NEAR(origin.x, 400.0f - 0.5f, 1.0e-3f);
  EXPECT_NEAR(origin.y, 300.0f - 0.5f, 1.0e-3f);
  const Wm3::Vector2f moved = camera.Project({100.0f, 50.0f, -60.0f});
  EXPECT_NEAR(moved.x - origin.x, 100.0f, 1.0e-3f);
  EXPECT_NEAR(moved.y - origin.y, -50.0f, 1.0e-3f);
}

TEST(RenderGeomCamera, LookAtPlacesTheCamera)
{
  moho::GeomCamera3 camera{};
  const Wm3::Vector3f eye{10.0f, 30.0f, -40.0f};
  const Wm3::Vector3f target{50.0f, 0.0f, 20.0f};
  camera.LookAt(eye, target, {0.0f, 1.0f, 0.0f});
  Wm3::Vector3f forward = Sub(target, eye);
  forward = Scale(forward, 1.0f / Length(forward));
  const moho::VMatrix4& m = camera.inverseView;
  ExpectNear3({m.r[3].x, m.r[3].y, m.r[3].z}, eye, 1.0e-4f);
  ExpectNear3({m.r[2].x, m.r[2].y, m.r[2].z}, forward, 1.0e-4f);
  const Wm3::Vector3f right{m.r[0].x, m.r[0].y, m.r[0].z};
  const Wm3::Vector3f up{m.r[1].x, m.r[1].y, m.r[1].z};
  EXPECT_NEAR(Dot(right, forward), 0.0f, 1.0e-5f);
  EXPECT_NEAR(Dot(up, forward), 0.0f, 1.0e-5f);
  EXPECT_NEAR(right.y, 0.0f, 1.0e-5f); // no roll
  EXPECT_GT(up.y, 0.0f);

  // Straight down with +y up: the collinear fallback still gives an orthonormal basis.
  moho::VMatrix4 basis{};
  moho::VEC_LookAtMatrix({0.0f, 10.0f, 0.0f}, {0.0f, 0.0f, 0.0f}, &basis, {0.0f, 1.0f, 0.0f});
  const Wm3::Vector3f r0{basis.r[0].x, basis.r[0].y, basis.r[0].z};
  const Wm3::Vector3f r1{basis.r[1].x, basis.r[1].y, basis.r[1].z};
  const Wm3::Vector3f r2{basis.r[2].x, basis.r[2].y, basis.r[2].z};
  EXPECT_NEAR(Length(r0), 1.0f, 1.0e-5f);
  EXPECT_NEAR(Length(r1), 1.0f, 1.0e-5f);
  EXPECT_NEAR(Dot(r0, r2), 0.0f, 1.0e-5f);
  EXPECT_NEAR(Dot(r0, r1), 0.0f, 1.0e-5f);
  ExpectNear3(r2, {0.0f, -1.0f, 0.0f}, 1.0e-6f);

  // The view matrix is the inverse of the look-at basis.
  moho::VMatrix4 lookAt{};
  moho::VMatrix4 view{};
  moho::VEC_LookAtMatrix(eye, target, &lookAt, {0.0f, 1.0f, 0.0f});
  moho::VEC_LookAtViewMatrix(eye, target, &view, {0.0f, 1.0f, 0.0f});
  const moho::VMatrix4 product = moho::VMatrix4::Multiply(lookAt, view);
  for (int r = 0; r < 4; ++r) {
    const float* row = &product.r[r].x;
    for (int c = 0; c < 4; ++c) {
      EXPECT_NEAR(row[c], r == c ? 1.0f : 0.0f, 1.0e-4f) << "r=" << r << " c=" << c;
    }
  }
}

TEST(RenderGeomCamera, BoxProjectionEnclosesEveryCorner)
{
  const Wm3::Vector3f corners[8] = {
    {1.0f, 2.0f, 3.0f}, {-4.0f, 0.0f, 1.0f}, {0.0f, 9.0f, 0.0f}, {2.0f, 2.0f, -7.0f},
    {0.5f, 0.5f, 0.5f}, {3.0f, -1.0f, 2.0f}, {0.0f, 0.0f, 0.0f}, {1.0f, 1.0f, 8.0f},
  };
  Wm3::AxisAlignedBox3f enclosed{};
  moho::EncloseCornerSet(&enclosed, corners);
  ExpectNear3(enclosed.Min, {-4.0f, -1.0f, -7.0f}, 0.0f);
  ExpectNear3(enclosed.Max, {3.0f, 9.0f, 8.0f}, 0.0f);

  const Wm3::AxisAlignedBox3f box({-1.0f, -2.0f, -30.0f}, {1.0f, 2.0f, -10.0f});
  moho::VMatrix4 translate = moho::VMatrix4::Identity();
  translate.r[3] = moho::Vector4f{5.0f, 0.0f, 1.0f, 1.0f};
  Wm3::AxisAlignedBox3f moved{};
  moho::ProjectBoxByMatrix(&translate, &box, &moved);
  ExpectNear3(moved.Min, {4.0f, -2.0f, -29.0f}, 1.0e-6f);
  ExpectNear3(moved.Max, {6.0f, 2.0f, -9.0f}, 1.0e-6f);

  // Through a perspective view-projection every corner, divided by its own w, lands inside the box.
  const moho::GeomCamera3 camera = MakeCamera({0.0f, 0.0f, 0.0f}, Wm3::Quaternionf{1.0f, 0.0f, 0.0f, 0.0f});
  Wm3::AxisAlignedBox3f projected{};
  moho::ProjectBoxByMatrix(&camera.viewProjection, &box, &projected);
  for (int i = 0; i < 8; ++i) {
    const float x = (i & 1) ? box.Max.x : box.Min.x;
    const float y = (i & 2) ? box.Max.y : box.Min.y;
    const float z = (i & 4) ? box.Max.z : box.Min.z;
    const moho::VMatrix4& m = camera.viewProjection;
    const float w = (m.r[0].w * x) + (m.r[1].w * y) + (m.r[2].w * z) + m.r[3].w;
    const float px = ((m.r[0].x * x) + (m.r[1].x * y) + (m.r[2].x * z) + m.r[3].x) / w;
    EXPECT_GE(px, projected.Min.x - 1.0e-5f);
    EXPECT_LE(px, projected.Max.x + 1.0e-5f);
  }
  EXPECT_GT(projected.Min.z, 0.0f);
  EXPECT_LT(projected.Max.z, 1.0f);
}

TEST(RenderGeomCamera, ViewportPixelProjectionMapsPixelCornersToNdcCorners)
{
  moho::GeomCamera3 camera{};
  camera.viewport.r[3] = moho::Vector4f{0.0f, 0.0f, 640.7f, 480.2f}; // truncated to whole pixels
  const moho::VMatrix4 m = moho::MakeViewportPixelProjection(camera);
  const auto ndc = [&m](const float x, const float y) {
    return Wm3::Vector2f{(x * m.r[0].x) + m.r[3].x, (y * m.r[1].y) + m.r[3].y};
  };
  // 0x00858EA1: the half-texel shift moves the pixel grid by half a pixel.
  const Wm3::Vector2f topLeft = ndc(0.5f, 0.5f);
  const Wm3::Vector2f bottomRight = ndc(640.5f, 480.5f);
  EXPECT_NEAR(topLeft.x, -1.0f, 1.0e-5f);
  EXPECT_NEAR(topLeft.y, 1.0f, 1.0e-5f);
  EXPECT_NEAR(bottomRight.x, 1.0f, 1.0e-5f);
  EXPECT_NEAR(bottomRight.y, -1.0f, 1.0e-5f);
  EXPECT_EQ(m.r[3].w, 1.0f);
}
