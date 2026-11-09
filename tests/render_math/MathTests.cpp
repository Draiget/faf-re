// moho/math: the vector, quaternion, box and Wild Magic query helpers, checked against the maths they
// implement (a rotation keeps lengths, a quaternion and its matrix rotate alike, a point found on a box
// is on the box). Where a function keeps a retail quirk, the expectation cites the binary.

#include "moho/math/GridPos.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector2f.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include "moho/math/Wm3Queries.h"
#include "moho/math/Wm3Segment3FafExtras.h"

#include <gtest/gtest.h>

#include <cmath>
#include <limits>
#include <random>

namespace
{
  constexpr float kPi = 3.14159265f;
  constexpr float kTolerance = 1.0e-4f;

  float Dot(const Wm3::Vector3f& a, const Wm3::Vector3f& b)
  {
    return (a.x * b.x) + (a.y * b.y) + (a.z * b.z);
  }

  float Length(const Wm3::Vector3f& v)
  {
    return std::sqrt(Dot(v, v));
  }

  Wm3::Vector3f Cross(const Wm3::Vector3f& a, const Wm3::Vector3f& b)
  {
    return {(a.y * b.z) - (a.z * b.y), (a.z * b.x) - (a.x * b.z), (a.x * b.y) - (a.y * b.x)};
  }

  // Rodrigues' rotation of `v` by `angle` about the unit `axis` (right-handed).
  Wm3::Vector3f Rotate(const Wm3::Vector3f& v, const Wm3::Vector3f& axis, const float angle)
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);
    const Wm3::Vector3f k = Cross(axis, v);
    const float d = Dot(axis, v) * (1.0f - c);
    return {(v.x * c) + (k.x * s) + (axis.x * d), (v.y * c) + (k.y * s) + (axis.y * d),
            (v.z * c) + (k.z * s) + (axis.z * d)};
  }

  Wm3::Quaternionf AxisAngle(const Wm3::Vector3f& axis, const float angle)
  {
    const float s = std::sin(angle * 0.5f);
    return Wm3::Quaternionf{std::cos(angle * 0.5f), axis.x * s, axis.y * s, axis.z * s};
  }

  Wm3::Vector3f RandomUnit(std::mt19937& rng)
  {
    std::uniform_real_distribution<float> lane(-1.0f, 1.0f);
    for (;;) {
      Wm3::Vector3f v{lane(rng), lane(rng), lane(rng)};
      const float length = Length(v);
      if (length > 0.1f && length <= 1.0f) {
        return {v.x / length, v.y / length, v.z / length};
      }
    }
  }

  void ExpectNear3(const Wm3::Vector3f& actual, const Wm3::Vector3f& expected, const float tolerance)
  {
    EXPECT_NEAR(actual.x, expected.x, tolerance);
    EXPECT_NEAR(actual.y, expected.y, tolerance);
    EXPECT_NEAR(actual.z, expected.z, tolerance);
  }

  // q and -q are the same rotation.
  void ExpectSameRotation(const Wm3::Quaternionf& a, const Wm3::Quaternionf& b, const float tolerance)
  {
    const float sign = ((a.w * b.w) + (a.x * b.x) + (a.y * b.y) + (a.z * b.z)) < 0.0f ? -1.0f : 1.0f;
    EXPECT_NEAR(a.w, sign * b.w, tolerance);
    EXPECT_NEAR(a.x, sign * b.x, tolerance);
    EXPECT_NEAR(a.y, sign * b.y, tolerance);
    EXPECT_NEAR(a.z, sign * b.z, tolerance);
  }
} // namespace

TEST(MathVector, ValidityRejectsNaNButAcceptsInfinity)
{
  const float nan = std::numeric_limits<float>::quiet_NaN();
  const float inf = std::numeric_limits<float>::infinity();
  EXPECT_TRUE(moho::IsValidVector3f({1.0f, 2.0f, 3.0f}));
  EXPECT_TRUE(moho::IsValidVector3f({inf, -inf, 0.0f}));
  EXPECT_FALSE(moho::IsValidVector3f({nan, 0.0f, 0.0f}));
  EXPECT_FALSE(moho::IsValidVector3f({0.0f, 0.0f, nan}));
  EXPECT_TRUE(moho::IsValidVector2f({inf, 1.0f}));
  EXPECT_FALSE(moho::IsValidVector2f({1.0f, nan}));
  EXPECT_FALSE(moho::IsValidVector3f(moho::Invalid<Wm3::Vector3f>()));
  const Wm3::Vector3f& zero = moho::Zeroed<Wm3::Vector3f>();
  EXPECT_EQ(zero.x, 0.0f);
  EXPECT_EQ(zero.y, 0.0f);
  EXPECT_EQ(zero.z, 0.0f);
  const Wm3::Quaternionf& zeroQuat = moho::Zeroed<Wm3::Quaternionf>();
  EXPECT_EQ(zeroQuat.w, 0.0f);
  EXPECT_EQ(zeroQuat.x, 0.0f);
}

TEST(MathVector, LengthHelpers)
{
  Wm3::Vector3f dest{};
  moho::NormalizeVectorInto(&dest, {3.0f, 0.0f, 4.0f});
  ExpectNear3(dest, {0.6f, 0.0f, 0.8f}, 1.0e-6f);
  moho::NormalizeVectorInto(&dest, {0.0f, 0.0f, 0.0f});
  ExpectNear3(dest, {0.0f, 0.0f, 0.0f}, 0.0f);

  EXPECT_TRUE(moho::IsUnitLengthVector3f({0.0f, 1.0f, 0.0f}));
  EXPECT_TRUE(moho::IsUnitLengthVector3f({0.0f, 1.0004f, 0.0f}));
  EXPECT_FALSE(moho::IsUnitLengthVector3f({0.0f, 1.01f, 0.0f}));

  EXPECT_FLOAT_EQ(moho::DistanceSquared3D({1.0f, 2.0f, 3.0f}, {4.0f, 6.0f, 3.0f}), 25.0f);
  EXPECT_FLOAT_EQ(moho::DistanceSquared2D({0.0f, 0.0f}, {3.0f, 4.0f}), 25.0f);
  EXPECT_FLOAT_EQ(moho::Distance2D({0.0f, 0.0f}, {3.0f, 4.0f}), 5.0f);

  Wm3::Vector3f v{3.0f, 4.0f, 0.0f};
  EXPECT_TRUE(moho::VecSetLength(&v, 10.0f));
  ExpectNear3(v, {6.0f, 8.0f, 0.0f}, 1.0e-4f);
  Wm3::Vector3f zero{};
  EXPECT_FALSE(moho::VecSetLength(&zero, 10.0f));

  Wm3::Vector3f longVector{0.0f, 0.0f, 20.0f};
  EXPECT_TRUE(moho::VecLimitLengthTo(&longVector, 5.0f));
  ExpectNear3(longVector, {0.0f, 0.0f, 5.0f}, 1.0e-4f);
  Wm3::Vector3f shortVector{1.0f, 1.0f, 0.0f};
  EXPECT_FALSE(moho::VecLimitLengthTo(&shortVector, 5.0f));
  ExpectNear3(shortVector, {1.0f, 1.0f, 0.0f}, 0.0f);
  EXPECT_FALSE(moho::VecLimitLengthTo(nullptr, 5.0f));

  Wm3::Vector3f scaled{2.0f, 4.0f, -6.0f};
  EXPECT_EQ(moho::VecScaleByReciprocalOrSetMax(&scaled, 2.0f), &scaled);
  ExpectNear3(scaled, {1.0f, 2.0f, -3.0f}, 1.0e-6f);
  EXPECT_EQ(moho::VecScaleByReciprocalOrSetMax(&scaled, 0.0f), &scaled); // 0x004ED810: a zero divisor writes FLT_MAX
  EXPECT_EQ(scaled.x, std::numeric_limits<float>::max());
  EXPECT_EQ(scaled.z, std::numeric_limits<float>::max());

  const Wm3::Vector3f target{0.0f, 0.0f, 7.0f};
  const Wm3::Vector3f source{1.0f, 0.0f, 0.0f};
  Wm3::Vector3f out{};
  EXPECT_EQ(moho::VecSetLengthTo(&out, &target, &source), &out);
  ExpectNear3(out, {7.0f, 0.0f, 0.0f}, 1.0e-4f);
  const Wm3::Vector3f zeroSource{};
  EXPECT_EQ(moho::VecSetLengthTo(&out, &target, &zeroSource), &out); // 0x0069A360: falls back to the target vector
  ExpectNear3(out, target, 0.0f);
}

TEST(MathVector, ReflectionAxisAndHeading)
{
  const Wm3::Vector3f incident{1.0f, -1.0f, 0.0f};
  const Wm3::Vector3f normal{0.0f, 1.0f, 0.0f};
  Wm3::Vector3f reflected{};
  EXPECT_EQ(moho::ReflectVector3fAcrossNormal(&reflected, &incident, &normal), &reflected);
  ExpectNear3(reflected, {1.0f, 1.0f, 0.0f}, 1.0e-6f);

  EXPECT_EQ(moho::VEC_LargestAxis({1.0f, -3.0f, 2.0f}), 1);
  EXPECT_EQ(moho::VEC_LargestAxis({-5.0f, 3.0f, 2.0f}), 0);
  EXPECT_EQ(moho::VEC_LargestAxis({0.0f, 0.0f, -0.5f}), 2);

  // atan2(x, z): +z is heading 0, +x a quarter turn.
  const Wm3::Vector3f north{0.0f, 0.0f, 1.0f};
  const Wm3::Vector3f east{1.0f, 0.0f, 0.0f};
  const Wm3::Vector3f south{0.0f, 0.0f, -1.0f};
  EXPECT_NEAR(moho::VEC_HeadingFromXZ(&north), 0.0f, 1.0e-6f);
  EXPECT_NEAR(moho::VEC_HeadingFromXZ(&east), kPi * 0.5f, 1.0e-6f);
  EXPECT_NEAR(std::fabs(moho::VEC_HeadingFromXZ(&south)), kPi, 1.0e-6f);
}

TEST(MathVector, EulerRollAndAxisAngleVectorBuildUnitQuaternions)
{
  const Wm3::Vector3f axis{0.0f, 1.0f, 0.0f};
  Wm3::Quatf quat{};
  moho::EulerRollToQuat(&axis, &quat, kPi * 0.5f);
  ExpectSameRotation(quat, AxisAngle(axis, kPi * 0.5f), 1.0e-6f);

  Wm3::Quaternionf fromVector{};
  moho::QuatFromAxisAngleVector(&fromVector, {0.0f, 0.0f, 2.0f}); // axis +z, angle 2 rad
  ExpectSameRotation(fromVector, AxisAngle({0.0f, 0.0f, 1.0f}, 2.0f), 1.0e-6f);
}

TEST(MathGrid, GridPosFloorsWorldCoordinates)
{
  Wm3::Vec3f position{17.9f, 0.0f, -0.5f};
  const moho::GridPos cell(&position, 4);
  EXPECT_EQ(cell.x, 4);
  EXPECT_EQ(cell.z, -1);
  Wm3::Vec3f exact{16.0f, 5.0f, 32.0f};
  const moho::GridPos edge(&exact, 16);
  EXPECT_EQ(edge.x, 1);
  EXPECT_EQ(edge.z, 2);
  EXPECT_EQ(moho::FloorSecondsToTicks(1.25f), 12);
  EXPECT_EQ(moho::FloorSecondsToTicks(-0.05f), -1);
  EXPECT_EQ(moho::FloorSecondsToTicks(3.0f), 30);
}

TEST(MathQuaternion, NormalizeAngleWrapsIntoSignedPi)
{
  const float inputs[] = {0.0f, 1.0f, -1.0f, 3.0f, 4.0f, -4.0f, 7.0f, -7.0f, 100.0f, -100.0f, 6.2f};
  for (const float input : inputs) {
    const float wrapped = moho::NormalizeAngleSignedRadians(input);
    SCOPED_TRACE(testing::Message() << "input " << input);
    EXPECT_GE(wrapped, -kPi - 1.0e-5f);
    EXPECT_LE(wrapped, kPi + 1.0e-5f);
    EXPECT_NEAR(std::sin(wrapped), std::sin(input), 2.0e-4f);
    EXPECT_NEAR(std::cos(wrapped), std::cos(input), 2.0e-4f);
  }
  EXPECT_NEAR(moho::NormalizeAngleSignedRadiansX87(7.0), 7.0f - (2.0f * kPi), 1.0e-5f);
}

TEST(MathQuaternion, MatrixAndVectorRotationAgreeWithRodrigues)
{
  std::mt19937 rng(42);
  std::uniform_real_distribution<float> angles(-3.0f, 3.0f);
  for (int i = 0; i < 200; ++i) {
    const Wm3::Vector3f axis = RandomUnit(rng);
    const float angle = angles(rng);
    const Wm3::Vector3f v = RandomUnit(rng);
    const Wm3::Quaternionf q = AxisAngle(axis, angle);
    SCOPED_TRACE(testing::Message() << "i=" << i);

    Wm3::Vector3f rotated{};
    moho::MultQuadVec(&rotated, &v, &q);
    ExpectNear3(rotated, Rotate(v, axis, angle), kTolerance);

    Wm3::Vector3f rows[3]{};
    moho::QuatToMatrix(&q, rows);
    for (int r = 0; r < 3; ++r) {
      EXPECT_NEAR(Length(rows[r]), 1.0f, kTolerance);
      for (int s = r + 1; s < 3; ++s) {
        EXPECT_NEAR(Dot(rows[r], rows[s]), 0.0f, kTolerance);
      }
    }

    // The matrix converts back to the same rotation through both trace branches.
    Wm3::Quaternionf back{};
    moho::MatrixRowsToQuatCanonical(rows, &back);
    ExpectSameRotation(back, q, 2.0e-4f);

    // MatrixToQuat (0x004EB3F0) reads its rows as the transpose: it returns the inverse rotation.
    Wm3::Quaternionf inverse{};
    moho::MatrixToQuat(rows, &inverse);
    ExpectSameRotation(inverse, moho::ConjugateQuat(q), 2.0e-4f);

    const Wm3::Vector3f columns[3] = {
      {rows[0].x, rows[1].x, rows[2].x}, {rows[0].y, rows[1].y, rows[2].y}, {rows[0].z, rows[1].z, rows[2].z}
    };
    Wm3::Quaternionf fromColumns{};
    moho::MatrixColumnsToQuatCanonical(columns, &fromColumns);
    ExpectSameRotation(fromColumns, q, 2.0e-4f);

    // The forward axis is the rotated +z.
    ExpectNear3(moho::QuatForwardAxis(q), Rotate({0.0f, 0.0f, 1.0f}, axis, angle), kTolerance);
  }
}

TEST(MathQuaternion, ProductComposesRotations)
{
  std::mt19937 rng(7);
  std::uniform_real_distribution<float> angles(-3.0f, 3.0f);
  for (int i = 0; i < 100; ++i) {
    const Wm3::Quaternionf a = AxisAngle(RandomUnit(rng), angles(rng));
    const Wm3::Quaternionf b = AxisAngle(RandomUnit(rng), angles(rng));
    const Wm3::Vector3f v = RandomUnit(rng);
    const Wm3::Quaternionf ab = moho::MultiplyQuat(a, b);

    Wm3::Vector3f byB{};
    moho::MultQuadVec(&byB, &v, &b);
    Wm3::Vector3f thenA{};
    moho::MultQuadVec(&thenA, &byB, &a);
    Wm3::Vector3f once{};
    moho::MultQuadVec(&once, &v, &ab);
    ExpectNear3(once, thenA, kTolerance);

    const Wm3::Quaternionf identity = moho::MultiplyQuat(a, moho::ConjugateQuat(a));
    EXPECT_NEAR(std::fabs(identity.w), 1.0f, kTolerance);
    EXPECT_NEAR(identity.x, 0.0f, kTolerance);
  }
}

TEST(MathQuaternion, NormalizeAndNearEqual)
{
  Wm3::Quaternionf q{2.0f, 0.0f, 0.0f, 0.0f};
  moho::NormalizeQuatInPlace(&q);
  EXPECT_FLOAT_EQ(q.w, 1.0f);
  Wm3::Quaternionf tiny{1.0e-8f, 0.0f, 0.0f, 0.0f};
  moho::NormalizeQuatInPlace(&tiny); // 0x004EDAA0: a degenerate quaternion becomes all zero, not identity
  EXPECT_EQ(tiny.w, 0.0f);
  EXPECT_EQ(tiny.x, 0.0f);

  const Wm3::Quaternionf a{1.0f, 0.0f, 0.0f, 0.0f};
  const Wm3::Quaternionf b{1.0f, 5.0e-7f, 0.0f, 0.0f};
  const Wm3::Quaternionf c{1.0f, 2.0e-6f, 0.0f, 0.0f};
  EXPECT_TRUE(moho::QuatsNearEqual(a, b));
  EXPECT_FALSE(moho::QuatsNearEqual(a, c));
}

TEST(MathQuaternion, InterpolationEndpointsAndMidpoint)
{
  const Wm3::Vector3f up{0.0f, 1.0f, 0.0f};
  const Wm3::Quaternionf from = AxisAngle(up, 0.0f);
  const Wm3::Quaternionf to = AxisAngle(up, 1.2f);
  Wm3::Quaternionf out{};

  // Both return their *second* argument at 0 and the first at 1 (0x004EBA80, 0x004EBC00).
  moho::SLERP(&to, &from, &out, 0.0f);
  ExpectSameRotation(out, from, 1.0e-5f);
  moho::SLERP(&to, &from, &out, 1.0f);
  ExpectSameRotation(out, to, 1.0e-5f);
  moho::SLERP(&to, &from, &out, 0.5f);
  ExpectSameRotation(out, AxisAngle(up, 0.6f), 1.0e-5f);
  moho::SLERP(&to, &from, &out, 7.0f); // clamped to 1
  ExpectSameRotation(out, to, 1.0e-5f);
  moho::SLERP(&from, &from, &out, 0.3f);
  ExpectSameRotation(out, from, 0.0f);

  moho::QuatLERP(&to, &from, &out, 0.0f);
  ExpectSameRotation(out, from, 1.0e-5f);
  moho::QuatLERP(&to, &from, &out, 1.0f);
  ExpectSameRotation(out, to, 1.0e-5f);
  moho::QuatLERP(&to, &from, &out, 0.5f);
  ExpectSameRotation(out, AxisAngle(up, 0.6f), 1.0e-5f); // same plane, so the normalized blend is the half angle
  EXPECT_NEAR((out.w * out.w) + (out.y * out.y), 1.0f, 1.0e-5f);

  // Shortest arc: -to is the same rotation and gives the same midpoint.
  const Wm3::Quaternionf negTo{-to.w, -to.x, -to.y, -to.z};
  moho::SLERP(&negTo, &from, &out, 0.5f);
  ExpectSameRotation(out, AxisAngle(up, 0.6f), 1.0e-5f);
}

TEST(MathQuaternion, AxisAngleRoundTrip)
{
  Wm3::Vector3f axis{};
  float angle = 0.0f;
  moho::QuatToAxisAndAngle(AxisAngle({0.0f, 0.0f, 1.0f}, 1.5f), &axis, &angle);
  EXPECT_NEAR(angle, 1.5f, 1.0e-5f);
  ExpectNear3(axis, {0.0f, 0.0f, 1.0f}, 1.0e-5f);

  moho::QuatToAxisAndAngle(Wm3::Quaternionf{1.0f, 0.0f, 0.0f, 0.0f}, &axis, &angle);
  EXPECT_EQ(angle, 0.0f);
  ExpectNear3(axis, {1.0f, 0.0f, 0.0f}, 0.0f); // 0x006C1070: no axis -> +x, angle 0
}

TEST(MathQuaternion, RotateByAngleAndBlendClampTheStep)
{
  const Wm3::Vector3f up{0.0f, 1.0f, 0.0f};
  Wm3::Quaternionf q = AxisAngle(up, 2.0f);
  EXPECT_TRUE(moho::RotateQuatByAngle(&q, 0.5f));
  ExpectSameRotation(q, AxisAngle(up, 0.5f), 1.0e-5f);

  Wm3::Quaternionf small = AxisAngle(up, 0.1f);
  EXPECT_FALSE(moho::RotateQuatByAngle(&small, 0.5f)); // already shorter than the step
  Wm3::Quaternionf any = AxisAngle(up, 1.0f);
  EXPECT_FALSE(moho::RotateQuatByAngle(&any, 4.0f)); // half-angle past pi/2

  const Wm3::Quaternionf current = AxisAngle(up, 0.0f);
  const Wm3::Quaternionf goal = AxisAngle(up, 1.0f);
  bool noStep = true;
  Wm3::Quaternionf out{};
  moho::BlendOrientationDeltaByMaxAngle(goal, current, 0.25f, &noStep, &out);
  EXPECT_FALSE(noStep);
  ExpectSameRotation(out, AxisAngle(up, 0.25f), 1.0e-5f);

  moho::BlendOrientationDeltaByMaxAngle(goal, current, 3.0f, &noStep, &out);
  EXPECT_TRUE(noStep);
  ExpectSameRotation(out, goal, 0.0f);
}

TEST(MathQuaternion, EulerMatrixAndShortestArc)
{
  // Heading only: a rotation about +y.
  Wm3::Vector3f matrix[3]{};
  moho::BuildRotationMatrixFromEulerHPR(matrix, 0.7f, 0.0f, 0.0f);
  const Wm3::Vector3f v{0.0f, 0.0f, 1.0f};
  const Wm3::Vector3f byMatrix{Dot(matrix[0], v), Dot(matrix[1], v), Dot(matrix[2], v)};
  ExpectNear3(byMatrix, Rotate(v, {0.0f, 1.0f, 0.0f}, 0.7f), kTolerance);

  Wm3::Vector3f full[3]{};
  moho::BuildRotationMatrixFromEulerHPR(full, 0.3f, -0.4f, 1.1f);
  for (int r = 0; r < 3; ++r) {
    EXPECT_NEAR(Length(full[r]), 1.0f, kTolerance);
  }

  const Wm3::Vector3f identity[3] = {{1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}};
  Wm3::Vector3f product[3]{};
  moho::Multiply3x3RowMatrices(product, full, identity);
  for (int r = 0; r < 3; ++r) {
    ExpectNear3(product[r], full[r], 0.0f);
  }

  std::mt19937 rng(11);
  for (int i = 0; i < 50; ++i) {
    const Wm3::Vector3f from = RandomUnit(rng);
    const Wm3::Vector3f to = RandomUnit(rng);
    if (Dot(from, to) < -0.95f) {
      continue;
    }
    Wm3::Quaternionf delta{};
    moho::BuildTiltShortestArcDelta(to, &delta, from);
    Wm3::Vector3f moved{};
    moho::MultQuadVec(&moved, &from, &delta);
    SCOPED_TRACE(testing::Message() << "i=" << i);
    ExpectNear3(moved, to, 2.0e-4f);
  }
}

TEST(MathQuaternion, VecRotTurnsForwardTowardTheReference)
{
  // Identity faces +z; a full step towards +x turns the forward axis onto +x.
  Wm3::Quaternionf q{1.0f, 0.0f, 0.0f, 0.0f};
  const Wm3::Vector3f east{1.0f, 0.0f, 0.0f};
  moho::QuatFromVecRot(&q, &east, kPi * 0.5f);
  ExpectNear3(moho::QuatForwardAxis(q), east, 1.0e-4f);

  Wm3::Quaternionf partial{1.0f, 0.0f, 0.0f, 0.0f};
  moho::QuatFromVecRot(&partial, &east, 0.5f);
  const Wm3::Vector3f forward = moho::QuatForwardAxis(partial);
  EXPECT_NEAR(std::acos(forward.z), 0.5f, 1.0e-4f);
  EXPECT_GT(forward.x, 0.0f);

  Wm3::Quaternionf crossed{};
  moho::QuatCrossAdd(&crossed, {0.0f, 0.0f, 1.0f}, {1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f});
  Wm3::Vector3f moved{};
  const Wm3::Vector3f z{0.0f, 0.0f, 1.0f};
  moho::MultQuadVec(&moved, &z, &crossed);
  ExpectNear3(moved, east, 1.0e-4f);
}

TEST(MathBox, AxisAlignedBoundsAndEmpty)
{
  const float c = std::cos(kPi / 4.0f);
  const Wm3::Box3f box(
    {10.0f, 0.0f, -5.0f}, {c, 0.0f, c}, {0.0f, 1.0f, 0.0f}, {-c, 0.0f, c}, 2.0f, 1.0f, 2.0f
  );
  const Wm3::AxisAlignedBox3f bounds = moho::AxisAlignedBoundsFromBox(box);
  const float half = 2.0f * std::sqrt(2.0f);
  EXPECT_NEAR(bounds.Min.x, 10.0f - half, 1.0e-4f);
  EXPECT_NEAR(bounds.Max.x, 10.0f + half, 1.0e-4f);
  EXPECT_NEAR(bounds.Min.y, -1.0f, 1.0e-4f);
  EXPECT_NEAR(bounds.Max.y, 1.0f, 1.0e-4f);
  EXPECT_NEAR(bounds.Min.z, -5.0f - half, 1.0e-4f);
  EXPECT_NEAR(bounds.Max.z, -5.0f + half, 1.0e-4f);

  const Wm3::AxisAlignedBox3f& empty = moho::Empty<Wm3::AxisAlignedBox3f>();
  EXPECT_GT(empty.Min.x, empty.Max.x);
  EXPECT_GT(empty.Min.y, empty.Max.y);
  EXPECT_GT(empty.Min.z, empty.Max.z);
}

TEST(MathBox, RaySlabClip)
{
  const Wm3::AxisAlignedBox3f box({0.0f, 0.0f, 0.0f}, {10.0f, 10.0f, 10.0f});
  moho::RaySlabState hit{};
  hit.originX = -5.0f;
  hit.originY = 5.0f;
  hit.originZ = 5.0f;
  hit.dirX = 1.0f;
  hit.tEnter = 0.0f;
  hit.tExit = 100.0f;
  ASSERT_TRUE(moho::RayBoxSlabClip(hit, box));
  EXPECT_NEAR(hit.tEnter, 5.0f, 1.0e-5f);
  EXPECT_NEAR(hit.tExit, 15.0f, 1.0e-5f);

  // An axis whose direction is below FLT_MIN is skipped without looking at the origin (0x00473E17 `jb` to the
  // next axis at 0x00473E85), so a ray parallel to a slab is not clipped by it even outside the box.
  moho::RaySlabState parallelOutside = hit;
  parallelOutside.originY = 50.0f;
  parallelOutside.tEnter = 0.0f;
  parallelOutside.tExit = 100.0f;
  EXPECT_TRUE(moho::RayBoxSlabClip(parallelOutside, box));

  moho::RaySlabState away = hit;
  away.dirX = -1.0f; // pointing away from the box: entry 0, exit -5
  away.tEnter = 0.0f;
  away.tExit = 100.0f;
  EXPECT_FALSE(moho::RayBoxSlabClip(away, box));

  moho::RaySlabState shortRay = hit;
  shortRay.tEnter = 0.0f;
  shortRay.tExit = 2.0f; // ends before the box
  EXPECT_FALSE(moho::RayBoxSlabClip(shortRay, box));
}

TEST(MathQueries, SegmentsAndDistances)
{
  const Wm3::Segment3f segment = Wm3::MakeSegment3fFromEndpoints({0.0f, 0.0f, 0.0f}, {10.0f, 0.0f, 0.0f});
  ExpectNear3(segment.Origin, {5.0f, 0.0f, 0.0f}, 1.0e-6f);
  ExpectNear3(segment.Direction, {1.0f, 0.0f, 0.0f}, 1.0e-6f);
  EXPECT_NEAR(segment.Extent, 5.0f, 1.0e-6f);
  const Wm3::Segment3f point = Wm3::MakeSegment3fFromEndpoints({1.0f, 2.0f, 3.0f}, {1.0f, 2.0f, 3.0f});
  EXPECT_EQ(point.Extent, 0.0f);

  Wm3::Vector3f closest{};
  EXPECT_NEAR(Wm3::SquaredDistanceVector3Segment3({4.0f, 3.0f, 0.0f}, segment, closest), 9.0f, 1.0e-4f);
  ExpectNear3(closest, {4.0f, 0.0f, 0.0f}, 1.0e-5f);
  EXPECT_NEAR(Wm3::SquaredDistanceVector3Segment3({13.0f, 4.0f, 0.0f}, segment, closest), 25.0f, 1.0e-4f);
  ExpectNear3(closest, {10.0f, 0.0f, 0.0f}, 1.0e-5f);
  EXPECT_NEAR(Wm3::DistanceVector3Segment3({-3.0f, 0.0f, 4.0f}, segment), 5.0f, 1.0e-4f);

  const Wm3::Box3f box(
    {0.0f, 0.0f, 0.0f}, {1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}, 1.0f, 2.0f, 3.0f
  );
  EXPECT_NEAR(Wm3::SquaredDistanceVector3Box3({4.0f, 0.0f, 0.0f}, box, closest), 9.0f, 1.0e-4f);
  ExpectNear3(closest, {1.0f, 0.0f, 0.0f}, 1.0e-5f);
  EXPECT_EQ(Wm3::SquaredDistanceVector3Box3({0.5f, -1.0f, 2.0f}, box, closest), 0.0f);
  EXPECT_TRUE(Wm3::PointInBox3({0.5f, -1.0f, 2.0f}, box));
  EXPECT_FALSE(Wm3::PointInBox3({0.5f, -2.5f, 2.0f}, box));
}

TEST(MathQueries, SegmentBoxAndSphereIntersections)
{
  const Wm3::Box3f box(
    {0.0f, 0.0f, 0.0f}, {1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}, 1.0f, 1.0f, 1.0f
  );
  Wm3::Vector3f points[2]{};
  const Wm3::Segment3f through = Wm3::MakeSegment3fFromEndpoints({-5.0f, 0.0f, 0.0f}, {5.0f, 0.0f, 0.0f});
  ASSERT_EQ(Wm3::FindSegment3Box3(through, box, true, points), 2);
  EXPECT_NEAR(std::fabs(points[0].x), 1.0f, 1.0e-5f);
  EXPECT_NEAR(std::fabs(points[1].x), 1.0f, 1.0e-5f);
  EXPECT_NEAR(points[0].x + points[1].x, 0.0f, 1.0e-5f);
  const Wm3::Segment3f past = Wm3::MakeSegment3fFromEndpoints({-5.0f, 3.0f, 0.0f}, {5.0f, 3.0f, 0.0f});
  EXPECT_EQ(Wm3::FindSegment3Box3(past, box, true, points), 0);

  const Wm3::Sphere3f sphere({0.0f, 0.0f, 0.0f}, 2.0f);
  ASSERT_EQ(Wm3::FindSegment3Sphere3(through, sphere, points), 2);
  EXPECT_NEAR(std::fabs(points[0].x), 2.0f, 1.0e-4f);
  EXPECT_NEAR(std::fabs(points[1].x), 2.0f, 1.0e-4f);
  EXPECT_EQ(Wm3::FindSegment3Sphere3(past, sphere, points), 0);

  EXPECT_TRUE(Wm3::TestBox3Sphere3(box, Wm3::Sphere3f({2.5f, 0.0f, 0.0f}, 2.0f)));
  EXPECT_FALSE(Wm3::TestBox3Sphere3(box, Wm3::Sphere3f({4.0f, 0.0f, 0.0f}, 2.0f)));
  EXPECT_FALSE(Wm3::TestBox3Sphere3(box, Wm3::Sphere3f({2.0f, 2.0f, 2.0f}, 1.6f))); // corner distance sqrt(3)

  // Wild Magic 3.8 (Wm3IntrBox3Sphere3.cpp: `if (iRetVal != 0 || m_fContactTime > fTMax) return false;`), and
  // retail with it, treats a region function's 1 (a contact found) as empty: a sphere of radius 1 sweeping at
  // -1 along x from x = 5 into the face x = 1 reports no contact. The sim calls Find only after Test passed.
  float contactTime = 0.0f;
  Wm3::Vector3f contactPoint{};
  EXPECT_FALSE(Wm3::FindBox3Sphere3(
    box, Wm3::Sphere3f({5.0f, 0.0f, 0.0f}, 1.0f), 10.0f, {0.0f, 0.0f, 0.0f}, {-1.0f, 0.0f, 0.0f}, contactTime,
    contactPoint
  ));
  // A centre inside the box is a contact at time 0, at the centre.
  ASSERT_TRUE(Wm3::FindBox3Sphere3(
    box, Wm3::Sphere3f({0.5f, 0.0f, 0.0f}, 1.0f), 10.0f, {0.0f, 0.0f, 0.0f}, {0.0f, 0.0f, 0.0f}, contactTime,
    contactPoint
  ));
  EXPECT_EQ(contactTime, 0.0f);
  EXPECT_EQ(contactPoint.x, 0.5f);
  EXPECT_FALSE(Wm3::FindBox3Sphere3(
    box, Wm3::Sphere3f({5.0f, 0.0f, 0.0f}, 1.0f), 2.0f, {0.0f, 0.0f, 0.0f}, {-1.0f, 0.0f, 0.0f}, contactTime,
    contactPoint
  ));

  EXPECT_TRUE(Wm3::TestLine3Box3(Wm3::Line3f({0.0f, 5.0f, 0.0f}, {0.0f, 1.0f, 0.0f}), box));
  EXPECT_FALSE(Wm3::TestLine3Box3(Wm3::Line3f({3.0f, 5.0f, 0.0f}, {0.0f, 1.0f, 0.0f}), box));
}

TEST(MathQueries, TwoDimensionalTestsAndContainment)
{
  const float c = std::cos(kPi / 4.0f);
  const Wm3::Box2f square({0.0f, 0.0f}, {1.0f, 0.0f}, {0.0f, 1.0f}, 1.0f, 1.0f);
  const Wm3::Box2f diamond({2.3f, 0.0f}, {c, c}, {-c, c}, 1.0f, 1.0f);     // reaches x = 2.3 - sqrt(2) < 1
  const Wm3::Box2f justApart({2.5f, 0.0f}, {c, c}, {-c, c}, 1.0f, 1.0f);  // reaches x = 2.5 - sqrt(2) > 1
  const Wm3::Box2f far({5.0f, 0.0f}, {1.0f, 0.0f}, {0.0f, 1.0f}, 1.0f, 1.0f);
  EXPECT_TRUE(Wm3::TestBox2Box2(square, diamond));
  EXPECT_FALSE(Wm3::TestBox2Box2(square, justApart));
  EXPECT_FALSE(Wm3::TestBox2Box2(square, far));
  EXPECT_TRUE(Wm3::TestBox2Circle2(square, Wm3::Circle2f({2.0f, 0.0f}, 1.5f)));
  EXPECT_FALSE(Wm3::TestBox2Circle2(square, Wm3::Circle2f({2.0f, 2.0f}, 1.2f))); // corner distance sqrt(2)

  const Wm3::Vector3f points[] = {{1.0f, 5.0f, -2.0f}, {-3.0f, 2.0f, 4.0f}, {0.0f, 0.0f, 0.0f}};
  const Wm3::Box3f fitted = Wm3::ContAlignedBox3(3, points);
  ExpectNear3(fitted.Center, {-1.0f, 2.5f, 1.0f}, 1.0e-6f);
  EXPECT_NEAR(fitted.Extent[0], 2.0f, 1.0e-6f);
  EXPECT_NEAR(fitted.Extent[1], 2.5f, 1.0e-6f);
  EXPECT_NEAR(fitted.Extent[2], 3.0f, 1.0e-6f);
  for (const Wm3::Vector3f& p : points) {
    EXPECT_TRUE(Wm3::PointInBox3(p, fitted));
  }
}
