#pragma once

#include "Wm3Box2.h"
#include "Wm3Box3.h"
#include "Wm3Circle2.h"
#include "Wm3Line3.h"
#include "Wm3Segment3.h"
#include "Wm3Sphere3.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

// Engine addition (dedicated-server plan WPR.21): the Wild Magic 3.8 queries
// the engine calls, computed as the shipped binary computes them, in place of
// the compiled Wm3Foundation library.
//
// The 2007 engine linked a Wild Magic built for x87, so its queries keep each
// expression on the x87 stack (24-bit significand, wide exponent) and round to
// float at every store; built from source for SSE, the library's results part
// from retail where an intermediate leaves the float range (difffuzz, the
// collision primitives' rows). Moho::CColPrimitive's tests, projectiles and
// unit steering run in the simulation, so these are ported from the retail
// functions with fa::X87Float; the vision and pick-ray tests follow the same
// rules. Algorithms and names are Wild Magic's (Geometric Tools, Inc., Wild
// Magic 3 license, version 1.0c; dependencies/WildMagic3p8/License).
//
// The class templates' headers still declare the query objects; the engine
// calls these functions instead.
namespace Wm3
{
  /**
   * Address: 0x00A462A0 (IntrSegment3Box3<float>::Find), with
   * IntrLine3Box3<float>::DoClipping 0x00A50220 and Clip 0x00A4FCC0.
   *
   * Returns the number of intersection points (0, 1 or 2) and writes them to
   * `points`.
   */
  [[nodiscard]] int FindSegment3Box3(const Segment3f& segment, const Box3f& box, bool solid, Vector3f points[2]) noexcept;

  /**
   * Address: 0x00A471C0 (IntrSegment3Sphere3<float>::Find)
   *
   * Returns the number of intersection points (0, 1 or 2) and writes them to
   * `points`. ZeroThreshold is the constructor's Math<float>::ZERO_TOLERANCE.
   */
  [[nodiscard]] int FindSegment3Sphere3(const Segment3f& segment, const Sphere3f& sphere, Vector3f points[2]) noexcept;

  /**
   * Address: 0x00A41560 (IntrBox3Sphere3<float>::Test)
   */
  [[nodiscard]] bool TestBox3Sphere3(const Box3f& box, const Sphere3f& sphere) noexcept;

  /**
   * Address: 0x00A43420 (IntrBox3Sphere3<float>::Find)
   *
   * The swept test of a sphere moving at `velocity1` against a box moving at
   * `velocity0`, up to `tMax`. On true, `contactTime` and `contactPoint` hold
   * the query's m_fContactTime and m_kContactPoint.
   */
  [[nodiscard]] bool FindBox3Sphere3(
    const Box3f& box,
    const Sphere3f& sphere,
    float tMax,
    const Vector3f& velocity0,
    const Vector3f& velocity1,
    float& contactTime,
    Vector3f& contactPoint
  ) noexcept;

  /**
   * Address: 0x00A45C00 (DistVector3Box3<float>::GetSquared)
   *
   * Squared distance from `point` to `box`; `closestOnBox` is the query's
   * closest point on the box (m_kClosestPoint1).
   */
  [[nodiscard]] float SquaredDistanceVector3Box3(const Vector3f& point, const Box3f& box, Vector3f& closestOnBox) noexcept;

  /**
   * Address: 0x00A484F0 (DistVector3Segment3<float>::GetSquared)
   *
   * Squared distance from `point` to `segment`; `closestOnSegment` is the
   * query's m_kClosestPoint1.
   */
  [[nodiscard]] float
  SquaredDistanceVector3Segment3(const Vector3f& point, const Segment3f& segment, Vector3f& closestOnSegment) noexcept;

  /**
   * Address: 0x00A480E0 (DistVector3Segment3<float>::Get): the square root of
   * the squared distance.
   */
  [[nodiscard]] float DistanceVector3Segment3(const Vector3f& point, const Segment3f& segment) noexcept;

  /**
   * Address: 0x00A47D40 (IntrBox2Box2<float>::Test)
   */
  [[nodiscard]] bool TestBox2Box2(const Box2f& box0, const Box2f& box1) noexcept;

  /**
   * IntrBox2Circle2<float>::Test: DistVector2Box2<float>::Get from the circle's
   * centre to the box, against the radius.
   */
  [[nodiscard]] bool TestBox2Circle2(const Box2f& box, const Circle2f& circle) noexcept;

  /**
   * IntrLine3Box3<float>::Test: the separating-axis test of an infinite line.
   */
  [[nodiscard]] bool TestLine3Box3(const Line3f& line, const Box3f& box) noexcept;

  /**
   * Address: 0x00A3BC10 (InBox<float>, Wm3ContBox3.cpp)
   */
  [[nodiscard]] bool PointInBox3(const Vector3f& point, const Box3f& box) noexcept;

  /**
   * Address: 0x00A3AE40 (ContAlignedBox<float>, Wm3ContBox3.cpp, without the
   * validity mask)
   *
   * The axis-aligned box of `points`: unit axes, centre and extents from the
   * per-lane minimum and maximum.
   */
  [[nodiscard]] Box3f ContAlignedBox3(int quantity, const Vector3f* points) noexcept;
} // namespace Wm3
