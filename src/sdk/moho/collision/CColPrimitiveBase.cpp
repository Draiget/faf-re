#include "moho/collision/CColPrimitiveBase.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <limits>

#include "gpg/core/utils/Global.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/camera/VTransform.h"
#include "moho/math/Wm3DistanceFafExtras.h"

namespace
{
  constexpr float kAxisLengthSqEpsilon = 1.0e-6f;
  constexpr float kSupportSelectionEpsilon = 1.0e-3f;
  constexpr float kSweepTMax = std::numeric_limits<float>::max();
  const Wm3::Vec3f kZeroVec3f{0.0f, 0.0f, 0.0f};

  [[nodiscard]] Wm3::Vec3f BuildBoxCenter(const Wm3::Box3f& box) noexcept
  {
    return {box.Center[0], box.Center[1], box.Center[2]};
  }

  [[nodiscard]] Wm3::Vec3f BoxAxis(const Wm3::Box3f& box, const int axisIndex) noexcept
  {
    return {box.Axis[axisIndex][0], box.Axis[axisIndex][1], box.Axis[axisIndex][2]};
  }

  /**
   * Address: 0x00475550 (FUN_00475550, sub_475550)
   *
   * IDA signature:
   * float* __usercall sub_475550@<eax>(float* box@<eax>, float* axis@<ecx>,
   *     float* outMin, float* outMax);
   *
   * What it does:
   * Projects one oriented box onto a direction and returns the interval it
   * covers - the centre's projection, give or take the box's radius along that
   * direction. This is the per-axis half of the separating-axis test:
   * ComputeBoxBoxContactManifold calls it once per box for each of the fifteen
   * candidate axes and declares a miss as soon as two intervals fail to meet.
   *
   * The axis is not required to be unit length. Callers that need a real
   * distance divide by its length afterwards, which is what the manifold's
   * overlap normalisation does.
   */
  void ProjectBoxOntoAxis(const Wm3::Box3f& box, const Wm3::Vec3f& axis, float* outMin, float* outMax) noexcept
  {
    const Wm3::Vec3f center = BuildBoxCenter(box);
    const Wm3::Vec3f axis0 = BoxAxis(box, 0);
    const Wm3::Vec3f axis1 = BoxAxis(box, 1);
    const Wm3::Vec3f axis2 = BoxAxis(box, 2);

    const float centerProjection = Wm3::Vector3f::Dot(axis, center);

    // Summed third-axis first, then second, then first, because that is the
    // order the binary accumulates in and float addition does not associate.
    const float radius = (std::fabs(Wm3::Vector3f::Dot(axis, axis2)) * box.Extent[2] +
                           std::fabs(Wm3::Vector3f::Dot(axis, axis1)) * box.Extent[1]) +
      std::fabs(Wm3::Vector3f::Dot(axis, axis0)) * box.Extent[0];

    *outMin = centerProjection - radius;
    *outMax = centerProjection + radius;
  }

  /**
   * Address: 0x004752F0 (FUN_004752F0, sub_4752F0)
   *
   * IDA signature:
   * float* __usercall sub_4752F0@<eax>(float* box@<eax>, float* direction@<edx>, float* out@<ecx>);
   *
   * What it does:
   * Returns the corner of the box lying furthest against `direction`. Starts
   * at the centre and steps one extent along each axis, subtracting where the
   * axis projects positively and adding where it projects negatively. An axis
   * inside the dead band contributes nothing, so a direction parallel to a
   * face yields a point on that face rather than an arbitrary corner.
   */
  [[nodiscard]] Wm3::Vec3f
  ComputeSupportPointAgainstDirection(const Wm3::Box3f& box, const Wm3::Vec3f& direction) noexcept
  {
    Wm3::Vec3f support = BuildBoxCenter(box);
    for (int axisIndex = 0; axisIndex < 3; ++axisIndex) {
      const Wm3::Vec3f axis = BoxAxis(box, axisIndex);
      const float projection = Wm3::Vector3f::Dot(direction, axis);
      const float extent = box.Extent[axisIndex];
      if (projection < -kSupportSelectionEpsilon) {
        support = support + axis * extent;
      } else if (projection > kSupportSelectionEpsilon) {
        support = support - axis * extent;
      }
    }
    return support;
  }

  struct BoxBoxContactManifold
  {
    Wm3::Vec3f pointOnA;          // +0x00
    Wm3::Vec3f pointOnB;          // +0x0C
    Wm3::Vec3f penetrationNormal; // +0x18
    float penetrationDepth;       // +0x24
  };
  static_assert(sizeof(BoxBoxContactManifold) == 0x28, "BoxBoxContactManifold size must be 0x28");

  /**
   * Address: 0x00474830 (FUN_00474830, box-vs-box SAT manifold helper)
   *
   * What it does:
   * Runs SAT overlap checks for two OBBs and returns witness points, penetration
   * normal, and depth for the best separating axis candidate.
   */
  [[nodiscard]] bool ComputeBoxBoxContactManifold(
    const Wm3::Box3f& lhs, const Wm3::Box3f& rhs, BoxBoxContactManifold* outManifold
  ) noexcept
  {
    const Wm3::Vec3f lhsAxes[3] = {BoxAxis(lhs, 0), BoxAxis(lhs, 2), BoxAxis(lhs, 1)};
    const Wm3::Vec3f rhsAxes[3] = {BoxAxis(rhs, 0), BoxAxis(rhs, 2), BoxAxis(rhs, 1)};

    std::array<Wm3::Vec3f, 15> candidateAxes{};
    std::array<float, 15> overlapAlongAxis{};
    int axisCount = 0;
    for (int axisIndex = 0; axisIndex < 3; ++axisIndex) {
      candidateAxes[axisCount++] = lhsAxes[axisIndex];
    }
    for (int axisIndex = 0; axisIndex < 3; ++axisIndex) {
      candidateAxes[axisCount++] = rhsAxes[axisIndex];
    }
    for (int lhsAxisIndex = 0; lhsAxisIndex < 3; ++lhsAxisIndex) {
      for (int rhsAxisIndex = 0; rhsAxisIndex < 3; ++rhsAxisIndex) {
        candidateAxes[axisCount++] = Wm3::Vector3f::Cross(lhsAxes[lhsAxisIndex], rhsAxes[rhsAxisIndex]);
      }
    }

    for (int axisIndex = 0; axisIndex < axisCount; ++axisIndex) {
      float lhsMin = 0.0f;
      float lhsMax = 0.0f;
      float rhsMin = 0.0f;
      float rhsMax = 0.0f;
      ProjectBoxOntoAxis(lhs, candidateAxes[axisIndex], &lhsMin, &lhsMax);
      ProjectBoxOntoAxis(rhs, candidateAxes[axisIndex], &rhsMin, &rhsMax);

      if (lhsMin > rhsMax || rhsMin > lhsMax) {
        return false;
      }
      overlapAlongAxis[axisIndex] = std::fmin(lhsMax, rhsMax) - std::fmax(lhsMin, rhsMin);
    }

    float bestDepth = std::numeric_limits<float>::max();
    Wm3::Vec3f bestAxis{};
    int bestAxisIndex = -1;
    bool hasBestAxis = false;
    for (int axisIndex = 0; axisIndex < axisCount; ++axisIndex) {
      const Wm3::Vec3f axis = candidateAxes[axisIndex];
      const float axisLengthSq = Wm3::Vector3f::LengthSq(axis);
      if (axisLengthSq < kAxisLengthSqEpsilon) {
        continue;
      }

      const float invAxisLength = 1.0f / Wm3::SqrtfBinary(axisLengthSq);
      const float normalizedOverlap = overlapAlongAxis[axisIndex] * invAxisLength;
      if (!hasBestAxis || normalizedOverlap < bestDepth) {
        bestDepth = normalizedOverlap;
        bestAxis = axis * invAxisLength;
        bestAxisIndex = axisIndex;
        hasBestAxis = true;
      }
    }

    if (!hasBestAxis) {
      return false;
    }

    const Wm3::Vec3f centerDelta = BuildBoxCenter(rhs) - BuildBoxCenter(lhs);
    if (Wm3::Vector3f::Dot(centerDelta, bestAxis) > 0.0f) {
      bestAxis = bestAxis * -1.0f;
    }

    outManifold->penetrationNormal = bestAxis;
    outManifold->penetrationDepth = bestDepth;

    if (bestAxisIndex <= 2) {
      const Wm3::Vec3f supportOnA = ComputeSupportPointAgainstDirection(lhs, bestAxis * -1.0f);
      outManifold->pointOnB = supportOnA;
      outManifold->pointOnA = supportOnA - bestAxis * bestDepth;
      return true;
    }

    if (bestAxisIndex <= 5) {
      const Wm3::Vec3f supportOnA = ComputeSupportPointAgainstDirection(lhs, bestAxis);
      outManifold->pointOnA = supportOnA;
      outManifold->pointOnB = supportOnA + bestAxis * bestDepth;
      return true;
    }

    const int edgeAxisIndex = bestAxisIndex - 6;
    const int lhsEdgeIndex = edgeAxisIndex / 3;
    const int rhsEdgeIndex = edgeAxisIndex % 3;

    const Wm3::Vec3f supportOnA = ComputeSupportPointAgainstDirection(lhs, bestAxis);
    const Wm3::Vec3f supportOnB = ComputeSupportPointAgainstDirection(rhs, bestAxis * -1.0f);

    const Wm3::Vec3f lineAxisLhs = lhsAxes[lhsEdgeIndex];
    const Wm3::Vec3f lineAxisRhs = rhsAxes[rhsEdgeIndex];
    const Wm3::Vec3f crossRhsAndNormal = Wm3::Vector3f::Cross(lineAxisRhs, bestAxis);
    const float denominator = Wm3::Vector3f::Dot(lineAxisLhs, crossRhsAndNormal);
    if (std::fabs(denominator) < kAxisLengthSqEpsilon) {
      return false;
    }

    const float t =
      (Wm3::Vector3f::Dot(supportOnB, crossRhsAndNormal) - Wm3::Vector3f::Dot(supportOnA, crossRhsAndNormal)) /
      denominator;
    outManifold->pointOnA = supportOnA + lineAxisLhs * t;
    outManifold->pointOnB = outManifold->pointOnA + bestAxis * bestDepth;
    return true;
  }

  [[nodiscard]] Wm3::Segment3f BuildSegmentFromEndpoints(const Wm3::Vec3f& start, const Wm3::Vec3f& end) noexcept
  {
    const Wm3::Vec3f delta = end - start;
    const float deltaLength = Wm3::Vector3f::Length(delta);

    Wm3::Segment3f segment{};
    segment.Origin = (start + end) * 0.5f;
    segment.Extent = deltaLength * 0.5f;
    if (deltaLength > 1.0e-6f) {
      segment.Direction = delta * (1.0f / deltaLength);
    } else {
      segment.Direction = {0.0f, 0.0f, 0.0f};
    }
    return segment;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004FFDE0 (FUN_004FFDE0, Moho::CColPrimitiveBase::CColPrimitiveBase)
   *
   * What it does:
   * Initializes one collision-primitive base runtime lane.
   */
  CColPrimitiveBase::CColPrimitiveBase() = default;

  /**
   * Address: 0x0067AC40 (FUN_0067AC40, inlined construction payload)
   *
   * What it does:
   * Initializes box primitive state from local box and stores local-center copy.
   */
  CColPrimitive<Wm3::Box3f>::CColPrimitive(const Wm3::Box3f& localBox)
    : mShape(localBox)
    , mLocalCenter(localBox.Center[0], localBox.Center[1], localBox.Center[2])
  {}

  /**
   * Address: 0x004FFC20 (FUN_004FFC20, Moho::CColPrimitive_Box::GetBoundingBox)
   *
   * IDA signature:
   * int __thiscall sub_4FFC20(char* this, int scratchOut);
   *
   * What it does:
   * Computes the world-space AABB from center/basis/extents.
   */
  Wm3::AxisAlignedBox3f CColPrimitive<Wm3::Box3f>::GetBoundingBox() const
  {
    Wm3::Vec3f minimum{};
    Wm3::Vec3f maximum{};
    mShape.ComputeAABB(minimum, maximum);
    return {minimum, maximum};
  }

  /**
   * Address: 0x004FF130 (FUN_004FF130, Moho::CColPrimitive_Box::GetSphere)
   *
   * What it does:
   * Box primitive has no sphere view and returns null.
   */
  const Wm3::Sphere3f* CColPrimitive<Wm3::Box3f>::GetSphere() const
  {
    return nullptr;
  }

  /**
   * Address: 0x004FF140 (FUN_004FF140, Moho::CColPrimitive_Box::GetBox)
   *
   * What it does:
   * Returns pointer to box payload at +0x04.
   */
  const Wm3::Box3f* CColPrimitive<Wm3::Box3f>::GetBox() const
  {
    return &mShape;
  }

  /**
   * Address: 0x004FF470 (FUN_004FF470, Moho::CColPrimitive_Box::SetTransform)
   *
   * IDA signature:
   * int __thiscall sub_100FF470(int this, float* transformPayload);
   *
   * What it does:
   * Rotates the local center by the orientation (`MultQuadVec`, 0x00452D40),
   * adds the world position, and takes the box axes from
   * `VAxes3::VAxes3(orient)` (0x004EC590), exactly the two calls the binary
   * makes; they used to be open-coded here as a private basis build.
   */
  void CColPrimitive<Wm3::Box3f>::SetTransform(const VTransform& transform)
  {
    Wm3::Vec3f rotatedCenter{};
    MultQuadVec(&rotatedCenter, &mLocalCenter, &transform.orient_);
    mShape.Center.x = rotatedCenter.x + transform.pos_.x;
    mShape.Center.y = transform.pos_.y + rotatedCenter.y;
    mShape.Center.z = transform.pos_.z + rotatedCenter.z;

    const VAxes3 axes(transform.orient_);
    mShape.Axis[0] = axes.vX;
    mShape.Axis[1] = axes.vY;
    mShape.Axis[2] = axes.vZ;
  }

  /**
   * Address: 0x004FFBE0 (FUN_004FFBE0, Moho::CColPrimitive_Box::GetCenter)
   *
   * What it does:
   * Writes the primitive's LOCAL center to caller output.
   *
   * 0x004FFBE4/E9/EF read `[ecx+40h]`, `[ecx+44h]`, `[ecx+48h]` -- that is
   * `mLocalCenter`, not `mShape.Center`. `SetTransform` (0x004FF470) settles
   * which is which: it rotates `[edi+40h]` through `MultQuadVec`
   * (`lea esi, [edi+40h]` at 0x004FF47D), adds the world position, and stores
   * the result into `[edi+4]`/`[edi+8]`/`[edi+0Ch]` -- `mShape.Center`. So
   * `mShape` is the world-space volume the grid and collision queries use, and
   * `mLocalCenter` is the untransformed offset this accessor exposes.
   *
   * Returning the world centre here put `Entity::GetTerrainCollisionGeom`'s
   * corner points in world space, and `CUnitMotion::HandleGroundCollision`
   * (0x006BC460) multiplies them by the body's world matrix again -- landing
   * every ground-contact sample at roughly twice the unit's world position.
   * `SPhysBody::ApplyGroundCollisionResponse` takes `relative = sample - mPos`
   * as a lever arm, so a unit 4.5 units long got an arm of several hundred,
   * and the angular impulse it accumulated grew by four orders of magnitude in
   * a single contact instead of damping.
   */
  Wm3::Vec3f* CColPrimitive<Wm3::Box3f>::GetCenter(Wm3::Vec3f* outCenter) const
  {
    *outCenter = mLocalCenter;
    return outCenter;
  }

  /**
   * Address: 0x004FFC00 (FUN_004FFC00, Moho::CColPrimitive_Box::SetCenter)
   *
   * What it does:
   * Copies caller center into the primitive's LOCAL center.
   *
   * 0x004FFC06/0C/12 store to `[ecx+40h]`, `[ecx+44h]`, `[ecx+48h]` --
   * `mLocalCenter`, the same lane `GetCenter` reads. The world-space
   * `mShape.Center` is derived from it by `SetTransform`, never written here.
   */
  const Wm3::Vec3f* CColPrimitive<Wm3::Box3f>::SetCenter(const Wm3::Vec3f* center)
  {
    mLocalCenter = *center;
    return center;
  }

  /**
   * Address: 0x004FF2D0 (FUN_004FF2D0, Moho::CColPrimitive_Box::CollideLine)
   *
   * What it does:
   * Tests segment-vs-box and fills first hit point, separation direction, and distance from line start.
   */
  bool CColPrimitive<Wm3::Box3f>::CollideLine(
    const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionSegmentResult* outResult
  ) const
  {
    const Wm3::Segment3f segment = BuildSegmentFromEndpoints(*lineStart, *lineEnd);

    int quantity = 0;
    Wm3::Vec3f points[2]{};
    int intrType = 0;
    if (!Wm3::IntrSegment3Box3fFind(segment, mShape, false, &quantity, points, &intrType)) {
      return false;
    }

    const Wm3::Vec3f hitPoint = points[0];
    const Wm3::Vec3f center = BuildBoxCenter(mShape);
    const Wm3::Vec3f centerToHit = center - hitPoint;
    Wm3::Vec3f direction{};
    Wm3::Vector3f::NormalizeInto(centerToHit, &direction);

    const Wm3::Vec3f hitFromStart = hitPoint - *lineStart;
    outResult->direction = direction;
    outResult->position = hitPoint;
    outResult->distanceFromLineStart = Wm3::SqrtfBinary(Wm3::Vector3f::LengthSq(hitFromStart));
    return true;
  }

  /**
   * Address: 0x004FF260 (FUN_004FF260, Moho::CColPrimitive_Box::CollideBox)
   *
   * What it does:
   * Runs OBB-vs-OBB SAT and returns minimum penetration axis/depth.
   */
  bool CColPrimitive<Wm3::Box3f>::CollideBox(const Wm3::Box3f* box, CollisionResult* outResult) const
  {
    BoxBoxContactManifold manifold{};
    if (!ComputeBoxBoxContactManifold(mShape, *box, &manifold)) {
      return false;
    }

    outResult->direction = manifold.penetrationNormal;
    outResult->penetrationDepth = manifold.penetrationDepth;
    return true;
  }

  /**
   * Address: 0x004FF150 (FUN_004FF150, Moho::CColPrimitive_Box::CollideSphere)
   *
   * What it does:
   * Tests sphere-vs-box overlap and fills penetration direction/depth.
   */
  bool CColPrimitive<Wm3::Box3f>::CollideSphere(const Wm3::Sphere3f* sphere, CollisionResult* outResult) const
  {
    const float squaredDistance = Wm3::DistVector3Box3fGetSquared(sphere->Center, mShape);
    if (sphere->Radius * sphere->Radius <= squaredDistance) {
      return false;
    }

    const Wm3::Vec3f center = BuildBoxCenter(mShape);
    const Wm3::Vec3f sphereToBox = sphere->Center - center;
    Wm3::Vec3f direction{};
    Wm3::Vector3f::NormalizeInto(sphereToBox, &direction);

    outResult->direction = direction;
    outResult->penetrationDepth = sphere->Radius - Wm3::SqrtfBinary(squaredDistance);
    return true;
  }

  /**
   * Address: 0x004FF450 (FUN_004FF450, Moho::CColPrimitive_Box::PointInShape)
   *
   * What it does:
   * Returns true when point lies inside oriented box extents.
   */
  bool CColPrimitive<Wm3::Box3f>::PointInShape(const Wm3::Vec3f* point) const
  {
    return mShape.ContainsPoint(*point);
  }

  /**
   * Address: 0x0067AD30 (FUN_0067AD30, inlined construction payload)
   *
   * What it does:
   * Initializes sphere primitive state from local center/radius.
   */
  CColPrimitive<Wm3::Sphere3f>::CColPrimitive(const Wm3::Vec3f& localCenter, const float radius)
    : mShape(localCenter, radius)
    , mLocalCenter(localCenter)
  {}

  /**
   * Address: 0x004FF9A0 (FUN_004FF9A0, Moho::CColPrimitive_Sphere::GetBoundingBox)
   *
   * IDA signature:
   * float *__thiscall sub_4FF9A0(float *this, float *a2);
   *
   * What it does:
   * Returns the axis-aligned bounds of `{center, radius}`.
   */
  Wm3::AxisAlignedBox3f CColPrimitive<Wm3::Sphere3f>::GetBoundingBox() const
  {
    const float radius = mShape.Radius;
    return {
      Wm3::Vec3f{mShape.Center.x - radius, mShape.Center.y - radius, mShape.Center.z - radius},
      Wm3::Vec3f{mShape.Center.x + radius, mShape.Center.y + radius, mShape.Center.z + radius},
    };
  }

  /**
   * Address: 0x004FE780 (FUN_004FE780, Moho::CColPrimitive_Sphere::GetSphere)
   *
   * What it does:
   * Returns pointer to sphere payload at +0x04.
   */
  const Wm3::Sphere3f* CColPrimitive<Wm3::Sphere3f>::GetSphere() const
  {
    return &mShape;
  }

  /**
   * Address: 0x004FE790 (FUN_004FE790, Moho::CColPrimitive_Sphere::GetBox)
   *
   * What it does:
   * Sphere primitive has no box view and returns null.
   */
  const Wm3::Box3f* CColPrimitive<Wm3::Sphere3f>::GetBox() const
  {
    return nullptr;
  }

  /**
   * Address: 0x004FEBC0 (FUN_004FEBC0, Moho::CColPrimitive_Sphere::SetTransform)
   *
   * IDA signature:
   * int __thiscall sub_4FEBC0(float *this, float *transformPayload);
   *
   * What it does:
   * Rotates the local center by the orientation (`MultQuadVec`, 0x00452D40)
   * and adds the world position.
   */
  void CColPrimitive<Wm3::Sphere3f>::SetTransform(const VTransform& transform)
  {
    Wm3::Vec3f rotatedCenter{};
    MultQuadVec(&rotatedCenter, &mLocalCenter, &transform.orient_);
    mShape.Center.x = transform.pos_.x + rotatedCenter.x;
    mShape.Center.y = transform.pos_.y + rotatedCenter.y;
    mShape.Center.z = transform.pos_.z + rotatedCenter.z;
  }

  /**
   * Address: 0x004FF960 (FUN_004FF960, Moho::CColPrimitive_Sphere::GetCenter)
   *
   * What it does:
   * Writes the primitive's LOCAL center to caller output.
   *
   * 0x004FF964/69/6F read `[ecx+14h]`, `[ecx+18h]`, `[ecx+1Ch]` --
   * `mLocalCenter`. `mShape` (the world-space sphere) sits at +0x04 and is
   * written by `SetTransform`; see the box primitive's `GetCenter` for the
   * full evidence and for what reading the world lane here costs.
   */
  Wm3::Vec3f* CColPrimitive<Wm3::Sphere3f>::GetCenter(Wm3::Vec3f* outCenter) const
  {
    *outCenter = mLocalCenter;
    return outCenter;
  }

  /**
   * Address: 0x004FF980 (FUN_004FF980, Moho::CColPrimitive_Sphere::SetCenter)
   *
   * What it does:
   * Copies caller center into the primitive's LOCAL center.
   *
   * 0x004FF986/8C/92 store to `[ecx+14h]`, `[ecx+18h]`, `[ecx+1Ch]` --
   * `mLocalCenter`, the same lane `GetCenter` reads.
   */
  const Wm3::Vec3f* CColPrimitive<Wm3::Sphere3f>::SetCenter(const Wm3::Vec3f* center)
  {
    mLocalCenter = *center;
    return center;
  }

  /**
   * Address: 0x004FE9D0 (FUN_004FE9D0, Moho::CColPrimitive_Sphere::CollideLine)
   *
   * What it does:
   * Tests segment-vs-sphere and fills first hit point, separation direction, and distance from line start.
   */
  bool CColPrimitive<Wm3::Sphere3f>::CollideLine(
    const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionSegmentResult* outResult
  ) const
  {
    const Wm3::Segment3f segment = BuildSegmentFromEndpoints(*lineStart, *lineEnd);

    int quantity = 0;
    Wm3::Vec3f points[2]{};
    float segmentT[2]{};
    if (!Wm3::IntrSegment3Sphere3fFind(segment, mShape, &quantity, points, segmentT)) {
      return false;
    }

    const Wm3::Vec3f hitPoint = points[0];
    const Wm3::Vec3f sphereToHit = mShape.Center - hitPoint;
    Wm3::Vec3f direction{};
    Wm3::Vector3f::NormalizeInto(sphereToHit, &direction);

    const Wm3::Vec3f hitFromStart = hitPoint - *lineStart;
    outResult->direction = direction;
    outResult->position = hitPoint;
    outResult->distanceFromLineStart = Wm3::SqrtfBinary(Wm3::Vector3f::LengthSq(hitFromStart));
    return true;
  }

  /**
   * Address: 0x004FE860 (FUN_004FE860, Moho::CColPrimitive_Sphere::CollideBox)
   *
   * What it does:
   * Tests box-vs-sphere overlap and fills penetration direction/depth.
   */
  bool CColPrimitive<Wm3::Sphere3f>::CollideBox(const Wm3::Box3f* box, CollisionResult* outResult) const
  {
    if (!Wm3::IntrBox3Sphere3fTest(*box, mShape)) {
      return false;
    }

    const Wm3::Vec3f boxCenter{box->Center[0], box->Center[1], box->Center[2]};
    const Wm3::Vec3f boxToSphere = boxCenter - mShape.Center;
    Wm3::Vec3f direction{};
    Wm3::Vector3f::NormalizeInto(boxToSphere, &direction);
    outResult->direction = direction;

    float contactTime = 0.0f;
    Wm3::Vec3f contactPoint{};
    int intrType = 0;
    if (Wm3::IntrBox3Sphere3fStaticFind(
          kSweepTMax, *box, mShape, kZeroVec3f, kZeroVec3f, &contactTime, &contactPoint, &intrType
        )) {
      const Wm3::Vec3f sphereToContact = contactPoint - mShape.Center;
      outResult->penetrationDepth = mShape.Radius - Wm3::SqrtfBinary(Wm3::Vector3f::LengthSq(sphereToContact));
    }
    return true;
  }

  /**
   * Address: 0x004FE7A0 (FUN_004FE7A0, Moho::CColPrimitive_Sphere::CollideSphere)
   *
   * What it does:
   * Tests sphere-vs-sphere overlap and fills penetration direction/depth.
   */
  bool CColPrimitive<Wm3::Sphere3f>::CollideSphere(const Wm3::Sphere3f* sphere, CollisionResult* outResult) const
  {
    const Wm3::Vec3f delta = sphere->Center - mShape.Center;
    const float combinedRadius = sphere->Radius + mShape.Radius;
    const float squaredDistance = Wm3::Vector3f::LengthSq(delta);
    if (combinedRadius * combinedRadius <= squaredDistance) {
      return false;
    }

    Wm3::Vec3f direction{};
    Wm3::Vector3f::NormalizeInto(delta, &direction);
    outResult->direction = direction;
    outResult->penetrationDepth = combinedRadius - Wm3::SqrtfBinary(squaredDistance);
    return true;
  }

  /**
   * Address: 0x004FEB60 (FUN_004FEB60, Moho::CColPrimitive_Sphere::PointInShape)
   *
   * What it does:
   * Returns true when point lies strictly inside sphere.
   */
  bool CColPrimitive<Wm3::Sphere3f>::PointInShape(const Wm3::Vec3f* point) const
  {
    const Wm3::Vec3f delta = *point - mShape.Center;
    return mShape.Radius * mShape.Radius > Wm3::Vector3f::LengthSq(delta);
  }

  /**
   * Address: 0x00676A40 (FUN_00676A40, Moho::CColPrimitiveBase::Collide)
   * Mangled: ?Collide@CColPrimitiveBase@Moho@@QAE_NPAVCColPrimitiveBase@2@PAUCollisionResult@2@@Z
   *
   * What it does:
   * Dispatches shape-vs-shape collision by querying `with` shape type (box vs
   * sphere), then calling the matching `CollideBox` or `CollideSphere` virtual
   * on `this`.  Asserts unreachable if `with` has neither shape.
   */
  bool CColPrimitiveBase::Collide(
    const CColPrimitiveBase* with,
    CollisionResult* outResult
  ) const
  {
    if (const Wm3::Box3f* box = with->GetBox()) {
      return CollideBox(box, outResult);
    }
    const Wm3::Sphere3f* sphere = with->GetSphere();
    if (!sphere) {
      gpg::HandleAssertFailure(
        "Reached the supposably unreachable.",
        94,
        "c:\\work\\rts\\main\\code\\src\\core/ColMain.h"
      );
    }
    return CollideSphere(sphere, outResult);
  }
} // namespace moho
