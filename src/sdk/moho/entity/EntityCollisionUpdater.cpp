#include "EntityCollisionUpdater.h"

#include <array>
#include <cmath>
#include <limits>

#include "EntityTransformPayload.h"
#include "wm3/Distance3.h"

namespace
{
  constexpr float kAxisLengthSqEpsilon = 1.0e-6f;
  constexpr float kSupportSelectionEpsilon = 1.0e-3f;
  constexpr float kSweepTMax = std::numeric_limits<float>::max();
  const Wm3::Vec3f kZeroVec3f{0.0f, 0.0f, 0.0f};

  struct Basis3x3
  {
    float m00;
    float m01;
    float m02;
    float m10;
    float m11;
    float m12;
    float m20;
    float m21;
    float m22;
  };

  [[nodiscard]] Basis3x3 BuildBasisFromQuaternion(const moho::EntityTransformPayload& transform) noexcept
  {
    // Matches FUN_004EC590 (quaternion -> 3x3 basis used by primitive transform).
    // Payload lanes are (w,x,y,z) in quatW/quatX/quatY/quatZ order.
    const float qw = transform.quatW;
    const float qx = transform.quatX;
    const float qy = transform.quatY;
    const float qz = transform.quatZ;

    const float twoQx = qx + qx;
    const float twoQy = qy + qy;
    const float twoQz = qz + qz;

    const float twoQxQx = twoQx * qx;
    const float twoQyQy = twoQy * qy;
    const float twoQzQz = twoQz * qz;
    const float twoQxQy = twoQx * qy;
    const float twoQxQz = twoQx * qz;
    const float twoQyQz = twoQy * qz;
    const float twoQwQx = twoQx * qw;
    const float twoQwQy = twoQy * qw;
    const float twoQwQz = twoQz * qw;

    Basis3x3 basis{};
    basis.m00 = 1.0f - (twoQyQy + twoQzQz);
    basis.m01 = twoQxQy + twoQwQz;
    basis.m02 = twoQxQz - twoQwQy;

    basis.m10 = twoQxQy - twoQwQz;
    basis.m11 = 1.0f - (twoQxQx + twoQzQz);
    basis.m12 = twoQyQz + twoQwQx;

    basis.m20 = twoQxQz + twoQwQy;
    basis.m21 = twoQyQz - twoQwQx;
    basis.m22 = 1.0f - (twoQxQx + twoQyQy);
    return basis;
  }

  struct RotatedVec3
  {
    float x;
    float y;
    float z;
  };

  [[nodiscard]] RotatedVec3 RotateVectorByQuaternion(
    const moho::EntityTransformPayload& transform, const float x, const float y, const float z
  ) noexcept
  {
    // Payload quaternion lanes are packed as (w,x,y,z) in quatW/quatX/quatY/quatZ.
    const float qw = transform.quatW;
    const float qx = transform.quatX;
    const float qy = transform.quatY;
    const float qz = transform.quatZ;

    const float uvx = qy * z - qz * y;
    const float uvy = qz * x - qx * z;
    const float uvz = qx * y - qy * x;

    const float uuvx = qy * uvz - qz * uvy;
    const float uuvy = qz * uvx - qx * uvz;
    const float uuvz = qx * uvy - qy * uvx;

    RotatedVec3 out{};
    out.x = x + 2.0f * (qw * uvx + uuvx);
    out.y = y + 2.0f * (qw * uvy + uuvy);
    out.z = z + 2.0f * (qw * uvz + uuvz);
    return out;
  }

  [[nodiscard]] Wm3::Vec3f BuildBoxCenter(const Wm3::Box3f& box) noexcept
  {
    return {box.Center[0], box.Center[1], box.Center[2]};
  }

  void WriteBoxCenter(Wm3::Box3f& box, const Wm3::Vec3f& center) noexcept
  {
    box.Center[0] = center.x;
    box.Center[1] = center.y;
    box.Center[2] = center.z;
  }

  [[nodiscard]] Wm3::Vec3f BoxAxis(const Wm3::Box3f& box, const int axisIndex) noexcept
  {
    return {box.Axis[axisIndex][0], box.Axis[axisIndex][1], box.Axis[axisIndex][2]};
  }

  void ProjectBoxOntoAxis(const Wm3::Box3f& box, const Wm3::Vec3f& axis, float* outMin, float* outMax) noexcept
  {
    const Wm3::Vec3f center = BuildBoxCenter(box);
    const Wm3::Vec3f axis0 = BoxAxis(box, 0);
    const Wm3::Vec3f axis1 = BoxAxis(box, 1);
    const Wm3::Vec3f axis2 = BoxAxis(box, 2);

    const float centerProjection = Wm3::Vector3f::Dot(axis, center);
    const float radius = std::fabs(Wm3::Vector3f::Dot(axis, axis0)) * box.Extent[0] +
      std::fabs(Wm3::Vector3f::Dot(axis, axis1)) * box.Extent[1] +
      std::fabs(Wm3::Vector3f::Dot(axis, axis2)) * box.Extent[2];

    *outMin = centerProjection - radius;
    *outMax = centerProjection + radius;
  }

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
   * Address: 0x0067AC40 (FUN_0067AC40, inlined construction payload)
   *
   * What it does:
   * Initializes box primitive state from local box and stores local-center copy.
   */
  BoxCollisionPrimitive::BoxCollisionPrimitive(const Wm3::Box3f& localBox)
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
   * Computes world-space AABB from center/basis/extents and writes it to caller scratch buffer.
   */
  const EntityCollisionBoundsView*
  BoxCollisionPrimitive::GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const
  {
    auto* const bounds = &scratch0x1C->bounds;
    Wm3::Vec3f minimum{};
    Wm3::Vec3f maximum{};
    mShape.ComputeAABB(minimum, maximum);
    bounds->minX = minimum.x;
    bounds->minY = minimum.y;
    bounds->minZ = minimum.z;
    bounds->maxX = maximum.x;
    bounds->maxY = maximum.y;
    bounds->maxZ = maximum.z;
    return bounds;
  }

  /**
   * Address: 0x004FF130 (FUN_004FF130, Moho::CColPrimitive_Box::GetSphere)
   *
   * What it does:
   * Box primitive has no sphere view and returns null.
   */
  const Wm3::Sphere3f* BoxCollisionPrimitive::GetSphere() const
  {
    return nullptr;
  }

  /**
   * Address: 0x004FF140 (FUN_004FF140, Moho::CColPrimitive_Box::GetBox)
   *
   * What it does:
   * Returns pointer to box payload at +0x04.
   */
  const Wm3::Box3f* BoxCollisionPrimitive::GetBox() const
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
   * Rotates local-center offset by transform orientation, adds world position,
   * and updates primitive basis rows.
   */
  void BoxCollisionPrimitive::SetTransform(const EntityTransformPayload& transform)
  {
    const Basis3x3 basis = BuildBasisFromQuaternion(transform);

    const float rotatedLocalX = mLocalCenter.x * basis.m00 + mLocalCenter.y * basis.m01 + mLocalCenter.z * basis.m02;
    const float rotatedLocalY = mLocalCenter.x * basis.m10 + mLocalCenter.y * basis.m11 + mLocalCenter.z * basis.m12;
    const float rotatedLocalZ = mLocalCenter.x * basis.m20 + mLocalCenter.y * basis.m21 + mLocalCenter.z * basis.m22;

    mShape.Center[0] = transform.posX + rotatedLocalX;
    mShape.Center[1] = transform.posY + rotatedLocalY;
    mShape.Center[2] = transform.posZ + rotatedLocalZ;

    mShape.Axis[0][0] = basis.m00;
    mShape.Axis[0][1] = basis.m01;
    mShape.Axis[0][2] = basis.m02;
    mShape.Axis[1][0] = basis.m10;
    mShape.Axis[1][1] = basis.m11;
    mShape.Axis[1][2] = basis.m12;
    mShape.Axis[2][0] = basis.m20;
    mShape.Axis[2][1] = basis.m21;
    mShape.Axis[2][2] = basis.m22;
  }

  /**
   * Address: 0x004FFBE0 (FUN_004FFBE0, Moho::CColPrimitive_Box::GetCenter)
   *
   * What it does:
   * Writes current box center to caller output.
   */
  Wm3::Vec3f* BoxCollisionPrimitive::GetCenter(Wm3::Vec3f* outCenter) const
  {
    *outCenter = BuildBoxCenter(mShape);
    return outCenter;
  }

  /**
   * Address: 0x004FFC00 (FUN_004FFC00, Moho::CColPrimitive_Box::SetCenter)
   *
   * What it does:
   * Copies caller center into current box center.
   */
  const Wm3::Vec3f* BoxCollisionPrimitive::SetCenter(const Wm3::Vec3f* center)
  {
    WriteBoxCenter(mShape, *center);
    return center;
  }

  /**
   * Address: 0x004FF2D0 (FUN_004FF2D0, Moho::CColPrimitive_Box::CollideLine)
   *
   * What it does:
   * Tests segment-vs-box and fills first hit point, separation direction, and distance from line start.
   */
  bool BoxCollisionPrimitive::CollideLine(
    const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult
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
  bool BoxCollisionPrimitive::CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const
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
  bool BoxCollisionPrimitive::CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const
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
  bool BoxCollisionPrimitive::PointInShape(const Wm3::Vec3f* point) const
  {
    return mShape.ContainsPoint(*point);
  }

  /**
   * Address: 0x0067AD30 (FUN_0067AD30, inlined construction payload)
   *
   * What it does:
   * Initializes sphere primitive state from local center/radius.
   */
  SphereCollisionPrimitive::SphereCollisionPrimitive(const Wm3::Vec3f& localCenter, const float radius)
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
   * Writes axis-aligned bounds from `{center,radius}` to caller scratch.
   */
  const EntityCollisionBoundsView*
  SphereCollisionPrimitive::GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const
  {
    auto* const bounds = &scratch0x1C->bounds;
    const float radius = mShape.Radius;
    bounds->minX = mShape.Center.x - radius;
    bounds->minY = mShape.Center.y - radius;
    bounds->minZ = mShape.Center.z - radius;
    bounds->maxX = mShape.Center.x + radius;
    bounds->maxY = mShape.Center.y + radius;
    bounds->maxZ = mShape.Center.z + radius;
    return bounds;
  }

  /**
   * Address: 0x004FE780 (FUN_004FE780, Moho::CColPrimitive_Sphere::GetSphere)
   *
   * What it does:
   * Returns pointer to sphere payload at +0x04.
   */
  const Wm3::Sphere3f* SphereCollisionPrimitive::GetSphere() const
  {
    return &mShape;
  }

  /**
   * Address: 0x004FE790 (FUN_004FE790, Moho::CColPrimitive_Sphere::GetBox)
   *
   * What it does:
   * Sphere primitive has no box view and returns null.
   */
  const Wm3::Box3f* SphereCollisionPrimitive::GetBox() const
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
   * Rotates local-center offset by transform orientation and adds world position.
   */
  void SphereCollisionPrimitive::SetTransform(const EntityTransformPayload& transform)
  {
    const RotatedVec3 rotated = RotateVectorByQuaternion(transform, mLocalCenter.x, mLocalCenter.y, mLocalCenter.z);
    mShape.Center.x = transform.posX + rotated.x;
    mShape.Center.y = transform.posY + rotated.y;
    mShape.Center.z = transform.posZ + rotated.z;
  }

  /**
   * Address: 0x004FF960 (FUN_004FF960, Moho::CColPrimitive_Sphere::GetCenter)
   *
   * What it does:
   * Writes current sphere center to caller output.
   */
  Wm3::Vec3f* SphereCollisionPrimitive::GetCenter(Wm3::Vec3f* outCenter) const
  {
    *outCenter = mShape.Center;
    return outCenter;
  }

  /**
   * Address: 0x004FF980 (FUN_004FF980, Moho::CColPrimitive_Sphere::SetCenter)
   *
   * What it does:
   * Copies caller center into current sphere center.
   */
  const Wm3::Vec3f* SphereCollisionPrimitive::SetCenter(const Wm3::Vec3f* center)
  {
    mShape.Center = *center;
    return center;
  }

  /**
   * Address: 0x004FE9D0 (FUN_004FE9D0, Moho::CColPrimitive_Sphere::CollideLine)
   *
   * What it does:
   * Tests segment-vs-sphere and fills first hit point, separation direction, and distance from line start.
   */
  bool SphereCollisionPrimitive::CollideLine(
    const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult
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
  bool SphereCollisionPrimitive::CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const
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
  bool SphereCollisionPrimitive::CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const
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
  bool SphereCollisionPrimitive::PointInShape(const Wm3::Vec3f* point) const
  {
    const Wm3::Vec3f delta = *point - mShape.Center;
    return mShape.Radius * mShape.Radius > Wm3::Vector3f::LengthSq(delta);
  }
} // namespace moho
