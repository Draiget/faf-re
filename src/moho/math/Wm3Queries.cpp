#include "moho/math/Wm3Queries.h"

#include <cmath>

#include "legacy/math/X87Float.h"

// The binary's x87 rules (msvc8::X87Float): an expression stays on the stack,
// and is rounded to float wherever the 2007 build stored it - each named
// variable, each Vector3 temporary, each argument and result of an inlined
// Wild Magic member (Dot, FAbs, Sqrt: IntrSegment3Sphere3<float>::Find stores
// kDiff.Dot(kDiff) at 0x00A47214 before subtracting the squared radius).
// Where the binary calls the out-of-line SSE Vector3 operators (operator+
// 0x00428DB0, scalar * vector 0x005006F0) the code below uses Wild Magic's
// float operators.

namespace
{
  using msvc8::X87Float;
  using Wm3::Vector2f;
  using Wm3::Vector3f;

  /// `fstp dword`.
  [[nodiscard]] float Store(const X87Float value) noexcept
  {
    return static_cast<float>(value);
  }

  /// Vector3::Dot inlined: ((x*x' + y*y') + z*z') on the stack, the result
  /// stored.
  [[nodiscard]] float Dot(const Vector3f& lhs, const Vector3f& rhs) noexcept
  {
    return Store((X87Float(lhs.x) * rhs.x + X87Float(lhs.y) * rhs.y) + X87Float(lhs.z) * rhs.z);
  }

  [[nodiscard]] float Dot(const Vector2f& lhs, const Vector2f& rhs) noexcept
  {
    return Store(X87Float(lhs.x) * rhs.x + X87Float(lhs.y) * rhs.y);
  }

  /// The inlined Vector3 operators: each lane formed on the stack and stored.
  [[nodiscard]] Vector3f Sub(const Vector3f& lhs, const Vector3f& rhs) noexcept
  {
    return {Store(X87Float(lhs.x) - rhs.x), Store(X87Float(lhs.y) - rhs.y), Store(X87Float(lhs.z) - rhs.z)};
  }

  [[nodiscard]] Vector3f Add(const Vector3f& lhs, const Vector3f& rhs) noexcept
  {
    return {Store(X87Float(lhs.x) + rhs.x), Store(X87Float(lhs.y) + rhs.y), Store(X87Float(lhs.z) + rhs.z)};
  }

  [[nodiscard]] Vector3f Scale(const float scalar, const Vector3f& vector) noexcept
  {
    return {Store(X87Float(scalar) * vector.x), Store(X87Float(scalar) * vector.y), Store(X87Float(scalar) * vector.z)};
  }

  [[nodiscard]] Vector3f Cross(const Vector3f& lhs, const Vector3f& rhs) noexcept
  {
    return {
      Store(X87Float(lhs.y) * rhs.z - X87Float(lhs.z) * rhs.y),
      Store(X87Float(lhs.z) * rhs.x - X87Float(lhs.x) * rhs.z),
      Store(X87Float(lhs.x) * rhs.y - X87Float(lhs.y) * rhs.x),
    };
  }

  [[nodiscard]] Vector2f Sub(const Vector2f& lhs, const Vector2f& rhs) noexcept
  {
    return {Store(X87Float(lhs.x) - rhs.x), Store(X87Float(lhs.y) - rhs.y)};
  }

  /// Math<float>::FAbs inlined: `fabs` of the stored argument, stored.
  [[nodiscard]] float FAbs(const float value) noexcept
  {
    return std::fabs(value);
  }

  /// Math<float>::Sqrt: `_CIsqrt` (0x00A91000) runs `fsqrt` under 24-bit
  /// precision control, one rounding of the root to a float.
  [[nodiscard]] float Sqrt(const float value) noexcept
  {
    return std::sqrt(value);
  }

  /// Math<float>::InvSqrt: `fld1; fdivr` of the root on the stack, stored.
  [[nodiscard]] float InvSqrt(const float value) noexcept
  {
    return Store(X87Float(1.0f) / Sqrt(value));
  }

  /// IntrLine3Box3<float>::Clip (0x00A4FCC0): the products stay on the stack
  /// for the comparisons, the quotient is stored. A NaN denominator takes
  /// the last branch (`test ah, 41h` / `test ah, 5` at 0x00A4FCCA, 0x00A4FD10).
  [[nodiscard]] bool Clip(const float denom, const float numer, float& t0, float& t1) noexcept
  {
    if (denom > 0.0f) {
      if (X87Float(numer) > X87Float(denom) * t1) {
        return false;
      }
      if (X87Float(numer) > X87Float(denom) * t0) {
        t0 = Store(X87Float(numer) / denom);
      }
      return true;
    }
    if (denom < 0.0f) {
      if (X87Float(numer) > X87Float(denom) * t0) {
        return false;
      }
      if (X87Float(numer) > X87Float(denom) * t1) {
        t1 = Store(X87Float(numer) / denom);
      }
      return true;
    }
    return numer <= 0.0f;
  }

  /// IntrLine3Box3<float>::DoClipping (0x00A50220). The intersection points
  /// are formed inline (0x00A504AC..0x00A50548).
  [[nodiscard]] int DoClipping(
    float t0,
    float t1,
    const Vector3f& origin,
    const Vector3f& direction,
    const Wm3::Box3f& box,
    const bool solid,
    Vector3f points[2]
  ) noexcept
  {
    const Vector3f diff = Sub(origin, box.Center);
    const Vector3f boxOrigin{Dot(diff, box.Axis[0]), Dot(diff, box.Axis[1]), Dot(diff, box.Axis[2])};
    const Vector3f boxDirection{Dot(direction, box.Axis[0]), Dot(direction, box.Axis[1]), Dot(direction, box.Axis[2])};

    const float saveT0 = t0;
    const float saveT1 = t1;
    const bool notAllClipped =
      Clip(+boxDirection.x, Store(-X87Float(boxOrigin.x) - box.Extent[0]), t0, t1) &&
      Clip(-boxDirection.x, Store(X87Float(boxOrigin.x) - box.Extent[0]), t0, t1) &&
      Clip(+boxDirection.y, Store(-X87Float(boxOrigin.y) - box.Extent[1]), t0, t1) &&
      Clip(-boxDirection.y, Store(X87Float(boxOrigin.y) - box.Extent[1]), t0, t1) &&
      Clip(+boxDirection.z, Store(-X87Float(boxOrigin.z) - box.Extent[2]), t0, t1) &&
      Clip(-boxDirection.z, Store(X87Float(boxOrigin.z) - box.Extent[2]), t0, t1);

    if (notAllClipped && (solid || t0 != saveT0 || t1 != saveT1)) {
      if (t1 > t0) {
        points[0] = Add(origin, Scale(t0, direction));
        points[1] = Add(origin, Scale(t1, direction));
        return 2;
      }
      points[0] = Add(origin, Scale(t0, direction));
      return 1;
    }
    return 0;
  }

  /// DistVector2Box2<float>::GetSquared (the closest point is not kept).
  [[nodiscard]] float SquaredDistanceVector2Box2(const Vector2f& point, const Wm3::Box2f& box) noexcept
  {
    const Vector2f diff = Sub(point, box.Center);
    float sqrDistance = 0.0f;
    for (int i = 0; i < 2; ++i) {
      const float closest = Dot(diff, box.Axis[i]);
      if (closest < -box.Extent[i]) {
        const float delta = Store(X87Float(closest) + box.Extent[i]);
        sqrDistance = Store(X87Float(delta) * delta + sqrDistance);
      } else if (closest > box.Extent[i]) {
        const float delta = Store(X87Float(closest) - box.Extent[i]);
        sqrDistance = Store(X87Float(delta) * delta + sqrDistance);
      }
    }
    return sqrDistance;
  }
} // namespace

namespace Wm3
{
  int FindSegment3Box3(const Segment3f& segment, const Box3f& box, const bool solid, Vector3f points[2]) noexcept
  {
    return DoClipping(-segment.Extent, segment.Extent, segment.Origin, segment.Direction, box, solid, points);
  }

  int FindSegment3Sphere3(const Segment3f& segment, const Sphere3f& sphere, Vector3f points[2]) noexcept
  {
    constexpr float kZeroThreshold = 1e-06f; // Math<float>::ZERO_TOLERANCE, set by the ctor 0x00A46A10

    const Vector3f diff = Sub(segment.Origin, sphere.Center);
    const float a0 = Store(X87Float(Dot(diff, diff)) - X87Float(sphere.Radius) * sphere.Radius);
    const float a1 = Dot(segment.Direction, diff);
    const float discr = Store(X87Float(a1) * a1 - a0);
    if (discr < 0.0f) {
      return 0;
    }

    const float tmp0 = Store(X87Float(segment.Extent) * segment.Extent + a0);
    const float tmp1 = Store(X87Float(2.0f) * a1 * segment.Extent);
    const float qm = Store(X87Float(tmp0) - tmp1);
    const float qp = Store(X87Float(tmp0) + tmp1);
    // 0x00A472AD..0x00A472BE: the product is compared on the stack - two
    // values a hair either side of the sphere give one past the float range.
    if (X87Float(qm) * qp <= X87Float(0.0f)) {
      const float root = Sqrt(discr);
      const float t = Store(qm > 0.0f ? -X87Float(a1) - root : -X87Float(a1) + root);
      // 0x00A47308..0x00A4735B: formed inline.
      points[0] = Add(segment.Origin, Scale(t, segment.Direction));
      return 1;
    }

    if (qm > 0.0f && FAbs(a1) < segment.Extent) {
      if (discr >= kZeroThreshold) {
        const float root = Sqrt(discr);
        const float t0 = Store(-X87Float(a1) - root);
        const float t1 = Store(-X87Float(a1) + root);
        // 0x00A473DB..0x00A47424: the SSE operators.
        points[0] = segment.Origin + t0 * segment.Direction;
        points[1] = segment.Origin + t1 * segment.Direction;
        return 2;
      }
      const float t = -a1;
      points[0] = segment.Origin + t * segment.Direction; // 0x00A47469..0x00A47479
      return 1;
    }
    return 0;
  }

  bool TestBox3Sphere3(const Box3f& box, const Sphere3f& sphere) noexcept
  {
    const Vector3f centerDiff = Sub(sphere.Center, box.Center);
    const float ax = FAbs(Dot(centerDiff, box.Axis[0]));
    const float ay = FAbs(Dot(centerDiff, box.Axis[1]));
    const float az = FAbs(Dot(centerDiff, box.Axis[2]));
    const float dx = Store(X87Float(ax) - box.Extent[0]);
    const float dy = Store(X87Float(ay) - box.Extent[1]);
    const float dz = Store(X87Float(az) - box.Extent[2]);

    if (ax <= box.Extent[0]) {
      if (ay <= box.Extent[1]) {
        if (az <= box.Extent[2]) {
          return true;
        }
        return dz <= sphere.Radius;
      }
      if (az <= box.Extent[2]) {
        return dy <= sphere.Radius;
      }
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      return X87Float(dy) * dy + X87Float(dz) * dz <= X87Float(rSqr);
    }
    if (ay <= box.Extent[1]) {
      if (az <= box.Extent[2]) {
        return dx <= sphere.Radius;
      }
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      return X87Float(dx) * dx + X87Float(dz) * dz <= X87Float(rSqr);
    }
    if (az <= box.Extent[2]) {
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      return X87Float(dx) * dx + X87Float(dy) * dy <= X87Float(rSqr);
    }
    const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
    return (X87Float(dx) * dx + X87Float(dy) * dy) + X87Float(dz) * dz <= X87Float(rSqr);
  }

  float SquaredDistanceVector3Box3(const Vector3f& point, const Box3f& box, Vector3f& closestOnBox) noexcept
  {
    const Vector3f diff = Sub(point, box.Center);
    float sqrDistance = 0.0f;
    float closest[3];
    for (int i = 0; i < 3; ++i) {
      closest[i] = Dot(diff, box.Axis[i]);
      if (closest[i] < -box.Extent[i]) {
        const float delta = Store(X87Float(closest[i]) + box.Extent[i]);
        sqrDistance = Store(X87Float(delta) * delta + sqrDistance);
        closest[i] = -box.Extent[i];
      } else if (closest[i] > box.Extent[i]) {
        const float delta = Store(X87Float(closest[i]) - box.Extent[i]);
        sqrDistance = Store(X87Float(delta) * delta + sqrDistance);
        closest[i] = box.Extent[i];
      }
    }

    closestOnBox = box.Center;
    for (int i = 0; i < 3; ++i) {
      closestOnBox = Add(closestOnBox, Scale(closest[i], box.Axis[i]));
    }
    return sqrDistance;
  }

  float SquaredDistanceVector3Segment3(const Vector3f& point, const Segment3f& segment, Vector3f& closestOnSegment) noexcept
  {
    const Vector3f diff = Sub(point, segment.Origin);
    const float param = Dot(segment.Direction, diff);
    if (-segment.Extent < param) {
      if (param < segment.Extent) {
        closestOnSegment = Add(segment.Origin, Scale(param, segment.Direction));
      } else {
        closestOnSegment = Add(segment.Origin, Scale(segment.Extent, segment.Direction));
      }
    } else {
      closestOnSegment = Sub(segment.Origin, Scale(segment.Extent, segment.Direction));
    }
    const Vector3f toClosest = Sub(closestOnSegment, point);
    return Dot(toClosest, toClosest);
  }

  float DistanceVector3Segment3(const Vector3f& point, const Segment3f& segment) noexcept
  {
    Vector3f closest;
    return Sqrt(SquaredDistanceVector3Segment3(point, segment, closest));
  }

  bool TestBox2Box2(const Box2f& box0, const Box2f& box1) noexcept
  {
    const Vector2f* const a = box0.Axis;
    const Vector2f* const b = box1.Axis;
    const float* const ea = box0.Extent;
    const float* const eb = box1.Extent;
    const Vector2f d = Sub(box1.Center, box0.Center);

    float absAdB[2][2];
    absAdB[0][0] = FAbs(Dot(a[0], b[0]));
    absAdB[0][1] = FAbs(Dot(a[0], b[1]));
    float absAdD = FAbs(Dot(a[0], d));
    float rSum = Store((X87Float(ea[0]) + X87Float(eb[0]) * absAdB[0][0]) + X87Float(eb[1]) * absAdB[0][1]);
    if (absAdD > rSum) {
      return false;
    }

    absAdB[1][0] = FAbs(Dot(a[1], b[0]));
    absAdB[1][1] = FAbs(Dot(a[1], b[1]));
    absAdD = FAbs(Dot(a[1], d));
    rSum = Store((X87Float(ea[1]) + X87Float(eb[0]) * absAdB[1][0]) + X87Float(eb[1]) * absAdB[1][1]);
    if (absAdD > rSum) {
      return false;
    }

    absAdD = FAbs(Dot(b[0], d));
    rSum = Store((X87Float(eb[0]) + X87Float(ea[0]) * absAdB[0][0]) + X87Float(ea[1]) * absAdB[1][0]);
    if (absAdD > rSum) {
      return false;
    }

    absAdD = FAbs(Dot(b[1], d));
    rSum = Store((X87Float(eb[1]) + X87Float(ea[0]) * absAdB[0][1]) + X87Float(ea[1]) * absAdB[1][1]);
    return !(absAdD > rSum);
  }

  bool TestBox2Circle2(const Box2f& box, const Circle2f& circle) noexcept
  {
    return Sqrt(SquaredDistanceVector2Box2(circle.Center, box)) <= circle.Radius;
  }

  bool TestLine3Box3(const Line3f& line, const Box3f& box) noexcept
  {
    const Vector3f diff = Sub(line.Origin, box.Center);
    const Vector3f wxd = Cross(line.Direction, diff);

    float awdu[3];
    float awxddu[3];
    awdu[1] = FAbs(Dot(line.Direction, box.Axis[1]));
    awdu[2] = FAbs(Dot(line.Direction, box.Axis[2]));
    awxddu[0] = FAbs(Dot(wxd, box.Axis[0]));
    float rhs = Store(X87Float(box.Extent[1]) * awdu[2] + X87Float(box.Extent[2]) * awdu[1]);
    if (awxddu[0] > rhs) {
      return false;
    }

    awdu[0] = FAbs(Dot(line.Direction, box.Axis[0]));
    awxddu[1] = FAbs(Dot(wxd, box.Axis[1]));
    rhs = Store(X87Float(box.Extent[0]) * awdu[2] + X87Float(box.Extent[2]) * awdu[0]);
    if (awxddu[1] > rhs) {
      return false;
    }

    awxddu[2] = FAbs(Dot(wxd, box.Axis[2]));
    rhs = Store(X87Float(box.Extent[0]) * awdu[1] + X87Float(box.Extent[1]) * awdu[0]);
    return !(awxddu[2] > rhs);
  }

  bool PointInBox3(const Vector3f& point, const Box3f& box) noexcept
  {
    const Vector3f diff = Sub(point, box.Center);
    for (int i = 0; i < 3; ++i) {
      if (FAbs(Dot(diff, box.Axis[i])) > box.Extent[i]) {
        return false;
      }
    }
    return true;
  }

  Box3f ContAlignedBox3(const int quantity, const Vector3f* const points) noexcept
  {
    Vector3f minimum = points[0];
    Vector3f maximum = minimum;
    for (int i = 1; i < quantity; ++i) {
      for (int lane = 0; lane < 3; ++lane) {
        if (points[i][lane] < minimum[lane]) {
          minimum[lane] = points[i][lane];
        } else if (points[i][lane] > maximum[lane]) {
          maximum[lane] = points[i][lane];
        }
      }
    }

    const Vector3f halfDiagonal = Scale(0.5f, Sub(maximum, minimum));
    return Box3f(
      Scale(0.5f, Add(minimum, maximum)),
      Vector3f(1.0f, 0.0f, 0.0f),
      Vector3f(0.0f, 1.0f, 0.0f),
      Vector3f(0.0f, 0.0f, 1.0f),
      halfDiagonal.x,
      halfDiagonal.y,
      halfDiagonal.z
    );
  }

  namespace
  {
    // IntrBox3Sphere3<float>'s private helpers, with the query's state.
    struct BoxSphereSweep
    {
      const Sphere3f& sphere;
      float contactTime = 0.0f; // Intersector's ctor

      [[nodiscard]] static float
      GetVertexIntersection(float dx, float dy, float dz, float vx, float vy, float vz, float rSqr) noexcept;
      [[nodiscard]] static float GetEdgeIntersection(float dx, float dz, float vx, float vz, float vSqr, float rSqr) noexcept;
      [[nodiscard]] int FindFaceRegionIntersection(
        float ex, float ey, float ez, float cx, float cy, float cz, float vx, float vy, float vz,
        float& ix, float& iy, float& iz, bool aboveFace
      ) noexcept;
      [[nodiscard]] int FindJustEdgeIntersection(
        float cy, float ex, float ey, float ez, float dx, float dz, float vx, float vy, float vz,
        float& ix, float& iy, float& iz
      ) noexcept;
      [[nodiscard]] int FindEdgeRegionIntersection(
        float ex, float ey, float ez, float cx, float cy, float cz, float vx, float vy, float vz,
        float& ix, float& iy, float& iz, bool aboveEdge
      ) noexcept;
      [[nodiscard]] int FindVertexRegionIntersection(
        float ex, float ey, float ez, float cx, float cy, float cz, float vx, float vy, float vz,
        float& ix, float& iy, float& iz
      ) noexcept;
    };

    float BoxSphereSweep::GetVertexIntersection(
      const float dx, const float dy, const float dz, const float vx, const float vy, const float vz, const float rSqr
    ) noexcept
    {
      const float vSqr = Store((X87Float(vx) * vx + X87Float(vy) * vy) + X87Float(vz) * vz);
      const float dot = Store((X87Float(dx) * vx + X87Float(dy) * vy) + X87Float(dz) * vz);
      const float diff = Store(((X87Float(dx) * dx + X87Float(dy) * dy) + X87Float(dz) * dz) - rSqr);
      const float inv = InvSqrt(FAbs(Store(X87Float(dot) * dot - X87Float(vSqr) * diff)));
      return Store(X87Float(diff) * inv / (X87Float(1.0f) - X87Float(dot) * inv));
    }

    float BoxSphereSweep::GetEdgeIntersection(
      const float dx, const float dz, const float vx, const float vz, const float vSqr, const float rSqr
    ) noexcept
    {
      const float dot = Store(X87Float(vx) * dx + X87Float(vz) * dz);
      const float diff = Store((X87Float(dx) * dx + X87Float(dz) * dz) - rSqr);
      const float inv = InvSqrt(FAbs(Store(X87Float(dot) * dot - X87Float(vSqr) * diff)));
      return Store(X87Float(diff) * inv / (X87Float(1.0f) - X87Float(dot) * inv));
    }

    int BoxSphereSweep::FindFaceRegionIntersection(
      const float ex, const float ey, const float ez, const float cx, const float cy, const float cz,
      const float vx, const float vy, const float vz, float& ix, float& iy, float& iz, const bool aboveFace
    ) noexcept
    {
      if (X87Float(cz) <= X87Float(ez) + sphere.Radius && aboveFace) {
        contactTime = 0.0f;
        return -1;
      }
      if (vz >= 0.0f) {
        return 0;
      }

      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      const float vSqrX = Store(X87Float(vz) * vz + X87Float(vx) * vx);
      const float vSqrY = Store(X87Float(vz) * vz + X87Float(vy) * vy);
      const float dz = Store(X87Float(cz) - ez);
      float dx;
      float dy;
      float crossX;
      float crossY;
      int xSign;
      int ySign;
      if (vx >= 0.0f) {
        xSign = 1;
        dx = Store(X87Float(cx) - ex);
        crossX = Store(X87Float(vx) * dz - X87Float(vz) * dx);
      } else {
        xSign = -1;
        dx = Store(X87Float(cx) + ex);
        crossX = Store(X87Float(vz) * dx - X87Float(vx) * dz);
      }
      if (vy >= 0.0f) {
        ySign = 1;
        dy = Store(X87Float(cy) - ey);
        crossY = Store(X87Float(vy) * dz - X87Float(vz) * dy);
      } else {
        ySign = -1;
        dy = Store(X87Float(cy) + ey);
        crossY = Store(X87Float(vz) * dy - X87Float(vy) * dz);
      }

      if (X87Float(crossX) > X87Float(sphere.Radius) * vx * X87Float::FromInt(xSign)) {
        if (X87Float(crossX) * crossX > X87Float(rSqr) * vSqrX) {
          return 0;
        }
        if (X87Float(crossY) > X87Float(sphere.Radius) * vy * X87Float::FromInt(ySign)) {
          if (X87Float(crossY) * crossY > X87Float(rSqr) * vSqrY) {
            return 0;
          }
          const Vector3f velocity(vx, vy, vz);
          const Vector3f d(dx, dy, dz);
          const Vector3f cross = Cross(d, velocity);
          if (X87Float(Dot(cross, cross)) > X87Float(rSqr) * Dot(velocity, velocity)) {
            return 0;
          }
          contactTime = GetVertexIntersection(dx, dy, dz, vx, vy, vz, rSqr);
          ix = Store(X87Float(ex) * X87Float::FromInt(xSign));
          iy = Store(X87Float(ey) * X87Float::FromInt(ySign));
        } else {
          contactTime = GetEdgeIntersection(dx, dz, vx, vz, vSqrX, rSqr);
          ix = Store(X87Float(ex) * X87Float::FromInt(xSign));
          iy = Store(X87Float(cy) + X87Float(vy) * contactTime);
        }
      } else {
        if (X87Float(crossY) > X87Float(sphere.Radius) * vy * X87Float::FromInt(ySign)) {
          if (X87Float(crossY) * crossY > X87Float(rSqr) * vSqrY) {
            return 0;
          }
          contactTime = GetEdgeIntersection(dy, dz, vy, vz, vSqrY, rSqr);
          ix = Store(X87Float(cx) + X87Float(vx) * contactTime);
          iy = Store(X87Float(ey) * X87Float::FromInt(ySign));
        } else {
          contactTime = Store((-X87Float(dz) + sphere.Radius) / vz);
          ix = Store(X87Float(contactTime) * vx + cx);
          iy = Store(X87Float(contactTime) * vy + cy);
        }
      }
      iz = ez;
      return 1;
    }

    int BoxSphereSweep::FindJustEdgeIntersection(
      const float cy, const float ex, const float ey, const float ez, const float dx, const float dz,
      const float vx, const float vy, const float vz, float& ix, float& iy, float& iz
    ) noexcept
    {
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      float dy;
      float crossZ;
      float crossX;
      int signY;
      if (vy >= 0.0f) {
        signY = 1;
        dy = Store(X87Float(cy) - ey);
        crossZ = Store(X87Float(dx) * vy - X87Float(dy) * vx);
        crossX = Store(X87Float(dz) * vy - X87Float(dy) * vz);
      } else {
        signY = -1;
        dy = Store(X87Float(cy) + ey);
        crossZ = Store(X87Float(dy) * vx - X87Float(dx) * vy);
        crossX = Store(X87Float(dy) * vz - X87Float(dz) * vy);
      }

      if (crossZ >= 0.0f && crossX >= 0.0f &&
          X87Float(crossX) * crossX + X87Float(crossZ) * crossZ >
            X87Float(vy) * vy * sphere.Radius * sphere.Radius) {
        const Vector3f velocity(vx, vy, vz);
        const Vector3f d(dx, dy, dz);
        const Vector3f cross = Cross(d, velocity);
        if (X87Float(Dot(cross, cross)) > X87Float(rSqr) * Dot(velocity, velocity)) {
          return 0;
        }
        contactTime = GetVertexIntersection(dx, dy, dz, vx, vy, vz, rSqr);
        ix = ex;
        iy = Store(X87Float::FromInt(signY) * ey);
        iz = ez;
      } else {
        const float vSqrX = Store(X87Float(vz) * vz + X87Float(vx) * vx);
        contactTime = GetEdgeIntersection(dx, dz, vx, vz, vSqrX, rSqr);
        ix = ex;
        iy = Store(X87Float(cy) + X87Float(contactTime) * vy);
        iz = ez;
      }
      return 1;
    }

    int BoxSphereSweep::FindEdgeRegionIntersection(
      const float ex, const float ey, const float ez, const float cx, const float cy, const float cz,
      const float vx, const float vy, const float vz, float& ix, float& iy, float& iz, const bool aboveEdge
    ) noexcept
    {
      const float dx = Store(X87Float(cx) - ex);
      const float dz = Store(X87Float(cz) - ez);
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      if (aboveEdge) {
        const float diff = Store((X87Float(dx) * dx + X87Float(dz) * dz) - rSqr);
        if (diff <= 0.0f) {
          contactTime = 0.0f;
          return -1;
        }
      }

      const float dot = Store(X87Float(vx) * dx + X87Float(vz) * dz);
      if (dot >= 0.0f) {
        return 0;
      }

      const float kross = Store(X87Float(vz) * dx - X87Float(vx) * dz);
      if (kross >= 0.0f) {
        if (vx >= 0.0f) {
          return 0;
        }
        if (X87Float(kross) <= -X87Float(sphere.Radius) * vx) {
          return FindJustEdgeIntersection(cy, ez, ey, ex, dz, dx, vz, vy, vx, iz, iy, ix);
        }
        return FindFaceRegionIntersection(ex, ey, ez, cx, cy, cz, vx, vy, vz, ix, iy, iz, false);
      }
      if (vz >= 0.0f) {
        return 0;
      }
      if (X87Float(kross) >= X87Float(sphere.Radius) * vz) {
        return FindJustEdgeIntersection(cy, ex, ey, ez, dx, dz, vx, vy, vz, ix, iy, iz);
      }
      return FindFaceRegionIntersection(ez, ey, ex, cz, cy, cx, vz, vy, vx, iz, iy, ix, false);
    }

    int BoxSphereSweep::FindVertexRegionIntersection(
      const float ex, const float ey, const float ez, const float cx, const float cy, const float cz,
      const float vx, const float vy, const float vz, float& ix, float& iy, float& iz
    ) noexcept
    {
      const float dx = Store(X87Float(cx) - ex);
      const float dy = Store(X87Float(cy) - ey);
      const float dz = Store(X87Float(cz) - ez);
      const float rSqr = Store(X87Float(sphere.Radius) * sphere.Radius);
      const float diff = Store(((X87Float(dx) * dx + X87Float(dy) * dy) + X87Float(dz) * dz) - rSqr);
      if (diff <= 0.0f) {
        contactTime = 0.0f;
        return -1;
      }
      if ((X87Float(vx) * dx + X87Float(vy) * dy) + X87Float(vz) * dz >= X87Float(0.0f)) {
        return 0;
      }

      const float crossX = Store(X87Float(vy) * dz - X87Float(vz) * dy);
      const float crossY = Store(X87Float(vx) * dz - X87Float(vz) * dx);
      const float crossZ = Store(X87Float(vy) * dx - X87Float(vx) * dy);
      const float crX2 = Store(X87Float(crossX) * crossX);
      const float crY2 = Store(X87Float(crossY) * crossY);
      const float crZ2 = Store(X87Float(crossZ) * crossZ);
      const float vx2 = Store(X87Float(vx) * vx);
      const float vy2 = Store(X87Float(vy) * vy);
      const float vz2 = Store(X87Float(vz) * vz);

      if ((crossY < 0.0f && crossZ >= 0.0f && X87Float(crY2) + crZ2 <= X87Float(rSqr) * vx2) ||
          (crossZ < 0.0f && crossX < 0.0f && X87Float(crX2) + crZ2 <= X87Float(rSqr) * vy2) ||
          (crossY >= 0.0f && crossX >= 0.0f && X87Float(crX2) + crY2 <= X87Float(rSqr) * vz2)) {
        contactTime = GetVertexIntersection(dx, dy, dz, vx, vy, vz, Store(X87Float(sphere.Radius) * sphere.Radius));
        ix = Store(X87Float(contactTime) * vx + cx);
        iy = Store(X87Float(contactTime) * vy + cy);
        iz = Store(X87Float(contactTime) * vz + cz);
        return 1;
      }
      if (crossY < 0.0f && crossZ >= 0.0f) {
        return FindEdgeRegionIntersection(ey, ex, ez, cy, cx, cz, vy, vx, vz, iy, ix, iz, false);
      }
      if (crossZ < 0.0f && crossX < 0.0f) {
        return FindEdgeRegionIntersection(ex, ey, ez, cx, cy, cz, vx, vy, vz, ix, iy, iz, false);
      }
      return FindEdgeRegionIntersection(ex, ez, ey, cx, cz, cy, vx, vz, vy, ix, iz, iy, false);
    }
  } // namespace

  bool FindBox3Sphere3(
    const Box3f& box,
    const Sphere3f& sphere,
    const float tMax,
    const Vector3f& velocity0,
    const Vector3f& velocity1,
    float& contactTime,
    Vector3f& contactPoint
  ) noexcept
  {
    BoxSphereSweep sweep{sphere};
    const Vector3f centerDiff = Sub(sphere.Center, box.Center);
    const Vector3f velocity = Sub(velocity1, velocity0);
    float ax = Dot(centerDiff, box.Axis[0]);
    float ay = Dot(centerDiff, box.Axis[1]);
    float az = Dot(centerDiff, box.Axis[2]);
    float vx = Dot(velocity, box.Axis[0]);
    float vy = Dot(velocity, box.Axis[1]);
    float vz = Dot(velocity, box.Axis[2]);

    int signX = 1;
    if (ax < 0.0f) {
      ax = -ax;
      vx = -vx;
      signX = -1;
    }
    int signY = 1;
    if (ay < 0.0f) {
      ay = -ay;
      vy = -vy;
      signY = -1;
    }
    int signZ = 1;
    if (az < 0.0f) {
      az = -az;
      vz = -vz;
      signZ = -1;
    }

    // Wild Magic leaves these unset on the paths that return 0, and Wild Magic
    // 3.8 then reports a hit (`iRetVal != 0` is the miss test below). Retail
    // reads them from slots its frame shares with other locals or from the
    // caller's stack (difffuzz, with the stack below the call zeroed: one
    // coordinate came back as the box-space az, one as |ax|, one as 0), which
    // no port reproduces. CColPrimitive<Sphere3f>::CollideBox calls Find with
    // zero velocities only after Test passed; with finite lanes Find then
    // returns -1 (already touching) or the centre-inside hit, so the
    // simulation never reaches them (ColSphere::CollideBox, 0 mismatches).
    float ix = 0.0f;
    float iy = 0.0f;
    float iz = 0.0f;
    int retVal;
    const float* const e = box.Extent;
    if (ax <= e[0]) {
      if (ay <= e[1]) {
        if (az <= e[2]) {
          contactTime = 0.0f;
          contactPoint = sphere.Center;
          return true;
        }
        retVal = sweep.FindFaceRegionIntersection(e[0], e[1], e[2], ax, ay, az, vx, vy, vz, ix, iy, iz, true);
      } else if (az <= e[2]) {
        retVal = sweep.FindFaceRegionIntersection(e[0], e[2], e[1], ax, az, ay, vx, vz, vy, ix, iz, iy, true);
      } else {
        retVal = sweep.FindEdgeRegionIntersection(e[1], e[0], e[2], ay, ax, az, vy, vx, vz, iy, ix, iz, true);
      }
    } else if (ay <= e[1]) {
      if (az <= e[2]) {
        retVal = sweep.FindFaceRegionIntersection(e[1], e[2], e[0], ay, az, ax, vy, vz, vx, iy, iz, ix, true);
      } else {
        retVal = sweep.FindEdgeRegionIntersection(e[0], e[1], e[2], ax, ay, az, vx, vy, vz, ix, iy, iz, true);
      }
    } else if (az <= e[2]) {
      retVal = sweep.FindEdgeRegionIntersection(e[0], e[2], e[1], ax, az, ay, vx, vz, vy, ix, iz, iy, true);
    } else {
      retVal = sweep.FindVertexRegionIntersection(e[0], e[1], e[2], ax, ay, az, vx, vy, vz, ix, iy, iz);
    }

    if (retVal != 0 || sweep.contactTime > tMax) {
      contactTime = sweep.contactTime;
      return false;
    }

    contactTime = sweep.contactTime;
    const Vector3f alongX = Scale(Store(X87Float::FromInt(signX) * ix), box.Axis[0]);
    const Vector3f alongY = Scale(Store(X87Float::FromInt(signY) * iy), box.Axis[1]);
    const Vector3f alongZ = Scale(Store(X87Float::FromInt(signZ) * iz), box.Axis[2]);
    contactPoint = Add(Add(Add(box.Center, alongX), alongY), alongZ);
    return true;
  }
} // namespace Wm3
