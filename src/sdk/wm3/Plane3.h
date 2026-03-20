#pragma once

#include <cmath>
#include <type_traits>

#include "Vector3.h"

namespace Wm3
{
  /**
   * Plane in form Dot(Normal, X) == Constant.
   * This matches classic Wm3 representation N*X = C.
   */
  template <class T> struct Plane3
  {
    Vector3<T> Normal{};
    T Constant{};

    constexpr Plane3() = default;
    constexpr Plane3(const Vector3<T>& normal, const T constant) noexcept :
        Normal(normal),
        Constant(constant)
    {}

    static constexpr Plane3 FromNormalPoint(const Vector3<T>& normal, const Vector3<T>& point) noexcept
    {
      return Plane3(normal, Vector3<T>::Dot(normal, point));
    }

    static Plane3 FromPoints(
      const Vector3<T>& p0, const Vector3<T>& p1, const Vector3<T>& p2, const T eps = T(1e-6)
    ) noexcept
    {
      static_assert(std::is_floating_point_v<T>, "FromPoints requires floating-point T");
      const Vector3<T> e1 = Vector3<T>::Sub(p1, p0);
      const Vector3<T> e2 = Vector3<T>::Sub(p2, p0);
      Vector3<T> normal = Vector3<T>::Cross(e1, e2);
      normal = Vector3<T>::Normalized(normal, eps);
      return Plane3(normal, Vector3<T>::Dot(normal, p0));
    }

    /** Normalize so that |Normal| == 1; returns previous |Normal|. */
    T Normalize(const T eps = T(1e-6)) noexcept
    {
      static_assert(std::is_floating_point_v<T>, "Normalize requires floating-point T");
      const T length = Vector3<T>::Length(Normal);
      if (length > eps) {
        const T invLength = T(1) / length;
        Normal = Vector3<T>::Scale(Normal, invLength);
        Constant *= invLength;
      } else {
        Normal = {T(0), T(0), T(0)};
        Constant = T(0);
      }
      return length;
    }

    /** Signed distance: Dot(N, X) - C. */
    T SignedDistance(const Vector3<T>& point) const noexcept
    {
      static_assert(std::is_floating_point_v<T>, "SignedDistance requires floating-point T");
      return Vector3<T>::Dot(Normal, point) - Constant;
    }

    Vector3<T> ProjectPoint(const Vector3<T>& point) const noexcept
    {
      static_assert(std::is_floating_point_v<T>, "ProjectPoint requires floating-point T");
      const T d = SignedDistance(point);
      return Vector3<T>::Sub(point, Vector3<T>::Scale(Normal, d));
    }

    void Flip() noexcept
    {
      Normal = {-Normal.x, -Normal.y, -Normal.z};
      Constant = -Constant;
    }

    static bool NearlyEquals(
      const Plane3& lhs, const Plane3& rhs, const T epsNormal = T(1e-5), const T epsConstant = T(1e-5)
    ) noexcept
    {
      return Vector3<T>::NearlyEquals(lhs.Normal, rhs.Normal, epsNormal) &&
             std::fabs(lhs.Constant - rhs.Constant) <= epsConstant;
    }

    struct LineHit
    {
      bool hit{};
      T t{};
      Vector3<T> point{};
    };

    static LineHit IntersectLine(
      const Plane3& plane, const Vector3<T>& p0, const Vector3<T>& direction, const T eps = T(1e-6)
    ) noexcept
    {
      static_assert(std::is_floating_point_v<T>, "IntersectLine requires floating-point T");
      const T denom = Vector3<T>::Dot(plane.Normal, direction);
      if (std::fabs(denom) <= eps) {
        return {};
      }
      const T t = (plane.Constant - Vector3<T>::Dot(plane.Normal, p0)) / denom;
      return {true, t, Vector3<T>::Add(p0, Vector3<T>::Scale(direction, t))};
    }

    static LineHit IntersectSegment(
      const Plane3& plane, const Vector3<T>& a, const Vector3<T>& b, const T eps = T(1e-6)
    ) noexcept
    {
      const Vector3<T> direction = Vector3<T>::Sub(b, a);
      const LineHit hit = IntersectLine(plane, a, direction, eps);
      if (!hit.hit || hit.t < T(0) || hit.t > T(1)) {
        return {};
      }
      return hit;
    }

    static LineHit IntersectRay(
      const Plane3& plane, const Vector3<T>& origin, const Vector3<T>& direction, const T eps = T(1e-6)
    ) noexcept
    {
      const LineHit hit = IntersectLine(plane, origin, direction, eps);
      if (!hit.hit || hit.t < T(0)) {
        return {};
      }
      return hit;
    }

    enum class Side
    {
      On,
      Front,
      Back,
    };

    Side Classify(const Vector3<T>& point, const T eps = T(1e-5)) const noexcept
    {
      static_assert(std::is_floating_point_v<T>, "Classify requires floating-point T");
      const T d = SignedDistance(point);
      if (d > eps) {
        return Side::Front;
      }
      if (d < -eps) {
        return Side::Back;
      }
      return Side::On;
    }

    /** Convert from Ax + By + Cz + D = 0 where Constant = -D. */
    static constexpr Plane3 FromAbCd(const Vector3<T>& abc, const T d) noexcept
    {
      return Plane3(abc, -d);
    }

    constexpr Vector3<T> GetAbc() const noexcept
    {
      return Normal;
    }
    constexpr T GetD() const noexcept
    {
      return -Constant;
    }

    template <class U> static constexpr Plane3<T> From(const Plane3<U>& plane) noexcept
    {
      return Plane3<T>({T(plane.Normal.x), T(plane.Normal.y), T(plane.Normal.z)}, T(plane.Constant));
    }
  };

  using Plane3f = Plane3<float>;
  using Plane3i = Plane3<int>; // storage-only; geometric ops expect floating-point

  static_assert(sizeof(Plane3f) == 0x10, "Plane3f size must be 0x10");
} // namespace Wm3
