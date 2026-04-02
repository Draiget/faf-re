#pragma once

#include "Vector3.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "Mat34.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace Wm3
{

  /**
   * Oriented box: Center, orthonormal Axis[3], half-sizes (Extent)
   * Layout strictly matches FA binary blob:
   *   center[3], axis[3][3], extent[3]  => total 15 scalars
   */
  template <class T> struct Box3
  {
    T Center[3];  // 0..2
    T Axis[3][3]; // 3..11
    T Extent[3];  // 12..14

    /** Returns pointer to the first scalar (useful for interop with raw float* blobs) */
    constexpr const T* Data() const noexcept
    {
      return &Center[0];
    }
    constexpr T* Data() noexcept
    {
      return &Center[0];
    }

    /** Default: zero center, identity axes, zero extent */
    constexpr Box3() noexcept :
        Center{T(0), T(0), T(0)},
        Axis{
          {T(1), T(0), T(0)},
          {T(0), T(1), T(0)},
          {T(0), T(0), T(1)},
        },
        Extent{T(0), T(0), T(0)}
    {}

    /** Construct from center, 3 axes (assumed orthonormal), and extents */
    constexpr Box3(
      const Vector3<T>& c,
      const Vector3<T>& axis0,
      const Vector3<T>& axis1,
      const Vector3<T>& axis2,
      const Vector3<T>& ex
    ) noexcept
    {
      Center[0] = c.x;
      Center[1] = c.y;
      Center[2] = c.z;

      Axis[0][0] = axis0.x;
      Axis[0][1] = axis0.y;
      Axis[0][2] = axis0.z;
      Axis[1][0] = axis1.x;
      Axis[1][1] = axis1.y;
      Axis[1][2] = axis1.z;
      Axis[2][0] = axis2.x;
      Axis[2][1] = axis2.y;
      Axis[2][2] = axis2.z;

      Extent[0] = ex.x;
      Extent[1] = ex.y;
      Extent[2] = ex.z;
    }

    /**
     * Address: 0x00474170 (FUN_00474170, Wm3::Box3f::Box3f)
     *
     * What it does:
     * Builds a box from center, three orthonormal axes, and scalar extents.
     */
    constexpr Box3(
      const Vector3<T>& c,
      const Vector3<T>& axis0,
      const Vector3<T>& axis1,
      const Vector3<T>& axis2,
      const T extentX,
      const T extentY,
      const T extentZ
    ) noexcept
      : Box3(c, axis0, axis1, axis2, Vector3<T>{extentX, extentY, extentZ})
    {}

    /** Factory from Mat34: axes in columns (m[0..2], m[4..6], m[8..10]), translation in m[3],m[7],m[11] */
    static constexpr Box3 FromMat34(const Mat34<T>& t, const Vector3<T>& ex) noexcept
    {
      Box3 b;
      b.Center[0] = t.m[3];
      b.Center[1] = t.m[7];
      b.Center[2] = t.m[11];

      b.Axis[0][0] = t.m[0];
      b.Axis[0][1] = t.m[1];
      b.Axis[0][2] = t.m[2];
      b.Axis[1][0] = t.m[4];
      b.Axis[1][1] = t.m[5];
      b.Axis[1][2] = t.m[6];
      b.Axis[2][0] = t.m[8];
      b.Axis[2][1] = t.m[9];
      b.Axis[2][2] = t.m[10];

      b.Extent[0] = ex.x;
      b.Extent[1] = ex.y;
      b.Extent[2] = ex.z;
      return b;
    }

    /** Convert to Mat34 (only rotation+translation; extents are not embedded) */
    constexpr Mat34<T> ToMat34() const noexcept
    {
      Mat34<T> t;
      t.m[0] = Axis[0][0];
      t.m[1] = Axis[0][1];
      t.m[2] = Axis[0][2];
      t.m[3] = Center[0];
      t.m[4] = Axis[1][0];
      t.m[5] = Axis[1][1];
      t.m[6] = Axis[1][2];
      t.m[7] = Center[1];
      t.m[8] = Axis[2][0];
      t.m[9] = Axis[2][1];
      t.m[10] = Axis[2][2];
      t.m[11] = Center[2];
      return t;
    }

    /** Enforce orthonormal basis using Gram-Schmidt; keeps axis[0] direction, re-orthogonalizes others */
    void Orthonormalize(T eps = T(1e-6)) noexcept
    {
      Vector3<T> a0{Axis[0][0], Axis[0][1], Axis[0][2]};
      Vector3<T> a1{Axis[1][0], Axis[1][1], Axis[1][2]};
      Vector3<T> a2{Axis[2][0], Axis[2][1], Axis[2][2]};

      // Normalize a0
      if (Vector3<T>::Normalize(a0, eps) <= eps) {
        a0 = {T(1), T(0), T(0)};
      }

      // Make a1 orthogonal to a0 and normalize
      a1 = a1 - a0 * Vector3<T>::Dot(a1, a0);
      if (Vector3<T>::Normalize(a1, eps) <= eps) {
        // Pick any orthonormal vector if degenerate
        a1 = Vector3<T>::Cross(a0, {T(0), T(0), T(1)});
        if (Vector3<T>::LengthSq(a1) <= eps) {
          a1 = Vector3<T>::Cross(a0, {T(0), T(1), T(0)});
        }
        Vector3<T>::Normalize(a1, eps);
      }

      // a2 = a0 x a1 to ensure right-handed basis
      a2 = Vector3<T>::Cross(a0, a1);
      if (Vector3<T>::Normalize(a2, eps) <= eps) {
        // Fallback orthogonal vector
        a2 = Vector3<T>::Cross(a0, a1);
        Vector3<T>::Normalize(a2, eps);
      }

      Axis[0][0] = a0.x;
      Axis[0][1] = a0.y;
      Axis[0][2] = a0.z;
      Axis[1][0] = a1.x;
      Axis[1][1] = a1.y;
      Axis[1][2] = a1.z;
      Axis[2][0] = a2.x;
      Axis[2][1] = a2.y;
      Axis[2][2] = a2.z;
    }

    /** Check axes are orthonormal within tolerance */
    bool IsOrthonormal(T tol = T(1e-4)) const noexcept
    {
      const Vector3<T> a0{Axis[0][0], Axis[0][1], Axis[0][2]};
      const Vector3<T> a1{Axis[1][0], Axis[1][1], Axis[1][2]};
      const Vector3<T> a2{Axis[2][0], Axis[2][1], Axis[2][2]};

      const auto dot01 = std::abs(Vector3<T>::Dot(a0, a1));
      const auto dot02 = std::abs(Vector3<T>::Dot(a0, a2));
      const auto dot12 = std::abs(Vector3<T>::Dot(a1, a2));
      const auto l0 = std::abs(Vector3<T>::Length(a0) - T(1));
      const auto l1 = std::abs(Vector3<T>::Length(a1) - T(1));
      const auto l2 = std::abs(Vector3<T>::Length(a2) - T(1));

      return dot01 <= tol && dot02 <= tol && dot12 <= tol && l0 <= tol && l1 <= tol && l2 <= tol;
    }

    /** Get 8 corners in world space (Center +- Axis*Extent) */
    void GetCorners(Vector3<T> out[8]) const noexcept
    {
      const Vector3<T> center{Center[0], Center[1], Center[2]};
      const Vector3<T> axis0{Axis[0][0], Axis[0][1], Axis[0][2]};
      const Vector3<T> axis1{Axis[1][0], Axis[1][1], Axis[1][2]};
      const Vector3<T> axis2{Axis[2][0], Axis[2][1], Axis[2][2]};
      const Vector3<T> extent{Extent[0], Extent[1], Extent[2]};
      const Vector3<T> e0 = axis0 * extent.x;
      const Vector3<T> e1 = axis1 * extent.y;
      const Vector3<T> e2 = axis2 * extent.z;

      // 8 combinations
      out[0] = center - e0 - e1 - e2;
      out[1] = center + e0 - e1 - e2;
      out[2] = center - e0 + e1 - e2;
      out[3] = center + e0 + e1 - e2;
      out[4] = center - e0 - e1 + e2;
      out[5] = center + e0 - e1 + e2;
      out[6] = center - e0 + e1 + e2;
      out[7] = center + e0 + e1 + e2;
    }

    /** Point containment test (matches FA routine semantics) */
    bool ContainsPoint(const Vector3<T>& point) const noexcept
    {
      const T dx = point.x - Center[0];
      const T dy = point.y - Center[1];
      const T dz = point.z - Center[2];
      const T* axisPtr = &Axis[0][0];

      for (int i = 0; i < 3; ++i) {
        const T dp = axisPtr[0] * dx + axisPtr[1] * dy + axisPtr[2] * dz;
        if (std::abs(dp) > Extent[i]) {
          return false;
        }
        axisPtr += 3;
      }
      return true;
    }

    /** Ray vs OBB (ray origin/dir in world space). Returns hit 't' if any (t >= 0) */
    bool IntersectRay(
      const Vector3<T>& rayOrigin, const Vector3<T>& rayDirection, T& tHit, T eps = T(1e-6)
    ) const noexcept
    {
      // Transform ray into box coordinates
      const Vector3<T> center{Center[0], Center[1], Center[2]};
      const Vector3<T> axis0{Axis[0][0], Axis[0][1], Axis[0][2]};
      const Vector3<T> axis1{Axis[1][0], Axis[1][1], Axis[1][2]};
      const Vector3<T> axis2{Axis[2][0], Axis[2][1], Axis[2][2]};
      const Vector3<T> o = rayOrigin - center;

      // Coordinates in box frame
      const T o0 = Vector3<T>::Dot(o, axis0);
      const T o1 = Vector3<T>::Dot(o, axis1);
      const T o2 = Vector3<T>::Dot(o, axis2);
      const T d0 = Vector3<T>::Dot(rayDirection, axis0);
      const T d1 = Vector3<T>::Dot(rayDirection, axis1);
      const T d2 = Vector3<T>::Dot(rayDirection, axis2);

      T tmin = -std::numeric_limits<T>::infinity();
      T tmax = std::numeric_limits<T>::infinity();
      const T ex[3] = {Extent[0], Extent[1], Extent[2]};
      const T oarr[3] = {o0, o1, o2};
      const T darr[3] = {d0, d1, d2};

      for (int i = 0; i < 3; ++i) {
        if (std::abs(darr[i]) < eps) {
          if (oarr[i] < -ex[i] || oarr[i] > ex[i]) {
            return false;
          }
        } else {
          const T invDir = T(1) / darr[i];
          T t1 = (-ex[i] - oarr[i]) * invDir;
          T t2 = (ex[i] - oarr[i]) * invDir;
          if (t1 > t2) {
            std::swap(t1, t2);
          }
          if (t1 > tmin) {
            tmin = t1;
          }
          if (t2 < tmax) {
            tmax = t2;
          }
          if (tmin > tmax) {
            return false;
          }
        }
      }
      tHit = (tmin >= T(0)) ? tmin : tmax;
      return tHit >= T(0);
    }

    /** Conservative AABB cover in world space (used in broad-phase) */
    void ComputeAABB(Vector3<T>& outMin, Vector3<T>& outMax) const noexcept
    {
      const Vector3<T> center{Center[0], Center[1], Center[2]};
      const Vector3<T> ax0{Axis[0][0], Axis[0][1], Axis[0][2]};
      const Vector3<T> ax1{Axis[1][0], Axis[1][1], Axis[1][2]};
      const Vector3<T> ax2{Axis[2][0], Axis[2][1], Axis[2][2]};
      const Vector3<T> extent{Extent[0], Extent[1], Extent[2]};
      const Vector3<T> r{
        std::abs(ax0.x) * extent.x + std::abs(ax1.x) * extent.y + std::abs(ax2.x) * extent.z,
        std::abs(ax0.y) * extent.x + std::abs(ax1.y) * extent.y + std::abs(ax2.y) * extent.z,
        std::abs(ax0.z) * extent.x + std::abs(ax1.z) * extent.y + std::abs(ax2.z) * extent.z
      };
      outMin = {center.x - r.x, center.y - r.y, center.z - r.z};
      outMax = {center.x + r.x, center.y + r.y, center.z + r.z};
    }

    /** Inflate extents by positive delta (component-wise) */
    void Inflate(const Vector3<T>& delta) noexcept
    {
      Extent[0] = std::max<T>(T(0), Extent[0] + delta.x);
      Extent[1] = std::max<T>(T(0), Extent[1] + delta.y);
      Extent[2] = std::max<T>(T(0), Extent[2] + delta.z);
    }

    /** Build from axis-aligned AABB (center = (min+max)/2, extents = (max-min)/2; axes = identity) */
    static constexpr Box3 FromAABB(const Vector3<T>& mn, const Vector3<T>& mx) noexcept
    {
      Box3 b;
      b.Center[0] = (mn.x + mx.x) * T(0.5);
      b.Center[1] = (mn.y + mx.y) * T(0.5);
      b.Center[2] = (mn.z + mx.z) * T(0.5);

      b.Axis[0][0] = T(1);
      b.Axis[0][1] = T(0);
      b.Axis[0][2] = T(0);
      b.Axis[1][0] = T(0);
      b.Axis[1][1] = T(1);
      b.Axis[1][2] = T(0);
      b.Axis[2][0] = T(0);
      b.Axis[2][1] = T(0);
      b.Axis[2][2] = T(1);

      b.Extent[0] = (mx.x - mn.x) * T(0.5);
      b.Extent[1] = (mx.y - mn.y) * T(0.5);
      b.Extent[2] = (mx.z - mn.z) * T(0.5);
      return b;
    }

    /**
     * Address: 0x00475800 (FUN_00475800, Wm3::Box3f::MemberDeserialize)
     *
     * What it does:
     * Reads reflected center/axes/extents from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00475910 (FUN_00475910, Wm3::Box3f::MemberSerialize)
     *
     * What it does:
     * Writes reflected center/axes/extents to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  using Box3f = Box3<float>;

  static_assert(sizeof(Box3f) == 0x3C, "Box3f size must be 0x3C");
} // namespace Wm3
