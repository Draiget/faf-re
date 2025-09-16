#pragma once
#include "Vector3.h"

#include <array>
#include <cmath>
#include <algorithm>
#include <cfloat>
#include <type_traits>

#include "Mat34.h"

namespace Wm3
{

    /**
     * Oriented box: Center, orthonormal Axis[3], half-sizes (Extent)
     * Layout strictly matches FA binary blob:
     *   center[3], axis[3][3], extent[3]  => total 15 scalars
     */
    template <class T>
    struct Box3 {
        T center[3];     // 0..2
        T axis[3][3];    // 3..11  (each axis is a column/row-style basis vector; see From/ToMat34)
        T extent[3];     // 12..14 (half-sizes along corresponding axes)

        /** Returns pointer to the first scalar (useful for interop with raw float* blobs) */
        constexpr const T* Data() const noexcept { return &center[0]; }
        constexpr T* Data() noexcept { return &center[0]; }

        /** Default: zero center, identity axes, zero extent */
        constexpr Box3() noexcept
            : center{ T(0),T(0),T(0) }, axis{ {{T(1),T(0),T(0)}, {T(0),T(1),T(0)}, {T(0),T(0),T(1)}} }, extent{ T(0),T(0),T(0) } {
        }

        /** Construct from center, 3 axes (assumed orthonormal), and extents */
        constexpr Box3(const Vec3<T>& c, const Vec3<T>& ax0, const Vec3<T>& ax1, const Vec3<T>& ax2, const Vec3<T>& ex) noexcept {
            center[0] = c.x; center[1] = c.y; center[2] = c.z;
            axis[0][0] = ax0.x; axis[0][1] = ax0.y; axis[0][2] = ax0.z;
            axis[1][0] = ax1.x; axis[1][1] = ax1.y; axis[1][2] = ax1.z;
            axis[2][0] = ax2.x; axis[2][1] = ax2.y; axis[2][2] = ax2.z;
            extent[0] = ex.x; extent[1] = ex.y; extent[2] = ex.z;
        }

        /** Factory from Mat34: axes in columns (m[0..2], m[4..6], m[8..10]), translation in m[3],m[7],m[11] */
        static constexpr Box3 FromMat34(const Mat34<T>& t, const Vec3<T>& ex) noexcept {
            Box3 b;
            b.center[0] = t.m[3];  b.center[1] = t.m[7];  b.center[2] = t.m[11];
            b.axis[0][0] = t.m[0]; b.axis[0][1] = t.m[1]; b.axis[0][2] = t.m[2];
            b.axis[1][0] = t.m[4]; b.axis[1][1] = t.m[5]; b.axis[1][2] = t.m[6];
            b.axis[2][0] = t.m[8]; b.axis[2][1] = t.m[9]; b.axis[2][2] = t.m[10];
            b.extent[0] = ex.x; b.extent[1] = ex.y; b.extent[2] = ex.z;
            return b;
        }

        /** Convert to Mat34 (only rotation+translation; extents are not embedded) */
        constexpr Mat34<T> ToMat34() const noexcept {
            Mat34<T> t;
            t.m = {
                axis[0][0], axis[0][1], axis[0][2], center[0],
                axis[1][0], axis[1][1], axis[1][2], center[1],
                axis[2][0], axis[2][1], axis[2][2], center[2]
            };
            return t;
        }

        /** Enforce orthonormal basis using Gram-Schmidt; keeps axis[0] direction, re-orthogonalizes others */
        void Orthonormalize(T eps = T(1e-6)) noexcept {
            Vec3<T> a0{ axis[0][0], axis[0][1], axis[0][2] };
            Vec3<T> a1{ axis[1][0], axis[1][1], axis[1][2] };
            Vec3<T> a2{ axis[2][0], axis[2][1], axis[2][2] };

            // Normalize a0
            if (Vec3<T>::Normalize(a0, eps) <= eps) a0 = { T(1),T(0),T(0) };

            // Make a1 orthogonal to a0 and normalize
            a1 = a1 - a0 * Vec3<T>::Dot(a1, a0);
            if (Vec3<T>::Normalize(a1, eps) <= eps) {
                // Pick any orthonormal vector if degenerate
                a1 = Vec3<T>::Cross(a0, { T(0),T(0),T(1) });
                if (Vec3<T>::LengthSq(a1) <= eps) a1 = Vec3<T>::Cross(a0, { T(0),T(1),T(0) });
                Vec3<T>::Normalize(a1, eps);
            }

            // a2 = a0 x a1 to ensure right-handed basis
            a2 = Vec3<T>::Cross(a0, a1);
            if (Vec3<T>::Normalize(a2, eps) <= eps) {
                // Fallback orthogonal vector
                a2 = Vec3<T>::Cross(a0, a1);
                Vec3<T>::Normalize(a2, eps);
            }

            axis[0][0] = a0.x; axis[0][1] = a0.y; axis[0][2] = a0.z;
            axis[1][0] = a1.x; axis[1][1] = a1.y; axis[1][2] = a1.z;
            axis[2][0] = a2.x; axis[2][1] = a2.y; axis[2][2] = a2.z;
        }

        /** Check axes are orthonormal within tolerance */
        bool IsOrthonormal(T tol = T(1e-4)) const noexcept {
            Vec3<T> a0{ axis[0][0], axis[0][1], axis[0][2] };
            Vec3<T> a1{ axis[1][0], axis[1][1], axis[1][2] };
            Vec3<T> a2{ axis[2][0], axis[2][1], axis[2][2] };
            auto dot01 = std::abs(Vec3<T>::Dot(a0, a1));
            auto dot02 = std::abs(Vec3<T>::Dot(a0, a2));
            auto dot12 = std::abs(Vec3<T>::Dot(a1, a2));
            auto l0 = std::abs(Vec3<T>::Length(a0) - T(1));
            auto l1 = std::abs(Vec3<T>::Length(a1) - T(1));
            auto l2 = std::abs(Vec3<T>::Length(a2) - T(1));
            return dot01 <= tol && dot02 <= tol && dot12 <= tol && l0 <= tol && l1 <= tol && l2 <= tol;
        }

        /** Get 8 corners in world space (Center +- Axis*Extent) */
        void GetCorners(Vec3<T> out[8]) const noexcept {
            Vec3<T> C{ center[0], center[1], center[2] };
            Vec3<T> A0{ axis[0][0], axis[0][1], axis[0][2] };
            Vec3<T> A1{ axis[1][0], axis[1][1], axis[1][2] };
            Vec3<T> A2{ axis[2][0], axis[2][1], axis[2][2] };
            Vec3<T> E{ extent[0], extent[1], extent[2] };
            Vec3<T> e0 = A0 * E.x;
            Vec3<T> e1 = A1 * E.y;
            Vec3<T> e2 = A2 * E.z;
            // 8 combinations
            out[0] = C - e0 - e1 - e2;
            out[1] = C + e0 - e1 - e2;
            out[2] = C - e0 + e1 - e2;
            out[3] = C + e0 + e1 - e2;
            out[4] = C - e0 - e1 + e2;
            out[5] = C + e0 - e1 + e2;
            out[6] = C - e0 + e1 + e2;
            out[7] = C + e0 + e1 + e2;
        }

        /** Point containment test (matches FA routine semantics) */
        bool ContainsPoint(const Vec3<T>& p) const noexcept {
            T dx = p.x - center[0];
            T dy = p.y - center[1];
            T dz = p.z - center[2];
            const T* a = &axis[0][0];
            for (int i = 0; i < 3; ++i) {
                T dp = a[0] * dx + a[1] * dy + a[2] * dz;
                if (std::abs(dp) > extent[i]) return false;
                a += 3;
            }
            return true;
        }

        /** Ray vs OBB (ray origin/dir in world space). Returns hit 't' if any (t >= 0) */
        bool IntersectRay(const Vec3<T>& ro, const Vec3<T>& rd, T& tHit, T eps = T(1e-6)) const noexcept {
            // Transform ray into box coordinates
            Vec3<T> C{ center[0], center[1], center[2] };
            Vec3<T> A0{ axis[0][0], axis[0][1], axis[0][2] };
            Vec3<T> A1{ axis[1][0], axis[1][1], axis[1][2] };
            Vec3<T> A2{ axis[2][0], axis[2][1], axis[2][2] };
            Vec3<T> o = ro - C;
            // Coordinates in box frame
            T o0 = Vec3<T>::Dot(o, A0), o1 = Vec3<T>::Dot(o, A1), o2 = Vec3<T>::Dot(o, A2);
            T d0 = Vec3<T>::Dot(rd, A0), d1 = Vec3<T>::Dot(rd, A1), d2 = Vec3<T>::Dot(rd, A2);

            T tmin = -std::numeric_limits<T>::infinity();
            T tmax = std::numeric_limits<T>::infinity();
            const T ex[3] = { extent[0], extent[1], extent[2] };
            const T oarr[3] = { o0, o1, o2 };
            const T darr[3] = { d0, d1, d2 };

            for (int i = 0;i < 3;i++) {
                if (std::abs(darr[i]) < eps) {
                    if (oarr[i] < -ex[i] || oarr[i] > ex[i]) return false;
                } else {
                    T ood = T(1) / darr[i];
                    T t1 = (-ex[i] - oarr[i]) * ood;
                    T t2 = (ex[i] - oarr[i]) * ood;
                    if (t1 > t2) std::swap(t1, t2);
                    if (t1 > tmin) tmin = t1;
                    if (t2 < tmax) tmax = t2;
                    if (tmin > tmax) return false;
                }
            }
            tHit = (tmin >= T(0)) ? tmin : tmax;
            return tHit >= T(0);
        }

        /** Conservative AABB cover in world space (used in broad-phase) */
        void ComputeAABB(Vec3<T>& outMin, Vec3<T>& outMax) const noexcept {
            Vec3<T> C{ center[0], center[1], center[2] };
            Vec3<T> ax0{ axis[0][0], axis[0][1], axis[0][2] };
            Vec3<T> ax1{ axis[1][0], axis[1][1], axis[1][2] };
            Vec3<T> ax2{ axis[2][0], axis[2][1], axis[2][2] };
            Vec3<T> E{ extent[0], extent[1], extent[2] };
            Vec3<T> r{
                std::abs(ax0.x) * E.x + std::abs(ax1.x) * E.y + std::abs(ax2.x) * E.z,
                std::abs(ax0.y) * E.x + std::abs(ax1.y) * E.y + std::abs(ax2.y) * E.z,
                std::abs(ax0.z) * E.x + std::abs(ax1.z) * E.y + std::abs(ax2.z) * E.z
            };
            outMin = { C.x - r.x, C.y - r.y, C.z - r.z };
            outMax = { C.x + r.x, C.y + r.y, C.z + r.z };
        }

        /** Inflate extents by positive delta (component-wise) */
        void Inflate(const Vec3<T>& delta) noexcept {
            extent[0] = std::max<T>(T(0), extent[0] + delta.x);
            extent[1] = std::max<T>(T(0), extent[1] + delta.y);
            extent[2] = std::max<T>(T(0), extent[2] + delta.z);
        }

        /** Build from axis-aligned AABB (center = (min+max)/2, extents = (max-min)/2; axes = identity) */
        static constexpr Box3 FromAABB(const Vec3<T>& mn, const Vec3<T>& mx) noexcept {
            Box3 b;
            b.center[0] = (mn.x + mx.x) * T(0.5);
            b.center[1] = (mn.y + mx.y) * T(0.5);
            b.center[2] = (mn.z + mx.z) * T(0.5);
            b.axis[0][0] = T(1); b.axis[0][1] = T(0); b.axis[0][2] = T(0);
            b.axis[1][0] = T(0); b.axis[1][1] = T(1); b.axis[1][2] = T(0);
            b.axis[2][0] = T(0); b.axis[2][1] = T(0); b.axis[2][2] = T(1);
            b.extent[0] = (mx.x - mn.x) * T(0.5);
            b.extent[1] = (mx.y - mn.y) * T(0.5);
            b.extent[2] = (mx.z - mn.z) * T(0.5);
            return b;
        }
    };
}
