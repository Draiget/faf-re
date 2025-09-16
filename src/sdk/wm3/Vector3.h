#pragma once
#include <complex>

namespace Wm3
{
    /**
     * Minimal 3D vector
     */
    template <class T>
    struct Vec3
	{
        T x{}, y{}, z{};

        /**
         * Dot product.
         */
        static constexpr T Dot(const Vec3& a, const Vec3& b) noexcept {
            return a.x * b.x + a.y * b.y + a.z * b.z;
        }

        /**
         * Cross product.
         */
        static constexpr Vec3 Cross(const Vec3& a, const Vec3& b) noexcept {
            return { a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x };
        }

        /**
         * Length squared.
         */
        static constexpr T LengthSq(const Vec3& v) noexcept { return Dot(v, v); }

        /**
         * Length.
         */
        static T Length(const Vec3& v) noexcept { return std::sqrt(LengthSq(v)); }

        /**
         * Normalize in-place; returns previous length.
         */
        static T Normalize(Vec3& v, T eps = T(1e-6)) noexcept {
            T len = Length(v);
            if (len > eps) {
                T inv = T(1) / len;
                v.x *= inv; v.y *= inv; v.z *= inv;
            }
            return len;
        }

        /**
         * Abs component-wise.
         */
        static constexpr Vec3 Abs(const Vec3& v) noexcept {
            using std::abs;
            return { T(abs(v.x)), T(abs(v.y)), T(abs(v.z)) };
        }

        /**
         * Normalize (copy).
         */
        static Vec3 Normalized(const Vec3& v, T eps = T(1e-6)) noexcept {
            T len = Length(v);
            if (len <= eps) return { T(0), T(0), T(0) };
            T inv = T(1) / len;
            return { v.x * inv, v.y * inv, v.z * inv };
        }

        /**
         * Nearly equals.
         */
        static bool NearlyEquals(const Vec3& a, const Vec3& b, T eps = T(1e-5)) noexcept {
            return std::fabs(a.x - b.x) <= eps && std::fabs(a.y - b.y) <= eps && std::fabs(a.z - b.z) <= eps;
        }

        /** Operators */

        constexpr Vec3 operator+(const Vec3& r) const noexcept { return { x + r.x, y + r.y, z + r.z }; }
        constexpr Vec3 operator-(const Vec3& r) const noexcept { return { x - r.x, y - r.y, z - r.z }; }
        constexpr Vec3 operator*(T s) const noexcept { return { x * s, y * s, z * s }; }
        friend constexpr Vec3 operator*(T s, const Vec3& v) noexcept { return { v.x * s, v.y * s, v.z * s }; }
    };
    
    using Vec3i = Vec3<int>;
    using Vec3f = Vec3<float>;
}
