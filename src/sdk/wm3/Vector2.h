#pragma once
#include <cmath>

namespace Wm3
{
    /**
     * Minimal 2D vector
     */
    template <class T>
    struct Vec2 {
        T x{}, y{};

        /** Dot product */
        static constexpr T Dot(const Vec2& a, const Vec2& b) noexcept {
            return a.x * b.x + a.y * b.y;
        }

        /**
         * 2D cross product (z-component as scalar).
         * Returns a.x*b.y - a.y*b.x
         */
        static constexpr T Cross(const Vec2& a, const Vec2& b) noexcept {
            return a.x * b.y - a.y * b.x;
        }

        /** Length squared */
        static constexpr T LengthSq(const Vec2& v) noexcept { return Dot(v, v); }

        /** Length */
        static T Length(const Vec2& v) noexcept { return std::sqrt(LengthSq(v)); }

        /** Normalize in-place; returns previous length */
        static T Normalize(Vec2& v, T eps = T(1e-6)) noexcept {
            T len = Length(v);
            if (len > eps) {
                T inv = T(1) / len;
                v.x *= inv; v.y *= inv;
            }
            return len;
        }

        /** Abs component-wise */
        static constexpr Vec2 Abs(const Vec2& v) noexcept {
            using std::abs;
            return { T(abs(v.x)), T(abs(v.y)) };
        }

        /** Operators */
        constexpr Vec2 operator+(const Vec2& r) const noexcept { return { x + r.x, y + r.y }; }
        constexpr Vec2 operator-(const Vec2& r) const noexcept { return { x - r.x, y - r.y }; }
        constexpr Vec2 operator*(T s) const noexcept { return { x * s, y * s }; }
        friend constexpr Vec2 operator*(T s, const Vec2& v) noexcept { return { v.x * s, v.y * s }; }
    };

    using Vec2i = Wm3::Vec2<int>;
    using Vec2f = Wm3::Vec2<float>;
}
