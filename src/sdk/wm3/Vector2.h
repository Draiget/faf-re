#pragma once

#include <cmath>
#include <type_traits>

namespace Wm3
{
  template <class T> struct Vector2;

  /**
   * Address: 0x006999F0 (FUN_006999F0, Wm3::Vector2f::Normalize)
   *
   * Wm3::Vector2<float>*
   *
   * IDA signature:
   * double __thiscall Wm3::Vector2f::Normalize(Wm3::Vector2f *this);
   *
   * What it does:
   * Normalizes vector in place with 1e-6 epsilon and returns pre-normalize length.
   */
  float NormalizeVector2fInPlace(Vector2<float>* value) noexcept;

  template <class T> struct Vector2
  {
    T x{};
    T y{};

    constexpr Vector2() = default;
    constexpr Vector2(const T xValue, const T yValue) noexcept :
        x(xValue),
        y(yValue)
    {}

    static constexpr Vector2 Add(const Vector2& a, const Vector2& b) noexcept
    {
      return {a.x + b.x, a.y + b.y};
    }

    static constexpr Vector2 Sub(const Vector2& a, const Vector2& b) noexcept
    {
      return {a.x - b.x, a.y - b.y};
    }

    static constexpr Vector2 Scale(const Vector2& v, const T scale) noexcept
    {
      return {v.x * scale, v.y * scale};
    }

    static constexpr Vector2 Zero() noexcept
    {
      return {T(0), T(0)};
    }

    static constexpr T Dot(const Vector2& a, const Vector2& b) noexcept
    {
      return a.x * b.x + a.y * b.y;
    }

    static constexpr T Cross(const Vector2& a, const Vector2& b) noexcept
    {
      return a.x * b.y - a.y * b.x;
    }

    static constexpr T LengthSq(const Vector2& v) noexcept
    {
      return Dot(v, v);
    }

    static T Length(const Vector2& v) noexcept
    {
      using std::sqrt;
      return sqrt(LengthSq(v));
    }

    static T Normalize(Vector2& v, const T eps = T(1e-6)) noexcept
    {
      if constexpr (std::is_same_v<T, float>) {
        if (eps == T(1e-6)) {
          return NormalizeVector2fInPlace(reinterpret_cast<Vector2<float>*>(&v));
        }
      }

      const T len = Length(v);
      if (len > eps) {
        const T inv = T(1) / len;
        v.x *= inv;
        v.y *= inv;
      } else {
        v.x = T(0);
        v.y = T(0);
      }
      return len;
    }

    static T Normalize(Vector2* const v, const T eps = T(1e-6)) noexcept
    {
      if (!v) {
        return T(0);
      }

      if constexpr (std::is_same_v<T, float>) {
        if (eps == T(1e-6)) {
          return NormalizeVector2fInPlace(reinterpret_cast<Vector2<float>*>(v));
        }
      }

      return Normalize(*v, eps);
    }

    static Vector2 NormalizeOrZero(const Vector2& v, const T minLenSq = T(1e-8)) noexcept
    {
      if (LengthSq(v) <= minLenSq) {
        return Zero();
      }

      Vector2 out = v;
      Normalize(out);
      return out;
    }

    T Normalize(const T eps = T(1e-6)) noexcept
    {
      return Vector2::Normalize(*this, eps);
    }

    static constexpr Vector2 Abs(const Vector2& v) noexcept
    {
      using std::abs;
      return {static_cast<T>(abs(v.x)), static_cast<T>(abs(v.y))};
    }

    static Vector2 Normalized(const Vector2& v, const T eps = T(1e-6)) noexcept
    {
      Vector2 out = v;
      Normalize(out, eps);
      return out;
    }

    static bool NearlyEquals(const Vector2& a, const Vector2& b, const T eps = T(1e-5)) noexcept
    {
      if constexpr (std::is_floating_point_v<T>) {
        using std::fabs;
        return fabs(a.x - b.x) <= eps && fabs(a.y - b.y) <= eps;
      }
      return a.x == b.x && a.y == b.y;
    }

    static bool IsntNaN(const Vector2* const v) noexcept
    {
      if (!v) {
        return false;
      }

      if constexpr (std::is_floating_point_v<T>) {
        using std::isnan;
        return !isnan(v->x) && !isnan(v->y);
      }
      return true;
    }

    static bool IsntNaN(const Vector2& v) noexcept
    {
      return IsntNaN(&v);
    }

    static bool IsInvalid(const Vector2& v) noexcept
    {
      return !IsntNaN(v);
    }

    bool IsntNaN() const noexcept
    {
      return Vector2::IsntNaN(this);
    }

    constexpr Vector2 operator+(const Vector2& rhs) const noexcept
    {
      return Add(*this, rhs);
    }
    constexpr Vector2 operator-(const Vector2& rhs) const noexcept
    {
      return Sub(*this, rhs);
    }
    constexpr Vector2 operator*(const T scale) const noexcept
    {
      return Scale(*this, scale);
    }
    constexpr Vector2 operator/(const T scale) const noexcept
    {
      return {x / scale, y / scale};
    }
    friend constexpr Vector2 operator*(const T scale, const Vector2& v) noexcept
    {
      return v * scale;
    }

    constexpr Vector2& operator+=(const Vector2& rhs) noexcept
    {
      return *this = *this + rhs;
    }
    constexpr Vector2& operator-=(const Vector2& rhs) noexcept
    {
      return *this = *this - rhs;
    }
    constexpr Vector2& operator*=(const T scale) noexcept
    {
      return *this = *this * scale;
    }
    constexpr Vector2& operator/=(const T scale) noexcept
    {
      return *this = *this / scale;
    }
  };

  template <class T> using Vec2 = Vector2<T>;

  template <class T> using IVector2 = Vector2<T>;

  using Vector2f = Vector2<float>;
  using Vector2i = Vector2<int>;

  using Vec2f = Vector2f;
  using Vec2i = Vector2i;

  static_assert(sizeof(Vector2f) == 0x08, "Vector2f size must be 0x08");
  static_assert(sizeof(Vector2i) == 0x08, "Vector2i size must be 0x08");
} // namespace Wm3
