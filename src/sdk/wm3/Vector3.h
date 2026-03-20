#pragma once

#include <cmath>
#include <type_traits>

namespace Wm3
{
  template <class T> struct Quaternion;

  template <class T> struct Vector3;

  /**
   * Address: 0x00452FC0 (FUN_00452FC0)
   *
   * float
   *
   * IDA signature:
   * float __cdecl sqrtf(float val);
   *
   * What it does:
   * Thin sqrtf wrapper used by math helpers in the original binary.
   */
  float SqrtfBinary(float value) noexcept;

  /**
   * Address: 0x00452AF0 (FUN_00452AF0, Wm3::Vector3f::Normalize)
   *
   * Wm3::Vector3<float>*
   *
   * IDA signature:
   * long double __thiscall func_NormalizeVecInPlace(Wm3::Vector3f *vec);
   *
   * What it does:
   * Normalizes vector in place with 1e-6 epsilon and returns pre-normalize length.
   */
  float NormalizeVector3fInPlace(Vector3<float>* value) noexcept;

  /**
   * Address: 0x0044F7E0 (FUN_0044F7E0, Wm3::Vector3::Normalize)
   *
   * Wm3::Vector3<float> const&, Wm3::Vector3<float>*
   *
   * IDA signature:
   * Wm3::Vector3f *__usercall func_NormalizeVecInto@<eax>(Wm3::Vector3f *vec@<edi>, Wm3::Vector3f *dest@<esi>);
   *
   * What it does:
   * Normalizes source vector into destination and writes zero vector for non-positive length.
   */
  Vector3<float>* NormalizeVector3fInto(const Vector3<float>& source, Vector3<float>* dest) noexcept;

  /**
   * Address: 0x005657F0 (FUN_005657F0, Wm3::Vector3f::IsntNaN)
   *
   * Wm3::Vector3<float> const*
   *
   * IDA signature:
   * BOOL __usercall Wm3::Vector3f::IsntNaN@<eax>(Wm3::Vector3f *a1@<esi>);
   *
   * What it does:
   * Returns true when all vector components are not NaN.
   */
  bool Vector3fIsntNaN(const Vector3<float>* value) noexcept;

  /**
   * Address: 0x00A3CF80 (FUN_00A3CF80, Wm3::Vector3f::GenerateOrthonormalBasis)
   *
   * Wm3::Vector3<float>*, Wm3::Vector3<float>*, Wm3::Vector3<float>*, bool
   *
   * IDA signature:
   * Wm3::Vector3f *__usercall Wm3::Vector3f::GenerateOrthonormalBasis@<eax>(double a1@<st0>, Wm3::Vector3f *a2,
   * Wm3::Vector3f *a3, Wm3::Vector3f *a4, bool a5);
   *
   * What it does:
   * Builds orthonormal basis vectors (u,v,w), optionally normalizing w first.
   */
  Vector3<float>* GenerateOrthonormalBasisVector3f(
    Vector3<float>* uOut, Vector3<float>* vOut, Vector3<float>* wInOut, bool unitLengthW
  ) noexcept;

  /**
   * Address: 0x00452D40 (FUN_00452D40, func_MultQuadVec)
   *
   * Wm3::Vector3<float>*, Wm3::Vector3<float> const&, Wm3::Quaternion<float> const&
   *
   * IDA signature:
   * Wm3::Vector3f *__usercall func_MultQuadVec@<eax>(Wm3::Vector3f *dest@<ebx>, Wm3::Vector3f *vec@<esi>,
   * Wm3::Quaternionf *quat@<ecx>);
   *
   * What it does:
   * Rotates `vec` by `quat` via quaternion-to-matrix conversion and writes into `dest`.
   */
  Vector3<float>* MultiplyQuaternionVector(
    Vector3<float>* dest, const Vector3<float>& vec, const Quaternion<float>& quat
  ) noexcept;

  template <class T> struct Vector3
  {
    T x{};
    T y{};
    T z{};

    constexpr Vector3() = default;
    constexpr Vector3(const T xValue, const T yValue, const T zValue) noexcept :
        x(xValue),
        y(yValue),
        z(zValue)
    {}

    static constexpr Vector3 Add(const Vector3& a, const Vector3& b) noexcept
    {
      return {a.x + b.x, a.y + b.y, a.z + b.z};
    }

    static constexpr Vector3 Sub(const Vector3& a, const Vector3& b) noexcept
    {
      return {a.x - b.x, a.y - b.y, a.z - b.z};
    }

    static constexpr Vector3 Scale(const Vector3& v, const T scale) noexcept
    {
      return {v.x * scale, v.y * scale, v.z * scale};
    }

    static constexpr T Dot(const Vector3& a, const Vector3& b) noexcept
    {
      return a.x * b.x + a.y * b.y + a.z * b.z;
    }

    static constexpr Vector3 Cross(const Vector3& a, const Vector3& b) noexcept
    {
      return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
    }

    static constexpr T LengthSq(const Vector3& v) noexcept
    {
      return Dot(v, v);
    }

    static T Length(const Vector3& v) noexcept
    {
      using std::sqrt;
      return sqrt(LengthSq(v));
    }

    static T Normalize(Vector3& v, const T eps = T(1e-6)) noexcept
    {
      if constexpr (std::is_same_v<T, float>) {
        if (eps == T(1e-6)) {
          return NormalizeVector3fInPlace(reinterpret_cast<Vector3<float>*>(&v));
        }
      }

      const T len = Length(v);
      if (len > eps) {
        const T inv = T(1) / len;
        v.x *= inv;
        v.y *= inv;
        v.z *= inv;
      } else {
        v.x = T(0);
        v.y = T(0);
        v.z = T(0);
      }
      return len;
    }

    static T Normalize(Vector3* const v, const T eps = T(1e-6)) noexcept
    {
      if (!v) {
        return T(0);
      }

      if constexpr (std::is_same_v<T, float>) {
        if (eps == T(1e-6)) {
          return NormalizeVector3fInPlace(reinterpret_cast<Vector3<float>*>(v));
        }
      }

      return Normalize(*v, eps);
    }

    static Vector3* NormalizeInto(const Vector3& source, Vector3* const dest) noexcept
    {
      if (!dest) {
        return nullptr;
      }

      if constexpr (std::is_same_v<T, float>) {
        return reinterpret_cast<Vector3*>(NormalizeVector3fInto(
          reinterpret_cast<const Vector3<float>&>(source), reinterpret_cast<Vector3<float>*>(dest)
        ));
      }

      const T len = Length(source);
      if (len > T(0)) {
        const T inv = T(1) / len;
        dest->x = source.x * inv;
        dest->y = source.y * inv;
        dest->z = source.z * inv;
      } else {
        dest->x = T(0);
        dest->y = T(0);
        dest->z = T(0);
      }
      return dest;
    }

    static Vector3* GenerateOrthonormalBasis(
      Vector3* const uOut, Vector3* const vOut, Vector3* const wInOut, const bool unitLengthW = false
    ) noexcept
    {
      if (!uOut || !vOut || !wInOut) {
        return nullptr;
      }

      if constexpr (std::is_same_v<T, float>) {
        return reinterpret_cast<Vector3*>(GenerateOrthonormalBasisVector3f(
          reinterpret_cast<Vector3<float>*>(uOut),
          reinterpret_cast<Vector3<float>*>(vOut),
          reinterpret_cast<Vector3<float>*>(wInOut),
          unitLengthW
        ));
      }

      static_assert(std::is_floating_point_v<T>, "GenerateOrthonormalBasis requires floating-point scalar type");

      if (!unitLengthW) {
        Normalize(*wInOut);
      }

      using std::abs;
      using std::sqrt;
      if (abs(wInOut->y) > abs(wInOut->x)) {
        const T invLength = T(1) / sqrt(wInOut->y * wInOut->y + wInOut->z * wInOut->z);
        uOut->x = T(0);
        uOut->y = wInOut->z * invLength;
        uOut->z = -wInOut->y * invLength;
        vOut->x = uOut->z * wInOut->y - wInOut->z * uOut->y;
        vOut->y = -wInOut->x * uOut->z;
        vOut->z = uOut->y * wInOut->x;
      } else {
        const T invLength = T(1) / sqrt(wInOut->x * wInOut->x + wInOut->z * wInOut->z);
        uOut->x = -wInOut->z * invLength;
        uOut->y = T(0);
        uOut->z = wInOut->x * invLength;
        vOut->x = uOut->z * wInOut->y;
        vOut->y = wInOut->z * uOut->x - uOut->z * wInOut->x;
        vOut->z = -wInOut->y * uOut->x;
      }
      return uOut;
    }

    T Normalize(const T eps = T(1e-6)) noexcept
    {
      return Vector3::Normalize(*this, eps);
    }

    static constexpr Vector3 Abs(const Vector3& v) noexcept
    {
      using std::abs;
      return {static_cast<T>(abs(v.x)), static_cast<T>(abs(v.y)), static_cast<T>(abs(v.z))};
    }

    static Vector3 Normalized(const Vector3& v, const T eps = T(1e-6)) noexcept
    {
      Vector3 out = v;
      Normalize(out, eps);
      return out;
    }

    static bool NearlyEquals(const Vector3& a, const Vector3& b, const T eps = T(1e-5)) noexcept
    {
      if constexpr (std::is_floating_point_v<T>) {
        using std::fabs;
        return fabs(a.x - b.x) <= eps && fabs(a.y - b.y) <= eps && fabs(a.z - b.z) <= eps;
      }
      return a.x == b.x && a.y == b.y && a.z == b.z;
    }

    static bool IsntNaN(const Vector3* const value) noexcept
    {
      if (!value) {
        return false;
      }

      if constexpr (std::is_same_v<T, float>) {
        return Vector3fIsntNaN(reinterpret_cast<const Vector3<float>*>(value));
      }

      if constexpr (std::is_floating_point_v<T>) {
        using std::isnan;
        return !isnan(value->x) && !isnan(value->y) && !isnan(value->z);
      }
      return true;
    }

    static bool IsntNaN(const Vector3& value) noexcept
    {
      return IsntNaN(&value);
    }

    bool IsntNaN() const noexcept
    {
      return Vector3::IsntNaN(this);
    }

    constexpr Vector3 operator+(const Vector3& rhs) const noexcept
    {
      return Add(*this, rhs);
    }
    constexpr Vector3 operator-(const Vector3& rhs) const noexcept
    {
      return Sub(*this, rhs);
    }
    constexpr Vector3 operator*(const T scale) const noexcept
    {
      return Scale(*this, scale);
    }
    constexpr Vector3 operator/(const T scale) const noexcept
    {
      return {x / scale, y / scale, z / scale};
    }
    friend constexpr Vector3 operator*(const T scale, const Vector3& v) noexcept
    {
      return v * scale;
    }

    constexpr Vector3& operator+=(const Vector3& rhs) noexcept
    {
      return *this = *this + rhs;
    }
    constexpr Vector3& operator-=(const Vector3& rhs) noexcept
    {
      return *this = *this - rhs;
    }
    constexpr Vector3& operator*=(const T scale) noexcept
    {
      return *this = *this * scale;
    }
    constexpr Vector3& operator/=(const T scale) noexcept
    {
      return *this = *this / scale;
    }
  };

  template <class T> using Vec3 = Vector3<T>;

  template <class T> using IVector3 = Vector3<T>;

  using Vector3f = Vector3<float>;
  using Vector3i = Vector3<int>;

  using Vec3f = Vector3f;
  using Vec3i = Vector3i;

  static_assert(sizeof(Vector3f) == 0x0C, "Vector3f size must be 0x0C");
  static_assert(sizeof(Vector3i) == 0x0C, "Vector3i size must be 0x0C");
} // namespace Wm3
