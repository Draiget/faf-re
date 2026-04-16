#include "Vector4f.h"

#include <complex>

#include "gpg/core/containers/String.h"

namespace moho
{
  /**
   * Address: 0x004ECED0 (FUN_004ECED0, Moho::ToString)
   *
   * What it does:
   * Formats one `Vector4f` lane set as `x=%f,y=%f,z=%f,w=%f`.
   */
  msvc8::string ToString(const Vector4f& value)
  {
    return gpg::STR_Printf("x=%f,y=%f,z=%f,w=%f", value.x, value.y, value.z, value.w);
  }

  /**
   * Address: 0x0046FAB0 (FUN_0046FAB0, Moho::Vector4f::Vector4f)
   *
   * float,float,float,float
   *
   * What it does:
   * Initializes all four scalar lanes in-order.
   */
  Vector4f::Vector4f(const float xValue, const float yValue, const float zValue, const float wValue) noexcept
    : x(xValue), y(yValue), z(zValue), w(wValue)
  {
  }

  /**
   * Address: 0x0046FAE0 (FUN_0046FAE0, Moho::Vector4f::operator[])
   *
   * What it does:
   * Returns one scalar lane by unchecked index.
   */
  float Vector4f::operator[](const std::uint32_t index) const noexcept
  {
    return (&x)[index];
  }

  /**
   * Address: 0x0046FAF0 (FUN_0046FAF0, Moho::Vector4f::X)
   *
   * What it does:
   * Returns x lane.
   */
  float Vector4f::X() const noexcept
  {
    return x;
  }

  /**
   * Address: 0x0046FB00 (FUN_0046FB00, Moho::Vector4f::Y)
   *
   * What it does:
   * Returns y lane.
   */
  float Vector4f::Y() const noexcept
  {
    return y;
  }

  /**
   * Address: 0x0046FB10 (FUN_0046FB10, Moho::Vector4f::Z)
   *
   * What it does:
   * Returns z lane.
   */
  float Vector4f::Z() const noexcept
  {
    return z;
  }

  /**
   * Address: 0x0046FB20 (FUN_0046FB20, Moho::Vector4f::operator=)
   *
   * What it does:
   * Copies all four scalar lanes from rhs.
   */
  Vector4f& Vector4f::operator=(const Vector4f& rhs) noexcept
  {
    x = rhs.x;
    y = rhs.y;
    z = rhs.z;
    w = rhs.w;
    return *this;
  }

  /**
   * Address: 0x0046FB40 (FUN_0046FB40, Moho::Vector4f::operator*=)
   *
   * What it does:
   * Multiplies all scalar lanes by one uniform scalar.
   */
  Vector4f& Vector4f::operator*=(const float scalar) noexcept
  {
    x *= scalar;
    y *= scalar;
    z *= scalar;
    w *= scalar;
    return *this;
  }

  Angle Vector4f::quaternion_to_euler() const
  {
    // Assumes unit quaternion; if not, consider normalizing beforehand.
    const float qx = x, qy = y, qz = z, qw = w;

    // roll (X-axis rotation)
    const float sinr_cosp = 2.0f * (qw * qx + qy * qz);
    const float cosr_cosp = 1.0f - 2.0f * (qx * qx + qy * qy);
    const float roll = std::atan2(sinr_cosp, cosr_cosp);

    // pitch (Y-axis rotation)
    const float sinp = 2.0f * (qw * qy - qz * qx);
    float pitch;
    if (std::fabs(sinp) >= 1.0f) {
      // use 90 degrees if out of range
      pitch = std::copysign(3.14159265358979323846f / 2.0f, sinp);
    } else {
      pitch = std::asin(sinp);
    }

    // yaw (Z-axis rotation)
    const float siny_cosp = 2.0f * (qw * qz + qx * qy);
    const float cosy_cosp = 1.0f - 2.0f * (qy * qy + qz * qz);
    const float yaw = std::atan2(siny_cosp, cosy_cosp);

    return {roll, pitch, yaw};
  }
} // namespace moho
