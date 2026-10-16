#pragma once

namespace moho
{
  /**
   * Address: 0x00FB78FC (initialized by FUN_00BEDC30: `atan(1.0) * 4.0`
   * stored to a float)
   *
   * Pi rounded to float, 0x40490FDB.
   */
  inline constexpr float kPi = 3.14159274f;

  /**
   * Address: 0x00FB7914 (initialized by FUN_00BEDC60: `kPi * 0.5`)
   *
   * Half pi rounded to float, 0x3FC90FDB -- one ulp above the literal
   * `1.5707963f` (0x3FC90FDA), which is not the value the image computes.
   */
  inline constexpr float kHalfPi = 1.57079637f;

  /**
   * Simple triple of Euler angles in radians (XYZ: roll around X, pitch around Y, yaw around Z).
   */
  struct Angle
  {
    float roll{};  // X
    float pitch{}; // Y
    float yaw{};   // Z
  };
} // namespace moho