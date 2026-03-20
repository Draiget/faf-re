#pragma once

namespace Wm3
{
  /**
   * Row-major 3x4 matrix (3 rows, 4 columns) used as a rigid/local transform.
   *
   * Layout:
   * m[0..2]   = basis row 0
   * m[3]      = translation x
   * m[4..6]   = basis row 1
   * m[7]      = translation y
   * m[8..10]  = basis row 2
   * m[11]     = translation z
   */
  template <class T> struct Mat34
  {
    T m[12]{};

    constexpr Mat34() = default;

    static constexpr Mat34 Identity() noexcept
    {
      Mat34 out{};
      out.m[0] = T(1);
      out.m[5] = T(1);
      out.m[10] = T(1);
      return out;
    }
  };

  using Mat34f = Mat34<float>;

  static_assert(sizeof(Mat34f) == 0x30, "Mat34f size must be 0x30");
} // namespace Wm3
