#include "Vector2.h"

#include "Vector3.h"

namespace Wm3
{
  /**
   * Address: 0x006999F0 (FUN_006999F0, Wm3::Vector2f::Normalize)
   *
   * Wm3::Vector2<float>*
   *
   * IDA signature:
   * double __thiscall Wm3::Vector2f::Normalize(Wm3::Vector2f *this);
   *
   * What it does:
   * Normalizes `value` in place with epsilon `1e-6`; returns pre-normalize length.
   */
  float NormalizeVector2fInPlace(Vector2<float>* const value) noexcept
  {
    if (!value) {
      return 0.0f;
    }

    const float length = SqrtfBinary(value->x * value->x + value->y * value->y);
    if (length <= 0.000001f) {
      value->x = 0.0f;
      value->y = 0.0f;
      return 0.0f;
    }

    const float invLength = 1.0f / length;
    value->x *= invLength;
    value->y *= invLength;
    return length;
  }
} // namespace Wm3
