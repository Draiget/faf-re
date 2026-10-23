#include "moho/math/Wm3Segment3FafExtras.h"

#include <cmath>

namespace Wm3
{
  /**
   * Address: 0x004FE130 (FUN_004FE130)
   *
   * IDA signature:
   * Wm3::Segment3f *__usercall Segment3::Segment3@<eax>(
   *     Wm3::Vector3f *end@<eax>, Wm3::Vector3f *start@<ecx>, Wm3::Segment3f *this@<esi>);
   *
   * What it does:
   * Halves `end - start` (0.5 at 0x00E4F724), takes its length as the extent
   * (sqrtf, 0x00452FC0, over y*y + z*z + x*x in that order), and normalizes
   * the half vector only when the extent is positive. The origin is
   * `start + half`, not `(start + end) / 2`.
   */
  Segment3f MakeSegment3fFromEndpoints(const Vector3f& start, const Vector3f& end) noexcept
  {
    const Vector3f half{(end.x - start.x) * 0.5f, (end.y - start.y) * 0.5f, (end.z - start.z) * 0.5f};
    const float extent = std::sqrt((half.y * half.y) + (half.z * half.z) + (half.x * half.x));

    Segment3f segment{};
    segment.Origin = Vector3f{start.x + half.x, start.y + half.y, start.z + half.z};
    if (extent > 0.0f) {
      const float inverseExtent = 1.0f / extent;
      segment.Direction = Vector3f{half.x * inverseExtent, half.y * inverseExtent, half.z * inverseExtent};
    } else {
      segment.Direction = Vector3f{0.0f, 0.0f, 0.0f};
    }
    segment.Extent = extent;
    return segment;
  }
} // namespace Wm3
