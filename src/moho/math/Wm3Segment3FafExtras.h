#pragma once
// FA's two-endpoint segment builder. Wild Magic 3.8's `Segment3` has only the
// (origin, direction, extent) constructor, and the vendored tree under
// `dependencies/WildMagic3p8` is not ours to extend, so FA's one extra
// construction path lives here as a free function.
//
// Everything else FA calls in Wild Magic (`DistVector3Box3f`,
// `DistVector3Segment3f`, `IntrSegment3Box3f`, `IntrSegment3Sphere3f`,
// `IntrBox3Sphere3f`, `InBox`, ...) is the library's own body, linked from
// Foundation.lib: callers construct those classes directly, as the binary does.
#include "Wm3Segment3.h"
#include "Wm3Vector3.h"

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
   * Builds the segment from `start` to `end`: `Origin` is the midpoint,
   * `Extent` half the distance, `Direction` the unit `end - start` (zero when
   * the endpoints coincide). Shared by the collision primitives' line tests,
   * the projectile and unit-motion sweeps, the AI brain's terrain-blocking
   * check and the world view's path simplification.
   */
  [[nodiscard]] Segment3f MakeSegment3fFromEndpoints(const Vector3f& start, const Vector3f& end) noexcept;
} // namespace Wm3
