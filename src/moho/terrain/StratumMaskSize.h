#pragma once

#include <algorithm>

// FAF addition: how big the dynamic sheet of a stratum mask is (docs/RENDERER_BACKENDS.md, "Stratum mask resolution"),
// one axis.
//
// `saved` is the size the map file stores the mask at, `half` half the map's size in cells (what the shipped code
// resampled every mask to) and `cells` the map's size in cells. The mask keeps what it was saved with, but
//   - never less than `half` (a coarser mask is raised to it, as before), and
//   - never more than two texels per world unit (`2 * cells`), but always up to 2048 whatever the map's size, and never
//   more than `ceiling`.
//     So 2048 is allowed on any map, 4096 only on a map of 2048 cells or more (40 km), and 8192 only on a 4096 map (81
//     km): the extra resolution is memory (an 8192 mask is 256 MB, two of them 512 MB) that a smaller map cannot use.
// A `ceiling` of 0 (console variable ren_StratumMaskMax) gives back the shipped behaviour: every mask is `half`.
namespace moho
{
  constexpr int kStratumMaskCeiling = 8192;
  constexpr int kStratumMaskAnyMap = 2048;

  /// ren_StratumMaskMax: the largest stratum mask side in texels (default kStratumMaskCeiling); 0 = half the map's
  /// size, as shipped. Read as a map's terrain finishes loading.
  extern int ren_StratumMaskMax;

  constexpr int StratumMaskExtent(
    const int saved,
    const int half,
    const int cells,
    const int ceiling = kStratumMaskCeiling
  ) noexcept
  {
    if (ceiling <= 0) {
      return half;
    }
    const int cap = std::min(std::max(kStratumMaskAnyMap, 2 * cells), ceiling);
    return std::max(half, std::min(saved, cap));
  }

  // The size rules, checked when this header is compiled.
  static_assert(StratumMaskExtent(2048, 1024, 2048) == 2048, "a 40 km map keeps a mask saved at one texel per unit");
  static_assert(StratumMaskExtent(4096, 2048, 4096) == 4096, "an 81 km map keeps a 4096 mask");
  static_assert(StratumMaskExtent(8192, 2048, 4096) == 8192, "and may use an 8K mask");
  static_assert(StratumMaskExtent(8192, 1024, 2048) == 4096, "a 40 km map gets no 8K mask");
  static_assert(StratumMaskExtent(8192, 512, 1024) == 2048, "a 20 km map neither");
  static_assert(StratumMaskExtent(8192, 256, 512) == 2048, "a 10 km map gets at most 2048");
  static_assert(StratumMaskExtent(4096, 256, 512) == 2048, "so a 4096 mask is cut to it");
  static_assert(StratumMaskExtent(2048, 256, 512) == 2048, "a 10 km map may use a 2048 mask");
  static_assert(StratumMaskExtent(128, 256, 512) == 256, "a coarse mask is raised to half the map's size");
  static_assert(StratumMaskExtent(256, 256, 512) == 256, "a mask saved at half the map's size stays");
  static_assert(StratumMaskExtent(16384, 8192, 16384) == 8192, "the ceiling holds on a huge map");
  static_assert(StratumMaskExtent(300, 256, 512) == 300, "an odd size between half and the cap is kept");
  static_assert(StratumMaskExtent(4096, 1024, 2048, 2048) == 2048, "ren_StratumMaskMax lowers the cap");
  static_assert(StratumMaskExtent(4096, 1024, 2048, 0) == 1024, "ren_StratumMaskMax 0 is the shipped size");
} // namespace moho
