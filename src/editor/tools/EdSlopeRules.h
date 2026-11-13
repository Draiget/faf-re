// The sim's terrain rules behind the slope view, engine independent so they can be tested on their own
// (tests/editor/SlopeRulesTests.cpp). Ported from FAF Studio's EdOverlaySlope.h (its tile cache left out: the view
// rates the whole map when the heights or the rule change), with the ring rule's pivot taken from the retail binary.
//
//   kind 0 "path": a mobile footprint of `n` x `n` cells (OCCUPY_MobileCheck 0x00564AB0, src/moho/sim/STIMap.cpp): the
//          largest height difference between neighbouring samples inside the window (x in [cx, cx + n], z in [cz, cz +
//          n]), in height words (128 per world unit), against the footprint's MaxSlope.
//   kind 1 "area": a structure without a flattened skirt (OCCUPY_CheckAreaFlatness 0x005651F0): highest minus lowest
//          sample over the same window, against the blueprint's Physics.MaxGroundVariation.
//   kind 2 "ring": a structure with Physics.FlattenSkirt (OCCUPY_CheckEdgeFlatness 0x00564F80, nearly every building):
//          only the 1-cell ring around the skirt rect (x0 = cx .. x1 = cx + n, z likewise) is read: the rows z0 - 1 and
//          z1 + 1 over x0 - 1 .. x1 + 1, then the columns x0 - 1 and x1 + 1 over z0 .. z1. The pivot is ceil(lowest
//          ring sample): 0x00565173 spills the running minimum (xmm3) to [esp+0x24], 0x00565179 loads it for the ceil
//          at 0x00565183 (FAF Studio's header took the last sample read instead). The rating is max(highest - pivot,
//          pivot - lowest), exact in words (a word is 2^-7 units), against MaxGroundVariation (blueprint +0x28c).
//
// Heights are given by a callback `int h(int x, int z)` (the height word of a sample; outside the field, the edge
// sample).
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

namespace faf::editor::sloperules
{
  constexpr int kTile = 64;  // cells per tile side
  constexpr int kLevels = 7; // block sizes 1, 2, 4 ... 64 cells
  constexpr int kMaxWindow = 16;
  constexpr int kWordsPerUnit = 128; // height words per world unit (CHeightField: elevation = word / 128)

  constexpr int kKindPath = 0;
  constexpr int kKindBuild = 1; // OCCUPY_CheckAreaFlatness
  constexpr int kKindRing = 2;  // OCCUPY_CheckEdgeFlatness

  /** The kind a Lua name stands for ("build" area rule, "ring" edge rule); anything else (including "path") is the
   * mobile rule, as before kind 2 existed. */
  [[nodiscard]] inline int KindFromName(
    const char* const name
  )
  {
    if (name != nullptr) {
      if (std::strcmp(name, "build") == 0) {
        return kKindBuild;
      }
      if (std::strcmp(name, "ring") == 0) {
        return kKindRing;
      }
    }
    return kKindPath;
  }

  /** ceil(word / 128) * 128: the engine's ceil() of an elevation, in words (exact: a word is a multiple of 2^-7 world
   * units). */
  [[nodiscard]] constexpr int CeilToUnit(
    const int word
  )
  {
    const int q = word >= 0 ? (word + kWordsPerUnit - 1) / kWordsPerUnit : -((-word) / kWordsPerUnit);
    return q * kWordsPerUnit;
  }

  /** The ring rule's deviation (words) from the extremes over the ring: the pivot is ceil(lowest), as the binary does.
   */
  [[nodiscard]] constexpr int RingDeviation(
    const int lo,
    const int hi
  )
  {
    const int pivot = CeilToUnit(lo);
    return std::max(hi - pivot, pivot - lo);
  }

  /** The rating of one cell computed straight from the rule (slow; the reference for the tests and the readout under
   * the pointer). */
  template <class Sampler>
  [[nodiscard]] inline int CellRating(
    const int kind,
    const int n,
    const int cx,
    const int cz,
    Sampler&& h
  )
  {
    if (kind == 0) {
      int maxDelta = 0;
      for (int z = cz; z <= cz + n; ++z) {
        for (int x = cx; x < cx + n; ++x) {
          maxDelta = std::max(maxDelta, std::abs(h(x + 1, z) - h(x, z)));
        }
      }
      for (int x = cx; x <= cx + n; ++x) {
        for (int z = cz; z < cz + n; ++z) {
          maxDelta = std::max(maxDelta, std::abs(h(x, z + 1) - h(x, z)));
        }
      }
      return maxDelta;
    }
    if (kind == kKindRing) {
      // a transliteration of OCCUPY_CheckEdgeFlatness: the rows above and below (walking x), then the columns left and
      // right (walking z)
      int lo = 1 << 30;
      int hi = -(1 << 30);
      for (int x = cx - 1; x <= cx + n + 1; ++x) {
        const int top = h(x, cz - 1);
        const int bottom = h(x, cz + n + 1);
        lo = std::min(lo, std::min(top, bottom));
        hi = std::max(hi, std::max(top, bottom));
      }
      for (int z = cz; z <= cz + n; ++z) {
        const int left = h(cx - 1, z);
        const int right = h(cx + n + 1, z);
        lo = std::min(lo, std::min(left, right));
        hi = std::max(hi, std::max(left, right));
      }
      return RingDeviation(lo, hi);
    }
    int lo = 1 << 30;
    int hi = -(1 << 30);
    for (int z = cz; z <= cz + n; ++z) {
      for (int x = cx; x <= cx + n; ++x) {
        const int v = h(x, z);
        lo = std::min(lo, v);
        hi = std::max(hi, v);
      }
    }
    return hi - lo;
  }

  /**
   * Sliding window extreme in O(count) (van Herk / Gil-Werman): out[i * outStride] = max (or min) of in[(i .. i + w -
   * 1) * inStride] for the first `outCount` (at most count - w + 1) positions i. `scratch` is two arrays of `count`
   * ints.
   */
  template <bool Max>
  inline void SlidingExtreme(
    const int* const in,
    const int inStride,
    const int count,
    const int w,
    int* const out,
    const int outStride,
    int* const scratch,
    const int outCount
  )
  {
    if (w < 1 || count < w) {
      return;
    }
    const int produced = std::min(outCount, count - w + 1);
    const auto pick = [](const int a, const int b) {
      return Max ? std::max(a, b) : std::min(a, b);
    };
    if (w == 1) {
      for (int i = 0; i < produced; ++i) {
        out[i * outStride] = in[i * inStride];
      }
      return;
    }
    int* const g = scratch;          // running extreme from the start of the block
    int* const hh = scratch + count; // running extreme back from the end of the block
    for (int i = 0; i < count; ++i) {
      const int v = in[i * inStride];
      g[i] = (i % w == 0) ? v : pick(g[i - 1], v);
    }
    for (int i = count - 1; i >= 0; --i) {
      const int v = in[i * inStride];
      hh[i] = (i == count - 1 || (i + 1) % w == 0) ? v : pick(hh[i + 1], v);
    }
    for (int i = 0; i < produced; ++i) {
      out[i * outStride] = pick(hh[i], g[i + w - 1]);
    }
  }

  /**
   * Kind 2 (ring) for the kTile x kTile cells whose first cell is (cx0, cz0). Needs the samples [cx0 - 1, cx0 + kTile +
   * n + 1] x [cz0 - 1, cz0 + kTile + n + 1]. Tile-local sample (u, v) = (x - (cx0 - 1), z - (cz0 - 1)); the cell (i, j)
   * looks at: the rows v = j and v = j + n + 2 over u in [i, i + n + 2], the columns u = i and u = i + n + 2 over v in
   * [j + 1, j + n + 1]; the pivot is ceil of their lowest. The four extremes come from sliding windows along the rows
   * (n + 3 wide) and along the columns (n + 1 wide), so the cost per cell does not grow with the skirt.
   */
  template <class Sampler>
  inline void RateRingTile(
    const int n,
    const int cx0,
    const int cz0,
    Sampler&& h,
    std::uint16_t* const out
  )
  {
    const int sw = kTile + n + 2;
    const std::size_t ssw = static_cast<std::size_t>(sw);
    std::vector<int> H(ssw * ssw);
    for (int v = 0; v < sw; ++v) {
      for (int u = 0; u < sw; ++u) {
        H[static_cast<std::size_t>(v) * ssw + u] = h(cx0 - 1 + u, cz0 - 1 + v);
      }
    }
    std::vector<int> scratch(ssw * 2);
    std::vector<int> rowHi(ssw * ssw), rowLo(ssw * ssw), colHi(ssw * ssw), colLo(ssw * ssw);
    for (int v = 0; v < sw; ++v) {
      SlidingExtreme<true>(
        &H[static_cast<std::size_t>(v) * ssw],
        1,
        sw,
        n + 3,
        &rowHi[static_cast<std::size_t>(v) * ssw],
        1,
        scratch.data(),
        kTile
      );
      SlidingExtreme<false>(
        &H[static_cast<std::size_t>(v) * ssw],
        1,
        sw,
        n + 3,
        &rowLo[static_cast<std::size_t>(v) * ssw],
        1,
        scratch.data(),
        kTile
      );
    }
    for (int u = 0; u < sw; ++u) {
      SlidingExtreme<true>(&H[u], sw, sw, n + 1, &colHi[u], sw, scratch.data(), kTile + 1);
      SlidingExtreme<false>(&H[u], sw, sw, n + 1, &colLo[u], sw, scratch.data(), kTile + 1);
    }
    for (int j = 0; j < kTile; ++j) {
      for (int i = 0; i < kTile; ++i) {
        const std::size_t top = static_cast<std::size_t>(j) * ssw + i;
        const std::size_t bottom = static_cast<std::size_t>(j + n + 2) * ssw + i;
        const std::size_t left = static_cast<std::size_t>(j + 1) * ssw + i;
        const std::size_t right = left + static_cast<std::size_t>(n + 2);
        const int hi = std::max(std::max(rowHi[top], rowHi[bottom]), std::max(colHi[left], colHi[right]));
        const int lo = std::min(std::min(rowLo[top], rowLo[bottom]), std::min(colLo[left], colLo[right]));
        const int dev = RingDeviation(lo, hi);
        out[static_cast<std::size_t>(j) * kTile + i] = static_cast<std::uint16_t>(std::min(65535, std::max(0, dev)));
      }
    }
  }

  /**
   * The ratings of the kTile x kTile cells whose first cell is (cx0, cz0), written to `out` (row major, x fastest),
   * with the separable sliding window passes: cost ~ cells * a few operations whatever the window. Needs the samples
   * [cx0, cx0 + kTile + n] x [cz0, cz0 + kTile + n] (kind 2: one more on every side).
   */
  template <class Sampler>
  inline void RateTile(
    const int kind,
    const int n,
    const int cx0,
    const int cz0,
    Sampler&& h,
    std::uint16_t* const out
  )
  {
    if (kind == kKindRing) {
      RateRingTile(n, cx0, cz0, h, out);
      return;
    }
    const int sw = kTile + n + 1;
    std::vector<int> H(static_cast<std::size_t>(sw) * sw);
    for (int j = 0; j < sw; ++j) {
      for (int i = 0; i < sw; ++i) {
        H[static_cast<std::size_t>(j) * sw + i] = h(cx0 + i, cz0 + j);
      }
    }
    std::vector<int> scratch(static_cast<std::size_t>(sw) * 2);
    std::vector<int> t1(static_cast<std::size_t>(sw) * sw), t2(static_cast<std::size_t>(sw) * sw);
    std::vector<int> r1(static_cast<std::size_t>(kTile) * kTile), r2(static_cast<std::size_t>(kTile) * kTile);
    const auto clampWord = [](const int v) {
      return static_cast<std::uint16_t>(std::min(65535, std::max(0, v)));
    };
    if (kind == 0) {
      // A[z][i] = max over x in [i, i + n - 1] of |h(x + 1, z) - h(x, z)|, then max over z in [j, j + n] (window n + 1)
      for (int z = 0; z < sw; ++z) {
        for (int x = 0; x + 1 < sw; ++x) {
          t1[static_cast<std::size_t>(z) * sw + x] =
            std::abs(H[static_cast<std::size_t>(z) * sw + x + 1] - H[static_cast<std::size_t>(z) * sw + x]);
        }
        SlidingExtreme<true>(
          &t1[static_cast<std::size_t>(z) * sw],
          1,
          sw - 1,
          n,
          &t2[static_cast<std::size_t>(z) * sw],
          1,
          scratch.data(),
          kTile
        );
      }
      for (int i = 0; i < kTile; ++i) {
        SlidingExtreme<true>(&t2[i], sw, sw, n + 1, &r1[i], kTile, scratch.data(), kTile);
      }
      // B[j][x] = max over z in [j, j + n - 1] of |h(x, z + 1) - h(x, z)|, then max over x in [i, i + n]
      for (int z = 0; z + 1 < sw; ++z) {
        for (int x = 0; x < sw; ++x) {
          t1[static_cast<std::size_t>(z) * sw + x] =
            std::abs(H[static_cast<std::size_t>(z + 1) * sw + x] - H[static_cast<std::size_t>(z) * sw + x]);
        }
      }
      for (int x = 0; x < sw; ++x) {
        SlidingExtreme<true>(&t1[x], sw, sw - 1, n, &t2[x], sw, scratch.data(), kTile);
      }
      for (int j = 0; j < kTile; ++j) {
        SlidingExtreme<true>(
          &t2[static_cast<std::size_t>(j) * sw],
          1,
          sw,
          n + 1,
          &r2[static_cast<std::size_t>(j) * kTile],
          1,
          scratch.data(),
          kTile
        );
      }
      for (std::size_t k = 0; k < r1.size(); ++k) {
        out[k] = clampWord(std::max(r1[k], r2[k]));
      }
    } else {
      // hi / lo over x in [i, i + n] per row, then over z in [j, j + n]
      std::vector<int> lo2(static_cast<std::size_t>(sw) * sw);
      for (int z = 0; z < sw; ++z) {
        SlidingExtreme<true>(
          &H[static_cast<std::size_t>(z) * sw],
          1,
          sw,
          n + 1,
          &t2[static_cast<std::size_t>(z) * sw],
          1,
          scratch.data(),
          kTile
        );
        SlidingExtreme<false>(
          &H[static_cast<std::size_t>(z) * sw],
          1,
          sw,
          n + 1,
          &lo2[static_cast<std::size_t>(z) * sw],
          1,
          scratch.data(),
          kTile
        );
      }
      for (int i = 0; i < kTile; ++i) {
        SlidingExtreme<true>(&t2[i], sw, sw, n + 1, &r1[i], kTile, scratch.data(), kTile);
        SlidingExtreme<false>(&lo2[i], sw, sw, n + 1, &r2[i], kTile, scratch.data(), kTile);
      }
      for (std::size_t k = 0; k < r1.size(); ++k) {
        out[k] = clampWord(r1[k] - r2[k]);
      }
    }
  }

  /**
   * Colour step of a rating `value` against `limit` (both in the same unit): 0 = flat (not drawn), 1 .. kSteps = green
   * to red up to the limit, kSteps + 1 = beyond the limit. Neighbouring blocks with the same step get the same colour,
   * so a run of them is drawn as one quad.
   */
  constexpr int kSteps = 24;
  [[nodiscard]] inline int ColorStep(
    const float value,
    const float limit
  )
  {
    const float t = value / limit;
    if (t > 1.0f) {
      return kSteps + 1;
    }
    const int step = static_cast<int>(t * static_cast<float>(kSteps));
    return std::min(kSteps, std::max(0, step));
  }
} // namespace faf::editor::sloperules
