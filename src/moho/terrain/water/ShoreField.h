#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

// The distance to the shore (docs/WATER_SIMULATION.md): for every height sample of the map the distance in world units
// to the nearest land sample. The shore waves of the water simulation run in it. Pure functions on plain arrays (no
// engine types), so that the headless lab of the water simulation (tools/watersimlab) computes exactly what the game
// does.
namespace moho::water
{
  // Exact euclidean distance transform of one line (Felzenszwalb and Huttenlocher): d[q] = min over p of f[p] + (q -
  // p)^2.
  inline void ShoreDistanceLine(
    const std::vector<double>& f,
    std::vector<double>& d,
    std::vector<int>& v,
    std::vector<double>& z
  )
  {
    const int n = static_cast<int>(f.size());
    int k = 0;
    v[0] = 0;
    z[0] = -1e30;
    z[1] = 1e30;
    for (int q = 1; q < n; ++q) {
      double s = 0.0;
      for (;;) {
        const int p = v[k];
        s = ((f[q] + static_cast<double>(q) * q) - (f[p] + static_cast<double>(p) * p)) / (2.0 * q - 2.0 * p);
        if (s <= z[k] && k > 0) {
          --k;
        } else {
          break;
        }
      }
      if (s <= z[k]) {
        v[k] = q; // k == 0: the new parabola is lower everywhere the old one was
        continue;
      }
      ++k;
      v[k] = q;
      z[k] = s;
      z[k + 1] = 1e30;
    }
    k = 0;
    for (int q = 0; q < n; ++q) {
      while (z[k + 1] < q) {
        ++k;
      }
      const double dq = static_cast<double>(q - v[k]);
      d[q] = dq * dq + f[v[k]];
    }
  }

  // `rawAt(x, z)` is the raw height of a sample (any callable returning a number). Land is ground above `level` (raw
  // height units). The result is smoothed over thirteen samples in both directions (twice a box of 6.5 units: the
  // contours of a distance field have cusps where the shores of a bay or two islands meet, and crests that follow them
  // show V shapes) so that neither those nor the staircase of a one-unit coast show in the contours the waves follow;
  // 1e4 where the map has no land.
  template <class RawAt>
  std::vector<float> ComputeShoreDistance(
    RawAt&& rawAt,
    const std::uint32_t width,
    const std::uint32_t height,
    const float level,
    const float windAngle = 0.0f
  )
  {
    const double kInf = 1e12;
    std::vector<double> grid(static_cast<std::size_t>(width) * height);
    for (std::uint32_t z = 0; z < height; ++z) {
      for (std::uint32_t x = 0; x < width; ++x) {
        const float raw = static_cast<float>(rawAt(x, z));
        grid[static_cast<std::size_t>(z) * width + x] = raw > level ? 0.0 : kInf;
      }
    }
    const std::size_t longest = std::max(width, height);
    std::vector<double> f(longest), d(longest), z(longest + 1U);
    std::vector<int> v(longest);
    for (std::uint32_t x = 0; x < width; ++x) { // columns
      f.assign(height, 0.0);
      d.assign(height, 0.0);
      for (std::uint32_t j = 0; j < height; ++j) {
        f[j] = grid[static_cast<std::size_t>(j) * width + x];
      }
      ShoreDistanceLine(f, d, v, z);
      for (std::uint32_t j = 0; j < height; ++j) {
        grid[static_cast<std::size_t>(j) * width + x] = d[j];
      }
    }
    for (std::uint32_t j = 0; j < height; ++j) { // rows
      f.assign(width, 0.0);
      d.assign(width, 0.0);
      for (std::uint32_t x = 0; x < width; ++x) {
        f[x] = grid[static_cast<std::size_t>(j) * width + x];
      }
      ShoreDistanceLine(f, d, v, z);
      for (std::uint32_t x = 0; x < width; ++x) {
        grid[static_cast<std::size_t>(j) * width + x] = d[x];
      }
    }
    std::vector<float> dist(grid.size());
    for (std::size_t i = 0; i < grid.size(); ++i) {
      dist[i] = static_cast<float>(std::min(std::sqrt(grid[i]), 1e4));
    }
    std::vector<float> tmp(dist.size());
    constexpr int kRadius = 6;
    for (int pass = 0; pass < 4; ++pass) {
      for (std::uint32_t j = 0; j < height; ++j) {
        for (std::uint32_t x = 0; x < width; ++x) {
          float sum = 0.0f;
          for (int o = -kRadius; o <= kRadius; ++o) {
            const std::uint32_t xx = (pass & 1) == 0
              ? static_cast<std::uint32_t>(std::min(std::max(static_cast<int>(x) + o, 0), static_cast<int>(width) - 1))
              : x;
            const std::uint32_t jj = (pass & 1) == 1
              ? static_cast<std::uint32_t>(std::min(std::max(static_cast<int>(j) + o, 0), static_cast<int>(height) - 1))
              : j;
            sum += dist[static_cast<std::size_t>(jj) * width + xx];
          }
          tmp[static_cast<std::size_t>(j) * width + x] = sum / static_cast<float>(2 * kRadius + 1);
        }
      }
      dist.swap(tmp);
    }
    // The fetch of the wind: how far the water runs UPWIND of every sample before it meets land, up to 220 units. A sea
    // needs room to build along the wind: a lake has a short fetch, so has the lee of an island, a channel between an
    // island and the shore, the open sea a long one. Worked out on a grid of every fourth sample (a march against the
    // wind over the land mask, then a blur) and handed on as the second half of the result, the same layout as the
    // distance: dist[width * height + i]. `windAngle` is the heading the waves travel along (x = cos, z = sin).
    {
      constexpr int kStep = 4;
      constexpr float kMax = 220.0f;
      constexpr float kMarch = 2.0f;
      const int cw = (static_cast<int>(width) + kStep - 1) / kStep;
      const int ch = (static_cast<int>(height) + kStep - 1) / kStep;
      std::vector<std::uint8_t> land(static_cast<std::size_t>(width) * height, 0U);
      for (std::uint32_t z = 0; z < height; ++z) {
        for (std::uint32_t x = 0; x < width; ++x) {
          land[static_cast<std::size_t>(z) * width + x] = static_cast<float>(rawAt(x, z)) > level ? 1U : 0U;
        }
      }
      const float ux = -std::cos(windAngle);
      const float uz = -std::sin(windAngle);
      std::vector<float> coarse(static_cast<std::size_t>(cw) * ch, 0.0f);
      for (int j = 0; j < ch; ++j) {
        for (int i = 0; i < cw; ++i) {
          const float x0 = (static_cast<float>(i) + 0.5f) * kStep;
          const float z0 = (static_cast<float>(j) + 0.5f) * kStep;
          float fetch = kMax;
          for (float d = 0.0f; d <= kMax; d += kMarch) {
            const int px = static_cast<int>(x0 + ux * d);
            const int pz = static_cast<int>(z0 + uz * d);
            if (px < 0 || pz < 0 || px >= static_cast<int>(width) || pz >= static_cast<int>(height)) {
              break; // off the map: open water as far as the eye reaches
            }
            if (land[static_cast<std::size_t>(pz) * width + px] != 0U) {
              fetch = d;
              break;
            }
          }
          coarse[static_cast<std::size_t>(j) * cw + i] = fetch;
        }
      }
      std::vector<float> line(coarse.size());
      for (int pass = 0; pass < 4; ++pass) { // a blur of five cells, along x and z twice
        for (int j = 0; j < ch; ++j) {
          for (int x = 0; x < cw; ++x) {
            float sum = 0.0f;
            for (int o = -2; o <= 2; ++o) {
              const int xx = (pass & 1) == 0 ? std::min(std::max(x + o, 0), cw - 1) : x;
              const int jj = (pass & 1) == 1 ? std::min(std::max(j + o, 0), ch - 1) : j;
              sum += coarse[static_cast<std::size_t>(jj) * cw + xx];
            }
            line[static_cast<std::size_t>(j) * cw + x] = sum / 5.0f;
          }
        }
        coarse.swap(line);
      }
      const std::size_t samples = dist.size();
      dist.resize(samples * 2U);
      for (std::uint32_t j = 0; j < height; ++j) {
        for (std::uint32_t x = 0; x < width; ++x) {
          const float fx = std::max((static_cast<float>(x) + 0.5f) / kStep - 0.5f, 0.0f);
          const float fz = std::max((static_cast<float>(j) + 0.5f) / kStep - 0.5f, 0.0f);
          const int x0 = std::min(static_cast<int>(fx), cw - 1);
          const int z0 = std::min(static_cast<int>(fz), ch - 1);
          const int x1 = std::min(x0 + 1, cw - 1);
          const int z1 = std::min(z0 + 1, ch - 1);
          const float ax = fx - static_cast<float>(x0);
          const float az = fz - static_cast<float>(z0);
          const float top = coarse[static_cast<std::size_t>(z0) * cw + x0] * (1.0f - ax) +
            coarse[static_cast<std::size_t>(z0) * cw + x1] * ax;
          const float bottom = coarse[static_cast<std::size_t>(z1) * cw + x0] * (1.0f - ax) +
            coarse[static_cast<std::size_t>(z1) * cw + x1] * ax;
          dist[samples + static_cast<std::size_t>(j) * width + x] = top * (1.0f - az) + bottom * az;
        }
      }
    }
    return dist;
  }

  // The level a domain has when it holds no water (a dry body, or the sea of a map that has none): every sample of it
  // counts as land.
  constexpr float kDryLevelRaw = -1.0e30f;

  // The shore field of a map with water bodies (docs/WATER_SIMULATION.md, "Water bodies"): the same two fields, but
  // per water. `domainAt(x, z)` is the water (0 the sea, a body's number) that owns the height sample (x, z) and
  // `levelRaw[domain]` its level in raw height units (kDryLevelRaw for none). For a domain a sample is land when it is
  // higher than the level of that domain or belongs to another domain, so the distance and the fetch of a lake end at
  // its own shore and never run into the sea or another lake. Each wet domain is worked out on the box of its own
  // samples with a margin (a lake costs a small fraction of the map) and its samples are copied into the result: one
  // number per sample, the layout of ComputeShoreDistance. A map that has one domain only calls ComputeShoreDistance
  // itself, so the result is bit for bit the old one.
  template <class RawAt, class DomainAt>
  std::vector<float> ComputeShoreDistanceDomains(
    RawAt&& rawAt,
    DomainAt&& domainAt,
    const std::vector<float>& levelRaw,
    const std::uint32_t width,
    const std::uint32_t height,
    const float windAngle = 0.0f
  )
  {
    const std::size_t samples = static_cast<std::size_t>(width) * height;
    struct Box
    {
      int x0 = 1 << 30;
      int z0 = 1 << 30;
      int x1 = -1;
      int z1 = -1;
      std::size_t count = 0;
    };
    std::vector<Box> boxes(levelRaw.size());
    std::vector<std::uint8_t> owner(samples, 0U);
    for (std::uint32_t z = 0; z < height; ++z) {
      for (std::uint32_t x = 0; x < width; ++x) {
        const std::size_t d = std::min<std::size_t>(static_cast<std::size_t>(domainAt(x, z)), levelRaw.size() - 1U);
        owner[static_cast<std::size_t>(z) * width + x] = static_cast<std::uint8_t>(d);
        Box& box = boxes[d];
        box.x0 = std::min(box.x0, static_cast<int>(x));
        box.z0 = std::min(box.z0, static_cast<int>(z));
        box.x1 = std::max(box.x1, static_cast<int>(x));
        box.z1 = std::max(box.z1, static_cast<int>(z));
        ++box.count;
      }
    }
    std::size_t present = 0;
    std::size_t only = 0;
    for (std::size_t d = 0; d < boxes.size(); ++d) {
      if (boxes[d].count > 0) {
        ++present;
        only = d;
      }
    }
    if (present == 1) {
      if (levelRaw[only] <= kDryLevelRaw * 0.5f) {
        return std::vector<float>(samples * 2U, 0.0f);
      }
      return ComputeShoreDistance(rawAt, width, height, levelRaw[only], windAngle);
    }
    // The fetch is worked out on a grid of every fourth sample: the box starts on one of that grid so the result
    // does not depend on where the box is. 32 samples of margin hold the blurs (13 samples, 16 on the coarse grid).
    constexpr int kMargin = 32;
    std::vector<float> result(samples * 2U, 0.0f);
    for (std::size_t d = 0; d < boxes.size(); ++d) {
      const Box& box = boxes[d];
      if (box.count == 0 || levelRaw[d] <= kDryLevelRaw * 0.5f) {
        continue;
      }
      const int x0 = std::max(box.x0 - kMargin, 0) & ~3;
      const int z0 = std::max(box.z0 - kMargin, 0) & ~3;
      const int x1 = std::min(box.x1 + 1 + kMargin, static_cast<int>(width));
      const int z1 = std::min(box.z1 + 1 + kMargin, static_cast<int>(height));
      const std::uint32_t rw = static_cast<std::uint32_t>(x1 - x0);
      const std::uint32_t rh = static_cast<std::uint32_t>(z1 - z0);
      const std::vector<float> part = ComputeShoreDistance([&](const std::uint32_t x, const std::uint32_t z) {
        const std::uint32_t gx = static_cast<std::uint32_t>(x0) + x;
        const std::uint32_t gz = static_cast<std::uint32_t>(z0) + z;
        return owner[static_cast<std::size_t>(gz) * width + gx] == d ? static_cast<float>(rawAt(gx, gz)) : 1.0e9f;
      }, rw, rh, levelRaw[d], windAngle);
      const std::size_t partSamples = static_cast<std::size_t>(rw) * rh;
      for (int z = box.z0; z <= box.z1; ++z) {
        for (int x = box.x0; x <= box.x1; ++x) {
          const std::size_t at = static_cast<std::size_t>(z) * width + static_cast<std::size_t>(x);
          if (owner[at] != d) {
            continue;
          }
          const std::size_t local = static_cast<std::size_t>(z - z0) * rw + static_cast<std::size_t>(x - x0);
          result[at] = part[local];
          result[samples + at] = part[partSamples + local];
        }
      }
    }
    return result;
  }
} // namespace moho::water
