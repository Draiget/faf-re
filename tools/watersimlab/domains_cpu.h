// The checks of the domain tests (docs/WATER_SIMULATION.md, "Water bodies") that need no GPU: the shore fields per
// water against a brute-force reference, the fetch of small lakes and the window centre on several levels. Included by
// the lab (domains.h, which adds the ones that run the shader on WARP) and by the host test
// tests/water/WaterDomainTests.cpp.
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "../../src/moho/terrain/water/ShoreField.h"
#include "../../src/moho/terrain/water/WaterDomains.h"
#include "../../src/moho/terrain/water/WaterSimParams.h"
#include "../../src/moho/terrain/water/WaterSourceGate.h"

namespace domains
{
  using moho::water::DomainTable;
  using moho::water::kDryLevelRaw;

  struct Check
  {
    int ok = 0;
    int failed = 0;
    void operator()(
      const bool good,
      const char* const what,
      const double a = 0.0,
      const double b = 0.0
    )
    {
      std::printf("  [%s] %s  (%.6g, %.6g)\n", good ? "ok" : "FAIL", what, a, b);
      (good ? ok : failed)++;
    }
  };

  constexpr float kCell = 0.5f;
  constexpr float kStep = 1.0f / 90.0f;
  constexpr int kN = 512;                 // cells of the window: 256 x 256 units
  constexpr std::uint32_t kSamples = 260; // height samples a side
  constexpr float kMargin = 0.1f;

  struct World
  {
    std::uint32_t hw = kSamples;
    std::uint32_t hh = kSamples;
    std::vector<float> ground; // world units per sample
    std::vector<std::uint16_t> raw;
    DomainTable table;
    std::vector<float> shore; // the fields of the samples, then (domains) the table
    float seaLevel = 25.0f;   // what the single level path (domains off) takes
    float windAngle = 0.0f;
  };

  inline float Ground(
    const World& w,
    const std::uint32_t x,
    const std::uint32_t z
  )
  {
    return w.ground[static_cast<std::size_t>(z) * w.hw + x];
  }

  // bilinear ground (world units) between the four surrounding samples, as the shader's GroundRaw
  inline float GroundAt(
    const World& w,
    const float x,
    const float z
  )
  {
    const float cx = std::min(std::max(x, 0.0f), static_cast<float>(w.hw - 1));
    const float cz = std::min(std::max(z, 0.0f), static_cast<float>(w.hh - 1));
    const std::uint32_t x0 = std::min(static_cast<std::uint32_t>(cx), w.hw - 2);
    const std::uint32_t z0 = std::min(static_cast<std::uint32_t>(cz), w.hh - 2);
    const float fx = cx - static_cast<float>(x0);
    const float fz = cz - static_cast<float>(z0);
    const auto r = [&](const std::uint32_t xx, const std::uint32_t zz) {
      return static_cast<float>(w.raw[static_cast<std::size_t>(zz) * w.hw + xx]);
    };
    const float a = r(x0, z0) + (r(x0 + 1, z0) - r(x0, z0)) * fx;
    const float b = r(x0, z0 + 1) + (r(x0 + 1, z0 + 1) - r(x0, z0 + 1)) * fx;
    return (a + (b - a) * fz) / 128.0f;
  }

  // `blockAt(bx, bz, level, body)`: level in world units (kNoWater for none) and body of a 2 x 2 block
  inline World MakeWorld(
    const std::function<float(float, float)>& groundFn,
    const std::function<void(std::uint32_t, std::uint32_t, float&, std::uint8_t&)>& blockAt,
    const bool shoreFields = true
  )
  {
    World w;
    w.ground.resize(static_cast<std::size_t>(w.hw) * w.hh);
    w.raw.resize(w.ground.size());
    for (std::uint32_t z = 0; z < w.hh; ++z) {
      for (std::uint32_t x = 0; x < w.hw; ++x) {
        const float g = groundFn(static_cast<float>(x), static_cast<float>(z));
        const std::size_t i = static_cast<std::size_t>(z) * w.hw + x;
        w.ground[i] = g;
        w.raw[i] = static_cast<std::uint16_t>(std::min(std::max(g * 128.0f, 0.0f), 65535.0f));
      }
    }
    w.table =
      moho::water::BuildDomainTable((w.hw - 1U) >> 1U, (w.hh - 1U) >> 1U, moho::water::kNoWaterLevel, kMargin, blockAt);
    if (shoreFields) {
      const DomainTable& t = w.table;
      w.shore = moho::water::ComputeShoreDistanceDomains([&](const std::uint32_t x, const std::uint32_t z) {
        return w.raw[static_cast<std::size_t>(z) * w.hw + x];
      }, [&](const std::uint32_t x, const std::uint32_t z) {
        return static_cast<std::uint32_t>(t.domain[moho::water::BlockOfSample(t, x, z)]);
      }, moho::water::DomainLevels(t), w.hw, w.hh, w.windAngle);
      w.shore.insert(w.shore.end(), t.levelRaw.begin(), t.levelRaw.end());
      w.shore.insert(w.shore.end(), t.domain.begin(), t.domain.end());
    }
    return w;
  }

  // the number of the domain of a world position, and its level (world units, kNoWater for none)
  inline std::uint32_t DomainOf(
    const World& w,
    const float x,
    const float z
  )
  {
    const std::uint32_t bx = std::min(static_cast<std::uint32_t>(std::max(x, 0.0f)) >> 1U, w.table.blocksX - 1U);
    const std::uint32_t bz = std::min(static_cast<std::uint32_t>(std::max(z, 0.0f)) >> 1U, w.table.blocksZ - 1U);
    return static_cast<std::uint32_t>(w.table.domain[static_cast<std::size_t>(bz) * w.table.blocksX + bx]);
  }

  inline float LevelOf(
    const World& w,
    const float x,
    const float z
  )
  {
    const std::uint32_t bx = std::min(static_cast<std::uint32_t>(std::max(x, 0.0f)) >> 1U, w.table.blocksX - 1U);
    const std::uint32_t bz = std::min(static_cast<std::uint32_t>(std::max(z, 0.0f)) >> 1U, w.table.blocksZ - 1U);
    const float raw = w.table.levelRaw[static_cast<std::size_t>(bz) * w.table.blocksX + bx];
    return raw <= kDryLevelRaw * 0.5f ? moho::water::kNoWaterLevel : raw / 128.0f + kMargin;
  }

  // ---- 6 and 7 ----------------------------------------------------------------------------------
  inline double Calm(
    const float fetch
  )
  {
    const float t = std::min(std::max((fetch - 25.0f) / (160.0f - 25.0f), 0.0f), 1.0f);
    const float smooth = t * t * (3.0f - 2.0f * t);
    return 0.08 + (1.0 - 0.08) * smooth;
  }

  inline void TestFetch(
    Check& check
  )
  {
    std::printf("6 fetch: small lakes stay calm, the open sea keeps its fetch, the march stops at a domain border\n");
    // the sea at 25 (ground 5), a raised lake of 20 x 20 and one of 60 x 60 (level 40, ground 30), and a pit of 40 x 40
    // below the sea (a dry polder: domain 3, ground 2): the old single level field marches across the pit
    const auto lake = [](const float x, const float z, const float x0, const float z0, const float size) {
      return x >= x0 && x < x0 + size && z >= z0 && z < z0 + size;
    };
    const World w = MakeWorld([&](const float x, const float z) {
      if (lake(x, z, 40.0f, 40.0f, 20.0f) || lake(x, z, 40.0f, 120.0f, 60.0f)) {
        return 30.0f;
      }
      if (lake(x, z, 150.0f, 150.0f, 40.0f)) {
        return 2.0f;
      }
      return 5.0f;
    }, [&](const std::uint32_t bx, const std::uint32_t bz, float& level, std::uint8_t& body) {
      const float x = static_cast<float>(bx * 2U);
      const float z = static_cast<float>(bz * 2U);
      if (lake(x, z, 40.0f, 40.0f, 20.0f)) {
        level = 40.0f;
        body = 1U;
      } else if (lake(x, z, 40.0f, 120.0f, 60.0f)) {
        level = 40.0f;
        body = 2U;
      } else if (lake(x, z, 150.0f, 150.0f, 40.0f)) {
        level = moho::water::kNoWaterLevel;
        body = 3U;
      } else {
        level = 25.0f;
        body = 0U;
      }
    });
    const std::size_t samples = static_cast<std::size_t>(w.hw) * w.hh;
    const auto open = [&](const std::uint32_t x, const std::uint32_t z) {
      return w.shore[samples + static_cast<std::size_t>(z) * w.hw + x];
    };
    float smallMax = 0.0f;
    for (std::uint32_t z = 41; z < 59; ++z) {
      for (std::uint32_t x = 41; x < 59; ++x) {
        smallMax = std::max(smallMax, open(x, z));
      }
    }
    float bigMax = 0.0f;
    double bigCalm = 0.0;
    for (std::uint32_t z = 121; z < 179; ++z) {
      for (std::uint32_t x = 41; x < 99; ++x) {
        bigMax = std::max(bigMax, open(x, z));
        bigCalm = std::max(bigCalm, Calm(open(x, z)));
      }
    }
    float seaMin = 1.0e9f;
    for (std::uint32_t z = 226; z < 250; ++z) {
      for (std::uint32_t x = 100; x < 250; ++x) {
        seaMin = std::min(seaMin, open(x, z));
      }
    }
    check(
      smallMax < 25.0f && Calm(smallMax) == 0.08,
      "a lake of 20 units: ShoreOpen < 25 everywhere, calm 0.08",
      smallMax,
      Calm(smallMax)
    );
    check(
      bigMax < 62.0f && bigCalm < 0.25,
      "a lake of 60 units: the fetch never exceeds its width, calm stays below 0.25",
      bigMax,
      bigCalm
    );
    check(seaMin > 160.0f && Calm(seaMin) > 0.99, "the open sea keeps its fetch: calm 1.0", seaMin, Calm(seaMin));
    // the march of the sea does not cross the pit: just downwind of the pit (the wind blows to +x, the march goes to
    // -x) the fetch is the distance to its border, not the way across it
    const std::vector<float> oldField =
      moho::water::ComputeShoreDistance([&](const std::uint32_t x, const std::uint32_t z) {
      return w.raw[static_cast<std::size_t>(z) * w.hw + x];
    }, w.hw, w.hh, (25.0f - kMargin) * 128.0f, 0.0f);
    double newSum = 0.0;
    double oldSum = 0.0;
    int n = 0;
    for (std::uint32_t z = 160; z < 180; ++z) {
      for (std::uint32_t x = 196; x < 202; ++x) { // 6 to 12 units east of the pit
        newSum += open(x, z);
        oldSum += oldField[samples + static_cast<std::size_t>(z) * w.hw + x];
        ++n;
      }
    }
    check(
      newSum / n < oldSum / n - 20.0,
      "the sea's fetch ends at the border of the pit (the single level field runs across it)",
      newSum / n,
      oldSum / n
    );
  }

  inline void TestBrute(
    Check& check
  )
  {
    std::printf("7 shore fields per domain against a brute-force reference on random domain maps\n");
    std::uint32_t seed = 987654321u;
    const auto random = [&]() {
      seed = seed * 1664525u + 1013904223u;
      return static_cast<float>(seed >> 8) * (1.0f / 16777216.0f);
    };
    int maps = 0;
    int bad = 0;
    int badFetch = 0;
    double worst = 0.0;
    for (int trial = 0; trial < 4; ++trial) {
      const std::uint32_t hw = 50U + static_cast<std::uint32_t>(random() * 30.0f);
      const std::uint32_t hh = 44U + static_cast<std::uint32_t>(random() * 30.0f);
      // blobs of domains on 2 x 2 blocks: the nearest of a few seeds
      const std::uint32_t bw = (hw - 1U) >> 1U;
      const std::uint32_t bh = (hh - 1U) >> 1U;
      const int seeds = 4 + trial;
      std::vector<float> sx(seeds), sz(seeds), level(seeds);
      for (int i = 0; i < seeds; ++i) {
        sx[i] = random() * static_cast<float>(bw);
        sz[i] = random() * static_cast<float>(bh);
        level[i] = random() < 0.2f ? moho::water::kNoWaterLevel : 15.0f + random() * 30.0f;
      }
      DomainTable table = moho::water::BuildDomainTable(
        bw,
        bh,
        moho::water::kNoWaterLevel,
        kMargin,
        [&](const std::uint32_t x, const std::uint32_t z, float& lv, std::uint8_t& body) {
        int best = 0;
        float bestD = 1e30f;
        for (int i = 0; i < seeds; ++i) {
          const float dx = static_cast<float>(x) - sx[i];
          const float dz = static_cast<float>(z) - sz[i];
          if (dx * dx + dz * dz < bestD) {
            bestD = dx * dx + dz * dz;
            best = i;
          }
        }
        lv = level[best];
        body = static_cast<std::uint8_t>(best);
      }
      );
      std::vector<std::uint16_t> raw(static_cast<std::size_t>(hw) * hh);
      for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<std::uint16_t>((10.0f + random() * 45.0f) * 128.0f);
      }
      const auto rawAt = [&](const std::uint32_t x, const std::uint32_t z) {
        return raw[static_cast<std::size_t>(z) * hw + x];
      };
      const auto domainAt = [&](const std::uint32_t x, const std::uint32_t z) {
        return static_cast<std::uint32_t>(table.domain[moho::water::BlockOfSample(table, x, z)]);
      };
      const std::vector<float> levels = moho::water::DomainLevels(table);
      const std::vector<float> got = moho::water::ComputeShoreDistanceDomains(rawAt, domainAt, levels, hw, hh, 1.1f);
      const std::size_t samples = static_cast<std::size_t>(hw) * hh;
      ++maps;
      for (int d = 0; d < seeds; ++d) {
        if (levels[d] <= kDryLevelRaw * 0.5f) {
          continue;
        }
        const auto isLand = [&](const std::uint32_t x, const std::uint32_t z) {
          return domainAt(x, z) != static_cast<std::uint32_t>(d) || static_cast<float>(rawAt(x, z)) > levels[d];
        };
        // brute force nearest land sample, exact, then the same smoothing (13 samples, four passes, clamped)
        std::vector<float> dist(samples);
        for (std::uint32_t z = 0; z < hh; ++z) {
          for (std::uint32_t x = 0; x < hw; ++x) {
            double best = 1e12;
            for (std::uint32_t qz = 0; qz < hh; ++qz) {
              for (std::uint32_t qx = 0; qx < hw; ++qx) {
                if (isLand(qx, qz)) {
                  const double dx = static_cast<double>(qx) - x;
                  const double dz = static_cast<double>(qz) - z;
                  best = std::min(best, dx * dx + dz * dz);
                }
              }
            }
            dist[static_cast<std::size_t>(z) * hw + x] = static_cast<float>(std::min(std::sqrt(best), 1e4));
          }
        }
        std::vector<float> tmp(samples);
        for (int pass = 0; pass < 4; ++pass) {
          for (int z = 0; z < static_cast<int>(hh); ++z) {
            for (int x = 0; x < static_cast<int>(hw); ++x) {
              float sum = 0.0f;
              for (int o = -6; o <= 6; ++o) {
                const int xx = (pass & 1) == 0 ? std::min(std::max(x + o, 0), static_cast<int>(hw) - 1) : x;
                const int zz = (pass & 1) == 1 ? std::min(std::max(z + o, 0), static_cast<int>(hh) - 1) : z;
                sum += dist[static_cast<std::size_t>(zz) * hw + xx];
              }
              tmp[static_cast<std::size_t>(z) * hw + x] = sum / 13.0f;
            }
          }
          dist.swap(tmp);
        }
        // the fetch: what ComputeShoreDistance gives on the whole map with the other domains as land
        const std::vector<float> reference =
          moho::water::ComputeShoreDistance([&](const std::uint32_t x, const std::uint32_t z) {
          return domainAt(x, z) == static_cast<std::uint32_t>(d) ? static_cast<float>(rawAt(x, z)) : 1.0e9f;
        }, hw, hh, levels[d], 1.1f);
        for (std::uint32_t z = 0; z < hh; ++z) {
          for (std::uint32_t x = 0; x < hw; ++x) {
            if (domainAt(x, z) != static_cast<std::uint32_t>(d)) {
              continue;
            }
            const std::size_t i = static_cast<std::size_t>(z) * hw + x;
            const double diff = std::fabs(static_cast<double>(got[i]) - dist[i]);
            worst = std::max(worst, diff);
            bad += diff > 2e-3 ? 1 : 0;
            badFetch += got[samples + i] != reference[samples + i] ? 1 : 0;
          }
        }
      }
    }
    check(
      bad == 0,
      "the distance of every sample equals the brute-force nearest foreign or high sample (smoothed alike)",
      bad,
      worst
    );
    check(
      badFetch == 0,
      "the fetch of every sample equals the one of the whole-map field with the other domains as land",
      badFetch
    );
  }

  // ---- 8 ----------------------------------------------------------------------------------------
  inline void TestCentre(
    Check& check
  )
  {
    std::printf("8 window centre: one level equals the plane intersection, several levels follow the ray down\n");
    const auto flat = [](const float, const float) {
      return 5.0f;
    };
    const auto sea = [](const float, const float, float& level) {
      level = 25.0f;
      return true;
    };
    float cx = 0.0f, cz = 0.0f;
    const float px = 100.0f, py = 80.0f, pz = 90.0f;
    float dx = 0.5f, dy = -0.6f, dz = 0.62f;
    const float len = std::sqrt(dx * dx + dy * dy + dz * dz);
    dx /= len;
    dy /= len;
    dz /= len;
    const bool hit = moho::water::WaterWindowCentre(px, py, pz, dx, dy, dz, 6000.0f, 8.0f, flat, sea, cx, cz);
    const float t = (25.0f - py) / dy;
    check(
      hit && std::fabs(cx - (px + dx * t)) < 0.01f && std::fabs(cz - (pz + dz * t)) < 0.01f,
      "the sea only: the point where the ray meets the sea plane",
      cx - (px + dx * t),
      cz - (pz + dz * t)
    );
    // a raised lake (level 40) at x 200 .. 260 in the sea (25): the camera above it
    const auto lakes = [](const float x, const float z, float& level) {
      level = x >= 200.0f && x < 260.0f && z >= 60.0f && z < 140.0f ? 40.0f : 25.0f;
      return true;
    };
    const auto bowl = [](const float x, const float z) {
      return x >= 200.0f && x < 260.0f && z >= 60.0f && z < 140.0f ? 30.0f : 5.0f;
    };
    const float qx = 180.0f, qy = 60.0f, qz = 100.0f;
    float ex = 0.8f, ey = -0.5f, ez = 0.0f;
    const float el = std::sqrt(ex * ex + ey * ey + ez * ez);
    ex /= el;
    ey /= el;
    ez /= el;
    const bool onLake = moho::water::WaterWindowCentre(qx, qy, qz, ex, ey, ez, 6000.0f, 8.0f, bowl, lakes, cx, cz);
    const float yAt = qy + ey * ((cx - qx) / ex);
    check(
      onLake && cx >= 200.0f && cx < 260.0f && std::fabs(yAt - 40.0f) < 0.01f,
      "above a lake: the point on its surface (level 40), not where the sea plane would be",
      cx,
      yAt
    );
    const bool miss = moho::water::WaterWindowCentre(qx, qy, qz, ex, 0.2f, ez, 6000.0f, 8.0f, bowl, lakes, cx, cz);
    check(!miss, "a ray that goes up has no water: the caller keeps the last centre");
    const auto noWater = [](const float, const float, float&) {
      return false;
    };
    check(
      !moho::water::WaterWindowCentre(px, py, pz, dx, dy, dz, 6000.0f, 8.0f, flat, noWater, cx, cz),
      "a ray that meets no water keeps the last centre"
    );
    const auto ridge = [](const float x, const float) {
      return x > 140.0f ? 200.0f : 5.0f;
    };
    check(
      !moho::water::WaterWindowCentre(px, py, pz, 0.7f, -0.2f, 0.0f, 6000.0f, 8.0f, ridge, sea, cx, cz),
      "a ray that meets the ground first keeps the last centre"
    );
  }
} // namespace domains

// runs the checks that need no GPU
inline void RunDomainsCpu(
  domains::Check& check
)
{
  domains::TestFetch(check);
  domains::TestBrute(check);
  domains::TestCentre(check);
}
