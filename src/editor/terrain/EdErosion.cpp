// the erosion suite, see EdErosion.h.
//
// Determinism: the grid solver is double buffered and gather style (every output sample is computed from the state at
// the start of the pass), the droplet solver processes tiles of a fixed size in four colour phases (tiles of one colour
// never touch each other, each tile has its own random stream), and the stream power solver is sequential. None of them
// depends on the thread count. The file pins fp_contract(off) like the core.
// The golden checksums (tests/editor/FieldTests.cpp, ErosionTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdErosion.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <queue>
#include <string>

namespace faf::editor::field::erosion
{
  namespace
  {
    constexpr int kRowChunk = 8;
    constexpr float kPi = 3.14159265358979f;

    /** f(z0, z1) for fixed chunks of rows; small grids run inline (the result never depends on it). */
    template <class F>
    void Rows(
      const int w,
      const int h,
      F&& f
    )
    {
      if (static_cast<long long>(w) * h < 6000) {
        f(0, h);
        return;
      }
      const int chunks = (h + kRowChunk - 1) / kRowChunk;
      ParallelFor(chunks, [&](const int c) {
        const int z0 = c * kRowChunk;
        f(z0, std::min(h, z0 + kRowChunk));
      });
    }

    inline std::size_t Ix(
      const int x,
      const int z,
      const int w
    )
    {
      return static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
    }
    inline float Clamp01(
      const float v
    )
    {
      return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
    }
    /** Values this small are zero for the solver; flushing them keeps the arrays free of denormal numbers, which are
     * very slow on x86. */
    inline float Flush(
      const float v
    )
    {
      return v < 1e-9f ? 0.0f : v;
    }

    // ---- random numbers (SplitMix64, one stream per tile and round)
    // -------------------------------------------------------------------------

    struct Rng
    {
      std::uint64_t s;
      explicit Rng(
        const std::uint64_t seed
      )
        : s(seed)
      {}
      std::uint32_t Next()
      {
        s += 0x9E3779B97F4A7C15ull;
        std::uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        return static_cast<std::uint32_t>(z >> 32);
      }
      float Unit()
      {
        return static_cast<float>(Next() >> 8) * (1.0f / 16777216.0f);
      }
    };

    std::uint64_t Mix(
      const std::uint64_t a,
      const std::uint64_t b,
      const std::uint64_t c
    )
    {
      std::uint64_t z =
        a * 0x9E3779B97F4A7C15ull + b * 0xC2B2AE3D27D4EB4Full + c * 0x165667B19E3779F9ull + 0x27D4EB2F165667C5ull;
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      return z ^ (z >> 31);
    }

    // ---- spatial variation
    // ----------------------------------------------------------------------------------------------------------------------

    /** Smooth value noise of the world position (feature size `scale` world units, `octaves` octaves of half the size),
     * spread to 0..1 (mean 0.5, +- 2.5 standard deviations = the range). A coarse grid (cell = step) samples the same
     * field. Sequential and deterministic. */
    void NoiseField(
      std::vector<float>& out,
      const int w,
      const int h,
      const float cell,
      const float scale,
      const std::uint32_t seed,
      const int octaves,
      const bool fixedSpread = false,
      const int ox = 0,
      const int oz = 0
    )
    {
      const std::size_t n = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
      out.assign(n, 0.0f);
      const auto lattice = [&](const std::uint64_t o, const int ix, const int iz) {
        return static_cast<float>(
                 Mix(
                   static_cast<std::uint64_t>(seed) * 131u + o,
                   static_cast<std::uint64_t>(static_cast<std::uint32_t>(ix)),
                   static_cast<std::uint64_t>(static_cast<std::uint32_t>(iz))
                 ) >>
                 40
               ) *
          (1.0f / 16777216.0f);
      };
      float amp = 1.0f;
      for (int o = 0; o < octaves; ++o, amp *= 0.5f) {
        const float inv = cell / std::max(1e-3f, scale / static_cast<float>(1 << o));
        for (int z = 0; z < h; ++z) {
          const float v = static_cast<float>(z + oz) * inv;
          const int iz = static_cast<int>(std::floor(v));
          const float fz = v - static_cast<float>(iz);
          const float sz = fz * fz * (3.0f - 2.0f * fz);
          for (int x = 0; x < w; ++x) {
            const float u = static_cast<float>(x + ox) * inv;
            const int ix = static_cast<int>(std::floor(u));
            const float fx = u - static_cast<float>(ix);
            const float sx = fx * fx * (3.0f - 2.0f * fx);
            const float a = lattice(static_cast<std::uint64_t>(o), ix, iz) * (1.0f - sx) +
              lattice(static_cast<std::uint64_t>(o), ix + 1, iz) * sx;
            const float b = lattice(static_cast<std::uint64_t>(o), ix, iz + 1) * (1.0f - sx) +
              lattice(static_cast<std::uint64_t>(o), ix + 1, iz + 1) * sx;
            out[Ix(x, z, w)] += amp * (a * (1.0f - sz) + b * sz);
          }
        }
      }
      double sum = 0.0, sum2 = 0.0;
      for (const float v : out) {
        sum += v;
        sum2 += static_cast<double>(v) * v;
      }
      double mean = sum / static_cast<double>(n);
      double sd = std::sqrt(std::max(0.0, sum2 / static_cast<double>(n) - mean * mean));
      if (fixedSpread) {
        // a window of a larger map (the brush): the same mapping for every window, from the statistics of this noise
        // (mean 0.5 and about 0.2 per octave amplitude)
        double a2 = 0.0, a1 = 0.0, am = 1.0;
        for (int o = 0; o < octaves; ++o, am *= 0.5) {
          a1 += am;
          a2 += am * am;
        }
        mean = 0.5 * a1;
        sd = 0.2 * std::sqrt(a2);
      }
      const float k = sd > 1e-9 ? static_cast<float>(1.0 / (5.0 * sd)) : 0.0f;
      for (float& v : out)
        v = Clamp01(0.5f + (v - static_cast<float>(mean)) * k);
    }

    /** 0..1 where the ground is a ridge or a high summit: convexity (the height over the mean of its surroundings,
     * radius ~6 world units) in units of its standard deviation, or the relative height cubed. */
    void RidgeMap(
      const std::vector<float>& t,
      const int w,
      const int h,
      const float cell,
      std::vector<float>& out
    )
    {
      const std::size_t n = t.size();
      const int r = std::max(1, std::min(10, static_cast<int>(6.0f / std::max(cell, 1e-3f) + 0.5f)));
      std::vector<float> tmp(n), mean(n);
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          float s = 0.0f;
          int c = 0;
          for (int k = std::max(0, x - r); k <= std::min(w - 1, x + r); ++k, ++c)
            s += t[Ix(k, z, w)];
          tmp[Ix(x, z, w)] = s / static_cast<float>(c);
        }
      }
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          float s = 0.0f;
          int c = 0;
          for (int k = std::max(0, z - r); k <= std::min(h - 1, z + r); ++k, ++c)
            s += tmp[Ix(x, k, w)];
          mean[Ix(x, z, w)] = s / static_cast<float>(c);
        }
      }
      double sum2 = 0.0;
      float lo = t[0], hi = t[0];
      for (std::size_t i = 0; i < n; ++i) {
        const double c = static_cast<double>(t[i]) - mean[i];
        sum2 += c * c;
        lo = std::min(lo, t[i]);
        hi = std::max(hi, t[i]);
      }
      const float sd = static_cast<float>(std::sqrt(sum2 / static_cast<double>(n)));
      const float inv = sd > 1e-6f ? 1.0f / (1.5f * sd) : 0.0f;
      const float span = std::max(1e-6f, hi - lo);
      out.resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        const float rel = (t[i] - lo) / span;
        out[i] = std::max(Clamp01((t[i] - mean[i]) * inv), rel * rel * rel);
      }
    }

    // ---- thermal slides
    // ---------------------------------------------------------------------------------------------------------------------

    struct ThermalScratch
    {
      std::vector<float> share, moved, next;
    };

    void ThermalImpl(
      std::vector<float>& t,
      const int w,
      const int h,
      const float cell,
      const float talus,
      const float rate,
      const std::vector<float>& rateMask,
      const int pinSides,
      ThermalScratch& sc
    )
    {
      static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
      static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
      const std::size_t n = t.size();
      sc.share.assign(n, 0.0f);
      sc.moved.assign(n, 0.0f);
      sc.next.resize(n);
      const float tAxis = talus * cell;
      const float tDiag = talus * cell * 1.41421356f;
      // pinSides: bit 0 / 1 = the -x / +x column, bit 2 / 3 = the -z / +z row is left alone (a side without its bit
      // takes part: a missing neighbour never gives or takes)
      const int loX = pinSides & 1, hiX = (pinSides >> 1) & 1, loZ = (pinSides >> 2) & 1, hiZ = (pinSides >> 3) & 1;
      const bool useMask = !rateMask.empty();
      const auto valid = [&](const int x, const int z) {
        return x >= loX && z >= loZ && x < w - hiX && z < h - hiZ;
      };
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            if (!valid(x, z))
              continue;
            const float c = t[i];
            float maxEx = 0.0f, sumEx = 0.0f;
            for (int k = 0; k < 8; ++k) {
              const int nx = x + dxs[k];
              const int nz = z + dzs[k];
              if (!valid(nx, nz))
                continue;
              const float ex = (c - t[Ix(nx, nz, w)]) - (k < 4 ? tAxis : tDiag);
              if (ex > 0.0f) {
                sumEx += ex;
                maxEx = std::max(maxEx, ex);
              }
            }
            if (sumEx > 0.0f) {
              float r = rate;
              if (useMask)
                r *= Clamp01(rateMask[i]);
              const float s = r * 0.5f * maxEx / sumEx;
              sc.share[i] = s;
              sc.moved[i] = s * sumEx;
            }
          }
        }
      });
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            const float c = t[i];
            if (!valid(x, z)) {
              sc.next[i] = c;
              continue;
            }
            float gain = 0.0f;
            for (int k = 0; k < 8; ++k) {
              const int nx = x + dxs[k];
              const int nz = z + dzs[k];
              if (!valid(nx, nz))
                continue;
              const std::size_t j = Ix(nx, nz, w);
              const float ex = (t[j] - c) - (k < 4 ? tAxis : tDiag);
              if (ex > 0.0f)
                gain += sc.share[j] * ex;
            }
            sc.next[i] = c - sc.moved[i] + gain;
          }
        }
      });
      t.swap(sc.next);
    }
  } // namespace

  void ThermalStep(
    std::vector<float>& t,
    const int w,
    const int h,
    const float cell,
    const float talus,
    const float rate,
    const std::vector<float>& rateMask,
    const bool pinBorder
  )
  {
    ThermalScratch sc;
    ThermalImpl(t, w, h, cell, talus, rate, rateMask, pinBorder ? 15 : 0, sc);
  }

  // ---- grid hydraulic erosion
  // -------------------------------------------------------------------------------------------------------------------

  void HydroState::Allocate(
    const int width,
    const int height,
    const float cellSize
  )
  {
    w = width;
    h = height;
    cell = cellSize;
    const std::size_t n = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
    t.assign(n, 0.0f);
    d.assign(n, 0.0f);
    s.assign(n, 0.0f);
    for (auto& a : f)
      a.assign(n, 0.0f);
    wear.assign(n, 0.0f);
    dep.assign(n, 0.0f);
    flow.assign(n, 0.0f);
  }

  namespace
  {
    /** The water surface of the (dry) cell outside an open edge: the edge cell's ground, carried on in the direction it
     * already descends in (`inner` = the neighbour on the other side), so water leaves a map edge like it leaves any
     * other cell and the edge cell is no special case (no pinned ring, no wall of material left standing at the
     * border). */
    inline float GhostSurface(
      const float edge,
      const float inner
    )
    {
      return edge + std::min(0.0f, edge - inner);
    }

    /**
     * Edge consistency: the outermost cells of the open sides take the change of their inner neighbour (`after` =
     * `before` + the neighbour's change), so the step between the edge and the cell beside it stays what the terrain
     * had: a border that is dug / filled differently from its neighbour (the drain at the edge digs it, sediment piles
     * there) is what stood as a vertical wall at the map border. `pinnedSides` (the bits of ThermalImpl /
     * HydroParams::pin_sides) are left alone; the corner follows the diagonal neighbour.
     */
    void MirrorEdgeChange(
      const std::vector<float>& before,
      std::vector<float>& after,
      const int w,
      const int h,
      const int pinnedSides
    )
    {
      if (w < 4 || h < 4)
        return;
      const bool openL = (pinnedSides & 1) == 0, openR = (pinnedSides & 2) == 0, openT = (pinnedSides & 4) == 0,
                 openB = (pinnedSides & 8) == 0;
      const auto chg = [&](const int x, const int z) {
        const std::size_t i = static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
        return after[i] - before[i];
      };
      const auto put = [&](const int x, const int z, const float c) {
        const std::size_t i = static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
        after[i] = before[i] + c;
      };
      // the inner cells are never written here, so the order does not matter
      for (int z = 1; z < h - 1; ++z) {
        if (openL)
          put(0, z, chg(1, z));
        if (openR)
          put(w - 1, z, chg(w - 2, z));
      }
      for (int x = 1; x < w - 1; ++x) {
        if (openT)
          put(x, 0, chg(x, 1));
        if (openB)
          put(x, h - 1, chg(x, h - 2));
      }
      if (openL && openT)
        put(0, 0, chg(1, 1));
      if (openR && openT)
        put(w - 1, 0, chg(w - 2, 1));
      if (openL && openB)
        put(0, h - 1, chg(1, h - 2));
      if (openR && openB)
        put(w - 1, h - 1, chg(w - 2, h - 2));
    }
  } // namespace

  void RunHydro(
    HydroState& st,
    const HydroParams& p,
    const int iterations
  )
  {
    const int w = st.w;
    const int h = st.h;
    if (w < 3 || h < 3)
      return;
    const std::size_t n = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
    const bool track = p.track;
    if (track) {
      if (st.wear.size() != n)
        st.wear.assign(n, 0.0f);
      if (st.dep.size() != n)
        st.dep.assign(n, 0.0f);
      if (st.flow.size() != n)
        st.flow.assign(n, 0.0f);
    }
    std::vector<float> tn(n), sn(n), dold(n);
    ThermalScratch tsc;
    const float cell = st.cell;
    const int sides = p.pin_border ? (p.pin_sides & 15) : 0; // the pinned sides of the rectangle
    const bool openEdge = p.open_edge;                       // the other sides let water and sediment leave
    const float gain = std::max(0.0f, std::min(0.5f, p.gain));
    const float evap = Clamp01(p.evaporation);
    const float depthMax = std::max(1e-4f, p.depth_max);
    const bool hasRain = !st.rain_rate.empty();
    const bool hasErode = !st.erode_rate.empty();
    const bool hasRock = !st.rock.empty();
    const float invDepthMax = 1.0f / depthMax;
    const auto pinned = [&](const int x, const int z) {
      return ((sides & 1) != 0 && x == 0) || ((sides & 2) != 0 && x == w - 1) || ((sides & 4) != 0 && z == 0) ||
        ((sides & 8) != 0 && z == h - 1);
    };
    float* const D = st.d.data();
    float* const S = st.s.data();
    float* const F0 = st.f[0].data();
    float* const F1 = st.f[1].data();
    float* const F2 = st.f[2].data();
    float* const F3 = st.f[3].data();

    for (int it = 0; it < iterations; ++it) {
      float* const T = st.t.data(); // st.t and tn trade places every iteration
      // rain
      if (p.rain > 0.0f) {
        Rows(w, h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i = Ix(x, z, w);
              D[i] += p.rain * (hasRain ? st.rain_rate[i] : 1.0f);
            }
          }
        });
      }
      // A: outflow fluxes from the water surface differences, scaled so no cell gives away more water than it has
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            if (pinned(x, z)) {
              F0[i] = F1[i] = F2[i] = F3[i] = 0.0f;
              continue;
            }
            const float H = T[i] + D[i];
            float a0 = 0.0f, a1 = 0.0f, a2 = 0.0f, a3 = 0.0f;
            if (x > 0)
              a0 = std::max(0.0f, F0[i] + gain * (H - (T[i - 1] + D[i - 1])));
            else if (openEdge)
              a0 = std::max(0.0f, F0[i] + gain * (H - GhostSurface(T[i], T[i + 1])));
            if (x < w - 1)
              a1 = std::max(0.0f, F1[i] + gain * (H - (T[i + 1] + D[i + 1])));
            else if (openEdge)
              a1 = std::max(0.0f, F1[i] + gain * (H - GhostSurface(T[i], T[i - 1])));
            if (z > 0)
              a2 = std::max(0.0f, F2[i] + gain * (H - (T[i - w] + D[i - w])));
            else if (openEdge)
              a2 = std::max(0.0f, F2[i] + gain * (H - GhostSurface(T[i], T[i + w])));
            if (z < h - 1)
              a3 = std::max(0.0f, F3[i] + gain * (H - (T[i + w] + D[i + w])));
            else if (openEdge)
              a3 = std::max(0.0f, F3[i] + gain * (H - GhostSurface(T[i], T[i - w])));
            const float sum = a0 + a1 + a2 + a3;
            if (sum > D[i]) {
              const float k = sum > 0.0f ? D[i] / sum : 0.0f;
              a0 *= k;
              a1 *= k;
              a2 *= k;
              a3 *= k;
            }
            F0[i] = Flush(a0);
            F1[i] = Flush(a1);
            F2[i] = Flush(a2);
            F3[i] = Flush(a3);
          }
        }
      });
      // B: water update, velocity, dissolving and settling
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            if (pinned(x, z)) {
              tn[i] = T[i];
              sn[i] = 0.0f;
              dold[i] = 0.0f;
              D[i] = 0.0f;
              continue;
            }
            const float inW = x > 0 ? F1[i - 1] : 0.0f;
            const float inE = x < w - 1 ? F0[i + 1] : 0.0f;
            const float inN = z > 0 ? F3[i - w] : 0.0f;
            const float inS = z < h - 1 ? F2[i + w] : 0.0f;
            const float out = F0[i] + F1[i] + F2[i] + F3[i];
            const float dOld = D[i];
            dold[i] = dOld;
            const float dNew = std::max(0.0f, dOld + (inW + inE + inN + inS) - out);
            const float dm = 0.5f * (dOld + dNew);
            const float inv = 1.0f / std::max(dm, 0.002f);
            float ux = 0.5f * (inW + F1[i] - inE - F0[i]) * inv;
            float uz = 0.5f * (inN + F3[i] - inS - F2[i]) * inv;
            float speed = std::sqrt(ux * ux + uz * uz);
            if (speed > p.max_speed) {
              const float k = p.max_speed / speed;
              ux *= k;
              uz *= k;
              speed = p.max_speed;
            }
            D[i] = dNew;
            if (track)
              st.flow[i] += speed * dNew;
            // slope from the terrain at the start of the pass
            const int xl = x > 0 ? x - 1 : x;
            const int xr = x < w - 1 ? x + 1 : x;
            const int zu = z > 0 ? z - 1 : z;
            const int zd = z < h - 1 ? z + 1 : z;
            const float gx = (T[Ix(xr, z, w)] - T[Ix(xl, z, w)]) / (static_cast<float>(xr - xl) * cell);
            const float gz = (T[Ix(x, zd, w)] - T[Ix(x, zu, w)]) / (static_cast<float>(zd - zu) * cell);
            const float g = std::sqrt(gx * gx + gz * gz);
            const float sinA = g / std::sqrt(1.0f + g * g);
            const float tilt = std::max(sinA, p.min_slope);
            const float cap = p.capacity * tilt * speed * std::min(1.0f, dNew * invDepthMax);
            const float s0 = S[i];
            float erode = 0.0f, deposit = 0.0f;
            if (cap > s0) {
              float k = p.erosion * (hasErode ? st.erode_rate[i] : 1.0f) * (hasRock ? st.rock[i] : 1.0f);
              erode = k * (cap - s0);
              if (p.cut_limit > 0.0f) {
                float low = T[i];
                if (x > 0)
                  low = std::min(low, T[i - 1]);
                if (x < w - 1)
                  low = std::min(low, T[i + 1]);
                if (z > 0)
                  low = std::min(low, T[i - w]);
                if (z < h - 1)
                  low = std::min(low, T[i + w]);
                erode = std::min(erode, p.cut_limit * (T[i] - low));
              }
              erode = std::max(0.0f, erode);
            } else {
              deposit = p.deposition * (s0 - cap);
            }
            tn[i] = T[i] - erode + deposit;
            sn[i] = s0 + erode - deposit;
            if (track) {
              st.wear[i] += erode;
              st.dep[i] += deposit;
            }
          }
        }
      });
      st.t.swap(tn);
      // C: the sediment travels with the water through the same pipes (upwind, so the total is conserved), then the
      // water evaporates
      {
        const float* const DO = dold.data();
        const float* const SN = sn.data();
        Rows(w, h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i = Ix(x, z, w);
              if (pinned(x, z)) {
                S[i] = 0.0f;
                D[i] = 0.0f;
                continue;
              }
              float v = SN[i];
              if (DO[i] > 0.0f)
                v -= SN[i] * (F0[i] + F1[i] + F2[i] + F3[i]) / DO[i];
              if (x > 0 && DO[i - 1] > 0.0f)
                v += SN[i - 1] * F1[i - 1] / DO[i - 1];
              if (x < w - 1 && DO[i + 1] > 0.0f)
                v += SN[i + 1] * F0[i + 1] / DO[i + 1];
              if (z > 0 && DO[i - w] > 0.0f)
                v += SN[i - w] * F3[i - w] / DO[i - w];
              if (z < h - 1 && DO[i + w] > 0.0f)
                v += SN[i + w] * F2[i + w] / DO[i + w];
              S[i] = Flush(v);
              D[i] = Flush(D[i] * (1.0f - evap));
            }
          }
        });
      }
      if (p.thermal > 0.0f && p.thermal_every > 0 && ((it + 1) % p.thermal_every) == 0) {
        ThermalImpl(
          st.t, w, h, cell, p.talus, p.thermal, st.thermal_rate.empty() ? st.erode_rate : st.thermal_rate, sides, tsc
        );
      }
    }
    if (p.settle) {
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            if (pinned(x, z))
              continue;
            st.t[i] += S[i];
            if (track)
              st.dep[i] += S[i];
            S[i] = 0.0f;
          }
        }
      });
    }
  }

  // ---- droplet erosion
  // --------------------------------------------------------------------------------------------------------------------------

  namespace
  {
    /** A queue of cell ids ordered by height in steps of 1/128 (the height word): O(1) push and pop. Cells of one step
     * leave in the order they came in. */
    class FloodQueue
    {
    public:
      FloodQueue(
        const float lo,
        const float hi
      )
        : base_(lo)
        , buckets_(static_cast<std::size_t>(std::max(1.0f, (hi - lo) * 128.0f)) + 2)
        , read_(buckets_.size(), 0)
      {}

      void Push(
        const float height,
        const std::uint32_t id
      )
      {
        const std::size_t b = Bucket(height);
        buckets_[b].push_back(id);
        if (b < cur_)
          cur_ = b;
        ++count_;
      }

      bool Pop(
        std::uint32_t& id
      )
      {
        if (count_ == 0)
          return false;
        while (read_[cur_] >= buckets_[cur_].size())
          ++cur_;
        id = buckets_[cur_][read_[cur_]++];
        --count_;
        return true;
      }

    private:
      std::size_t Bucket(
        const float height
      ) const
      {
        const float v = (height - base_) * 128.0f;
        const std::size_t b = v <= 0.0f ? 0 : static_cast<std::size_t>(v);
        return std::min(b, buckets_.size() - 1);
      }

      float base_;
      std::vector<std::vector<std::uint32_t>> buckets_;
      std::vector<std::size_t> read_;
      std::size_t cur_ = 0;
      std::size_t count_ = 0;
    };

    inline void MinMax(
      const std::vector<float>& v,
      float& lo,
      float& hi
    )
    {
      lo = v.empty() ? 0.0f : v[0];
      hi = lo;
      for (const float x : v) {
        lo = std::min(lo, x);
        hi = std::max(hi, x);
      }
    }

    /** The terrain with every closed depression filled up to its spill height plus `eps` per step towards the outlet
     * (priority flood, Barnes 2014): water on it always finds a way out. Sequential, deterministic. */
    void FillSurface(
      const std::vector<float>& hv,
      const int w,
      const int h,
      const float eps,
      std::vector<float>& fill
    )
    {
      static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
      static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
      const std::size_t n = hv.size();
      fill = hv;
      std::vector<std::uint8_t> done(n, 0);
      float lo, hi;
      MinMax(hv, lo, hi);
      FloodQueue open(lo, hi + eps * static_cast<float>(w + h));
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          if (x == 0 || z == 0 || x == w - 1 || z == h - 1) {
            const std::uint32_t i = static_cast<std::uint32_t>(Ix(x, z, w));
            done[i] = 1;
            open.Push(fill[i], i);
          }
        }
      }
      std::uint32_t c = 0;
      while (open.Pop(c)) {
        const int cx = static_cast<int>(c % static_cast<std::uint32_t>(w));
        const int cz = static_cast<int>(c / static_cast<std::uint32_t>(w));
        for (int k = 0; k < 8; ++k) {
          const int nx = cx + dxs[k], nz = cz + dzs[k];
          if (nx < 0 || nz < 0 || nx >= w || nz >= h)
            continue;
          const std::uint32_t j = static_cast<std::uint32_t>(Ix(nx, nz, w));
          if (done[j])
            continue;
          done[j] = 1;
          fill[j] = std::max(hv[j], fill[c] + eps);
          open.Push(fill[j], j);
        }
      }
    }
  } // namespace

  namespace
  {
    /**
     * Drains every closed depression by cutting its lowest rim instead of filling it (priority flood outwards from the
     * edge, Barnes 2014, with carving): when the flood reaches a cell lower than the one it comes from, the chain of
     * cells it came through is lowered to just below that cell until it is lower already. Only ever lowers the terrain.
     * Deterministic.
     */
    void BreachPits(
      std::vector<float>& t,
      const int w,
      const int h,
      const float eps,
      std::vector<float>& fill,
      const float epsFill
    )
    {
      static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
      static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
      const std::size_t n = t.size();
      fill = t;
      std::vector<std::uint8_t> done(n, 0);
      std::vector<std::uint32_t> parent(n, 0);
      float lo, hi;
      MinMax(t, lo, hi);
      FloodQueue open(lo, hi + epsFill * static_cast<float>(w + h));
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          if (x == 0 || z == 0 || x == w - 1 || z == h - 1) {
            const std::uint32_t i = static_cast<std::uint32_t>(Ix(x, z, w));
            done[i] = 1;
            parent[i] = i;
            open.Push(fill[i], i);
          }
        }
      }
      std::uint32_t c = 0;
      while (open.Pop(c)) {
        const int cx = static_cast<int>(c % static_cast<std::uint32_t>(w));
        const int cz = static_cast<int>(c / static_cast<std::uint32_t>(w));
        for (int k = 0; k < 8; ++k) {
          const int nx = cx + dxs[k], nz = cz + dzs[k];
          if (nx < 0 || nz < 0 || nx >= w || nz >= h)
            continue;
          const std::uint32_t j = static_cast<std::uint32_t>(Ix(nx, nz, w));
          if (done[j])
            continue;
          done[j] = 1;
          parent[j] = c;
          if (t[j] < t[c]) {
            // j lies lower than the cell the flood reached it from: cut the way out from j through c and its ancestors
            float level = t[j];
            std::uint32_t a = c;
            for (int step = 1; step < 100000; ++step) {
              level -= eps;
              if (t[a] <= level)
                break;
              t[a] = level;
              fill[a] = level;
              if (parent[a] == a)
                break; // (an outlet on the edge is lowered too when the way out needs it: the water has to be able to
                       // leave)
              a = parent[a];
            }
          }
          fill[j] = std::max(t[j], fill[c] + epsFill);
          open.Push(fill[j], j);
        }
      }
    }
  } // namespace

  namespace
  {
    using DropParams = DropletParams; // (defined in EdErosion.h: the GPU version reads the same parameters)

    struct DropGrids
    {
      std::vector<float>* wear = nullptr;
      std::vector<float>* dep = nullptr;
      std::vector<float>* flow = nullptr;
    };

    /** Lets a droplet drop `amount` of sediment on the four samples around (fx, fz) of cell i00, bilinear, but never
     * above the spill surface plus a hair: a filled basin takes no more. Returns what was actually dropped. */
    float Settle(
      std::vector<float>& t,
      const std::vector<float>& hs,
      DropGrids& g,
      const int w,
      const std::size_t i00,
      const float fx,
      const float fz,
      const float amount,
      const float cell
    )
    {
      if (amount <= 0.0f)
        return 0.0f;
      const std::size_t idx[4] = {
        i00, i00 + 1, i00 + static_cast<std::size_t>(w), i00 + static_cast<std::size_t>(w) + 1
      };
      const float wgt[4] = {(1.0f - fx) * (1.0f - fz), fx * (1.0f - fz), (1.0f - fx) * fz, fx * fz};
      float done = 0.0f;
      for (int k = 0; k < 4; ++k) {
        const float room = std::max(0.0f, hs[idx[k]] - t[idx[k]] + 0.02f * cell);
        const float a = std::min(amount * wgt[k], room);
        t[idx[k]] += a;
        if (g.dep != nullptr)
          (*g.dep)[idx[k]] += a;
        done += a;
      }
      return done;
    }

    constexpr int kMaxRadius = 12;
    inline int MaxLife(
      const DropParams& p
    )
    {
      return static_cast<int>(std::ceil(static_cast<float>(p.lifetime) * (1.0f + 0.4f * p.drop_vary))) + 1;
    }

    /** Mirror boundary: an index outside 0..n-1 is reflected back into it (-1 -> 1, n -> n - 2); -1 when even that
     * falls outside (a tiny map). */
    inline int Reflect(
      const int i,
      const int n
    )
    {
      int r = i;
      if (r < 0)
        r = -r;
      if (r > n - 1)
        r = 2 * (n - 1) - r;
      return (r < 0 || r > n - 1) ? -1 : r;
    }

    /** One droplet; all reads and writes stay within `reach` cells of the start position (lifetime + radius + 2). */
    void RunDroplet(
      std::vector<float>& t,
      const std::vector<float>& hs,
      const int w,
      const int h,
      const float cell,
      const DropParams& base,
      const std::vector<float>* rock,
      DropGrids& g,
      Rng& rng,
      const double x0,
      const double z0
    )
    {
      DropParams p = base;
      if (base.drop_vary > 0.0f) {
        const float u = base.drop_vary;
        const auto sgn = [&rng]() {
          return rng.Unit() * 2.0f - 1.0f;
        };
        p.radius = std::max(
          1,
          std::min(
            kMaxRadius, static_cast<int>(std::floor(static_cast<float>(base.radius) * (1.0f + u * sgn()) + 0.5f))
          )
        );
        p.lifetime = std::max(
          1,
          std::min(
            MaxLife(base),
            static_cast<int>(std::floor(static_cast<float>(base.lifetime) * (1.0f + 0.4f * u * sgn()) + 0.5f))
          )
        );
        p.inertia = Clamp01(std::min(0.95f, base.inertia * (1.0f + u * sgn())));
        p.capacity = base.capacity * (1.0f + 0.6f * u * sgn());
        p.erode = base.erode * (1.0f + 0.4f * u * sgn());
        p.water = base.water * (1.0f + 0.5f * u * sgn());
      }
      float px = static_cast<float>(x0);
      float pz = static_cast<float>(z0);
      float dx = 0.0f, dz = 0.0f;
      float speed = p.speed;
      float water = p.water;
      float sediment = 0.0f;
      const int R = p.radius;
      for (int life = 0; life < p.lifetime; ++life) {
        const int ix = static_cast<int>(px);
        const int iz = static_cast<int>(pz);
        if (ix < 0 || iz < 0 || ix >= w - 1 || iz >= h - 1)
          break;
        const float fx = px - static_cast<float>(ix);
        const float fz = pz - static_cast<float>(iz);
        const std::size_t i00 = Ix(ix, iz, w);
        const float h00 = hs[i00], h10 = hs[i00 + 1], h01 = hs[i00 + w], h11 = hs[i00 + w + 1];
        const float gx = ((h10 - h00) * (1.0f - fz) + (h11 - h01) * fz) / cell;
        const float gz = ((h01 - h00) * (1.0f - fx) + (h11 - h10) * fx) / cell;
        const float height =
          h00 * (1.0f - fx) * (1.0f - fz) + h10 * fx * (1.0f - fz) + h01 * (1.0f - fx) * fz + h11 * fx * fz;
        dx = dx * p.inertia - gx * (1.0f - p.inertia);
        dz = dz * p.inertia - gz * (1.0f - p.inertia);
        float len = std::sqrt(dx * dx + dz * dz);
        if (len < 1e-6f) {
          const float a = rng.Unit() * 2.0f * kPi;
          dx = std::cos(a);
          dz = std::sin(a);
          len = 1.0f;
        }
        dx /= len;
        dz /= len;
        px += dx;
        pz += dz;
        const int nx = static_cast<int>(px);
        const int nz = static_cast<int>(pz);
        const bool leaves = px < 0.0f || pz < 0.0f || nx >= w - 1 || nz >= h - 1;
        float newHeight;
        if (leaves) {
          newHeight = height; // runs off the map: ends here
        } else {
          const float ex = px - static_cast<float>(nx);
          const float ez = pz - static_cast<float>(nz);
          const std::size_t j = Ix(nx, nz, w);
          newHeight = hs[j] * (1.0f - ex) * (1.0f - ez) + hs[j + 1] * ex * (1.0f - ez) + hs[j + w] * (1.0f - ex) * ez +
            hs[j + w + 1] * ex * ez;
        }
        if (leaves)
          return; // runs off the map with its sediment
        const float dh = newHeight - height;
        const float cap = std::max(-dh, p.min_slope * cell) * speed * water * p.capacity;
        if (g.flow != nullptr)
          (*g.flow)[i00] += water;
        if (sediment > cap || dh > 0.0f) {
          const float amount = dh > 0.0f ? std::min(dh, sediment) : (sediment - cap) * p.deposit;
          sediment -= Settle(t, hs, g, w, i00, fx, fz, amount, cell);
        } else {
          float amount = std::min((cap - sediment) * p.erode, -dh);
          // inside a filled basin the droplet runs on the spill surface above the real ground: nothing to dissolve
          // there (the rim at the outlet is eroded, so the basin drains)
          const float ground = t[i00] * (1.0f - fx) * (1.0f - fz) + t[i00 + 1] * fx * (1.0f - fz) +
            t[i00 + w] * (1.0f - fx) * fz + t[i00 + w + 1] * fx * fz;
          if (height - ground > 0.03f * cell || life < 2)
            amount = 0.0f; // (a droplet picks up nothing in its first steps: no craters where it lands)
          if (amount > 0.0f && p.demand != nullptr)
            amount *= (*p.demand)[i00];
          if (amount > 0.0f) {
            // The brush is a full disc whose weights add up to one; the part that lies outside the map is reflected at
            // the edge (cell -1 is cell 1, cell w is cell w - 2, ...), so a cell on the border is dug as deep as one
            // inside. Without it the border would take half the digging (a lip stands there) and, once the disc were
            // clipped and renormalised, twice as much.
            float wsum = 0.0f;
            for (int oz = -R; oz <= R; ++oz) {
              for (int ox = -R; ox <= R; ++ox) {
                const float d = std::sqrt(static_cast<float>(ox * ox + oz * oz));
                if (d < static_cast<float>(R) + 0.5f)
                  wsum += static_cast<float>(R) + 0.5f - d;
              }
            }
            if (wsum > 0.0f) {
              float taken = 0.0f;
              for (int oz = -R; oz <= R; ++oz) {
                for (int ox = -R; ox <= R; ++ox) {
                  const float d = std::sqrt(static_cast<float>(ox * ox + oz * oz));
                  if (d >= static_cast<float>(R) + 0.5f)
                    continue;
                  const int cx = Reflect(ix + ox, w), cz = Reflect(iz + oz, h);
                  if (cx < 0 || cz < 0)
                    continue;
                  const std::size_t j = Ix(cx, cz, w);
                  const float k = (rock != nullptr ? Clamp01((*rock)[j]) : 1.0f);
                  // no cell goes deeper than `round_cut` below the surface the round started with: runaway holes where
                  // many droplets meet cannot form
                  const float a = std::min(
                    amount * (static_cast<float>(R) + 0.5f - d) / wsum * k,
                    std::max(0.0f, t[j] - (hs[j] - p.round_cut * cell))
                  );
                  t[j] -= a;
                  taken += a;
                  if (g.wear != nullptr)
                    (*g.wear)[j] += a;
                }
              }
              sediment += taken;
            }
          }
        }
        // accel 1: the droplet speeds up going down (v^2 grows by the drop times gravity); accel 0 is the old rule,
        // which slowed it down on the way down (v^2 + dh * gravity with dh < 0), so on any real slope the speed fell to
        // 0 within a step or two, the capacity with it, and nothing was dug (the droplets only scratched the first
        // cells of their run)
        speed = std::sqrt(std::max(0.0f, speed * speed + dh * p.gravity / cell * (1.0f - 2.0f * p.accel)));
        water *= (1.0f - p.evaporate);
      }
      // the rest settles where the droplet stopped (within the room the spill surface leaves)
      if (sediment > 0.0f) {
        const int ix = std::max(0, std::min(w - 2, static_cast<int>(px)));
        const int iz = std::max(0, std::min(h - 2, static_cast<int>(pz)));
        Settle(t, hs, g, w, Ix(ix, iz, w), px - static_cast<float>(ix), pz - static_cast<float>(iz), sediment, cell);
      }
    }

    void BlurPass(std::vector<float>& v, std::vector<float>& tmp, int w, int h);

    /**
     * Hillslope creep: diffuses the change `t - t0` the droplets have made so far (a few binomial smoothing passes,
     * fractions blend the next pass in); the input's own relief is not touched, and `rock` (erodibility 0..1, optional)
     * keeps protected ground as it is. Without it the droplets dig lines and nothing ever lowers the ground between two
     * lines: the ridges between the grooves stay at their old height, the next round's droplets are caught by the
     * deepened grooves, and the terrain turns into a comb (a main ridge with evenly spaced parallel grooves, razor
     * thin, which grow deeper and deeper with every run while the rest of the slope stays smooth). With creep the walls
     * slump into the groove as they steepen, so a groove widens into a rounded valley, spurs between valleys round off,
     * and the erosion spreads over the whole slope.
     */
    void Creep(
      std::vector<float>& t,
      const std::vector<float>& t0,
      const std::vector<float>* rock,
      const int w,
      const int h,
      const float passes,
      std::vector<float>& d,
      std::vector<float>& sm,
      std::vector<float>& tmp
    )
    {
      const std::size_t n = t.size();
      d.resize(n);
      tmp.resize(n);
      for (std::size_t i = 0; i < n; ++i)
        d[i] = t[i] - t0[i];
      sm = d;
      const int whole = static_cast<int>(passes);
      for (int b = 0; b < whole; ++b)
        BlurPass(sm, tmp, w, h);
      const float frac = passes - static_cast<float>(whole);
      if (frac > 0.0f) {
        std::vector<float> prev = sm;
        BlurPass(sm, tmp, w, h);
        for (std::size_t i = 0; i < n; ++i)
          sm[i] = prev[i] + frac * (sm[i] - prev[i]);
      }
      for (std::size_t i = 0; i < n; ++i)
        t[i] += (rock != nullptr ? Clamp01((*rock)[i]) : 1.0f) * (sm[i] - d[i]);
    }

    void RunDroplets(
      std::vector<float>& t,
      const int w,
      const int h,
      const float cell,
      const DropParams& p,
      const std::vector<float>* rock,
      DropGrids& g
    )
    {
      if (w < 4 || h < 4)
        return;
      const int reach = (p.drop_vary > 0.0f ? MaxLife(p) : p.lifetime) +
        (p.drop_vary > 0.0f
           ? std::min(kMaxRadius, static_cast<int>(std::ceil(static_cast<float>(p.radius) * (1.0f + p.drop_vary))))
           : p.radius) +
        3;
      const int tile = std::max(48, 2 * reach + 2);
      const int tx = (w + tile - 1) / tile;
      const int tz = (h + tile - 1) / tile;
      const int rounds = std::max(1, p.rounds);
      std::vector<float> steer;
      // creep per round: the share of the change a round adds is density / rounds, so the smoothing per round follows
      // it (density 2 and 32 rounds = p.creep passes); at most 48 passes
      const float creepPasses =
        std::min(48.0f, std::max(0.0f, p.creep) * (p.density * 0.5f) * (32.0f / static_cast<float>(rounds)));
      std::vector<float> t0, cd, cs, ct;
      if (creepPasses > 0.0f)
        t0 = t;
      for (int round = 0; round < rounds; ++round) {
        if (p.drain_pits > 0.0f)
          FillSurface(t, w, h, 0.004f * cell, steer);
        const std::vector<float>& hs = p.drain_pits > 0.0f ? steer : t;
        for (int colour = 0; colour < 4; ++colour) {
          std::vector<int> tiles;
          for (int j = 0; j < tz; ++j) {
            for (int i = 0; i < tx; ++i) {
              if ((i & 1) + 2 * (j & 1) == colour)
                tiles.push_back(j * tx + i);
            }
          }
          ParallelFor(static_cast<int>(tiles.size()), [&](const int k) {
            const int id = tiles[static_cast<std::size_t>(k)];
            const int i = id % tx, j = id / tx;
            const int bx0 = i * tile, bz0 = j * tile;
            const int bw = std::min(tile, w - bx0), bh = std::min(tile, h - bz0);
            const double want = static_cast<double>(p.density) * static_cast<double>(bw) * static_cast<double>(bh) /
              static_cast<double>(rounds);
            Rng rng(Mix(p.seed, static_cast<std::uint64_t>(round), static_cast<std::uint64_t>(id)));
            int count = static_cast<int>(want);
            if (static_cast<double>(rng.Unit()) < want - count)
              ++count;
            for (int c = 0; c < count; ++c) {
              const double x0 = bx0 + static_cast<double>(rng.Unit()) * (bw - 1);
              const double z0 = bz0 + static_cast<double>(rng.Unit()) * (bh - 1);
              if (p.accept != nullptr) {
                const float u = rng.Unit();
                if (u > (*p.accept)[Ix(static_cast<int>(x0 + 0.5), static_cast<int>(z0 + 0.5), w)])
                  continue;
              }
              RunDroplet(t, hs, w, h, cell, p, rock, g, rng, x0, z0);
            }
          });
        }
        if (creepPasses > 0.0f)
          Creep(t, t0, rock, w, h, creepPasses, cd, cs, ct);
      }
    }

    // ---- stream power incision
    // ------------------------------------------------------------------------------------------------------------------

    struct StreamParams
    {
      int iterations = 10;
      float k = 0.05f; // erodibility: F = k * (drainage area - area_min)^m; one iteration removes F / (1 + F) * max_cut
                       // of the drop to the lowest neighbour (small streams a little, big rivers up to max_cut: the
                       // share saturates smoothly, so a river twice the size cuts visibly faster instead of every
                       // channel cutting at max_cut like a hard cap would)
      float m = 0.5f;  // drainage area exponent
      float spread = 1.0f; // multiple flow direction exponent: 1 spreads the water over all lower neighbours by slope,
                           // large = single steepest direction
      float diffusion = 0.2f; // thermal rate for the hillslopes between iterations
      float talus = 0.7f;
      float uplift = 0.0f;  // height added to the interior per iteration
      float max_cut = 0.5f; // at most this share of the drop to the lowest neighbour is removed per iteration
      float area_min =
        24.0f; // drainage area (cells) below which nothing is incised: only real channels, the slopes keep their shape
      int widen = 1; // the incision is smoothed this many times (3 x 3 binomial) before it is applied: wider channels
                     // (the smallest streams)
      float width_vary = 1.0f; // 0..1: bigger rivers get a wider valley: one more smoothing pass for a catchment of 48
                               // cells, two for 240, three for 1008, four for 4080 (1 = all four, 0.5 = the first two,
                               // 0 = none): small streams stay narrow gullies, rivers get valleys
      int route_every = 1; // the drainage network (pit breaching, flow routing, catchments) is recomputed every this
                           // many iterations; in between the incision follows the network of the last one (the channels
                           // move slowly: 2 - 3 give nearly the same result at half the cost)
      bool breach = true;  // closed depressions are drained by cutting their lowest rim (false: they stay, and no river
                           // crosses them)
      float jitter = 0.0f; // the flow is routed over the terrain plus smooth noise of this height (in cells of rise per
                           // cell): rivers pick their own paths, branch and meander instead of running straight down
                           // smooth slopes side by side; the ground itself gets no noise
      std::uint32_t seed = 1;
    };

    /** Cell indices by descending value, equal values by ascending index (LSD radix sort on the float bit patterns:
     * stable, O(n)). */
    void SortDescending(
      const std::vector<float>& v,
      std::vector<std::uint32_t>& order
    )
    {
      const std::size_t n = v.size();
      std::vector<std::uint32_t> key(n), tmpKey(n), tmpOrder(n);
      order.resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t u;
        std::memcpy(&u, &v[i], sizeof(u));
        u = (u & 0x80000000u) ? ~u : (u | 0x80000000u); // ascending order of the float value
        key[i] = ~u;                                    // descending
        order[i] = static_cast<std::uint32_t>(i);
      }
      for (int shift = 0; shift < 32; shift += 8) {
        std::size_t count[257] = {};
        for (std::size_t i = 0; i < n; ++i)
          ++count[((key[i] >> shift) & 0xFF) + 1];
        for (int b = 0; b < 256; ++b)
          count[b + 1] += count[b];
        for (std::size_t i = 0; i < n; ++i) {
          const std::size_t dst = count[(key[i] >> shift) & 0xFF]++;
          tmpKey[dst] = key[i];
          tmpOrder[dst] = order[i];
        }
        key.swap(tmpKey);
        order.swap(tmpOrder);
      }
    }

    /**
     * Drainage network of the pit filled terrain: `fill` is the filled surface (FillSurface), cells are visited from
     * the highest down (equal heights by index) and pass their catchment (1 + everything above) to their lower
     * neighbours (multiple flow direction: shares proportional to slope^spread); `slope` receives the steepest drop per
     * unit distance of every cell. Edge cells are outlets. Sequential and ordered: deterministic.
     */
    void Drainage(
      const std::vector<float>& fill,
      const int w,
      const int h,
      const float cell,
      const float spread,
      std::vector<float>& area,
      std::vector<float>& slope,
      const std::vector<float>* rain = nullptr
    )
    {
      static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
      static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
      const std::size_t n = fill.size();
      std::vector<std::uint32_t> order;
      SortDescending(fill, order);
      if (rain != nullptr && rain->size() == n)
        area = *rain; // the water every cell makes (default 1)
      else
        area.assign(n, 1.0f);
      slope.assign(n, 0.0f);
      for (std::size_t k = 0; k < n; ++k) {
        const std::uint32_t c = order[k];
        const int cx = static_cast<int>(c % static_cast<std::uint32_t>(w));
        const int cz = static_cast<int>(c / static_cast<std::uint32_t>(w));
        float s[8];
        std::uint32_t id[8];
        int count = 0;
        float sum = 0.0f, best = 0.0f;
        for (int d = 0; d < 8; ++d) {
          const int nx = cx + dxs[d], nz = cz + dzs[d];
          if (nx < 0 || nz < 0 || nx >= w || nz >= h)
            continue;
          const std::uint32_t j = static_cast<std::uint32_t>(Ix(nx, nz, w));
          const float drop = (fill[c] - fill[j]) / (static_cast<float>(d < 4 ? 1.0 : 1.41421356) * cell);
          if (drop <= 0.0f)
            continue;
          best = std::max(best, drop);
          const float wgt = spread == 1.0f ? drop : std::pow(drop, spread);
          s[count] = wgt;
          id[count] = j;
          sum += wgt;
          ++count;
        }
        slope[c] = best;
        if (count > 0 && sum > 0.0f) {
          const float a = area[c] / sum;
          for (int q = 0; q < count; ++q)
            area[id[q]] += a * s[q];
        }
      }
    }

    /** One 3 x 3 binomial smoothing pass of `v` (rows then columns, edge samples clamp); `tmp` is scratch. */
    void BlurPass(
      std::vector<float>& v,
      std::vector<float>& tmp,
      const int w,
      const int h
    )
    {
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const int xl = std::max(0, x - 1), xr = std::min(w - 1, x + 1);
            tmp[Ix(x, z, w)] = 0.25f * v[Ix(xl, z, w)] + 0.5f * v[Ix(x, z, w)] + 0.25f * v[Ix(xr, z, w)];
          }
        }
      });
      Rows(w, h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          const int zu = std::max(0, z - 1), zd = std::min(h - 1, z + 1);
          for (int x = 0; x < w; ++x)
            v[Ix(x, z, w)] = 0.25f * tmp[Ix(x, zu, w)] + 0.5f * tmp[Ix(x, z, w)] + 0.25f * tmp[Ix(x, zd, w)];
        }
      });
    }

    void RunStream(
      std::vector<float>& t,
      const int w,
      const int h,
      const float cell,
      const StreamParams& p,
      const std::vector<float>* rock,
      std::vector<float>& wear,
      std::vector<float>& area,
      const std::vector<float>* rain = nullptr,
      const std::vector<float>* slideRate = nullptr
    )
    {
      if (w < 3 || h < 3)
        return;
      const std::size_t n = t.size();
      std::vector<float> fill, slope, inc(n), tmp(n), jit, noisy, accum;
      std::vector<std::uint8_t> band(n);
      if (p.jitter > 0.0f)
        NoiseField(jit, w, h, cell, 4.0f * cell, p.seed * 7u + 3u, 2);
      const std::vector<float>* ref = &t; // the surface the flow is routed on and the filled surface is compared with
      ThermalScratch tsc;
      const std::vector<float> none;
      const std::vector<float>& slide = slideRate != nullptr ? *slideRate : none;
      // the centre weight of the 1D binomial kernel after j passes: a line smoothed j times keeps this share of its
      // depth, the amount is scaled back up so `k` keeps its meaning (depth)
      static const float kCentre[9] = {
        1.0f, 0.5f, 0.375f, 0.3125f, 0.2734375f, 0.24609375f, 0.2255859375f, 0.20947265625f, 0.196380615234375f
      };
      const int widen = std::max(0, std::min(8, p.widen));
      const int grow = std::min(
        8 - widen, static_cast<int>(std::floor(4.0f * p.width_vary + 0.5f))
      ); // the most extra smoothing passes of the biggest rivers
      const int passesMax = widen + grow;
      const int every = std::max(1, p.route_every);
      for (int it = 0; it <= p.iterations; ++it) {
        if (it % every == 0 || it == p.iterations) {
          if (p.breach) {
            tmp = t;
            BreachPits(t, w, h, 0.002f * cell, fill, 0.004f * cell);
            for (std::size_t i = 0; i < n; ++i)
              wear[i] += tmp[i] - t[i];
          } else {
            FillSurface(t, w, h, 0.004f * cell, fill);
          }
          if (p.jitter > 0.0f) {
            noisy.resize(n);
            for (std::size_t i = 0; i < n; ++i)
              noisy[i] = t[i] + (jit[i] - 0.5f) * p.jitter * cell;
            FillSurface(noisy, w, h, 0.004f * cell, fill);
            ref = &noisy;
          }
          Drainage(fill, w, h, cell, p.spread, area, slope, rain);
        }
        if (it == p.iterations)
          break;
        // incision: where the ground lies on the (filled) surface and drains. F = k * (area - area_min)^m grows with
        // the catchment; the share F / (1 + F) of max_cut of the drop to the lowest neighbour is removed (a graded
        // river: it can never dig below its neighbours)
        Rows(w, h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i = Ix(x, z, w);
              float v = 0.0f;
              std::uint8_t b = 0;
              if (
                x > 0 && z > 0 && x < w - 1 && z < h - 1 && area[i] > p.area_min && fill[i] - (*ref)[i] < 0.03f * cell
              ) {
                float low = t[i];
                low = std::min(low, std::min(std::min(t[i - 1], t[i + 1]), std::min(t[i - w], t[i + w])));
                const float ad = area[i] - p.area_min;
                const float f = p.k * (p.m == 0.5f ? std::sqrt(ad) : std::pow(ad, p.m));
                float share = p.max_cut * f / (1.0f + f);
                if (rock != nullptr)
                  share *= Clamp01((*rock)[i]);
                v = share * std::max(0.0f, t[i] - low);
                if (grow > 0)
                  b = static_cast<std::uint8_t>(
                    (ad >= 48.0f ? 1 : 0) + (ad >= 240.0f ? 1 : 0) + (ad >= 1008.0f ? 1 : 0) + (ad >= 4080.0f ? 1 : 0)
                  ); // = floor(log4(1 + ad / 16)): no libm in the golden
                if (b > grow)
                  b = static_cast<std::uint8_t>(grow);
              }
              inc[i] = v;
              band[i] = b;
            }
          }
        });
        // valley width: the incision of a band is smoothed (widen + band) times, Horner style: one pass over the map
        // per smoothing pass in total, the biggest rivers are smoothed the most
        if (passesMax > 0) {
          std::vector<float>& acc = accum;
          acc.assign(n, 0.0f);
          for (int j = passesMax; j >= 0; --j) {
            if (j < passesMax)
              BlurPass(acc, tmp, w, h);
            const int bandHere = j - widen; // the cells whose total number of passes is j
            const float scale = 1.0f / kCentre[j];
            if (bandHere >= 0 && bandHere <= grow) {
              for (std::size_t i = 0; i < n; ++i)
                if (static_cast<int>(band[i]) == bandHere)
                  acc[i] += inc[i] * scale;
            }
          }
          inc = acc;
        }
        for (int z = 0; z < h; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i = Ix(x, z, w);
            if (x == 0 || z == 0 || x == w - 1 || z == h - 1) {
              t[i] += p.uplift; // the edge cells are outlets and are not cut, but they rise with the rest (else the
                                // uplift stands as a wall at the border)
              continue;
            }
            // a cell never drops below its lowest neighbour: incision cannot go below base level and does not dig pits
            const float low = std::min(std::min(std::min(t[i - 1], t[i + 1]), std::min(t[i - w], t[i + w])), t[i]);
            const float cut = std::min(inc[i], t[i] - low);
            t[i] += p.uplift - cut;
            wear[i] += cut;
          }
        }
        if (p.diffusion > 0.0f)
          ThermalImpl(t, w, h, cell, p.talus, p.diffusion, slide, 0, tsc);
      }
    }

    /** Smooths the change `after - before` with a 3 x 3 binomial kernel, `amount` 0..1 blends the smoothed change in (1
     * = fully smoothed): takes the cell scale noise out of an erosion result and keeps its structure. */
    void SmoothDelta(
      const std::vector<float>& before,
      std::vector<float>& after,
      const int w,
      const int h,
      const float amount,
      const int passes,
      const bool pinnedEdge = false
    )
    {
      if (amount <= 0.0f || passes <= 0)
        return;
      const std::size_t n = before.size();
      std::vector<float> d(n), tmp(n);
      for (std::size_t i = 0; i < n; ++i)
        d[i] = after[i] - before[i];
      std::vector<float> sm = d;
      for (int pass = 0; pass < passes; ++pass) {
        Rows(w, h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const int xl = std::max(0, x - 1), xr = std::min(w - 1, x + 1);
              tmp[Ix(x, z, w)] = 0.25f * sm[Ix(xl, z, w)] + 0.5f * sm[Ix(x, z, w)] + 0.25f * sm[Ix(xr, z, w)];
            }
          }
        });
        Rows(w, h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const int zu = std::max(0, z - 1), zd = std::min(h - 1, z + 1);
            for (int x = 0; x < w; ++x)
              sm[Ix(x, z, w)] = 0.25f * tmp[Ix(x, zu, w)] + 0.5f * tmp[Ix(x, z, w)] + 0.25f * tmp[Ix(x, zd, w)];
          }
        });
      }
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          const std::size_t i = Ix(x, z, w);
          // only a pinned edge keeps its own change (it stays untouched); an edge that takes part is smoothed like the
          // rest, else its change would differ from its neighbours' by the noise
          const bool edge = pinnedEdge && (x == 0 || z == 0 || x == w - 1 || z == h - 1);
          after[i] = before[i] + (edge ? d[i] : d[i] + amount * (sm[i] - d[i]));
        }
      }
    }

    // ---- ops
    // --------------------------------------------------------------------------------------------------------------------------------------

    struct Results
    {
      Grid height, wear, deposit, flow, water, sediment;
    };

    Grid Shaped(
      const Grid& like
    )
    {
      return Grid(like.w, like.h, like.cell, like.ox, like.oz);
    }

    bool Emit(
      const OpArgs& a,
      Results& r,
      Grid& out,
      std::string& err
    )
    {
      const std::string which = a.p.S("output", "height");
      if (a.extra != nullptr) {
        // drainage accumulation of the result as a 0..1 mask: log2 of the catchment (cells) over log2 of `accum_range`
        if (a.p.N("masks", 1.0) != 0.0) {
          std::vector<float> fill, area, slope;
          FillSurface(r.height.v, r.height.w, r.height.h, 0.004f * r.height.cell, fill);
          Drainage(fill, r.height.w, r.height.h, r.height.cell, 1.0f, area, slope);
          Grid acc = Shaped(r.height);
          const float inv = 1.0f / std::log2(std::max(4.0f, static_cast<float>(a.p.N("accum_range", 4000.0))));
          for (std::size_t i = 0; i < area.size(); ++i)
            acc.v[i] = Clamp01(std::log2(std::max(1.0f, area[i])) * inv);
          (*a.extra)["accum"] = std::move(acc);
        }
        (*a.extra)["wear"] = r.wear;
        (*a.extra)["deposit"] = r.deposit;
        (*a.extra)["flow"] = r.flow;
        (*a.extra)["water"] = r.water;
        (*a.extra)["sediment"] = r.sediment;
      }
      if (which == "height")
        out = std::move(r.height);
      else if (which == "wear")
        out = std::move(r.wear);
      else if (which == "deposit")
        out = std::move(r.deposit);
      else if (which == "flow")
        out = std::move(r.flow);
      else if (which == "water")
        out = std::move(r.water);
      else if (which == "sediment")
        out = std::move(r.sediment);
      else {
        err = "unknown output '" + which + "' (height wear deposit flow water sediment)";
        return false;
      }
      return true;
    }

    const Grid* NeedA(
      const OpArgs& a,
      std::string& err
    )
    {
      const auto it = a.in.find("a");
      if (it == a.in.end()) {
        err = "missing input 'a'";
        return nullptr;
      }
      const auto m = a.in.find("mask");
      if (m != a.in.end() && !m->second->SameShape(*it->second)) {
        err = "the mask differs in size";
        return nullptr;
      }
      return it->second.get();
    }

    const std::vector<float>* RockOf(
      const OpArgs& a
    )
    {
      const auto m = a.in.find("mask");
      return m != a.in.end() ? &m->second->v : nullptr;
    }

    /**
     * What makes one run different from place to place (all optional, all off by default = the uniform behaviour the
     * solvers always had): vary / vary_scale   erodibility is multiplied by 1 - vary * noise (noise 0..1 of feature
     * size vary_scale world units): hard and soft ground side by side rain_vary           the water every place gets
     * varies by +- rain_vary (hydraulic rain, droplet release probability, stream catchment) protect erodibility is
     * multiplied by 1 - protect * (ridge / summit map): ridges and high ground keep their shape The input mask
     * (erodibility 0..1) multiplies with all of it.
     */
    struct Factors
    {
      std::vector<float> rock, rain, accept, thermal, soft;
      const std::vector<float>* rockPtr = nullptr;
      const std::vector<float>* softPtr = nullptr; // the hardness from vary / protect alone (no input mask): scales
                                                   // what a droplet takes up, not only where it takes it from
      const std::vector<float>* thermalPtr =
        nullptr; // thermal slide rate factor: ridges and summits (protect) slide less; empty = no mask
      Factors() = default;
      Factors(const Factors&) = delete;
      Factors& operator=(const Factors&) = delete;
    };

    void BuildFactors(
      const OpArgs& a,
      const Grid& src,
      Factors& f
    )
    {
      const float vary = Clamp01(static_cast<float>(a.p.N("vary", 0.0)));
      const float protect = Clamp01(static_cast<float>(a.p.N("protect", 0.0)));
      const float rainVary = Clamp01(static_cast<float>(a.p.N("rain_vary", 0.0)));
      const std::uint32_t seed = static_cast<std::uint32_t>(a.p.N("seed", 1.0));
      const std::size_t n = src.v.size();
      f.rockPtr = RockOf(a);
      if (vary > 0.0f || protect > 0.0f) {
        f.rock.assign(n, 1.0f);
        f.soft.assign(n, 1.0f);
        if (f.rockPtr != nullptr)
          f.rock = *f.rockPtr;
        std::vector<float> m;
        if (vary > 0.0f) {
          NoiseField(m, src.w, src.h, src.cell, std::max(2.0f, static_cast<float>(a.p.N("vary_scale", 60.0))), seed, 3);
          for (std::size_t i = 0; i < n; ++i) {
            // a contrast curve: more clearly hard and clearly soft ground than the plain noise has (which is mostly in
            // between)
            const float c = Clamp01((m[i] - 0.2f) * (1.0f / 0.6f));
            const float hard = c * c * (3.0f - 2.0f * c);
            f.rock[i] *= 1.0f - vary * hard;
            f.soft[i] *= 1.0f - vary * hard;
          }
        }
        if (protect > 0.0f) {
          RidgeMap(src.v, src.w, src.h, src.cell, m);
          f.thermal.resize(n);
          for (std::size_t i = 0; i < n; ++i) {
            f.rock[i] *= 1.0f - protect * m[i];
            f.soft[i] *= 1.0f - protect * m[i];
            f.thermal[i] = 1.0f - protect * m[i];
          }
          f.thermalPtr = &f.thermal;
        }
        f.rockPtr = &f.rock;
        f.softPtr = &f.soft;
      }
      if (rainVary > 0.0f) {
        std::vector<float> m;
        NoiseField(
          m,
          src.w,
          src.h,
          src.cell,
          std::max(2.0f, 0.5f * static_cast<float>(a.p.N("vary_scale", 60.0))),
          seed * 5u + 11u,
          3
        );
        f.rain.resize(n);
        f.accept.resize(n);
        for (std::size_t i = 0; i < n; ++i) {
          f.rain[i] = 1.0f + rainVary * (2.0f * m[i] - 1.0f);
          f.accept[i] = 1.0f - rainVary * m[i];
        }
      }
    }

    /**
     * After the run: `conserve` (0..1) puts the share of the volume the run lost (sediment that left over the edge, was
     * not placed, or a river carried off) back where material settles (the deposit map, else the low ground), or takes
     * a gain off where it was dug; `keep_range` (1) stretches the result so its lowest and highest point are those of
     * the input again; `max_change` (units, 0 = off) limits how far any sample may move from the input. In this order.
     */
    void PostProcess(
      const OpArgs& a,
      const std::vector<float>& before,
      std::vector<float>& after,
      const std::vector<float>* deposit,
      const std::vector<float>* wear
    )
    {
      const std::size_t n = before.size();
      if (n == 0 || after.size() != n)
        return;
      const float conserve = Clamp01(static_cast<float>(a.p.N("conserve", 0.0)));
      if (conserve > 0.0f) {
        double v = 0.0;
        for (std::size_t i = 0; i < n; ++i)
          v += static_cast<double>(before[i]) - after[i];
        v *= conserve;
        const bool lost = v > 0.0;
        const std::vector<float>* pick = lost ? deposit : wear;
        std::vector<float> w(n);
        float lo = before[0], hi = before[0];
        for (const float x : before) {
          lo = std::min(lo, x);
          hi = std::max(hi, x);
        }
        double sum = 0.0;
        const bool useMap = pick != nullptr && pick->size() == n;
        double mapSum = 0.0;
        if (useMap)
          for (const float x : *pick)
            mapSum += x;
        for (std::size_t i = 0; i < n; ++i) {
          const float rel = (before[i] - lo) / std::max(1e-6f, hi - lo);
          const float low = lost ? (1.0f - rel) * (1.0f - rel) : rel * rel;
          w[i] = (useMap && mapSum > 1e-9) ? (*pick)[i] : low;
          sum += w[i];
        }
        if (sum > 1e-12) {
          const double k = v / sum;
          for (std::size_t i = 0; i < n; ++i)
            after[i] += static_cast<float>(k * w[i]);
        }
      }
      if (a.p.N("keep_range", 0.0) != 0.0) {
        // the robust range: the lowest / highest 0.25% of the samples are ignored, so one filled pit or one lone peak
        // does not decide the stretch; afterwards nothing leaves the input's range
        const auto robust = [n](const std::vector<float>& v, float& lo, float& hi) {
          std::vector<float> c = v;
          const std::size_t k = std::min(n / 2, static_cast<std::size_t>(static_cast<double>(n) * 0.0025));
          std::nth_element(c.begin(), c.begin() + static_cast<std::ptrdiff_t>(k), c.end());
          lo = c[k];
          std::nth_element(c.begin(), c.begin() + static_cast<std::ptrdiff_t>(n - 1 - k), c.end());
          hi = c[n - 1 - k];
        };
        float lo0, hi0, lo1, hi1;
        robust(before, lo0, hi0);
        robust(after, lo1, hi1);
        float minB = before[0], maxB = before[0];
        for (const float x : before) {
          minB = std::min(minB, x);
          maxB = std::max(maxB, x);
        }
        if (hi1 - lo1 > 1e-6f) {
          const float k = (hi0 - lo0) / (hi1 - lo1);
          for (std::size_t i = 0; i < n; ++i)
            after[i] = std::max(minB, std::min(maxB, lo0 + (after[i] - lo1) * k));
        }
      }
      const float cap = static_cast<float>(a.p.N("max_change", 0.0));
      if (cap > 0.0f) {
        for (std::size_t i = 0; i < n; ++i)
          after[i] = before[i] + std::max(-cap, std::min(cap, after[i] - before[i]));
      }
    }

    HydroParams HydroOf(
      const OpArgs& a
    )
    {
      HydroParams p;
      p.iterations = std::max(0, std::min(20000, static_cast<int>(a.p.N("iterations", p.iterations))));
      p.rain = static_cast<float>(a.p.N("rain", p.rain));
      p.evaporation = static_cast<float>(a.p.N("evaporation", p.evaporation));
      p.gain = static_cast<float>(a.p.N("gain", p.gain));
      p.capacity = static_cast<float>(a.p.N("capacity", p.capacity));
      p.erosion = static_cast<float>(a.p.N("erosion", p.erosion));
      p.deposition = static_cast<float>(a.p.N("deposition", p.deposition));
      p.depth_max = static_cast<float>(a.p.N("depth_max", p.depth_max));
      p.min_slope = static_cast<float>(a.p.N("min_slope", p.min_slope));
      p.max_speed = static_cast<float>(a.p.N("max_speed", p.max_speed));
      p.cut_limit = static_cast<float>(a.p.N("cut_limit", p.cut_limit));
      p.talus = static_cast<float>(a.p.N("talus", p.talus));
      p.thermal = static_cast<float>(a.p.N("thermal", p.thermal));
      p.thermal_every = static_cast<int>(a.p.N("thermal_every", p.thermal_every));
      // edge: open (default: the edge cells take part and water runs out over the map edge), closed (walls), pinned
      // (the outer ring keeps its height: the old behaviour, leaves a step at the border)
      const std::string edge = a.p.S("edge", "open");
      p.pin_border = edge == "pinned";
      p.open_edge = edge != "closed";
      p.settle = a.p.N("settle", 1.0) != 0.0;
      p.track = a.p.N("masks", 1.0) != 0.0;
      return p;
    }

    bool OpHydraulic(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = NeedA(a, err);
      if (src == nullptr)
        return false;
      const HydroParams p = HydroOf(a);
      HydroState st;
      st.Allocate(src->w, src->h, src->cell);
      st.t = src->v;
      Factors fac;
      BuildFactors(a, *src, fac);
      if (fac.rockPtr != nullptr)
        st.rock = *fac.rockPtr;
      if (!fac.rain.empty())
        st.rain_rate = fac.rain;
      if (fac.thermalPtr != nullptr)
        st.thermal_rate = *fac.thermalPtr;
      RunHydro(st, p, p.iterations);
      SmoothDelta(
        src->v,
        st.t,
        src->w,
        src->h,
        static_cast<float>(a.p.N("smooth", 1.0)),
        static_cast<int>(a.p.N("smooth_passes", 1)),
        p.pin_border
      );
      if (p.open_edge && !p.pin_border)
        MirrorEdgeChange(src->v, st.t, src->w, src->h, 0);
      PostProcess(a, src->v, st.t, &st.dep, &st.wear);
      Results r;
      r.height = Shaped(*src);
      r.height.v = st.t;
      r.wear = Shaped(*src);
      r.wear.v = st.wear;
      r.deposit = Shaped(*src);
      r.deposit.v = st.dep;
      r.flow = Shaped(*src);
      r.flow.v = st.flow;
      r.water = Shaped(*src);
      r.water.v = st.d;
      r.sediment = Shaped(*src);
      r.sediment.v = st.s;
      return Emit(a, r, out, err);
    }

    bool OpDroplet(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = NeedA(a, err);
      if (src == nullptr)
        return false;
      DropParams p = DropletParamsOf(a);
      Factors fac;
      BuildFactors(a, *src, fac);
      p.demand = fac.softPtr;
      if (!fac.accept.empty()) {
        // the thinned release keeps the mean density: more candidates where it is accepted less
        double mean = 0.0;
        for (const float x : fac.accept)
          mean += x;
        mean /= static_cast<double>(fac.accept.size());
        p.density = static_cast<float>(p.density / std::max(0.05, mean));
        p.accept = &fac.accept;
      }
      Results r;
      r.height = *src;
      r.wear = Shaped(*src);
      r.deposit = Shaped(*src);
      r.flow = Shaped(*src);
      r.water = Shaped(*src);
      r.sediment = Shaped(*src);
      DropGrids g{&r.wear.v, &r.deposit.v, &r.flow.v};
      RunDroplets(r.height.v, src->w, src->h, src->cell, p, fac.rockPtr, g);
      SmoothDelta(
        src->v,
        r.height.v,
        src->w,
        src->h,
        static_cast<float>(a.p.N("smooth", 1.0)),
        static_cast<int>(a.p.N("smooth_passes", 2))
      );
      const float thermal = static_cast<float>(a.p.N("thermal", 0.0));
      const int steps = std::max(0, std::min(1000, static_cast<int>(a.p.N("thermal_steps", 0.0))));
      if (thermal > 0.0f && steps > 0) {
        ThermalScratch sc;
        const std::vector<float> none;
        const std::vector<float>& rate = fac.thermalPtr != nullptr ? *fac.thermalPtr : none;
        for (int i = 0; i < steps; ++i)
          ThermalImpl(
            r.height.v, src->w, src->h, src->cell, static_cast<float>(a.p.N("talus", 0.8)), thermal, rate, 0, sc
          );
      }
      PostProcess(a, src->v, r.height.v, &r.deposit.v, &r.wear.v);
      return Emit(a, r, out, err);
    }

    bool OpStream(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = NeedA(a, err);
      if (src == nullptr)
        return false;
      StreamParams p;
      p.iterations = std::max(0, std::min(1000, static_cast<int>(a.p.N("iterations", p.iterations))));
      p.k = static_cast<float>(a.p.N("k", p.k));
      p.m = static_cast<float>(a.p.N("m", p.m));
      p.diffusion = static_cast<float>(a.p.N("diffusion", p.diffusion));
      p.talus = static_cast<float>(a.p.N("talus", p.talus));
      p.uplift = static_cast<float>(a.p.N("uplift", p.uplift));
      p.max_cut = static_cast<float>(a.p.N("max_cut", p.max_cut));
      p.area_min = static_cast<float>(a.p.N("area_min", p.area_min));
      p.widen = std::max(0, std::min(8, static_cast<int>(a.p.N("widen", p.widen))));
      p.width_vary = Clamp01(static_cast<float>(a.p.N("width_vary", p.width_vary)));
      p.route_every = std::max(1, std::min(16, static_cast<int>(a.p.N("route_every", p.route_every))));
      p.spread = std::max(0.1f, static_cast<float>(a.p.N("spread", p.spread)));
      p.breach = a.p.N("breach", 1.0) != 0.0;
      p.jitter = std::max(0.0f, static_cast<float>(a.p.N("jitter", 0.0)));
      p.seed = static_cast<std::uint32_t>(a.p.N("seed", 1.0));
      Factors fac;
      BuildFactors(a, *src, fac);
      Results r;
      r.height = *src;
      r.wear = Shaped(*src);
      r.deposit = Shaped(*src);
      r.flow = Shaped(*src);
      r.water = Shaped(*src);
      r.sediment = Shaped(*src);
      std::vector<float> area;
      RunStream(
        r.height.v,
        src->w,
        src->h,
        src->cell,
        p,
        fac.rockPtr,
        r.wear.v,
        area,
        fac.rain.empty() ? nullptr : &fac.rain,
        fac.thermalPtr
      );
      if (area.size() == r.flow.v.size())
        r.flow.v = area;
      PostProcess(a, src->v, r.height.v, &r.deposit.v, &r.wear.v);
      return Emit(a, r, out, err);
    }

    /**
     * Slope-area relation of the terrain (a quality statistic): on the pit filled surface the drainage area A of every
     * cell and its steepest drop S are binned by log2(A); the result is a `bins` x 3 grid: row 0 = log2 of the bin's
     * lowest area, row 1 = mean S, row 2 = number of cells. Eroded terrain follows S ~ A^-theta with theta around 0.45
     * (Flint's law) in the channel range; noise terrain has theta near 0.
     */
    bool OpSlopeArea(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const auto it = a.in.find("a");
      if (it == a.in.end()) {
        err = "missing input 'a'";
        return false;
      }
      const Grid& src = *it->second;
      const int bins = std::max(2, std::min(24, static_cast<int>(a.p.N("bins", 12))));
      const int first = std::max(0, std::min(10, static_cast<int>(a.p.N("first", 1))));
      std::vector<float> fill, area, slope;
      FillSurface(src.v, src.w, src.h, 0.004f * src.cell, fill);
      Drainage(fill, src.w, src.h, src.cell, static_cast<float>(a.p.N("spread", 1.1)), area, slope);
      out = Grid(bins, 3, 1.0f, 0.0f, 0.0f);
      std::vector<double> sum(static_cast<std::size_t>(bins), 0.0), cnt(static_cast<std::size_t>(bins), 0.0);
      for (std::size_t i = 0; i < area.size(); ++i) {
        const int x = i % static_cast<std::size_t>(src.w), z = static_cast<int>(i / static_cast<std::size_t>(src.w));
        if (x == 0 || z == 0 || x == src.w - 1 || z == src.h - 1)
          continue;
        const int b = static_cast<int>(std::floor(std::log2(std::max(1.0f, area[i])))) - first;
        if (b < 0 || b >= bins)
          continue;
        sum[static_cast<std::size_t>(b)] += slope[i];
        cnt[static_cast<std::size_t>(b)] += 1.0;
      }
      for (int b = 0; b < bins; ++b) {
        out.At(b, 0) = static_cast<float>(b + first);
        out.At(b, 1) = cnt[static_cast<std::size_t>(b)] > 0.0
          ? static_cast<float>(sum[static_cast<std::size_t>(b)] / cnt[static_cast<std::size_t>(b)])
          : 0.0f;
        out.At(b, 2) = static_cast<float>(cnt[static_cast<std::size_t>(b)]);
      }
      return true;
    }

    /** Depth of the closed depressions: the pit filled surface minus the terrain (0 on ground that drains). A quality
     * statistic and a mask source (lakes). */
    bool OpBasinDepth(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const auto it = a.in.find("a");
      if (it == a.in.end()) {
        err = "missing input 'a'";
        return false;
      }
      const Grid& src = *it->second;
      std::vector<float> fill;
      FillSurface(src.v, src.w, src.h, 0.0f, fill);
      out = Grid(src.w, src.h, src.cell, src.ox, src.oz);
      for (std::size_t i = 0; i < fill.size(); ++i)
        out.v[i] = fill[i] - src.v[i];
      return true;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterOp("erode_hydraulic", &OpHydraulic);
        RegisterOp("erode_droplet", &OpDroplet);
        RegisterOp("erode_stream", &OpStream);
        RegisterOp("slope_area", &OpSlopeArea);
        RegisterOp("basin_depth", &OpBasinDepth);
      }
    };
    const Registrar gRegistrar{};
  } // namespace

  // ---- the shared parts of the ops, for the GPU versions
  // ----------------------------------------------------------------------------------------

  DropletParams DropletParamsOf(
    const OpArgs& a
  )
  {
    DropletParams p;
    p.density = static_cast<float>(a.p.N("density", p.density));
    p.lifetime = std::max(1, std::min(200, static_cast<int>(a.p.N("lifetime", p.lifetime))));
    p.inertia = Clamp01(static_cast<float>(a.p.N("inertia", p.inertia)));
    p.capacity = static_cast<float>(a.p.N("capacity", p.capacity));
    p.min_slope = static_cast<float>(a.p.N("min_slope", p.min_slope));
    p.erode = static_cast<float>(a.p.N("erode", p.erode));
    p.deposit = static_cast<float>(a.p.N("deposit", p.deposit));
    p.evaporate = static_cast<float>(a.p.N("evaporate", p.evaporate));
    p.gravity = static_cast<float>(a.p.N("gravity", p.gravity));
    p.radius = std::max(1, std::min(8, static_cast<int>(a.p.N("radius", p.radius))));
    p.speed = static_cast<float>(a.p.N("speed", p.speed));
    p.water = static_cast<float>(a.p.N("water", p.water));
    p.drain_pits = Clamp01(static_cast<float>(a.p.N("drain_pits", p.drain_pits)));
    p.round_cut = std::max(0.01f, static_cast<float>(a.p.N("round_cut", p.round_cut)));
    p.rounds = std::max(1, std::min(64, static_cast<int>(a.p.N("rounds", p.rounds))));
    p.seed = static_cast<std::uint32_t>(a.p.N("seed", 1.0));
    p.drop_vary = Clamp01(static_cast<float>(a.p.N("drop_vary", 0.0)));
    p.accel = Clamp01(static_cast<float>(a.p.N("accel", p.accel)));
    p.creep = std::max(0.0f, std::min(8.0f, static_cast<float>(a.p.N("creep", p.creep))));
    return p;
  }

  HydroParams HydroParamsOf(
    const OpArgs& a
  )
  {
    return HydroOf(a);
  }

  void BuildOpFactors(
    const OpArgs& a,
    const Grid& src,
    OpFactors& out
  )
  {
    Factors f;
    BuildFactors(a, src, f);
    out = OpFactors();
    if (f.rockPtr != nullptr)
      out.rock = *f.rockPtr;
    if (f.softPtr != nullptr)
      out.soft = *f.softPtr;
    if (f.thermalPtr != nullptr)
      out.thermal = *f.thermalPtr;
    out.rain = f.rain;
    out.accept = f.accept;
  }

  bool FinishHydroOp(
    const OpArgs& a,
    const Grid& src,
    const HydroParams& p,
    HydroState& st,
    Grid& out,
    std::string& err
  )
  {
    const std::size_t n = src.v.size();
    for (std::vector<float>* v : {&st.d, &st.s, &st.wear, &st.dep, &st.flow}) {
      if (v->size() != n)
        v->assign(n, 0.0f);
    }
    SmoothDelta(
      src.v,
      st.t,
      src.w,
      src.h,
      static_cast<float>(a.p.N("smooth", 1.0)),
      static_cast<int>(a.p.N("smooth_passes", 1)),
      p.pin_border
    );
    if (p.open_edge && !p.pin_border)
      MirrorEdgeChange(src.v, st.t, src.w, src.h, 0);
    PostProcess(a, src.v, st.t, &st.dep, &st.wear);
    Results r;
    r.height = Shaped(src);
    r.height.v = st.t;
    r.wear = Shaped(src);
    r.wear.v = st.wear;
    r.deposit = Shaped(src);
    r.deposit.v = st.dep;
    r.flow = Shaped(src);
    r.flow.v = st.flow;
    r.water = Shaped(src);
    r.water.v = st.d;
    r.sediment = Shaped(src);
    r.sediment.v = st.s;
    return Emit(a, r, out, err);
  }

  bool FinishDropletOp(
    const OpArgs& a,
    const Grid& src,
    std::vector<float>& height,
    std::vector<float>& wear,
    std::vector<float>& deposit,
    std::vector<float>& flow,
    Grid& out,
    std::string& err
  )
  {
    const std::size_t n = src.v.size();
    for (std::vector<float>* v : {&wear, &deposit, &flow}) {
      if (v->size() != n)
        v->assign(n, 0.0f);
    }
    PostProcess(a, src.v, height, &deposit, &wear);
    Results r;
    r.height = Shaped(src);
    r.height.v = height;
    r.wear = Shaped(src);
    r.wear.v = wear;
    r.deposit = Shaped(src);
    r.deposit.v = deposit;
    r.flow = Shaped(src);
    r.flow.v = flow;
    r.water = Shaped(src);
    r.sediment = Shaped(src);
    return Emit(a, r, out, err);
  }

  void FillSteeringSurface(
    const std::vector<float>& t,
    const int w,
    const int h,
    const float eps,
    std::vector<float>& fill
  )
  {
    FillSurface(t, w, h, eps, fill);
  }

  // ---- the local erosion brush
  // ------------------------------------------------------------------------------------------------------------------
  //
  // The brush runs water droplets on the real terrain (Beyer / Lague): every dab releases a few hundred droplets at
  // random positions inside the brush, they run downhill on the bilinear surface with inertia, dissolve ground where
  // they are fast on a slope and settle it where they slow down. All writes are multiplied by the brush weight of the
  // cell they land on, so the change is exactly zero outside the brush radius and follows its falloff inside; the
  // heights, not a window copy, are what the droplets read (no pinned rim, no frozen water state at the edge of a
  // window). The earlier brush solved the pipe model of the grid solver on a square window: four flow directions (a
  // diamond of settled sediment and parallel rills along the axes), settling and water not weighted by the brush, and
  // water / sediment left standing outside the window between dabs (the straight edges).
  //
  // Continuity: nothing the dab does is a threshold of the brush weights (a droplet's water and load are proportional
  // to its start weight, its random numbers come from its own stream), so a brush mask that differs a little gives a
  // result that differs a little.

  namespace
  {
    float RoundWeight(
      const double dist,
      const double radius,
      const double falloff
    )
    {
      if (dist >= radius)
        return 0.0f;
      const double f = std::max(0.0, std::min(1.0, falloff));
      const double width = std::min(radius, std::max(radius * f, 1.0));
      const double inner = radius - width;
      if (dist <= inner)
        return 1.0f;
      return static_cast<float>(0.5 * (1.0 + std::cos(static_cast<double>(kPi) * (dist - inner) / width)));
    }

    std::uint16_t Word(
      const float height
    )
    {
      const float v = std::floor(height * 128.0f + 0.5f);
      return static_cast<std::uint16_t>(v < 0.0f ? 0.0f : (v > 65535.0f ? 65535.0f : v));
    }

    constexpr float kBrushCapacity =
      1.5f; // sediment capacity of a droplet per unit of slope * speed * water, at HydroParams::capacity = 1 (heights
            // in world units, the sample spacing is 1)
    constexpr float kBrushPileKernel = 3.5f; // radius of the cone a droplet dumps its sediment with (deposit brush)
    constexpr float kBrushDensity =
      0.03f; // droplets per sample of the brush's bounding square per round (HydroParams::rain / 0.006 scales it)
    constexpr float kBrushVary = 0.5f; // every droplet its own lifetime, inertia, load and dissolving rate (breaks the
                                       // evenly spaced parallel rills of identical droplets)
    constexpr float kBrushKernel = 2.0f; // radius of the cone the droplet digs with, in samples (the digging is centred
                                         // on the exact position, not on a cell)
    constexpr float kBrushRollCut = 0.4f; // no sample is dug deeper than this below its height at the start of the dab
    constexpr int kBrushMaxDrops =
      2000; // (a bigger brush gets the same water in fewer, bigger droplets: the cost stays bounded)

    /** The window a dab works on and its per sample brush weights. */
    struct BrushCtx
    {
      int w = 0, h = 0;                          // the map
      int x0 = 0, z0 = 0, ww = 0, wh = 0;        // the window (inclusive corner, size)
      const std::vector<float>* start = nullptr; // where droplets are released and how much water they get
      const std::vector<float>* write = nullptr; // the brush weight of a sample: what is dug and settled there is
                                                 // multiplied with it (0 = never touched)
      const std::vector<float>* rock = nullptr;  // optional: erodibility factor of a sample
      const std::vector<float>* base = nullptr;  // the window's heights at the start of the dab
      bool pile = false;                         // deposit brush: a droplet may build above its surroundings
    };

    inline float WinAt(
      const std::vector<float>* a,
      const BrushCtx& c,
      const int x,
      const int z
    )
    {
      if (a == nullptr)
        return 1.0f;
      const int ix = x - c.x0, iz = z - c.z0;
      if (ix < 0 || iz < 0 || ix >= c.ww || iz >= c.wh)
        return 0.0f;
      return (*a)[Ix(ix, iz, c.ww)];
    }

    /** The weights bilinear at a continuous position (the samples outside the window count 0). */
    inline float WinBilinear(
      const std::vector<float>& a,
      const BrushCtx& c,
      const float px,
      const float pz
    )
    {
      const int ix = static_cast<int>(std::floor(px)), iz = static_cast<int>(std::floor(pz));
      const float fx = px - static_cast<float>(ix), fz = pz - static_cast<float>(iz);
      return WinAt(&a, c, ix, iz) * (1.0f - fx) * (1.0f - fz) + WinAt(&a, c, ix + 1, iz) * fx * (1.0f - fz) +
        WinAt(&a, c, ix, iz + 1) * (1.0f - fx) * fz + WinAt(&a, c, ix + 1, iz + 1) * fx * fz;
    }

    struct BrushDrop
    {
      float inertia = 0.3f;
      float capacity = 1.0f;
      float erode = 0.2f;
      float deposit = 0.1f;
      float evaporate = 0.02f;
      float min_slope = 0.02f;
      float cut_limit = 0.5f;
      float gravity = 4.0f;
      float speed = 1.0f;
      int lifetime = 30;
    };

    inline float LowestAround(
      const std::vector<float>& t,
      const int w,
      const int h,
      const int x,
      const int z,
      float* highest = nullptr
    )
    {
      float lo = t[Ix(x, z, w)], hi = lo;
      for (int dz = -1; dz <= 1; ++dz) {
        for (int dx = -1; dx <= 1; ++dx) {
          const int nx = x + dx, nz = z + dz;
          if ((dx == 0 && dz == 0) || nx < 0 || nz < 0 || nx >= w || nz >= h)
            continue;
          const float v = t[Ix(nx, nz, w)];
          lo = std::min(lo, v);
          hi = std::max(hi, v);
        }
      }
      if (highest != nullptr)
        *highest = hi;
      return lo;
    }

    struct Kernel
    {
      float kw[64];
      int cx[64], cz[64];
      int count = 0;
      float wsum = 0.0f;
    };

    /** The samples within kBrushKernel of (px, pz) with their cone weights (a continuous centre: no cell quantisation);
     * samples past the map edge are mirrored back (so the border takes as much as the inside: no lip). `wsum` is the
     * sum over the whole cone, also the part that falls outside the map or the brush. */
    void GatherKernel(
      const BrushCtx& c,
      const float px,
      const float pz,
      Kernel& k,
      const float radius = kBrushKernel
    )
    {
      const int r = static_cast<int>(std::ceil(radius));
      const int ix = static_cast<int>(std::floor(px)), iz = static_cast<int>(std::floor(pz));
      k.count = 0;
      k.wsum = 0.0f;
      for (int oz = -r + 1; oz <= r; ++oz) {
        for (int ox = -r + 1; ox <= r; ++ox) {
          const float ddx = static_cast<float>(ix + ox) - px, ddz = static_cast<float>(iz + oz) - pz;
          const float d = std::sqrt(ddx * ddx + ddz * ddz);
          if (d >= radius)
            continue;
          const float wk = radius - d;
          k.wsum += wk;
          const int mx = Reflect(ix + ox, c.w), mz = Reflect(iz + oz, c.h);
          if (mx < 0 || mz < 0)
            continue;
          k.kw[k.count] = wk;
          k.cx[k.count] = mx;
          k.cz[k.count] = mz;
          ++k.count;
        }
      }
    }

    /** Digs `amount` out of the samples around (px, pz) with the cone; each sample gives its share times its brush
     * weight (and erodibility), never more than a share of its drop to the lowest neighbour (no pits) and never below
     * its start height minus kBrushRollCut. Returns what was dug. */
    float BrushDig(
      std::vector<float>& t,
      const BrushCtx& c,
      const BrushDrop& p,
      const float px,
      const float pz,
      const float amount
    )
    {
      Kernel k;
      GatherKernel(c, px, pz, k);
      if (k.wsum <= 0.0f)
        return 0.0f;
      float taken = 0.0f;
      for (int q = 0; q < k.count; ++q) {
        const float wt = WinAt(c.write, c, k.cx[q], k.cz[q]);
        if (wt <= 0.0f)
          continue;
        const std::size_t j = Ix(k.cx[q], k.cz[q], c.w);
        float a = amount * k.kw[q] / k.wsum * wt;
        if (c.rock != nullptr)
          a *= WinAt(c.rock, c, k.cx[q], k.cz[q]);
        const int bx = k.cx[q] - c.x0, bz = k.cz[q] - c.z0;
        if (bx >= 0 && bz >= 0 && bx < c.ww && bz < c.wh)
          a = std::min(a, std::max(0.0f, t[j] - ((*c.base)[Ix(bx, bz, c.ww)] - kBrushRollCut)));
        if (a <= 1e-7f)
          continue;
        if (p.cut_limit > 0.0f)
          a = std::min(a, p.cut_limit * std::max(0.0f, t[j] - LowestAround(t, c.w, c.h, k.cx[q], k.cz[q])));
        if (a <= 0.0f)
          continue;
        t[j] -= a;
        taken += a;
      }
      return taken;
    }

    /** The deposit brush's dump: `amount` of sediment on the samples around (px, pz) with the cone, times their brush
     * weight. */
    void BrushPile(
      std::vector<float>& t,
      const BrushCtx& c,
      const float px,
      const float pz,
      const float amount
    )
    {
      Kernel k;
      GatherKernel(c, px, pz, k, kBrushPileKernel);
      if (k.wsum <= 0.0f)
        return;
      for (int q = 0; q < k.count; ++q) {
        const float wt = WinAt(c.write, c, k.cx[q], k.cz[q]);
        if (wt > 0.0f)
          t[Ix(k.cx[q], k.cz[q], c.w)] += amount * k.kw[q] / k.wsum * wt;
      }
    }

    /** Settles `amount` on the four samples around (px, pz), bilinear, times their brush weight; a sample takes no more
     * than the room up to its highest neighbour (a droplet fills a hollow, it does not build spikes) unless the brush
     * builds. Returns what was settled. */
    float BrushSettle(
      std::vector<float>& t,
      const BrushCtx& c,
      const float px,
      const float pz,
      const float amount
    )
    {
      if (amount <= 0.0f)
        return 0.0f;
      const int ix = std::max(0, std::min(c.w - 2, static_cast<int>(std::floor(px)))),
                iz = std::max(0, std::min(c.h - 2, static_cast<int>(std::floor(pz))));
      const float fx = px - static_cast<float>(ix), fz = pz - static_cast<float>(iz);
      const float bw[4] = {(1.0f - fx) * (1.0f - fz), fx * (1.0f - fz), (1.0f - fx) * fz, fx * fz};
      float done = 0.0f;
      for (int k = 0; k < 4; ++k) {
        const int x = ix + (k & 1), z = iz + (k >> 1);
        const float wt = WinAt(c.write, c, x, z);
        if (wt <= 0.0f)
          continue;
        const std::size_t j = Ix(x, z, c.w);
        // (the erode and rain brushes settle with the weight squared: the load that runs out past the brush is carried
        // away, it does not pile up as a ring along its edge)
        float a = amount * bw[k] * (c.pile ? wt : wt * wt);
        if (!c.pile) {
          float hi;
          LowestAround(t, c.w, c.h, x, z, &hi);
          a = std::min(a, std::max(0.0f, hi - t[j]) + 0.01f);
        }
        t[j] += a;
        done += a;
      }
      return done;
    }

    /** One droplet of the brush: released at (sx, sz) with `water` (its start weight) and `load` sediment; runs on t.
     * Returns the sediment it still carried when it ended (off the map, or what the weights did not let it settle). */
    float BrushDroplet(
      std::vector<float>& t,
      const BrushCtx& c,
      const BrushDrop& base,
      Rng& rng,
      const float sx,
      const float sz,
      const float water0,
      const float load0
    )
    {
      BrushDrop p = base;
      {
        const auto sgn = [&rng]() {
          return rng.Unit() * 2.0f - 1.0f;
        };
        p.lifetime = std::max(
          4, static_cast<int>(std::floor(static_cast<float>(base.lifetime) * (1.0f + 0.4f * kBrushVary * sgn()) + 0.5f))
        );
        p.inertia = Clamp01(std::min(0.95f, base.inertia * (1.0f + kBrushVary * sgn())));
        p.capacity = base.capacity * (1.0f + 0.6f * kBrushVary * sgn());
        p.erode = base.erode * (1.0f + 0.4f * kBrushVary * sgn());
      }
      float water = water0 * (1.0f + 0.5f * kBrushVary * (rng.Unit() * 2.0f - 1.0f));
      float px = sx, pz = sz, dx = 0.0f, dz = 0.0f, speed = p.speed, sediment = load0;
      const int w = c.w, h = c.h;
      for (int life = 0; life < p.lifetime; ++life) {
        const int ix = static_cast<int>(std::floor(px)), iz = static_cast<int>(std::floor(pz));
        if (px < 0.0f || pz < 0.0f || ix >= w - 1 || iz >= h - 1)
          return sediment; // off the map: the load goes with it
        const float fx = px - static_cast<float>(ix), fz = pz - static_cast<float>(iz);
        const std::size_t i00 = Ix(ix, iz, w);
        const float h00 = t[i00], h10 = t[i00 + 1], h01 = t[i00 + static_cast<std::size_t>(w)],
                    h11 = t[i00 + static_cast<std::size_t>(w) + 1];
        const float gx = (h10 - h00) * (1.0f - fz) + (h11 - h01) * fz;
        const float gz = (h01 - h00) * (1.0f - fx) + (h11 - h10) * fx;
        const float height =
          h00 * (1.0f - fx) * (1.0f - fz) + h10 * fx * (1.0f - fz) + h01 * (1.0f - fx) * fz + h11 * fx * fz;
        dx = dx * p.inertia - gx * (1.0f - p.inertia);
        dz = dz * p.inertia - gz * (1.0f - p.inertia);
        float len = std::sqrt(dx * dx + dz * dz);
        if (len < 1e-6f) {
          const float a = rng.Unit() * 2.0f * kPi;
          dx = std::cos(a);
          dz = std::sin(a);
          len = 1.0f;
        }
        dx /= len;
        dz /= len;
        const float ox = px, oz = pz;
        px += dx;
        pz += dz;
        const int nx = static_cast<int>(std::floor(px)), nz = static_cast<int>(std::floor(pz));
        if (px < 0.0f || pz < 0.0f || nx >= w - 1 || nz >= h - 1)
          return sediment;
        const float ex = px - static_cast<float>(nx), ez = pz - static_cast<float>(nz);
        const std::size_t j = Ix(nx, nz, w);
        const float newHeight = t[j] * (1.0f - ex) * (1.0f - ez) + t[j + 1] * ex * (1.0f - ez) +
          t[j + static_cast<std::size_t>(w)] * (1.0f - ex) * ez + t[j + static_cast<std::size_t>(w) + 1] * ex * ez;
        const float dh = newHeight - height;
        const float cap = std::max(-dh, p.min_slope) * speed * water * p.capacity * kBrushCapacity;
        if (sediment > cap || dh > 0.0f) {
          const float amount = dh > 0.0f ? std::min(dh, sediment) : (sediment - cap) * p.deposit;
          sediment -= BrushSettle(t, c, ox, oz, amount);
        } else if (life >= 1) {
          sediment += BrushDig(t, c, p, ox, oz, std::min((cap - sediment) * p.erode, -dh));
        }
        speed = std::min(4.0f, std::sqrt(std::max(0.0f, speed * speed - dh * p.gravity)));
        water *= (1.0f - p.evaporate);
      }
      if (sediment > 0.0f)
        sediment -= BrushSettle(t, c, px, pz, sediment);
      return std::max(0.0f, sediment);
    }

    /** Puts `volume` of the sediment that left the brush back inside it: spread over the part of the brush that lies
     * below the brush's mean ground, by brush weight and depth below that mean (the foot of the slope and the hollows
     * take it, summits and ridges do not), so the brush moves material instead of only removing it and the mountain
     * keeps its mass. */
    void BrushReturn(
      std::vector<float>& t,
      const BrushCtx& c,
      const std::vector<float>& write,
      const double volume
    )
    {
      double sumW = 0.0, sumH = 0.0;
      for (int z = 0; z < c.wh; ++z) {
        for (int x = 0; x < c.ww; ++x) {
          const float wt = write[Ix(x, z, c.ww)];
          if (wt <= 0.0f)
            continue;
          sumW += wt;
          sumH += static_cast<double>(wt) * t[Ix(c.x0 + x, c.z0 + z, c.w)];
        }
      }
      if (sumW <= 1e-9)
        return;
      const float mean = static_cast<float>(sumH / sumW);
      std::vector<float> wt(write.size(), 0.0f);
      double sum = 0.0;
      for (int z = 0; z < c.wh; ++z) {
        for (int x = 0; x < c.ww; ++x) {
          const std::size_t i = Ix(x, z, c.ww);
          if (write[i] <= 0.0f)
            continue;
          wt[i] = write[i] * std::max(0.0f, mean - t[Ix(c.x0 + x, c.z0 + z, c.w)]);
          sum += wt[i];
        }
      }
      if (sum <= 1e-12)
        return;
      const double k = volume / sum;
      for (int z = 0; z < c.wh; ++z)
        for (int x = 0; x < c.ww; ++x)
          t[Ix(c.x0 + x, c.z0 + z, c.w)] += static_cast<float>(k * wt[Ix(x, z, c.ww)]);
    }
  } // namespace

  void BrushWindow(
    const BrushDab& dab,
    const int w,
    const int h,
    int& x0,
    int& z0,
    int& x1,
    int& z1
  )
  {
    const double radius = std::max(1.0, dab.radius);
    double margin = dab.margin;
    if (margin < 0.0)
      margin = BrushDefaultMargin(dab.mode, radius);
    x0 = std::max(0, static_cast<int>(std::floor(dab.cx - radius - margin)) - 1);
    z0 = std::max(0, static_cast<int>(std::floor(dab.cz - radius - margin)) - 1);
    x1 = std::min(w - 1, static_cast<int>(std::ceil(dab.cx + radius + margin)) + 1);
    z1 = std::min(h - 1, static_cast<int>(std::ceil(dab.cz + radius + margin)) + 1);
  }

  double BrushDefaultMargin(
    const int mode,
    const double radius
  )
  {
    return mode == 1 ? 0.8 * radius + 3.0 : 0.0;
  }

  void ErodeSession::Begin(
    const int w,
    const int h,
    const std::uint16_t* words,
    const HydroParams& params
  )
  {
    w_ = w;
    h_ = h;
    params_ = params;
    const std::size_t n = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
    t_.resize(n);
    for (std::size_t i = 0; i < n; ++i)
      t_[i] = static_cast<float>(words[i]) * (1.0f / 128.0f);
    dabs_ = 0;
    seed_ = 0;
    active_ = w >= 3 && h >= 3;
  }

  void ErodeSession::Store(
    const int x,
    const int z,
    const std::uint16_t word
  )
  {
    if (active_ && x >= 0 && z >= 0 && x < w_ && z < h_) {
      t_[Ix(x, z, w_)] = static_cast<float>(word) * (1.0f / 128.0f);
    }
  }

  void ErodeSession::End()
  {
    active_ = false;
    t_.clear();
    t_.shrink_to_fit();
  }

  bool ErodeSession::Dab(
    const BrushDab& dab,
    int& x0,
    int& z0,
    int& x1,
    int& z1,
    std::vector<std::uint16_t>& words
  )
  {
    if (!active_)
      return false;
    const double radius = std::max(1.0, dab.radius);
    double margin = dab.margin;
    if (margin < 0.0)
      margin = BrushDefaultMargin(dab.mode, radius);
    BrushWindow(dab, w_, h_, x0, z0, x1, z1);
    const int ww = x1 - x0 + 1;
    const int wh = z1 - z0 + 1;
    if (ww < 3 || wh < 3)
      return false;
    const std::size_t n = static_cast<std::size_t>(ww) * static_cast<std::size_t>(wh);
    if (dabs_ == 0)
      seed_ = static_cast<std::uint32_t>(
        Mix(
          params_.seed,
          static_cast<std::uint64_t>(static_cast<std::int64_t>(std::floor(dab.cx * 4.0))),
          static_cast<std::uint64_t>(static_cast<std::int64_t>(std::floor(dab.cz * 4.0)))
        ) >>
        32
      );
    const std::uint64_t dabId = dabs_++;
    const bool custom = dab.weights.size() == n;
    std::vector<float> vary;
    if (params_.vary > 0.0f)
      NoiseField(vary, ww, wh, 1.0f, std::max(2.0f, params_.vary_scale), 17u, 3, true, x0, z0);
    std::vector<float> start(n), write(n), rock, base(n);
    if (params_.vary > 0.0f)
      rock.assign(n, 1.0f);
    // the window sides that lie inside the map are not touched (the brush weights are zero there); a side on the map
    // edge is an ordinary row of samples
    int sides = 0;
    if (x0 > 0)
      sides |= 1;
    if (x1 < w_ - 1)
      sides |= 2;
    if (z0 > 0)
      sides |= 4;
    if (z1 < h_ - 1)
      sides |= 8;
    const double reach = radius +
      0.9 * margin; // rain brush: the ground is dug this far from the centre (the water runs on beyond the brush)
    for (int z = 0; z < wh; ++z) {
      for (int x = 0; x < ww; ++x) {
        const std::size_t i = Ix(x, z, ww);
        const double ddx = static_cast<double>(x0 + x) - dab.cx;
        const double ddz = static_cast<double>(z0 + z) - dab.cz;
        const double dist = std::sqrt(ddx * ddx + ddz * ddz);
        const bool rim = ((sides & 1) != 0 && x == 0) || ((sides & 4) != 0 && z == 0) ||
          ((sides & 2) != 0 && x == ww - 1) || ((sides & 8) != 0 && z == wh - 1);
        const float wgt = rim ? 0.0f : (custom ? dab.weights[i] : RoundWeight(dist, radius, dab.falloff));
        base[i] = t_[Ix(x0 + x, z0 + z, w_)];
        float rainW = wgt;
        const float dig = dab.mode == 1 ? (rim ? 0.0f : RoundWeight(dist, reach, 1.0)) : wgt;
        if (!vary.empty()) {
          const float cv = Clamp01((vary[i] - 0.2f) * (1.0f / 0.6f));
          const float hard = cv * cv * (3.0f - 2.0f * cv);
          rock[i] = 1.0f - params_.vary * hard;
          rainW *= 1.0f + params_.vary * (1.0f - 2.0f * hard) * 0.7f;
        }
        start[i] = rainW;
        write[i] = dig;
      }
    }
    BrushCtx c;
    c.w = w_;
    c.h = h_;
    c.x0 = x0;
    c.z0 = z0;
    c.ww = ww;
    c.wh = wh;
    c.start = &start;
    c.write = &write;
    c.rock = rock.empty() ? nullptr : &rock;
    c.base = &base;
    c.pile = dab.mode == 2;
    BrushDrop p;
    p.inertia = Clamp01(params_.inertia);
    p.capacity = params_.capacity;
    p.erode = params_.erosion * static_cast<float>(dab.strength);
    p.deposit = params_.deposition;
    p.evaporate = params_.evaporation;
    p.min_slope = params_.min_slope;
    p.cut_limit = params_.cut_limit;
    p.lifetime = static_cast<int>(std::max(16.0, std::min(48.0, 18.0 + 1.5 * radius)) * (dab.mode == 1 ? 1.5 : 1.0));
    // the droplets: released over the bounding square of the brush (fixed, independent of the weights), each with the
    // water of its start weight
    const double side = 2.0 * radius;
    const double rainK = static_cast<double>(params_.rain) / 0.006;
    double wantD =
      static_cast<double>(std::max(0, dab.iterations)) * kBrushDensity * rainK * side * side * dab.strength;
    int drops = static_cast<int>(std::min(static_cast<double>(kBrushMaxDrops), std::ceil(wantD)));
    const int grid = std::max(1, static_cast<int>(std::ceil(std::sqrt(static_cast<double>(std::max(1, drops))))));
    if (dab.mode == 2)
      drops = grid * grid;
    if (dab.mode == 2)
      wantD *= 0.5; // (the deposit brush runs with half the water: the pile slides, it is not washed away)
    const double loadPerArea = dab.amount * dab.strength * side * side / std::max(1, drops);
    const float waterScale = static_cast<float>(wantD / std::max(1.0, static_cast<double>(drops)));
    const float cdx = static_cast<float>(dab.cx), cdz = static_cast<float>(dab.cz);
    double lost = 0.0;
    for (int k = 0; k < drops; ++k) {
      Rng rng(Mix(seed_, dabId, static_cast<std::uint64_t>(k)));
      float ux = rng.Unit(), uz = rng.Unit();
      if (dab.mode == 2) {
        // the deposit brush lays its pile on a jittered grid (one droplet per cell of a grid, anywhere inside it): an
        // even heap, not the clumps independent random positions make
        ux = (static_cast<float>(k % grid) + ux) / static_cast<float>(grid);
        uz = (static_cast<float>(k / grid) + uz) / static_cast<float>(grid);
      }
      const float sx = cdx + (ux * 2.0f - 1.0f) * static_cast<float>(radius);
      const float sz = cdz + (uz * 2.0f - 1.0f) * static_cast<float>(radius);
      const float sw = WinBilinear(start, c, sx, sz);
      if (sw <= 0.0f)
        continue;
      // deposit brush: the droplet first dumps its share of the sediment where it is released (the pile), then runs and
      // carries what it takes up from the loose heap downhill
      if (dab.mode == 2)
        BrushPile(t_, c, sx, sz, static_cast<float>(loadPerArea));
      lost += BrushDroplet(t_, c, p, rng, sx, sz, sw * waterScale, 0.0f);
    }
    if (dab.mode != 2 && lost > 0.0 && params_.conserve > 0.0f)
      BrushReturn(t_, c, write, lost * static_cast<double>(params_.conserve));
    // thermal slides, weighted by the brush; only samples whose whole neighbourhood is under the brush take part
    // (nothing is handed to a sample outside it)
    if (params_.thermal > 0.0f && params_.thermal_every > 0) {
      const int steps = std::max(0, dab.iterations) / params_.thermal_every;
      if (steps > 0) {
        std::vector<float> wt(n, 0.0f), tw(n);
        for (int z = 0; z < wh; ++z) {
          for (int x = 0; x < ww; ++x) {
            float m = write[Ix(x, z, ww)];
            for (int dz = -1; dz <= 1 && m > 0.0f; ++dz) {
              for (int dx = -1; dx <= 1; ++dx) {
                const int gx = x0 + x + dx, gz = z0 + z + dz;
                if (gx < 0 || gz < 0 || gx >= w_ || gz >= h_)
                  continue; // (past the map edge: nothing there to hand material to)
                const int lx = x + dx, lz = z + dz;
                if (lx < 0 || lz < 0 || lx >= ww || lz >= wh || write[Ix(lx, lz, ww)] <= 0.0f) {
                  m = 0.0f;
                  break;
                }
              }
            }
            wt[Ix(x, z, ww)] = m;
          }
        }
        for (int z = 0; z < wh; ++z)
          for (int x = 0; x < ww; ++x)
            tw[Ix(x, z, ww)] = t_[Ix(x0 + x, z0 + z, w_)];
        ThermalScratch sc;
        const float rate = std::min(1.0f, params_.thermal * static_cast<float>(dab.strength));
        for (int s = 0; s < steps; ++s)
          ThermalImpl(tw, ww, wh, 1.0f, params_.talus, rate, wt, sides, sc);
        for (int z = 0; z < wh; ++z)
          for (int x = 0; x < ww; ++x)
            if (wt[Ix(x, z, ww)] > 0.0f || write[Ix(x, z, ww)] > 0.0f) {
              // (a sample that only receives is in the brush too: its whole neighbourhood of givers has weight)
              t_[Ix(x0 + x, z0 + z, w_)] = tw[Ix(x, z, ww)];
            }
      }
    }
    words.resize(n);
    for (int z = 0; z < wh; ++z)
      for (int x = 0; x < ww; ++x)
        words[Ix(x, z, ww)] = Word(t_[Ix(x0 + x, z0 + z, w_)]);
    return true;
  }

  bool ErodeSession::Finish(
    int& x0,
    int& z0,
    int& x1,
    int& z1,
    std::vector<std::uint16_t>& words
  )
  {
    // nothing is held back: every dab wrote what it did (the droplets settle their own load)
    (void)x0;
    (void)z0;
    (void)x1;
    (void)z1;
    (void)words;
    return false;
  }
} // namespace faf::editor::field::erosion
