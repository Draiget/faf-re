// shared helpers of the stage T7 op files (EdFieldGen.cpp, EdFieldFilt.cpp, EdFieldEro2.cpp). Header only, engine
// independent. The helpers are private copies of the small things EdFieldCore.cpp keeps in its anonymous namespace
// (noise hashing, edge sampling, row chunks), so the T7 files do not touch the core.
//
// Rules every op of these files follows (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md, section T7): every
// output sample is computed from the inputs alone in a fixed order (gather style, double buffered), reductions combine
// fixed chunks in chunk order, parameters are read through Params::N (float32 rounded), world units in the parameters,
// samples inside.
#pragma once
// The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace faf::editor::field::t7
{
  constexpr float kPi = 3.14159265358979f;
  constexpr double kPiD = 3.14159265358979323846;
  constexpr int kChunk = 8;

  inline float Clamp01(
    const float v
  )
  {
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
  }
  inline double Clamp01D(
    const double v
  )
  {
    return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v);
  }
  inline float Lerp(
    const float a,
    const float b,
    const float t
  )
  {
    return a + (b - a) * t;
  }
  inline float SmoothStep(
    const float e0,
    const float e1,
    const float v
  )
  {
    if (e1 == e0)
      return v < e0 ? 0.0f : 1.0f;
    const float t = Clamp01((v - e0) / (e1 - e0));
    return t * t * (3.0f - 2.0f * t);
  }

  inline const Grid* Get(
    const OpArgs& a,
    const char* const key
  )
  {
    const auto it = a.in.find(key);
    return it != a.in.end() ? it->second.get() : nullptr;
  }

  inline const Grid* Need(
    const OpArgs& a,
    const char* const key,
    std::string& err
  )
  {
    const Grid* g = Get(a, key);
    if (g == nullptr)
      err = std::string("missing input '") + key + "'";
    return g;
  }

  /** f(z0, z1) for fixed chunks of rows. */
  template <class F>
  void Rows(
    const int h,
    F&& f
  )
  {
    const int chunks = (h + kChunk - 1) / kChunk;
    ParallelFor(chunks, [&](const int c) {
      const int z0 = c * kChunk;
      f(z0, std::min(h, z0 + kChunk));
    });
  }

  /** out(x, z) = f(x, z) for every sample. */
  template <class F>
  void Cells(
    Grid& out,
    F&& f
  )
  {
    const int w = out.w;
    Rows(out.h, [&](const int z0, const int z1) {
      for (int z = z0; z < z1; ++z) {
        float* row = out.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
        for (int x = 0; x < w; ++x)
          row[x] = f(x, z);
      }
    });
  }

  /** The output takes its shape from `like`, else `a`, else width / height / cell / ox / oz. */
  inline bool MakeOut(
    const OpArgs& a,
    Grid& out,
    std::string& err
  )
  {
    const Grid* ref = Get(a, "like");
    if (ref == nullptr)
      ref = Get(a, "a");
    if (
      const Grid* const inA = Get(a, "a"); inA != nullptr && ref != nullptr && (inA->w != ref->w || inA->h != ref->h)
    ) {
      err = "'like' and 'a' differ in size";
      return false;
    }
    if (ref != nullptr) {
      out = Grid(ref->w, ref->h, ref->cell, ref->ox, ref->oz);
      return true;
    }
    const int w = static_cast<int>(a.p.N("width", 0));
    const int h = static_cast<int>(a.p.N("height", 0));
    if (w < 1 || h < 1 || static_cast<long long>(w) * h > (1LL << 27)) {
      err = "give 'like' or 'a', or width and height (at most 128M samples)";
      return false;
    }
    out = Grid(
      w,
      h,
      static_cast<float>(a.p.N("cell", 1.0)),
      static_cast<float>(a.p.N("ox", 0.0)),
      static_cast<float>(a.p.N("oz", 0.0))
    );
    return true;
  }

  /** Checks that an optional input has the shape of `ref`; sets err and returns false when it does not. */
  inline bool SameOrNone(
    const Grid* g,
    const Grid& ref,
    const char* const name,
    std::string& err
  )
  {
    if (g != nullptr && !g->SameShape(ref)) {
      err = std::string("input '") + name + "' differs in size";
      return false;
    }
    return true;
  }

  inline double WorldX(
    const Grid& g,
    const int x
  )
  {
    return static_cast<double>(g.ox) + static_cast<double>(x) * static_cast<double>(g.cell);
  }
  inline double WorldZ(
    const Grid& g,
    const int z
  )
  {
    return static_cast<double>(g.oz) + static_cast<double>(z) * static_cast<double>(g.cell);
  }

  inline std::uint32_t SeedOf(
    const OpArgs& a
  )
  {
    return static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
  }

  // ---- edge modes
  // ------------------------------------------------------------------------------------------------------------------------------

  enum Edge
  {
    kClamp = 0,
    kWrap = 1,
    kMirror = 2
  };

  inline Edge ParseEdge(
    const OpArgs& a,
    const Edge fallback
  )
  {
    const std::string s = a.p.S("edge", "");
    if (s == "clamp")
      return kClamp;
    if (s == "wrap")
      return kWrap;
    if (s == "mirror")
      return kMirror;
    return fallback;
  }

  inline int WrapI(
    int i,
    const int n
  )
  {
    i %= n;
    return i < 0 ? i + n : i;
  }

  inline int MirrorI(
    int i,
    const int n
  )
  {
    if (n == 1)
      return 0;
    const int period = 2 * (n - 1);
    i = WrapI(i, period);
    return i < n ? i : period - i;
  }

  inline int IndexOf(
    const int i,
    const int n,
    const Edge e
  )
  {
    if (e == kWrap)
      return WrapI(i, n);
    if (e == kMirror)
      return MirrorI(i, n);
    return i < 0 ? 0 : (i >= n ? n - 1 : i);
  }

  inline float Fetch(
    const Grid& g,
    const int ix,
    const int iz,
    const Edge e
  )
  {
    return g.At(IndexOf(ix, g.w, e), IndexOf(iz, g.h, e));
  }

  /** Bilinear sample at fractional sample coordinates. */
  inline float Bilinear(
    const Grid& g,
    const double gx,
    const double gz,
    const Edge e
  )
  {
    const double fx = std::floor(gx);
    const double fz = std::floor(gz);
    const float tx = static_cast<float>(gx - fx);
    const float tz = static_cast<float>(gz - fz);
    const int ix = static_cast<int>(fx);
    const int iz = static_cast<int>(fz);
    const float a = Fetch(g, ix, iz, e);
    const float b = Fetch(g, ix + 1, iz, e);
    const float c = Fetch(g, ix, iz + 1, e);
    const float d = Fetch(g, ix + 1, iz + 1, e);
    const float top = a + (b - a) * tx;
    const float bottom = c + (d - c) * tx;
    return top + (bottom - top) * tz;
  }

  /** Bilinear sample with clamped edges and a fast path inside the grid. */
  inline float BilinearC(
    const Grid& g,
    const float gx,
    const float gz
  )
  {
    const float mx = static_cast<float>(g.w - 1);
    const float mz = static_cast<float>(g.h - 1);
    const float cx = gx < 0.0f ? 0.0f : (gx > mx ? mx : gx);
    const float cz = gz < 0.0f ? 0.0f : (gz > mz ? mz : gz);
    int ix = static_cast<int>(cx);
    int iz = static_cast<int>(cz);
    if (ix >= g.w - 1)
      ix = std::max(0, g.w - 2);
    if (iz >= g.h - 1)
      iz = std::max(0, g.h - 2);
    const float tx = cx - static_cast<float>(ix);
    const float tz = cz - static_cast<float>(iz);
    const int ix1 = std::min(g.w - 1, ix + 1);
    const int iz1 = std::min(g.h - 1, iz + 1);
    const float* r0 = g.v.data() + static_cast<std::size_t>(iz) * static_cast<std::size_t>(g.w);
    const float* r1 = g.v.data() + static_cast<std::size_t>(iz1) * static_cast<std::size_t>(g.w);
    const float top = r0[ix] + (r0[ix1] - r0[ix]) * tx;
    const float bottom = r1[ix] + (r1[ix1] - r1[ix]) * tx;
    return top + (bottom - top) * tz;
  }

  // ---- noise (the same lattice hash as the core, with derivatives)
  // -------------------------------------------------------------------------------

  inline std::uint32_t Hash32(
    std::uint32_t x
  )
  {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
  }

  inline std::uint32_t Hash2(
    const int ix,
    const int iz,
    const std::uint32_t seed
  )
  {
    return Hash32(
      static_cast<std::uint32_t>(ix) * 0x9E3779B1U ^
      Hash32(static_cast<std::uint32_t>(iz) + seed * 0x85EBCA6BU + 0x165667B1U)
    );
  }

  inline float Unit(
    const std::uint32_t h
  )
  {
    return static_cast<float>(h >> 8) * (1.0f / 16777216.0f);
  } // [0, 1)

  inline const float (
    *GradTable()
  )[2]
  {
    static const float g[8][2] = {
      {1.0f, 0.0f},
      {-1.0f, 0.0f},
      {0.0f, 1.0f},
      {0.0f, -1.0f},
      {0.70710678f, 0.70710678f},
      {-0.70710678f, 0.70710678f},
      {0.70710678f, -0.70710678f},
      {-0.70710678f, -0.70710678f}
    };
    return g;
  }

  inline float Fade(
    const float t
  )
  {
    return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
  }
  inline float FadeD(
    const float t
  )
  {
    return 30.0f * t * t * (t - 1.0f) * (t - 1.0f);
  }

  /** Gradient noise about -1..1 with its analytic derivative (per lattice unit): the value is the core's Perlin (same
   * hash, same gradients, same scale). */
  inline float PerlinD(
    const double x,
    const double z,
    const std::uint32_t seed,
    float& dnx,
    float& dnz,
    const bool fine = false
  )
  {
    const float (*G)[2] = fine ? Gradients64() : GradTable();
    const std::uint32_t gm = fine ? 63u : 7u;
    const double fx0 = std::floor(x);
    const double fz0 = std::floor(z);
    const int ix = static_cast<int>(fx0);
    const int iz = static_cast<int>(fz0);
    const float fx = static_cast<float>(x - fx0);
    const float fz = static_cast<float>(z - fz0);
    const float u = Fade(fx), v = Fade(fz), du = FadeD(fx), dv = FadeD(fz);
    const float* ga = G[Hash2(ix, iz, seed) & gm];
    const float* gb = G[Hash2(ix + 1, iz, seed) & gm];
    const float* gc = G[Hash2(ix, iz + 1, seed) & gm];
    const float* gd = G[Hash2(ix + 1, iz + 1, seed) & gm];
    const float va = ga[0] * fx + ga[1] * fz;
    const float vb = gb[0] * (fx - 1.0f) + gb[1] * fz;
    const float vc = gc[0] * fx + gc[1] * (fz - 1.0f);
    const float vd = gd[0] * (fx - 1.0f) + gd[1] * (fz - 1.0f);
    const float k = va - vb - vc + vd;
    const float n = va + u * (vb - va) + v * (vc - va) + u * v * k;
    const float s = 1.41421356f;
    dnx = s *
      (ga[0] + u * (gb[0] - ga[0]) + v * (gc[0] - ga[0]) + u * v * (ga[0] - gb[0] - gc[0] + gd[0]) +
       du * (vb - va + v * k));
    dnz = s *
      (ga[1] + u * (gb[1] - ga[1]) + v * (gc[1] - ga[1]) + u * v * (ga[1] - gb[1] - gc[1] + gd[1]) +
       dv * (vc - va + u * k));
    return n * s;
  }

  inline float Perlin(
    const double x,
    const double z,
    const std::uint32_t seed,
    const bool fine = false
  )
  {
    float dx, dz;
    return PerlinD(x, z, seed, dx, dz, fine);
  }

  /** Octave o of `rotate` noise at world position (wx, wz): the point in the octave's own frame (lattice units), see
   * OctaveFrame in EdFieldCore.h. */
  inline void RotatedPoint(
    const int o,
    const double px,
    const double pz,
    double& qx,
    double& qz
  )
  {
    const OctaveFrame& fr = OctaveFrameOf(o);
    qx = px * fr.c - pz * fr.s + fr.ox;
    qz = px * fr.s + pz * fr.c + fr.oz;
  }

  /** Fractal sum of Perlin, about 0..1 (0.5 + 0.5 * normalised sum), world position in, fixed constants. */
  inline float Fbm01(
    const double wx,
    const double wz,
    const std::uint32_t seed,
    const double scale,
    const int octaves,
    const float persistence = 0.5f
  )
  {
    float sum = 0.0f, norm = 0.0f, amp = 1.0f;
    double freq = 1.0 / scale;
    for (int o = 0; o < octaves; ++o) {
      const std::uint32_t s = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
      float n = Perlin(wx * freq, wz * freq, s);
      n = std::max(-1.0f, std::min(1.0f, n));
      sum += n * amp;
      norm += amp;
      amp *= persistence;
      freq *= 2.0;
    }
    return Clamp01(0.5f + 0.5f * sum / norm * 1.4f);
  }

  // ---- gaussian blur (clamped edges)
  // ---------------------------------------------------------------------------------------------------------------

  /** One-sided gaussian kernel k[0..r] (sigma in samples), normalised over the full symmetric kernel. */
  inline std::vector<float> GaussKernel(
    const double sigma,
    int& r
  )
  {
    r = std::max(1, static_cast<int>(std::ceil(3.0 * sigma)));
    std::vector<double> d(static_cast<std::size_t>(r) + 1);
    double sum = 0.0;
    for (int i = 0; i <= r; ++i) {
      d[static_cast<std::size_t>(i)] =
        std::exp(-0.5 * static_cast<double>(i) * static_cast<double>(i) / (sigma * sigma));
      sum += (i == 0 ? 1.0 : 2.0) * d[static_cast<std::size_t>(i)];
    }
    std::vector<float> k;
    for (const double v : d)
      k.push_back(static_cast<float>(v / sum));
    return k;
  }

  /** dst = gaussian blur of src (sigma in samples), clamped edges. dst may not alias src. */
  inline void GaussBlur(
    const Grid& src,
    Grid& dst,
    const double sigma
  )
  {
    const int w = src.w, h = src.h;
    dst = Grid(w, h, src.cell, src.ox, src.oz);
    if (sigma <= 1e-6) {
      dst.v = src.v;
      return;
    }
    int r = 0;
    const std::vector<float> k = GaussKernel(sigma, r);
    Grid tmp(w, h, src.cell, src.ox, src.oz);
    Rows(h, [&](const int z0, const int z1) {
      for (int z = z0; z < z1; ++z) {
        const float* in = src.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
        float* o = tmp.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
        for (int x = 0; x < w; ++x) {
          float sum = k[0] * in[x];
          if (x >= r && x + r < w) {
            for (int i = 1; i <= r; ++i)
              sum += k[static_cast<std::size_t>(i)] * (in[x - i] + in[x + i]);
          } else {
            for (int i = 1; i <= r; ++i)
              sum += k[static_cast<std::size_t>(i)] * (in[std::max(0, x - i)] + in[std::min(w - 1, x + i)]);
          }
          o[x] = sum;
        }
      }
    });
    Rows(h, [&](const int z0, const int z1) {
      std::vector<float> acc(static_cast<std::size_t>(w));
      for (int z = z0; z < z1; ++z) {
        const float* mid = tmp.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
        for (int x = 0; x < w; ++x)
          acc[static_cast<std::size_t>(x)] = k[0] * mid[x];
        for (int i = 1; i <= r; ++i) {
          const float* up = tmp.v.data() + static_cast<std::size_t>(std::max(0, z - i)) * static_cast<std::size_t>(w);
          const float* dn =
            tmp.v.data() + static_cast<std::size_t>(std::min(h - 1, z + i)) * static_cast<std::size_t>(w);
          const float ki = k[static_cast<std::size_t>(i)];
          for (int x = 0; x < w; ++x)
            acc[static_cast<std::size_t>(x)] += ki * (up[x] + dn[x]);
        }
        float* o = dst.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
        for (int x = 0; x < w; ++x)
          o[x] = acc[static_cast<std::size_t>(x)];
      }
    });
  }

  /** Central difference gradient (rise per run) with clamped edges. */
  inline void GradientAt(
    const Grid& g,
    const int x,
    const int z,
    float& gx,
    float& gz
  )
  {
    const int x0 = std::max(0, x - 1), x1 = std::min(g.w - 1, x + 1);
    const int z0 = std::max(0, z - 1), z1 = std::min(g.h - 1, z + 1);
    gx = x1 > x0 ? (g.At(x1, z) - g.At(x0, z)) / (static_cast<float>(x1 - x0) * g.cell) : 0.0f;
    gz = z1 > z0 ? (g.At(x, z1) - g.At(x, z0)) / (static_cast<float>(z1 - z0) * g.cell) : 0.0f;
  }

  /** Parses `mask` (optional, same shape) and blends `res` into `src` by it: out = src + (res - src) * mask. */
  inline void ApplyMask(
    const Grid* mask,
    const Grid& src,
    Grid& out
  )
  {
    if (mask == nullptr)
      return;
    Cells(out, [&](const int x, const int z) {
      return Lerp(src.At(x, z), out.At(x, z), Clamp01(mask->At(x, z)));
    });
  }

  /** Cell indices by descending value, equal values by ascending index (LSD radix sort on the float bit patterns:
   * stable, O(n), the same order as a sort by (value desc, index asc)). */
  inline void SortDescending(
    const std::vector<float>& v,
    std::vector<std::uint32_t>& order
  )
  {
    const std::size_t n = v.size();
    std::vector<std::uint32_t> key(n), tmpKey(n), tmpOrder(n);
    order.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
      std::uint32_t u;
      const float f = v[i] == 0.0f ? 0.0f : v[i]; // -0 and +0 are equal values
      std::memcpy(&u, &f, sizeof(u));
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
} // namespace faf::editor::field::t7
