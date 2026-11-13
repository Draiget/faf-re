// stage T7 generators and domain warps of the field engine (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md,
// section T7). Engine independent like EdFieldCore; registered through RegisterOp.
//
//   musgrave     like/width,height. Musgrave multifractals: mode ridged (default) | hybrid | hetero. seed, scale
//   (units), octaves, lacunarity, h (spectral exponent), offset, gain. Result 0..1. fbm_damped   Gradient-noise fBm
//   whose octaves are damped where the accumulated slope is steep (analytic derivatives): smooth valleys, rough crests,
//   the "eroded" look of noise.
//                seed, scale, octaves, persistence, lacunarity, damp. 0..1.
//   cells        Voronoi variants. metric euclid | manhattan | chebyshev | minkowski (p); mode f1 | f2 | f3 | edge (f2
//   - f1) | crack | id | smooth (soft minimum, `smooth` = sharpness) |
//                border (exact distance to the cell border) | plate (a level per cell with bevelled borders) | facet (a
//                level per cell tilted towards the centre); scale (units), jitter, thickness, bevel, drop, warp
//                (units), warp_scale (units), seed.
//   craters      A scatter of impact craters (bowl + raised rim): scale (cell size, units), density (share of cells
//   with a crater), rmin / rmax (crater radius, share of the cell), depth, rim
//                (share of depth), shape (bowl exponent), base (level outside), seed. Result 0..1 (base +- relief).
//   dunes        Asymmetric dune ridges: wavelength (units), angle (wind direction, degrees; the crests are
//   perpendicular), asym (0 = sine, 1.5 = sharp slip face), warp (units, meander of the
//                crests), warp_size (units), variation (crest height variation), ripples (secondary wave amplitude),
//                seed. 0..1.
//   cracks       Networks of cracks (dry mud, fractured rock): scale (units), crack_width (units; not `width`, that is
//   the size of the grid), levels (1..3 finer networks), warp (units), jitter, profile v | u | flat, seed. 1 in a
//   crack, 0 on the plates. island       Island heights / masks from a ragged disc: cx, cz (world; default the middle),
//   radius (units; 0 = half the smaller side), aspect, angle (degrees), roughness (0..1 of the radius),
//                noise_scale (units), edge (coast softness, share of the radius), power (profile exponent), output
//                height | mask | distance, seed.
//   dwarp        Domain warp of `a` (optional mask): kind fbm | curl | swirl | ripple | pinch. strength (units; swirl:
//   degrees), size (units; swirl / pinch: radius), octaves, iterations (fbm: 2 =
//                warp of a warp), angle / wavelength / phase (ripple), cx, cz (swirl / pinch centre, world), seed, edge
//                clamp | wrap | mirror.
//
//   musgrave / fbm_damped also take rotate (0 default, 1: every octave in its own frame and 64 gradient directions, no
//   lattice seams: see OctaveFrame in EdFieldCore.h).
//
// Every output sample is computed from the inputs and the world position alone, so the results are bit identical for
// any thread count. The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldUtil.h"

#include <cmath>

namespace faf::editor::field
{
  using namespace t7;

  namespace
  {
    // ---- musgrave
    // --------------------------------------------------------------------------------------------------------------------------------

    bool OpMusgrave(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      const std::uint32_t seed = SeedOf(a);
      const double scale = std::max(1e-3, a.p.N("scale", 100.0));
      const int octaves = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 6))));
      const float lac = std::max(1.1f, static_cast<float>(a.p.N("lacunarity", 2.0)));
      const float hExp = static_cast<float>(a.p.N("h", 1.0));
      const float offset = static_cast<float>(a.p.N("offset", 1.0));
      const float gain = static_cast<float>(a.p.N("gain", 2.0));
      const bool rotate = a.p.N("rotate", 0.0) >= 0.5;
      const std::string mode = a.p.S("mode", "ridged");
      if (mode != "ridged" && mode != "hybrid" && mode != "hetero") {
        err = "musgrave: mode must be ridged, hybrid or hetero";
        return false;
      }
      const int kind = mode == "ridged" ? 0 : (mode == "hybrid" ? 1 : 2);
      std::vector<float> amps(static_cast<std::size_t>(octaves));
      float ampSum = 0.0f;
      for (int o = 0; o < octaves; ++o) {
        amps[static_cast<std::size_t>(o)] = std::pow(lac, -hExp * static_cast<float>(o));
        ampSum += amps[static_cast<std::size_t>(o)];
      }
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        const double wx = WorldX(g, x), wz = WorldZ(g, z);
        double freq = 1.0 / scale;
        float result = 0.0f;
        float weight = 1.0f;
        for (int o = 0; o < octaves; ++o) {
          const std::uint32_t s = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
          double qx = wx * freq, qz = wz * freq;
          if (rotate)
            RotatedPoint(o, wx * freq, wz * freq, qx, qz);
          float n = Perlin(qx, qz, s, rotate);
          n = std::max(-1.0f, std::min(1.0f, n));
          const float amp = amps[static_cast<std::size_t>(o)];
          if (kind == 0) {
            float sig = offset - std::fabs(n);
            sig *= sig;
            sig *= weight;
            weight = Clamp01(sig * gain);
            result += sig * amp;
          } else if (kind == 1) {
            const float sig = (n + offset) * amp;
            if (o == 0) {
              result = sig;
              weight = result;
            } else {
              weight = std::min(weight, 1.0f);
              result += weight * sig;
              weight *= sig;
            }
          } else {
            if (o == 0) {
              result = offset + n;
            } else {
              result += (n + offset) * amp * result;
            }
          }
          freq *= static_cast<double>(lac);
        }
        if (kind == 0)
          return Clamp01(result / (ampSum * std::max(1e-3f, offset * offset)));
        return Clamp01(result / (ampSum * std::max(1e-3f, offset + 1.0f)));
      });
      return true;
    }

    // ---- fbm_damped
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpFbmDamped(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      const std::uint32_t seed = SeedOf(a);
      const double scale = std::max(1e-3, a.p.N("scale", 150.0));
      const int octaves = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 8))));
      const float pers = static_cast<float>(a.p.N("persistence", 0.5));
      const float lac = std::max(1.1f, static_cast<float>(a.p.N("lacunarity", 2.0)));
      const float damp = std::max(0.0f, static_cast<float>(a.p.N("damp", 1.0)));
      const bool rotate = a.p.N("rotate", 0.0) >= 0.5;
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        const double wx = WorldX(g, x), wz = WorldZ(g, z);
        double freq = 1.0 / scale;
        float sum = 0.0f, norm = 0.0f, amp = 1.0f, dsx = 0.0f, dsz = 0.0f;
        for (int o = 0; o < octaves; ++o) {
          const std::uint32_t s = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
          float dnx, dnz;
          double qx = wx * freq, qz = wz * freq;
          if (rotate)
            RotatedPoint(o, wx * freq, wz * freq, qx, qz);
          const float n = PerlinD(qx, qz, s, dnx, dnz, rotate);
          if (rotate) {
            const OctaveFrame& fr = OctaveFrameOf(o); // the gradient back into the world frame
            const float gx = static_cast<float>(fr.c) * dnx + static_cast<float>(fr.s) * dnz;
            const float gz = static_cast<float>(-fr.s) * dnx + static_cast<float>(fr.c) * dnz;
            dnx = gx;
            dnz = gz;
          }
          dsx += dnx;
          dsz += dnz;
          sum += amp * n / (1.0f + damp * (dsx * dsx + dsz * dsz) * 0.25f);
          norm += amp;
          amp *= pers;
          freq *= static_cast<double>(lac);
        }
        return Clamp01(0.5f + 0.5f * sum / norm * 1.6f);
      });
      return true;
    }

    // ---- cells (Voronoi variants)
    // ----------------------------------------------------------------------------------------------------------------

    struct CellHit
    {
      float f1 = 1e9f, f2 = 1e9f, f3 = 1e9f;
      std::uint32_t id = 0;
      float cx = 0.0f, cz = 0.0f; // vector from the sample to the nearest feature point (cell units)
      float soft = 0.0f;          // sum of exp(-k d)
    };

    struct CellSetup
    {
      std::uint32_t seed = 1;
      float jitter = 1.0f;
      int metric = 0; // 0 euclid, 1 manhattan, 2 chebyshev, 3 minkowski
      float p = 3.0f;
      float k = 8.0f;
      int range = 1;
    };

    inline float Metric(
      const CellSetup& s,
      const float ex,
      const float ez
    )
    {
      switch (s.metric) {
      case 1:
        return std::fabs(ex) + std::fabs(ez);
      case 2:
        return std::max(std::fabs(ex), std::fabs(ez));
      case 3:
        return std::pow(std::pow(std::fabs(ex), s.p) + std::pow(std::fabs(ez), s.p), 1.0f / s.p);
      default:
        return std::sqrt(ex * ex + ez * ez);
      }
    }

    inline void FeaturePoint(
      const CellSetup& s,
      const int cx,
      const int cz,
      float& jx,
      float& jz,
      std::uint32_t& h
    )
    {
      h = Hash2(cx, cz, s.seed);
      jx = 0.5f + (Unit(h) - 0.5f) * s.jitter;
      jz = 0.5f + (Unit(Hash32(h ^ 0x68E31DA4U)) - 0.5f) * s.jitter;
    }

    CellHit Nearest(
      const CellSetup& s,
      const double px,
      const double pz
    )
    {
      CellHit hit;
      const double fx0 = std::floor(px), fz0 = std::floor(pz);
      const int cx = static_cast<int>(fx0), cz = static_cast<int>(fz0);
      const float lx = static_cast<float>(px - fx0), lz = static_cast<float>(pz - fz0);
      for (int dz = -s.range; dz <= s.range; ++dz) {
        for (int dx = -s.range; dx <= s.range; ++dx) {
          float jx, jz;
          std::uint32_t h;
          FeaturePoint(s, cx + dx, cz + dz, jx, jz, h);
          const float ex = static_cast<float>(dx) + jx - lx;
          const float ez = static_cast<float>(dz) + jz - lz;
          const float d = Metric(s, ex, ez);
          hit.soft += std::exp(-s.k * d);
          if (d < hit.f1) {
            hit.f3 = hit.f2;
            hit.f2 = hit.f1;
            hit.f1 = d;
            hit.id = h;
            hit.cx = ex;
            hit.cz = ez;
          } else if (d < hit.f2) {
            hit.f3 = hit.f2;
            hit.f2 = d;
          } else if (d < hit.f3) {
            hit.f3 = d;
          }
        }
      }
      return hit;
    }

    /** Exact distance (cell units) from the sample to the border of its Voronoi cell (Euclidean metric): the second
     * pass of the two pass algorithm. */
    float BorderDistance(
      const CellSetup& s,
      const double px,
      const double pz,
      const CellHit& hit
    )
    {
      const double fx0 = std::floor(px), fz0 = std::floor(pz);
      const int cx = static_cast<int>(fx0), cz = static_cast<int>(fz0);
      const float lx = static_cast<float>(px - fx0), lz = static_cast<float>(pz - fz0);
      float best = 1e9f;
      for (int dz = -2; dz <= 2; ++dz) {
        for (int dx = -2; dx <= 2; ++dx) {
          float jx, jz;
          std::uint32_t h;
          FeaturePoint(s, cx + dx, cz + dz, jx, jz, h);
          const float ex = static_cast<float>(dx) + jx - lx;
          const float ez = static_cast<float>(dz) + jz - lz;
          const float rx = ex - hit.cx, rz = ez - hit.cz;
          const float len = std::sqrt(rx * rx + rz * rz);
          if (len < 1e-5f)
            continue;
          const float d = (0.5f * (hit.cx + ex) * rx + 0.5f * (hit.cz + ez) * rz) / len;
          best = std::min(best, d);
        }
      }
      return best;
    }

    bool OpCells(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      CellSetup s;
      s.seed = SeedOf(a);
      s.jitter = Clamp01(static_cast<float>(a.p.N("jitter", 1.0)));
      const std::string metric = a.p.S("metric", "euclid");
      if (metric == "euclid")
        s.metric = 0;
      else if (metric == "manhattan")
        s.metric = 1;
      else if (metric == "chebyshev")
        s.metric = 2;
      else if (metric == "minkowski")
        s.metric = 3;
      else {
        err = "cells: metric must be euclid, manhattan, chebyshev or minkowski";
        return false;
      }
      s.p = std::max(0.2f, static_cast<float>(a.p.N("p", 3.0)));
      s.k = std::max(0.5f, static_cast<float>(a.p.N("smooth", 8.0)));
      const std::string mode = a.p.S("mode", "f1");
      static const char* const modes[] = {
        "f1", "f2", "f3", "edge", "crack", "id", "smooth", "border", "plate", "facet"
      };
      int m = -1;
      for (int i = 0; i < 10; ++i) {
        if (mode == modes[i])
          m = i;
      }
      if (m < 0) {
        err = "cells: unknown mode '" + mode + "'";
        return false;
      }
      if (m == 7 || m == 8)
        s.metric = 0; // the border distance is a Euclidean construction
      s.range = (m == 2 || m == 6 || s.metric == 1 || s.metric == 3) ? 2 : 1;
      const double scale = std::max(1e-3, a.p.N("scale", 80.0));
      const float width = std::max(1e-4f, static_cast<float>(a.p.N("thickness", 0.12)));
      const float bevel = std::max(1e-4f, static_cast<float>(a.p.N("bevel", 0.1)));
      const float drop = static_cast<float>(a.p.N("drop", 0.5));
      const double warp = a.p.N("warp", 0.0);
      const double warpScale = std::max(1.0, a.p.N("warp_scale", scale * 2.0));
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        double wx = WorldX(g, x), wz = WorldZ(g, z);
        if (warp != 0.0) {
          const float nx = Fbm01(wx, wz, s.seed + 7001U, warpScale, 3);
          const float nz = Fbm01(wx + 123.4, wz - 77.7, s.seed + 7002U, warpScale, 3);
          wx += warp * (2.0 * nx - 1.0);
          wz += warp * (2.0 * nz - 1.0);
        }
        const double px = wx / scale, pz = wz / scale;
        const CellHit hit = Nearest(s, px, pz);
        switch (m) {
        case 0:
          return Clamp01(hit.f1);
        case 1:
          return Clamp01(hit.f2 * (1.0f / 1.4f));
        case 2:
          return Clamp01(hit.f3 * (1.0f / 1.7f));
        case 3:
          return Clamp01(hit.f2 - hit.f1);
        case 4:
          return 1.0f - SmoothStep(0.0f, width, hit.f2 - hit.f1);
        case 5:
          return Unit(Hash32(hit.id ^ 0xA511E9B3U));
        case 6:
          return Clamp01(-std::log(std::max(hit.soft, 1e-20f)) / s.k);
        case 7:
          return Clamp01(2.0f * BorderDistance(s, px, pz, hit));
        case 8: {
          const float bd = BorderDistance(s, px, pz, hit);
          const float level = Unit(Hash32(hit.id ^ 0xA511E9B3U));
          return Clamp01(level * (1.0f - drop * (1.0f - SmoothStep(0.0f, bevel, bd))));
        }
        default: {
          const float level = Unit(Hash32(hit.id ^ 0xA511E9B3U));
          return Clamp01(0.7f * level + 0.3f * (1.0f - Clamp01(hit.f1)));
        }
        }
      });
      return true;
    }

    // ---- craters
    // ---------------------------------------------------------------------------------------------------------------------------------

    bool OpCraters(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      const std::uint32_t seed = SeedOf(a);
      const double scale = std::max(1.0, a.p.N("scale", 120.0));
      const float density = Clamp01(static_cast<float>(a.p.N("density", 0.6)));
      const float rmax = std::max(0.02f, std::min(0.5f, static_cast<float>(a.p.N("rmax", 0.45))));
      const float rmin = std::max(0.01f, std::min(rmax, static_cast<float>(a.p.N("rmin", 0.15))));
      const float depth = static_cast<float>(a.p.N("depth", 0.4));
      const float rim = static_cast<float>(a.p.N("rim", 0.25));
      const float shape = std::max(0.5f, static_cast<float>(a.p.N("shape", 1.5)));
      const float base = static_cast<float>(a.p.N("base", 0.5));
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        const double px = WorldX(g, x) / scale, pz = WorldZ(g, z) / scale;
        const double fx0 = std::floor(px), fz0 = std::floor(pz);
        const int cx = static_cast<int>(fx0), cz = static_cast<int>(fz0);
        const float lx = static_cast<float>(px - fx0), lz = static_cast<float>(pz - fz0);
        float sum = 0.0f;
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            const std::uint32_t h = Hash2(cx + dx, cz + dz, seed);
            if (Unit(h) > density)
              continue;
            const float rr = rmin + (rmax - rmin) * Unit(Hash32(h ^ 0x1234567U));
            const float fxp = rr + (1.0f - 2.0f * rr) * Unit(Hash32(h ^ 0x9E3779B9U));
            const float fzp = rr + (1.0f - 2.0f * rr) * Unit(Hash32(h ^ 0x7F4A7C15U));
            const float ex = static_cast<float>(dx) + fxp - lx;
            const float ez = static_cast<float>(dz) + fzp - lz;
            const float r = std::sqrt(ex * ex + ez * ez) / rr;
            if (r > 2.2f)
              continue;
            const float d = depth * (rr / rmax) * (0.7f + 0.3f * Unit(Hash32(h ^ 0x2545F491U)));
            float v = 0.0f;
            if (r < 1.0f)
              v -= d * std::pow(1.0f - r * r, shape);
            const float t = (r - 1.0f) / 0.3f;
            v += d * rim * std::exp(-t * t);
            sum += v;
          }
        }
        return Clamp01(base + sum);
      });
      return true;
    }

    // ---- dunes
    // -----------------------------------------------------------------------------------------------------------------------------------

    bool OpDunes(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      const std::uint32_t seed = SeedOf(a);
      const double wl = std::max(1.0, a.p.N("wavelength", 60.0));
      const double ang = a.p.N("angle", 0.0) * kPiD / 180.0;
      const double ux = std::cos(ang), uz = std::sin(ang);
      const float asym = static_cast<float>(a.p.N("asym", 0.9));
      const double warp = a.p.N("warp", 25.0);
      const double warpSize = std::max(2.0, a.p.N("warp_size", 120.0));
      const float variation = Clamp01(static_cast<float>(a.p.N("variation", 0.4)));
      const float ripples = Clamp01(static_cast<float>(a.p.N("ripples", 0.12)));
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        const double wx = WorldX(g, x), wz = WorldZ(g, z);
        const float meander = Fbm01(wx, wz, seed + 31U, warpSize, 3) - 0.5f;
        const double s = (wx * ux + wz * uz + warp * 2.0 * static_cast<double>(meander)) / wl;
        const double th = 2.0 * kPiD * (s - std::floor(s));
        const float wave = 0.5f - 0.5f * std::cos(static_cast<float>(th) + asym * std::sin(static_cast<float>(th)));
        const float crest = 1.0f - variation + variation * 2.0f * Fbm01(wx, wz, seed + 77U, warpSize * 1.7, 2);
        float v = wave * Clamp01(crest);
        if (ripples > 0.0f) {
          const double sr = (wx * ux + wz * uz + warp * 1.5 * static_cast<double>(meander)) / (wl * 0.12);
          const float rp = 0.5f - 0.5f * std::cos(static_cast<float>(2.0 * kPiD * (sr - std::floor(sr))) + 0.8f);
          v = v * (1.0f - ripples) + ripples * rp * (0.3f + 0.7f * wave);
        }
        return Clamp01(v);
      });
      return true;
    }

    // ---- cracks
    // ----------------------------------------------------------------------------------------------------------------------------------

    bool OpCracks(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      CellSetup s;
      s.seed = SeedOf(a);
      s.jitter = Clamp01(static_cast<float>(a.p.N("jitter", 0.9)));
      s.range = 1;
      const double scale = std::max(2.0, a.p.N("scale", 80.0));
      const double width = std::max(0.05, a.p.N("crack_width", 3.0));
      const int levels = std::max(1, std::min(3, static_cast<int>(a.p.N("levels", 2))));
      const double warp = a.p.N("warp", 12.0);
      const std::string profile = a.p.S("profile", "v");
      const int prof = profile == "u" ? 1 : (profile == "flat" ? 2 : 0);
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        double wx = WorldX(g, x), wz = WorldZ(g, z);
        if (warp != 0.0) {
          const float nx = Fbm01(wx, wz, s.seed + 5101U, scale * 1.5, 3);
          const float nz = Fbm01(wx + 55.5, wz + 91.1, s.seed + 5102U, scale * 1.5, 3);
          wx += warp * (2.0 * nx - 1.0);
          wz += warp * (2.0 * nz - 1.0);
        }
        float best = 0.0f;
        double sc = scale;
        double wd = width;
        float weight = 1.0f;
        for (int lv = 0; lv < levels; ++lv) {
          CellSetup t = s;
          t.seed = s.seed + static_cast<std::uint32_t>(lv) * 977U;
          const double px = wx / sc, pz = wz / sc;
          const CellHit hit = Nearest(t, px, pz);
          const float bd = BorderDistance(t, px, pz, hit) * static_cast<float>(sc); // units
          const float half = static_cast<float>(wd * 0.5);
          float c;
          if (prof == 2)
            c = bd < half ? 1.0f : 0.0f;
          else if (prof == 1)
            c = 1.0f - SmoothStep(half * 0.6f, half * 1.2f, bd);
          else
            c = Clamp01(1.0f - bd / std::max(half, 1e-3f));
          best = std::max(best, c * weight);
          sc *= 0.45;
          wd *= 0.6;
          weight *= 0.65f;
        }
        return Clamp01(best);
      });
      return true;
    }

    // ---- island
    // ----------------------------------------------------------------------------------------------------------------------------------

    bool OpIsland(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      const std::string output = a.p.S("output", "height");
      if (output != "height" && output != "mask" && output != "distance") {
        err = "island: output must be height, mask or distance";
        return false;
      }
      const Grid& g = out;
      const double cxw = a.p.Has("cx") ? a.p.N("cx", 0) : WorldX(g, 0) + 0.5 * (g.w - 1) * g.cell;
      const double czw = a.p.Has("cz") ? a.p.N("cz", 0) : WorldZ(g, 0) + 0.5 * (g.h - 1) * g.cell;
      const double radius = std::max(
        1e-3,
        a.p.Has("radius") && a.p.N("radius", 0) > 0.0 ? a.p.N("radius", 1) : 0.5 * std::min(g.w - 1, g.h - 1) * g.cell
      );
      const double aspect = std::max(0.2, a.p.N("aspect", 1.0));
      const double ang = a.p.N("angle", 0.0) * kPiD / 180.0;
      const double ca = std::cos(ang), sa = std::sin(ang);
      const float rough = static_cast<float>(a.p.N("roughness", 0.35));
      const double nscale = std::max(2.0, a.p.N("noise_scale", radius * 0.5));
      const float edge = std::max(0.005f, static_cast<float>(a.p.N("edge", 0.08)));
      const float power = std::max(0.2f, static_cast<float>(a.p.N("power", 1.4)));
      const std::uint32_t seed = SeedOf(a);
      const int mode = output == "height" ? 0 : (output == "mask" ? 1 : 2);
      Cells(out, [&](const int x, const int z) {
        const double ex = WorldX(g, x) - cxw, ez = WorldZ(g, z) - czw;
        const double u = (ex * ca + ez * sa) / aspect, v = -ex * sa + ez * ca;
        float q = static_cast<float>(std::sqrt(u * u + v * v) / radius);
        const float n = Fbm01(WorldX(g, x), WorldZ(g, z), seed, nscale, 5);
        q += rough * (n - 0.5f) * 2.0f * (0.3f + 0.7f * std::min(1.0f, q));
        if (mode == 1)
          return 1.0f - SmoothStep(1.0f - edge, 1.0f, q);
        if (mode == 2)
          return Clamp01(1.0f - q);
        const float land = 1.0f - SmoothStep(1.0f - edge, 1.0f, q);
        return land * std::pow(Clamp01(1.0f - q * 0.9f), power);
      });
      return true;
    }

    // ---- dwarp
    // -----------------------------------------------------------------------------------------------------------------------------------

    bool OpDWarp(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* mask = Get(a, "mask");
      if (!SameOrNone(mask, *src, "mask", err))
        return false;
      const std::string kind = a.p.S("kind", "fbm");
      if (kind != "fbm" && kind != "curl" && kind != "swirl" && kind != "ripple" && kind != "pinch") {
        err = "dwarp: kind must be fbm, curl, swirl, ripple or pinch";
        return false;
      }
      const int k = kind == "fbm" ? 0 : (kind == "curl" ? 1 : (kind == "swirl" ? 2 : (kind == "ripple" ? 3 : 4)));
      const std::uint32_t seed = SeedOf(a);
      const double strength = a.p.N("strength", 40.0);
      const double size = std::max(1.0, a.p.N("size", 100.0));
      const int octaves = std::max(1, std::min(8, static_cast<int>(a.p.N("octaves", 3))));
      const int iters = std::max(1, std::min(3, static_cast<int>(a.p.N("iterations", 1))));
      const Edge e = ParseEdge(a, kClamp);
      const Grid& g = out;
      const double cxw = a.p.Has("cx") ? a.p.N("cx", 0) : WorldX(g, 0) + 0.5 * (g.w - 1) * g.cell;
      const double czw = a.p.Has("cz") ? a.p.N("cz", 0) : WorldZ(g, 0) + 0.5 * (g.h - 1) * g.cell;
      const double ang = a.p.N("angle", 0.0) * kPiD / 180.0;
      const double rx = std::cos(ang), rz = std::sin(ang);
      const double wl = std::max(1.0, a.p.N("wavelength", 60.0));
      const double phase = a.p.N("phase", 0.0);
      const double cell = static_cast<double>(g.cell);
      Cells(out, [&](const int x, const int z) {
        const double wx = WorldX(g, x), wz = WorldZ(g, z);
        double dx = 0.0, dz = 0.0; // displacement in world units
        if (k == 0) {
          double px = wx, pz = wz;
          for (int it = 0; it < iters; ++it) {
            const double ox = (2.0 * Fbm01(px, pz, seed, size, octaves) - 1.0);
            const double oz = (2.0 * Fbm01(px + 17.3, pz - 41.9, seed + 1U, size, octaves) - 1.0);
            dx = ox * strength;
            dz = oz * strength;
            px = wx + dx * 0.8;
            pz = wz + dz * 0.8;
          }
        } else if (k == 1) {
          double freq = 1.0 / size;
          float sx = 0.0f, sz = 0.0f, amp = 1.0f, norm = 0.0f;
          for (int o = 0; o < octaves; ++o) {
            float dnx, dnz;
            const std::uint32_t s = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
            PerlinD(wx * freq, wz * freq, s, dnx, dnz);
            sx += amp * dnx;
            sz += amp * dnz;
            norm += amp;
            amp *= 0.5f;
            freq *= 2.0;
          }
          dx = strength * 0.5 * static_cast<double>(sz / norm);
          dz = -strength * 0.5 * static_cast<double>(sx / norm);
        } else if (k == 2) {
          const double ex = wx - cxw, ez = wz - czw;
          const double d = std::sqrt(ex * ex + ez * ez) / size;
          const double rot = strength * kPiD / 180.0 * std::exp(-d * d);
          const double c = std::cos(rot), s = std::sin(rot);
          dx = (ex * c - ez * s + cxw) - wx;
          dz = (ex * s + ez * c + czw) - wz;
        } else if (k == 3) {
          const double s = -wx * rz + wz * rx; // across the ripple direction
          const double wave = std::sin(2.0 * kPiD * s / wl + phase);
          dx = rx * strength * wave;
          dz = rz * strength * wave;
        } else {
          const double ex = wx - cxw, ez = wz - czw;
          const double d = std::sqrt(ex * ex + ez * ez) / size;
          const double f = 1.0 - strength * std::exp(-d * d); // strength is a factor here (0.5 = magnify the middle)
          dx = ex * f + cxw - wx;
          dz = ez * f + czw - wz;
        }
        const float warped = Bilinear(*src, static_cast<double>(x) + dx / cell, static_cast<double>(z) + dz / cell, e);
        return mask != nullptr ? Lerp(src->At(x, z), warped, Clamp01(mask->At(x, z))) : warped;
      });
      return true;
    }

    struct GenOpRegistrar
    {
      GenOpRegistrar()
      {
        RegisterOp("musgrave", &OpMusgrave);
        RegisterOp("fbm_damped", &OpFbmDamped);
        RegisterOp("cells", &OpCells);
        RegisterOp("craters", &OpCraters);
        RegisterOp("dunes", &OpDunes);
        RegisterOp("cracks", &OpCracks);
        RegisterOp("island", &OpIsland);
        RegisterOp("dwarp", &OpDWarp);
      }
    };
    const GenOpRegistrar gGenOpRegistrar{};
  } // namespace
} // namespace faf::editor::field
