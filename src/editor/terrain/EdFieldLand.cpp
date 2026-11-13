// ops of the Fields panel's "Generate" section: natural looking terrain noise and the maths that mixes a generated
// relief into the terrain that is already there. Engine independent like EdFieldCore; registered through RegisterOp.
// Tested by tests/editor/FieldLandTests.cpp.
//
//   fractal      Generator (like / width, height). Fractal gradient noise built to look like land:
//                  seed, scale (feature size, units), octaves (1..16), finest (smallest wavelength an octave may have,
//                  units: octaves below it are dropped, default 0 = keep all), persistence (gain per octave, default
//                  0.5), lacunarity (default 2), kind fbm (default) | billow (rounded hills) | ridged (sharp crests,
//                  ridged multifractal: every octave is weighted by the one before), sharpness (ridged: ridge exponent,
//                  default 2 = round crests, 3+ = knife edges), warp (domain warp by a second noise, units, default 0;
//                  an octave is moved by at most a quarter of its own wavelength), warp_scale (units, default 0.8 *
//                  scale), slope_detail (-1..1: finer octaves are louder where the coarser ones are steep (+) or on the
//                  flat ground (-), default 0), rotate (default 1: every octave in its own turned and shifted frame,
//                  see OctaveFrame in EdFieldCore.h; 0 = all octaves on the same lattice, for comparison). The gradient
//                  noise uses 64 gradient directions (no preferred axis). Result in 0..1 (0.5 = the middle; extremes
//                  are rounded off softly, never cut flat): use `amplitude` to get world units.
//   amplitude    a = any field. Zero-mean relief with an exact size: out = (a - centre) * k. mode peak (default: the
//   largest deviation from the centre becomes exactly `amplitude`) |
//                range (highest minus lowest becomes exactly `amplitude`) | sd (the standard deviation becomes
//                `amplitude`). centre mean (default: zero-mean result) | min (the lowest sample becomes 0, so the
//                result lies in 0..size). A field without any variation gives 0. Statistics are taken over the whole
//                field in a fixed order (the same bits for any thread count).
//   terrain_mix  a = the terrain, b = a zero-mean relief (the `amplitude` of a generator), optional mask (0..1). The
//   result is what the terrain becomes: a + (target - a) * strength * mask with
//                the target by `mode`: add (a + b) | multiply (a + b * (a - lowest) / (highest - lowest): higher ground
//                gets more of the relief, the lowest point none) | max (raise only: a + max(b, 0)) | min (lower only: a
//                + min(b, 0)) | replace (mean(a) + b: the relief instead of the terrain, the average height stays).
//                strength 0..1 (default 1). Where strength * mask is 0 the result is exactly `a`.
//   keep_side    a = a changed terrain, b = the terrain before. Water level `level`, `margin` (units, default 0.25):
//   ground that was above the water stays at least margin above it, ground that
//                was below stays at least margin below it (a sample that was within margin of the surface keeps its own
//                distance). `soft` (units, default 1) rounds the clamp (a smooth maximum that never goes below the
//                limit), 0 = hard. Only a lowered dry sample or a raised wet one is touched, and never moved past its
//                old height: everything else is exactly `a`.
//
// Every output sample is computed from the inputs and the world position alone, so the results are bit identical for
// any thread count. The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldFractal.h"
#include "editor/terrain/EdFieldUtil.h"

#include <cmath>

namespace faf::editor::field
{
  using namespace t7;

  namespace
  {
    // ---- fractal
    // ---------------------------------------------------------------------------------------------------------------------------------

    using fractal::Kind;
    using fractal::Setup;
    using fractal::kBillow;
    using fractal::kErosive;
    using fractal::kFbm;
    using fractal::kRidged;
    using FractalSetup = Setup;

    /** Octave o of the gradient noise at the point (wx, wz) (world), with the gradient per lattice unit in the world
     * frame. */
    inline float Octave(
      const FractalSetup& s,
      const int o,
      const double px,
      const double pz,
      float& gx,
      float& gz
    )
    {
      double qx = px, qz = pz;
      if (s.rotate)
        RotatedPoint(o, px, pz, qx, qz);
      float dx, dz;
      const float n = PerlinD(qx, qz, s.octSeed[o], dx, dz, true);
      if (s.rotate) {
        const OctaveFrame& fr = OctaveFrameOf(o);
        gx = static_cast<float>(fr.c) * dx + static_cast<float>(fr.s) * dz;
        gz = static_cast<float>(-fr.s) * dx + static_cast<float>(fr.c) * dz;
      } else {
        gx = dx;
        gz = dz;
      }
      return std::max(-1.0f, std::min(1.0f, n));
    }

    /** Three octave noise in about -1..1 (the warp field), its own seeds. */
    inline float WarpNoise(
      const FractalSetup& s,
      const std::uint32_t salt,
      const double wx,
      const double wz
    )
    {
      float sum = 0.0f, norm = 0.0f, amp = 1.0f;
      double freq = 1.0 / s.warpScale;
      for (int o = 0; o < 3; ++o) {
        const std::uint32_t seed = Hash32(s.seed * 977U + salt * 31U + static_cast<std::uint32_t>(o) * 6151U + 5U);
        double qx = wx * freq, qz = wz * freq;
        if (s.rotate)
          RotatedPoint(o + 5, wx * freq, wz * freq, qx, qz);
        sum += amp * std::max(-1.0f, std::min(1.0f, Perlin(qx, qz, seed, true)));
        norm += amp;
        amp *= 0.5f;
        freq *= 2.0;
      }
      return sum / norm;
    }

    float FractalAt(
      const FractalSetup& s,
      const double wx0,
      const double wz0
    )
    {
      double warpX = 0.0, warpZ = 0.0;
      if (s.warp > 0.0) {
        warpX = static_cast<double>(WarpNoise(s, 1, wx0, wz0)) * s.warp;
        warpZ = static_cast<double>(WarpNoise(s, 2, wx0, wz0)) * s.warp;
        if (s.warpLevels >= 2) { // a warp of a warp: the second pair of noises is read at the place the first one moved
                                 // to
          const double px = wx0 + warpX * 0.8, pz = wz0 + warpZ * 0.8;
          warpX = static_cast<double>(WarpNoise(s, 3, px, pz)) * s.warp;
          warpZ = static_cast<double>(WarpNoise(s, 4, px, pz)) * s.warp;
        }
      }
      const bool erosive = s.style == kErosive;
      float sum = 0.0f;
      float weight = 1.0f;
      float accX = 0.0f, accZ = 0.0f,
            accAmp = 0.0f; // gradient of the octaves so far, in units of (amplitude per feature size)
      float eroX = 0.0f, eroZ = 0.0f,
            eroAmp = 0.0f; // the same for the signal of the erosive style (the gradient of what is summed)
      for (int o = 0; o < s.octaves; ++o) {
        const double freq = s.freq[o];
        // An octave is moved by the warp, but never by more than a quarter of its own wavelength: the broad shapes bend
        // a lot, the fine ones only a little (a fine octave pushed by many wavelengths turns into smeared, worm like
        // ridges).
        const double move = s.move[o];
        float gx, gz;
        const float n = Octave(s, o, (wx0 + warpX * move) * freq, (wz0 + warpZ * move) * freq, gx, gz);
        float amp = s.amps[o];
        if (s.slopeDetail != 0.0f && o > 0 && accAmp > 0.0f) {
          const float steep =
            std::sqrt(accX * accX + accZ * accZ) / accAmp; // about 1 on the typical slope of the coarse octaves
          const float f = Clamp01(steep * 0.6f);
          amp *= std::max(0.0f, 1.0f + s.slopeDetail * (2.0f * f - 1.0f));
        }
        if (erosive && o > 0 && eroAmp > 0.0f) {
          const float steep2 = (eroX * eroX + eroZ * eroZ) /
            (eroAmp * eroAmp); // the squared slope of the terrain so far (about 1 on the typical slope)
          amp /= 1.0f + s.erosion * steep2;
        }
        amp *= s.fade[o];
        float signal;
        float sgx = gx, sgz = gz; // gradient of the signal (per lattice unit), erosive style only
        switch (s.kind) {
        case kBillow:
          signal = 2.0f * (std::fabs(n) - 0.25f);
          if (erosive) {
            const float sg = n < 0.0f ? -2.0f : 2.0f;
            sgx *= sg;
            sgz *= sg;
          }
          break;
        case kRidged: {
          const float r0 = 1.0f - std::fabs(n);
          float r = s.sharp == 2.0f ? r0 * r0 : std::pow(r0, s.sharp);
          if (erosive) {
            const float dr = -s.sharp * (s.sharp == 2.0f ? r0 : std::pow(std::max(r0, 1e-6f), s.sharp - 1.0f)) *
              (n < 0.0f ? -1.0f : 1.0f) * 2.0f * weight;
            sgx *= dr;
            sgz *= dr;
          }
          r *= weight;
          weight = Clamp01(r * 2.0f);
          signal = 2.0f * r - 1.0f;
          break;
        }
        default:
          signal = n;
          break;
        }
        sum += signal * amp;
        const float k = static_cast<float>(freq * s.scale);
        accX += s.amps[o] * gx * k;
        accZ += s.amps[o] * gz * k;
        accAmp += s.amps[o];
        if (erosive) {
          eroX += s.amps[o] * sgx * k;
          eroZ += s.amps[o] * sgz * k;
          eroAmp += s.amps[o];
        }
      }
      // soft limit instead of a clamp: a clamp would cut flat topped discs into the highest peaks
      const float x = sum / s.norm * s.fit;
      return 0.5f + 0.5f * x / (1.0f + std::fabs(x));
    }

    bool OpFractal(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      if (!MakeOut(a, out, err))
        return false;
      FractalSetup s;
      if (!fractal::Read(a, out.cell, s, err))
        return false;
      const Grid& g = out;
      Cells(out, [&](const int x, const int z) {
        return FractalAt(s, WorldX(g, x), WorldZ(g, z));
      });
      return true;
    }

    // ---- amplitude
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpAmplitude(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const double amp = a.p.N("amplitude", 10.0);
      const std::string mode = a.p.S("mode", "peak");
      const std::string centre = a.p.S("centre", "mean");
      if (mode != "peak" && mode != "range" && mode != "sd") {
        err = "amplitude: mode must be peak, range or sd";
        return false;
      }
      if (centre != "mean" && centre != "min") {
        err = "amplitude: centre must be mean or min";
        return false;
      }
      // fixed order statistics in double: the same bits for any thread count
      double sum = 0.0;
      float lo = src->v.empty() ? 0.0f : src->v[0], hi = lo;
      for (const float v : src->v) {
        sum += static_cast<double>(v);
        lo = std::min(lo, v);
        hi = std::max(hi, v);
      }
      const double n = static_cast<double>(std::max<std::size_t>(1, src->v.size()));
      const double mean = sum / n;
      double var = 0.0;
      for (const float v : src->v)
        var += (static_cast<double>(v) - mean) * (static_cast<double>(v) - mean);
      const double sd = std::sqrt(var / n);
      double base = mean;
      double size;
      if (mode == "peak")
        size = std::max(mean - static_cast<double>(lo), static_cast<double>(hi) - mean);
      else if (mode == "range")
        size = static_cast<double>(hi) - static_cast<double>(lo);
      else
        size = sd;
      if (centre == "min")
        base = static_cast<double>(lo);
      const double k = size > 1e-12 ? amp / size : 0.0;
      Cells(out, [&](const int x, const int z) {
        return static_cast<float>((static_cast<double>(src->At(x, z)) - base) * k);
      });
      return true;
    }

    // ---- terrain_mix
    // -----------------------------------------------------------------------------------------------------------------------------

    bool OpTerrainMix(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* ter = Need(a, "a", err);
      const Grid* rel = Need(a, "b", err);
      if (ter == nullptr || rel == nullptr || !MakeOut(a, out, err))
        return false;
      if (!rel->SameShape(*ter)) {
        err = "terrain_mix: the relief differs in size from the terrain";
        return false;
      }
      const Grid* mask = Get(a, "mask");
      if (!SameOrNone(mask, *ter, "mask", err))
        return false;
      const std::string mode = a.p.S("mode", "add");
      if (mode != "add" && mode != "multiply" && mode != "max" && mode != "min" && mode != "replace") {
        err = "terrain_mix: mode must be add, multiply, max, min or replace";
        return false;
      }
      const float strength = Clamp01(static_cast<float>(a.p.N("strength", 1.0)));
      double sum = 0.0;
      float lo = ter->v.empty() ? 0.0f : ter->v[0], hi = lo;
      for (const float v : ter->v) {
        sum += static_cast<double>(v);
        lo = std::min(lo, v);
        hi = std::max(hi, v);
      }
      const float mean = static_cast<float>(sum / static_cast<double>(std::max<std::size_t>(1, ter->v.size())));
      const float span = hi - lo;
      Cells(out, [&](const int x, const int z) {
        const float h = ter->At(x, z);
        const float t = strength * (mask != nullptr ? Clamp01(mask->At(x, z)) : 1.0f);
        if (t <= 0.0f)
          return h;
        const float d = rel->At(x, z);
        float target;
        if (mode == "add")
          target = h + d;
        else if (mode == "multiply")
          target = h + d * (span > 1e-6f ? (h - lo) / span : 1.0f);
        else if (mode == "max")
          target = h + std::max(d, 0.0f);
        else if (mode == "min")
          target = h + std::min(d, 0.0f);
        else
          target = mean + d;
        return h + (target - h) * t;
      });
      return true;
    }

    // ---- keep_side
    // -------------------------------------------------------------------------------------------------------------------------------

    /** A maximum that never goes below max(a, b) and exceeds it by at most k / 4 (polynomial smooth maximum). */
    inline float SoftMax(
      const float a,
      const float b,
      const float k
    )
    {
      const float m = std::max(a, b);
      if (k <= 1e-6f)
        return m;
      const float h = std::max(k - std::fabs(a - b), 0.0f) / k;
      return m + h * h * k * 0.25f;
    }

    bool OpKeepSide(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* res = Need(a, "a", err);
      const Grid* before = Need(a, "b", err);
      if (res == nullptr || before == nullptr || !MakeOut(a, out, err))
        return false;
      if (!before->SameShape(*res)) {
        err = "keep_side: the two terrains differ in size";
        return false;
      }
      const float level = static_cast<float>(a.p.N("level", 25.0));
      const float margin = std::max(0.0f, static_cast<float>(a.p.N("margin", 0.25)));
      const float soft = std::max(0.0f, static_cast<float>(a.p.N("soft", 1.0)));
      Cells(out, [&](const int x, const int z) {
        const float r = res->At(x, z);
        const float h = before->At(x, z);
        if (h >= level) {
          if (r >= h)
            return r; // raised or untouched dry ground can not go under water
          const float floorH =
            level + std::min(margin, h - level); // ground that was barely above the water stays barely above it
          return std::min(h, SoftMax(r, floorH, soft));
        }
        if (r <= h)
          return r;
        const float ceilH = level - std::min(margin, level - h);
        return std::max(h, -SoftMax(-r, -ceilH, soft));
      });
      return true;
    }

    struct LandOpRegistrar
    {
      LandOpRegistrar()
      {
        RegisterOp("fractal", &OpFractal);
        RegisterOp("amplitude", &OpAmplitude);
        RegisterOp("terrain_mix", &OpTerrainMix);
        RegisterOp("keep_side", &OpKeepSide);
      }
    };
    const LandOpRegistrar gLandOpRegistrar{};
  } // namespace
} // namespace faf::editor::field
