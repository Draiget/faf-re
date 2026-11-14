// the parameters of the `fractal` op, shared by the CPU op (EdFieldLand.cpp) and its GPU version (EdGpuGen.cpp), so
// both read every option the same way (same clamps, same octave amplitudes, seeds, wavelengths). Header only, engine
// independent. Documentation of the options: EdFieldLand.cpp.
#pragma once
// The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldUtil.h"

#include <algorithm>
#include <cmath>
#include <string>

namespace faf::editor::field::fractal
{
  enum Kind
  {
    kFbm = 0,
    kBillow = 1,
    kRidged = 2
  };
  enum Style
  {
    kClassic = 0,
    kErosive = 1
  };

  struct Setup
  {
    std::uint32_t seed = 1;
    double scale = 120.0;
    int octaves = 6;
    float gain = 0.5f;
    float lac = 2.0f;
    Kind kind = kFbm;
    Style style = kClassic;
    float erosion = 1.0f; // erosive style: how strongly steep ground damps the finer octaves (already multiplied by 0.5
                          // for ridged noise, whose crests are steep by nature)
    float sharp = 2.0f;
    double warp = 0.0;
    double warpScale = 96.0;
    int warpLevels = 1; // 2 = the warp is itself evaluated at a warped place (a warp of a warp)
    float slopeDetail = 0.0f;
    bool rotate = true;
    bool antialias = false; // octaves with a wavelength of 2..4 samples fade out, shorter ones are dropped: a coarse
                            // preview is a low-pass of the full resolution result
    float norm = 0.0f;      // sum of the octave amplitudes
    float fit = 1.0f;       // maps the normalised sum to about 0..1
    float amps[16] = {};
    float fade[16] = {};  // antialias factor per octave (1 without antialias)
    double freq[16] = {}; // lattice units per world unit
    double wave[16] = {}; // wavelength in world units
    double move[16] = {}; // how much of the domain warp an octave follows (0..1)
    std::uint32_t octSeed[16] = {};
  };

  /** Reads the options of `op fractal`; `cell` = world units between two samples of the output (for antialias). false
   * with `err` set on a bad option. */
  inline bool Read(
    const OpArgs& a,
    const float cell,
    Setup& s,
    std::string& err
  )
  {
    using namespace t7;
    s = Setup();
    s.seed = SeedOf(a);
    s.scale = std::max(1e-3, a.p.N("scale", 120.0));
    const int wantOct = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 6))));
    s.gain = std::max(0.05f, std::min(0.95f, static_cast<float>(a.p.N("persistence", 0.5))));
    s.lac = std::max(1.2f, std::min(4.0f, static_cast<float>(a.p.N("lacunarity", 2.0))));
    const std::string kind = a.p.S("kind", "fbm");
    if (kind == "fbm")
      s.kind = kFbm;
    else if (kind == "billow")
      s.kind = kBillow;
    else if (kind == "ridged")
      s.kind = kRidged;
    else {
      err = "fractal: kind must be fbm, billow or ridged";
      return false;
    }
    const std::string style = a.p.S("style", "classic");
    if (style == "classic")
      s.style = kClassic;
    else if (style == "erosive")
      s.style = kErosive;
    else {
      err = "fractal: style must be classic or erosive";
      return false;
    }
    s.erosion =
      std::max(0.0f, std::min(16.0f, static_cast<float>(a.p.N("erosion", 1.0)))) * (s.kind == kRidged ? 0.5f : 1.0f);
    s.sharp = std::max(0.5f, std::min(8.0f, static_cast<float>(a.p.N("sharpness", 2.0))));
    s.warp = std::max(0.0, a.p.N("warp", 0.0));
    s.warpScale = std::max(1e-3, a.p.N("warp_scale", 0.8 * s.scale));
    s.warpLevels = std::max(1, std::min(2, static_cast<int>(a.p.N("warp_levels", 1))));
    s.slopeDetail = std::max(-1.0f, std::min(1.0f, static_cast<float>(a.p.N("slope_detail", 0.0))));
    s.rotate = a.p.N("rotate", 1.0) >= 0.5;
    s.antialias = a.p.N("antialias", 0.0) >= 0.5;
    const double finest = std::max(0.0, a.p.N("finest", 0.0));
    int octaves = 1;
    double wave = s.scale;
    const auto fadeOf = [&](const double wl) {
      if (!s.antialias)
        return 1.0f;
      const float r = static_cast<float>(wl / static_cast<double>(cell));
      const float t = Clamp01((r - 2.0f) * 0.5f);
      return t * t * (3.0f - 2.0f * t);
    };
    while (octaves < wantOct && wave / static_cast<double>(s.lac) >= finest &&
           fadeOf(wave / static_cast<double>(s.lac)) > 0.0f) {
      wave /= static_cast<double>(s.lac);
      ++octaves;
    }
    s.octaves = octaves;
    float amp = 1.0f;
    double freq = 1.0 / s.scale;
    double wavelength = s.scale;
    for (int o = 0; o < octaves; ++o) {
      s.amps[o] = amp;
      s.norm += amp;
      s.octSeed[o] = Hash32(s.seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
      s.freq[o] = freq;
      s.wave[o] = wavelength;
      s.fade[o] = o == 0 ? 1.0f : fadeOf(wavelength);
      s.move[o] = s.warp > 0.0 ? std::min(1.0, wavelength / (4.0 * s.warp)) : 0.0;
      amp *= s.gain;
      freq *= static_cast<double>(s.lac);
      wavelength /= static_cast<double>(s.lac);
    }
    // The sum of the octaves is rarely near its theoretical limit: stretch it so the typical extremes land near 0 and 1
    // (the exact size is the job of `amplitude`).
    switch (s.kind) {
    case kRidged:
      s.fit = 1.6f;
      break;
    case kBillow:
      s.fit = 2.7f;
      break;
    default:
      s.fit = 3.0f;
      break;
    }
    s.fit = static_cast<float>(a.p.N("fit", static_cast<double>(s.fit)));
    return true;
  }
} // namespace faf::editor::field::fractal
