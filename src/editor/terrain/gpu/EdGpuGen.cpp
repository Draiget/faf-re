// EDITOR GPU compute: GPU versions of the generator ops (noise: perlin simplex ridged billow fractal musgrave
// fbm_damped; cellular: voronoi cells cracks; craters dunes island). Generators have no input field, so the only
// transfer is the download of the result: they are the best case for the GPU. Each op reads its options exactly like
// the CPU op (the same clamps; `fractal` through EdFieldFractal.h) and answers Unsupported for what it does not handle,
// so the CPU op keeps working. docs/projects/editor/GPU_COMPUTE.md, "Generator and filter kernels".
#pragma fp_contract(off)

#include "editor/terrain/gpu/EdGpuGen.h"

#include "editor/terrain/EdFieldFractal.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/gen_fbm_params.hlsli"
#include "editor/terrain/gpu/gen_cells_params.hlsli"
#include "editor/terrain/gpu/gen_craters_params.hlsli"
#include "editor/terrain/gpu/gen_dunes_params.hlsli"
#include "editor/terrain/gpu/gen_fbmd_params.hlsli"
#include "editor/terrain/gpu/gen_fractal_params.hlsli"
#include "editor/terrain/gpu/gen_island_params.hlsli"
#include "editor/terrain/gpu/gen_musgrave_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using namespace gen;
  namespace fractal = field::fractal;

  namespace
  {
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

    // ---- perlin, simplex, ridged, billow
    // --------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpNoiseGpu(
      Executor& ex,
      const OpArgs& a,
      const int kind,
      const char* const defaultBasis,
      Grid& out
    )
    {
      Shape s;
      if (!ShapeOf(a, s) || !Fits(ex, s.Count(), 1))
        return OpResult::Unsupported;
      const std::uint32_t seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const double scale = std::max(1e-3, a.p.N("scale", 100.0));
      const int octaves = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 5))));
      const float persistence = static_cast<float>(a.p.N("persistence", 0.5));
      const float lacunarity = static_cast<float>(a.p.N("lacunarity", 2.0));
      const int basis = (a.p.S("basis", defaultBasis) == "simplex") ? 1 : 0;
      const double shiftX = a.p.N("shiftx", 0.0);
      const double shiftZ = a.p.N("shiftz", 0.0);
      const bool rotate = a.p.N("rotate", 0.0) >= 0.5;
      std::vector<float> tab(static_cast<std::size_t>(octaves) * 16u, 0.0f);
      std::vector<std::uint32_t> seeds(static_cast<std::size_t>(octaves));
      float amp = 1.0f;
      float norm = 0.0f;
      double freq = 1.0 / scale;
      for (int o = 0; o < octaves; ++o) {
        seeds[static_cast<std::size_t>(o)] = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
        double c = 1.0, sn = 0.0, fox = 0.0, foz = 0.0;
        if (rotate) {
          const field::OctaveFrame& fr = field::OctaveFrameOf(o);
          c = fr.c;
          sn = fr.s;
          fox = fr.ox;
          foz = fr.oz;
        }
        const double wox = static_cast<double>(s.ox) + shiftX, woz = static_cast<double>(s.oz) + shiftZ;
        const bool ok = basis == 1 ? PutSimplexMap(tab, o, wox, woz, s.cell, freq, c, sn, fox, foz)
                                   : PutOctaveMap(tab, o, wox, woz, s.cell, freq, c, sn, fox, foz);
        if (!ok)
          return OpResult::Unsupported;
        tab[static_cast<std::size_t>(o) * 16u + 8u] = amp;
        norm += amp;
        amp *= persistence;
        freq *= static_cast<double>(lacunarity);
      }
      std::unique_ptr<Resource> octBuf, seedBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      FAF_GPU_TRY(UploadVec(ex, seeds, seedBuf));
      hk::FbmParams p{};
      p.w = static_cast<std::uint32_t>(s.w);
      p.octaves = static_cast<std::uint32_t>(octaves);
      p.kind = static_cast<std::uint32_t>(kind);
      p.basis = static_cast<std::uint32_t>(basis);
      p.fine = rotate ? 1u : 0u;
      p.norm = norm;
      Bindings b;
      b.Srv(1, *octBuf).Srv(2, *seedBuf);
      return RunGenerator(ex, "gen_fbm", s, static_cast<double>(octaves) * (basis == 1 ? 0.7 : 1.0), p, b, out);
    }

    std::expected<OpResult, std::string> OpPerlinGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& o
    )
    {
      return OpNoiseGpu(ex, a, 0, "perlin", o);
    }
    std::expected<OpResult, std::string> OpSimplexGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& o
    )
    {
      return OpNoiseGpu(ex, a, 0, "simplex", o);
    }
    std::expected<OpResult, std::string> OpRidgedGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& o
    )
    {
      return OpNoiseGpu(ex, a, 1, "perlin", o);
    }
    std::expected<OpResult, std::string> OpBillowGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& o
    )
    {
      return OpNoiseGpu(ex, a, 2, "perlin", o);
    }

    // ---- fractal
    // ------------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpFractalGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const auto read = fractal::Read(a, sh.cell);
      if (!read)
        return OpResult::Unsupported; // a bad option: the CPU op reports it
      const fractal::Setup& s = *read;
      constexpr int kRecords = 19;
      std::vector<float> tab(static_cast<std::size_t>(kRecords) * 16u, 0.0f);
      std::vector<std::uint32_t> seeds(16u + 12u, 0u);
      const double wox = static_cast<double>(sh.ox), woz = static_cast<double>(sh.oz),
                   cell = static_cast<double>(sh.cell);
      for (int o = 0; o < s.octaves; ++o) {
        double c = 1.0, sn = 0.0, fox = 0.0, foz = 0.0;
        if (s.rotate) {
          const field::OctaveFrame& fr = field::OctaveFrameOf(o);
          c = fr.c;
          sn = fr.s;
          fox = fr.ox;
          foz = fr.oz;
        }
        if (!PutOctaveMap(tab, o, wox, woz, cell, s.freq[o], c, sn, fox, foz))
          return OpResult::Unsupported;
        float* r = tab.data() + static_cast<std::size_t>(o) * 16u;
        r[8] = s.amps[o];
        r[9] = static_cast<float>(s.move[o]);
        r[10] = static_cast<float>(c);
        r[11] = static_cast<float>(sn);
        r[12] = static_cast<float>(s.freq[o] * s.scale);
        r[13] = s.fade[o];
        seeds[static_cast<std::size_t>(o)] = s.octSeed[o];
      }
      if (s.warp > 0.0) {
        double freq = 1.0 / s.warpScale;
        for (int o = 0; o < 3; ++o) {
          double c = 1.0, sn = 0.0, fox = 0.0, foz = 0.0;
          if (s.rotate) {
            const field::OctaveFrame& fr = field::OctaveFrameOf(o + 5);
            c = fr.c;
            sn = fr.s;
            fox = fr.ox;
            foz = fr.oz;
          }
          if (!PutOctaveMap(tab, 16 + o, wox, woz, cell, freq, c, sn, fox, foz))
            return OpResult::Unsupported;
          freq *= 2.0;
          for (std::uint32_t salt = 1; salt <= 4; ++salt) {
            seeds[16u + (salt - 1u) * 3u + static_cast<std::uint32_t>(o)] =
              Hash32(s.seed * 977U + salt * 31U + static_cast<std::uint32_t>(o) * 6151U + 5U);
          }
        }
      }
      std::unique_ptr<Resource> octBuf, seedBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      FAF_GPU_TRY(UploadVec(ex, seeds, seedBuf));
      hk::FractalParams p{};
      p.w = static_cast<std::uint32_t>(sh.w);
      p.octaves = static_cast<std::uint32_t>(s.octaves);
      p.kind = static_cast<std::uint32_t>(s.kind);
      p.style = static_cast<std::uint32_t>(s.style);
      p.warpLevels = static_cast<std::uint32_t>(s.warpLevels);
      p.warp = static_cast<float>(s.warp);
      p.slopeDetail = s.slopeDetail;
      p.erosion = s.erosion;
      p.sharp = s.sharp;
      p.norm = s.norm;
      p.fit = s.fit;
      p.invCell = static_cast<float>(1.0 / cell);
      Bindings b;
      b.Srv(1, *octBuf).Srv(2, *seedBuf);
      const double units = static_cast<double>(s.octaves) * (s.style == fractal::kErosive ? 1.2 : 1.0) +
        (s.warp > 0.0 ? 6.0 * s.warpLevels : 0.0);
      return RunGenerator(ex, "gen_fractal", sh, units, p, b, out);
    }

    // ---- musgrave, fbm_damped
    // ----------------------------------------------------------------------------------------------------------------------

    /** The octave table of a plain octave stack: octave o at frequency 1 / scale * lacunarity^o, in its own frame when
     * `rotate` (field 8 is left to the caller). false: Unsupported. */
    bool FillOctaves(
      std::vector<float>& tab,
      std::vector<std::uint32_t>& seeds,
      const int octaves,
      const std::uint32_t seed,
      const double scale,
      const double lacunarity,
      const bool rotate,
      const Shape& sh
    )
    {
      tab.assign(static_cast<std::size_t>(octaves) * 16u, 0.0f);
      seeds.assign(static_cast<std::size_t>(octaves), 0u);
      double freq = 1.0 / scale;
      for (int o = 0; o < octaves; ++o) {
        seeds[static_cast<std::size_t>(o)] = Hash32(seed * 131U + static_cast<std::uint32_t>(o) * 7919U + 17U);
        double c = 1.0, sn = 0.0, fox = 0.0, foz = 0.0;
        if (rotate) {
          const field::OctaveFrame& fr = field::OctaveFrameOf(o);
          c = fr.c;
          sn = fr.s;
          fox = fr.ox;
          foz = fr.oz;
        }
        if (!PutOctaveMap(
              tab,
              o,
              static_cast<double>(sh.ox),
              static_cast<double>(sh.oz),
              static_cast<double>(sh.cell),
              freq,
              c,
              sn,
              fox,
              foz
            ))
          return false;
        tab[static_cast<std::size_t>(o) * 16u + 10u] = static_cast<float>(c);
        tab[static_cast<std::size_t>(o) * 16u + 11u] = static_cast<float>(sn);
        freq *= lacunarity;
      }
      return true;
    }

    std::expected<OpResult, std::string> OpMusgraveGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const std::uint32_t seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const double scale = std::max(1e-3, a.p.N("scale", 100.0));
      const int octaves = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 6))));
      const float lac = std::max(1.1f, static_cast<float>(a.p.N("lacunarity", 2.0)));
      const float hExp = static_cast<float>(a.p.N("h", 1.0));
      const float offset = static_cast<float>(a.p.N("offset", 1.0));
      const float gain = static_cast<float>(a.p.N("gain", 2.0));
      const bool rotate = a.p.N("rotate", 0.0) >= 0.5;
      const std::string mode = a.p.S("mode", "ridged");
      if (mode != "ridged" && mode != "hybrid" && mode != "hetero")
        return OpResult::Unsupported;
      const int kind = mode == "ridged" ? 0 : (mode == "hybrid" ? 1 : 2);
      std::vector<float> tab;
      std::vector<std::uint32_t> seeds;
      if (!FillOctaves(tab, seeds, octaves, seed, scale, static_cast<double>(lac), rotate, sh))
        return OpResult::Unsupported;
      float ampSum = 0.0f;
      for (int o = 0; o < octaves; ++o) {
        const float amp = std::pow(lac, -hExp * static_cast<float>(o));
        tab[static_cast<std::size_t>(o) * 16u + 8u] = amp;
        ampSum += amp;
      }
      std::unique_ptr<Resource> octBuf, seedBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      FAF_GPU_TRY(UploadVec(ex, seeds, seedBuf));
      hk::MusgraveParams p{};
      p.w = static_cast<std::uint32_t>(sh.w);
      p.octaves = static_cast<std::uint32_t>(octaves);
      p.kind = static_cast<std::uint32_t>(kind);
      p.fine = rotate ? 1u : 0u;
      p.offset = offset;
      p.gain = gain;
      p.divisor = kind == 0 ? ampSum * std::max(1e-3f, offset * offset) : ampSum * std::max(1e-3f, offset + 1.0f);
      Bindings b;
      b.Srv(1, *octBuf).Srv(2, *seedBuf);
      return RunGenerator(ex, "gen_musgrave", sh, static_cast<double>(octaves), p, b, out);
    }

    std::expected<OpResult, std::string> OpFbmDampedGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const std::uint32_t seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const double scale = std::max(1e-3, a.p.N("scale", 150.0));
      const int octaves = std::max(1, std::min(16, static_cast<int>(a.p.N("octaves", 8))));
      const float pers = static_cast<float>(a.p.N("persistence", 0.5));
      const float lac = std::max(1.1f, static_cast<float>(a.p.N("lacunarity", 2.0)));
      const float damp = std::max(0.0f, static_cast<float>(a.p.N("damp", 1.0)));
      const bool rotate = a.p.N("rotate", 0.0) >= 0.5;
      std::vector<float> tab;
      std::vector<std::uint32_t> seeds;
      if (!FillOctaves(tab, seeds, octaves, seed, scale, static_cast<double>(lac), rotate, sh))
        return OpResult::Unsupported;
      std::unique_ptr<Resource> octBuf, seedBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      FAF_GPU_TRY(UploadVec(ex, seeds, seedBuf));
      hk::FbmdParams p{};
      p.w = static_cast<std::uint32_t>(sh.w);
      p.octaves = static_cast<std::uint32_t>(octaves);
      p.fine = rotate ? 1u : 0u;
      p.persistence = pers;
      p.damp = damp;
      Bindings b;
      b.Srv(1, *octBuf).Srv(2, *seedBuf);
      return RunGenerator(ex, "gen_fbmd", sh, static_cast<double>(octaves) * 1.1, p, b, out);
    }

    // ---- voronoi, cells, cracks
    // -------------------------------------------------------------------------------------------------------------------

    /** Record `rec` of the table: the map of a lattice at `scale` world units per cell, shifted by (sx, sz) world
     * units; field 8 = scale. */
    bool PutCellMap(
      std::vector<float>& tab,
      const int rec,
      const Shape& sh,
      const double scale,
      const double sx,
      const double sz
    )
    {
      const double inv = 1.0 / scale;
      const double a = static_cast<double>(sh.cell) * inv;
      if (!PutMap(
            tab, rec, (static_cast<double>(sh.ox) + sx) * inv, (static_cast<double>(sh.oz) + sz) * inv, a, 0.0, 0.0, a
          ))
        return false;
      tab[static_cast<std::size_t>(rec) * 16u + 8u] = static_cast<float>(scale);
      return true;
    }

    /** The two warp noises of cells / cracks: records 3 and 4 (maps of Fbm01's octave 0 at `size` world units, the
     * second shifted by (sx, sz)). */
    bool PutCellWarp(
      std::vector<float>& tab,
      const Shape& sh,
      const double size,
      const double sx,
      const double sz
    )
    {
      return PutCellMap(tab, 3, sh, size, 0.0, 0.0) && PutCellMap(tab, 4, sh, size, sx, sz);
    }

    std::expected<OpResult, std::string> RunCells(
      Executor& ex,
      const Shape& sh,
      hk::CellsParams p,
      const std::vector<float>& tab,
      const double units,
      Grid& out
    )
    {
      std::unique_ptr<Resource> octBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      p.w = static_cast<std::uint32_t>(sh.w);
      Bindings b;
      b.Srv(1, *octBuf);
      return RunGenerator(ex, "gen_cells", sh, units, p, b, out);
    }

    std::expected<OpResult, std::string> OpVoronoiGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const double scale = std::max(1e-3, a.p.N("scale", 100.0));
      const float jitter = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("jitter", 1.0))));
      const std::string mode = a.p.S("mode", "f1");
      std::vector<float> tab(5u * 16u, 0.0f);
      if (!PutCellMap(tab, 0, sh, scale, 0.0, 0.0))
        return OpResult::Unsupported;
      hk::CellsParams p{};
      p.op = 0;
      p.mode = mode == "f2" ? 1u : (mode == "edge" ? 2u : (mode == "id" ? 3u : (mode == "crack" ? 4u : 0u)));
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.jitter = jitter;
      p.width = std::max(1e-4f, static_cast<float>(a.p.N("thickness", 0.1)));
      return RunCells(ex, sh, p, tab, 9.0, out);
    }

    std::expected<OpResult, std::string> OpCellsGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      hk::CellsParams p{};
      p.op = 1;
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.jitter = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("jitter", 1.0))));
      const std::string metric = a.p.S("metric", "euclid");
      std::uint32_t m = 0;
      if (metric == "euclid")
        m = 0;
      else if (metric == "manhattan")
        m = 1;
      else if (metric == "chebyshev")
        m = 2;
      else if (metric == "minkowski")
        m = 3;
      else
        return OpResult::Unsupported;
      p.pexp = std::max(0.2f, static_cast<float>(a.p.N("p", 3.0)));
      p.ksoft = std::max(0.5f, static_cast<float>(a.p.N("smooth", 8.0)));
      const std::string mode = a.p.S("mode", "f1");
      static const char* const modes[] = {
        "f1", "f2", "f3", "edge", "crack", "id", "smooth", "border", "plate", "facet"
      };
      int mi = -1;
      for (int i = 0; i < 10; ++i) {
        if (mode == modes[i])
          mi = i;
      }
      if (mi < 0)
        return OpResult::Unsupported;
      if (mi == 7 || mi == 8)
        m = 0;
      p.metric = m;
      p.mode = static_cast<std::uint32_t>(mi);
      p.range = (mi == 2 || mi == 6 || m == 1 || m == 3) ? 2u : 1u;
      const double scale = std::max(1e-3, a.p.N("scale", 80.0));
      p.width = std::max(1e-4f, static_cast<float>(a.p.N("thickness", 0.12)));
      p.bevel = std::max(1e-4f, static_cast<float>(a.p.N("bevel", 0.1)));
      p.drop = static_cast<float>(a.p.N("drop", 0.5));
      const double warp = a.p.N("warp", 0.0);
      const double warpScale = std::max(1.0, a.p.N("warp_scale", scale * 2.0));
      std::vector<float> tab(5u * 16u, 0.0f);
      if (!PutCellMap(tab, 0, sh, scale, 0.0, 0.0))
        return OpResult::Unsupported;
      if (warp != 0.0) {
        if (!PutCellWarp(tab, sh, warpScale, 123.4, -77.7))
          return OpResult::Unsupported;
        p.warpOn = 1;
        p.warp = static_cast<float>(warp);
        p.seedA = p.seed + 7001U;
        p.seedB = p.seed + 7002U;
        p.warpOct = 3;
      }
      const double cellsPerSample = (p.range == 2 ? 25.0 : 9.0) * (mi == 7 || mi == 8 ? 3.0 : 1.0) / 3.0;
      return RunCells(ex, sh, p, tab, cellsPerSample + (warp != 0.0 ? 6.0 : 0.0), out);
    }

    std::expected<OpResult, std::string> OpCracksGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      hk::CellsParams p{};
      p.op = 2;
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.jitter = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("jitter", 0.9))));
      p.range = 1;
      const double scale = std::max(2.0, a.p.N("scale", 80.0));
      double width = std::max(0.05, a.p.N("crack_width", 3.0));
      const int levels = std::max(1, std::min(3, static_cast<int>(a.p.N("levels", 2))));
      const double warp = a.p.N("warp", 12.0);
      const std::string profile = a.p.S("profile", "v");
      p.profile = profile == "u" ? 1u : (profile == "flat" ? 2u : 0u);
      p.levels = static_cast<std::uint32_t>(levels);
      std::vector<float> tab(5u * 16u, 0.0f);
      double sc = scale;
      float weight = 1.0f;
      for (int lv = 0; lv < levels; ++lv) {
        if (!PutCellMap(tab, lv, sh, sc, 0.0, 0.0))
          return OpResult::Unsupported;
        tab[static_cast<std::size_t>(lv) * 16u + 9u] = static_cast<float>(width);
        tab[static_cast<std::size_t>(lv) * 16u + 10u] = weight;
        sc *= 0.45;
        width *= 0.6;
        weight *= 0.65f;
      }
      if (warp != 0.0) {
        if (!PutCellWarp(tab, sh, scale * 1.5, 55.5, 91.1))
          return OpResult::Unsupported;
        p.warpOn = 1;
        p.warp = static_cast<float>(warp);
        p.seedA = p.seed + 5101U;
        p.seedB = p.seed + 5102U;
        p.warpOct = 3;
      }
      return RunCells(ex, sh, p, tab, 4.0 * levels + (warp != 0.0 ? 6.0 : 0.0), out);
    }

    // ---- craters, dunes, island
    // --------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpCratersGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const double scale = std::max(1.0, a.p.N("scale", 120.0));
      hk::CratersParams p{};
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.density = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("density", 0.6))));
      p.rmax = std::max(0.02f, std::min(0.5f, static_cast<float>(a.p.N("rmax", 0.45))));
      p.rmin = std::max(0.01f, std::min(p.rmax, static_cast<float>(a.p.N("rmin", 0.15))));
      p.depth = static_cast<float>(a.p.N("depth", 0.4));
      p.rim = static_cast<float>(a.p.N("rim", 0.25));
      p.shape = std::max(0.5f, static_cast<float>(a.p.N("shape", 1.5)));
      p.base = static_cast<float>(a.p.N("base", 0.5));
      std::vector<float> tab(16u, 0.0f);
      if (!PutCellMap(tab, 0, sh, scale, 0.0, 0.0))
        return OpResult::Unsupported;
      std::unique_ptr<Resource> octBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      p.w = static_cast<std::uint32_t>(sh.w);
      Bindings b;
      b.Srv(1, *octBuf);
      return RunGenerator(ex, "gen_craters", sh, 4.0, p, b, out);
    }

    std::expected<OpResult, std::string> OpDunesGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const std::uint32_t seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const double wl = std::max(1.0, a.p.N("wavelength", 60.0));
      const double ang = a.p.N("angle", 0.0) * 3.14159265358979323846 / 180.0;
      const double ux = std::cos(ang), uz = std::sin(ang);
      const double warp = a.p.N("warp", 25.0);
      const double warpSize = std::max(2.0, a.p.N("warp_size", 120.0));
      hk::DunesParams p{};
      p.seed = seed;
      p.asym = static_cast<float>(a.p.N("asym", 0.9));
      p.variation = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("variation", 0.4))));
      p.ripples = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("ripples", 0.12))));
      const double cell = static_cast<double>(sh.cell);
      const double s0 = (static_cast<double>(sh.ox) * ux + static_cast<double>(sh.oz) * uz) / wl;
      const double wlr = wl * 0.12;
      const double sr0 = (static_cast<double>(sh.ox) * ux + static_cast<double>(sh.oz) * uz) / wlr;
      p.fu0 = static_cast<float>(s0 - std::floor(s0));
      p.pa = static_cast<float>(cell * ux / wl);
      p.pb = static_cast<float>(cell * uz / wl);
      p.fur0 = static_cast<float>(sr0 - std::floor(sr0));
      p.pra = static_cast<float>(cell * ux / wlr);
      p.prb = static_cast<float>(cell * uz / wlr);
      p.meanderK = static_cast<float>(warp * 2.0 / wl);
      p.meanderKr = static_cast<float>(warp * 1.5 / wlr);
      std::vector<float> tab(32u, 0.0f);
      if (!PutCellMap(tab, 0, sh, warpSize, 0.0, 0.0) || !PutCellMap(tab, 1, sh, warpSize * 1.7, 0.0, 0.0))
        return OpResult::Unsupported;
      std::unique_ptr<Resource> octBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      p.w = static_cast<std::uint32_t>(sh.w);
      Bindings b;
      b.Srv(1, *octBuf);
      return RunGenerator(ex, "gen_dunes", sh, 5.0, p, b, out);
    }

    std::expected<OpResult, std::string> OpIslandGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Shape sh;
      if (!ShapeOf(a, sh) || !Fits(ex, sh.Count(), 1))
        return OpResult::Unsupported;
      const std::string output = a.p.S("output", "height");
      if (output != "height" && output != "mask" && output != "distance")
        return OpResult::Unsupported;
      const double cell = static_cast<double>(sh.cell), wox = static_cast<double>(sh.ox),
                   woz = static_cast<double>(sh.oz);
      const double cxw = a.p.Has("cx") ? a.p.N("cx", 0) : wox + 0.5 * (sh.w - 1) * cell;
      const double czw = a.p.Has("cz") ? a.p.N("cz", 0) : woz + 0.5 * (sh.h - 1) * cell;
      const double radius = std::max(
        1e-3,
        a.p.Has("radius") && a.p.N("radius", 0) > 0.0 ? a.p.N("radius", 1) : 0.5 * std::min(sh.w - 1, sh.h - 1) * cell
      );
      const double aspect = std::max(0.2, a.p.N("aspect", 1.0));
      const double ang = a.p.N("angle", 0.0) * 3.14159265358979323846 / 180.0;
      const double ca = std::cos(ang), sa = std::sin(ang);
      const double nscale = std::max(2.0, a.p.N("noise_scale", radius * 0.5));
      hk::IslandParams p{};
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.outKind = output == "height" ? 0u : (output == "mask" ? 1u : 2u);
      const double ex0 = wox - cxw, ez0 = woz - czw;
      p.u0 = static_cast<float>((ex0 * ca + ez0 * sa) / aspect);
      p.ua = static_cast<float>(cell * ca / aspect);
      p.ub = static_cast<float>(cell * sa / aspect);
      p.v0 = static_cast<float>(-ex0 * sa + ez0 * ca);
      p.va = static_cast<float>(-cell * sa);
      p.vb = static_cast<float>(cell * ca);
      p.radius = static_cast<float>(radius);
      p.rough = static_cast<float>(a.p.N("roughness", 0.35));
      p.edge = std::max(0.005f, static_cast<float>(a.p.N("edge", 0.08)));
      p.power = std::max(0.2f, static_cast<float>(a.p.N("power", 1.4)));
      std::vector<float> tab(16u, 0.0f);
      if (!PutCellMap(tab, 0, sh, nscale, 0.0, 0.0))
        return OpResult::Unsupported;
      std::unique_ptr<Resource> octBuf;
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      p.w = static_cast<std::uint32_t>(sh.w);
      Bindings b;
      b.Srv(1, *octBuf);
      return RunGenerator(ex, "gen_island", sh, 5.0, p, b, out);
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("perlin", &OpPerlinGpu);
        RegisterGpuOp("simplex", &OpSimplexGpu);
        RegisterGpuOp("ridged", &OpRidgedGpu);
        RegisterGpuOp("billow", &OpBillowGpu);
        RegisterGpuOp("fractal", &OpFractalGpu);
        RegisterGpuOp("musgrave", &OpMusgraveGpu);
        RegisterGpuOp("fbm_damped", &OpFbmDampedGpu);
        RegisterGpuOp("voronoi", &OpVoronoiGpu);
        RegisterGpuOp("cells", &OpCellsGpu);
        RegisterGpuOp("cracks", &OpCracksGpu);
        RegisterGpuOp("craters", &OpCratersGpu);
        RegisterGpuOp("dunes", &OpDunesGpu);
        RegisterGpuOp("island", &OpIslandGpu);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
