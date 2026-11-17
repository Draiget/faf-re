// EDITOR GPU compute: GPU versions of heavy filter ops (occlusion, bilateral, diffuse, blur_dir, dwarp and the slope /
// curvature / aspect / normal_map / hillshade family). Each op reads its options exactly like the CPU op
// (EdFieldFilt.cpp, EdFieldCore.cpp, EdFieldGen.cpp) and answers Unsupported for what it does not handle, so the CPU op
// keeps working. A filter transfers its input and its result over the bus: ops whose arithmetic is a few operations per
// sample (the slope family) only go to the GPU on big fields (kMinCheap samples). docs/projects/editor/GPU_COMPUTE.md,
// "Generator and filter kernels".
#pragma fp_contract(off)

#include "editor/terrain/gpu/EdGpuGen.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/filt_bilateral_params.hlsli"
#include "editor/terrain/gpu/filt_blurdir_params.hlsli"
#include "editor/terrain/gpu/filt_diffuse_params.hlsli"
#include "editor/terrain/gpu/filt_dwarp_params.hlsli"
#include "editor/terrain/gpu/filt_normal_params.hlsli"
#include "editor/terrain/gpu/filt_occlusion_params.hlsli"
#include "editor/terrain/gpu/filt_terrain_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using namespace gen;

  namespace
  {
    constexpr float kPi = 3.14159265358979f;

    /** Uploads the source `a`, makes the result field. The output grid takes its metadata from the op's shape (`like`,
     * else `a`). */
    struct Job
    {
      const Grid* src = nullptr;
      Shape shape;
      Field in;
      Field res;
    };

    /** Reads `a` and the output shape; false = Unsupported (the CPU op reports bad input itself). */
    bool Begin(
      Executor& ex,
      const OpArgs& a,
      const int fields,
      Job& j
    )
    {
      j.src = In(a, "a");
      if (j.src == nullptr || j.src->w < 1 || j.src->h < 1 || !ShapeOf(a, j.shape))
        return false;
      return Fits(ex, j.shape.Count(), fields);
    }

    /** `mask` must be absent or of the source's shape (else the CPU op reports it). */
    bool MaskOk(
      const OpArgs& a,
      const Job& j
    )
    {
      const Grid* m = In(a, "mask");
      return m == nullptr || m->SameShape(*j.src);
    }

    std::expected<void, std::string> Upload(
      Executor& ex,
      Job& j
    )
    {
      FAF_GPU_TRY(UploadGrid(ex, *j.src, j.in));
      return MakeField(ex, j.shape.w, j.shape.h, j.res);
    }

    std::expected<OpResult, std::string> Finish(
      Executor& ex,
      Job& j,
      Grid& out
    )
    {
      Grid result = NewGrid(j.shape);
      FAF_GPU_TRY(DownloadGrid(ex, j.res, result));
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- occlusion
    // --------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpOcclusionGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!Begin(ex, a, 2, j))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "cavity");
      if (mode != "cavity" && mode != "convex" && mode != "both")
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const int m = mode == "cavity" ? 0 : (mode == "convex" ? 1 : 2);
      const int dirs = std::max(4, std::min(32, static_cast<int>(a.p.N("directions", 12))));
      const float radius = std::max(static_cast<float>(src.cell), static_cast<float>(a.p.N("radius", 30.0)));
      const float gain = static_cast<float>(a.p.N("gain", 1.0));
      const int steps = std::max(2, std::min(32, static_cast<int>(std::lround(radius / src.cell))));
      std::vector<float> ray(static_cast<std::size_t>(steps + 2 * dirs));
      for (int s = 0; s < steps; ++s) {
        const float t = static_cast<float>(s + 1) / static_cast<float>(steps);
        ray[static_cast<std::size_t>(s)] = std::max(1.0f, (radius / src.cell) * t * t);
      }
      for (int d = 0; d < dirs; ++d) {
        const float th = 2.0f * kPi * static_cast<float>(d) / static_cast<float>(dirs);
        ray[static_cast<std::size_t>(steps + d)] = std::cos(th);
        ray[static_cast<std::size_t>(steps + dirs + d)] = std::sin(th);
      }
      const KernelInfo* k = FindKernel("filt_occlusion");
      if (k == nullptr) {
        return std::unexpected("kernel filt_occlusion is missing");
      }
      std::unique_ptr<Resource> rayBuf;
      FAF_GPU_TRY(Upload(ex, j));
      FAF_GPU_TRY(UploadVec(ex, ray, rayBuf));
      hk::OcclusionParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.dirs = static_cast<std::uint32_t>(dirs);
      p.steps = static_cast<std::uint32_t>(steps);
      p.mode = static_cast<std::uint32_t>(m);
      p.cell = src.cell;
      p.gain = gain;
      Bindings b;
      b.Srv(1, *rayBuf).Srv(2, j.in.R()).Uav(0, j.res.R());
      FAF_GPU_TRY(DispatchBands(ex, *k, p.w, p.h, static_cast<double>(dirs) * static_cast<double>(steps) * 0.12, p, b));
      return Finish(ex, j, out);
    }

    // ---- bilateral
    // ----------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpBilateralGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!Begin(ex, a, 3, j) || !MaskOk(a, j))
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const int r =
        std::max(1, std::min(12, static_cast<int>(std::lround(a.p.N("radius", 6.0) / static_cast<double>(src.cell)))));
      const float sr = std::max(1e-4f, static_cast<float>(a.p.N("sigma_r", 2.0)));
      const float sigS = std::max(0.3f, static_cast<float>(r) * 0.5f);
      std::vector<float> ws(static_cast<std::size_t>((2 * r + 1) * (2 * r + 1)));
      for (int dz = -r; dz <= r; ++dz) {
        for (int dx = -r; dx <= r; ++dx)
          ws[static_cast<std::size_t>((dz + r) * (2 * r + 1) + dx + r)] =
            std::exp(-0.5f * static_cast<float>(dx * dx + dz * dz) / (sigS * sigS));
      }
      const KernelInfo* k = FindKernel("filt_bilateral");
      if (k == nullptr) {
        return std::unexpected("kernel filt_bilateral is missing");
      }
      std::unique_ptr<Resource> wsBuf;
      MaskBind mask;
      FAF_GPU_TRY(Upload(ex, j));
      FAF_GPU_TRY(UploadVec(ex, ws, wsBuf));
      FAF_GPU_TRY(BindMask(ex, a, mask));
      hk::BilateralParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.rad = static_cast<std::uint32_t>(r);
      p.hasMask = mask.has ? 1u : 0u;
      p.inv = 1.0f / (sr * sr);
      Bindings b;
      b.Srv(1, *wsBuf).Srv(2, j.in.R()).Srv(3, mask.R()).Uav(0, j.res.R());
      FAF_GPU_TRY(DispatchBands(ex, *k, p.w, p.h, static_cast<double>((2 * r + 1) * (2 * r + 1)) * 0.1, p, b));
      return Finish(ex, j, out);
    }

    // ---- diffuse (iterated)
    // -------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpDiffuseGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!Begin(ex, a, 4, j) || !MaskOk(a, j))
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const int iterations = std::max(0, std::min(5000, static_cast<int>(a.p.N("iterations", 20))));
      if (iterations == 0)
        return OpResult::Unsupported;
      const float kappa = std::max(1e-4f, static_cast<float>(a.p.N("kappa", 0.4)));
      const float rate = std::max(0.0f, std::min(0.25f, static_cast<float>(a.p.N("rate", 0.2))));
      const KernelInfo* k = FindKernel("filt_diffuse");
      if (k == nullptr) {
        return std::unexpected("kernel filt_diffuse is missing");
      }
      PingPong pp;
      MaskBind mask;
      FAF_GPU_TRY(UploadGrid(ex, src, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, src.w, src.h, pp.f[1]));
      FAF_GPU_TRY(BindMask(ex, a, mask));
      hk::DiffuseParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.rows = p.h;
      p.expo = a.p.S("g", "lorentz") == "exp" ? 1u : 0u;
      p.hasMask = mask.has ? 1u : 0u;
      p.invK2 = 1.0f / (kappa * kappa);
      p.invCell = 1.0f / src.cell;
      p.rate = rate;
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        Bindings b;
        b.Srv(1, pp.Src().R()).Srv(2, mask.R()).Uav(0, pp.Dst().R());
        FAF_GPU_TRY(DispatchGrid(ex, *k, p.w, p.h, p, b));
        pp.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid result = NewGrid(j.shape);
      FAF_GPU_TRY(DownloadGrid(ex, pp.Src(), result));
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- blur_dir
    // ---------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpBlurDirGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!Begin(ex, a, 3, j) || !MaskOk(a, j))
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const double ang = a.p.N("angle", 0.0) * 3.14159265358979323846 / 180.0;
      const float ux = static_cast<float>(std::cos(ang)), uz = static_cast<float>(std::sin(ang));
      const float len = std::max(0.0f, static_cast<float>(a.p.N("length", 20.0) / static_cast<double>(src.cell)));
      const std::string shape = a.p.S("shape", "box");
      const int half = std::max(0, std::min(256, static_cast<int>(std::ceil(len * 0.5f))));
      if (half == 0)
        return OpResult::Unsupported;
      std::vector<float> wt(static_cast<std::size_t>(2 * half + 1));
      float wsum = 0.0f;
      for (int i = -half; i <= half; ++i) {
        const float t = static_cast<float>(i) / static_cast<float>(half);
        float v = 1.0f;
        if (shape == "tri")
          v = 1.0f - std::fabs(t);
        else if (shape == "gauss")
          v = std::exp(-2.0f * t * t);
        wt[static_cast<std::size_t>(i + half)] = v;
        wsum += v;
      }
      const KernelInfo* k = FindKernel("filt_blurdir");
      if (k == nullptr) {
        return std::unexpected("kernel filt_blurdir is missing");
      }
      std::unique_ptr<Resource> wtBuf;
      MaskBind mask;
      FAF_GPU_TRY(Upload(ex, j));
      FAF_GPU_TRY(UploadVec(ex, wt, wtBuf));
      FAF_GPU_TRY(BindMask(ex, a, mask));
      hk::BlurDirParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.taps = static_cast<std::uint32_t>(half);
      p.hasMask = mask.has ? 1u : 0u;
      p.ux = ux;
      p.uz = uz;
      p.wsum = wsum;
      Bindings b;
      b.Srv(1, *wtBuf).Srv(2, j.in.R()).Srv(3, mask.R()).Uav(0, j.res.R());
      FAF_GPU_TRY(DispatchBands(ex, *k, p.w, p.h, static_cast<double>(2 * half + 1) * 0.08, p, b));
      return Finish(ex, j, out);
    }

    // ---- dwarp
    // --------------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpDWarpGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!Begin(ex, a, 3, j) || !MaskOk(a, j))
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const std::string kind = a.p.S("kind", "fbm");
      if (kind != "fbm" && kind != "curl" && kind != "swirl" && kind != "ripple" && kind != "pinch")
        return OpResult::Unsupported;
      const int k = kind == "fbm" ? 0 : (kind == "curl" ? 1 : (kind == "swirl" ? 2 : (kind == "ripple" ? 3 : 4)));
      const std::string edge = a.p.S("edge", "");
      hk::DWarpParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.kind = static_cast<std::uint32_t>(k);
      p.iters = static_cast<std::uint32_t>(std::max(1, std::min(3, static_cast<int>(a.p.N("iterations", 1)))));
      p.octaves = static_cast<std::uint32_t>(std::max(1, std::min(8, static_cast<int>(a.p.N("octaves", 3)))));
      p.edge = edge == "wrap" ? 1u : (edge == "mirror" ? 2u : 0u);
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const double strength = a.p.N("strength", 40.0);
      const double size = std::max(1.0, a.p.N("size", 100.0));
      const double cell = static_cast<double>(j.shape.cell), wox = static_cast<double>(j.shape.ox),
                   woz = static_cast<double>(j.shape.oz);
      const double cxw = a.p.Has("cx") ? a.p.N("cx", 0) : wox + 0.5 * (j.shape.w - 1) * cell;
      const double czw = a.p.Has("cz") ? a.p.N("cz", 0) : woz + 0.5 * (j.shape.h - 1) * cell;
      const double ang = a.p.N("angle", 0.0) * 3.14159265358979323846 / 180.0;
      const double rx = std::cos(ang), rz = std::sin(ang);
      const double wl = std::max(1.0, a.p.N("wavelength", 60.0));
      p.strength = static_cast<float>(strength);
      p.size = static_cast<float>(size);
      p.invSize = static_cast<float>(1.0 / size);
      p.cell = static_cast<float>(cell);
      p.invCell = static_cast<float>(1.0 / static_cast<double>(src.cell));
      p.e0x = static_cast<float>(wox - cxw);
      p.e0z = static_cast<float>(woz - czw);
      const double s0 = (-wox * rz + woz * rx) / wl;
      p.fu0 = static_cast<float>(s0 - std::floor(s0));
      p.pa = static_cast<float>(-cell * rz / wl);
      p.pb = static_cast<float>(cell * rx / wl);
      p.phase = static_cast<float>(a.p.N("phase", 0.0));
      p.rx = static_cast<float>(rx);
      p.rz = static_cast<float>(rz);
      p.rotK = static_cast<float>(strength * 3.14159265358979323846 / 180.0);
      std::vector<float> tab(32u, 0.0f);
      const auto putMap = [&](const int rec, const double sx, const double sz) {
        const double inv = 1.0 / size, aa = cell * inv;
        return PutMap(tab, rec, (wox + sx) * inv, (woz + sz) * inv, aa, 0.0, 0.0, aa);
      };
      if (!putMap(0, 0.0, 0.0) || !putMap(1, 17.3, -41.9))
        return OpResult::Unsupported;
      const KernelInfo* ki = FindKernel("filt_dwarp");
      if (ki == nullptr) {
        return std::unexpected("kernel filt_dwarp is missing");
      }
      std::unique_ptr<Resource> octBuf;
      MaskBind mask;
      FAF_GPU_TRY(Upload(ex, j));
      FAF_GPU_TRY(UploadVec(ex, tab, octBuf));
      FAF_GPU_TRY(BindMask(ex, a, mask));
      p.hasMask = mask.has ? 1u : 0u;
      Bindings b;
      b.Srv(1, *octBuf).Srv(2, j.in.R()).Srv(3, mask.R()).Uav(0, j.res.R());
      const double units = k == 0 ? 2.0 * p.iters * p.octaves : (k == 1 ? static_cast<double>(p.octaves) : 1.0);
      FAF_GPU_TRY(DispatchBands(ex, *ki, p.w, p.h, units, p, b));
      return Finish(ex, j, out);
    }

    // ---- slope, curvature, aspect, hillshade, normal_map (cheap stencils)
    // -----------------------------------------------------------------------------

    /** Ops of a few operations per sample: the transfer of input and result costs more than the maths on a small field.
     * Fields below 16 x ed_gpu_min_cells (default 1048576, 1024 x 1024) stay on the CPU. */
    bool BigEnough(
      const OpArgs& a
    )
    {
      return CellsOf(a) >= static_cast<double>(GetPolicy().minCells) * 16.0;
    }

    std::expected<OpResult, std::string> RunTerrain(
      Executor& ex,
      Job& j,
      hk::TerrainParams p,
      const double units,
      Grid& out
    )
    {
      const KernelInfo* k = FindKernel("filt_terrain");
      if (k == nullptr) {
        return std::unexpected("kernel filt_terrain is missing");
      }
      FAF_GPU_TRY(Upload(ex, j));
      p.w = static_cast<std::uint32_t>(j.src->w);
      p.h = static_cast<std::uint32_t>(j.src->h);
      p.cell = j.src->cell;
      Bindings b;
      b.Srv(1, j.in.R()).Uav(0, j.res.R());
      FAF_GPU_TRY(DispatchBands(ex, *k, p.w, p.h, units, p, b));
      return Finish(ex, j, out);
    }

    std::expected<OpResult, std::string> OpSlopeGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!BigEnough(a) || !Begin(ex, a, 2, j))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "degrees");
      if (mode != "degrees" && mode != "gradient")
        return OpResult::Unsupported; // rating / variation (window maximum) stay on the CPU
      hk::TerrainParams p{};
      p.op = 0;
      p.n = static_cast<std::uint32_t>(std::max(1, std::min(16, static_cast<int>(a.p.N("radius", 1)))));
      p.mode = mode == "degrees" ? 0u : 1u;
      p.degK = 180.0f / kPi;
      return RunTerrain(ex, j, p, 0.05, out);
    }

    std::expected<OpResult, std::string> OpCurvatureGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!BigEnough(a) || !Begin(ex, a, 2, j))
        return OpResult::Unsupported;
      const int n = std::max(1, std::min(32, static_cast<int>(a.p.N("radius", 1))));
      hk::TerrainParams p{};
      p.op = 1;
      p.n = static_cast<std::uint32_t>(n);
      p.gain = static_cast<float>(a.p.N("gain", 10.0));
      p.mode = a.p.N("raw", 0) != 0 ? 1u : 0u;
      p.d2 = static_cast<float>(n) * static_cast<float>(n) * j.src->cell * j.src->cell;
      return RunTerrain(ex, j, p, 0.05, out);
    }

    std::expected<OpResult, std::string> OpAspectGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!BigEnough(a) || !Begin(ex, a, 2, j))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "facing");
      if (mode != "facing" && mode != "degrees")
        return OpResult::Unsupported;
      const double ang = a.p.N("azimuth", 0.0) * 3.14159265358979 / 180.0;
      hk::TerrainParams p{};
      p.op = 2;
      p.n = static_cast<std::uint32_t>(std::max(1, std::min(16, static_cast<int>(a.p.N("radius", 1)))));
      p.mode = mode == "degrees" ? 1u : 0u;
      p.dirx = static_cast<float>(std::cos(ang));
      p.dirz = static_cast<float>(std::sin(ang));
      p.flatK = std::max(1e-6f, static_cast<float>(a.p.N("flat", 0.05)));
      p.degK = 180.0f / kPi;
      return RunTerrain(ex, j, p, 0.06, out);
    }

    std::expected<OpResult, std::string> OpHillshadeGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!BigEnough(a) || !Begin(ex, a, 2, j))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "shade");
      if (mode != "shade" && mode != "lit" && mode != "shadow")
        return OpResult::Unsupported;
      const int m = mode == "shade" ? 0 : (mode == "lit" ? 1 : 2);
      const double kPiD = 3.14159265358979323846;
      const double az = a.p.N("azimuth", 315.0) * kPiD / 180.0;
      const double alt = std::max(1.0, std::min(89.0, a.p.N("altitude", 40.0))) * kPiD / 180.0;
      hk::TerrainParams p{};
      p.op = 3;
      p.mode = static_cast<std::uint32_t>(m);
      p.zf = static_cast<float>(a.p.N("z", 1.0));
      p.ambient = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("ambient", 0.15))));
      p.shadows = (m != 0 || a.p.N("shadows", 0) != 0) ? 1u : 0u;
      const float cell = j.src->cell;
      p.len = std::max(cell, static_cast<float>(a.p.N("shadow_len", 150.0))) / cell;
      p.lx = static_cast<float>(std::cos(alt) * std::cos(az));
      p.ly = static_cast<float>(std::sin(alt));
      p.lz = static_cast<float>(std::cos(alt) * std::sin(az));
      p.dirx = static_cast<float>(std::cos(az));
      p.dirz = static_cast<float>(std::sin(az));
      p.tanAlt = static_cast<float>(std::tan(alt));
      return RunTerrain(ex, j, p, p.shadows != 0 ? 0.6 : 0.08, out);
    }

    std::expected<OpResult, std::string> OpNormalMapGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      Job j;
      if (!BigEnough(a) || !Begin(ex, a, 4, j))
        return OpResult::Unsupported;
      const Grid& src = *j.src;
      const float span = std::max(0.05f, static_cast<float>(a.p.N("span", 1.0)));
      const float strength = static_cast<float>(a.p.N("strength", 1.0));
      const float shiftUnits = static_cast<float>(a.p.N("shift", 0.0));
      hk::NormalParams p{};
      p.w = static_cast<std::uint32_t>(src.w);
      p.h = static_cast<std::uint32_t>(src.h);
      p.raw = a.p.N("signed", 0.0) != 0.0 ? 1u : 0u;
      p.shift = shiftUnits / src.cell;
      p.taps = 0.5f * span / src.cell;
      p.scale = strength / span;
      p.cell = src.cell;
      const KernelInfo* k = FindKernel("filt_normal");
      if (k == nullptr) {
        return std::unexpected("kernel filt_normal is missing");
      }
      Field fy, fz;
      FAF_GPU_TRY(Upload(ex, j));
      FAF_GPU_TRY(MakeField(ex, src.w, src.h, fy));
      FAF_GPU_TRY(MakeField(ex, src.w, src.h, fz));
      Bindings b;
      b.Srv(1, j.in.R()).Uav(0, j.res.R()).Uav(1, fy.R()).Uav(2, fz.R());
      FAF_GPU_TRY(DispatchBands(ex, *k, p.w, p.h, 0.25, p, b));
      Grid gx = NewGrid(j.shape);
      gx.ox = src.ox + shiftUnits; // the result lies where it was computed (as on the CPU)
      gx.oz = src.oz + shiftUnits;
      Grid gy(gx.w, gx.h, gx.cell, gx.ox, gx.oz), gz = gy;
      FAF_GPU_TRY(DownloadGrid(ex, j.res, gx));
      if (a.extra != nullptr) {
        FAF_GPU_TRY(DownloadGrid(ex, fy, gy));
        FAF_GPU_TRY(DownloadGrid(ex, fz, gz));
        (*a.extra)["y"] = std::move(gy);
        (*a.extra)["z"] = std::move(gz);
      }
      out = std::move(gx);
      return OpResult::Done;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("occlusion", &OpOcclusionGpu);
        RegisterGpuOp("bilateral", &OpBilateralGpu);
        RegisterGpuOp("diffuse", &OpDiffuseGpu);
        RegisterGpuOp("blur_dir", &OpBlurDirGpu);
        RegisterGpuOp("dwarp", &OpDWarpGpu);
        RegisterGpuOp("slope", &OpSlopeGpu);
        RegisterGpuOp("curvature", &OpCurvatureGpu);
        RegisterGpuOp("aspect", &OpAspectGpu);
        RegisterGpuOp("hillshade", &OpHillshadeGpu);
        RegisterGpuOp("normal_map", &OpNormalMapGpu);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
