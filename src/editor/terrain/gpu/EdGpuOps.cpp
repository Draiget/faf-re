// EDITOR GPU compute: GPU implementations of field ops, the policy and the self test. See EdGpuOps.h and
// docs/projects/editor/GPU_COMPUTE.md.
//
// THE TEMPLATE FOR A NEW GPU OP is OpBlurGpu below (and gpu/blur_pass.hlsl, gpu/blur_params.hlsli): read the inputs,
// refuse what the GPU version does not handle with Unsupported, upload, dispatch kernels, download into a LOCAL grid,
// and only then move it into `out`.
#pragma fp_contract(off)

#include "editor/terrain/gpu/EdGpuOps.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <vector>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>

// constant buffer structs of the kernels: the very files the kernels include (so the layouts cannot differ); inside a
// namespace that has the HLSL scalar type names
namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/blur_params.hlsli"
#include "editor/terrain/gpu/field_params.hlsli"
#include "editor/terrain/gpu/filt_lerpmask_params.hlsli"
#include "editor/terrain/gpu/reduce_params.hlsli"
#include "editor/terrain/gpu/scale_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using field::Grid;
  using field::GridPtr;
  using field::OpArgs;

  // ---- registry, policy, statistics
  // ------------------------------------------------------------------------------------------------------------

  namespace
  {
    std::mutex gRegistryMutex;
    std::map<std::string, GpuOpFn>& Ops()
    {
      static std::map<std::string, GpuOpFn> ops;
      return ops;
    }
    std::map<std::string, float>& OpMinCells()
    {
      static std::map<std::string, float> cells;
      return cells;
    }
    std::atomic<bool> gSelfTestPassed{false};
    std::atomic<BeforeUseFn> gHook{nullptr};
    std::atomic<bool> gHookDone{false};
    std::mutex gErrorMutex;
    std::string gLastError;

    double MsSince(
      const std::chrono::steady_clock::time_point t0
    )
    {
      return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    }
  } // namespace

  Policy& GetPolicy()
  {
    static Policy policy;
    return policy;
  }

  void RegisterGpuOp(
    const char* const name,
    const GpuOpFn fn,
    const float minCells
  )
  {
    const std::lock_guard<std::mutex> lock(gRegistryMutex);
    Ops()[name] = fn;
    OpMinCells()[name] = minCells;
  }

  float GpuOpMinCells(
    const std::string& name
  )
  {
    const std::lock_guard<std::mutex> lock(gRegistryMutex);
    const auto it = OpMinCells().find(name);
    return it != OpMinCells().end() ? it->second : -1.0f;
  }

  std::vector<std::string> GpuOpNames()
  {
    const std::lock_guard<std::mutex> lock(gRegistryMutex);
    std::vector<std::string> names;
    for (const auto& kv : Ops()) {
      names.push_back(kv.first);
    }
    return names;
  }

  bool SelfTestPassed()
  {
    return gSelfTestPassed.load();
  }
  void ResetSelfTestState()
  {
    gSelfTestPassed.store(false);
  }

  void SetBeforeUseHook(
    const BeforeUseFn fn
  )
  {
    gHook.store(fn);
    gHookDone.store(false);
  }

  std::string LastOpError()
  {
    const std::lock_guard<std::mutex> lock(gErrorMutex);
    return gLastError;
  }

  void SetLastOpError(
    const std::string& text
  )
  {
    const std::lock_guard<std::mutex> lock(gErrorMutex);
    gLastError = text;
  }

  double CellsOf(
    const OpArgs& args
  )
  {
    const auto pick = [&](const char* key) -> const Grid* {
      const auto it = args.in.find(key);
      return it != args.in.end() ? it->second.get() : nullptr;
    };
    if (const Grid* g = pick("a"); g != nullptr) {
      return static_cast<double>(g->w) * static_cast<double>(g->h);
    }
    if (const Grid* g = pick("like"); g != nullptr) {
      return static_cast<double>(g->w) * static_cast<double>(g->h);
    }
    return args.p.N("width", 0.0) * args.p.N("height", 0.0);
  }

  bool TryRun(
    const std::string& name,
    const OpArgs& args,
    Grid& out
  )
  {
    try {
      GpuOpFn fn = nullptr;
      float opMin = -1.0f;
      {
        const std::lock_guard<std::mutex> lock(gRegistryMutex);
        const auto it = Ops().find(name);
        if (it == Ops().end()) {
          return false;
        }
        fn = it->second;
        const auto m = OpMinCells().find(name);
        if (m != OpMinCells().end()) {
          opMin = m->second;
        }
      }
      const Policy& policy = GetPolicy();
      const float minCells = opMin >= 0.0f ? std::min(opMin, policy.minCells) : policy.minCells;
      if (!policy.enabled || CellsOf(args) < static_cast<double>(minCells)) {
        return false;
      }
      Backend& backend = CurrentBackend();
      if (!backend.MayWork()) {
        return false;
      }
      if (!gHookDone.load()) {
        const BeforeUseFn hook = gHook.load();
        if (hook == nullptr || hook()) {
          gHookDone.store(true);
        }
      }
      Lease lease(false);
      if (!lease) {
        if (!lease.Busy() && !lease.Error().empty()) {
          SetLastOpError(name + ": " + lease.Error());
        }
        return false;
      }
      if (policy.selfTestFirst && !gSelfTestPassed.load()) {
        // the first real use on this device: prove that the kernels compile and give the CPU's results; a device that
        // does not is switched off for the session
        const SelfTestReport rep = RunSelfTest(*lease);
        if (!rep.ok) {
          std::string why = "GPU self test failed: " +
            (rep.error.empty() ? std::string("a kernel gave different results than the CPU") : rep.error);
          for (const SelfTestPart& p : rep.parts) {
            if (!p.ok) {
              why += "; " + p.name + ": " + p.detail;
              break;
            }
          }
          SetLastOpError(name + ": " + why);
          lease.Fail(why);
          return false;
        }
        gSelfTestPassed.store(true);
      }
      const auto t0 = std::chrono::steady_clock::now();
      Grid result;
      std::expected<OpResult, std::string> r = std::unexpected(std::string());
      try {
        r = fn(*lease, args, result);
      } catch (const std::exception& e) {
        r = std::unexpected(std::string("exception: ") + e.what());
      } catch (...) {
        r = std::unexpected("exception");
      }
      if (r && *r == OpResult::Done) {
        out = std::move(result);
        field::NoteOpGpu(name, MsSince(t0));
        return true;
      }
      if (!r) {
        field::NoteOpFallback(name);
        SetLastOpError(name + ": " + r.error());
        if (lease->DeviceLost()) {
          lease.Fail(r.error());
        }
      }
      return false;
    } catch (...) {
      return false;
    }
  }

  void Install()
  {
    field::SetOpInterceptor(&TryRun);
  }

  // ---- the template op: blur / box
  // ---------------------------------------------------------------------------------------------------------------

  namespace
  {
    /** One-sided kernel k[0..r] of a symmetric normalised kernel: a private copy of MakeKernel in EdFieldCore.cpp (same
     * arithmetic, so the weights are the same bits). */
    std::vector<float> MakeKernel(
      const bool gauss,
      const double sigmaOrRadius,
      int& r
    )
    {
      std::vector<float> k;
      if (gauss) {
        r = std::max(1, static_cast<int>(std::ceil(3.0 * sigmaOrRadius)));
        std::vector<double> d(static_cast<std::size_t>(r) + 1);
        double sum = 0.0;
        for (int i = 0; i <= r; ++i) {
          d[static_cast<std::size_t>(i)] =
            std::exp(-0.5 * static_cast<double>(i) * static_cast<double>(i) / (sigmaOrRadius * sigmaOrRadius));
          sum += (i == 0 ? 1.0 : 2.0) * d[static_cast<std::size_t>(i)];
        }
        for (const double v : d) {
          k.push_back(static_cast<float>(v / sum));
        }
      } else {
        r = std::max(1, static_cast<int>(std::floor(sigmaOrRadius + 0.5)));
        k.assign(static_cast<std::size_t>(r) + 1, static_cast<float>(1.0 / (2.0 * r + 1.0)));
      }
      return k;
    }

  } // namespace

  bool BlurAffordable(
    const int w,
    const int h,
    const double sigma
  )
  {
    const int r = std::max(1, static_cast<int>(std::ceil(3.0 * sigma)));
    const double work = 2.0 * static_cast<double>(w) * static_cast<double>(h) * (2.0 * r + 1.0);
    return r <= 8192 && work <= 3.0e10; // one dispatch this long could hit the 2 second driver reset
  }

  std::expected<void, std::string> BlurDevice(
    Executor& ex,
    const Resource& src,
    Resource& tmp,
    Resource& dst,
    const int w,
    const int h,
    const double sigma
  )
  {
    const KernelInfo* kernel = FindKernel("blur_pass");
    if (kernel == nullptr) {
      return std::unexpected("kernel blur_pass is missing");
    }
    int r = 0;
    const std::vector<float> weights = MakeKernel(true, sigma, r);
    std::unique_ptr<Resource> kbuf;
    FAF_GPU_TRY(MakeBuffer(ex, static_cast<u32>(weights.size()), kbuf));
    FAF_GPU_TRY(UploadBuffer(ex, *kbuf, weights.data(), weights.size() * 4));
    hk::BlurParams params{};
    params.w = static_cast<std::uint32_t>(w);
    params.h = static_cast<std::uint32_t>(h);
    params.radius = static_cast<std::uint32_t>(r);
    params.vertical = 0;
    Bindings b0;
    b0.Srv(0, src).Srv(1, *kbuf).Uav(0, tmp);
    FAF_GPU_TRY(DispatchGrid(ex, *kernel, params.w, params.h, params, b0));
    params.vertical = 1;
    Bindings b1;
    b1.Srv(0, tmp).Srv(1, *kbuf).Uav(0, dst);
    return DispatchGrid(ex, *kernel, params.w, params.h, params, b1);
  }

  namespace
  {
    const Grid* InputOf(
      const OpArgs& a,
      const char* const key
    )
    {
      const auto it = a.in.find(key);
      return it != a.in.end() ? it->second.get() : nullptr;
    }

    std::expected<OpResult, std::string> OpBlurGpu(
      Executor& ex,
      const OpArgs& a,
      const bool gauss,
      Grid& out
    )
    {
      // 1. what the GPU version does not handle goes back to the CPU op (which also reports bad inputs with its own
      // messages)
      const Grid* src = InputOf(a, "a");
      if (src == nullptr || src->w < 1 || src->h < 1) {
        return OpResult::Unsupported;
      }
      if (const Grid* like = InputOf(a, "like"); like != nullptr && !like->SameShape(*src)) {
        return OpResult::Unsupported;
      }
      // the CPU op blends with the mask only when it has the field's shape (else it ignores it): the same here
      const Grid* mask = InputOf(a, "mask");
      if (mask != nullptr && !mask->SameShape(*src)) {
        mask = nullptr;
      }
      const double radius =
        a.p.N("radius", 4.0) / static_cast<double>(src->cell); // world units -> samples, as on the CPU
      if (radius <= 1e-6) {
        return OpResult::Unsupported;
      }
      int r = 0;
      const std::vector<float> weights = MakeKernel(gauss, radius, r);
      const double work = 2.0 * static_cast<double>(src->w) * static_cast<double>(src->h) * (2.0 * r + 1.0);
      if (r > 8192 || work > 3.0e10) {
        return OpResult::Unsupported; // one dispatch this long could hit the 2 second driver reset: the CPU does it
      }
      const std::uint64_t bytes = (mask != nullptr ? 5ull : 2ull) * src->Count() * 4ull + weights.size() * 4ull;
      if (bytes > ex.MaxBytes()) {
        return OpResult::Unsupported;
      }
      const KernelInfo* kernel = FindKernel("blur_pass");
      if (kernel == nullptr) {
        return std::unexpected("kernel blur_pass is missing");
      }

      // 2. upload, two passes (x then z) over a ping-pong pair, download into a local grid
      PingPong pp;
      std::unique_ptr<Resource> kbuf;
      FAF_GPU_TRY(UploadGrid(ex, *src, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, pp.f[1]));
      FAF_GPU_TRY(MakeBuffer(ex, static_cast<u32>(weights.size()), kbuf));
      FAF_GPU_TRY(UploadBuffer(ex, *kbuf, weights.data(), weights.size() * 4));
      hk::BlurParams params{};
      params.w = static_cast<std::uint32_t>(src->w);
      params.h = static_cast<std::uint32_t>(src->h);
      params.radius = static_cast<std::uint32_t>(r);
      for (std::uint32_t pass = 0; pass < 2; ++pass) {
        params.vertical = pass;
        Bindings b;
        b.Srv(0, pp.Src().R()).Srv(1, *kbuf).Uav(0, pp.Dst().R());
        FAF_GPU_TRY(DispatchGrid(ex, *kernel, params.w, params.h, params, b));
        pp.Flip();
      }
      Field* resultField = &pp.Src();
      Field blended;
      if (mask != nullptr) {
        // out = src + (blurred - src) * clamp01(mask), one more pass (kernel filt_lerpmask)
        const KernelInfo* lerpKernel = FindKernel("filt_lerpmask");
        Field orig, mfield;
        if (lerpKernel == nullptr) {
          return std::unexpected("kernel filt_lerpmask is missing");
        }
        FAF_GPU_TRY(UploadGrid(ex, *src, orig));
        FAF_GPU_TRY(UploadGrid(ex, *mask, mfield));
        FAF_GPU_TRY(MakeField(ex, src->w, src->h, blended));
        hk::LerpMaskParams lp{};
        lp.w = params.w;
        lp.h = params.h;
        Bindings lb;
        lb.Srv(0, orig.R()).Srv(1, pp.Src().R()).Srv(2, mfield.R()).Uav(0, blended.R());
        FAF_GPU_TRY(DispatchGrid(ex, *lerpKernel, lp.w, lp.h, lp, lb));
        resultField = &blended;
      }
      Grid result(src->w, src->h, src->cell, src->ox, src->oz);
      FAF_GPU_TRY(DownloadGrid(ex, *resultField, result));
      out = std::move(result);
      return OpResult::Done;
    }

    std::expected<OpResult, std::string> OpBlurGaussGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      return OpBlurGpu(ex, a, true, out);
    }
    std::expected<OpResult, std::string> OpBlurBoxGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      return OpBlurGpu(ex, a, false, out);
    }

    struct BuiltinOps
    {
      BuiltinOps()
      {
        RegisterGpuOp("blur", &OpBlurGaussGpu);
        RegisterGpuOp("box", &OpBlurBoxGpu);
      }
    };
    const BuiltinOps gBuiltinOps;
  } // namespace

  // ---- self test
  // ---------------------------------------------------------------------------------------------------------------------------------

  namespace
  {
    std::string Fmt(
      const char* const f,
      const double a,
      const double b = 0.0,
      const double c = 0.0
    )
    {
      char buf[160];
      std::snprintf(buf, sizeof(buf), f, a, b, c);
      return buf;
    }

    SelfTestPart PartScaleOffset(
      Executor& ex
    )
    {
      SelfTestPart part;
      part.name = "scale + offset (64 x 64)";
      const auto t0 = std::chrono::steady_clock::now();
      const auto tested = [&]() -> std::expected<void, std::string> {
        const KernelInfo* k = FindKernel("scale_offset");
        if (k == nullptr) {
          return std::unexpected("kernel scale_offset is missing");
        }
        const std::uint32_t n = 64 * 64;
        std::vector<float> in(n), res(n);
        for (std::uint32_t i = 0; i < n; ++i)
          in[i] = static_cast<float>(i % 97) * 0.25f - 3.0f;
        std::unique_ptr<Resource> a, b;
        FAF_GPU_TRY(MakeBuffer(ex, n, a));
        FAF_GPU_TRY(MakeBuffer(ex, n, b));
        FAF_GPU_TRY(UploadBuffer(ex, *a, in.data(), n * 4));
        hk::ScaleParams p{};
        p.count = n;
        p.scale = 1.5f;
        p.offset = -0.75f;
        Bindings bind;
        bind.Srv(0, *a).Uav(0, *b);
        FAF_GPU_TRY(DispatchGrid(ex, *k, n, 1, p, bind));
        FAF_GPU_TRY(ex.Download(*b, res.data(), n * 4));
        double worst = 0.0;
        for (std::uint32_t i = 0; i < n; ++i)
          worst = std::max(worst, static_cast<double>(std::fabs(res[i] - (in[i] * 1.5f - 0.75f))));
        part.ok = worst <= 1e-5;
        part.detail = Fmt("largest difference %g", worst);
        return {};
      }();
      if (!tested)
        part.detail = tested.error();
      part.ms = MsSince(t0);
      return part;
    }

    SelfTestPart PartReduce(
      Executor& ex
    )
    {
      SelfTestPart part;
      part.name = "group shared memory reduction (10000 values)";
      const auto t0 = std::chrono::steady_clock::now();
      const auto tested = [&]() -> std::expected<void, std::string> {
        const KernelInfo* k = FindKernel("reduce_sum");
        if (k == nullptr) {
          return std::unexpected("kernel reduce_sum is missing");
        }
        const std::uint32_t n = 10000;
        const std::uint32_t groups = (n + 255) / 256;
        std::vector<float> in(n), res(groups);
        for (std::uint32_t i = 0; i < n; ++i)
          in[i] = static_cast<float>(i % 7); // small integers: exact sums in any order
        std::unique_ptr<Resource> a, b;
        FAF_GPU_TRY(MakeBuffer(ex, n, a));
        FAF_GPU_TRY(MakeBuffer(ex, groups, b));
        FAF_GPU_TRY(UploadBuffer(ex, *a, in.data(), n * 4));
        hk::ReduceParams p{};
        p.count = n;
        Bindings bind;
        bind.Srv(0, *a).Uav(0, *b);
        Groups g;
        g.x = groups;
        FAF_GPU_TRY(ex.Dispatch(*k, g, &p, static_cast<u32>(sizeof(p)), bind));
        FAF_GPU_TRY(ex.Download(*b, res.data(), groups * 4));
        std::uint32_t wrong = 0;
        for (std::uint32_t gi = 0; gi < groups; ++gi) {
          float expect = 0.0f;
          for (std::uint32_t i = gi * 256; i < std::min(n, gi * 256 + 256); ++i)
            expect += in[i];
          if (res[gi] != expect)
            ++wrong;
        }
        part.ok = wrong == 0;
        part.detail = wrong == 0 ? std::string("all sums equal") : Fmt("%g of %g sums differ", wrong, groups);
        return {};
      }();
      if (!tested)
        part.detail = tested.error();
      part.ms = MsSince(t0);
      return part;
    }

    SelfTestPart PartBlur(
      Executor& ex
    )
    {
      SelfTestPart part;
      part.name = "gaussian blur (96 x 80) against the CPU op";
      const auto t0 = std::chrono::steady_clock::now();
      const auto tested = [&]() -> std::expected<void, std::string> {
        auto in = std::make_shared<Grid>(96, 80, 2.0f, 10.0f, -4.0f);
        for (std::size_t i = 0; i < in->v.size(); ++i) {
          std::uint32_t h = static_cast<std::uint32_t>(i) * 2654435761u;
          h ^= h >> 15;
          h *= 2246822519u;
          h ^= h >> 13;
          in->v[i] = static_cast<float>(h >> 8) * (1.0f / 16777216.0f) * 100.0f;
        }
        OpArgs args;
        args.in["a"] = in;
        args.p.num["radius"] = 6.0;
        Grid gpuOut, cpuOut;
        if (const auto gpu = OpBlurGpu(ex, args, true, gpuOut); !gpu || *gpu != OpResult::Done) {
          return std::unexpected(
            !gpu && !gpu.error().empty() ? gpu.error() : std::string("the GPU op refused the self test input")
          );
        }
        if (const auto ran = field::RunOpCpu("blur", args, cpuOut); !ran) {
          return std::unexpected("CPU op failed: " + ran.error());
        }
        double worst = 0.0;
        for (std::size_t i = 0; i < cpuOut.v.size(); ++i)
          worst = std::max(worst, static_cast<double>(std::fabs(gpuOut.v[i] - cpuOut.v[i])));
        part.ok = gpuOut.SameShape(cpuOut) && worst <= 1e-3; // values are up to 100: a few float32 steps
        part.detail = Fmt("largest difference %g (values up to 100)", worst);
        return {};
      }();
      if (!tested)
        part.detail = tested.error();
      part.ms = MsSince(t0);
      return part;
    }

    SelfTestPart PartTexture(
      Executor& ex
    )
    {
      SelfTestPart part;
      part.name = "texture sampling (32 x 24 to 64 x 48)";
      const auto t0 = std::chrono::steady_clock::now();
      const auto tested = [&]() -> std::expected<void, std::string> {
        if (!ex.SupportsTextures()) {
          return std::unexpected("textures are not supported by this device");
        }
        const KernelInfo* k = FindKernel("tex_resample");
        if (k == nullptr) {
          return std::unexpected("kernel tex_resample is missing");
        }
        const int sw = 32, sh = 24, dw = 64, dh = 48;
        std::vector<float> in(static_cast<std::size_t>(sw) * sh);
        for (int z = 0; z < sh; ++z)
          for (int x = 0; x < sw; ++x)
            in[static_cast<std::size_t>(z) * sw + x] = static_cast<float>((x * 7 + z * 13) % 31) / 31.0f;
        Field f;
        std::unique_ptr<Resource> tex;
        FAF_GPU_TRY(MakeField(ex, sw, sh, f));
        FAF_GPU_TRY(UploadField(ex, f, in.data()));
        FAF_GPU_TRY(MakeTextureFromField(ex, f, tex));
        Field out;
        FAF_GPU_TRY(MakeField(ex, dw, dh, out));
        hk::FieldParams p{};
        p.w = dw;
        p.h = dh;
        p.srcW = sw;
        p.srcH = sh;
        Bindings bind;
        bind.Srv(0, *tex).Uav(0, out.R());
        FAF_GPU_TRY(DispatchGrid(ex, *k, dw, dh, p, bind));
        std::vector<float> res(static_cast<std::size_t>(dw) * dh);
        FAF_GPU_TRY(DownloadField(ex, out, res.data()));
        double worst = 0.0;
        const auto texel = [&](int x, int z) {
          return in
            [static_cast<std::size_t>(std::min(sh - 1, std::max(0, z))) * sw +
             static_cast<std::size_t>(std::min(sw - 1, std::max(0, x)))];
        };
        for (int z = 0; z < dh; ++z) {
          for (int x = 0; x < dw; ++x) {
            const float fx = (static_cast<float>(x) + 0.5f) / static_cast<float>(dw) * static_cast<float>(sw) - 0.5f;
            const float fz = (static_cast<float>(z) + 0.5f) / static_cast<float>(dh) * static_cast<float>(sh) - 0.5f;
            const int x0 = static_cast<int>(std::floor(fx));
            const int z0 = static_cast<int>(std::floor(fz));
            const float tx = fx - static_cast<float>(x0);
            const float tz = fz - static_cast<float>(z0);
            const float top = texel(x0, z0) + (texel(x0 + 1, z0) - texel(x0, z0)) * tx;
            const float bottom = texel(x0, z0 + 1) + (texel(x0 + 1, z0 + 1) - texel(x0, z0 + 1)) * tx;
            const float expect = top + (bottom - top) * tz;
            worst = std::max(worst, static_cast<double>(std::fabs(res[static_cast<std::size_t>(z) * dw + x] - expect)));
          }
        }
        part.ok = worst <= 0.01; // hardware filtering uses 8 bit weights: up to ~0.004 for values in 0..1
        part.detail = Fmt("largest difference %g (values 0..1, hardware filtering allows ~0.004)", worst);
        return {};
      }();
      if (!tested)
        part.detail = tested.error();
      part.ms = MsSince(t0);
      return part;
    }
  } // namespace

  SelfTestReport RunSelfTest(
    Executor& ex
  )
  {
    SelfTestReport rep;
    const auto t0 = std::chrono::steady_clock::now();
    try {
      rep.parts.push_back(PartScaleOffset(ex));
      rep.parts.push_back(PartReduce(ex));
      rep.parts.push_back(PartBlur(ex));
      rep.parts.push_back(PartTexture(ex));
    } catch (const std::exception& e) {
      rep.error = std::string("exception: ") + e.what();
    } catch (...) {
      rep.error = "exception";
    }
    double dummy = 0.0;
    if (const auto synced = ex.Sync(&dummy); !synced && rep.error.empty()) {
      rep.error = synced.error();
    }
    rep.ok = rep.error.empty() && rep.parts.size() == 4 && rep.parts[0].ok && rep.parts[1].ok && rep.parts[2].ok;
    rep.texturesOk = rep.parts.size() == 4 && rep.parts[3].ok;
    rep.ms = MsSince(t0);
    return rep;
  }

  SelfTestReport RunSelfTest()
  {
    SelfTestReport rep;
    Lease lease(true);
    if (!lease) {
      rep.error = lease.Error().empty() ? "the GPU backend is not available" : lease.Error();
      return rep;
    }
    rep = RunSelfTest(*lease);
    if (rep.ok) {
      gSelfTestPassed.store(true);
    }
    if (lease->DeviceLost()) {
      lease.Fail(rep.error.empty() ? "device lost during the self test" : rep.error);
    }
    return rep;
  }
} // namespace faf::editor::gpu
