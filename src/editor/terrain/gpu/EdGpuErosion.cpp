// EDITOR GPU compute: the erosion ops on the graphics card (docs/projects/editor/GPU_COMPUTE.md, "Erosion kernels").
// Registered under the CPU ops' names (erode_hydraulic, erode_droplet), so the interceptor picks them for any field of
// at least kMinCells samples; any parameter or input they do not handle returns Unsupported and the CPU op runs.
//
//   erode_hydraulic   a shallow water / pipe model with eight pipes per cell, sediment capacity from a softly saturated
//   slope and the flow speed, conservative sediment transport, evaporation,
//                     the thermal slides of the CPU op every few iterations. Kernels
//                     gpu/erosion_hydro_{flux,water,transport,settle}.hlsl and erosion_thermal_{a,b}.hlsl.
//   erode_droplet     one thread per droplet (Beyer / Lague), the ground changed by atomic adds on fixed point
//   integers, rounds with a refreshed steering surface and creep, the cell noise filter and
//                     thermal slides on the card. Kernels gpu/erosion_drop.hlsl, erosion_drop_resolve.hlsl,
//                     erosion_steer.hlsl, erosion_delta.hlsl, erosion_blend.hlsl (+ blur_pass).
// Everything around the solve (hardness / rain / protect factors, the cell noise filter of the hydraulic op, conserve,
// keep_range, max_change, the outputs) is the CPU op's own code, exported from EdErosion.cpp (BuildOpFactors,
// FinishHydroOp, FinishDropletOp), so a setting means the same on both paths.
#pragma fp_contract(off)

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "editor/terrain/EdErosion.h"
#include "editor/terrain/gpu/EdGpuOps.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/blur_params.hlsli"
#include "editor/terrain/gpu/erosion_drop_params.hlsli"
#include "editor/terrain/gpu/erosion_hydro_params.hlsli"
#include "editor/terrain/gpu/erosion_thermal_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using field::Grid;
  using field::OpArgs;
  namespace ero = field::erosion;

  namespace
  {
    /** Erosion pays off on small fields too: 64 x 64 samples and up (the policy's own minimum still applies when it is
     * lower). */
    constexpr float kMinCells = 4096.0f;
    constexpr std::uint64_t kMaxBufferElements = 1ull << 27;

    const Grid* InputOf(
      const OpArgs& a,
      const char* const key
    )
    {
      const auto it = a.in.find(key);
      return it != a.in.end() ? it->second.get() : nullptr;
    }

    float Clamp01(
      const float v
    )
    {
      return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
    }

    /** What both ops refuse before they touch the device. */
    OpResult Preflight(
      const OpArgs& a,
      const Grid*& src
    )
    {
      src = nullptr;
      if (a.p.N("cpu_only", 0.0) != 0.0)
        return OpResult::Unsupported; // the node's "CPU only" choice (A / B comparison)
      src = InputOf(a, "a");
      if (src == nullptr || src->w < 4 || src->h < 4 || src->v.size() != src->Count())
        return OpResult::Unsupported;
      if (const Grid* m = InputOf(a, "mask"); m != nullptr && !m->SameShape(*src))
        return OpResult::Unsupported; // the CPU op reports the mismatch
      const std::string which = a.p.S("output", "height");
      if (
        which != "height" && which != "wear" && which != "deposit" && which != "flow" && which != "water" &&
        which != "sediment"
      )
        return OpResult::Unsupported;
      return OpResult::Done;
    }

    /** wear / deposit / flow (and water, sediment) are needed: an output choice, or (unless masks=0) the editor asks
     * for them all (a.extra) or conserve puts the lost volume back where the deposit is. */
    bool WantsMasks(
      const OpArgs& a
    )
    {
      if (a.p.S("output", "height") != "height")
        return true;
      return a.p.N("masks", 1.0) != 0.0 &&
        (a.extra != nullptr ||
         a.p.N("conserve", 0.0) > 0.0); // masks=0: the editor does not use them (a preview, a graph that wires none)
    }

    /** A field with its own zeroed buffer, or the 1 element dummy a kernel gets for an array that is switched off by a
     * flag (never read or written then). */
    struct Dev
    {
      Executor& ex;
      std::unique_ptr<Resource>
        dummy[7]; // [0] read only; [1..6] one per unused written slot (one resource is never bound to two UAV slots of
                  // a dispatch: the runtime drops the dispatch's writes)
      explicit Dev(
        Executor& e
      )
        : ex(e)
      {}
      std::expected<void, std::string> Zero(
        Field& f,
        const int w,
        const int h
      )
      {
        FAF_GPU_TRY(MakeField(ex, w, h, f));
        FAF_GPU_TRY(FillBuffer(ex, f.R(), 0u));
        return {};
      }
      std::expected<void, std::string> Zero(
        std::unique_ptr<Resource>& r,
        const u32 count
      )
      {
        FAF_GPU_TRY(MakeBuffer(ex, count, r));
        FAF_GPU_TRY(FillBuffer(ex, *r, 0u));
        return {};
      }
      std::expected<void, std::string> Dummies()
      {
        for (auto& d : dummy) {
          FAF_GPU_TRY(MakeBuffer(ex, 1, d));
          FAF_GPU_TRY(FillBuffer(ex, *d, 0u));
        }
        return {};
      }
      std::expected<void, std::string> Optional(
        const std::vector<float>& v,
        const int w,
        const int h,
        Field& f
      )
      {
        if (v.empty())
          return {};
        if (v.size() != static_cast<std::size_t>(w) * static_cast<std::size_t>(h)) {
          return std::unexpected("per cell factor of the wrong size");
        }
        FAF_GPU_TRY(MakeField(ex, w, h, f));
        return UploadField(ex, f, v.data());
      }
    };

    const Resource& Or(
      const Field& f,
      const Resource& other
    )
    {
      return f ? f.R() : other;
    }

    // ---- thermal slides
    // --------------------------------------------------------------------------------------------------------------------

    struct ThermalKit
    {
      const KernelInfo* a = nullptr;
      const KernelInfo* b = nullptr;
      Field share, moved;
      std::expected<void, std::string> Make(
        Dev& d,
        const int w,
        const int h
      )
      {
        a = FindKernel("erosion_thermal_a");
        b = FindKernel("erosion_thermal_b");
        if (a == nullptr || b == nullptr) {
          return std::unexpected("kernel erosion_thermal_a / erosion_thermal_b is missing");
        }
        FAF_GPU_TRY(MakeField(d.ex, w, h, share));
        return MakeField(d.ex, w, h, moved);
      }
      /** One slide step from pp.Src() into pp.Dst(), then flips. */
      std::expected<void, std::string> Step(
        Executor& ex,
        PingPong& pp,
        const Resource& mask,
        const bool hasMask,
        const hk::ErodeThermalParams& tp
      )
      {
        {
          Bindings bi;
          bi.Srv(0, pp.Src().R()).Srv(1, mask).Uav(0, share.R()).Uav(1, moved.R());
          FAF_GPU_TRY(DispatchGrid(ex, *a, tp.w, tp.h, tp, bi));
        }
        {
          Bindings bi;
          bi.Srv(0, pp.Src().R()).Srv(1, share.R()).Srv(2, moved.R()).Uav(0, pp.Dst().R());
          FAF_GPU_TRY(DispatchGrid(ex, *b, tp.w, tp.h, tp, bi));
        }
        (void)hasMask;
        pp.Flip();
        return {};
      }
    };

    hk::ErodeThermalParams ThermalParams(
      const int w,
      const int h,
      const float cell,
      const float talus,
      const float rate,
      const bool hasMask,
      const int pinSides
    )
    {
      hk::ErodeThermalParams tp{};
      tp.w = static_cast<std::uint32_t>(w);
      tp.h = static_cast<std::uint32_t>(h);
      tp.pinSides = static_cast<std::uint32_t>(pinSides);
      tp.hasMask = hasMask ? 1u : 0u;
      tp.tAxis = talus * cell;
      tp.tDiag = talus * cell * 1.41421356f;
      tp.rate = rate;
      return tp;
    }

    // ---- erode_hydraulic
    // -------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpHydraulicGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = nullptr;
      if (const OpResult pre = Preflight(a, src); pre != OpResult::Done)
        return pre;
      const ero::HydroParams p = ero::HydroParamsOf(a);
      if (p.iterations <= 0)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      const std::uint64_t n = static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h);
      if (4ull * n > kMaxBufferElements || 25ull * n * 4ull > ex.MaxBytes())
        return OpResult::Unsupported; // the flux planes are 4 n elements; about 24 fields in all
      const KernelInfo* kFlux = FindKernel("erosion_hydro_flux");
      const KernelInfo* kWater = FindKernel("erosion_hydro_water");
      const KernelInfo* kTrans = FindKernel("erosion_hydro_transport");
      const KernelInfo* kSettle = FindKernel("erosion_hydro_settle");
      const KernelInfo* kApply = FindKernel("erosion_hydro_apply");
      if (kFlux == nullptr || kWater == nullptr || kTrans == nullptr || kSettle == nullptr || kApply == nullptr) {
        return std::unexpected("an erosion_hydro kernel is missing");
      }

      ero::OpFactors fac;
      ero::BuildOpFactors(a, *src, fac);
      const bool masks = WantsMasks(a);
      const bool thermalOn = p.thermal > 0.0f && p.thermal_every > 0;

      Dev dev(ex);
      PingPong T;
      Field D, S, SN, DO, dT, rain, rock, thermalRate, wear, dep, flow;
      std::unique_ptr<Resource> Fa, Fb;
      ThermalKit tk;
      FAF_GPU_TRY(dev.Dummies());
      FAF_GPU_TRY(MakeField(ex, w, h, T.f[1]));
      FAF_GPU_TRY(UploadGrid(ex, *src, T.f[0]));
      FAF_GPU_TRY(dev.Zero(D, w, h));
      FAF_GPU_TRY(dev.Zero(S, w, h));
      FAF_GPU_TRY(MakeField(ex, w, h, SN));
      FAF_GPU_TRY(MakeField(ex, w, h, DO));
      FAF_GPU_TRY(MakeField(ex, w, h, dT));
      FAF_GPU_TRY(dev.Zero(Fa, static_cast<u32>(4 * n)));
      FAF_GPU_TRY(dev.Zero(Fb, static_cast<u32>(4 * n)));
      FAF_GPU_TRY(dev.Optional(fac.rain, w, h, rain));
      FAF_GPU_TRY(dev.Optional(fac.rock, w, h, rock));
      FAF_GPU_TRY(dev.Optional(fac.thermal, w, h, thermalRate));
      if (masks) {
        FAF_GPU_TRY(dev.Zero(wear, w, h));
        FAF_GPU_TRY(dev.Zero(dep, w, h));
        FAF_GPU_TRY(dev.Zero(flow, w, h));
      }
      if (thermalOn) {
        FAF_GPU_TRY(tk.Make(dev, w, h));
      }

      const int sides = p.pin_border ? (p.pin_sides & 15) : 0;
      hk::ErodeHydroParams hp{};
      hp.w = static_cast<std::uint32_t>(w);
      hp.h = static_cast<std::uint32_t>(h);
      hp.flags = (fac.rain.empty() ? 0u : 1u) | (fac.rock.empty() ? 0u : 2u) | (p.open_edge ? 4u : 0u) |
        (p.pin_border ? 8u : 0u) | (masks ? 16u : 0u);
      // the eight pipes: the diagonal ones carry a quarter of the gain, so the sum of the weights is 5 gain and stays
      // stable up to 0.2 (the CPU's four pipes: 0.25)
      hp.gain = std::max(0.0f, std::min(0.2f, p.gain));
      hp.evap = Clamp01(p.evaporation);
      hp.rain = p.rain;
      hp.capacity = p.capacity;
      hp.erosion = p.erosion;
      hp.deposition = p.deposition;
      hp.invDepthMax = 1.0f / std::max(1e-4f, p.depth_max);
      hp.minSlope = p.min_slope;
      hp.slopeCap = std::max(0.05f, static_cast<float>(a.p.N("slope_cap", 0.4)));
      hp.maxSpeed = p.max_speed;
      hp.cutLimit = p.cut_limit;
      hp.cell = src->cell;
      hp.rainNoise = Clamp01(static_cast<float>(a.p.N("rain_noise", 0.2)));
      hp.seed = static_cast<std::uint32_t>(a.p.N("seed", 1.0));
      hp.velFloor = 0.002f;
      hp.damp = Clamp01(static_cast<float>(a.p.N("flux_damp", 0.3)));
      hp.vThresh = std::max(0.0f, static_cast<float>(a.p.N("speed_floor", 0.0)));
      hp.speedPow = std::max(0.25f, static_cast<float>(a.p.N("speed_pow", 1.0)));
      hp.rampMax = std::max(1.0f, static_cast<float>(a.p.N("depth_gain", 4.0)));
      hp.tauC = std::max(0.0f, static_cast<float>(a.p.N("shear_floor", 0.0)));
      hp.spread = Clamp01(static_cast<float>(a.p.N("erode_spread", 0.7)));
      const hk::ErodeThermalParams tp = ThermalParams(w, h, src->cell, p.talus, p.thermal, !fac.thermal.empty(), sides);

      const Resource& d0 = *dev.dummy[0];
      const Resource& wearR = masks ? wear.R() : *dev.dummy[1];
      const Resource& depR = masks ? dep.R() : *dev.dummy[2];
      const Resource& flowR = masks ? flow.R() : *dev.dummy[3];
      IterStats st;
      const auto ok =
        RunIterations(ex, static_cast<u32>(p.iterations), 60.0, [&](const u32 it) -> std::expected<void, std::string> {
        hp.iter = it;
        {
          Bindings b;
          b.Srv(0, T.Src().R()).Srv(1, D.R()).Srv(2, Or(rain, d0)).Uav(0, *Fa).Uav(1, *Fb);
          FAF_GPU_TRY(DispatchGrid(ex, *kFlux, hp.w, hp.h, hp, b));
        }
        {
          Bindings b;
          b.Srv(0, T.Src().R()).Srv(1, *Fa).Srv(2, *Fb).Srv(3, Or(rain, d0)).Srv(4, Or(rock, d0)).Srv(5, S.R());
          b.Uav(0, dT.R()).Uav(1, D.R()).Uav(2, SN.R()).Uav(3, DO.R()).Uav(4, wearR).Uav(5, depR).Uav(6, flowR);
          FAF_GPU_TRY(DispatchGrid(ex, *kWater, hp.w, hp.h, hp, b));
        }
        {
          Bindings b;
          b.Srv(0, T.Src().R()).Srv(1, dT.R()).Uav(0, T.Dst().R());
          FAF_GPU_TRY(DispatchGrid(ex, *kApply, hp.w, hp.h, hp, b));
        }
        T.Flip();
        {
          Bindings b;
          b.Srv(0, *Fa).Srv(1, *Fb).Srv(2, SN.R()).Srv(3, DO.R()).Uav(0, S.R()).Uav(1, D.R());
          FAF_GPU_TRY(DispatchGrid(ex, *kTrans, hp.w, hp.h, hp, b));
        }
        if (thermalOn && ((it + 1) % static_cast<u32>(p.thermal_every)) == 0) {
          FAF_GPU_TRY(tk.Step(ex, T, Or(thermalRate, d0), !fac.thermal.empty(), tp));
        }
        return {};
      }, &st);
      if (!ok)
        return std::unexpected(ok.error());
      if (p.settle) {
        Bindings b;
        b.Uav(0, T.Src().R()).Uav(1, S.R()).Uav(2, depR);
        FAF_GPU_TRY(DispatchGrid(ex, *kSettle, hp.w, hp.h, hp, b));
      }

      ero::HydroState hs;
      hs.w = w;
      hs.h = h;
      hs.cell = src->cell;
      hs.t.resize(static_cast<std::size_t>(n));
      FAF_GPU_TRY(DownloadField(ex, T.Src(), hs.t.data()));
      if (masks) {
        hs.d.resize(static_cast<std::size_t>(n));
        hs.s.resize(static_cast<std::size_t>(n));
        hs.wear.resize(static_cast<std::size_t>(n));
        hs.dep.resize(static_cast<std::size_t>(n));
        hs.flow.resize(static_cast<std::size_t>(n));
        FAF_GPU_TRY(DownloadField(ex, D, hs.d.data()));
        FAF_GPU_TRY(DownloadField(ex, S, hs.s.data()));
        FAF_GPU_TRY(DownloadField(ex, wear, hs.wear.data()));
        FAF_GPU_TRY(DownloadField(ex, dep, hs.dep.data()));
        FAF_GPU_TRY(DownloadField(ex, flow, hs.flow.data()));
      }
      Grid result;
      if (auto finished = ero::FinishHydroOp(a, *src, p, hs, result); !finished) {
        return std::unexpected(finished.error());
      }
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- erode_droplet
    // ---------------------------------------------------------------------------------------------------------------------

    std::uint32_t HostHash(
      std::uint32_t x
    )
    {
      x ^= x >> 16;
      x *= 0x7feb352du;
      x ^= x >> 15;
      x *= 0x846ca68bu;
      x ^= x >> 16;
      return x;
    }

    /** The change of a field since `base` (d = t - base), smoothed by `passes` binomial 3 x 3 passes (a fraction blends
     * one more in), then t += amount * mask * (smoothed - d): the creep between droplet rounds (base = the input, mask
     * = rock) and the cell noise filter at the end (mask none). t is a PingPong: the result lands in Dst and the pair
     * flips. */
    struct DeltaFilter
    {
      const KernelInfo* kDelta = nullptr;
      const KernelInfo* kBlend = nullptr;
      const KernelInfo* kBlur = nullptr;
      std::unique_ptr<Resource> weights;
      Field d, f[3];

      std::expected<void, std::string> Make(
        Dev& dev,
        const int w,
        const int h
      )
      {
        kDelta = FindKernel("erosion_delta");
        kBlend = FindKernel("erosion_blend");
        kBlur = FindKernel("blur_pass");
        if (kDelta == nullptr || kBlend == nullptr || kBlur == nullptr) {
          return std::unexpected("kernel erosion_delta / erosion_blend / blur_pass is missing");
        }
        const float kern[2] = {0.5f, 0.25f}; // centre 1/2, sides 1/4: with the clamped edges the CPU BlurPass
        FAF_GPU_TRY(MakeField(dev.ex, w, h, d));
        FAF_GPU_TRY(MakeField(dev.ex, w, h, f[0]));
        FAF_GPU_TRY(MakeField(dev.ex, w, h, f[1]));
        FAF_GPU_TRY(MakeField(dev.ex, w, h, f[2]));
        FAF_GPU_TRY(MakeBuffer(dev.ex, 2, weights));
        return UploadBuffer(dev.ex, *weights, kern, sizeof(kern));
      }

      /** One smoothing pass of `from` into a scratch field other than `from` (never `d`, which the blend needs);
       * returns it (or the error). */
      std::expected<Field*, std::string> Pass(
        Executor& ex,
        Field* from
      )
      {
        Field* out = nullptr;
        Field* tmp = nullptr;
        for (Field& c : f) {
          if (&c == from)
            continue;
          if (out == nullptr)
            out = &c;
          else if (tmp == nullptr)
            tmp = &c;
        }
        if (out == nullptr || tmp == nullptr) {
          return std::unexpected("no scratch field left");
        }
        hk::BlurParams bp{};
        bp.w = static_cast<std::uint32_t>(d.w);
        bp.h = static_cast<std::uint32_t>(d.h);
        bp.radius = 1;
        {
          bp.vertical = 0;
          Bindings bi;
          bi.Srv(0, from->R()).Srv(1, *weights).Uav(0, tmp->R());
          FAF_GPU_TRY(DispatchGrid(ex, *kBlur, bp.w, bp.h, bp, bi));
        }
        {
          bp.vertical = 1;
          Bindings bi;
          bi.Srv(0, tmp->R()).Srv(1, *weights).Uav(0, out->R());
          FAF_GPU_TRY(DispatchGrid(ex, *kBlur, bp.w, bp.h, bp, bi));
        }
        return out;
      }

      std::expected<void, std::string> Run(
        Executor& ex,
        PingPong& t,
        const Field& base,
        const float passes,
        const float amount,
        const Resource* mask,
        const bool edgeKeep,
        const Resource& dummy
      )
      {
        hk::ErodeThermalParams tp{};
        tp.w = static_cast<std::uint32_t>(d.w);
        tp.h = static_cast<std::uint32_t>(d.h);
        {
          Bindings bi;
          bi.Srv(0, t.Src().R()).Srv(1, base.R()).Uav(0, d.R());
          FAF_GPU_TRY(DispatchGrid(ex, *kDelta, tp.w, tp.h, tp, bi));
        }
        const int whole = static_cast<int>(passes);
        const float frac = passes - static_cast<float>(whole);
        Field* sm = &d;
        for (int k = 0; k < whole; ++k) {
          const auto next = Pass(ex, sm);
          if (!next)
            return std::unexpected(next.error());
          sm = *next;
        }
        Field* sm2 = sm;
        if (frac > 0.0f) {
          const auto next = Pass(ex, sm);
          if (!next)
            return std::unexpected(next.error());
          sm2 = *next;
        }
        tp.amount = amount;
        tp.blendNext = frac;
        tp.hasMask = mask != nullptr ? 1u : 0u;
        tp.edgeKeep = edgeKeep ? 1u : 0u;
        Bindings bi;
        bi.Srv(0, t.Src().R())
          .Srv(1, d.R())
          .Srv(2, sm->R())
          .Srv(3, sm2->R())
          .Srv(4, mask != nullptr ? *mask : dummy)
          .Uav(0, t.Dst().R());
        FAF_GPU_TRY(DispatchGrid(ex, *kBlend, tp.w, tp.h, tp, bi));
        t.Flip();
        return {};
      }
    };

    std::expected<OpResult, std::string> OpDropletGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = nullptr;
      if (const OpResult pre = Preflight(a, src); pre != OpResult::Done)
        return pre;
      ero::DropletParams p = ero::DropletParamsOf(a);
      if (p.density <= 0.0f)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      const std::uint64_t n = static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h);
      if (n > kMaxBufferElements || 26ull * n * 4ull > ex.MaxBytes())
        return OpResult::Unsupported;
      const KernelInfo* kDrop = FindKernel("erosion_drop");
      const KernelInfo* kResolve = FindKernel("erosion_drop_resolve");
      const KernelInfo* kSteer = FindKernel("erosion_steer");
      const KernelInfo* kCopy = FindKernel("erosion_copy");
      if (kDrop == nullptr || kResolve == nullptr || kSteer == nullptr || kCopy == nullptr) {
        return std::unexpected("an erosion_drop kernel is missing");
      }

      ero::OpFactors fac;
      ero::BuildOpFactors(a, *src, fac);
      if (!fac.accept.empty()) {
        // the thinned release keeps the mean density: more candidates where it is accepted less
        double mean = 0.0;
        for (const float x : fac.accept)
          mean += x;
        mean /= static_cast<double>(fac.accept.size());
        p.density = static_cast<float>(p.density / std::max(0.05, mean));
      }
      const bool masks = WantsMasks(a);
      const int rounds = std::max(1, p.rounds);
      const float creepPasses =
        std::min(48.0f, std::max(0.0f, p.creep) * (p.density * 0.5f) * (32.0f / static_cast<float>(rounds)));
      const int smoothPasses = std::max(0, std::min(16, static_cast<int>(a.p.N("smooth_passes", 2))));
      const float smoothAmount = static_cast<float>(a.p.N("smooth", 1.0));
      const float thermal = static_cast<float>(a.p.N("thermal", 0.0));
      const int thermalSteps = std::max(0, std::min(1000, static_cast<int>(a.p.N("thermal_steps", 0.0))));
      const bool thermalOn = thermal > 0.0f && thermalSteps > 0;
      const bool pits = p.drain_pits > 0.0f;
      const int steerEvery = std::max(1, static_cast<int>(a.p.N("steer_every", 8.0)));
      const bool smoothOn = smoothPasses > 0 && smoothAmount > 0.0f;

      // droplets per round: the density share, rounded stochastically per round; at most kBatch per dispatch (one
      // dispatch stays far below the driver's time limit)
      constexpr std::uint32_t kBatch = 1u << 19;
      const double want = static_cast<double>(p.density) * static_cast<double>(n) / static_cast<double>(rounds);
      if (want > 4.0e9)
        return OpResult::Unsupported;
      const std::uint32_t whole = static_cast<std::uint32_t>(want);
      const double fraction = want - static_cast<double>(whole);
      const std::uint32_t batches = (whole + 1u + kBatch - 1u) / kBatch;

      Dev dev(ex);
      PingPong T;
      Field t0, tprev, hs, rock, soft, accept, thermalRate, wearF, depF, flowF;
      std::unique_ptr<Resource> dq, wq, pq, fq;
      DeltaFilter filter;
      ThermalKit tk;
      FAF_GPU_TRY(dev.Dummies());
      FAF_GPU_TRY(UploadGrid(ex, *src, T.f[0]));
      FAF_GPU_TRY(UploadGrid(ex, *src, t0));
      FAF_GPU_TRY(MakeField(ex, w, h, T.f[1]));
      FAF_GPU_TRY(dev.Zero(dq, static_cast<u32>(n)));
      if (masks) {
        FAF_GPU_TRY(dev.Zero(wq, static_cast<u32>(n)));
        FAF_GPU_TRY(dev.Zero(pq, static_cast<u32>(n)));
        FAF_GPU_TRY(dev.Zero(fq, static_cast<u32>(n)));
        FAF_GPU_TRY(dev.Zero(wearF, w, h));
        FAF_GPU_TRY(dev.Zero(depF, w, h));
        FAF_GPU_TRY(dev.Zero(flowF, w, h));
      }
      FAF_GPU_TRY(dev.Optional(fac.rock, w, h, rock));
      FAF_GPU_TRY(dev.Optional(fac.soft, w, h, soft));
      FAF_GPU_TRY(dev.Optional(fac.accept, w, h, accept));
      FAF_GPU_TRY(dev.Optional(fac.thermal, w, h, thermalRate));
      if (pits) {
        FAF_GPU_TRY(UploadGrid(ex, *src, hs));
        FAF_GPU_TRY(MakeField(ex, w, h, tprev));
      }
      if (creepPasses > 0.0f || smoothOn) {
        FAF_GPU_TRY(filter.Make(dev, w, h));
      }
      if (thermalOn) {
        FAF_GPU_TRY(tk.Make(dev, w, h));
      }

      hk::ErodeDropParams dp{};
      dp.w = static_cast<std::uint32_t>(w);
      dp.h = static_cast<std::uint32_t>(h);
      dp.gw = 1024;
      dp.seed = p.seed;
      dp.flags = (fac.accept.empty() ? 0u : 1u) | (fac.rock.empty() ? 0u : 2u) | (fac.soft.empty() ? 0u : 4u) |
        (masks ? 8u : 0u) | (p.drop_vary > 0.0f ? 16u : 0u);
      dp.lifetime = static_cast<std::uint32_t>(p.lifetime);
      dp.inertia = p.inertia;
      dp.capacity = p.capacity;
      dp.minSlope = p.min_slope;
      dp.erode = p.erode;
      dp.deposit = p.deposit;
      dp.evaporate = p.evaporate;
      dp.gravity = p.gravity;
      dp.speed = p.speed;
      dp.water = p.water;
      dp.roundCut = p.round_cut;
      dp.accel = p.accel;
      dp.dropVary = p.drop_vary;
      dp.cell = src->cell;
      dp.radius = static_cast<std::uint32_t>(p.radius);
      dp.maxLife =
        static_cast<std::uint32_t>(std::ceil(static_cast<float>(p.lifetime) * (1.0f + 0.4f * p.drop_vary))) + 1u;
      hk::ErodeThermalParams gp = ThermalParams(w, h, src->cell, 0.0f, 0.0f, false, 0);
      gp.flags = masks ? 8u : 0u;

      const Resource& d0 = *dev.dummy[0];
      const Resource& rockR = Or(rock, d0);
      const Resource& wqR = masks ? *wq : *dev.dummy[1];
      const Resource& pqR = masks ? *pq : *dev.dummy[2];
      const Resource& fqR = masks ? *fq : *dev.dummy[3];
      std::vector<float> host;
      const u32 total = static_cast<u32>(rounds) * batches;
      IterStats st;
      const auto ok = RunIterations(ex, total, 60.0, [&](const u32 it) -> std::expected<void, std::string> {
        const u32 round = it / batches;
        const u32 batch = it % batches;
        if (batch == 0) {
          if (pits && (round % static_cast<u32>(steerEvery)) == 0) {
            // a full refresh of the steering surface: the pit filled terrain, computed on the CPU (a priority flood
            // does not parallelise)
            host.resize(static_cast<std::size_t>(n));
            std::vector<float> fill;
            FAF_GPU_TRY(DownloadField(ex, T.Src(), host.data()));
            ero::FillSteeringSurface(host, w, h, 0.004f * src->cell, fill);
            FAF_GPU_TRY(UploadField(ex, hs, fill.data()));
          }
          if (pits) {
            Bindings bi;
            bi.Srv(0, T.Src().R()).Uav(0, tprev.R());
            FAF_GPU_TRY(DispatchGrid(ex, *kCopy, gp.w, gp.h, gp, bi));
          }
        }
        // this batch of droplets
        std::uint32_t count =
          whole + ((HostHash(p.seed * 7919u + round * 104729u + 17u) >> 8) * (1.0 / 16777216.0) < fraction ? 1u : 0u);
        const std::uint32_t first = batch * kBatch;
        count = count > first ? std::min(kBatch, count - first) : 0u;
        if (count > 0) {
          dp.count = count;
          dp.roundNo = round;
          dp.idOffset = first;
          Bindings bi;
          bi.Srv(0, pits ? hs.R() : T.Src().R())
            .Srv(1, T.Src().R())
            .Srv(2, Or(accept, d0))
            .Srv(3, rockR)
            .Srv(4, Or(soft, d0));
          bi.Uav(0, *dq).Uav(1, wqR).Uav(2, pqR).Uav(3, fqR);
          const std::uint32_t rowsNeeded = (count + dp.gw - 1) / dp.gw;
          FAF_GPU_TRY(DispatchGrid(ex, *kDrop, dp.gw, rowsNeeded, dp, bi));
        }
        if (batch + 1 == batches) {
          // the end of the round: the integers into the floats, the steering surface follows, creep
          {
            Bindings bi;
            bi.Uav(0, T.Src().R())
              .Uav(1, *dq)
              .Uav(2, masks ? wearF.R() : *dev.dummy[4])
              .Uav(3, wqR)
              .Uav(4, masks ? depF.R() : *dev.dummy[5])
              .Uav(5, pqR)
              .Uav(6, masks ? flowF.R() : *dev.dummy[6])
              .Uav(7, fqR);
            FAF_GPU_TRY(DispatchGrid(ex, *kResolve, gp.w, gp.h, gp, bi));
          }
          if (creepPasses > 0.0f) {
            FAF_GPU_TRY(filter.Run(ex, T, t0, creepPasses, 1.0f, fac.rock.empty() ? nullptr : &rockR, false, d0));
          }
          if (pits) {
            Bindings bi;
            bi.Srv(0, tprev.R()).Srv(1, T.Src().R()).Uav(0, hs.R());
            FAF_GPU_TRY(DispatchGrid(ex, *kSteer, gp.w, gp.h, gp, bi));
          }
        }
        return {};
      }, &st);
      if (!ok)
        return std::unexpected(ok.error());

      // the cell noise filter (the CPU SmoothDelta: the change since the input, smoothed), then the thermal slides
      if (smoothOn) {
        const auto okFilter = RunIterations(ex, 1, 60.0, [&](u32) -> std::expected<void, std::string> {
          return filter.Run(
            ex, T, t0, static_cast<float>(smoothPasses), std::min(1.0f, smoothAmount), nullptr, false, d0
          );
        });
        if (!okFilter)
          return std::unexpected(okFilter.error());
      }
      if (thermalOn) {
        const hk::ErodeThermalParams tp =
          ThermalParams(w, h, src->cell, static_cast<float>(a.p.N("talus", 0.8)), thermal, !fac.thermal.empty(), 0);
        const auto okThermal =
          RunIterations(ex, static_cast<u32>(thermalSteps), 60.0, [&](u32) -> std::expected<void, std::string> {
          return tk.Step(ex, T, Or(thermalRate, d0), !fac.thermal.empty(), tp);
        });
        if (!okThermal)
          return std::unexpected(okThermal.error());
      }

      std::vector<float> height(static_cast<std::size_t>(n)), wear, deposit, flow;
      FAF_GPU_TRY(DownloadField(ex, T.Src(), height.data()));
      if (masks) {
        wear.resize(static_cast<std::size_t>(n));
        deposit.resize(static_cast<std::size_t>(n));
        flow.resize(static_cast<std::size_t>(n));
        FAF_GPU_TRY(DownloadField(ex, wearF, wear.data()));
        FAF_GPU_TRY(DownloadField(ex, depF, deposit.data()));
        FAF_GPU_TRY(DownloadField(ex, flowF, flow.data()));
      }
      Grid result;
      if (auto finished = ero::FinishDropletOp(a, *src, height, wear, deposit, flow, result); !finished) {
        return std::unexpected(finished.error());
      }
      out = std::move(result);
      return OpResult::Done;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("erode_hydraulic", &OpHydraulicGpu, kMinCells);
        RegisterGpuOp("erode_droplet", &OpDropletGpu, kMinCells);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
