// EDITOR GPU compute: GPU versions of the iterated stencil ops of the field engine that are not erosion solvers of
// their own: settle, thermal_map (EdFieldEro2.cpp). Each op reads its options exactly like the CPU op, answers
// Unsupported for what it does not handle (the CPU op then runs and reports bad input itself) and keeps the field on
// the device for all iterations (ping-pong buffers, RunIterations: time limited submissions), so only one upload and
// one download cross the bus. The arithmetic is the CPU op's, in the same order. docs/projects/editor/GPU_COMPUTE.md,
// "More field ops (GP4)".
#pragma fp_contract(off)

#include "editor/terrain/EdFieldUtil.h"
#include "editor/terrain/gpu/EdGpuFieldCommon.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/field_glacier_params.hlsli"
#include "editor/terrain/gpu/field_settle_params.hlsli"
#include "editor/terrain/gpu/field_slide_params.hlsli"
#include "editor/terrain/gpu/field_snowinit_params.hlsli"
#include "editor/terrain/gpu/field_weather_params.hlsli"
#include "editor/terrain/gpu/field_wind_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using namespace fops;

  namespace
  {
    // ---- settle
    // -------------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpSettleGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* mask = In(a, "mask");
      if (src == nullptr || (mask != nullptr && !mask->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "deposit")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 20);
      if (iterations == 0)
        return OpResult::Unsupported;
      if (!Fits(ex, src->Count(), 5))
        return OpResult::Unsupported;
      const KernelInfo* k = FindKernel("field_settle");
      if (k == nullptr) {
        return std::unexpected("kernel field_settle is missing");
      }
      hk::SettleParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      p.rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.4))));
      p.cap = std::max(0.0f, static_cast<float>(a.p.N("cap", 0.5)));
      p.slopeLo = static_cast<float>(a.p.N("slope_lo", 0.2));
      p.slopeHi = static_cast<float>(a.p.N("slope_hi", 0.6));
      p.cell = src->cell;
      PingPong pp;
      Field dep;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, pp.f[1]));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, dep));
      FAF_GPU_TRY(FillBuffer(ex, dep.R(), 0u));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      p.hasMask = mb.has ? 1u : 0u;
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        Bindings b;
        b.Srv(0, pp.Src().R()).Srv(1, mb.R()).Uav(0, pp.Dst().R()).Uav(1, dep.R());
        FAF_GPU_TRY(DispatchGrid(ex, *k, p.w, p.h, p, b));
        pp.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      std::map<std::string, Grid> all;
      all["height"] = Grid(src->w, src->h, src->cell, src->ox, src->oz);
      all["deposit"] = Grid(src->w, src->h, src->cell, src->ox, src->oz);
      FAF_GPU_TRY(DownloadGrid(ex, pp.Src(), all["height"]));
      if (want == "deposit" || a.extra != nullptr) {
        Grid sum(src->w, src->h, src->cell, src->ox, src->oz);
        FAF_GPU_TRY(DownloadGrid(ex, dep, sum));
        const float sc = std::max(1e-4f, static_cast<float>(a.p.N("deposit_scale", 1.0)));
        for (std::size_t i = 0; i < sum.v.size(); ++i)
          all["deposit"].v[i] = Clamp01(sum.v[i] / sc);
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- slides of a loose layer (thermal_map)
    // -------------------------------------------------------------------------------------------------------

    /**
     * The two passes of EdFieldEro2.cpp SlideT on the device. Buffers the op does not use are bound to a one element
     * dummy (every slot a kernel declares must be bound); the flags in the constant buffer keep the kernels away from
     * them.
     */
    struct Slider
    {
      const KernelInfo* ka = nullptr;
      const KernelInfo* kb = nullptr;
      hk::SlideParams p{};
      Field share, moved;
      std::unique_ptr<Resource> dummy, dummyW1,
        dummyW2; // one element stand-ins: a read-only one, and one per unused written slot (a resource is never both
                 // SRV and UAV of a dispatch)
      const Resource* rock = nullptr;
      const Resource* tmap = nullptr;
      const Resource* rmask = nullptr;
      const Resource* gain = nullptr;
      const Resource* lost = nullptr;

      std::expected<void, std::string> Init(
        Executor& ex,
        const int w,
        const int h
      )
      {
        ka = FindKernel("field_slide_a");
        kb = FindKernel("field_slide_b");
        if (ka == nullptr || kb == nullptr) {
          return std::unexpected("kernel field_slide_a / field_slide_b is missing");
        }
        p.w = static_cast<std::uint32_t>(w);
        p.h = static_cast<std::uint32_t>(h);
        const float zero = 0.0f;
        FAF_GPU_TRY(MakeField(ex, w, h, share));
        FAF_GPU_TRY(MakeField(ex, w, h, moved));
        FAF_GPU_TRY(MakeBuffer(ex, 1, dummy));
        FAF_GPU_TRY(UploadBuffer(ex, *dummy, &zero, 4));
        FAF_GPU_TRY(MakeBuffer(ex, 1, dummyW1));
        FAF_GPU_TRY(UploadBuffer(ex, *dummyW1, &zero, 4));
        FAF_GPU_TRY(MakeBuffer(ex, 1, dummyW2));
        return UploadBuffer(ex, *dummyW2, &zero, 4);
      }

      const Resource& Or(
        const Resource* r
      ) const
      {
        return r != nullptr ? *r : *dummy;
      }

      /** One slide step: `loose` -> `next`. */
      std::expected<void, std::string> Step(
        Executor& ex,
        const Resource& loose,
        Resource& next
      )
      {
        Bindings a;
        a.Srv(0, loose).Srv(1, Or(rock)).Srv(2, Or(tmap)).Srv(3, Or(rmask)).Uav(0, share.R()).Uav(1, moved.R());
        FAF_GPU_TRY(DispatchGrid(ex, *ka, p.w, p.h, p, a));
        Bindings b;
        b.Srv(0, loose)
          .Srv(1, Or(rock))
          .Srv(2, Or(tmap))
          .Srv(3, share.R())
          .Srv(4, moved.R())
          .Uav(0, next)
          .Uav(1, gain != nullptr ? *gain : *dummyW1)
          .Uav(2, lost != nullptr ? *lost : *dummyW2);
        return DispatchGrid(ex, *kb, p.w, p.h, p, b);
      }
    };

    std::expected<OpResult, std::string> OpThermalMapGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* tmap = In(a, "b");
      const Grid* mask = In(a, "mask");
      if (src == nullptr || (tmap != nullptr && !tmap->SameShape(*src)) || (mask != nullptr && !mask->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "scree" && want != "moved")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 30);
      if (iterations == 0)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      if (!Fits(ex, src->Count(), 10))
        return OpResult::Unsupported;
      Slider sl;
      FAF_GPU_TRY(sl.Init(ex, w, h));
      sl.p.cell = src->cell;
      sl.p.rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      sl.p.talus = static_cast<float>(a.p.N("talus", 0.6));
      const bool needSums = want != "height" || a.extra != nullptr;
      PingPong pp;
      Field tm, rm, gain, lost;
      FAF_GPU_TRY(UploadGrid(ex, *src, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, pp.f[1]));
      if (tmap != nullptr) {
        // the talus of each cell: lo + (hi - lo) * map, as the CPU op forms it
        const float lo = std::max(0.0f, static_cast<float>(a.p.N("talus_lo", 0.35))),
                    hi = std::max(0.0f, static_cast<float>(a.p.N("talus_hi", 1.0)));
        std::vector<float> talus(src->Count());
        for (std::size_t i = 0; i < talus.size(); ++i)
          talus[i] = lo + (hi - lo) * Clamp01(tmap->v[i]);
        FAF_GPU_TRY(MakeField(ex, w, h, tm));
        FAF_GPU_TRY(UploadField(ex, tm, talus.data()));
        sl.tmap = &tm.R();
        sl.p.hasMap = 1;
      }
      if (mask != nullptr) {
        FAF_GPU_TRY(UploadGrid(ex, *mask, rm));
        sl.rmask = &rm.R();
        sl.p.hasMask = 1;
      }
      if (needSums) {
        FAF_GPU_TRY(MakeField(ex, w, h, gain));
        FAF_GPU_TRY(MakeField(ex, w, h, lost));
        FAF_GPU_TRY(FillBuffer(ex, gain.R(), 0u));
        FAF_GPU_TRY(FillBuffer(ex, lost.R(), 0u));
        sl.gain = &gain.R();
        sl.lost = &lost.R();
        sl.p.hasGain = 1;
        sl.p.hasLost = 1;
      }
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        FAF_GPU_TRY(sl.Step(ex, pp.Src().R(), pp.Dst().R()));
        pp.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      std::map<std::string, Grid> all;
      all["height"] = Grid(w, h, src->cell, src->ox, src->oz);
      all["scree"] = Grid(w, h, src->cell, src->ox, src->oz);
      all["moved"] = Grid(w, h, src->cell, src->ox, src->oz);
      FAF_GPU_TRY(DownloadGrid(ex, pp.Src(), all["height"]));
      if (needSums) {
        Grid g(w, h, src->cell, src->ox, src->oz), l(w, h, src->cell, src->ox, src->oz);
        FAF_GPU_TRY(DownloadGrid(ex, gain, g));
        FAF_GPU_TRY(DownloadGrid(ex, lost, l));
        const float sc = std::max(1e-4f, static_cast<float>(a.p.N("scree_scale", 1.0)));
        for (std::size_t i = 0; i < g.v.size(); ++i) {
          all["scree"].v[i] = Clamp01(g.v[i] / sc);
          all["moved"].v[i] = Clamp01(l.v[i] / sc);
        }
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- thermal (EdFieldCore.cpp OpThermal: the same slides with one talus for the whole field)
    // ------------------------------------------------------

    std::expected<OpResult, std::string> OpThermalGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* mask = In(a, "mask");
      Shape shape;
      if (src == nullptr || (mask != nullptr && !mask->SameShape(*src)) || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const int iterations = std::max(0, std::min(100000, static_cast<int>(a.p.N("iterations", 20))));
      if (iterations == 0 || !Fits(ex, src->Count(), 6))
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      Slider sl;
      FAF_GPU_TRY(sl.Init(ex, w, h));
      sl.p.cell = src->cell;
      sl.p.rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      sl.p.talus = std::max(0.0f, static_cast<float>(a.p.N("talus", 0.6)));
      PingPong pp;
      Field rm;
      FAF_GPU_TRY(UploadGrid(ex, *src, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, pp.f[1]));
      if (mask != nullptr) {
        FAF_GPU_TRY(UploadGrid(ex, *mask, rm));
        sl.rmask = &rm.R();
        sl.p.hasMask = 1;
      }
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        FAF_GPU_TRY(sl.Step(ex, pp.Src().R(), pp.Dst().R()));
        pp.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, pp.Src(), g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- erode_rocksoil
    // -----------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpRockSoilGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* soil0 = In(a, "b");
      if (src == nullptr || (soil0 != nullptr && !soil0->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "soil" && want != "rock" && want != "moved")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 60);
      if (iterations == 0)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      if (!Fits(ex, n, 14))
        return OpResult::Unsupported;
      const KernelInfo* kw = FindKernel("field_weather");
      if (kw == nullptr) {
        return std::unexpected("kernel field_weather is missing");
      }
      const float weather = std::max(0.0f, static_cast<float>(a.p.N("weather", 0.01)));
      const float depth0 = std::max(1e-3f, static_cast<float>(a.p.N("depth0", 1.0)));
      const float soilTalus = std::max(0.0f, static_cast<float>(a.p.N("soil_talus", 0.35)));
      const float rockTalus = std::max(0.0f, static_cast<float>(a.p.N("rock_talus", 1.2)));
      const int rockEvery = std::max(1, static_cast<int>(a.p.N("rock_every", 4)));
      const float rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      const float vis = std::max(1e-3f, static_cast<float>(a.p.N("rock_vis", 0.4)));
      const float soilConst = static_cast<float>(a.p.N("soil", 0.8));
      std::vector<float> soilV(n), rockV(n);
      for (std::size_t i = 0; i < n; ++i) {
        soilV[i] = std::max(0.0f, soil0 != nullptr ? soil0->v[i] : soilConst);
        rockV[i] = src->v[i] - soilV[i];
      }
      PingPong soil, rock;
      Field lost;
      FAF_GPU_TRY(MakeField(ex, w, h, soil.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, soil.f[1]));
      FAF_GPU_TRY(MakeField(ex, w, h, rock.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, rock.f[1]));
      FAF_GPU_TRY(UploadField(ex, soil.f[0], soilV.data()));
      FAF_GPU_TRY(UploadField(ex, rock.f[0], rockV.data()));
      FAF_GPU_TRY(MakeField(ex, w, h, lost));
      FAF_GPU_TRY(FillBuffer(ex, lost.R(), 0u));
      Slider onSoil, onRock; // the soil slides over the rock (surface = rock + soil, capped by the soil), the rock as a
                             // layer of its own
      FAF_GPU_TRY(onSoil.Init(ex, w, h));
      FAF_GPU_TRY(onRock.Init(ex, w, h));
      onSoil.p.cell = onRock.p.cell = src->cell;
      onSoil.p.rate = onRock.p.rate = rate;
      onSoil.p.talus = soilTalus;
      onSoil.p.hasRock = 1;
      onSoil.p.hasLost = 1;
      onSoil.lost = &lost.R();
      onRock.p.talus = rockTalus;
      hk::WeatherParams wp{};
      wp.w = static_cast<std::uint32_t>(w);
      wp.h = static_cast<std::uint32_t>(h);
      wp.weather = weather;
      wp.depth0 = depth0;
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32 it) -> std::expected<void, std::string> {
        Bindings b;
        b.Uav(0, rock.Src().R()).Uav(1, soil.Src().R());
        FAF_GPU_TRY(DispatchGrid(ex, *kw, wp.w, wp.h, wp, b));
        onSoil.rock = &rock.Src().R();
        FAF_GPU_TRY(onSoil.Step(ex, soil.Src().R(), soil.Dst().R()));
        soil.Flip();
        if (rockTalus > 0.0f && (it % static_cast<u32>(rockEvery)) == static_cast<u32>(rockEvery) - 1u) {
          FAF_GPU_TRY(onRock.Step(ex, rock.Src().R(), rock.Dst().R()));
          rock.Flip();
        }
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid gSoil = LikeOf(*src), gRock = LikeOf(*src), gLost = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, soil.Src(), gSoil));
      FAF_GPU_TRY(DownloadGrid(ex, rock.Src(), gRock));
      FAF_GPU_TRY(DownloadGrid(ex, lost, gLost));
      std::map<std::string, Grid> all;
      all["height"] = LikeOf(*src);
      all["soil"] = LikeOf(*src);
      all["rock"] = LikeOf(*src);
      all["moved"] = LikeOf(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = gRock.v[i] + gSoil.v[i];
        all["soil"].v[i] = gSoil.v[i];
        all["rock"].v[i] = 1.0f - field::t7::SmoothStep(0.0f, vis, gSoil.v[i]);
        all["moved"].v[i] = Clamp01(gLost.v[i]);
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- erode_snow
    // ---------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpSnowGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* acc = In(a, "mask");
      if (src == nullptr || (acc != nullptr && !acc->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "snow" && want != "cover" && want != "moved")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 40);
      if (iterations == 0)
        return OpResult::Unsupported; // only the snow that falls: a point pass
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      if (!Fits(ex, n, 10))
        return OpResult::Unsupported;
      const KernelInfo* ki = FindKernel("field_snowinit");
      if (ki == nullptr) {
        return std::unexpected("kernel field_snowinit is missing");
      }
      const float line = static_cast<float>(a.p.N("snowline", 40.0));
      const float band = std::max(1e-3f, static_cast<float>(a.p.N("band", 10.0)));
      const float coverDepth = std::max(1e-3f, static_cast<float>(a.p.N("cover_depth", 0.5)));
      hk::SnowInitParams ip{};
      ip.w = static_cast<std::uint32_t>(w);
      ip.h = static_cast<std::uint32_t>(h);
      ip.cell = src->cell;
      ip.amount = std::max(0.0f, static_cast<float>(a.p.N("amount", 3.0)));
      ip.lineLo = line - band;
      ip.lineHi = line + band;
      ip.steepLo = static_cast<float>(a.p.N("steep_lo", 0.8));
      ip.steepHi = static_cast<float>(a.p.N("steep_hi", 1.4));
      Field ground, lost;
      PingPong snow;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, ground));
      FAF_GPU_TRY(MakeField(ex, w, h, snow.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, snow.f[1]));
      FAF_GPU_TRY(MakeField(ex, w, h, lost));
      FAF_GPU_TRY(FillBuffer(ex, lost.R(), 0u));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      ip.hasMask = mb.has ? 1u : 0u;
      Bindings bi;
      bi.Srv(0, ground.R()).Srv(1, mb.R()).Uav(0, snow.f[0].R());
      FAF_GPU_TRY(DispatchGrid(ex, *ki, ip.w, ip.h, ip, bi));
      Slider sl;
      FAF_GPU_TRY(sl.Init(ex, w, h));
      sl.p.cell = src->cell;
      sl.p.rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      sl.p.talus = std::max(0.0f, static_cast<float>(a.p.N("snow_talus", 0.9)));
      sl.p.hasRock = 1;
      sl.p.hasLost = 1;
      sl.rock = &ground.R();
      sl.lost = &lost.R();
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        FAF_GPU_TRY(sl.Step(ex, snow.Src().R(), snow.Dst().R()));
        snow.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid gSnow = LikeOf(*src), gLost = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, snow.Src(), gSnow));
      FAF_GPU_TRY(DownloadGrid(ex, lost, gLost));
      std::map<std::string, Grid> all;
      all["height"] = LikeOf(*src);
      all["snow"] = LikeOf(*src);
      all["cover"] = LikeOf(*src);
      all["moved"] = LikeOf(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = src->v[i] + gSnow.v[i];
        all["snow"].v[i] = gSnow.v[i];
        all["cover"].v[i] = field::t7::SmoothStep(0.0f, coverDepth, gSnow.v[i]);
        all["moved"].v[i] = Clamp01(gLost.v[i]);
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- erode_wind
    // ---------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpWindGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* sand0 = In(a, "b");
      if (src == nullptr || (sand0 != nullptr && !sand0->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "sand" && want != "abrasion")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 40);
      if (iterations == 0)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      if (!Fits(ex, n, 12))
        return OpResult::Unsupported;
      const KernelInfo* ka = FindKernel("field_wind_a");
      const KernelInfo* kb = FindKernel("field_wind_b");
      if (ka == nullptr || kb == nullptr) {
        return std::unexpected("kernel field_wind_a / field_wind_b is missing");
      }
      const double az = a.p.N("azimuth", 0.0) * field::t7::kPiD / 180.0;
      hk::WindParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.cell = src->cell;
      p.windx = static_cast<float>(std::cos(az));
      p.windz = static_cast<float>(std::sin(az));
      p.awx = std::fabs(p.windx);
      p.awz = std::fabs(p.windz);
      p.speed = std::max(0.0f, std::min(0.7f, static_cast<float>(a.p.N("speed", 0.5))));
      p.abrade = std::max(0.0f, static_cast<float>(a.p.N("abrade", 0.02)));
      p.drag = std::max(0.0f, static_cast<float>(a.p.N("drag", 1.5)));
      const float repose = std::max(0.05f, static_cast<float>(a.p.N("repose", 0.62)));
      const float sandConst = std::max(0.0f, static_cast<float>(a.p.N("sand", 0.5)));
      std::vector<float> sandV(n), rockV(n);
      for (std::size_t i = 0; i < n; ++i) {
        sandV[i] = std::max(0.0f, sand0 != nullptr ? sand0->v[i] : sandConst);
        rockV[i] = src->v[i] - sandV[i];
      }
      PingPong sand;
      Field rock, wear, take, vel;
      FAF_GPU_TRY(MakeField(ex, w, h, sand.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, sand.f[1]));
      FAF_GPU_TRY(MakeField(ex, w, h, rock));
      FAF_GPU_TRY(UploadField(ex, sand.f[0], sandV.data()));
      FAF_GPU_TRY(UploadField(ex, rock, rockV.data()));
      FAF_GPU_TRY(MakeField(ex, w, h, wear));
      FAF_GPU_TRY(FillBuffer(ex, wear.R(), 0u));
      FAF_GPU_TRY(MakeField(ex, w, h, take));
      FAF_GPU_TRY(MakeField(ex, w, h, vel));
      Slider sl; // the sand slides at the angle of repose on the rock, always at rate 0.5 (as the CPU op)
      FAF_GPU_TRY(sl.Init(ex, w, h));
      sl.p.cell = src->cell;
      sl.p.rate = 0.5f;
      sl.p.talus = repose;
      sl.p.hasRock = 1;
      sl.rock = &rock.R();
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32) -> std::expected<void, std::string> {
        Bindings ba;
        ba.Srv(0, rock.R()).Srv(1, sand.Src().R()).Uav(0, take.R()).Uav(1, vel.R());
        FAF_GPU_TRY(DispatchGrid(ex, *ka, p.w, p.h, p, ba));
        Bindings bb;
        bb.Srv(0, sand.Src().R())
          .Srv(1, take.R())
          .Srv(2, vel.R())
          .Uav(0, sand.Dst().R())
          .Uav(1, rock.R())
          .Uav(2, wear.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kb, p.w, p.h, p, bb));
        sand.Flip();
        FAF_GPU_TRY(sl.Step(ex, sand.Src().R(), sand.Dst().R()));
        sand.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid gSand = LikeOf(*src), gRock = LikeOf(*src), gWear = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, sand.Src(), gSand));
      FAF_GPU_TRY(DownloadGrid(ex, rock, gRock));
      FAF_GPU_TRY(DownloadGrid(ex, wear, gWear));
      std::map<std::string, Grid> all;
      all["height"] = LikeOf(*src);
      all["sand"] = LikeOf(*src);
      all["abrasion"] = LikeOf(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = gRock.v[i] + gSand.v[i];
        all["sand"].v[i] = gSand.v[i];
        all["abrasion"].v[i] = Clamp01(gWear.v[i]);
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    // ---- erode_glacier
    // ------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpGlacierGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* accMask = In(a, "b");
      if (src == nullptr || (accMask != nullptr && !accMask->SameShape(*src)))
        return OpResult::Unsupported;
      const std::string want = a.p.S("output", "height");
      if (want != "height" && want != "ice" && want != "cover" && want != "carve")
        return OpResult::Unsupported;
      const int iterations = ItersOf(a, 200, 5000);
      if (iterations == 0)
        return OpResult::Unsupported;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      if (!Fits(ex, n, 9))
        return OpResult::Unsupported;
      const KernelInfo* ka = FindKernel("field_glacier_a");
      const KernelInfo* kb = FindKernel("field_glacier_b");
      if (ka == nullptr || kb == nullptr) {
        return std::unexpected("kernel field_glacier_a / field_glacier_b is missing");
      }
      hk::GlacierParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.cell = src->cell;
      p.cc = p.cell * p.cell;
      p.ela = static_cast<float>(a.p.N("ela", 40.0));
      p.grad = std::max(0.0f, static_cast<float>(a.p.N("grad", 0.02)));
      p.accMax = std::max(0.0f, static_cast<float>(a.p.N("acc_max", 0.5)));
      p.ablMax = std::max(0.0f, static_cast<float>(a.p.N("abl_max", 1.0)));
      p.flow = std::max(0.0f, static_cast<float>(a.p.N("flow", 0.02)));
      p.maxIce = std::max(1.0f, static_cast<float>(a.p.N("max_ice", 120.0)));
      p.erode = std::max(0.0f, static_cast<float>(a.p.N("erode", 0.0005)));
      p.erodePow = std::max(0.5f, static_cast<float>(a.p.N("erode_pow", 1.5)));
      p.maxCut = std::max(0.0f, static_cast<float>(a.p.N("max_cut", 25.0)));
      p.dtMax = std::max(1e-4f, static_cast<float>(a.p.N("dt", 1.0)));
      p.powKind = p.erodePow == 1.0f ? 1u : (p.erodePow == 2.0f ? 2u : (p.erodePow == 1.5f ? 3u : 0u));
      p.hasAcc = accMask != nullptr ? 1u : 0u;
      Field bed, dif, gsl, cut, acc;
      PingPong ice;
      std::unique_ptr<Resource> dmaxA, dmaxB, dummy;
      const float zero = 0.0f;
      FAF_GPU_TRY(UploadGrid(ex, *src, bed));
      FAF_GPU_TRY(MakeField(ex, w, h, ice.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, ice.f[1]));
      FAF_GPU_TRY(FillBuffer(ex, ice.f[0].R(), 0u));
      FAF_GPU_TRY(MakeField(ex, w, h, dif));
      FAF_GPU_TRY(MakeField(ex, w, h, gsl));
      FAF_GPU_TRY(MakeField(ex, w, h, cut));
      FAF_GPU_TRY(FillBuffer(ex, cut.R(), 0u));
      FAF_GPU_TRY(MakeBuffer(ex, 1, dmaxA));
      FAF_GPU_TRY(MakeBuffer(ex, 1, dmaxB));
      FAF_GPU_TRY(FillBuffer(ex, *dmaxA, 0u));
      FAF_GPU_TRY(FillBuffer(ex, *dmaxB, 0u));
      FAF_GPU_TRY(MakeBuffer(ex, 1, dummy));
      FAF_GPU_TRY(UploadBuffer(ex, *dummy, &zero, 4));
      if (accMask != nullptr) {
        FAF_GPU_TRY(UploadGrid(ex, *accMask, acc));
      }
      const Resource& accR = accMask != nullptr ? acc.R() : *dummy;
      const auto ok =
        RunIterations(ex, static_cast<u32>(iterations), 60.0, [&](const u32 it) -> std::expected<void, std::string> {
        Resource& cur = (it & 1u) != 0u ? *dmaxB : *dmaxA;
        Resource& nxt = (it & 1u) != 0u ? *dmaxA : *dmaxB;
        Bindings ba;
        ba.Srv(0, bed.R()).Srv(1, ice.Src().R()).Uav(0, dif.R()).Uav(1, gsl.R()).Uav(2, cur).Uav(3, nxt);
        FAF_GPU_TRY(DispatchGrid(ex, *ka, p.w, p.h, p, ba));
        Bindings bb;
        bb.Srv(0, bed.R())
          .Srv(1, ice.Src().R())
          .Srv(2, dif.R())
          .Srv(3, gsl.R())
          .Srv(4, accR)
          .Srv(5, cur)
          .Uav(0, ice.Dst().R())
          .Uav(1, cut.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kb, p.w, p.h, p, bb));
        ice.Flip();
        return {};
      });
      if (!ok)
        return std::unexpected(ok.error());
      Grid gIce = LikeOf(*src), gCut = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, ice.Src(), gIce));
      FAF_GPU_TRY(DownloadGrid(ex, cut, gCut));
      std::map<std::string, Grid> all;
      all["height"] = LikeOf(*src);
      all["ice"] = LikeOf(*src);
      all["cover"] = LikeOf(*src);
      all["carve"] = LikeOf(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = src->v[i] - gCut.v[i];
        all["ice"].v[i] = gIce.v[i];
        all["cover"].v[i] = field::t7::SmoothStep(0.0f, 2.0f, gIce.v[i]);
        all["carve"].v[i] = gCut.v[i];
      }
      Grid result;
      if (!Emit(a, result, all, "height"))
        return OpResult::Unsupported;
      out = std::move(result);
      return OpResult::Done;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("thermal", &OpThermalGpu, 16384.0f);
        RegisterGpuOp("erode_glacier", &OpGlacierGpu, 16384.0f);
        RegisterGpuOp("erode_wind", &OpWindGpu, 16384.0f);
        RegisterGpuOp("erode_snow", &OpSnowGpu, 16384.0f);
        RegisterGpuOp("erode_rocksoil", &OpRockSoilGpu, 16384.0f);
        RegisterGpuOp("settle", &OpSettleGpu, 16384.0f);
        RegisterGpuOp("thermal_map", &OpThermalMapGpu, 16384.0f);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
