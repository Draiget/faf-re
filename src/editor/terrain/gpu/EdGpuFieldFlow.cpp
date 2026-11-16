// EDITOR GPU compute: GPU versions of ops built on a flow accumulation (EdFieldFilt.cpp OpWetness). The CPU op sorts
// the cells by height and passes every cell's catchment to its lower neighbours in one sequential sweep; that order
// cannot be run in parallel directly. Here the field is cut into tiles of 32 x 32 samples: one thread per tile works
// through its cells in height order (a rank sort inside the tile, once), what flows between tiles is exchanged between
// sweeps, and the host sweeps until nothing changes (the fixed point is the CPU result: the flow graph has no cycles,
// so sweep n is exact for every cell whose upstream paths cross at most n - 1 tile borders).
// docs/projects/editor/GPU_COMPUTE.md, "More field ops (GP4)".
#pragma fp_contract(off)

#include "editor/terrain/EdFieldUtil.h"
#include "editor/terrain/gpu/EdGpuFieldCommon.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/field_wet_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using namespace fops;

  namespace
  {
    /**
     * Flow accumulation of heights `hgt` (device field, w x h): the catchment of every sample (1 + everything that
     * drains into it) in `area`. `d8` = every sample gives all it collected to its steepest lower neighbour (op flow),
     * else it shares it among all lower neighbours in proportion to (drop / distance)^pf (op wetness).
     */
    std::expected<void, std::string> FlowAccumulate(
      Executor& ex,
      const Field& hgt,
      Field& area,
      const int w,
      const int h,
      const bool d8,
      const float pf
    )
    {
      const KernelInfo* kprep = FindKernel(d8 ? "field_flowprep" : "field_wetprep");
      const KernelInfo* krank = FindKernel("field_wetrank");
      const KernelInfo* ksweep = FindKernel(d8 ? "field_flowsweep" : "field_wetsweep");
      if (kprep == nullptr || krank == nullptr || ksweep == nullptr) {
        return std::unexpected(
          "kernel field_wetprep / field_wetrank / field_wetsweep (field_flowprep / field_flowsweep) is missing"
        );
      }
      hk::WetParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.tilesX = static_cast<std::uint32_t>((w + 31) / 32);
      p.tilesZ = static_cast<std::uint32_t>((h + 31) / 32);
      p.pf = pf;
      const std::uint32_t tiles = p.tilesX * p.tilesZ;
      Field inv; // wetness: 1 / sum of the weights, flow: the target index (a 4 byte element either way)
      PingPong pp;
      std::unique_ptr<Resource> order, changed;
      FAF_GPU_TRY(MakeField(ex, w, h, inv));
      FAF_GPU_TRY(MakeBuffer(ex, tiles * 1024u, order));
      FAF_GPU_TRY(MakeBuffer(ex, 1, changed));
      FAF_GPU_TRY(MakeField(ex, w, h, pp.f[0]));
      FAF_GPU_TRY(MakeField(ex, w, h, pp.f[1]));
      FAF_GPU_TRY(FillBuffer(ex, pp.f[0].R(), 0u));
      {
        Bindings b;
        b.Srv(0, hgt.R()).Uav(0, inv.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kprep, p.w, p.h, p, b));
      }
      {
        // the rank sort: 1M comparisons per tile, in bands of 512 tiles per submission
        constexpr std::uint32_t kBand = 512;
        const std::uint32_t bands = (tiles + kBand - 1) / kBand;
        Bindings b;
        b.Srv(0, hgt.R()).Uav(0, *order);
        const auto ok = RunIterations(ex, bands, 60.0, [&](const u32 bi) -> std::expected<void, std::string> {
          hk::WetParams q = p;
          q.tile0 = bi * kBand;
          Groups g;
          g.x = std::min(kBand, tiles - q.tile0);
          return ex.Dispatch(*krank, g, &q, static_cast<u32>(sizeof(q)), b);
        });
        if (!ok)
          return std::unexpected(ok.error());
      }
      // sweeps until nothing changes (batches of 6 between two looks at the flag)
      constexpr int kBatch = 6;
      constexpr int kMaxSweeps = 6000;
      bool converged = false;
      for (int done = 0; done < kMaxSweeps && !converged; done += kBatch) {
        FAF_GPU_TRY(FillBuffer(ex, *changed, 0u));
        for (int s = 0; s < kBatch; ++s) {
          Bindings b;
          b.Srv(0, hgt.R()).Srv(1, inv.R()).Srv(2, *order).Srv(3, pp.Src().R()).Uav(0, pp.Dst().R()).Uav(1, *changed);
          FAF_GPU_TRY(DispatchGrid(ex, *ksweep, tiles, 1, p, b));
          pp.Flip();
        }
        std::uint32_t flag = 1;
        FAF_GPU_TRY(ex.Download(*changed, &flag, 4));
        converged = flag == 0;
      }
      if (!converged) {
        return std::unexpected("wetness: the flow accumulation did not settle");
      }
      area = std::move(pp.Src());
      return {};
    }

    std::expected<OpResult, std::string> OpWetnessGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      Shape shape;
      if (src == nullptr || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "wet");
      if (mode != "wet" && mode != "twi" && mode != "area")
        return OpResult::Unsupported; // the CPU op reports the bad mode
      // the CPU needs about 400 ns per sample (a sort and a sequential sweep with eight powers per sample): 1000 taps
      if (!WorthIt(a, 1000.0) || !Fits(ex, src->Count(), 10))
        return OpResult::Unsupported;
      const KernelInfo* kfin = FindKernel("field_wetfinal");
      if (kfin == nullptr) {
        return std::unexpected("kernel field_wetfinal is missing");
      }
      const int w = src->w, h = src->h;
      const float pf = static_cast<float>(std::max(0.5, std::min(8.0, a.p.N("p", 1.1))));
      const double sm = a.p.N("smooth", 0.0) / static_cast<double>(src->cell);
      const bool smooth = sm > 0.05;
      if (smooth && !BlurAffordable(w, h, sm))
        return OpResult::Unsupported;
      Field hgt, area, twi, tmp, sg, res;
      FAF_GPU_TRY(UploadGrid(ex, *src, hgt));
      FAF_GPU_TRY(FlowAccumulate(ex, hgt, area, w, h, false, pf));
      hk::WetParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.cell = src->cell;
      p.lo = static_cast<float>(a.p.N("lo", 3.0));
      p.hi = static_cast<float>(a.p.N("hi", 11.0));
      p.mode = mode == "twi" ? 1u : (mode == "area" ? 2u : 0u);
      FAF_GPU_TRY(MakeField(ex, w, h, twi));
      FAF_GPU_TRY(MakeField(ex, w, h, res));
      p.stage = 0;
      {
        Bindings b;
        b.Srv(0, hgt.R()).Srv(1, area.R()).Srv(2, hgt.R()).Uav(0, twi.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kfin, p.w, p.h, p, b));
      }
      const Field* t = &twi;
      if (smooth) {
        FAF_GPU_TRY(MakeField(ex, w, h, tmp));
        FAF_GPU_TRY(MakeField(ex, w, h, sg));
        FAF_GPU_TRY(BlurDevice(ex, twi.R(), tmp.R(), sg.R(), w, h, sm));
        t = &sg;
      }
      p.stage = 1;
      {
        Bindings b;
        b.Srv(0, hgt.R()).Srv(1, area.R()).Srv(2, t->R()).Uav(0, res.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kfin, p.w, p.h, p, b));
      }
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    std::expected<OpResult, std::string> OpFlowGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      Shape shape;
      if (src == nullptr || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "log");
      if (mode != "cells" && mode != "area" && mode != "log")
        return OpResult::Unsupported; // the CPU op reports the bad mode
      // the CPU needs about 190 ns per sample (a sort and a sequential pass): 500 taps
      if (!WorthIt(a, 500.0) || !Fits(ex, src->Count(), 6))
        return OpResult::Unsupported;
      const KernelInfo* kfin = FindKernel("field_flowfinal");
      if (kfin == nullptr) {
        return std::unexpected("kernel field_flowfinal is missing");
      }
      const int w = src->w, h = src->h;
      Field hgt, cells, res;
      FAF_GPU_TRY(UploadGrid(ex, *src, hgt));
      FAF_GPU_TRY(FlowAccumulate(ex, hgt, cells, w, h, true, 1.0f));
      FAF_GPU_TRY(MakeField(ex, w, h, res));
      hk::WetParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.mode = mode == "cells" ? 0u : (mode == "area" ? 1u : 2u);
      p.hi = src->cell * src->cell;
      const double range = std::max(2.0, a.p.N("range", 1.0e6));
      p.lo = static_cast<float>(1.0 / std::log(range));
      Bindings b;
      b.Srv(0, cells.R()).Uav(0, res.R());
      FAF_GPU_TRY(DispatchGrid(ex, *kfin, p.w, p.h, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("wetness", &OpWetnessGpu, 16384.0f);
        RegisterGpuOp("flow", &OpFlowGpu, 16384.0f);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
