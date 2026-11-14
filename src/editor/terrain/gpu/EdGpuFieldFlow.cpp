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
    bool FlowAccumulate(
      Executor& ex,
      const Field& hgt,
      Field& area,
      const int w,
      const int h,
      const bool d8,
      const float pf,
      std::string& err
    )
    {
      const KernelInfo* kprep = FindKernel(d8 ? "field_flowprep" : "field_wetprep");
      const KernelInfo* krank = FindKernel("field_wetrank");
      const KernelInfo* ksweep = FindKernel(d8 ? "field_flowsweep" : "field_wetsweep");
      if (kprep == nullptr || krank == nullptr || ksweep == nullptr) {
        err = "kernel field_wetprep / field_wetrank / field_wetsweep (field_flowprep / field_flowsweep) is missing";
        return false;
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
      if (
        !MakeField(ex, w, h, inv, err) || !MakeBuffer(ex, tiles * 1024u, order, err) ||
        !MakeBuffer(ex, 1, changed, err) || !MakeField(ex, w, h, pp.f[0], err) || !MakeField(ex, w, h, pp.f[1], err) ||
        !FillBuffer(ex, pp.f[0].R(), 0u, err)
      ) {
        return false;
      }
      {
        Bindings b;
        b.Srv(0, hgt.R()).Uav(0, inv.R());
        if (!DispatchGrid(ex, *kprep, p.w, p.h, p, b, err))
          return false;
      }
      {
        // the rank sort: 1M comparisons per tile, in bands of 512 tiles per submission
        constexpr std::uint32_t kBand = 512;
        const std::uint32_t bands = (tiles + kBand - 1) / kBand;
        Bindings b;
        b.Srv(0, hgt.R()).Uav(0, *order);
        const bool ok = RunIterations(ex, bands, 60.0, [&](const u32 bi, std::string& e) {
          hk::WetParams q = p;
          q.tile0 = bi * kBand;
          Groups g;
          g.x = std::min(kBand, tiles - q.tile0);
          return ex.Dispatch(*krank, g, &q, static_cast<u32>(sizeof(q)), b, e);
        }, err);
        if (!ok)
          return false;
      }
      // sweeps until nothing changes (batches of 6 between two looks at the flag)
      constexpr int kBatch = 6;
      constexpr int kMaxSweeps = 6000;
      bool converged = false;
      for (int done = 0; done < kMaxSweeps && !converged; done += kBatch) {
        if (!FillBuffer(ex, *changed, 0u, err))
          return false;
        for (int s = 0; s < kBatch; ++s) {
          Bindings b;
          b.Srv(0, hgt.R()).Srv(1, inv.R()).Srv(2, *order).Srv(3, pp.Src().R()).Uav(0, pp.Dst().R()).Uav(1, *changed);
          if (!DispatchGrid(ex, *ksweep, tiles, 1, p, b, err))
            return false;
          pp.Flip();
        }
        std::uint32_t flag = 1;
        if (!ex.Download(*changed, &flag, 4, err))
          return false;
        converged = flag == 0;
      }
      if (!converged) {
        err = "wetness: the flow accumulation did not settle";
        return false;
      }
      area = std::move(pp.Src());
      return true;
    }

    OpResult OpWetnessGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out,
      std::string& err
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
        err = "kernel field_wetfinal is missing";
        return OpResult::Failed;
      }
      const int w = src->w, h = src->h;
      const float pf = static_cast<float>(std::max(0.5, std::min(8.0, a.p.N("p", 1.1))));
      const double sm = a.p.N("smooth", 0.0) / static_cast<double>(src->cell);
      const bool smooth = sm > 0.05;
      if (smooth && !BlurAffordable(w, h, sm))
        return OpResult::Unsupported;
      Field hgt, area, twi, tmp, sg, res;
      if (!UploadGrid(ex, *src, hgt, err))
        return OpResult::Failed;
      if (!FlowAccumulate(ex, hgt, area, w, h, false, pf, err))
        return OpResult::Failed;
      hk::WetParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.cell = src->cell;
      p.lo = static_cast<float>(a.p.N("lo", 3.0));
      p.hi = static_cast<float>(a.p.N("hi", 11.0));
      p.mode = mode == "twi" ? 1u : (mode == "area" ? 2u : 0u);
      if (!MakeField(ex, w, h, twi, err) || !MakeField(ex, w, h, res, err))
        return OpResult::Failed;
      p.stage = 0;
      {
        Bindings b;
        b.Srv(0, hgt.R()).Srv(1, area.R()).Srv(2, hgt.R()).Uav(0, twi.R());
        if (!DispatchGrid(ex, *kfin, p.w, p.h, p, b, err))
          return OpResult::Failed;
      }
      const Field* t = &twi;
      if (smooth) {
        if (
          !MakeField(ex, w, h, tmp, err) || !MakeField(ex, w, h, sg, err) ||
          !BlurDevice(ex, twi.R(), tmp.R(), sg.R(), w, h, sm, err)
        )
          return OpResult::Failed;
        t = &sg;
      }
      p.stage = 1;
      {
        Bindings b;
        b.Srv(0, hgt.R()).Srv(1, area.R()).Srv(2, t->R()).Uav(0, res.R());
        if (!DispatchGrid(ex, *kfin, p.w, p.h, p, b, err))
          return OpResult::Failed;
      }
      Grid g = NewGrid(shape);
      if (!DownloadGrid(ex, res, g, err))
        return OpResult::Failed;
      out = std::move(g);
      return OpResult::Done;
    }

    OpResult OpFlowGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out,
      std::string& err
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
        err = "kernel field_flowfinal is missing";
        return OpResult::Failed;
      }
      const int w = src->w, h = src->h;
      Field hgt, cells, res;
      if (
        !UploadGrid(ex, *src, hgt, err) || !FlowAccumulate(ex, hgt, cells, w, h, true, 1.0f, err) ||
        !MakeField(ex, w, h, res, err)
      )
        return OpResult::Failed;
      hk::WetParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.mode = mode == "cells" ? 0u : (mode == "area" ? 1u : 2u);
      p.hi = src->cell * src->cell;
      const double range = std::max(2.0, a.p.N("range", 1.0e6));
      p.lo = static_cast<float>(1.0 / std::log(range));
      Bindings b;
      b.Srv(0, cells.R()).Uav(0, res.R());
      if (!DispatchGrid(ex, *kfin, p.w, p.h, p, b, err))
        return OpResult::Failed;
      Grid g = NewGrid(shape);
      if (!DownloadGrid(ex, res, g, err))
        return OpResult::Failed;
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
