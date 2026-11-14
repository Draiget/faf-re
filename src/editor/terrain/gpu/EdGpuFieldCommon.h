// EDITOR GPU compute: helpers shared by the field op files (EdGpuFieldIter.cpp, EdGpuFieldFilt.cpp). Internal: no other
// file includes it. docs/projects/editor/GPU_COMPUTE.md, "More field ops (GP4)".
#pragma once
#pragma fp_contract(off)

#include <map>

#include "editor/terrain/gpu/EdGpuGen.h"

namespace faf::editor::gpu::fops
{
  using namespace gen;

  inline float Clamp01(
    const float v
  )
  {
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
  }

  /** The `iterations` option the iterated CPU ops read (EdFieldEro2.cpp ItersOf). */
  inline int ItersOf(
    const OpArgs& a,
    const int fallback,
    const int cap = 20000
  )
  {
    return std::max(0, std::min(cap, static_cast<int>(a.p.N("iterations", fallback))));
  }

  /** Input `a` (null = the CPU op reports the error). A `like` of another size is the CPU op's error too. */
  inline const Grid* Source(
    const OpArgs& a
  )
  {
    const Grid* src = In(a, "a");
    if (src == nullptr || src->w < 1 || src->h < 1)
      return nullptr;
    if (const Grid* like = In(a, "like"); like != nullptr && !like->SameShape(*src))
      return nullptr;
    return src;
  }

  /** Like Source, and a `like` must also place the result exactly where `a` lies: ops whose CPU version takes the
   * placement of some results from `like` and of others from `a` leave the odd case to the CPU. */
  inline const Grid* SourceStrict(
    const OpArgs& a
  )
  {
    const Grid* src = Source(a);
    if (src == nullptr)
      return nullptr;
    if (
      const Grid* like = In(a, "like");
      like != nullptr && (like->cell != src->cell || like->ox != src->ox || like->oz != src->oz)
    )
      return nullptr;
    return src;
  }

  /** Puts the chosen result into `out` and the others into the extra outputs (EdFieldEro2.cpp Emit). false = unknown
   * output name (the CPU op reports it). */
  inline bool Emit(
    const OpArgs& a,
    Grid& out,
    std::map<std::string, Grid>& all,
    const char* const fallback
  )
  {
    const auto it = all.find(a.p.S("output", fallback));
    if (it == all.end())
      return false;
    const std::string want = it->first;
    for (auto& kv : all) {
      if (kv.first != want && a.extra != nullptr)
        (*a.extra)[kv.first] = std::move(kv.second);
    }
    out = std::move(it->second);
    return true;
  }

  /**
   * Ops with a few operations per sample do not pay for the transfer. `workPerCell` is the cost of one sample in "taps"
   * (one memory read and a compare or multiply add; calibrated on the CPU ops: about 0.4 ns per tap with 4 threads).
   * The GPU version runs when the work is at least kMinWork per sample (below that the bus costs more than the CPU does
   * the maths) and the whole op is worth about 10 ms of CPU time or more (cells * taps >= kTapsPerMinCell *
   * ed_gpu_min_cells = 25e6 at the default): a smaller job loses to the one time compile of the kernel and the fixed
   * cost of a submission. ed_gpu_min_cells 0 (the tests, and "everything on the GPU") skips both; the registered per op
   * minimum of samples applies on top (TryRun).
   */
  inline constexpr double kMinWork = 8.0;
  inline constexpr double kTapsPerMinCell = 380.0;
  inline bool WorthIt(
    const OpArgs& a,
    const double workPerCell
  )
  {
    const double minCells = static_cast<double>(GetPolicy().minCells);
    return minCells <= 0.0 || (workPerCell >= kMinWork && CellsOf(a) * workPerCell >= kTapsPerMinCell * minCells);
  }

  /** Ops of a few operations per sample (a 3 x 3 stencil) only go to the GPU on big fields: the transfer of input and
   * result costs more than the maths below that. 16 x ed_gpu_min_cells samples (default 1048576). */
  inline bool BigField(
    const OpArgs& a
  )
  {
    return CellsOf(a) >= static_cast<double>(GetPolicy().minCells) * 16.0;
  }

  /** Taps (reads and multiply adds) per sample of a Gaussian blur with this sigma (samples): two passes of 2r + 1. */
  inline double BlurTaps(
    const double sigma
  )
  {
    return 2.0 * (2.0 * std::max(1, static_cast<int>(std::ceil(3.0 * sigma))) + 1.0);
  }

  /** An output grid placed like the source. */
  inline Grid LikeOf(
    const Grid& g
  )
  {
    return Grid(g.w, g.h, g.cell, g.ox, g.oz);
  }

} // namespace faf::editor::gpu::fops
