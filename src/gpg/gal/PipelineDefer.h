#pragma once

// Engine addition, not in the shipped binary.
//
// `ren_AsyncPipelines`: a Direct3D 12 or Vulkan pipeline the driver hasn't built yet for a draw inside a
// PipelineDeferScope is built on a worker thread, and the draw is skipped until it is ready (a frame or two later),
// instead of the driver compiling it on the render thread. A compile there took 0.2-0.7 s when a unit type or a
// shader variant (ray-traced shadows turned on) first came into view, a visible freeze. Only the world's per-frame
// draws open the scope (meshes, the terrain and its decals): a draw that happens once (a thumbnail, a map bake)
// keeps building its pipeline in place, since skipping it would lose it.

namespace gpg::gal
{
  /** `ren_AsyncPipelines`: 1 (the default) builds missing mesh pipelines on worker threads, 0 in place. */
  inline bool gAsyncPipelines = true;

  /** Pipelines building at once at most; a draw that finds them all busy is skipped and asks again next frame. */
  inline constexpr unsigned kMaxPendingPipelines = 4U;

  /** How many PipelineDeferScope are open (render thread only). */
  inline int gPipelineDeferDepth = 0;

  /** While one is alive, draws on the render thread may wait for their pipeline. */
  struct PipelineDeferScope
  {
    PipelineDeferScope() noexcept
    {
      ++gPipelineDeferDepth;
    }
    ~PipelineDeferScope()
    {
      --gPipelineDeferDepth;
    }
    PipelineDeferScope(const PipelineDeferScope&) = delete;
    PipelineDeferScope& operator=(const PipelineDeferScope&) = delete;
  };

  [[nodiscard]] inline bool PipelinesMayDefer() noexcept
  {
    return gAsyncPipelines && gPipelineDeferDepth > 0;
  }
} // namespace gpg::gal
