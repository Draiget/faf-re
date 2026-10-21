#pragma once

// FAF instrumentation, not in the shipped binary.
//
// Per-pass render timings. With FAF_GPU_PROFILE=<frames> in the environment,
// every `RenderProfileScope` measures the CPU time of its pass on the render
// thread and asks the active backend to measure its GPU time
// (`Device::BeginProfileRegion` / `EndProfileRegion`; a backend without
// `kGpuFeatureTimestamps` reports none). Every <frames> frames one block of
// log lines gives, per pass, the calls, CPU ms and GPU ms per frame. Without
// the variable a scope costs one well-predicted branch.

#include <cstdint>

#include "gpg/gal/DrawStatistics.h"

namespace gpg::gal
{
  class RenderProfiler
  {
  public:
    static constexpr std::uint32_t kMaxRegions = 48U;

    /** True when FAF_GPU_PROFILE is set (read once). */
    [[nodiscard]] static bool Enabled() noexcept
    {
      static const bool sEnabled = ReadInterval() > 0;
      return sEnabled;
    }

    [[nodiscard]] static RenderProfiler& Get() noexcept;

    /** The region index for `name` (a string literal), registered on first use. */
    [[nodiscard]] std::uint32_t Region(const char* name) noexcept;
    [[nodiscard]] const char* RegionName(std::uint32_t region) const noexcept;

    void BeginRegion(std::uint32_t region) noexcept;
    void EndRegion(std::uint32_t region) noexcept;

    /** Backends report resolved GPU times here, possibly frames later. */
    void AddGpuTime(std::uint32_t region, double milliseconds) noexcept;
    /** GPU time of one whole frame (first command to Present), possibly frames later. */
    void AddGpuFrameTime(double milliseconds) noexcept;

    /** One frame ended: `frame` is its draw statistics. Logs every interval. */
    void EndFrame(const DrawStatistics& frame) noexcept;

    /**
     * What `ren_Info` shows. The last frame's draw statistics and wall time are
     * kept with or without FAF_GPU_PROFILE; the render CPU and GPU times exist
     * only with it, as averages over the last completed interval.
     */
    struct Summary
    {
      std::uint64_t frames = 0U;          // frames ended so far
      DrawStatistics lastFrame{};
      double lastFrameWallMilliseconds = 0.0;
      std::uint32_t intervalFrames = 0U;  // 0: no profiled interval yet
      double intervalCpuMilliseconds = 0.0; // the outermost pass ("Frame"), per frame
      double intervalGpuMilliseconds = 0.0; // whole frame, per frame
    };
    [[nodiscard]] const Summary& GetSummary() const noexcept { return mSummary; }

  private:
    [[nodiscard]] static int ReadInterval() noexcept;

    struct RegionTotals
    {
      const char* name = nullptr;
      std::int64_t startTicks = 0;
      std::int64_t cpuTicks = 0;
      std::uint32_t calls = 0U;
      std::uint32_t depth = 0U;
      double gpuMilliseconds = 0.0;
      std::uint32_t gpuSamples = 0U;
    };

    RegionTotals mRegions[kMaxRegions]{};
    std::uint32_t mRegionCount = 0U;
    std::uint32_t mFrames = 0U;
    double mGpuFrameMilliseconds = 0.0;
    std::uint32_t mGpuFrames = 0U;
    std::uint64_t mUploadBytes = 0U;
    std::uint64_t mStateChanges = 0U;
    std::uint64_t mDrawCalls = 0U;
    std::int64_t mIntervalStartTicks = 0;
    std::int64_t mLastFrameEndTicks = 0;
    Summary mSummary{};
  };

  /** Brackets one render pass (see `RenderProfiler`). `name` must be a string literal. */
  class RenderProfileScope
  {
  public:
    explicit RenderProfileScope(const char* const name) noexcept
    {
      if (RenderProfiler::Enabled()) {
        mRegion = RenderProfiler::Get().Region(name);
        RenderProfiler::Get().BeginRegion(mRegion);
      }
    }

    ~RenderProfileScope()
    {
      if (mRegion != kNoRegion) {
        RenderProfiler::Get().EndRegion(mRegion);
      }
    }

    RenderProfileScope(const RenderProfileScope&) = delete;
    RenderProfileScope& operator=(const RenderProfileScope&) = delete;

  private:
    static constexpr std::uint32_t kNoRegion = 0xFFFFFFFFU;
    std::uint32_t mRegion = kNoRegion;
  };
} // namespace gpg::gal
