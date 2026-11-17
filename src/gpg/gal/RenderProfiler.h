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
//
// Work outside the render passes (UI script, input, garbage collection) uses
// `CpuProfileScope`: CPU time only, reported with its time per call and its
// slowest call, so a one-off hitch such as a selection change shows beside the
// per-frame average. `FAF_PROFILE_COUNT` adds to a named counter reported per
// frame. Both run on the main thread, where the render passes run too.

#include <cstdint>
#include <vector>

#include "gpg/gal/DrawStatistics.h"

namespace gpg::gal
{
  class RenderProfiler
  {
  public:
    static constexpr std::uint32_t kMaxRegions = 64U;
    static constexpr std::uint32_t kMaxCounters = 32U;
    static constexpr std::uint32_t kMaxReportHooks = 4U;

    /** True when FAF_GPU_PROFILE is set (read once). */
    [[nodiscard]] static bool Enabled() noexcept
    {
      static const bool sEnabled = ReadInterval() > 0;
      return sEnabled;
    }

    [[nodiscard]] static RenderProfiler& Get() noexcept;

    /** The profiler's clock, for callers that keep their own totals (see `AddReportHook`). */
    [[nodiscard]] static std::int64_t NowTicks() noexcept;
    [[nodiscard]] static double TicksToMilliseconds(std::int64_t ticks) noexcept;

    /** The region index for `name` (a string literal), registered on first use. */
    [[nodiscard]] std::uint32_t Region(const char* name) noexcept;

    /**
     * `measureGpu` false: CPU time only, for work outside the render passes. Such a
     * region is logged as `cpu` with its time per call and its slowest call.
     */
    void BeginRegion(std::uint32_t region, bool measureGpu = true) noexcept;
    void EndRegion(std::uint32_t region, bool measureGpu = true) noexcept;

    /** The counter index for `name` (a string literal), registered on first use. */
    [[nodiscard]] std::uint32_t Counter(const char* name) noexcept;
    /** Adds to a counter; the log gives each counter's total per frame. */
    void AddCount(
      const std::uint32_t counter,
      const std::uint64_t amount
    ) noexcept
    {
      mCounters[counter].total += amount;
    }

    /**
     * Called at the end of every profile block with the block's frame count, to log
     * totals kept elsewhere and reset them.
     */
    using ReportHook = void (*)(double frames);
    void AddReportHook(ReportHook hook) noexcept;

    /** Backends report resolved GPU times here, possibly frames later. */
    void AddGpuTime(std::uint32_t region, double milliseconds) noexcept;
    /**
     * Pixel-shader invocations and rasterised primitives of one region call
     * (FAF_GPU_PROFILE_PIXELS=1 and a backend that measures them).
     */
    void
    AddGpuPipelineStatistics(std::uint32_t region, std::uint64_t pixelInvocations, std::uint64_t primitives) noexcept;
    /** FAF_GPU_PROFILE_PIXELS=1: backends also count pixels and primitives per region (read once). */
    [[nodiscard]] static bool PixelStatisticsEnabled() noexcept;
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
      std::uint64_t frames = 0U; // frames ended so far
      DrawStatistics lastFrame{};
      double lastFrameWallMilliseconds = 0.0;
      std::uint32_t intervalFrames = 0U;    // 0: no profiled interval yet
      double intervalCpuMilliseconds = 0.0; // the outermost pass ("Frame"), per frame
      double intervalGpuMilliseconds = 0.0; // whole frame, per frame
    };
    [[nodiscard]] const Summary& GetSummary() const noexcept
    {
      return mSummary;
    }

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
      // Draw calls and upload bytes submitted inside the region (outermost call only).
      std::uint32_t drawsAtStart = 0U;
      std::uint64_t uploadAtStart = 0U;
      std::uint64_t draws = 0U;
      std::uint64_t uploadBytes = 0U;
      std::uint64_t pixels = 0U;
      std::uint64_t primitives = 0U;
      std::uint32_t statisticsSamples = 0U;
      // CPU-only regions (CpuProfileScope): the slowest call of the interval.
      bool cpuOnly = false;
      std::int64_t maxCallTicks = 0;
    };

    struct CounterTotals
    {
      const char* name = nullptr;
      std::uint64_t total = 0U;
    };

    RegionTotals mRegions[kMaxRegions]{};
    std::uint32_t mRegionCount = 0U;
    CounterTotals mCounters[kMaxCounters]{};
    std::uint32_t mCounterCount = 0U;
    ReportHook mReportHooks[kMaxReportHooks]{};
    std::uint32_t mReportHookCount = 0U;
    std::uint32_t mFrames = 0U;
    double mGpuFrameMilliseconds = 0.0;
    std::uint32_t mGpuFrames = 0U;
    std::uint64_t mUploadBytes = 0U;
    std::uint64_t mStateChanges = 0U;
    std::uint64_t mDrawCalls = 0U;
    std::int64_t mIntervalStartTicks = 0;
    std::int64_t mLastFrameEndTicks = 0;
    std::vector<float> mFrameWalls; // this interval's frame times (wall, ms), for the spike line

    Summary mSummary{};
  };

  /** Brackets one render pass (see `RenderProfiler`). `name` must be a string literal. */
  class RenderProfileScope
  {
  public:
    explicit RenderProfileScope(
      const char* const name
    ) noexcept
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

  /**
   * Brackets CPU work outside the render passes (UI script, input, garbage
   * collection): CPU time only, logged with its time per call and its slowest
   * call. `name` must be a string literal. Main thread only.
   */
  class CpuProfileScope
  {
  public:
    explicit CpuProfileScope(
      const char* const name
    ) noexcept
    {
      if (RenderProfiler::Enabled()) {
        mRegion = RenderProfiler::Get().Region(name);
        RenderProfiler::Get().BeginRegion(mRegion, false);
      }
    }

    ~CpuProfileScope()
    {
      if (mRegion != kNoRegion) {
        RenderProfiler::Get().EndRegion(mRegion, false);
      }
    }

    CpuProfileScope(const CpuProfileScope&) = delete;
    CpuProfileScope& operator=(const CpuProfileScope&) = delete;

  private:
    static constexpr std::uint32_t kNoRegion = 0xFFFFFFFFU;
    std::uint32_t mRegion = kNoRegion;
  };
} // namespace gpg::gal

/**
 * Adds `amount` to the profiler counter `name` (a string literal) when
 * FAF_GPU_PROFILE is set; one well-predicted branch otherwise. Main thread only.
 */
#define FAF_PROFILE_COUNT(name, amount)                                                                                \
  do {                                                                                                                 \
    if (::gpg::gal::RenderProfiler::Enabled()) {                                                                       \
      static const std::uint32_t sFafProfileCounter = ::gpg::gal::RenderProfiler::Get().Counter(name);                 \
      ::gpg::gal::RenderProfiler::Get().AddCount(sFafProfileCounter, static_cast<std::uint64_t>(amount));              \
    }                                                                                                                  \
  } while (false)
