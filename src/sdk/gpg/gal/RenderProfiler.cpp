// FAF instrumentation, not in the shipped binary (see RenderProfiler.h).

#include "RenderProfiler.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include <Windows.h>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"

namespace gpg::gal
{
  namespace
  {
    [[nodiscard]] std::int64_t NowTicks() noexcept
    {
      LARGE_INTEGER now{};
      ::QueryPerformanceCounter(&now);
      return now.QuadPart;
    }

    [[nodiscard]] double TicksToMilliseconds(const std::int64_t ticks) noexcept
    {
      static const double sFrequency = [] {
        LARGE_INTEGER frequency{};
        ::QueryPerformanceFrequency(&frequency);
        return static_cast<double>(frequency.QuadPart);
      }();
      return 1000.0 * static_cast<double>(ticks) / sFrequency;
    }
  } // namespace

  RenderProfiler& RenderProfiler::Get() noexcept
  {
    static RenderProfiler sProfiler;
    return sProfiler;
  }

  int RenderProfiler::ReadInterval() noexcept
  {
    char text[16] = {};
    std::size_t length = 0;
    if (::getenv_s(&length, text, sizeof(text), "FAF_GPU_PROFILE") != 0 || length == 0U) {
      return 0;
    }
    return std::max(0, std::atoi(text));
  }

  std::uint32_t RenderProfiler::Region(const char* const name) noexcept
  {
    for (std::uint32_t index = 0U; index < mRegionCount; ++index) {
      if (mRegions[index].name == name || std::strcmp(mRegions[index].name, name) == 0) {
        return index;
      }
    }
    if (mRegionCount == kMaxRegions) {
      return kMaxRegions - 1U;
    }
    mRegions[mRegionCount].name = name;
    return mRegionCount++;
  }

  const char* RenderProfiler::RegionName(const std::uint32_t region) const noexcept
  {
    return region < mRegionCount ? mRegions[region].name : "";
  }

  void RenderProfiler::BeginRegion(const std::uint32_t region) noexcept
  {
    RegionTotals& totals = mRegions[region];
    // A region re-entered from inside itself is timed once, outermost.
    if (totals.depth++ != 0U) {
      return;
    }
    ++totals.calls;
    totals.startTicks = NowTicks();
    totals.drawsAtStart = PendingDrawStatistics().drawCalls;
    totals.uploadAtStart = PendingDrawStatistics().uploadBytes;
    if (Device* const device = Device::GetInstance(); device != nullptr) {
      device->BeginProfileRegion(region);
    }
  }

  void RenderProfiler::EndRegion(const std::uint32_t region) noexcept
  {
    RegionTotals& totals = mRegions[region];
    if (totals.depth == 0U || --totals.depth != 0U) {
      return;
    }
    if (Device* const device = Device::GetInstance(); device != nullptr) {
      device->EndProfileRegion(region);
    }
    totals.cpuTicks += NowTicks() - totals.startTicks;
    // The tally restarts when a frame's statistics are taken; a region open
    // across that counts from zero.
    const DrawStatistics& pending = PendingDrawStatistics();
    totals.draws += pending.drawCalls >= totals.drawsAtStart ? pending.drawCalls - totals.drawsAtStart : pending.drawCalls;
    totals.uploadBytes +=
      pending.uploadBytes >= totals.uploadAtStart ? pending.uploadBytes - totals.uploadAtStart : pending.uploadBytes;
  }

  void RenderProfiler::AddGpuTime(const std::uint32_t region, const double milliseconds) noexcept
  {
    if (region < mRegionCount) {
      mRegions[region].gpuMilliseconds += milliseconds;
      ++mRegions[region].gpuSamples;
    }
  }

  void RenderProfiler::AddGpuPipelineStatistics(
    const std::uint32_t region, const std::uint64_t pixelInvocations, const std::uint64_t primitives
  ) noexcept
  {
    if (region < mRegionCount) {
      mRegions[region].pixels += pixelInvocations;
      mRegions[region].primitives += primitives;
      ++mRegions[region].statisticsSamples;
    }
  }

  bool RenderProfiler::PixelStatisticsEnabled() noexcept
  {
    static const bool sEnabled = [] {
      char text[8] = {};
      std::size_t length = 0;
      return ::getenv_s(&length, text, sizeof(text), "FAF_GPU_PROFILE_PIXELS") == 0 && length != 0U && text[0] == '1';
    }();
    return sEnabled;
  }

  void RenderProfiler::AddGpuFrameTime(const double milliseconds) noexcept
  {
    mGpuFrameMilliseconds += milliseconds;
    ++mGpuFrames;
  }

  void RenderProfiler::EndFrame(const DrawStatistics& frame) noexcept
  {
    const std::int64_t now = NowTicks();
    ++mSummary.frames;
    mSummary.lastFrame = frame;
    mSummary.lastFrameWallMilliseconds = mLastFrameEndTicks != 0 ? TicksToMilliseconds(now - mLastFrameEndTicks) : 0.0;
    mLastFrameEndTicks = now;
    if (!Enabled()) {
      return;
    }
    if (mFrames == 0U) {
      mIntervalStartTicks = NowTicks();
    }
    mUploadBytes += frame.uploadBytes;
    mStateChanges += frame.stateChanges;
    mDrawCalls += frame.drawCalls;
    static const int sInterval = ReadInterval();
    if (++mFrames < static_cast<std::uint32_t>(sInterval)) {
      return;
    }

    const double frames = static_cast<double>(mFrames);
    const double wallMilliseconds = TicksToMilliseconds(NowTicks() - mIntervalStartTicks);
    gpg::Logf(
      "Render profile over %u frames: %.2f ms/frame wall, GPU %.2f ms/frame, %.1f draws, %.1f state changes, %.1f KB uploaded per frame",
      mFrames, wallMilliseconds / frames, mGpuFrames != 0U ? mGpuFrameMilliseconds / static_cast<double>(mGpuFrames) : 0.0,
      static_cast<double>(mDrawCalls) / frames, static_cast<double>(mStateChanges) / frames,
      static_cast<double>(mUploadBytes) / frames / 1024.0
    );
    mSummary.intervalFrames = mFrames;
    mSummary.intervalGpuMilliseconds = mGpuFrames != 0U ? mGpuFrameMilliseconds / static_cast<double>(mGpuFrames) : 0.0;
    mSummary.intervalCpuMilliseconds = 0.0;
    for (std::uint32_t index = 0U; index < mRegionCount; ++index) {
      RegionTotals& totals = mRegions[index];
      if (std::strcmp(totals.name, "Frame") == 0) {
        mSummary.intervalCpuMilliseconds = TicksToMilliseconds(totals.cpuTicks) / frames;
      }
      if (totals.calls != 0U || totals.gpuSamples != 0U) {
        // GPU samples resolve a few frames late, so they are averaged over the
        // frames they cover: one sample set per call.
        const double gpuPerCall = totals.gpuSamples != 0U ? totals.gpuMilliseconds / totals.gpuSamples : 0.0;
        gpg::Logf(
          "  pass %-22s %6.2f calls  CPU %7.3f ms  GPU %7.3f ms per frame, %7.1f draws, %8.1f KB", totals.name,
          static_cast<double>(totals.calls) / frames, TicksToMilliseconds(totals.cpuTicks) / frames,
          gpuPerCall * static_cast<double>(totals.calls) / frames, static_cast<double>(totals.draws) / frames,
          static_cast<double>(totals.uploadBytes) / frames / 1024.0
        );
        if (totals.statisticsSamples != 0U) {
          // Averaged over the calls measured, then per frame like the GPU time.
          const double perCall = static_cast<double>(totals.calls) / frames / static_cast<double>(totals.statisticsSamples);
          gpg::Logf(
            "    pixels %-20s %10.3f Mpix  %10.1f kprims per frame", totals.name,
            static_cast<double>(totals.pixels) * perCall / 1.0e6, static_cast<double>(totals.primitives) * perCall / 1.0e3
          );
        }
      }
      totals.cpuTicks = 0;
      totals.calls = 0U;
      totals.gpuMilliseconds = 0.0;
      totals.gpuSamples = 0U;
      totals.draws = 0U;
      totals.uploadBytes = 0U;
      totals.pixels = 0U;
      totals.primitives = 0U;
      totals.statisticsSamples = 0U;
    }
    mFrames = 0U;
    mGpuFrameMilliseconds = 0.0;
    mGpuFrames = 0U;
    mUploadBytes = 0U;
    mStateChanges = 0U;
    mDrawCalls = 0U;
  }
} // namespace gpg::gal
