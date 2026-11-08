#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace moho
{
  // Render/UI-thread diagnostics, separate from the recovered object layouts.
  // Like the pools themselves, this is not a concurrent-access interface.
  struct ParticlePoolSessionStats
  {
    std::size_t particleBuffersPeak = 0;
    std::size_t trailBuffersPeak = 0;
    std::size_t particleBuffersCapacity = 0;
    std::size_t trailBuffersCapacity = 0;
    std::uint64_t particlesPoolDropped = 0;
    std::uint64_t trailSegmentsPoolDropped = 0;
    std::uint64_t pendingParticlesUploadDiscarded = 0;
    std::uint64_t pendingTrailSegmentsUploadDiscarded = 0;
    bool saturated = false;
  };

  class ParticlePoolStats
  {
  public:
    void BeginSession() noexcept
    {
      if (active_) {
        return;
      }
      session_ = {};
      session_.particleBuffersCapacity = particleCapacity_;
      session_.trailBuffersCapacity = trailCapacity_;
      active_ = true;
    }

    [[nodiscard]] std::optional<ParticlePoolSessionStats> EndSession() noexcept
    {
      if (!active_) {
        return std::nullopt;
      }
      // Close before logging: a repeated teardown, or a logging failure, must
      // not publish the same session twice.
      active_ = false;
      return session_;
    }

    void SetParticleCapacity(const std::size_t capacity) noexcept
    {
      particleCapacity_ = capacity;
      if (active_) {
        session_.particleBuffersCapacity = std::max(session_.particleBuffersCapacity, capacity);
      }
    }

    void AddTrailBuffer() noexcept
    {
      ++trailCapacity_;
      if (active_) {
        session_.trailBuffersCapacity = std::max(session_.trailBuffersCapacity, trailCapacity_);
      }
    }

    void PoolsDestroyed() noexcept
    {
      particleCapacity_ = 0;
      trailCapacity_ = 0;
      // Resource lifetime is not session lifetime. Preserve the current
      // session's high-water marks and losses until its explicit end.
    }

    void ObserveParticleAcquire(const std::size_t total, const std::size_t available) noexcept
    {
      SetParticleCapacity(total);
      if (active_ && available <= total) {
        session_.particleBuffersPeak = std::max(session_.particleBuffersPeak, total - available);
      }
    }

    void ObserveTrailAcquire(const std::size_t available) noexcept
    {
      if (active_ && available <= trailCapacity_) {
        session_.trailBuffersPeak = std::max(session_.trailBuffersPeak, trailCapacity_ - available);
      }
    }

    void DropParticles(const std::size_t count) noexcept { Add(session_.particlesPoolDropped, count); }
    void DropTrailSegments(const std::size_t count) noexcept { Add(session_.trailSegmentsPoolDropped, count); }
    void DiscardPendingParticleUpload(const std::size_t count) noexcept
    {
      Add(session_.pendingParticlesUploadDiscarded, count);
    }
    void DiscardPendingTrailUpload(const std::size_t count) noexcept
    {
      Add(session_.pendingTrailSegmentsUploadDiscarded, count);
    }

  private:
    void Add(std::uint64_t& value, const std::size_t count) noexcept
    {
      if (!active_) {
        return;
      }
      constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
      if (count > maximum - value) {
        value = maximum;
        session_.saturated = true;
      } else {
        value += count;
      }
    }

    ParticlePoolSessionStats session_;
    std::size_t particleCapacity_ = 0;
    std::size_t trailCapacity_ = 0;
    bool active_ = false;
  };

  inline ParticlePoolStats particlePoolStats;

  // Called only at world-session boundaries, not on replay seek, bucket clear
  // or device reset. Emits at most one bounded summary for each begun session.
  void EndParticlePoolStatsSession() noexcept;
} // namespace moho
