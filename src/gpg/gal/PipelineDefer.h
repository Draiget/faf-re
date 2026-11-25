#pragma once

// Engine addition, not in the shipped binary.
//
// `ren_AsyncPipelines`: a Direct3D 12 or Vulkan pipeline the driver hasn't built yet for a draw inside a
// PipelineDeferScope is built on a worker thread, and the draw is skipped until it is ready (a frame or two later),
// instead of the driver compiling it on the render thread. A compile there took 0.2-0.7 s when a unit type or a
// shader variant (ray-traced shadows turned on) first came into view, a visible freeze. Only the world's per-frame
// draws open the scope (meshes, the terrain and its decals): a draw that happens once (a thumbnail, a map bake)
// keeps building its pipeline in place, since skipping it would lose it.
//
// The Vulkan backend tries a pipeline the driver refused for want of memory again later (PipelineRetries).

#include <chrono>
#include <future>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>

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

  /** What a worker's build that the driver refused throws into its future (TakeBuiltPipeline). */
  struct PipelineRefused
  {
    bool forNow = false; // for want of memory: tried again later (PipelineRetries)
  };

  /** How a build ended. */
  enum class PipelineBuildEnd
  {
    kBuilt,
    kRefusedForNow, // for want of memory (PipelineRefused::forNow, std::bad_alloc): it may build later
    kRefused,
  };

  /** Tries in all of a pipeline the driver refuses for want of memory, the last in place (PipelineRetries). */
  inline constexpr unsigned kPipelineTries = 6U;
  /** The wait before its second try; each later wait is twice the one before (0.5 s to 8 s, 15.5 s in all). */
  inline constexpr std::chrono::milliseconds kPipelineRetrySpacing{500};

  /**
   * The pipelines the driver refused for want of memory (out of host or device memory, which a moment later may be
   * there), by key. Each is tried kPipelineTries times in all, kPipelineRetrySpacing after its first refusal and then
   * twice as long each time, and its last try is made in place, so that it has an answer. A draw that needs one waits
   * meanwhile, as for a worker's build. Any other refusal, and the last try's, the backend keeps as a failure, whose
   * draws are skipped for the rest of the session. Render thread only.
   */
  class PipelineRetries
  {
  public:
    using Clock = std::chrono::steady_clock;

    enum class Turn
    {
      kFirst,   // never refused: built as any other
      kWaiting, // refused, and its next try is not due yet
      kAgain,   // refused, and its next try is due
      kLast,    // refused, and its last try is due: in place
    };

    [[nodiscard]] Turn TurnOf(
      const std::string& key,
      const Clock::time_point now
    ) const
    {
      const auto entry = mEntries.find(key);
      if (entry == mEntries.end()) {
        return Turn::kFirst;
      }
      if (now < entry->second.next) {
        return Turn::kWaiting;
      }
      return entry->second.refusals + 1U >= kPipelineTries ? Turn::kLast : Turn::kAgain;
    }

    /**
     * A try of `key` refused for want of memory at `now`: true when another try follows, false after the last one,
     * which forgets the key.
     */
    bool Refused(
      const std::string& key,
      const Clock::time_point now
    )
    {
      Entry& entry = mEntries[key];
      ++entry.refusals;
      if (entry.refusals >= kPipelineTries) {
        mEntries.erase(key);
        return false;
      }
      entry.next = now + Spacing(entry.refusals);
      return true;
    }

    /** `key` built, or failed for good. */
    void Forget(
      const std::string& key
    )
    {
      mEntries.erase(key);
    }

    /** The device's pipelines went, and their keys with them. */
    void Clear() noexcept
    {
      mEntries.clear();
    }

    /** The wait after a pipeline's `refusals`-th refusal (1 the first). */
    [[nodiscard]] static Clock::duration Spacing(
      const unsigned refusals
    ) noexcept
    {
      return kPipelineRetrySpacing * (1U << (refusals - 1U));
    }

  private:
    struct Entry
    {
      unsigned refusals = 0U;
      Clock::time_point next{};
    };
    std::unordered_map<std::string, Entry> mEntries;
  };

  /**
   * A finished build's pipeline; a null one when the build threw, so a worker's exception never reaches the draw that
   * takes it. `end`, where given, says how it ended: a refusal for want of memory, or a build that ran out of memory
   * itself (std::bad_alloc), may build later; anything else that threw is a failure, like one the driver refused.
   */
  template <class Handle>
  [[nodiscard]] Handle TakeBuiltPipeline(
    std::future<Handle>& build,
    PipelineBuildEnd* const end = nullptr
  ) noexcept
  {
    PipelineBuildEnd how = PipelineBuildEnd::kRefused;
    Handle built{};
    try {
      built = build.get();
      how = PipelineBuildEnd::kBuilt;
    } catch (const PipelineRefused& refused) {
      how = refused.forNow ? PipelineBuildEnd::kRefusedForNow : PipelineBuildEnd::kRefused;
    } catch (const std::bad_alloc&) {
      how = PipelineBuildEnd::kRefusedForNow;
    } catch (...) {}
    if (end != nullptr) {
      *end = how;
    }
    return built;
  }

  /**
   * Hands every finished build in `pending` to `settle(key, pipeline, end)` and drops it from `pending`. A build stays
   * in `pending` until a draw asks for its key again, and one asked for once (an effect seen for a moment, a variant
   * switched off again) would otherwise hold one of the kMaxPendingPipelines slots for the rest of the session.
   */
  template <class Handle, class Settle>
  void SettleFinishedPipelines(
    std::unordered_map<std::string, std::future<Handle>>& pending,
    Settle&& settle
  )
  {
    for (auto entry = pending.begin(); entry != pending.end();) {
      if (entry->second.valid() && entry->second.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        ++entry;
        continue;
      }
      if (entry->second.valid()) {
        PipelineBuildEnd end = PipelineBuildEnd::kRefused;
        Handle built = TakeBuiltPipeline(entry->second, &end);
        settle(entry->first, std::move(built), end);
      }
      entry = pending.erase(entry);
    }
  }

  /** Moves every finished build from `pending` into `built`, a failure as a null pipeline (SettleFinishedPipelines). */
  template <class Handle>
  void CollectFinishedPipelines(
    std::unordered_map<std::string, std::future<Handle>>& pending,
    std::unordered_map<std::string, Handle>& built
  )
  {
    SettleFinishedPipelines(pending, [&built](const std::string& key, Handle pipeline, PipelineBuildEnd) {
      built.emplace(key, std::move(pipeline));
    });
  }
} // namespace gpg::gal
