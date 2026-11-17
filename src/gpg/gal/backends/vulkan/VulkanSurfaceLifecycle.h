// FAF addition: when DeviceVulkan::TestCooperativeLevel lets go of a head's window surface and takes the next, and
// what it answers the engine, apart from the Vulkan calls that carry it out, so that
// tests/vulkan/SurfaceLifecycleTests.cpp checks it without a device or a window. A desktop window keeps its surface
// while the program runs; an Android activity's goes when the activity goes to the back, comes again when it is in
// front, and can change its size in place (VulkanSurface.h).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace gpg::gal::vulkan
{
  class SurfaceLifecycle
  {
  public:
    /** What an attempt to take a head's next surface and make its swap chain came to (DeviceVulkan::AttachSurface). */
    enum class Attach : std::uint8_t
    {
      Attached,  // the head has a surface and a swap chain again
      NoSurface, // the window has no surface to make one from (an Android activity in the back), or it went again
      NoArea,    // the window is minimised: its surface has no area, which no swap chain can be made for
      Refused,   // the window has a surface, and the surface or its swap chain was refused
    };

    /** What the device does after an attempt. */
    enum class Verdict : std::uint8_t
    {
      Continue, // nothing more: the next frame's TestCooperativeLevel tries again where the head has no surface
      Warn,     // log the refusal, the first of its run
      End,      // end the program: the surface has refused for kRefusalLimitMs
    };

    /**
     * How long a surface that is there may refuse before the program ends. It can be on its way out; one that
     * stays would leave a black window over a game that goes on, with nobody told.
     */
    static constexpr std::uint64_t kRefusalLimitMs = 5000U;

    /**
     * Whether a head lets go of the surface it has: it went (`lost`: an acquire, a present or a surface query
     * answered VK_ERROR_SURFACE_LOST_KHR, or the swap chain could not be made again for it), or the platform says
     * the window's surface is no longer the one it has (`current` false).
     */
    [[nodiscard]] static bool Releases(
      const bool lost,
      const bool current
    ) noexcept
    {
      return lost || !current;
    }

    /**
     * Whether the engine lays out anew after a head took its next surface: it draws into the swap chain's
     * images (not `scaled`, which keeps its own image and size), and they have another size than before.
     */
    [[nodiscard]] static bool NewSize(
      const bool scaled,
      const std::uint32_t oldWidth,
      const std::uint32_t oldHeight,
      const std::uint32_t newWidth,
      const std::uint32_t newHeight
    ) noexcept
    {
      return !scaled && (oldWidth != newWidth || oldHeight != newHeight);
    }

    /** For `heads` heads, each with its surface (Setup). */
    void SetHeadCount(
      const std::size_t heads
    )
    {
      mHeads.assign(heads, Head{});
      mNewSize = false;
    }

    /**
     * Records head `head`'s attempt to take its next surface, which came to `outcome` at `nowMs` (a steady clock's
     * milliseconds), with `newSize` as NewSize says. A surface that refuses warns once and ends the program once
     * it has refused for kRefusalLimitMs; any other outcome ends a run of refusals.
     */
    [[nodiscard]] Verdict Attempted(
      const std::size_t head,
      const Attach outcome,
      const bool newSize,
      const std::uint64_t nowMs
    )
    {
      if (head >= mHeads.size()) {
        mHeads.resize(head + 1U);
      }
      Head& state = mHeads[head];
      if (outcome != Attach::Refused) {
        state.refusing = false;
        mNewSize = mNewSize || (outcome == Attach::Attached && newSize);
        return Verdict::Continue;
      }
      if (!state.refusing) {
        state.refusing = true;
        state.refusingSince = nowMs;
        return Verdict::Warn;
      }
      return (nowMs - state.refusingSince > kRefusalLimitMs) ? Verdict::End : Verdict::Continue;
    }

    /**
     * TestCooperativeLevel's answer once every head without a surface was tried: 2 while one has none, as
     * Direct3D 9 answers when the display is taken from it, and Paint draws nothing; 1 once every head has one
     * and a head took a new size since the last answer (NewSize), for Paint's InitContext, which lays out anew;
     * else 0. A new size waits through answers of 2.
     */
    [[nodiscard]] int Answer(
      const bool everyHeadHasSurface
    ) noexcept
    {
      if (!everyHeadHasSurface) {
        return 2;
      }
      const bool newSize = mNewSize;
      mNewSize = false;
      return newSize ? 1 : 0;
    }

  private:
    struct Head
    {
      bool refusing = false;
      std::uint64_t refusingSince = 0U;
    };

    std::vector<Head> mHeads;
    bool mNewSize = false;
  };
} // namespace gpg::gal::vulkan
