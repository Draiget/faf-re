#pragma once

// Engine addition, not in the shipped binary (see gpg/gal/PipelineDiskCache.h).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gpg/gal/backends/vulkan/VulkanLoader.h"

namespace gpg::gal::vulkan
{
  /**
   * The Vulkan side of `gPipelineDiskCache`: the device's VkPipelineCache starts from one file in the shader cache
   * directory, so the next session's pipelines come from it instead of the driver building each one again. The file
   * is written once the cache stops growing for `kQuietSeconds` (from `OnFrame`, on a background thread) and when the
   * device closes. A file from another device or driver, or a damaged one, is left out before the driver sees it.
   */
  class PipelineCacheFile
  {
  public:
    /** The saved data for the device `properties` describes, or nothing (another device, the cache off, no file). */
    [[nodiscard]] std::vector<std::uint8_t>
    Open(const VkPhysicalDeviceProperties& properties, const std::string& directory);

    /** Once a frame: writes the cache when it grew and then stayed the same for `kQuietSeconds`. */
    void OnFrame(VkDevice device, VkPipelineCache cache);

    /** Writes the cache if it changed, before the device destroys it. */
    void Close(VkDevice device, VkPipelineCache cache) noexcept;

  private:
    static constexpr std::chrono::seconds kCheckEvery{2};
    static constexpr std::chrono::seconds kQuietSeconds{5};

    void Save(VkDevice device, VkPipelineCache cache, bool inBackground) noexcept;

    std::string mPath; // empty: the cache isn't kept on disk
    std::size_t mSavedSize = 0U;
    std::size_t mLastSize = 0U;
    std::chrono::steady_clock::time_point mLastCheck{};
    std::chrono::steady_clock::time_point mLastGrowth{};
  };
} // namespace gpg::gal::vulkan
