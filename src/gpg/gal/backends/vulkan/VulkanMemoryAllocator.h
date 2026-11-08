#pragma once

// FAF addition: device-memory sub-allocation, independent of texture formats.
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#ifndef VK_NO_PROTOTYPES
#define VK_NO_PROTOTYPES
#endif
#include <vulkan/vulkan.h>

namespace gpg::gal::vulkan
{
  /** One sub-allocation of device memory. */
  struct Allocation
  {
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize offset = 0;
    VkDeviceSize size = 0;
    std::uint8_t* mapped = nullptr; // host-visible memory only
    std::int32_t block = -1;
    bool linear = false;            // buffers and images live in separate blocks (bufferImageGranularity)
  };

  /** Device memory in large blocks per memory type, first fit, with coalescing frees. */
  class MemoryAllocator
  {
  public:
    void Initialize(VkPhysicalDevice physicalDevice, VkDevice device);
    void Release() noexcept;

    /** Throws a gal Error when no memory type fits or the device is out of memory. */
    [[nodiscard]] Allocation Allocate(const VkMemoryRequirements& requirements, VkMemoryPropertyFlags required, bool linear);
    void Free(const Allocation& allocation) noexcept;
    /** Bytes in device memory blocks (memory diagnostics). */
    [[nodiscard]] std::uint64_t BlockBytes() const noexcept;

  private:
    friend struct MemoryAllocatorTestAccess;

    struct Block
    {
      VkDeviceMemory memory = VK_NULL_HANDLE;
      VkDeviceSize size = 0;
      std::uint32_t type = 0;
      bool linear = false;
      std::uint8_t* mapped = nullptr;
      std::map<VkDeviceSize, VkDeviceSize> free; // offset -> size
    };

    [[nodiscard]] std::uint32_t FindType(std::uint32_t typeBits, VkMemoryPropertyFlags required) const;

    VkDevice mDevice = VK_NULL_HANDLE;
    VkPhysicalDeviceMemoryProperties mProperties{};
    std::vector<std::unique_ptr<Block>> mBlocks;
  };

} // namespace gpg::gal::vulkan
