#pragma once

// FAF addition, not in the shipped binary.
//
// Building blocks of the Vulkan gal backend: error reporting, the DXGI to
// Vulkan format tables (the gal format tables are DXGI-based, shared with
// Direct3D 11 and 12), a device-memory sub-allocator, the upload allocator
// every CPU-to-GPU copy goes through, and images and buffers that remember
// their layout for barriers.

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include <dxgiformat.h>

#include "VulkanLoader.h"

namespace gpg::gal::vulkan
{
  /** Frames the CPU may record ahead of the GPU. */
  inline constexpr std::uint32_t kFramesInFlight = 3;

  [[nodiscard]] const char* ResultName(VkResult result) noexcept;

  /** Throws a gal Error naming the VkResult when `result` is an error. */
  void CheckVk(const char* file, int line, VkResult result);

  /** A texture format: the Vulkan format and the swizzle that gives D3D's channel meaning. */
  struct TextureFormat
  {
    VkFormat format = VK_FORMAT_UNDEFINED;
    VkComponentMapping swizzle{};
  };

  [[nodiscard]] TextureFormat ToVulkanTexture(DXGI_FORMAT format) noexcept;
  [[nodiscard]] VkFormat ToVulkanVertex(DXGI_FORMAT format) noexcept;
  [[nodiscard]] bool IsDepthFormat(VkFormat format) noexcept;
  [[nodiscard]] bool HasStencil(VkFormat format) noexcept;

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

  private:
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

  /** One upload-memory allocation: written by the CPU, read by the GPU once. */
  struct UploadAllocation
  {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceSize offset = 0;
    std::uint8_t* cpu = nullptr;
  };

  /**
   * Host-visible memory in pages, each one buffer usable as a transfer
   * source, vertex, index or uniform buffer. Allocations are tagged with the
   * submission that reads them; a page is reused once that one completed.
   */
  class UploadAllocator
  {
  public:
    void Initialize(MemoryAllocator& memory, VkDevice device);
    void Release() noexcept;

    [[nodiscard]] UploadAllocation Allocate(VkDeviceSize bytes, VkDeviceSize alignment, std::uint64_t serial);
    void Retire(std::uint64_t completedSerial) noexcept;
    [[nodiscard]] std::uint64_t TakeAllocatedBytes() noexcept;
    [[nodiscard]] std::uint64_t BusyBytes() const noexcept;

  private:
    struct Page
    {
      VkBuffer buffer = VK_NULL_HANDLE;
      Allocation memory;
      VkDeviceSize size = 0;
      VkDeviceSize used = 0;
      std::uint64_t lastSerial = 0;
      bool busy = false;
    };

    [[nodiscard]] Page* NewPage(VkDeviceSize size);
    void DestroyPage(Page& page) noexcept;

    MemoryAllocator* mMemory = nullptr;
    VkDevice mDevice = VK_NULL_HANDLE;
    std::vector<std::unique_ptr<Page>> mPages;
    Page* mCurrent = nullptr;
    std::uint64_t mAllocatedBytes = 0;
  };

  /** An image and the layout its last barrier left it in. */
  struct TrackedImage
  {
    VkImage image = VK_NULL_HANDLE;
    Allocation memory;
    VkFormat format = VK_FORMAT_UNDEFINED;
    VkImageAspectFlags aspect = VK_IMAGE_ASPECT_COLOR_BIT;
    VkImageLayout layout = VK_IMAGE_LAYOUT_UNDEFINED;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t depth = 1;
    std::uint32_t mipLevels = 1;
    std::uint32_t layers = 1;
    bool owned = true; // swap-chain images belong to the swap chain
  };

  struct TrackedBuffer
  {
    VkBuffer buffer = VK_NULL_HANDLE;
    Allocation memory;
    VkDeviceSize size = 0;
    bool written = false; // a transfer wrote it since the last draw-side barrier
  };
} // namespace gpg::gal::vulkan
