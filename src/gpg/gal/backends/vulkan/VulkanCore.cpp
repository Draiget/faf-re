// FAF addition, not in the shipped binary: see VulkanCore.h.

#include "VulkanCore.h"

#include <algorithm>
#include <cstdio>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/PlacedResources.h"

namespace gpg::gal::vulkan
{
  const char* ResultName(const VkResult result) noexcept
  {
    switch (result) {
    case VK_SUCCESS:
      return "VK_SUCCESS";
    case VK_NOT_READY:
      return "VK_NOT_READY";
    case VK_TIMEOUT:
      return "VK_TIMEOUT";
    case VK_SUBOPTIMAL_KHR:
      return "VK_SUBOPTIMAL_KHR";
    case VK_ERROR_OUT_OF_HOST_MEMORY:
      return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:
      return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_INITIALIZATION_FAILED:
      return "VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_DEVICE_LOST:
      return "VK_ERROR_DEVICE_LOST";
    case VK_ERROR_MEMORY_MAP_FAILED:
      return "VK_ERROR_MEMORY_MAP_FAILED";
    case VK_ERROR_LAYER_NOT_PRESENT:
      return "VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_EXTENSION_NOT_PRESENT:
      return "VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_FEATURE_NOT_PRESENT:
      return "VK_ERROR_FEATURE_NOT_PRESENT";
    case VK_ERROR_INCOMPATIBLE_DRIVER:
      return "VK_ERROR_INCOMPATIBLE_DRIVER";
    case VK_ERROR_FORMAT_NOT_SUPPORTED:
      return "VK_ERROR_FORMAT_NOT_SUPPORTED";
    case VK_ERROR_SURFACE_LOST_KHR:
      return "VK_ERROR_SURFACE_LOST_KHR";
    case VK_ERROR_NATIVE_WINDOW_IN_USE_KHR:
      return "VK_ERROR_NATIVE_WINDOW_IN_USE_KHR";
    case VK_ERROR_OUT_OF_DATE_KHR:
      return "VK_ERROR_OUT_OF_DATE_KHR";
    default:
      return "VkResult";
    }
  }

  void CheckVk(const char* const file, const int line, const VkResult result)
  {
    if (result >= 0) {
      return;
    }
    char message[128]{};
    std::snprintf(message, sizeof(message), "%s (%d)", ResultName(result), static_cast<int>(result));
    if (result == VK_ERROR_DEVICE_LOST || result == VK_ERROR_OUT_OF_DEVICE_MEMORY || result == VK_ERROR_OUT_OF_HOST_MEMORY) {
      // Logged here, before the throw: whatever catches it may not get to write anything.
      gpg::Warnf("Vulkan: %s at %s(%d)", message, (file != nullptr) ? file : "?", line);
    }
    backend::ThrowError(file, line, message);
  }

  namespace
  {
    constexpr VkComponentMapping kIdentity{
      VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY,
    };
  } // namespace

  TextureFormat ToVulkanTexture(const DXGI_FORMAT format) noexcept
  {
    TextureFormat result{VK_FORMAT_UNDEFINED, kIdentity};
    switch (format) {
    case DXGI_FORMAT_B8G8R8A8_UNORM:
    case DXGI_FORMAT_B8G8R8A8_TYPELESS:
      result.format = VK_FORMAT_B8G8R8A8_UNORM;
      break;
    case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
      result.format = VK_FORMAT_B8G8R8A8_SRGB;
      break;
    case DXGI_FORMAT_B8G8R8X8_UNORM:
    case DXGI_FORMAT_B8G8R8X8_TYPELESS:
      result.format = VK_FORMAT_B8G8R8A8_UNORM;
      result.swizzle.a = VK_COMPONENT_SWIZZLE_ONE;
      break;
    case DXGI_FORMAT_B8G8R8X8_UNORM_SRGB:
      result.format = VK_FORMAT_B8G8R8A8_SRGB;
      result.swizzle.a = VK_COMPONENT_SWIZZLE_ONE;
      break;
    case DXGI_FORMAT_R8G8B8A8_UNORM:
    case DXGI_FORMAT_R8G8B8A8_TYPELESS:
      result.format = VK_FORMAT_R8G8B8A8_UNORM;
      break;
    case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
      result.format = VK_FORMAT_R8G8B8A8_SRGB;
      break;
    case DXGI_FORMAT_R8G8B8A8_UINT:
      result.format = VK_FORMAT_R8G8B8A8_UINT;
      break;
    case DXGI_FORMAT_B5G6R5_UNORM:
      result.format = VK_FORMAT_R5G6B5_UNORM_PACK16; // same bit layout: B in the low bits
      break;
    case DXGI_FORMAT_B5G5R5A1_UNORM:
      result.format = VK_FORMAT_A1R5G5B5_UNORM_PACK16;
      break;
    case DXGI_FORMAT_B4G4R4A4_UNORM:
      result.format = VK_FORMAT_A4R4G4B4_UNORM_PACK16;
      break;
    case DXGI_FORMAT_A8_UNORM:
      result.format = VK_FORMAT_R8_UNORM;
      result.swizzle = {VK_COMPONENT_SWIZZLE_ZERO, VK_COMPONENT_SWIZZLE_ZERO, VK_COMPONENT_SWIZZLE_ZERO, VK_COMPONENT_SWIZZLE_R};
      break;
    case DXGI_FORMAT_R8_UNORM:
      result.format = VK_FORMAT_R8_UNORM;
      break;
    case DXGI_FORMAT_R8G8_UNORM:
      result.format = VK_FORMAT_R8G8_UNORM;
      break;
    case DXGI_FORMAT_BC1_UNORM:
    case DXGI_FORMAT_BC1_TYPELESS:
      result.format = VK_FORMAT_BC1_RGBA_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_BC1_UNORM_SRGB:
      result.format = VK_FORMAT_BC1_RGBA_SRGB_BLOCK;
      break;
    case DXGI_FORMAT_BC2_UNORM:
    case DXGI_FORMAT_BC2_TYPELESS:
      result.format = VK_FORMAT_BC2_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_BC2_UNORM_SRGB:
      result.format = VK_FORMAT_BC2_SRGB_BLOCK;
      break;
    case DXGI_FORMAT_BC3_UNORM:
    case DXGI_FORMAT_BC3_TYPELESS:
      result.format = VK_FORMAT_BC3_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_BC3_UNORM_SRGB:
      result.format = VK_FORMAT_BC3_SRGB_BLOCK;
      break;
    case DXGI_FORMAT_BC4_UNORM:
      result.format = VK_FORMAT_BC4_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_BC5_UNORM:
      result.format = VK_FORMAT_BC5_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_BC7_UNORM:
      result.format = VK_FORMAT_BC7_UNORM_BLOCK;
      break;
    case DXGI_FORMAT_R16_FLOAT:
      result.format = VK_FORMAT_R16_SFLOAT;
      break;
    case DXGI_FORMAT_R16G16_FLOAT:
      result.format = VK_FORMAT_R16G16_SFLOAT;
      break;
    case DXGI_FORMAT_R16G16B16A16_FLOAT:
      result.format = VK_FORMAT_R16G16B16A16_SFLOAT;
      break;
    case DXGI_FORMAT_R32_FLOAT:
      result.format = VK_FORMAT_R32_SFLOAT;
      break;
    case DXGI_FORMAT_R32G32_FLOAT:
      result.format = VK_FORMAT_R32G32_SFLOAT;
      break;
    case DXGI_FORMAT_R32G32B32A32_FLOAT:
      result.format = VK_FORMAT_R32G32B32A32_SFLOAT;
      break;
    case DXGI_FORMAT_R10G10B10A2_UNORM:
      result.format = VK_FORMAT_A2B10G10R10_UNORM_PACK32;
      break;
    case DXGI_FORMAT_R16_UNORM:
      result.format = VK_FORMAT_R16_UNORM;
      break;
    case DXGI_FORMAT_R16G16_UNORM:
      result.format = VK_FORMAT_R16G16_UNORM;
      break;
    case DXGI_FORMAT_R16G16B16A16_UNORM:
      result.format = VK_FORMAT_R16G16B16A16_UNORM;
      break;
    case DXGI_FORMAT_D24_UNORM_S8_UINT:
    case DXGI_FORMAT_R24G8_TYPELESS:
    case DXGI_FORMAT_R24_UNORM_X8_TYPELESS:
      result.format = VK_FORMAT_D24_UNORM_S8_UINT;
      break;
    case DXGI_FORMAT_D32_FLOAT:
    case DXGI_FORMAT_R32_TYPELESS:
      result.format = VK_FORMAT_D32_SFLOAT;
      break;
    case DXGI_FORMAT_D16_UNORM:
    case DXGI_FORMAT_R16_TYPELESS:
      result.format = VK_FORMAT_D16_UNORM;
      break;
    default:
      break;
    }
    return result;
  }

  VkFormat ToVulkanVertex(const DXGI_FORMAT format) noexcept
  {
    switch (format) {
    case DXGI_FORMAT_R32G32B32A32_FLOAT:
      return VK_FORMAT_R32G32B32A32_SFLOAT;
    case DXGI_FORMAT_R32G32B32A32_UINT:
      return VK_FORMAT_R32G32B32A32_UINT;
    case DXGI_FORMAT_R32G32B32A32_SINT:
      return VK_FORMAT_R32G32B32A32_SINT;
    case DXGI_FORMAT_R32G32B32_FLOAT:
      return VK_FORMAT_R32G32B32_SFLOAT;
    case DXGI_FORMAT_R32G32_FLOAT:
      return VK_FORMAT_R32G32_SFLOAT;
    case DXGI_FORMAT_R32_FLOAT:
      return VK_FORMAT_R32_SFLOAT;
    case DXGI_FORMAT_R16G16B16A16_FLOAT:
      return VK_FORMAT_R16G16B16A16_SFLOAT;
    case DXGI_FORMAT_R16G16_FLOAT:
      return VK_FORMAT_R16G16_SFLOAT;
    case DXGI_FORMAT_R16G16B16A16_UINT:
      return VK_FORMAT_R16G16B16A16_UINT;
    case DXGI_FORMAT_R16G16B16A16_UNORM:
      return VK_FORMAT_R16G16B16A16_UNORM;
    case DXGI_FORMAT_R8G8B8A8_UINT:
      return VK_FORMAT_R8G8B8A8_UINT;
    case DXGI_FORMAT_R8G8B8A8_UNORM:
      return VK_FORMAT_R8G8B8A8_UNORM;
    case DXGI_FORMAT_R8G8B8A8_SNORM:
      return VK_FORMAT_R8G8B8A8_SNORM;
    case DXGI_FORMAT_B8G8R8A8_UNORM:
      return VK_FORMAT_B8G8R8A8_UNORM;
    case DXGI_FORMAT_R8_SINT:
      return VK_FORMAT_R8_SINT;
    default:
      return VK_FORMAT_UNDEFINED;
    }
  }

  bool IsDepthFormat(const VkFormat format) noexcept
  {
    return format == VK_FORMAT_D16_UNORM || format == VK_FORMAT_D32_SFLOAT || format == VK_FORMAT_D24_UNORM_S8_UINT ||
      format == VK_FORMAT_D32_SFLOAT_S8_UINT || format == VK_FORMAT_X8_D24_UNORM_PACK32;
  }

  bool HasStencil(const VkFormat format) noexcept
  {
    return format == VK_FORMAT_D24_UNORM_S8_UINT || format == VK_FORMAT_D32_SFLOAT_S8_UINT;
  }

  // ---------------------------------------------------------------------------
  // Allocation alignment

  namespace
  {
    [[nodiscard]] VkDeviceSize AlignUp(const VkDeviceSize value, const VkDeviceSize alignment) noexcept
    {
      return (alignment <= 1U) ? value : (value + alignment - 1U) / alignment * alignment;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // UploadAllocator

  namespace
  {
    constexpr VkDeviceSize kPageSize = 8ULL << 20U;
  }

  void UploadAllocator::Initialize(MemoryAllocator& memory, const VkDevice device)
  {
    mMemory = &memory;
    mDevice = device;
  }

  void UploadAllocator::DestroyPage(Page& page) noexcept
  {
    if (page.buffer != VK_NULL_HANDLE) {
      Vk().vkDestroyBuffer(mDevice, page.buffer, nullptr);
    }
    mMemory->Free(page.memory);
    page = Page{};
  }

  void UploadAllocator::Release() noexcept
  {
    for (const std::unique_ptr<Page>& page : mPages) {
      DestroyPage(*page);
    }
    mPages.clear();
    mCurrent = nullptr;
  }

  UploadAllocator::Page* UploadAllocator::NewPage(const VkDeviceSize size)
  {
    auto page = std::make_unique<Page>();
    page->size = size;
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = size;
    info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_INDEX_BUFFER_BIT |
      VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;
    info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    CheckVk("VulkanCore.cpp", __LINE__, Vk().vkCreateBuffer(mDevice, &info, nullptr, &page->buffer));
    VkMemoryRequirements requirements{};
    Vk().vkGetBufferMemoryRequirements(mDevice, page->buffer, &requirements);
    page->memory = mMemory->Allocate(
      requirements, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, true
    );
    CheckVk("VulkanCore.cpp", __LINE__, Vk().vkBindBufferMemory(mDevice, page->buffer, page->memory.memory, page->memory.offset));
    mPages.push_back(std::move(page));
    return mPages.back().get();
  }

  UploadAllocation UploadAllocator::Allocate(const VkDeviceSize bytes, const VkDeviceSize alignment, const std::uint64_t serial)
  {
    const VkDeviceSize size = std::max<VkDeviceSize>(bytes, 1U);
    if (mCurrent != nullptr) {
      const VkDeviceSize offset = AlignUp(mCurrent->used, alignment);
      if (offset + size <= mCurrent->size) {
        mCurrent->used = offset + size;
        mCurrent->lastSerial = serial;
        mCurrent->busy = true;
        mAllocatedBytes += size;
        return UploadAllocation{mCurrent->buffer, offset, mCurrent->memory.mapped + offset};
      }
    }
    Page* chosen = nullptr;
    for (const std::unique_ptr<Page>& page : mPages) {
      if (!page->busy && page->size >= size && (chosen == nullptr || page->size < chosen->size)) {
        chosen = page.get();
      }
    }
    if (chosen == nullptr) {
      chosen = NewPage(std::max(kPageSize, AlignUp(size, 64ULL * 1024U)));
    }
    chosen->used = size;
    chosen->lastSerial = serial;
    chosen->busy = true;
    if (chosen->size <= kPageSize) {
      mCurrent = chosen;
    }
    mAllocatedBytes += size;
    return UploadAllocation{chosen->buffer, 0U, chosen->memory.mapped};
  }

  void UploadAllocator::Retire(const std::uint64_t completedSerial) noexcept
  {
    for (const std::unique_ptr<Page>& page : mPages) {
      if (page->busy && page->lastSerial <= completedSerial) {
        page->busy = false;
        page->used = 0U;
      }
    }
    // Oversized pages that sit idle go, and so do idle ordinary pages past the reserve.
    const std::uint64_t idleReserve = static_cast<std::uint64_t>(std::max(gUploadIdleMB, 0)) << 20U;
    std::uint64_t idleKept = 0U;
    for (auto page = mPages.begin(); page != mPages.end();) {
      if ((*page)->busy || page->get() == mCurrent) {
        ++page;
      } else if ((*page)->size > kPageSize || idleKept + (*page)->size > idleReserve) {
        DestroyPage(**page);
        page = mPages.erase(page);
      } else {
        idleKept += (*page)->size;
        ++page;
      }
    }
  }

  std::uint64_t UploadAllocator::PageBytes() const noexcept
  {
    std::uint64_t bytes = 0U;
    for (const auto& page : mPages) {
      bytes += page->size;
    }
    return bytes;
  }

  std::uint64_t UploadAllocator::TakeAllocatedBytes() noexcept
  {
    const std::uint64_t bytes = mAllocatedBytes;
    mAllocatedBytes = 0U;
    return bytes;
  }

  std::uint64_t UploadAllocator::BusyBytes() const noexcept
  {
    std::uint64_t bytes = 0U;
    for (const std::unique_ptr<Page>& page : mPages) {
      if (page->busy) {
        bytes += page->size;
      }
    }
    return bytes;
  }
} // namespace gpg::gal::vulkan
