// FAF addition: see VulkanMemoryAllocator.h.
#include "VulkanMemoryAllocator.h"

#include <algorithm>
#include "VulkanLoader.h"
#include "gpg/gal/backends/common/BackendErrors.h"

namespace gpg::gal::vulkan
{
  void CheckVk(const char* file, int line, VkResult result);

  namespace
  {
    constexpr VkDeviceSize kBlockSize = 64ULL << 20U;

    [[nodiscard]] VkDeviceSize AlignUp(const VkDeviceSize value, const VkDeviceSize alignment) noexcept
    {
      return (alignment <= 1U) ? value : (value + alignment - 1U) / alignment * alignment;
    }
  } // namespace

  void MemoryAllocator::Initialize(const VkPhysicalDevice physicalDevice, const VkDevice device)
  {
    mDevice = device;
    Vk().vkGetPhysicalDeviceMemoryProperties(physicalDevice, &mProperties);
  }

  void MemoryAllocator::Release() noexcept
  {
    for (const std::unique_ptr<Block>& block : mBlocks) {
      if (block != nullptr && block->memory != VK_NULL_HANDLE) {
        if (block->mapped != nullptr) {
          Vk().vkUnmapMemory(mDevice, block->memory);
        }
        Vk().vkFreeMemory(mDevice, block->memory, nullptr);
      }
    }
    mBlocks.clear();
    mDevice = VK_NULL_HANDLE;
  }

  std::uint32_t MemoryAllocator::FindType(const std::uint32_t typeBits, const VkMemoryPropertyFlags required) const
  {
    for (std::uint32_t type = 0U; type < mProperties.memoryTypeCount; ++type) {
      if ((typeBits & (1U << type)) != 0U && (mProperties.memoryTypes[type].propertyFlags & required) == required) {
        return type;
      }
    }
    backend::ThrowError("VulkanMemoryAllocator.cpp", __LINE__, "no Vulkan memory type fits the resource");
  }

  Allocation MemoryAllocator::Allocate(const VkMemoryRequirements& requirements, const VkMemoryPropertyFlags required, const bool linear)
  {
    const std::uint32_t type = FindType(requirements.memoryTypeBits, required);
    const bool hostVisible = (mProperties.memoryTypes[type].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) != 0U;

    for (std::size_t index = 0U; index < mBlocks.size(); ++index) {
      Block* const block = mBlocks[index].get();
      if (block == nullptr || block->type != type || block->linear != linear) {
        continue;
      }
      for (auto range = block->free.begin(); range != block->free.end(); ++range) {
        const VkDeviceSize start = AlignUp(range->first, requirements.alignment);
        const VkDeviceSize end = range->first + range->second;
        if (start + requirements.size > end) {
          continue;
        }
        const VkDeviceSize rangeStart = range->first;
        const VkDeviceSize allocationEnd = start + requirements.size;
        if (start > rangeStart) {
          // Prepare the only extra node before changing the existing free range.
          // If allocation fails, the full range remains available for a later try.
          if (allocationEnd < end) {
            block->free.emplace(allocationEnd, end - allocationEnd);
          }
          range->second = start - rangeStart;
        } else if (allocationEnd < end) {
          // Reuse the existing node for the suffix; no heap allocation is needed.
          auto suffix = block->free.extract(range);
          suffix.key() = allocationEnd;
          suffix.mapped() = end - allocationEnd;
          block->free.insert(std::move(suffix));
        } else {
          block->free.erase(range);
        }
        Allocation allocation;
        allocation.memory = block->memory;
        allocation.offset = start;
        allocation.size = requirements.size;
        allocation.mapped = (block->mapped != nullptr) ? block->mapped + start : nullptr;
        allocation.block = static_cast<std::int32_t>(index);
        allocation.linear = linear;
        return allocation;
      }
    }

    // A new block: large requests get one of their own size.
    auto block = std::make_unique<Block>();
    block->size = std::max(kBlockSize, AlignUp(requirements.size, 1ULL << 20U));
    block->type = type;
    block->linear = linear;
    VkMemoryAllocateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    info.allocationSize = block->size;
    info.memoryTypeIndex = type;
    CheckVk("VulkanMemoryAllocator.cpp", __LINE__, Vk().vkAllocateMemory(mDevice, &info, nullptr, &block->memory));
    // Until the block is published, its unique_ptr only owns the bookkeeping.
    // A failed map or container allocation must also release the native memory.
    struct UnpublishedBlock
    {
      VkDevice device;
      Block* block;

      ~UnpublishedBlock() noexcept
      {
        if (block != nullptr) {
          if (block->mapped != nullptr) {
            Vk().vkUnmapMemory(device, block->memory);
          }
          Vk().vkFreeMemory(device, block->memory, nullptr);
        }
      }
    } unpublished{mDevice, block.get()};
    if (hostVisible) {
      void* mapped = nullptr;
      CheckVk("VulkanMemoryAllocator.cpp", __LINE__, Vk().vkMapMemory(mDevice, block->memory, 0U, VK_WHOLE_SIZE, 0U, &mapped));
      block->mapped = static_cast<std::uint8_t*>(mapped);
    }
    if (requirements.size < block->size) {
      block->free[requirements.size] = block->size - requirements.size;
    }
    Allocation allocation;
    allocation.memory = block->memory;
    allocation.offset = 0U;
    allocation.size = requirements.size;
    allocation.mapped = block->mapped;
    allocation.linear = linear;

    // Reuse an empty slot of the block list.
    for (std::size_t index = 0U; index < mBlocks.size(); ++index) {
      if (mBlocks[index] == nullptr) {
        allocation.block = static_cast<std::int32_t>(index);
        mBlocks[index] = std::move(block);
        unpublished.block = nullptr;
        return allocation;
      }
    }
    allocation.block = static_cast<std::int32_t>(mBlocks.size());
    mBlocks.push_back(std::move(block));
    unpublished.block = nullptr;
    return allocation;
  }

  void MemoryAllocator::Free(const Allocation& allocation) noexcept
  {
    if (allocation.block < 0 || static_cast<std::size_t>(allocation.block) >= mBlocks.size()) {
      return;
    }
    Block* const block = mBlocks[static_cast<std::size_t>(allocation.block)].get();
    if (block == nullptr) {
      return;
    }
    VkDeviceSize start = allocation.offset;
    VkDeviceSize size = allocation.size;
    // Merge with the free neighbours.
    auto next = block->free.lower_bound(start);
    if (next != block->free.end() && next->first == start + size) {
      size += next->second;
      next = block->free.erase(next);
    }
    if (next != block->free.begin()) {
      auto previous = std::prev(next);
      if (previous->first + previous->second == start) {
        start = previous->first;
        size += previous->second;
        block->free.erase(previous);
      }
    }
    block->free[start] = size;

    // A wholly free block goes back to the driver: at once if it's oversized, otherwise when
    // another empty block of its kind stays for the next allocations.
    const auto wholeFree = [](const Block& candidate) {
      return candidate.free.size() == 1U && candidate.free.begin()->second == candidate.size;
    };
    const bool anotherEmpty = std::any_of(mBlocks.begin(), mBlocks.end(), [&](const std::unique_ptr<Block>& other) {
      return other != nullptr && other.get() != block && other->type == block->type && other->linear == block->linear && wholeFree(*other);
    });
    if (wholeFree(*block) && (block->size > kBlockSize || anotherEmpty)) {
      if (block->mapped != nullptr) {
        Vk().vkUnmapMemory(mDevice, block->memory);
      }
      Vk().vkFreeMemory(mDevice, block->memory, nullptr);
      mBlocks[static_cast<std::size_t>(allocation.block)].reset();
    }
  }

  std::uint64_t MemoryAllocator::BlockBytes() const noexcept
  {
    std::uint64_t bytes = 0U;
    for (const std::unique_ptr<Block>& block : mBlocks) {
      bytes += block != nullptr ? block->size : 0U; // a slot Free emptied
    }
    return bytes;
  }

} // namespace gpg::gal::vulkan
