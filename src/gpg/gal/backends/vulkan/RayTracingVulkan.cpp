// FAF addition, not in the shipped binary.
//
// Engine addition (ren_RayTracedShadows, RayTracing.h): the Vulkan side of the ray-traced scene. Needs
// VK_KHR_acceleration_structure, VK_KHR_ray_query (with VK_KHR_deferred_host_operations, which the first
// requires) and buffer device addresses. Bottom-level structures live in a few large device buffers; their
// build inputs and the top-level instance list come from host-visible buffers reused once the GPU is past
// them. The scene is descriptor set 2 of the effect pipeline layouts (ModernHlsl's [[vk::binding(0, 2)]]).

#include "DeviceVulkan.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/effects/RayTracedShadows.h"

namespace gpg::gal
{
  using vulkan::CheckVk;
  using vulkan::Vk;

  namespace
  {
    constexpr VkDeviceSize kRayChunkBytes = 32ULL << 20U;
    constexpr VkDeviceSize kRayInputChunkBytes = 16ULL << 20U;

    [[nodiscard]] VkDeviceSize AlignUp(const VkDeviceSize value, const VkDeviceSize alignment) noexcept
    {
      return (value + alignment - 1U) & ~(alignment - 1U);
    }
  } // namespace

  bool DeviceVulkan::CreateRayBuffer(const VkDeviceSize bytes, const VkBufferUsageFlags usage, const bool host, RayBuffer& out)
  {
    out = RayBuffer{};
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = bytes;
    info.usage = usage | VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT;
    info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (Vk().vkCreateBuffer(mDevice, &info, nullptr, &out.buffer) != VK_SUCCESS) {
      return false;
    }
    VkMemoryRequirements requirements{};
    Vk().vkGetBufferMemoryRequirements(mDevice, out.buffer, &requirements);
    VkPhysicalDeviceMemoryProperties properties{};
    Vk().vkGetPhysicalDeviceMemoryProperties(mPhysical, &properties);
    const VkMemoryPropertyFlags wanted =
      host ? (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) : VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    std::uint32_t type = ~0U;
    for (std::uint32_t index = 0U; index < properties.memoryTypeCount; ++index) {
      if ((requirements.memoryTypeBits & (1U << index)) != 0U && (properties.memoryTypes[index].propertyFlags & wanted) == wanted) {
        type = index;
        break;
      }
    }
    VkMemoryAllocateFlagsInfo flags{};
    flags.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO;
    flags.flags = VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT;
    VkMemoryAllocateInfo allocate{};
    allocate.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocate.pNext = &flags;
    allocate.allocationSize = requirements.size;
    allocate.memoryTypeIndex = type;
    if (type == ~0U || Vk().vkAllocateMemory(mDevice, &allocate, nullptr, &out.memory) != VK_SUCCESS ||
        Vk().vkBindBufferMemory(mDevice, out.buffer, out.memory, 0U) != VK_SUCCESS) {
      DestroyRayBuffer(out);
      return false;
    }
    if (host) {
      void* mapped = nullptr;
      if (Vk().vkMapMemory(mDevice, out.memory, 0U, VK_WHOLE_SIZE, 0U, &mapped) != VK_SUCCESS) {
        DestroyRayBuffer(out);
        return false;
      }
      out.mapped = static_cast<std::uint8_t*>(mapped);
    }
    VkBufferDeviceAddressInfo address{};
    address.sType = VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO;
    address.buffer = out.buffer;
    out.address = Vk().vkGetBufferDeviceAddress(mDevice, &address);
    out.size = bytes;
    return true;
  }

  void DeviceVulkan::DestroyRayBuffer(RayBuffer& buffer) noexcept
  {
    if (buffer.buffer != VK_NULL_HANDLE) {
      Vk().vkDestroyBuffer(mDevice, buffer.buffer, nullptr);
    }
    if (buffer.memory != VK_NULL_HANDLE) {
      Vk().vkFreeMemory(mDevice, buffer.memory, nullptr);
    }
    buffer = RayBuffer{};
  }

  void DeviceVulkan::RetireRay(const VkAccelerationStructureKHR structure, const RayBuffer& buffer, const VkDescriptorSet set)
  {
    RayGarbage garbage;
    garbage.serial = RecordingSerial();
    garbage.structure = structure;
    garbage.buffer = buffer;
    garbage.set = set;
    mRayGarbage.push_back(garbage);
  }

  void DeviceVulkan::CollectRayGarbage(const bool all)
  {
    std::uint64_t completed = 0U;
    Vk().vkGetSemaphoreCounterValue(mDevice, mTimeline, &completed);
    auto keep = mRayGarbage.begin();
    for (auto it = mRayGarbage.begin(); it != mRayGarbage.end(); ++it) {
      if (all || it->serial <= completed) {
        if (it->structure != VK_NULL_HANDLE) {
          Vk().vkDestroyAccelerationStructureKHR(mDevice, it->structure, nullptr);
        }
        if (it->set != VK_NULL_HANDLE) {
          Vk().vkFreeDescriptorSets(mDevice, mRayPool, 1U, &it->set);
        }
        if (it->range.bytes != 0U) {
          RayArenaFree(it->range);
        }
        DestroyRayBuffer(it->buffer);
      } else {
        *keep++ = *it;
      }
    }
    mRayGarbage.erase(keep, mRayGarbage.end());
    for (RayInputChunk& chunk : mRayInputs) {
      if (&chunk != mRayInputCurrent && (all || chunk.serial <= completed)) {
        chunk.used = 0U;
      }
    }
  }

  bool DeviceVulkan::RayArenaAllocate(const VkDeviceSize bytes, RayRange& out)
  {
    const VkDeviceSize size = AlignUp(bytes, 256U);
    for (std::uint32_t chunk = 0U; chunk < mRayChunks.size(); ++chunk) {
      std::map<VkDeviceSize, VkDeviceSize>& holes = mRayChunks[chunk].holes;
      for (auto hole = holes.begin(); hole != holes.end(); ++hole) {
        if (hole->second < size) {
          continue;
        }
        out.chunk = chunk;
        out.offset = hole->first;
        out.bytes = size;
        const VkDeviceSize left = hole->second - size;
        const VkDeviceSize next = hole->first + size;
        holes.erase(hole);
        if (left != 0U) {
          holes.emplace(next, left);
        }
        return true;
      }
    }
    RayChunk chunk;
    if (!CreateRayBuffer(std::max(kRayChunkBytes, size), VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_STORAGE_BIT_KHR, false, chunk.buffer)) {
      return false;
    }
    chunk.holes.emplace(0U, chunk.buffer.size);
    mRayChunks.push_back(std::move(chunk));
    return RayArenaAllocate(bytes, out);
  }

  void DeviceVulkan::RayArenaFree(const RayRange& range)
  {
    std::map<VkDeviceSize, VkDeviceSize>& holes = mRayChunks[range.chunk].holes;
    auto inserted = holes.emplace(range.offset, range.bytes).first;
    const auto next = std::next(inserted);
    if (next != holes.end() && inserted->first + inserted->second == next->first) {
      inserted->second += next->second;
      holes.erase(next);
    }
    if (inserted != holes.begin()) {
      const auto previous = std::prev(inserted);
      if (previous->first + previous->second == inserted->first) {
        previous->second += inserted->second;
        holes.erase(inserted);
      }
    }
  }

  std::uint8_t* DeviceVulkan::RayInput(const VkDeviceSize bytes, VkDeviceAddress& address)
  {
    const VkDeviceSize size = AlignUp(bytes, 256U);
    if (mRayInputCurrent == nullptr || mRayInputCurrent->used + size > mRayInputCurrent->buffer.size) {
      if (mRayInputCurrent != nullptr) {
        mRayInputCurrent->serial = RecordingSerial();
      }
      mRayInputCurrent = nullptr;
      CollectRayGarbage(false);
      for (RayInputChunk& chunk : mRayInputs) {
        if (chunk.used == 0U && chunk.buffer.size >= size) {
          mRayInputCurrent = &chunk;
          break;
        }
      }
      if (mRayInputCurrent == nullptr) {
        RayInputChunk chunk;
        if (!CreateRayBuffer(std::max(kRayInputChunkBytes, size), VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_BUILD_INPUT_READ_ONLY_BIT_KHR, true,
                             chunk.buffer)) {
          return nullptr;
        }
        mRayInputs.push_back(std::move(chunk));
        mRayInputCurrent = &mRayInputs.back();
        // push_back may have moved the others; none but the current one is referenced by pointer.
      }
    }
    mRayInputCurrent->serial = RecordingSerial();
    std::uint8_t* const cpu = mRayInputCurrent->buffer.mapped + mRayInputCurrent->used;
    address = mRayInputCurrent->buffer.address + mRayInputCurrent->used;
    mRayInputCurrent->used += size;
    return cpu;
  }

  bool DeviceVulkan::EnsureRayScratch(const VkDeviceSize bytes)
  {
    const VkDeviceSize needed = bytes + mRayScratchAlignment;
    if (mRayScratch.buffer != VK_NULL_HANDLE && mRayScratch.size >= needed) {
      return true;
    }
    if (mRayScratch.buffer != VK_NULL_HANDLE) {
      RetireRay(VK_NULL_HANDLE, mRayScratch, VK_NULL_HANDLE);
      mRayScratch = RayBuffer{};
    }
    return CreateRayBuffer(AlignUp(std::max<VkDeviceSize>(needed, 4ULL << 20U), 65536U), VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, false, mRayScratch);
  }

  void DeviceVulkan::RayBarrier(const VkPipelineStageFlags2 sourceStages, const VkAccessFlags2 sourceAccess,
                                const VkPipelineStageFlags2 destinationStages, const VkAccessFlags2 destinationAccess)
  {
    VkMemoryBarrier2 barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2;
    barrier.srcStageMask = sourceStages;
    barrier.srcAccessMask = sourceAccess;
    barrier.dstStageMask = destinationStages;
    barrier.dstAccessMask = destinationAccess;
    VkDependencyInfo dependency{};
    dependency.sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO;
    dependency.memoryBarrierCount = 1U;
    dependency.pMemoryBarriers = &barrier;
    Vk().vkCmdPipelineBarrier2(mCommands, &dependency);
  }

  void DeviceVulkan::CreateRayTracingObjects()
  {
    ++gRaySceneEpoch;
    if (!mRayQuery) {
      return;
    }
    VkPhysicalDeviceAccelerationStructurePropertiesKHR accelerationProperties{};
    accelerationProperties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_PROPERTIES_KHR;
    VkPhysicalDeviceProperties2 properties{};
    properties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    properties.pNext = &accelerationProperties;
    Vk().vkGetPhysicalDeviceProperties2(mPhysical, &properties);
    mRayScratchAlignment = std::max<VkDeviceSize>(accelerationProperties.minAccelerationStructureScratchOffsetAlignment, 256U);

    VkDescriptorPoolSize size{};
    size.type = VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR;
    size.descriptorCount = 64U;
    VkDescriptorPoolCreateInfo pool{};
    pool.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pool.maxSets = 64U;
    pool.poolSizeCount = 1U;
    pool.pPoolSizes = &size;
    CheckVk("RayTracingVulkan.cpp", __LINE__, Vk().vkCreateDescriptorPool(mDevice, &pool, nullptr, &mRayPool));
    mGpuFeatures |= kGpuFeatureRayQuery;
    // An empty scene, so every effect draw has one to bind until the renderer hands its own.
    BuildRayScene();
  }

  void DeviceVulkan::ReleaseRayTracingObjects() noexcept
  {
    ++gRaySceneEpoch;
    if (mDevice == VK_NULL_HANDLE) {
      return;
    }
    if (mTlas != VK_NULL_HANDLE || mTlasBuffer.buffer != VK_NULL_HANDLE) {
      RetireRay(mTlas, mTlasBuffer, mRaySet);
      mTlas = VK_NULL_HANDLE;
      mTlasBuffer = RayBuffer{};
      mRaySet = VK_NULL_HANDLE;
    }
    for (auto& [id, piece] : mRayGeometries) {
      RayGarbage garbage;
      garbage.structure = piece.structure;
      mRayGarbage.push_back(garbage);
    }
    mRayGeometries.clear();
    if (mRayPool != VK_NULL_HANDLE) {
      CollectRayGarbage(true);
    }
    mRayGarbage.clear();
    for (RayChunk& chunk : mRayChunks) {
      DestroyRayBuffer(chunk.buffer);
    }
    mRayChunks.clear();
    for (RayInputChunk& chunk : mRayInputs) {
      DestroyRayBuffer(chunk.buffer);
    }
    mRayInputs.clear();
    mRayInputCurrent = nullptr;
    DestroyRayBuffer(mRayScratch);
    if (mRayPool != VK_NULL_HANDLE) {
      Vk().vkDestroyDescriptorPool(mDevice, mRayPool, nullptr);
      mRayPool = VK_NULL_HANDLE;
    }
    if (mRayLayout != VK_NULL_HANDLE) {
      Vk().vkDestroyDescriptorSetLayout(mDevice, mRayLayout, nullptr);
      mRayLayout = VK_NULL_HANDLE;
    }
    mRayInstances.clear();
  }

  RayGeometryId DeviceVulkan::CreateRayGeometry(const RayGeometryDesc& desc)
  {
    if (!mRayQuery || desc.positions == nullptr || desc.indices == nullptr || desc.vertexCount == 0U || desc.indexCount < 3U ||
        desc.positionStride < 12U) {
      return 0U;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const std::uint32_t triangles = desc.indexCount / 3U;
    VkDeviceAddress vertexAddress = 0U;
    VkDeviceAddress indexAddress = 0U;
    std::uint8_t* const vertices = RayInput(static_cast<VkDeviceSize>(desc.vertexCount) * 12U, vertexAddress);
    std::uint8_t* const indices = RayInput(static_cast<VkDeviceSize>(triangles) * 12U, indexAddress);
    if (vertices == nullptr || indices == nullptr) {
      return 0U;
    }
    const auto* source = reinterpret_cast<const std::uint8_t*>(desc.positions);
    for (std::uint32_t vertex = 0U; vertex < desc.vertexCount; ++vertex) {
      std::memcpy(vertices + (static_cast<std::size_t>(vertex) * 12U), source + (static_cast<std::size_t>(vertex) * desc.positionStride), 12U);
    }
    std::memcpy(indices, desc.indices, static_cast<std::size_t>(triangles) * 12U);

    VkAccelerationStructureGeometryKHR geometry{};
    geometry.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_KHR;
    geometry.geometryType = VK_GEOMETRY_TYPE_TRIANGLES_KHR;
    geometry.flags = VK_GEOMETRY_OPAQUE_BIT_KHR;
    geometry.geometry.triangles.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_TRIANGLES_DATA_KHR;
    geometry.geometry.triangles.vertexFormat = VK_FORMAT_R32G32B32_SFLOAT;
    geometry.geometry.triangles.vertexData.deviceAddress = vertexAddress;
    geometry.geometry.triangles.vertexStride = 12U;
    geometry.geometry.triangles.maxVertex = desc.vertexCount - 1U;
    geometry.geometry.triangles.indexType = VK_INDEX_TYPE_UINT32;
    geometry.geometry.triangles.indexData.deviceAddress = indexAddress;

    VkAccelerationStructureBuildGeometryInfoKHR build{};
    build.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_GEOMETRY_INFO_KHR;
    build.type = VK_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL_KHR;
    build.flags = VK_BUILD_ACCELERATION_STRUCTURE_PREFER_FAST_TRACE_BIT_KHR;
    build.mode = VK_BUILD_ACCELERATION_STRUCTURE_MODE_BUILD_KHR;
    build.geometryCount = 1U;
    build.pGeometries = &geometry;
    VkAccelerationStructureBuildSizesInfoKHR sizes{};
    sizes.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_SIZES_INFO_KHR;
    Vk().vkGetAccelerationStructureBuildSizesKHR(mDevice, VK_ACCELERATION_STRUCTURE_BUILD_TYPE_DEVICE_KHR, &build, &triangles, &sizes);

    RayGeometryVulkan piece;
    if (sizes.accelerationStructureSize == 0U || !RayArenaAllocate(sizes.accelerationStructureSize, piece.range) ||
        !EnsureRayScratch(sizes.buildScratchSize)) {
      gpg::Logf("Vulkan: out of memory for ray geometry '%s'", desc.name);
      return 0U;
    }
    VkAccelerationStructureCreateInfoKHR create{};
    create.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CREATE_INFO_KHR;
    create.buffer = mRayChunks[piece.range.chunk].buffer.buffer;
    create.offset = piece.range.offset;
    create.size = sizes.accelerationStructureSize;
    create.type = VK_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL_KHR;
    if (Vk().vkCreateAccelerationStructureKHR(mDevice, &create, nullptr, &piece.structure) != VK_SUCCESS) {
      RayArenaFree(piece.range);
      return 0U;
    }
    VkAccelerationStructureDeviceAddressInfoKHR addressInfo{};
    addressInfo.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_DEVICE_ADDRESS_INFO_KHR;
    addressInfo.accelerationStructure = piece.structure;
    piece.address = Vk().vkGetAccelerationStructureDeviceAddressKHR(mDevice, &addressInfo);

    build.dstAccelerationStructure = piece.structure;
    build.scratchData.deviceAddress = AlignUp(mRayScratch.address, mRayScratchAlignment);
    VkAccelerationStructureBuildRangeInfoKHR range{};
    range.primitiveCount = triangles;
    const VkAccelerationStructureBuildRangeInfoKHR* const ranges = &range;
    EndRendering();
    // The shared scratch buffer: the build before this one must be done with it.
    RayBarrier(VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
               VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR | VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR,
               VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
               VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR | VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR);
    Vk().vkCmdBuildAccelerationStructuresKHR(mCommands, 1U, &build, &ranges);
    RayBarrier(VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR, VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR,
               VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR, VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR);
    const RayGeometryId id = mNextRayGeometry++;
    mRayGeometries.emplace(id, piece);
    return id;
  }

  void DeviceVulkan::DestroyRayGeometry(const RayGeometryId geometry)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const auto found = mRayGeometries.find(geometry);
    if (found == mRayGeometries.end()) {
      return;
    }
    RayGarbage garbage;
    garbage.serial = RecordingSerial();
    garbage.structure = found->second.structure;
    garbage.range = found->second.range;
    mRayGarbage.push_back(garbage);
    mRayGeometries.erase(found);
  }

  bool DeviceVulkan::SetRayInstances(const RayInstance* const instances, const std::uint32_t count)
  {
    if (!mRayQuery) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    mRayInstances.clear();
    mRayInstances.reserve(count);
    for (std::uint32_t index = 0U; index < count; ++index) {
      const RayInstance& instance = instances[index];
      const auto found = mRayGeometries.find(instance.geometry);
      if (found == mRayGeometries.end()) {
        continue;
      }
      VkAccelerationStructureInstanceKHR desc{};
      std::memcpy(desc.transform.matrix, instance.transform, sizeof(desc.transform.matrix));
      desc.instanceCustomIndex = 0U;
      desc.mask = instance.mask;
      desc.instanceShaderBindingTableRecordOffset = 0U;
      desc.flags = VK_GEOMETRY_INSTANCE_TRIANGLE_FACING_CULL_DISABLE_BIT_KHR | VK_GEOMETRY_INSTANCE_FORCE_OPAQUE_BIT_KHR;
      desc.accelerationStructureReference = found->second.address;
      mRayInstances.push_back(desc);
    }
    return BuildRayScene();
  }

  bool DeviceVulkan::BuildRayScene()
  {
    CollectRayGarbage(false);
    const auto count = static_cast<std::uint32_t>(mRayInstances.size());
    VkDeviceAddress instanceAddress = 0U;
    std::uint8_t* const cpu =
      RayInput(std::max<VkDeviceSize>(1U, count) * sizeof(VkAccelerationStructureInstanceKHR), instanceAddress);
    if (cpu == nullptr) {
      return false;
    }
    if (count != 0U) {
      std::memcpy(cpu, mRayInstances.data(), static_cast<std::size_t>(count) * sizeof(VkAccelerationStructureInstanceKHR));
    }
    VkAccelerationStructureGeometryKHR geometry{};
    geometry.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_KHR;
    geometry.geometryType = VK_GEOMETRY_TYPE_INSTANCES_KHR;
    geometry.geometry.instances.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_INSTANCES_DATA_KHR;
    geometry.geometry.instances.arrayOfPointers = VK_FALSE;
    geometry.geometry.instances.data.deviceAddress = instanceAddress;
    VkAccelerationStructureBuildGeometryInfoKHR build{};
    build.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_GEOMETRY_INFO_KHR;
    build.type = VK_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL_KHR;
    build.flags = VK_BUILD_ACCELERATION_STRUCTURE_PREFER_FAST_BUILD_BIT_KHR;
    build.mode = VK_BUILD_ACCELERATION_STRUCTURE_MODE_BUILD_KHR;
    build.geometryCount = 1U;
    build.pGeometries = &geometry;
    VkAccelerationStructureBuildSizesInfoKHR sizes{};
    sizes.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_SIZES_INFO_KHR;
    Vk().vkGetAccelerationStructureBuildSizesKHR(mDevice, VK_ACCELERATION_STRUCTURE_BUILD_TYPE_DEVICE_KHR, &build, &count, &sizes);

    if (mTlas == VK_NULL_HANDLE || mTlasBuffer.size < sizes.accelerationStructureSize) {
      if (mTlas != VK_NULL_HANDLE || mTlasBuffer.buffer != VK_NULL_HANDLE) {
        RetireRay(mTlas, mTlasBuffer, mRaySet);
        mTlas = VK_NULL_HANDLE;
        mTlasBuffer = RayBuffer{};
        mRaySet = VK_NULL_HANDLE;
      }
      const VkDeviceSize bytes = AlignUp(sizes.accelerationStructureSize + (sizes.accelerationStructureSize / 2U) + 256U, 65536U);
      if (!CreateRayBuffer(bytes, VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_STORAGE_BIT_KHR, false, mTlasBuffer)) {
        return false;
      }
      VkAccelerationStructureCreateInfoKHR create{};
      create.sType = VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CREATE_INFO_KHR;
      create.buffer = mTlasBuffer.buffer;
      create.size = bytes;
      create.type = VK_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL_KHR;
      if (Vk().vkCreateAccelerationStructureKHR(mDevice, &create, nullptr, &mTlas) != VK_SUCCESS) {
        DestroyRayBuffer(mTlasBuffer);
        mTlas = VK_NULL_HANDLE;
        return false;
      }
      VkDescriptorSetAllocateInfo allocate{};
      allocate.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
      allocate.descriptorPool = mRayPool;
      allocate.descriptorSetCount = 1U;
      allocate.pSetLayouts = &mRayLayout;
      CheckVk("RayTracingVulkan.cpp", __LINE__, Vk().vkAllocateDescriptorSets(mDevice, &allocate, &mRaySet));
      VkWriteDescriptorSetAccelerationStructureKHR structureWrite{};
      structureWrite.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_KHR;
      structureWrite.accelerationStructureCount = 1U;
      structureWrite.pAccelerationStructures = &mTlas;
      VkWriteDescriptorSet write{};
      write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
      write.pNext = &structureWrite;
      write.dstSet = mRaySet;
      write.dstBinding = 0U;
      write.descriptorCount = 1U;
      write.descriptorType = VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR;
      Vk().vkUpdateDescriptorSets(mDevice, 1U, &write, 0U, nullptr);
    }
    if (!EnsureRayScratch(sizes.buildScratchSize)) {
      return false;
    }
    build.dstAccelerationStructure = mTlas;
    build.scratchData.deviceAddress = AlignUp(mRayScratch.address, mRayScratchAlignment);
    VkAccelerationStructureBuildRangeInfoKHR range{};
    range.primitiveCount = count;
    const VkAccelerationStructureBuildRangeInfoKHR* const ranges = &range;
    EndRendering();
    // Earlier draws read the scene being replaced; earlier builds wrote the pieces it points at and used the scratch.
    RayBarrier(VK_PIPELINE_STAGE_2_ALL_GRAPHICS_BIT | VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT | VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
               VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR | VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR,
               VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
               VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR | VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR);
    Vk().vkCmdBuildAccelerationStructuresKHR(mCommands, 1U, &build, &ranges);
    RayBarrier(VK_PIPELINE_STAGE_2_ACCELERATION_STRUCTURE_BUILD_BIT_KHR, VK_ACCESS_2_ACCELERATION_STRUCTURE_WRITE_BIT_KHR,
               VK_PIPELINE_STAGE_2_ALL_GRAPHICS_BIT | VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT,
               VK_ACCESS_2_ACCELERATION_STRUCTURE_READ_BIT_KHR);
    return mRaySet != VK_NULL_HANDLE;
  }
} // namespace gpg::gal
