// FAF addition: what DeviceVulkan checks against the device's limits before it makes its pipeline layouts and
// GPU programs. Vulkan promises only its minimum limits (VkPhysicalDeviceLimits), which desktop GPUs exceed many
// times over and a phone's GPU need not: per shader stage 16 sampled images, 16 samplers, 4 storage buffers and
// 12 uniform buffers, 128 threads in a compute work group, 64 fragment input components. Header-only and free of
// Vulkan calls, so that tests/vulkan/LimitsTests.cpp checks it with limits of its own.
#pragma once

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <string>

#include <vulkan/vulkan_core.h>

namespace gpg::gal::vulkan
{
  /** A descriptor set layout's bindings, as its VkDescriptorSetLayoutCreateInfo names them. */
  struct SetBindings
  {
    const VkDescriptorSetLayoutBinding* bindings = nullptr;
    std::uint32_t count = 0U;
  };

  /**
   * The descriptors that one stage sees or that a layout holds, of the four kinds DeviceVulkan's layouts have
   * (sampled images, samplers, storage and uniform buffers), each as its limits count it. Storage images, texel
   * buffers and input attachments, which those layouts don't have, are not counted, nor the ray-traced scene's
   * acceleration structure, whose limits are VkPhysicalDeviceAccelerationStructurePropertiesKHR's.
   */
  struct DescriptorCounts
  {
    std::uint32_t sampledImages = 0U;
    std::uint32_t samplers = 0U;
    std::uint32_t storageBuffers = 0U;
    std::uint32_t uniformBuffers = 0U;
  };

  /** The descriptors of `sets` that a stage of `stages` sees, counted as the limits count them. */
  inline DescriptorCounts CountDescriptors(
    const std::initializer_list<SetBindings> sets,
    const VkShaderStageFlags stages
  ) noexcept
  {
    DescriptorCounts counts;
    for (const SetBindings& set : sets) {
      for (std::uint32_t index = 0U; index < set.count; ++index) {
        const VkDescriptorSetLayoutBinding& binding = set.bindings[index];
        if ((binding.stageFlags & stages) == 0U) {
          continue;
        }
        switch (binding.descriptorType) {
        case VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
          counts.sampledImages += binding.descriptorCount;
          counts.samplers += binding.descriptorCount;
          break;
        case VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
          counts.sampledImages += binding.descriptorCount;
          break;
        case VK_DESCRIPTOR_TYPE_SAMPLER:
          counts.samplers += binding.descriptorCount;
          break;
        case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
        case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC:
          counts.storageBuffers += binding.descriptorCount;
          break;
        case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
        case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
          counts.uniformBuffers += binding.descriptorCount;
          break;
        default:
          break;
        }
      }
    }
    return counts;
  }

  /**
   * What a pipeline layout of `sets` holds beyond the device's `limits`, for a warning that names it: the first
   * kind of descriptor CountDescriptors counts of which one shader stage sees more than maxPerStageDescriptor*
   * allows (or of all of them more than maxPerStageResources), or the layout holds more than maxDescriptorSet*
   * allows. Empty when the layout keeps to those limits, which every set layout alone may do while the pipeline
   * layout does not.
   */
  inline std::string LayoutBeyondLimits(
    const VkPhysicalDeviceLimits& limits,
    const std::initializer_list<SetBindings> sets
  )
  {
    const auto beyond = [](const char* const what, const std::uint32_t count, const std::uint32_t limit) {
      return std::to_string(count) + " " + what + ", where the device allows " + std::to_string(limit);
    };
    for (const VkShaderStageFlagBits stage :
         {VK_SHADER_STAGE_VERTEX_BIT,
          VK_SHADER_STAGE_TESSELLATION_CONTROL_BIT,
          VK_SHADER_STAGE_TESSELLATION_EVALUATION_BIT,
          VK_SHADER_STAGE_GEOMETRY_BIT,
          VK_SHADER_STAGE_FRAGMENT_BIT,
          VK_SHADER_STAGE_COMPUTE_BIT}) {
      const DescriptorCounts seen = CountDescriptors(sets, stage);
      if (seen.sampledImages > limits.maxPerStageDescriptorSampledImages) {
        return beyond("sampled images in a stage", seen.sampledImages, limits.maxPerStageDescriptorSampledImages);
      }
      if (seen.samplers > limits.maxPerStageDescriptorSamplers) {
        return beyond("samplers in a stage", seen.samplers, limits.maxPerStageDescriptorSamplers);
      }
      if (seen.storageBuffers > limits.maxPerStageDescriptorStorageBuffers) {
        return beyond("storage buffers in a stage", seen.storageBuffers, limits.maxPerStageDescriptorStorageBuffers);
      }
      if (seen.uniformBuffers > limits.maxPerStageDescriptorUniformBuffers) {
        return beyond("uniform buffers in a stage", seen.uniformBuffers, limits.maxPerStageDescriptorUniformBuffers);
      }
      const std::uint32_t resources = seen.sampledImages + seen.storageBuffers + seen.uniformBuffers;
      if (resources > limits.maxPerStageResources) {
        return beyond("resources in a stage", resources, limits.maxPerStageResources);
      }
    }
    const DescriptorCounts held = CountDescriptors(sets, VK_SHADER_STAGE_ALL);
    if (held.sampledImages > limits.maxDescriptorSetSampledImages) {
      return beyond("sampled images in the layout", held.sampledImages, limits.maxDescriptorSetSampledImages);
    }
    if (held.samplers > limits.maxDescriptorSetSamplers) {
      return beyond("samplers in the layout", held.samplers, limits.maxDescriptorSetSamplers);
    }
    if (held.storageBuffers > limits.maxDescriptorSetStorageBuffers) {
      return beyond("storage buffers in the layout", held.storageBuffers, limits.maxDescriptorSetStorageBuffers);
    }
    if (held.uniformBuffers > limits.maxDescriptorSetUniformBuffers) {
      return beyond("uniform buffers in the layout", held.uniformBuffers, limits.maxDescriptorSetUniformBuffers);
    }
    return {};
  }

  /** Whether a compute work group of `size` threads, as the module declares it, fits the device's `limits`. */
  inline bool WorkGroupFits(
    const VkPhysicalDeviceLimits& limits,
    const std::uint32_t (&size)[3]
  ) noexcept
  {
    const std::uint64_t threads = std::uint64_t{size[0]} * size[1] * size[2];
    return size[0] <= limits.maxComputeWorkGroupSize[0] && size[1] <= limits.maxComputeWorkGroupSize[1] &&
      size[2] <= limits.maxComputeWorkGroupSize[2] && threads <= limits.maxComputeWorkGroupInvocations;
  }

  /**
   * The device's last fragment input location: four components each, of maxFragmentInputComponents as the device
   * reports it. Vulkan promises at least 64, 16 locations; a device that reports fewer gets its own, and one with
   * fewer than four components location 0.
   */
  inline std::uint32_t LastFragmentInputLocation(
    const VkPhysicalDeviceLimits& limits
  ) noexcept
  {
    return std::max(limits.maxFragmentInputComponents / 4U, 1U) - 1U;
  }

  /**
   * The depth bias clamp a pipeline takes: the rasterizer state's on a device made with the depthBiasClamp
   * feature, else 0, the only clamp Vulkan allows without it.
   */
  inline float PipelineDepthBiasClamp(
    const bool depthBiasClampFeature,
    const float clamp
  ) noexcept
  {
    return depthBiasClampFeature ? clamp : 0.0f;
  }
} // namespace gpg::gal::vulkan
