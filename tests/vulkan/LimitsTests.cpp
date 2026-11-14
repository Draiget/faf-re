// FAF addition: what DeviceVulkan checks against a device's limits (src/gpg/gal/backends/vulkan/VulkanLimits.h),
// with limits made up here: Vulkan 1.3's required minimums (the specification's "Required Limits" table), which
// a phone's GPU may report, and a desktop GPU's.
#include "gpg/gal/backends/vulkan/VulkanLimits.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using gpg::gal::vulkan::CountDescriptors;
using gpg::gal::vulkan::DescriptorCounts;
using gpg::gal::vulkan::LayoutBeyondLimits;
using gpg::gal::vulkan::SetBindings;

namespace
{
  constexpr VkShaderStageFlags kGraphics = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
  constexpr VkShaderStageFlags kGpuStages = kGraphics | VK_SHADER_STAGE_COMPUTE_BIT;

  VkPhysicalDeviceLimits MinimumLimits()
  {
    VkPhysicalDeviceLimits limits{};
    limits.maxPerStageDescriptorSamplers = 16U;
    limits.maxPerStageDescriptorUniformBuffers = 12U;
    limits.maxPerStageDescriptorStorageBuffers = 4U;
    limits.maxPerStageDescriptorSampledImages = 16U;
    limits.maxPerStageResources = 128U;
    limits.maxDescriptorSetSamplers = 96U;
    limits.maxDescriptorSetUniformBuffers = 72U;
    limits.maxDescriptorSetStorageBuffers = 24U;
    limits.maxDescriptorSetSampledImages = 96U;
    limits.maxComputeWorkGroupInvocations = 128U;
    limits.maxComputeWorkGroupSize[0] = 128U;
    limits.maxComputeWorkGroupSize[1] = 128U;
    limits.maxComputeWorkGroupSize[2] = 64U;
    limits.maxFragmentInputComponents = 64U;
    return limits;
  }

  VkPhysicalDeviceLimits DesktopLimits()
  {
    VkPhysicalDeviceLimits limits = MinimumLimits();
    limits.maxPerStageDescriptorSamplers = 1000000U;
    limits.maxPerStageDescriptorUniformBuffers = 1000000U;
    limits.maxPerStageDescriptorStorageBuffers = 1000000U;
    limits.maxPerStageDescriptorSampledImages = 1000000U;
    limits.maxPerStageResources = 0xFFFFFFFFU;
    limits.maxDescriptorSetSamplers = 1000000U;
    limits.maxDescriptorSetUniformBuffers = 1000000U;
    limits.maxDescriptorSetStorageBuffers = 1000000U;
    limits.maxDescriptorSetSampledImages = 1000000U;
    limits.maxComputeWorkGroupInvocations = 1024U;
    limits.maxComputeWorkGroupSize[0] = 1024U;
    limits.maxComputeWorkGroupSize[1] = 1024U;
    limits.maxComputeWorkGroupSize[2] = 1024U;
    limits.maxFragmentInputComponents = 128U;
    return limits;
  }

  VkDescriptorSetLayoutBinding Binding(
    const std::uint32_t binding,
    const VkDescriptorType type,
    const std::uint32_t count,
    const VkShaderStageFlags stages
  )
  {
    return {binding, type, count, stages, nullptr};
  }

  SetBindings Set(
    const std::vector<VkDescriptorSetLayoutBinding>& bindings
  )
  {
    return {bindings.data(), static_cast<std::uint32_t>(bindings.size())};
  }

  /**
   * A hand-made copy of the GPU programs' set that DeviceVulkan::CreateGpuDrivenObjects makes: b0, t0..t3, t4..t5,
   * u0..u1, s0, t6.
   */
  std::vector<VkDescriptorSetLayoutBinding> GpuProgramSet()
  {
    std::vector<VkDescriptorSetLayoutBinding> set{Binding(0U, VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1U, kGpuStages)};
    for (std::uint32_t binding = 1U; binding <= 4U; ++binding) {
      set.push_back(Binding(binding, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1U, kGpuStages));
    }
    set.push_back(Binding(5U, VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1U, kGpuStages));
    set.push_back(Binding(6U, VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1U, kGpuStages));
    set.push_back(Binding(7U, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1U, kGpuStages));
    set.push_back(Binding(8U, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1U, kGpuStages));
    set.push_back(Binding(9U, VK_DESCRIPTOR_TYPE_SAMPLER, 1U, kGpuStages));
    set.push_back(Binding(10U, VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1U, kGpuStages));
    return set;
  }

  /** A hand-made copy of the ray-traced scene's set that DeviceVulkan::CreateLayouts makes with ray queries. */
  std::vector<VkDescriptorSetLayoutBinding> RaySceneSet()
  {
    return {
      Binding(0U, VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR, 1U, kGpuStages),
      Binding(1U, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1U, kGpuStages),
      Binding(2U, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1U, kGpuStages),
      Binding(3U, VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 64U, kGpuStages),
      Binding(4U, VK_DESCRIPTOR_TYPE_SAMPLER, 1U, kGpuStages),
    };
  }

  /** A hand-made copy of the effects' set 0 that DeviceVulkan::CreateLayouts makes: 64 textures, then 64 samplers. */
  std::vector<VkDescriptorSetLayoutBinding> EffectTextureSet()
  {
    std::vector<VkDescriptorSetLayoutBinding> set;
    for (std::uint32_t binding = 0U; binding < 128U; ++binding) {
      set.push_back(
        Binding(binding, (binding < 64U) ? VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE : VK_DESCRIPTOR_TYPE_SAMPLER, 1U, kGraphics)
      );
    }
    return set;
  }
} // namespace

TEST(
  VulkanLimits,
  DescriptorsCountForTheStagesThatSeeThem
)
{
  const std::vector<VkDescriptorSetLayoutBinding> set{
    Binding(0U, VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 2U, VK_SHADER_STAGE_FRAGMENT_BIT),
    Binding(1U, VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 3U, kGraphics),
    Binding(2U, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 1U, VK_SHADER_STAGE_VERTEX_BIT),
    Binding(3U, VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC, 1U, kGraphics),
    Binding(4U, VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR, 1U, kGraphics),
  };
  const DescriptorCounts fragment = CountDescriptors({Set(set)}, VK_SHADER_STAGE_FRAGMENT_BIT);
  EXPECT_EQ(fragment.sampledImages, 5U) << "a combined image sampler is a sampled image and a sampler";
  EXPECT_EQ(fragment.samplers, 2U);
  EXPECT_EQ(fragment.storageBuffers, 0U) << "the vertex stage's alone";
  EXPECT_EQ(fragment.uniformBuffers, 1U);
  const DescriptorCounts all = CountDescriptors({Set(set), Set(set)}, VK_SHADER_STAGE_ALL);
  EXPECT_EQ(all.sampledImages, 10U);
  EXPECT_EQ(all.samplers, 4U);
  EXPECT_EQ(all.storageBuffers, 2U);
  EXPECT_EQ(all.uniformBuffers, 2U);
}

TEST(
  VulkanLimits,
  GpuProgramsLayoutHoldsItsSetAndTheRayTracedScene
)
{
  const std::vector<VkDescriptorSetLayoutBinding> programs = GpuProgramSet();
  const std::vector<VkDescriptorSetLayoutBinding> scene = RaySceneSet();
  EXPECT_EQ(LayoutBeyondLimits(DesktopLimits(), {Set(programs), Set(scene)}), "");

  // Vulkan's minimum: the set alone holds 6 storage buffers for every stage, where 4 are promised.
  VkPhysicalDeviceLimits limits = MinimumLimits();
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(programs)}), "6 storage buffers in a stage, where the device allows 4");
  limits.maxPerStageDescriptorStorageBuffers = 6U;
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(programs)}), "");
  // With ray queries the scene's 64 textures and two storage buffers are in the same layout, which a device
  // whose limits the set alone keeps to may not make.
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(programs), Set(scene)}), "67 sampled images in a stage, where the device allows 16"
  );
  limits.maxPerStageDescriptorSampledImages = 67U;
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(programs), Set(scene)}), "8 storage buffers in a stage, where the device allows 6"
  );
  limits.maxPerStageDescriptorStorageBuffers = 8U;
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(programs), Set(scene)}), "");
  // An empty set (the layout's unused set 1) holds nothing.
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(programs), {}, Set(scene)}), "");
}

TEST(
  VulkanLimits,
  EffectsLayoutHoldsItsTexturesConstantsAndTheRayTracedScene
)
{
  const std::vector<VkDescriptorSetLayoutBinding> textures = EffectTextureSet();
  const std::vector<VkDescriptorSetLayoutBinding> constants{
    Binding(0U, VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1U, kGraphics)
  };
  const std::vector<VkDescriptorSetLayoutBinding> scene = RaySceneSet();
  EXPECT_EQ(LayoutBeyondLimits(DesktopLimits(), {Set(textures), Set(constants), Set(scene)}), "");

  // Vulkan's minimum of 16 textures per stage is below the 64 slots an effect has.
  EXPECT_EQ(
    LayoutBeyondLimits(MinimumLimits(), {Set(textures), Set(constants)}),
    "64 sampled images in a stage, where the device allows 16"
  );
  VkPhysicalDeviceLimits limits = DesktopLimits();
  limits.maxPerStageDescriptorSampledImages = 64U;
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(textures), Set(constants)}), "");
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(textures), Set(constants), Set(scene)}),
    "128 sampled images in a stage, where the device allows 64"
  );
  limits.maxPerStageDescriptorSampledImages = 128U;
  limits.maxPerStageDescriptorSamplers = 64U;
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(textures), Set(constants), Set(scene)}),
    "65 samplers in a stage, where the device allows 64"
  );
}

TEST(
  VulkanLimits,
  LayoutLimitsCountEveryStageTogether
)
{
  const std::vector<VkDescriptorSetLayoutBinding> textures = EffectTextureSet();
  const std::vector<VkDescriptorSetLayoutBinding> scene = RaySceneSet();
  // A stage may see all 128 textures, the whole layout hold only Vulkan's minimum of 96.
  VkPhysicalDeviceLimits limits = DesktopLimits();
  limits.maxDescriptorSetSampledImages = 96U;
  EXPECT_EQ(LayoutBeyondLimits(limits, {Set(textures)}), "");
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(textures), Set(scene)}),
    "128 sampled images in the layout, where the device allows 96"
  );
  // maxPerStageResources counts textures, storage and uniform buffers together (not samplers).
  limits = DesktopLimits();
  limits.maxPerStageResources = 128U;
  EXPECT_EQ(
    LayoutBeyondLimits(limits, {Set(textures), Set(scene)}), "130 resources in a stage, where the device allows 128"
  );
}

TEST(
  VulkanLimits,
  WorkGroupsFitTheDevicesSizeAndThreads
)
{
  const VkPhysicalDeviceLimits minimum = MinimumLimits();
  EXPECT_FALSE(gpg::gal::vulkan::WorkGroupFits(minimum, {1024U, 1U, 1U})) << "CompactIconsCS";
  EXPECT_TRUE(gpg::gal::vulkan::WorkGroupFits(DesktopLimits(), {1024U, 1U, 1U}));
  EXPECT_TRUE(gpg::gal::vulkan::WorkGroupFits(minimum, {128U, 1U, 1U}));
  EXPECT_TRUE(gpg::gal::vulkan::WorkGroupFits(minimum, {8U, 8U, 2U}));
  EXPECT_FALSE(gpg::gal::vulkan::WorkGroupFits(minimum, {8U, 8U, 4U})) << "256 threads";
  EXPECT_FALSE(gpg::gal::vulkan::WorkGroupFits(minimum, {1U, 1U, 65U})) << "z beyond 64";
  VkPhysicalDeviceLimits wide = DesktopLimits();
  wide.maxComputeWorkGroupSize[0] = 0xFFFFFFFFU;
  wide.maxComputeWorkGroupSize[1] = 0xFFFFFFFFU;
  EXPECT_FALSE(gpg::gal::vulkan::WorkGroupFits(wide, {0x10000U, 0x10000U, 1U})) << "a product past 32 bits";
}

TEST(
  VulkanLimits,
  LastFragmentInputLocationHasFourComponentsEach
)
{
  VkPhysicalDeviceLimits limits = MinimumLimits();
  EXPECT_EQ(gpg::gal::vulkan::LastFragmentInputLocation(limits), 15U);
  limits.maxFragmentInputComponents = 128U;
  EXPECT_EQ(gpg::gal::vulkan::LastFragmentInputLocation(limits), 31U);
  limits.maxFragmentInputComponents = 32U;
  EXPECT_EQ(gpg::gal::vulkan::LastFragmentInputLocation(limits), 7U) << "below Vulkan's promise: the device's own";
  limits.maxFragmentInputComponents = 2U;
  EXPECT_EQ(gpg::gal::vulkan::LastFragmentInputLocation(limits), 0U) << "less than a location: location 0";
  limits.maxFragmentInputComponents = 0U;
  EXPECT_EQ(gpg::gal::vulkan::LastFragmentInputLocation(limits), 0U);
}

TEST(
  VulkanLimits,
  DepthBiasClampNeedsTheFeature
)
{
  EXPECT_EQ(gpg::gal::vulkan::PipelineDepthBiasClamp(true, 0.25f), 0.25f);
  EXPECT_EQ(gpg::gal::vulkan::PipelineDepthBiasClamp(false, 0.25f), 0.0f);
}
