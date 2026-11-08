// FAF addition: synchronization scopes for dynamic-rendering attachment reuse.
#include "gpg/gal/backends/vulkan/VulkanAttachmentBarrier.h"

#include <cstdint>

#include <gtest/gtest.h>

namespace
{
  struct AttachmentCase
  {
    VkImageLayout layout;
    VkImageAspectFlags aspect;
    VkPipelineStageFlags2 stages;
    VkAccessFlags2 read;
    VkAccessFlags2 write;
  };

  VkImage TestImage()
  {
#if VK_USE_64_BIT_PTR_DEFINES
    return reinterpret_cast<VkImage>(std::uintptr_t{0x1234U});
#else
    return static_cast<VkImage>(0x1234U);
#endif
  }

  class VulkanAttachmentBarrier : public testing::TestWithParam<AttachmentCase> {};

  TEST_P(VulkanAttachmentBarrier, AttachmentWritesBecomeVisibleToReadsAndWrites)
  {
    const auto& c = GetParam();
    const auto barrier = gpg::gal::vulkan::AttachmentWriteBarrier(TestImage(), c.layout, c.aspect);
    EXPECT_EQ(barrier.srcStageMask, c.stages);
    EXPECT_EQ(barrier.dstStageMask, c.stages);
    EXPECT_EQ(barrier.srcAccessMask, c.write);
    EXPECT_EQ(barrier.dstAccessMask, c.read | c.write);
  }

  TEST_P(VulkanAttachmentBarrier, KeepsLayoutAndCurrentAttachmentSubresource)
  {
    const auto& c = GetParam();
    const auto image = TestImage();
    const auto barrier = gpg::gal::vulkan::AttachmentWriteBarrier(image, c.layout, c.aspect);
    EXPECT_EQ(barrier.sType, VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER_2);
    EXPECT_EQ(barrier.pNext, nullptr);
    EXPECT_EQ(barrier.oldLayout, c.layout);
    EXPECT_EQ(barrier.newLayout, c.layout);
    EXPECT_EQ(barrier.image, image);
    EXPECT_EQ(barrier.srcQueueFamilyIndex, VK_QUEUE_FAMILY_IGNORED);
    EXPECT_EQ(barrier.dstQueueFamilyIndex, VK_QUEUE_FAMILY_IGNORED);
    EXPECT_EQ(barrier.subresourceRange.aspectMask, c.aspect);
    EXPECT_EQ(barrier.subresourceRange.baseMipLevel, 0U);
    EXPECT_EQ(barrier.subresourceRange.levelCount, 1U);
    EXPECT_EQ(barrier.subresourceRange.baseArrayLayer, 0U);
    EXPECT_EQ(barrier.subresourceRange.layerCount, 1U);
  }

  INSTANTIATE_TEST_SUITE_P(
    ColorDepthStencil, VulkanAttachmentBarrier,
    testing::Values(
      AttachmentCase{VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, VK_IMAGE_ASPECT_COLOR_BIT,
                     VK_PIPELINE_STAGE_2_COLOR_ATTACHMENT_OUTPUT_BIT,
                     VK_ACCESS_2_COLOR_ATTACHMENT_READ_BIT, VK_ACCESS_2_COLOR_ATTACHMENT_WRITE_BIT},
      AttachmentCase{VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL, VK_IMAGE_ASPECT_DEPTH_BIT,
                     VK_PIPELINE_STAGE_2_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_2_LATE_FRAGMENT_TESTS_BIT,
                     VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_READ_BIT, VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT},
      AttachmentCase{VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
                     VK_IMAGE_ASPECT_DEPTH_BIT | VK_IMAGE_ASPECT_STENCIL_BIT,
                     VK_PIPELINE_STAGE_2_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_2_LATE_FRAGMENT_TESTS_BIT,
                     VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_READ_BIT, VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT}));
}
