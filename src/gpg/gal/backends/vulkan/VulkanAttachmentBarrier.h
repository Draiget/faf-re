// FAF addition: the dependency between consecutive dynamic-rendering instances.
#pragma once

#include <vulkan/vulkan_core.h>

namespace gpg::gal::vulkan
{
  // layout is COLOR_ATTACHMENT_OPTIMAL or DEPTH_STENCIL_ATTACHMENT_OPTIMAL.
  // Current attachment views address mip 0 and layer 0 only.
  inline VkImageMemoryBarrier2 AttachmentWriteBarrier(const VkImage image, const VkImageLayout layout,
                                                    const VkImageAspectFlags aspect)
  {
    const bool color = layout == VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    const VkPipelineStageFlags2 stages = color
      ? VK_PIPELINE_STAGE_2_COLOR_ATTACHMENT_OUTPUT_BIT
      : VK_PIPELINE_STAGE_2_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_2_LATE_FRAGMENT_TESTS_BIT;
    const VkAccessFlags2 read = color
      ? VK_ACCESS_2_COLOR_ATTACHMENT_READ_BIT : VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_READ_BIT;
    const VkAccessFlags2 write = color
      ? VK_ACCESS_2_COLOR_ATTACHMENT_WRITE_BIT : VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    VkImageMemoryBarrier2 barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER_2;
    barrier.srcStageMask = stages;
    barrier.srcAccessMask = write;
    barrier.dstStageMask = stages;
    barrier.dstAccessMask = read | write;
    barrier.oldLayout = layout;
    barrier.newLayout = layout;
    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.image = image;
    barrier.subresourceRange = {aspect, 0U, 1U, 0U, 1U};
    return barrier;
  }
}
