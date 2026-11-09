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

  // The stages and accesses that use an image in `layout`, for one side of a layout change
  // (`ren_VulkanPreciseBarriers`): as the source, the writes to make available; as the
  // destination, the reads and writes to make them visible to. False for a layout without a
  // narrow scope (undefined, present, general): the change then waits for and holds everything.
  inline bool LayoutScope(const VkImageLayout layout, const bool source, VkPipelineStageFlags2& stages, VkAccessFlags2& access)
  {
    switch (layout) {
    case VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL:
      stages = VK_PIPELINE_STAGE_2_COLOR_ATTACHMENT_OUTPUT_BIT;
      access = source ? VK_ACCESS_2_COLOR_ATTACHMENT_WRITE_BIT
                      : (VK_ACCESS_2_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_2_COLOR_ATTACHMENT_WRITE_BIT);
      return true;
    case VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL:
      stages = VK_PIPELINE_STAGE_2_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_2_LATE_FRAGMENT_TESTS_BIT;
      access = source ? VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT
                      : (VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_READ_BIT | VK_ACCESS_2_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT);
      return true;
    case VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL:
      // Sampled by vertex, tessellation, pixel or compute shaders; reads leave nothing to make available.
      stages = VK_PIPELINE_STAGE_2_PRE_RASTERIZATION_SHADERS_BIT | VK_PIPELINE_STAGE_2_FRAGMENT_SHADER_BIT
        | VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT;
      access = source ? VK_ACCESS_2_NONE : VK_ACCESS_2_SHADER_READ_BIT;
      return true;
    case VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL:
      stages = VK_PIPELINE_STAGE_2_ALL_TRANSFER_BIT;
      access = source ? VK_ACCESS_2_NONE : VK_ACCESS_2_TRANSFER_READ_BIT;
      return true;
    case VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL:
      stages = VK_PIPELINE_STAGE_2_ALL_TRANSFER_BIT;
      access = VK_ACCESS_2_TRANSFER_WRITE_BIT;
      return true;
    default:
      return false;
    }
  }
}
