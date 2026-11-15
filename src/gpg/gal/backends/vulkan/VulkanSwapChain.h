// FAF addition: what DeviceVulkan::CreateSwapChain makes a window's swap chain with, from what its surface
// supports, and when a suboptimal one is made again. A desktop surface has all the engine asks for; Android's
// window surfaces have no B8G8R8A8 format, only INHERIT for composite alpha, and a current transform that turns
// the image on a phone's portrait panel.
#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include <vulkan/vulkan_core.h>

namespace gpg::gal::vulkan
{
  /**
   * B8G8R8A8_UNORM, the engine's back buffer format, else R8G8B8A8_UNORM, in sRGB's nonlinear colour space:
   * the back buffer target stays B8G8R8A8 to the engine, and copies and readbacks put the channels in order
   * (OtherChannelOrder). Without `bgra` (FAF_GAL_NO_BGRA) B8G8R8A8 is left out, and only R8G8B8A8 will do.
   * VK_FORMAT_UNDEFINED when the surface has neither that will do. A surface that lists no format, which
   * Vulkan does not allow, is taken to have B8G8R8A8_UNORM.
   */
  inline VkSurfaceFormatKHR ChooseSurfaceFormat(
    const std::vector<VkSurfaceFormatKHR>& formats,
    const bool bgra
  )
  {
    if (formats.empty()) {
      return {bgra ? VK_FORMAT_B8G8R8A8_UNORM : VK_FORMAT_UNDEFINED, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR};
    }
    for (const VkFormat wanted : {VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM}) {
      if (wanted == VK_FORMAT_B8G8R8A8_UNORM && !bgra) {
        continue;
      }
      for (const VkSurfaceFormatKHR& format : formats) {
        if (format.format == wanted && format.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
          return format;
        }
      }
    }
    return {VK_FORMAT_UNDEFINED, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR};
  }

  /** What the engine does with a back buffer's images: draws into them, copies from and into them, samples them. */
  inline constexpr VkImageUsageFlags kSwapChainUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
    VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;

  /**
   * The usage of kSwapChainUsage the surface does not support, which a swap chain may not ask for. Desktop and
   * Android window surfaces support all of it.
   */
  inline VkImageUsageFlags MissingSwapChainUsage(
    const VkSurfaceCapabilitiesKHR& capabilities
  )
  {
    return kSwapChainUsage & ~capabilities.supportedUsageFlags;
  }

  /**
   * Opaque where the surface has it, else the first mode it has: Android's surfaces have only INHERIT, the
   * window saying for itself, and the game's is opaque.
   */
  inline VkCompositeAlphaFlagBitsKHR SwapChainCompositeAlpha(
    const VkSurfaceCapabilitiesKHR& capabilities
  )
  {
    const VkCompositeAlphaFlagsKHR supported = capabilities.supportedCompositeAlpha;
    if ((supported & VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR) != 0U) {
      return VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    }
    return static_cast<VkCompositeAlphaFlagBitsKHR>(supported & (~supported + 1U));
  }

  /**
   * The identity where the surface allows it: the engine draws upright, and the compositor turns the image to
   * the display. The current transform says how the display stands against the panel's own orientation (a
   * phone's panel is portrait, the game landscape); a swap chain made with it promises images turned already.
   */
  inline VkSurfaceTransformFlagBitsKHR SwapChainPreTransform(
    const VkSurfaceCapabilitiesKHR& capabilities
  )
  {
    return ((capabilities.supportedTransforms & VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR) != 0U)
      ? VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR
      : capabilities.currentTransform;
  }

  /**
   * The size of a swap chain for a window of `width` x `height`: the surface's current extent, where it has one
   * (not 0xFFFFFFFF, which leaves the size to the swap chain), within the extents the surface allows.
   */
  inline VkExtent2D SwapChainExtent(
    const VkSurfaceCapabilitiesKHR& capabilities,
    const std::uint32_t width,
    const std::uint32_t height
  ) noexcept
  {
    VkExtent2D extent{width, height};
    if (capabilities.currentExtent.width != 0xFFFFFFFFU) {
      extent = capabilities.currentExtent;
    }
    extent.width =
      std::clamp(extent.width, capabilities.minImageExtent.width, std::max(capabilities.maxImageExtent.width, 1U));
    extent.height =
      std::clamp(extent.height, capabilities.minImageExtent.height, std::max(capabilities.maxImageExtent.height, 1U));
    return extent;
  }

  /**
   * Whether a scaled head's swap chain of `extent`, made with `preTransform`, that an acquire or a present
   * answered VK_SUBOPTIMAL_KHR is made again before the next acquire. Android 10 and later answer it to every
   * present while a swap chain's pre-transform is not the window's current transform, which SwapChainPreTransform's
   * identity is on a turned phone panel: a new one would take the identity again and be as suboptimal, after a
   * wait for the device, every frame. Such a swap chain is made again only where a new one would differ: in size,
   * or in pre-transform (a surface without the identity, whose transform the swap chain took, has turned since).
   * Any other is made again as before; a desktop surface answers it when the window's size changed.
   */
  inline bool RemakeSuboptimalSwapChain(
    const VkSurfaceCapabilitiesKHR& capabilities,
    const VkSurfaceTransformFlagBitsKHR preTransform,
    const VkExtent2D extent
  ) noexcept
  {
    if (preTransform == capabilities.currentTransform || preTransform != SwapChainPreTransform(capabilities)) {
      return true;
    }
    const VkExtent2D next = SwapChainExtent(capabilities, extent.width, extent.height);
    return next.width != extent.width || next.height != extent.height;
  }

  /**
   * Whether `first` and `second` are 8-bit RGBA and BGRA, one each, of one encoding (both UNORM or both sRGB):
   * the same pixels with red and blue in each other's place, which vkCmdCopyImage copies as bits and a blit of
   * the same size puts in order. Between UNORM and sRGB a blit would convert the values as well.
   */
  inline bool OtherChannelOrder(
    const VkFormat first,
    const VkFormat second
  )
  {
    const auto swapped = [](const VkFormat a, const VkFormat b) {
      return (a == VK_FORMAT_R8G8B8A8_UNORM && b == VK_FORMAT_B8G8R8A8_UNORM) ||
        (a == VK_FORMAT_R8G8B8A8_SRGB && b == VK_FORMAT_B8G8R8A8_SRGB);
    };
    return swapped(first, second) || swapped(second, first);
  }
} // namespace gpg::gal::vulkan
