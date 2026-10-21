#pragma once

// FAF addition, not in the shipped binary.
//
// The platform half of the Vulkan backend: the instance extension that makes
// window surfaces and the surface for one window. Only this unit knows the
// window system (VK_KHR_win32_surface); another platform replaces it alone.

#include "VulkanLoader.h"

namespace gpg::gal::vulkan
{
  /** The platform's surface extension name. */
  [[nodiscard]] const char* PlatformSurfaceExtension() noexcept;

  /** Creates a surface for `window` (an HWND on Windows); VK_NULL_HANDLE on failure, `result` says why. */
  [[nodiscard]] VkSurfaceKHR CreateWindowSurface(VkInstance instance, void* window, VkResult& result);
} // namespace gpg::gal::vulkan
