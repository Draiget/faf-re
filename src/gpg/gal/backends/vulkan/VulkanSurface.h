#pragma once

// FAF addition, not in the shipped binary.
//
// The platform half of the Vulkan backend: the instance extension that makes
// window surfaces and the surface for one window. Only this unit knows the
// window system (VK_KHR_win32_surface); another platform replaces it alone.
//
// A desktop window keeps its surface while the program runs. A platform whose
// window can lose it (an Android activity's goes when the activity goes to the
// back, and comes again when it is in front; it can also change its size in
// place) says so through the last three functions, for each head's window:
// DeviceVulkan's TestCooperativeLevel then lets go of a surface that is no
// longer current and takes the next one. The desktop versions keep the one
// surface; with FAF_GAL_SURFACE_LOSS (VulkanSurface.cpp) they take that route
// on a desktop.

#include "VulkanLoader.h"

namespace gpg::gal::vulkan
{
  /** The platform's surface extension name. */
  [[nodiscard]] const char* PlatformSurfaceExtension() noexcept;

  /**
   * Creates a surface for `window` (an HWND on Windows); VK_NULL_HANDLE on failure, `result` says why:
   * VK_ERROR_SURFACE_LOST_KHR while the window has no surface to make one from (see WaitForWindowSurface).
   */
  [[nodiscard]] VkSurfaceKHR CreateWindowSurface(VkInstance instance, void* window, VkResult& result);

  /** Destroys a surface CreateWindowSurface made, with whatever the platform holds for it. */
  void DestroyWindowSurface(VkInstance instance, VkSurfaceKHR surface) noexcept;

  /**
   * Whether `window` still has the surface CreateWindowSurface made for it last, at the size it had then. True
   * on a desktop, where the surface stays as long as the window.
   */
  [[nodiscard]] bool WindowSurfaceIsCurrent(void* window) noexcept;

  /** Returns once `window` has a surface CreateWindowSurface can make one from; at once on a desktop. */
  void WaitForWindowSurface(void* window) noexcept;
} // namespace gpg::gal::vulkan
