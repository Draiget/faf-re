// FAF addition, not in the shipped binary: see VulkanSurface.h.

#include <windows.h>

#define VK_USE_PLATFORM_WIN32_KHR
#include "VulkanSurface.h"

namespace gpg::gal::vulkan
{
  const char* PlatformSurfaceExtension() noexcept
  {
    return VK_KHR_WIN32_SURFACE_EXTENSION_NAME;
  }

  VkSurfaceKHR CreateWindowSurface(const VkInstance instance, void* const window, VkResult& result)
  {
    const auto create =
      reinterpret_cast<PFN_vkCreateWin32SurfaceKHR>(Vk().vkGetInstanceProcAddr(instance, "vkCreateWin32SurfaceKHR"));
    if (create == nullptr) {
      result = VK_ERROR_EXTENSION_NOT_PRESENT;
      return VK_NULL_HANDLE;
    }
    VkWin32SurfaceCreateInfoKHR info{};
    info.sType = VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
    info.hinstance = ::GetModuleHandleW(nullptr);
    info.hwnd = static_cast<HWND>(window);
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    result = create(instance, &info, nullptr, &surface);
    return (result == VK_SUCCESS) ? surface : VK_NULL_HANDLE;
  }
} // namespace gpg::gal::vulkan
