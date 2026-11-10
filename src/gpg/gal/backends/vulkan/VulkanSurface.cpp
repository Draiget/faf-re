// FAF addition, not in the shipped binary: see VulkanSurface.h.

#if defined(_WIN32)
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
#else
// The Linux client (issue #255): the window is SDL3's (an SDL_Window*, the handle the window system
// gives the wx stand-in's windows, issue #256), and SDL3 knows whether it is X11 or Wayland: it
// names the surface extension and creates the surface.
#include <cstring>

#include "VulkanSurface.h"

#include <SDL3/SDL_vulkan.h>

namespace gpg::gal::vulkan
{
  const char* PlatformSurfaceExtension() noexcept
  {
    Uint32 count = 0;
    const char* const* const names = SDL_Vulkan_GetInstanceExtensions(&count);
    for (Uint32 index = 0; names != nullptr && index < count; ++index) {
      if (std::strcmp(names[index], VK_KHR_SURFACE_EXTENSION_NAME) != 0) {
        return names[index];
      }
    }
    return "VK_KHR_xlib_surface";  // SDL's video isn't up: the X11 one, which XWayland serves too
  }

  VkSurfaceKHR CreateWindowSurface(const VkInstance instance, void* const window, VkResult& result)
  {
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    if (window == nullptr || !SDL_Vulkan_CreateSurface(static_cast<SDL_Window*>(window), instance, nullptr, &surface)) {
      result = VK_ERROR_INITIALIZATION_FAILED;
      return VK_NULL_HANDLE;
    }
    result = VK_SUCCESS;
    return surface;
  }
} // namespace gpg::gal::vulkan
#endif
