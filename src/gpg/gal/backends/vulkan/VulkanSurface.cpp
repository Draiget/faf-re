// FAF addition, not in the shipped binary: see VulkanSurface.h.

#include <chrono>
#include <cstdlib>
#include <thread>

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>

#define VK_USE_PLATFORM_WIN32_KHR
#include "VulkanSurface.h"

namespace gpg::gal::vulkan
{
  const char* PlatformSurfaceExtension() noexcept
  {
    return VK_KHR_WIN32_SURFACE_EXTENSION_NAME;
  }

  namespace
  {
    VkSurfaceKHR CreatePlatformSurface(
      const VkInstance instance,
      void* const window,
      VkResult& result
    )
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
  } // namespace
} // namespace gpg::gal::vulkan
#else
// The Linux client (issue #255): the window is SDL3's (an SDL_Window*, the handle the window system
// gives the application shell windows, issue #256), and SDL3 knows whether it is X11 or Wayland: it
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
    return "VK_KHR_xlib_surface"; // SDL's video isn't up: the X11 one, which XWayland serves too
  }

  namespace
  {
    VkSurfaceKHR CreatePlatformSurface(
      const VkInstance instance,
      void* const window,
      VkResult& result
    )
    {
      VkSurfaceKHR surface = VK_NULL_HANDLE;
      if (
        window == nullptr || !SDL_Vulkan_CreateSurface(static_cast<SDL_Window*>(window), instance, nullptr, &surface)
      ) {
        result = VK_ERROR_INITIALIZATION_FAILED;
        return VK_NULL_HANDLE;
      }
      result = VK_SUCCESS;
      return surface;
    }
  } // namespace
} // namespace gpg::gal::vulkan
#endif

namespace gpg::gal::vulkan
{
  // A desktop window's surface stays while the program runs: nothing to wait for or to let go of, unless the
  // diagnostic below lets it go.
  namespace
  {
    using Clock = std::chrono::steady_clock;

    /**
     * Diagnostics: FAF_GAL_SURFACE_LOSS=<seconds> lets each surface go after that many seconds, and the window has
     * none for a second after it: the route an Android activity's surface takes when the activity goes to the back
     * and comes again (DeviceVulkan::TestCooperativeLevel). Zero without it, which leaves the surface alone. One
     * clock serves every window.
     */
    [[nodiscard]] Clock::duration SurfaceLifetime() noexcept
    {
      static const Clock::duration lifetime = [] {
        const char* const value = std::getenv("FAF_GAL_SURFACE_LOSS");
        const long seconds = (value != nullptr) ? std::strtol(value, nullptr, 10) : 0L;
        return Clock::duration(std::chrono::seconds((seconds > 0L) ? seconds : 0L));
      }();
      return lifetime;
    }

    constexpr std::chrono::seconds kSurfaceGap{1};
    // Only the device's thread makes and destroys surfaces (DeviceVulkan, under its lock).
    Clock::time_point gSurfaceMade{};
    Clock::time_point gSurfaceDestroyed{};

    [[nodiscard]] bool InSurfaceGap() noexcept
    {
      return SurfaceLifetime() != Clock::duration::zero() && Clock::now() - gSurfaceDestroyed < kSurfaceGap;
    }
  } // namespace

  VkSurfaceKHR CreateWindowSurface(
    const VkInstance instance,
    void* const window,
    VkResult& result
  )
  {
    if (InSurfaceGap()) {
      result = VK_ERROR_SURFACE_LOST_KHR;
      return VK_NULL_HANDLE;
    }
    gSurfaceMade = Clock::now();
    return CreatePlatformSurface(instance, window, result);
  }

  void DestroyWindowSurface(
    const VkInstance instance,
    const VkSurfaceKHR surface
  ) noexcept
  {
    Vk().vkDestroySurfaceKHR(instance, surface, nullptr);
    gSurfaceDestroyed = Clock::now();
  }

  bool WindowSurfaceIsCurrent(
    void* const window
  ) noexcept
  {
    static_cast<void>(window);
    return SurfaceLifetime() == Clock::duration::zero() || Clock::now() - gSurfaceMade < SurfaceLifetime();
  }

  void WaitForWindowSurface(
    void* const window
  ) noexcept
  {
    static_cast<void>(window);
    while (InSurfaceGap()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
} // namespace gpg::gal::vulkan
