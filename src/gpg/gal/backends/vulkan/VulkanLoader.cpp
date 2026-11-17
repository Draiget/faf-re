// FAF addition, not in the shipped binary: see VulkanLoader.h.

#include "VulkanLoader.h"

#if FAFRE_PLATFORM_MACOS // MoltenVK's path beside the executable
#include <filesystem>

#include "platform/posix/SystemPosix.h"
#endif

namespace gpg::gal::vulkan
{
  Functions& Vk()
  {
    static Functions functions;
    return functions;
  }

  bool Functions::LoadGlobal()
  {
    if (module != nullptr) {
      return true;
    }
#if FAFRE_PLATFORM_WINDOWS
    module = ::LoadLibraryA("vulkan-1.dll");
#elif FAFRE_PLATFORM_MACOS // MoltenVK, Vulkan over Metal: macOS has no system Vulkan
    // The macOS client (issue #263): MoltenVK beside the executable is the whole Vulkan API, with no
    // loader in between; a system loader (the Vulkan SDK's or Homebrew's) when it isn't there.
    // LoadLibraryA is dlopen here.
    const std::filesystem::path beside = std::filesystem::path(platform::posix::ExecutablePath()).parent_path();
    module = ::LoadLibraryA((beside / "libMoltenVK.dylib").c_str());
    if (module == nullptr) {
      module = ::LoadLibraryA("libvulkan.1.dylib");
    }
#else
    // The Linux client (issue #255): the Vulkan loader's soname; LoadLibraryA is dlopen there.
    module = ::LoadLibraryA("libvulkan.so.1");
#endif
    if (module == nullptr) {
      return false;
    }
    vkGetInstanceProcAddr =
      reinterpret_cast<PFN_vkGetInstanceProcAddr>(::GetProcAddress(module, "vkGetInstanceProcAddr"));
    if (vkGetInstanceProcAddr == nullptr) {
      Unload();
      return false;
    }
#define FAF_VK_LOAD_GLOBAL(name) name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(nullptr, #name));
    FAF_VK_GLOBAL_FUNCTIONS(FAF_VK_LOAD_GLOBAL)
#undef FAF_VK_LOAD_GLOBAL
    return vkCreateInstance != nullptr && vkEnumerateInstanceExtensionProperties != nullptr;
  }

  bool Functions::LoadInstance(
    const VkInstance instance
  )
  {
    bool complete = true;
#define FAF_VK_LOAD_INSTANCE(name)                                                                                     \
  name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(instance, #name));                                         \
  complete = complete && (name != nullptr);
    FAF_VK_INSTANCE_FUNCTIONS(FAF_VK_LOAD_INSTANCE)
#undef FAF_VK_LOAD_INSTANCE
#define FAF_VK_LOAD_OPTIONAL(name) name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(instance, #name));
    FAF_VK_DEBUG_FUNCTIONS(FAF_VK_LOAD_OPTIONAL)
#undef FAF_VK_LOAD_OPTIONAL
    return complete;
  }

  bool Functions::LoadDevice(
    const VkDevice device
  )
  {
    bool complete = true;
#define FAF_VK_LOAD_DEVICE(name)                                                                                       \
  name = reinterpret_cast<PFN_##name>(vkGetDeviceProcAddr(device, #name));                                             \
  complete = complete && (name != nullptr);
    FAF_VK_DEVICE_FUNCTIONS(FAF_VK_LOAD_DEVICE)
#undef FAF_VK_LOAD_DEVICE
    return complete;
  }

  bool Functions::LoadRay(
    const VkDevice device
  )
  {
    bool complete = true;
#define FAF_VK_LOAD_RAY(name)                                                                                          \
  name = reinterpret_cast<PFN_##name>(vkGetDeviceProcAddr(device, #name));                                             \
  complete = complete && (name != nullptr);
    FAF_VK_RAY_FUNCTIONS(FAF_VK_LOAD_RAY)
#undef FAF_VK_LOAD_RAY
    return complete;
  }

  void Functions::Unload() noexcept
  {
    if (module != nullptr) {
      ::FreeLibrary(module);
    }
    *this = Functions{};
  }
} // namespace gpg::gal::vulkan
