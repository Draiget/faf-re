// FAF addition, not in the shipped binary: see VulkanLoader.h.

#include "VulkanLoader.h"

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
    module = ::LoadLibraryA("vulkan-1.dll");
    if (module == nullptr) {
      return false;
    }
    vkGetInstanceProcAddr = reinterpret_cast<PFN_vkGetInstanceProcAddr>(::GetProcAddress(module, "vkGetInstanceProcAddr"));
    if (vkGetInstanceProcAddr == nullptr) {
      Unload();
      return false;
    }
#define FAF_VK_LOAD_GLOBAL(name) name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(nullptr, #name));
    FAF_VK_GLOBAL_FUNCTIONS(FAF_VK_LOAD_GLOBAL)
#undef FAF_VK_LOAD_GLOBAL
    return vkCreateInstance != nullptr && vkEnumerateInstanceExtensionProperties != nullptr;
  }

  bool Functions::LoadInstance(const VkInstance instance)
  {
    bool complete = true;
#define FAF_VK_LOAD_INSTANCE(name)                                                     \
  name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(instance, #name));         \
  complete = complete && (name != nullptr);
    FAF_VK_INSTANCE_FUNCTIONS(FAF_VK_LOAD_INSTANCE)
#undef FAF_VK_LOAD_INSTANCE
#define FAF_VK_LOAD_OPTIONAL(name) name = reinterpret_cast<PFN_##name>(vkGetInstanceProcAddr(instance, #name));
    FAF_VK_DEBUG_FUNCTIONS(FAF_VK_LOAD_OPTIONAL)
#undef FAF_VK_LOAD_OPTIONAL
    return complete;
  }

  bool Functions::LoadDevice(const VkDevice device)
  {
    bool complete = true;
#define FAF_VK_LOAD_DEVICE(name)                                                       \
  name = reinterpret_cast<PFN_##name>(vkGetDeviceProcAddr(device, #name));             \
  complete = complete && (name != nullptr);
    FAF_VK_DEVICE_FUNCTIONS(FAF_VK_LOAD_DEVICE)
#undef FAF_VK_LOAD_DEVICE
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
