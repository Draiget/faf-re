// FAF addition, not in the shipped binary: the Vulkan gal device.

#include "DeviceVulkan.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <d3dcompiler.h>
#include <wrl/client.h>

#include "VulkanSurface.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/TextureContext.h"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/common/RuntimeInfo.h"
#include "gpg/gal/backends/d3d11/D3D11VertexLayouts.h"
#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

namespace gpg::gal
{
  using backend::CheckHresult;
  using backend::ThrowError;
  using vulkan::CheckVk;
  using vulkan::Vk;

  namespace
  {
    struct MacroPair
    {
      const char* name;
      const char* value;
    };

    // The Direct3D 10 effect dialect (see DeviceD3D12), plus one naming this backend.
    constexpr MacroPair kInjectedMacros[] = {
      {"technique", "technique10"}, {"VERSION", "DIRECT3D10"}, {"vs_1_1", "vs_4_0"},   {"vs_1_3", "vs_4_0"},
      {"vs_1_4", "vs_4_0"},         {"vs_2_0", "vs_4_0"},      {"vs_3_0", "vs_4_0"},   {"ps_1_1", "ps_4_0"},
      {"ps_1_3", "ps_4_0"},         {"ps_1_4", "ps_4_0"},      {"ps_2_0", "ps_4_0"},   {"ps_2_a", "ps_4_0"},
      {"ps_2_b", "ps_4_0"},         {"ps_3_0", "ps_4_0"},      {"MipFilter", "Filter"}, {"MinFilter", "Filter"},
      {"MagFilter", "Filter"},      {"NONE", "MIN_MAG_MIP_POINT"}, {"LINEAR", "MIN_MAG_MIP_LINEAR"},
      {"POINT", "MIN_MAG_MIP_POINT"}, {"VULKAN", "1"},
    };

    // D3D10's primitive topology per gal token (0x00D43078).
    constexpr VkPrimitiveTopology kTopologyByToken[15] = {
      VK_PRIMITIVE_TOPOLOGY_MAX_ENUM,
      VK_PRIMITIVE_TOPOLOGY_POINT_LIST,
      VK_PRIMITIVE_TOPOLOGY_LINE_LIST,
      VK_PRIMITIVE_TOPOLOGY_LINE_STRIP,
      VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
      VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP,
      VK_PRIMITIVE_TOPOLOGY_LINE_LIST_WITH_ADJACENCY,
      VK_PRIMITIVE_TOPOLOGY_LINE_STRIP_WITH_ADJACENCY,
      VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST_WITH_ADJACENCY,
      VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP_WITH_ADJACENCY,
      VK_PRIMITIVE_TOPOLOGY_MAX_ENUM,
      VK_PRIMITIVE_TOPOLOGY_POINT_LIST,
      VK_PRIMITIVE_TOPOLOGY_LINE_STRIP,
      VK_PRIMITIVE_TOPOLOGY_LINE_STRIP,
      VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
    };

    constexpr std::uint32_t kTextureBindings = effects::kMaxTextureSlots;  // set 0, bindings 0..63
    constexpr std::uint32_t kSamplerBindings = effects::kMaxSamplerSlots;  // set 0, bindings 64..127
    constexpr std::uint32_t kZeroBinding = 15U;                            // vertex binding of missing inputs

    [[nodiscard]] bool CommandLineHas(const char* const option)
    {
      std::string commandLine = ::GetCommandLineA();
      std::string needle = option;
      const auto lower = [](std::string& text) {
        std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      };
      lower(commandLine);
      lower(needle);
      return commandLine.find(needle) != std::string::npos;
    }

    [[nodiscard]] bool IsRgbaTexture(Texture& texture)
    {
      const DXGI_FORMAT format = static_cast<TextureVulkan&>(texture).DxgiFormat();
      return format == DXGI_FORMAT_R8G8B8A8_UNORM || format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
    }

    /** See DeviceD3D12: plain counts, D3DSTREAMSOURCE_INDEXEDDATA | count, or an instance-data stream. */
    [[nodiscard]] std::uint32_t InstanceCount(const std::int32_t token) noexcept
    {
      const auto bits = static_cast<std::uint32_t>(token);
      if ((bits & 0x80000000U) != 0U) {
        return 1U;
      }
      return std::max<std::uint32_t>(bits & 0x3FFFFFFFU, 1U);
    }

    // D3D11/12 enumerators (as the effect description keeps them) -> Vulkan.
    [[nodiscard]] VkBlendFactor BlendFactor(const std::uint8_t blend) noexcept
    {
      switch (blend) {
      case 1: return VK_BLEND_FACTOR_ZERO;
      case 2: return VK_BLEND_FACTOR_ONE;
      case 3: return VK_BLEND_FACTOR_SRC_COLOR;
      case 4: return VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR;
      case 5: return VK_BLEND_FACTOR_SRC_ALPHA;
      case 6: return VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
      case 7: return VK_BLEND_FACTOR_DST_ALPHA;
      case 8: return VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA;
      case 9: return VK_BLEND_FACTOR_DST_COLOR;
      case 10: return VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR;
      case 11: return VK_BLEND_FACTOR_SRC_ALPHA_SATURATE;
      case 14: return VK_BLEND_FACTOR_CONSTANT_COLOR;
      case 15: return VK_BLEND_FACTOR_ONE_MINUS_CONSTANT_COLOR;
      default: return VK_BLEND_FACTOR_ONE;
      }
    }

    [[nodiscard]] VkBlendOp BlendOp(const std::uint8_t op) noexcept
    {
      switch (op) {
      case 2: return VK_BLEND_OP_SUBTRACT;
      case 3: return VK_BLEND_OP_REVERSE_SUBTRACT;
      case 4: return VK_BLEND_OP_MIN;
      case 5: return VK_BLEND_OP_MAX;
      default: return VK_BLEND_OP_ADD;
      }
    }

    [[nodiscard]] VkCompareOp CompareOp(const std::uint8_t func) noexcept
    {
      return (func >= 1U && func <= 8U) ? static_cast<VkCompareOp>(func - 1U) : VK_COMPARE_OP_ALWAYS;
    }

    [[nodiscard]] VkStencilOp StencilOp(const std::uint8_t op) noexcept
    {
      return (op >= 1U && op <= 8U) ? static_cast<VkStencilOp>(op - 1U) : VK_STENCIL_OP_KEEP;
    }

    [[nodiscard]] VkSamplerAddressMode AddressMode(const std::uint8_t mode) noexcept
    {
      switch (mode) {
      case 1: return VK_SAMPLER_ADDRESS_MODE_REPEAT;
      case 2: return VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT;
      case 4: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER;
      case 5: return VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE;
      default: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
      }
    }

    class KeyWriter
    {
    public:
      template <class T>
      void Add(const T& value)
      {
        mKey.append(reinterpret_cast<const char*>(&value), sizeof(T));
      }
      [[nodiscard]] std::string& Key() noexcept { return mKey; }

    private:
      std::string mKey;
    };

    [[nodiscard]] VkImageAspectFlags AspectOf(const VkFormat format) noexcept
    {
      if (vulkan::IsDepthFormat(format)) {
        return VK_IMAGE_ASPECT_DEPTH_BIT | (vulkan::HasStencil(format) ? VK_IMAGE_ASPECT_STENCIL_BIT : 0U);
      }
      return VK_IMAGE_ASPECT_COLOR_BIT;
    }

    void WriteBmp(const char* const path, const imaging::Image& image)
    {
      if (image.subresources.empty() || dxgi::FormatElementBytes(image.format) != 4U || dxgi::IsBlockCompressed(image.format)) {
        return;
      }
      const imaging::Image::Subresource& top = image.subresources.front();
      BITMAPFILEHEADER fileHeader{};
      BITMAPINFOHEADER infoHeader{};
      infoHeader.biSize = sizeof(infoHeader);
      infoHeader.biWidth = static_cast<LONG>(top.width);
      infoHeader.biHeight = -static_cast<LONG>(top.height);
      infoHeader.biPlanes = 1;
      infoHeader.biBitCount = 32;
      infoHeader.biCompression = BI_RGB;
      fileHeader.bfType = 0x4D42;
      fileHeader.bfOffBits = sizeof(fileHeader) + sizeof(infoHeader);
      fileHeader.bfSize = fileHeader.bfOffBits + top.width * top.height * 4U;
      if (FILE* const file = std::fopen(path, "wb")) {
        std::fwrite(&fileHeader, sizeof(fileHeader), 1U, file);
        std::fwrite(&infoHeader, sizeof(infoHeader), 1U, file);
        for (std::uint32_t row = 0U; row < top.height; ++row) {
          std::fwrite(image.bytes.data() + top.offset + static_cast<std::size_t>(row) * top.rowPitch, 4U, top.width, file);
        }
        std::fclose(file);
        gpg::Logf("Vulkan: dump %s", path);
      }
    }

    VKAPI_ATTR VkBool32 VKAPI_CALL DebugMessage(
      VkDebugUtilsMessageSeverityFlagBitsEXT severity,
      VkDebugUtilsMessageTypeFlagsEXT,
      const VkDebugUtilsMessengerCallbackDataEXT* data,
      void*
    )
    {
      static std::set<std::int32_t> seen;
      static std::mutex mutex;
      const std::lock_guard<std::mutex> lock(mutex);
      if (severity >= VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT && data != nullptr && seen.size() < 300U &&
          seen.insert(data->messageIdNumber).second) {
        gpg::Warnf("Vulkan validation: %s", (data->pMessage != nullptr) ? data->pMessage : "");
      }
      return VK_FALSE;
    }
  } // namespace

  struct DeviceVulkan::ProgramState
  {
    std::vector<VkSampler> samplers;
    std::int32_t viewportParameter = -1;
    float lastViewport[4]{-1.0f, -1.0f, -1.0f, -1.0f};

    std::uint64_t constantsVersion = 0;
    std::uint64_t constantsSerial = 0;
    std::uint64_t constantsFrame = ~0ULL;
    VkDescriptorSet constants = VK_NULL_HANDLE;

    std::uint64_t tableFrame = ~0ULL;
    std::uint64_t textureVersion = 0;
    const RenderTarget* tableSurface = nullptr;
    VkDescriptorSet table = VK_NULL_HANDLE;
    std::shared_ptr<const std::vector<effects::TextureBinding>> tableBindings;
  };

  // ---------------------------------------------------------------------------
  // Construction and setup

  DeviceVulkan::DeviceVulkan()
    : mCursor(&IsRgbaTexture)
  {}

  DeviceVulkan::~DeviceVulkan()
  {
    Shutdown();
  }

  void DeviceVulkan::Shutdown() noexcept
  {
    if (mDevice != VK_NULL_HANDLE) {
      Vk().vkDeviceWaitIdle(mDevice);
    }
    ReleaseGpuDrivenObjects();
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    mPass = BoundPass{};
    for (StreamBinding& stream : mStreams) {
      stream = StreamBinding{};
    }
    mIndexBuffer.reset();
    mPipelineState.reset();
    mCursor.Destroy();
    if (mDevice != VK_NULL_HANDLE) {
      mSubmittedSerial = ~0ULL >> 1U; // everything retired below is complete
      for (Garbage& garbage : mGarbage) {
        garbage.serial = 0U;
      }
      CollectCompleted();
      for (auto& [key, pipeline] : mPipelines) {
        if (pipeline != VK_NULL_HANDLE) {
          Vk().vkDestroyPipeline(mDevice, pipeline, nullptr);
        }
      }
      mPipelines.clear();
      for (auto& [key, module] : mModules) {
        Vk().vkDestroyShaderModule(mDevice, module, nullptr);
      }
      mModules.clear();
      for (auto& [key, module] : mLinkedModules) {
        Vk().vkDestroyShaderModule(mDevice, module, nullptr);
      }
      mLinkedModules.clear();
      for (auto& [key, sampler] : mSamplers) {
        Vk().vkDestroySampler(mDevice, sampler, nullptr);
      }
      mSamplers.clear();
      for (int index = 0; index < 3; ++index) {
        if (mNullViews[index] != VK_NULL_HANDLE) {
          Vk().vkDestroyImageView(mDevice, mNullViews[index], nullptr);
        }
        if (mNullImages[index].image != VK_NULL_HANDLE) {
          Vk().vkDestroyImage(mDevice, mNullImages[index].image, nullptr);
          mMemory.Free(mNullImages[index].memory);
        }
      }
      if (mZeroBuffer.buffer != VK_NULL_HANDLE) {
        Vk().vkDestroyBuffer(mDevice, mZeroBuffer.buffer, nullptr);
        mMemory.Free(mZeroBuffer.memory);
      }
      for (SwapChain& swapChain : mSwapChains) {
        DestroySwapChain(swapChain, false);
      }
      mSwapChains.clear();
      for (Frame& frame : mFrames) {
        for (VkDescriptorPool pool : frame.descriptorPools) {
          Vk().vkDestroyDescriptorPool(mDevice, pool, nullptr);
        }
        frame.descriptorPools.clear();
        for (VkSemaphore semaphore : frame.acquire) {
          Vk().vkDestroySemaphore(mDevice, semaphore, nullptr);
        }
        frame.acquire.clear();
        if (frame.pool != VK_NULL_HANDLE) {
          Vk().vkDestroyCommandPool(mDevice, frame.pool, nullptr);
        }
        frame = Frame{};
      }
      if (mPipelineCache != VK_NULL_HANDLE) {
        Vk().vkDestroyPipelineCache(mDevice, mPipelineCache, nullptr);
      }
      if (mPipelineLayout != VK_NULL_HANDLE) {
        Vk().vkDestroyPipelineLayout(mDevice, mPipelineLayout, nullptr);
      }
      if (mTextureLayout != VK_NULL_HANDLE) {
        Vk().vkDestroyDescriptorSetLayout(mDevice, mTextureLayout, nullptr);
      }
      if (mConstantLayout != VK_NULL_HANDLE) {
        Vk().vkDestroyDescriptorSetLayout(mDevice, mConstantLayout, nullptr);
      }
      if (mTimeline != VK_NULL_HANDLE) {
        Vk().vkDestroySemaphore(mDevice, mTimeline, nullptr);
      }
      mUpload.Release();
      mMemory.Release();
      Vk().vkDestroyDevice(mDevice, nullptr);
      mDevice = VK_NULL_HANDLE;
    } else {
      for (SwapChain& swapChain : mSwapChains) {
        if (swapChain.surface != VK_NULL_HANDLE && mInstance != VK_NULL_HANDLE) {
          Vk().vkDestroySurfaceKHR(mInstance, swapChain.surface, nullptr);
        }
      }
      mSwapChains.clear();
    }
    if (mInstance != VK_NULL_HANDLE) {
      if (mMessenger != VK_NULL_HANDLE && Vk().vkDestroyDebugUtilsMessengerEXT != nullptr) {
        Vk().vkDestroyDebugUtilsMessengerEXT(mInstance, mMessenger, nullptr);
      }
      Vk().vkDestroyInstance(mInstance, nullptr);
      mInstance = VK_NULL_HANDLE;
    }
    mDeviceContext = DeviceContext(DeviceApi::Unset);
  }

  void DeviceVulkan::CreateInstance()
  {
    std::uint32_t version = VK_API_VERSION_1_0;
    if (Vk().vkEnumerateInstanceVersion != nullptr) {
      Vk().vkEnumerateInstanceVersion(&version);
    }
    if (version < VK_API_VERSION_1_3) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "the Vulkan loader is older than 1.3");
    }

    std::vector<const char*> extensions{VK_KHR_SURFACE_EXTENSION_NAME, vulkan::PlatformSurfaceExtension()};
    std::vector<const char*> layers;
    const bool debug = CommandLineHas("/vulkandebug");
    if (debug) {
      std::uint32_t count = 0U;
      Vk().vkEnumerateInstanceLayerProperties(&count, nullptr);
      std::vector<VkLayerProperties> available(count);
      Vk().vkEnumerateInstanceLayerProperties(&count, available.data());
      for (const VkLayerProperties& layer : available) {
        if (std::strcmp(layer.layerName, "VK_LAYER_KHRONOS_validation") == 0) {
          layers.push_back("VK_LAYER_KHRONOS_validation");
          extensions.push_back(VK_EXT_DEBUG_UTILS_EXTENSION_NAME);
        }
      }
      if (layers.empty()) {
        gpg::Warnf("Vulkan: the validation layer is not installed");
      }
    }

    VkApplicationInfo application{};
    application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    application.pApplicationName = "Forged Alliance";
    application.pEngineName = "Moho";
    application.apiVersion = VK_API_VERSION_1_3;
    VkInstanceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    info.pApplicationInfo = &application;
    info.enabledExtensionCount = static_cast<std::uint32_t>(extensions.size());
    info.ppEnabledExtensionNames = extensions.data();
    info.enabledLayerCount = static_cast<std::uint32_t>(layers.size());
    info.ppEnabledLayerNames = layers.data();
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateInstance(&info, nullptr, &mInstance));
    if (!Vk().LoadInstance(mInstance)) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "the Vulkan instance lacks required functions");
    }
    if (!layers.empty() && Vk().vkCreateDebugUtilsMessengerEXT != nullptr) {
      VkDebugUtilsMessengerCreateInfoEXT messenger{};
      messenger.sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
      messenger.messageSeverity = VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT;
      messenger.messageType = VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT |
        VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
      messenger.pfnUserCallback = &DebugMessage;
      Vk().vkCreateDebugUtilsMessengerEXT(mInstance, &messenger, nullptr, &mMessenger);
    }
  }

  void DeviceVulkan::PickPhysicalDevice(const std::int32_t adapter)
  {
    std::uint32_t count = 0U;
    Vk().vkEnumeratePhysicalDevices(mInstance, &count, nullptr);
    mPhysicalDevices.resize(count);
    Vk().vkEnumeratePhysicalDevices(mInstance, &count, mPhysicalDevices.data());
    if (count == 0U) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "no Vulkan device");
    }

    // A device with Vulkan 1.3 and a queue that draws and presents to head 0.
    const auto usable = [&](const VkPhysicalDevice device, std::uint32_t& family) {
      VkPhysicalDeviceProperties properties{};
      Vk().vkGetPhysicalDeviceProperties(device, &properties);
      if (properties.apiVersion < VK_API_VERSION_1_3) {
        return false;
      }
      std::uint32_t families = 0U;
      Vk().vkGetPhysicalDeviceQueueFamilyProperties(device, &families, nullptr);
      std::vector<VkQueueFamilyProperties> queues(families);
      Vk().vkGetPhysicalDeviceQueueFamilyProperties(device, &families, queues.data());
      for (std::uint32_t index = 0U; index < families; ++index) {
        VkBool32 present = VK_TRUE;
        if (!mSwapChains.empty()) {
          Vk().vkGetPhysicalDeviceSurfaceSupportKHR(device, index, mSwapChains.front().surface, &present);
        }
        if ((queues[index].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0U && present == VK_TRUE) {
          family = index;
          return true;
        }
      }
      return false;
    };

    std::uint32_t family = 0U;
    if (adapter >= 0 && static_cast<std::uint32_t>(adapter) < count && usable(mPhysicalDevices[static_cast<std::size_t>(adapter)], family)) {
      mPhysical = mPhysicalDevices[static_cast<std::size_t>(adapter)];
      mQueueFamily = family;
    } else {
      // Prefer a discrete GPU.
      for (int pass = 0; pass < 2 && mPhysical == VK_NULL_HANDLE; ++pass) {
        for (const VkPhysicalDevice device : mPhysicalDevices) {
          VkPhysicalDeviceProperties properties{};
          Vk().vkGetPhysicalDeviceProperties(device, &properties);
          if (pass == 0 && properties.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            continue;
          }
          if (usable(device, family)) {
            mPhysical = device;
            mQueueFamily = family;
            break;
          }
        }
      }
    }
    if (mPhysical == VK_NULL_HANDLE) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "no Vulkan 1.3 device can draw to the window");
    }
    Vk().vkGetPhysicalDeviceProperties(mPhysical, &mProperties);

    // The driver's own name and version text (Vulkan 1.2); driverVersion's
    // encoding is vendor-specific.
    VkPhysicalDeviceDriverProperties driver{};
    driver.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;
    VkPhysicalDeviceProperties2 properties2{};
    properties2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    properties2.pNext = &driver;
    Vk().vkGetPhysicalDeviceProperties2(mPhysical, &properties2);
    mDriverName = std::string(driver.driverName) + " " + driver.driverInfo;
  }

  void DeviceVulkan::CreateLogicalDevice()
  {
    VkPhysicalDeviceVulkan13Features available13{};
    available13.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES;
    VkPhysicalDeviceVulkan12Features available12{};
    available12.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES;
    available12.pNext = &available13;
    VkPhysicalDeviceFeatures2 available{};
    available.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    available.pNext = &available12;
    Vk().vkGetPhysicalDeviceFeatures2(mPhysical, &available);
    // scalarBlockLayout: $Globals keeps Direct3D's constant-buffer packing
    // (-fvk-use-dx-layout), which std140 rules do not allow.
    if (available13.dynamicRendering != VK_TRUE || available13.synchronization2 != VK_TRUE || available12.timelineSemaphore != VK_TRUE ||
        available12.scalarBlockLayout != VK_TRUE) {
      ThrowError(
        "DeviceVulkan.cpp", __LINE__, "the Vulkan device lacks dynamic rendering, synchronization2, timeline semaphores or scalar block layout"
      );
    }

    VkPhysicalDeviceVulkan13Features features13{};
    features13.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES;
    features13.dynamicRendering = VK_TRUE;
    features13.synchronization2 = VK_TRUE;
    VkPhysicalDeviceVulkan12Features features12{};
    features12.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES;
    features12.pNext = &features13;
    features12.timelineSemaphore = VK_TRUE;
    features12.scalarBlockLayout = VK_TRUE;
    features12.samplerMirrorClampToEdge = available12.samplerMirrorClampToEdge;
    VkPhysicalDeviceFeatures2 features{};
    features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    features.pNext = &features12;
    features.features.samplerAnisotropy = available.features.samplerAnisotropy;
    features.features.fillModeNonSolid = available.features.fillModeNonSolid;
    features.features.textureCompressionBC = available.features.textureCompressionBC;
    mAnisotropy = available.features.samplerAnisotropy == VK_TRUE;
    mWireframeSupported = available.features.fillModeNonSolid == VK_TRUE;
    if (available.features.textureCompressionBC != VK_TRUE) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "the Vulkan device has no BC texture compression");
    }

    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queue{};
    queue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue.queueFamilyIndex = mQueueFamily;
    queue.queueCount = 1U;
    queue.pQueuePriorities = &priority;
    // VK_EXT_memory_budget is optional: ren_Info reports heap budgets with it,
    // and only heap sizes without it.
    std::uint32_t extensionCount = 0U;
    Vk().vkEnumerateDeviceExtensionProperties(mPhysical, nullptr, &extensionCount, nullptr);
    std::vector<VkExtensionProperties> available_extensions(extensionCount);
    Vk().vkEnumerateDeviceExtensionProperties(mPhysical, nullptr, &extensionCount, available_extensions.data());
    mMemoryBudget = std::any_of(available_extensions.begin(), available_extensions.end(), [](const VkExtensionProperties& extension) {
      return std::strcmp(extension.extensionName, VK_EXT_MEMORY_BUDGET_EXTENSION_NAME) == 0;
    });
    const char* const extensions[] = {VK_KHR_SWAPCHAIN_EXTENSION_NAME, VK_EXT_MEMORY_BUDGET_EXTENSION_NAME};
    VkDeviceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    info.pNext = &features;
    info.queueCreateInfoCount = 1U;
    info.pQueueCreateInfos = &queue;
    info.enabledExtensionCount = mMemoryBudget ? 2U : 1U;
    info.ppEnabledExtensionNames = extensions;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateDevice(mPhysical, &info, nullptr, &mDevice));
    if (!Vk().LoadDevice(mDevice)) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "the Vulkan device lacks required functions");
    }
    Vk().vkGetDeviceQueue(mDevice, mQueueFamily, 0U, &mQueue);

    VkSemaphoreTypeCreateInfo timelineType{};
    timelineType.sType = VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO;
    timelineType.semaphoreType = VK_SEMAPHORE_TYPE_TIMELINE;
    timelineType.initialValue = 0U;
    VkSemaphoreCreateInfo semaphore{};
    semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    semaphore.pNext = &timelineType;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateSemaphore(mDevice, &semaphore, nullptr, &mTimeline));

    mMemory.Initialize(mPhysical, mDevice);
    mUpload.Initialize(mMemory, mDevice);

    // D24S8 where it exists (NVIDIA, Intel); D32S8 otherwise (AMD).
    VkFormatProperties properties{};
    Vk().vkGetPhysicalDeviceFormatProperties(mPhysical, VK_FORMAT_D24_UNORM_S8_UINT, &properties);
    mDepthStencilFormat = ((properties.optimalTilingFeatures & VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT) != 0U)
      ? VK_FORMAT_D24_UNORM_S8_UINT
      : VK_FORMAT_D32_SFLOAT_S8_UINT;

    gpg::Logf(
      "Vulkan: device created on '%s' (vendor 0x%04X device 0x%04X, API %u.%u.%u, driver 0x%08X), depth-stencil %s",
      mProperties.deviceName, mProperties.vendorID, mProperties.deviceID, VK_API_VERSION_MAJOR(mProperties.apiVersion),
      VK_API_VERSION_MINOR(mProperties.apiVersion), VK_API_VERSION_PATCH(mProperties.apiVersion), mProperties.driverVersion,
      (mDepthStencilFormat == VK_FORMAT_D24_UNORM_S8_UINT) ? "D24S8" : "D32S8"
    );
  }

  void DeviceVulkan::CreateFrames()
  {
    for (Frame& frame : mFrames) {
      VkCommandPoolCreateInfo pool{};
      pool.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
      pool.flags = VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;
      pool.queueFamilyIndex = mQueueFamily;
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateCommandPool(mDevice, &pool, nullptr, &frame.pool));
    }
  }

  void DeviceVulkan::CreateLayouts()
  {
    std::vector<VkDescriptorSetLayoutBinding> bindings;
    for (std::uint32_t index = 0U; index < kTextureBindings + kSamplerBindings; ++index) {
      VkDescriptorSetLayoutBinding binding{};
      binding.binding = index;
      binding.descriptorType = (index < kTextureBindings) ? VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE : VK_DESCRIPTOR_TYPE_SAMPLER;
      binding.descriptorCount = 1U;
      binding.stageFlags = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
      bindings.push_back(binding);
    }
    VkDescriptorSetLayoutCreateInfo layout{};
    layout.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout.bindingCount = static_cast<std::uint32_t>(bindings.size());
    layout.pBindings = bindings.data();
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateDescriptorSetLayout(mDevice, &layout, nullptr, &mTextureLayout));

    VkDescriptorSetLayoutBinding constants{};
    constants.binding = 0U;
    constants.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    constants.descriptorCount = 1U;
    constants.stageFlags = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
    layout.bindingCount = 1U;
    layout.pBindings = &constants;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateDescriptorSetLayout(mDevice, &layout, nullptr, &mConstantLayout));

    const VkDescriptorSetLayout sets[2] = {mTextureLayout, mConstantLayout};
    VkPipelineLayoutCreateInfo pipeline{};
    pipeline.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipeline.setLayoutCount = 2U;
    pipeline.pSetLayouts = sets;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreatePipelineLayout(mDevice, &pipeline, nullptr, &mPipelineLayout));

    VkPipelineCacheCreateInfo cache{};
    cache.sType = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreatePipelineCache(mDevice, &cache, nullptr, &mPipelineCache));

    effects::SamplerDesc defaults;
    mDefaultSampler = SamplerFor(defaults);
  }

  void DeviceVulkan::CreateNullImages()
  {
    for (int kind = 0; kind < 3; ++kind) {
      vulkan::TrackedImage& image = mNullImages[kind];
      VkImageCreateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
      info.imageType = (kind == 2) ? VK_IMAGE_TYPE_3D : VK_IMAGE_TYPE_2D;
      info.format = VK_FORMAT_R8G8B8A8_UNORM;
      info.extent = {1U, 1U, 1U};
      info.mipLevels = 1U;
      info.arrayLayers = (kind == 1) ? 6U : 1U;
      info.flags = (kind == 1) ? VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT : 0U;
      info.samples = VK_SAMPLE_COUNT_1_BIT;
      info.tiling = VK_IMAGE_TILING_OPTIMAL;
      info.usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImage(mDevice, &info, nullptr, &image.image));
      VkMemoryRequirements requirements{};
      Vk().vkGetImageMemoryRequirements(mDevice, image.image, &requirements);
      image.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, false);
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBindImageMemory(mDevice, image.image, image.memory.memory, image.memory.offset));
      image.format = info.format;
      image.width = image.height = image.depth = 1U;
      image.layers = info.arrayLayers;
      const std::uint32_t zero = 0U;
      for (std::uint32_t layer = 0U; layer < image.layers; ++layer) {
        UploadImageLevel(image, DXGI_FORMAT_R8G8B8A8_UNORM, 0U, layer, &zero);
      }
      Transition(image, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
      VkImageViewCreateInfo view{};
      view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
      view.image = image.image;
      view.viewType = (kind == 0) ? VK_IMAGE_VIEW_TYPE_2D : (kind == 1) ? VK_IMAGE_VIEW_TYPE_CUBE : VK_IMAGE_VIEW_TYPE_3D;
      view.format = info.format;
      view.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 1U, 0U, info.arrayLayers};
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImageView(mDevice, &view, nullptr, &mNullViews[kind]));
    }
    mZeroBuffer = CreateDeviceBuffer(256U, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT);
    std::uint8_t zeros[256]{};
    UploadBuffer(mZeroBuffer, 0U, zeros, sizeof(zeros));
  }

  void DeviceVulkan::CreateSwapChain(SwapChain& swapChain, std::uint32_t width, std::uint32_t height)
  {
    VkSurfaceCapabilitiesKHR capabilities{};
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkGetPhysicalDeviceSurfaceCapabilitiesKHR(mPhysical, swapChain.surface, &capabilities));
    std::uint32_t count = 0U;
    Vk().vkGetPhysicalDeviceSurfaceFormatsKHR(mPhysical, swapChain.surface, &count, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(count);
    Vk().vkGetPhysicalDeviceSurfaceFormatsKHR(mPhysical, swapChain.surface, &count, formats.data());
    VkSurfaceFormatKHR chosen = formats.empty() ? VkSurfaceFormatKHR{VK_FORMAT_B8G8R8A8_UNORM, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR} : formats.front();
    for (const VkSurfaceFormatKHR& format : formats) {
      if (format.format == VK_FORMAT_B8G8R8A8_UNORM && format.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
        chosen = format;
      }
    }
    if (chosen.format != VK_FORMAT_B8G8R8A8_UNORM) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "the window surface has no B8G8R8A8_UNORM format");
    }
    Vk().vkGetPhysicalDeviceSurfacePresentModesKHR(mPhysical, swapChain.surface, &count, nullptr);
    std::vector<VkPresentModeKHR> modes(count);
    Vk().vkGetPhysicalDeviceSurfacePresentModesKHR(mPhysical, swapChain.surface, &count, modes.data());
    VkPresentModeKHR mode = VK_PRESENT_MODE_FIFO_KHR;
    if (!mDeviceContext.mVSync) {
      for (const VkPresentModeKHR candidate : {VK_PRESENT_MODE_MAILBOX_KHR, VK_PRESENT_MODE_IMMEDIATE_KHR}) {
        if (std::find(modes.begin(), modes.end(), candidate) != modes.end()) {
          mode = candidate;
          break;
        }
      }
    }

    VkExtent2D extent{width, height};
    if (capabilities.currentExtent.width != 0xFFFFFFFFU) {
      extent = capabilities.currentExtent;
    }
    extent.width = std::clamp(extent.width, capabilities.minImageExtent.width, std::max(capabilities.maxImageExtent.width, 1U));
    extent.height = std::clamp(extent.height, capabilities.minImageExtent.height, std::max(capabilities.maxImageExtent.height, 1U));

    VkSwapchainCreateInfoKHR info{};
    info.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    info.surface = swapChain.surface;
    info.minImageCount = std::max(vulkan::kFramesInFlight, capabilities.minImageCount);
    if (capabilities.maxImageCount != 0U) {
      info.minImageCount = std::min(info.minImageCount, capabilities.maxImageCount);
    }
    info.imageFormat = chosen.format;
    info.imageColorSpace = chosen.colorSpace;
    info.imageExtent = extent;
    info.imageArrayLayers = 1U;
    info.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT |
      VK_IMAGE_USAGE_SAMPLED_BIT;
    info.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    info.preTransform = capabilities.currentTransform;
    info.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    info.presentMode = mode;
    info.clipped = VK_TRUE;
    info.oldSwapchain = swapChain.swapchain;
    VkSwapchainKHR created = VK_NULL_HANDLE;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateSwapchainKHR(mDevice, &info, nullptr, &created));
    if (swapChain.swapchain != VK_NULL_HANDLE) {
      Vk().vkDestroySwapchainKHR(mDevice, swapChain.swapchain, nullptr);
    }
    swapChain.swapchain = created;
    swapChain.format = chosen.format;
    swapChain.extent = extent;
    swapChain.presentMode = mode;
    Vk().vkGetSwapchainImagesKHR(mDevice, created, &count, nullptr);
    swapChain.images.resize(count);
    Vk().vkGetSwapchainImagesKHR(mDevice, created, &count, swapChain.images.data());
    for (VkSemaphore semaphore : swapChain.renderFinished) {
      Vk().vkDestroySemaphore(mDevice, semaphore, nullptr);
    }
    swapChain.renderFinished.assign(count, VK_NULL_HANDLE);
    VkSemaphoreCreateInfo semaphore{};
    semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    for (VkSemaphore& finished : swapChain.renderFinished) {
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateSemaphore(mDevice, &semaphore, nullptr, &finished));
    }
    swapChain.hasImage = false;
    gpg::Logf(
      "Vulkan: swap chain %ux%u, %u images, %s", extent.width, extent.height, count,
      (mode == VK_PRESENT_MODE_FIFO_KHR) ? "FIFO (vsync)" : (mode == VK_PRESENT_MODE_MAILBOX_KHR) ? "mailbox" : "immediate"
    );
  }

  void DeviceVulkan::DestroySwapChain(SwapChain& swapChain, const bool keepSurface) noexcept
  {
    for (VkSemaphore semaphore : swapChain.renderFinished) {
      Vk().vkDestroySemaphore(mDevice, semaphore, nullptr);
    }
    swapChain.renderFinished.clear();
    if (swapChain.swapchain != VK_NULL_HANDLE) {
      Vk().vkDestroySwapchainKHR(mDevice, swapChain.swapchain, nullptr);
      swapChain.swapchain = VK_NULL_HANDLE;
    }
    swapChain.images.clear();
    swapChain.hasImage = false;
    if (!keepSurface && swapChain.surface != VK_NULL_HANDLE) {
      Vk().vkDestroySurfaceKHR(mInstance, swapChain.surface, nullptr);
      swapChain.surface = VK_NULL_HANDLE;
    }
  }

  void DeviceVulkan::CreateSwapChains(const DeviceContext& context)
  {
    for (int headIndex = 0; headIndex < context.GetHeadCount(); ++headIndex) {
      const Head& head = context.GetHead(static_cast<std::uint32_t>(headIndex));
      std::uint32_t width = head.mWidth;
      std::uint32_t height = head.mHeight;
      if (width == 0U || height == 0U) {
        RECT client{};
        ::GetClientRect(static_cast<HWND>(head.mWindow), &client);
        width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }
      CreateSwapChain(mSwapChains[static_cast<std::size_t>(headIndex)], width, height);
    }
    VkSemaphoreCreateInfo semaphore{};
    semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    for (Frame& frame : mFrames) {
      while (frame.acquire.size() < mSwapChains.size()) {
        VkSemaphore acquire = VK_NULL_HANDLE;
        CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateSemaphore(mDevice, &semaphore, nullptr, &acquire));
        frame.acquire.push_back(acquire);
      }
    }
  }

  void DeviceVulkan::CreateRenderTargets()
  {
    mHeadOutputContexts.clear();
    mHeadOutputContexts.resize(mSwapChains.size());
    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      SwapChain& swapChain = mSwapChains[headIndex];
      std::vector<RenderTargetVulkan::Buffer> buffers;
      for (const VkImage image : swapChain.images) {
        RenderTargetVulkan::Buffer buffer;
        buffer.image.image = image;
        buffer.image.owned = false;
        buffer.image.format = swapChain.format;
        buffer.image.width = swapChain.extent.width;
        buffer.image.height = swapChain.extent.height;
        buffer.image.layout = VK_IMAGE_LAYOUT_UNDEFINED;
        VkImageViewCreateInfo view{};
        view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        view.image = image;
        view.viewType = VK_IMAGE_VIEW_TYPE_2D;
        view.format = swapChain.format;
        view.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 1U, 0U, 1U};
        CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImageView(mDevice, &view, nullptr, &buffer.view));
        buffers.push_back(buffer);
      }
      OutputContext& output = mHeadOutputContexts[headIndex];
      auto* const target = new RenderTargetVulkan(std::move(buffers), DXGI_FORMAT_B8G8R8A8_UNORM, static_cast<int>(headIndex));
      output.surface.reset(target);
      const DepthStencilTargetContext depthContext(swapChain.extent.width, swapChain.extent.height, 3U, false);
      output.depthStencil = CreateDepthStencilTarget(&depthContext);
      gpg::Logf("Vulkan: head %u back buffer target %p (%ux%u)", static_cast<unsigned>(headIndex), target, swapChain.extent.width,
                swapChain.extent.height);
    }
    if (!mHeadOutputContexts.empty()) {
      ClearTarget(&mHeadOutputContexts.front());
      D3DVIEWPORT9 viewport{};
      const RenderTargetContext* const context = mHeadOutputContexts.front().surface->GetContext();
      viewport.Width = context->width_;
      viewport.Height = context->height_;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceVulkan::ReleaseRenderTargets() noexcept
  {
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    try {
      Submit(true, false);
      Submit(true, false);
    } catch (...) {
    }
  }

  void DeviceVulkan::CheckAvailableFormats(DeviceContext* const context)
  {
    const DeviceApi api = context->mDeviceType;
    mDeviceContext = *context;
    mDeviceContext.mDeviceType = api;
    mDeviceContext.mMaxPrimitiveCount = 0x10000U;
    mDeviceContext.mMaxVertexCount = 0xFFFFU;
    mDeviceContext.mHWBasedInstancing = true;
    mDeviceContext.mVertexShaderProfile = 4;
    mDeviceContext.mPixelShaderProfile = 8;

    const auto supports = [&](const DXGI_FORMAT format, const VkFormatFeatureFlags wanted) {
      const vulkan::TextureFormat mapped = vulkan::ToVulkanTexture(format);
      if (mapped.format == VK_FORMAT_UNDEFINED) {
        return false;
      }
      VkFormatProperties properties{};
      Vk().vkGetPhysicalDeviceFormatProperties(mPhysical, mapped.format, &properties);
      return (properties.optimalTilingFeatures & wanted) == wanted;
    };
    for (int headIndex = 0; headIndex < mDeviceContext.GetHeadCount(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
      head.adapterModes.clear();
      head.validFormats1.clear();
      for (std::int32_t format = 1; format < 8; ++format) {
        if (supports(dxgi::RenderTargetFormatToDxgi(static_cast<std::uint32_t>(format)), VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT)) {
          head.validFormats1.push_back(format);
        }
      }
      head.validFormats2.clear();
      for (std::int32_t format = 1; format < 20; ++format) {
        if (supports(dxgi::TextureFormatToDxgi(static_cast<std::uint32_t>(format)), VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT)) {
          head.validFormats2.push_back(format);
        }
      }
      head.mStrs.clear();
    }
  }

  void DeviceVulkan::Setup(DeviceContext* const context)
  {
    mCurThreadId = static_cast<int>(::GetCurrentThreadId());
    mLog.clear();
    if (backend::SetupFailureRequested("vulkan")) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "device creation failed on request (FAF_GAL_FAIL_SETUP)");
    }
    if (!Vk().LoadGlobal()) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Vulkan is not available (vulkan-1.dll)");
    }
    effects::ShaderCompiler& compiler = effects::ShaderCompiler::Instance();
    if (!compiler.Available()) {
      ThrowError("DeviceVulkan.cpp", __LINE__, compiler.LoadError().c_str());
    }
    if (imaging::ImageCodec::Instance() == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "no texture decoder (d3dx11_43.dll and a WARP device are needed)");
    }
    mDeviceContext = *context;

    CreateInstance();
    mSwapChains.resize(static_cast<std::size_t>(context->GetHeadCount()));
    for (int headIndex = 0; headIndex < context->GetHeadCount(); ++headIndex) {
      SwapChain& swapChain = mSwapChains[static_cast<std::size_t>(headIndex)];
      swapChain.window = context->GetHead(static_cast<std::uint32_t>(headIndex)).mWindow;
      VkResult result = VK_SUCCESS;
      swapChain.surface = vulkan::CreateWindowSurface(mInstance, swapChain.window, result);
      CheckVk("DeviceVulkan.cpp", __LINE__, result);
    }
    PickPhysicalDevice(context->mAdapter);
    CreateLogicalDevice();
    CreateFrames();
    BeginCommandBuffer();
    CreateLayouts();
    CreateNullImages();
    CreateGpuDrivenObjects();
    CreateSwapChains(*context);
    AcquireNextImages();

    std::fill(std::begin(mStreamFrequencies), std::end(mStreamFrequencies), 0);
    mPipelineState.reset(new PipelineStateVulkan());
    ResetState();
    CheckAvailableFormats(context);
    CreateRenderTargets();
    gpg::Logf(
      "Vulkan: ready (%d head(s), effects through the FAF effect layer, %s SPIR-V, shader cache %s, vsync %s)",
      mDeviceContext.GetHeadCount(), compiler.Version().c_str(),
      effects::ShaderCacheDirectory().empty() ? "off" : effects::ShaderCacheDirectory().c_str(), mDeviceContext.mVSync ? "on" : "off"
    );
    // ren_Info's facts, logged once here until the console command lands.
    DeviceRuntimeInfo runtimeInfo;
    if (GetRuntimeInfo(runtimeInfo)) {
      common::LogRuntimeInfo("Vulkan", runtimeInfo);
    }
  }

  bool DeviceVulkan::GetRuntimeInfo(DeviceRuntimeInfo& out)
  {
    if (mPhysical == VK_NULL_HANDLE || mDevice == VK_NULL_HANDLE) {
      return false;
    }
    out.api = "Vulkan";
    out.adapter = mProperties.deviceName;
    out.vendorId = mProperties.vendorID;
    out.deviceId = mProperties.deviceID;
    char text[160]{};
    std::snprintf(text, sizeof(text), "%s (0x%08X)", mDriverName.c_str(), mProperties.driverVersion);
    out.driverVersion = text;
    std::snprintf(
      text, sizeof(text), "Vulkan %u.%u.%u", VK_API_VERSION_MAJOR(mProperties.apiVersion), VK_API_VERSION_MINOR(mProperties.apiVersion),
      VK_API_VERSION_PATCH(mProperties.apiVersion)
    );
    out.featureLevel = text;

    // Device-local heaps count as video memory, the rest as shared system
    // memory; the budget extension adds what the driver allows and uses now.
    VkPhysicalDeviceMemoryBudgetPropertiesEXT budget{};
    budget.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT;
    VkPhysicalDeviceMemoryProperties2 memory{};
    memory.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2;
    memory.pNext = mMemoryBudget ? &budget : nullptr;
    Vk().vkGetPhysicalDeviceMemoryProperties2(mPhysical, &memory);
    for (std::uint32_t heap = 0U; heap < memory.memoryProperties.memoryHeapCount; ++heap) {
      const bool local = (memory.memoryProperties.memoryHeaps[heap].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) != 0U;
      (local ? out.dedicatedVideoMemory : out.sharedSystemMemory) += memory.memoryProperties.memoryHeaps[heap].size;
      if (mMemoryBudget) {
        (local ? out.localBudget : out.nonLocalBudget) += budget.heapBudget[heap];
        (local ? out.localUsage : out.nonLocalUsage) += budget.heapUsage[heap];
      }
    }

    if (!mSwapChains.empty()) {
      const SwapChain& swapChain = mSwapChains.front();
      const VkPresentModeKHR mode = swapChain.presentMode;
      std::snprintf(
        text, sizeof(text), "%ux%u %s %u images%s", swapChain.extent.width, swapChain.extent.height,
        (mode == VK_PRESENT_MODE_FIFO_KHR) ? "FIFO" : (mode == VK_PRESENT_MODE_MAILBOX_KHR) ? "mailbox" : "immediate",
        static_cast<unsigned>(swapChain.images.size()), (mSwapChains.size() > 1U) ? ", more heads" : ""
      );
      out.swapChain = text;
    }
    out.vsync = mDeviceContext.mVSync;
    out.gpuDrivenFeatures = GetGpuDrivenFeatures();
    return true;
  }

  void DeviceVulkan::ResetState()
  {
    mCurrent = RenderState{};
    mCurrent.rasterizer.cullMode = 1U;
    mCurrent.rasterizer.frontCounterClockwise = true;
    mCurrent.depthStencil.depthFunc = 8U;
  }

  // ---------------------------------------------------------------------------
  // Submission

  void DeviceVulkan::BeginCommandBuffer()
  {
    Frame& frame = mFrames[mFrameIndex];
    if (frame.used == frame.buffers.size()) {
      VkCommandBufferAllocateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
      info.commandPool = frame.pool;
      info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
      info.commandBufferCount = 1U;
      VkCommandBuffer buffer = VK_NULL_HANDLE;
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkAllocateCommandBuffers(mDevice, &info, &buffer));
      frame.buffers.push_back(buffer);
    }
    mCommands = frame.buffers[frame.used++];
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBeginCommandBuffer(mCommands, &begin));
    mViewportDirty = true;
  }

  void DeviceVulkan::Submit(const bool wait, const bool present)
  {
    EndRendering();
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkEndCommandBuffer(mCommands));

    std::vector<VkSemaphoreSubmitInfo> waits;
    std::vector<VkSemaphoreSubmitInfo> signals;
    Frame& frame = mFrames[mFrameIndex];
    for (std::size_t index = 0U; index < mSwapChains.size(); ++index) {
      SwapChain& swapChain = mSwapChains[index];
      if (swapChain.acquireWaitPending && index < frame.acquire.size() && frame.acquire[index] != VK_NULL_HANDLE) {
        // The first submission after an acquire waits for the image.
        VkSemaphoreSubmitInfo semaphore{};
        semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO;
        semaphore.semaphore = frame.acquire[index];
        semaphore.stageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
        waits.push_back(semaphore);
      }
      if (present && swapChain.hasImage) {
        VkSemaphoreSubmitInfo semaphore{};
        semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO;
        semaphore.semaphore = swapChain.renderFinished[swapChain.acquired];
        semaphore.stageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
        signals.push_back(semaphore);
      }
    }
    const std::uint64_t serial = ++mSubmittedSerial;
    VkSemaphoreSubmitInfo timeline{};
    timeline.sType = VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO;
    timeline.semaphore = mTimeline;
    timeline.value = serial;
    timeline.stageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    signals.push_back(timeline);

    VkCommandBufferSubmitInfo commands{};
    commands.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_SUBMIT_INFO;
    commands.commandBuffer = mCommands;
    VkSubmitInfo2 submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO_2;
    submit.waitSemaphoreInfoCount = static_cast<std::uint32_t>(waits.size());
    submit.pWaitSemaphoreInfos = waits.data();
    submit.commandBufferInfoCount = 1U;
    submit.pCommandBufferInfos = &commands;
    submit.signalSemaphoreInfoCount = static_cast<std::uint32_t>(signals.size());
    submit.pSignalSemaphoreInfos = signals.data();
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkQueueSubmit2(mQueue, 1U, &submit, VK_NULL_HANDLE));
    frame.serial = serial;
    // Waited once; later submissions of the frame need not wait again.
    for (SwapChain& swapChain : mSwapChains) {
      swapChain.acquireWaitPending = false;
    }
    if (wait) {
      WaitForSerial(serial);
    }
    CollectCompleted();
    if (!present) {
      BeginCommandBuffer();
    }
  }

  void DeviceVulkan::WaitForSerial(const std::uint64_t serial)
  {
    if (serial == 0U) {
      return;
    }
    VkSemaphoreWaitInfo info{};
    info.sType = VK_STRUCTURE_TYPE_SEMAPHORE_WAIT_INFO;
    info.semaphoreCount = 1U;
    info.pSemaphores = &mTimeline;
    info.pValues = &serial;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkWaitSemaphores(mDevice, &info, ~0ULL));
  }

  void DeviceVulkan::CollectCompleted()
  {
    std::uint64_t completed = 0U;
    Vk().vkGetSemaphoreCounterValue(mDevice, mTimeline, &completed);
    mUpload.Retire(completed);
    std::size_t kept = 0U;
    for (std::size_t index = 0U; index < mGarbage.size(); ++index) {
      Garbage& garbage = mGarbage[index];
      if (garbage.serial <= completed) {
        if (garbage.view != VK_NULL_HANDLE) {
          Vk().vkDestroyImageView(mDevice, garbage.view, nullptr);
        }
        if (garbage.image != VK_NULL_HANDLE) {
          Vk().vkDestroyImage(mDevice, garbage.image, nullptr);
        }
        if (garbage.buffer != VK_NULL_HANDLE) {
          Vk().vkDestroyBuffer(mDevice, garbage.buffer, nullptr);
        }
        mMemory.Free(garbage.memory);
        continue;
      }
      if (kept != index) {
        mGarbage[kept] = garbage;
      }
      ++kept;
    }
    mGarbage.resize(kept);
  }

  void DeviceVulkan::AcquireNextImages()
  {
    Frame& frame = mFrames[mFrameIndex];
    for (std::size_t index = 0U; index < mSwapChains.size(); ++index) {
      SwapChain& swapChain = mSwapChains[index];
      swapChain.hasImage = false;
      if (swapChain.swapchain == VK_NULL_HANDLE) {
        continue;
      }
      const VkResult result =
        Vk().vkAcquireNextImageKHR(mDevice, swapChain.swapchain, ~0ULL, frame.acquire[index], VK_NULL_HANDLE, &swapChain.acquired);
      if (result == VK_SUCCESS || result == VK_SUBOPTIMAL_KHR) {
        swapChain.hasImage = true;
        swapChain.acquireWaitPending = true;
      } else {
        gpg::Warnf("Vulkan: acquiring head %u's image failed (%s)", static_cast<unsigned>(index), vulkan::ResultName(result));
      }
    }
  }

  std::uint32_t DeviceVulkan::AcquiredImage(const std::uint32_t swapChain)
  {
    return (swapChain < mSwapChains.size()) ? mSwapChains[swapChain].acquired : 0U;
  }

  vulkan::UploadAllocation DeviceVulkan::AllocateUpload(const VkDeviceSize bytes, const VkDeviceSize alignment)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    static std::uint64_t sinceSubmit = 0U;
    sinceSubmit += mUpload.TakeAllocatedBytes();
    if (sinceSubmit > (96ULL << 20U) && !mPreparingDraw) {
      sinceSubmit = 0U;
      Submit(mUpload.BusyBytes() > (384ULL << 20U), false);
    }
    return mUpload.Allocate(bytes, std::max<VkDeviceSize>(alignment, 16U), RecordingSerial());
  }

  vulkan::TrackedBuffer DeviceVulkan::CreateDeviceBuffer(const VkDeviceSize bytes, const VkBufferUsageFlags usage)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    vulkan::TrackedBuffer buffer;
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = bytes;
    info.usage = usage;
    info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateBuffer(mDevice, &info, nullptr, &buffer.buffer));
    VkMemoryRequirements requirements{};
    Vk().vkGetBufferMemoryRequirements(mDevice, buffer.buffer, &requirements);
    buffer.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, true);
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBindBufferMemory(mDevice, buffer.buffer, buffer.memory.memory, buffer.memory.offset));
    buffer.size = bytes;
    return buffer;
  }

  void DeviceVulkan::TransferBarrier()
  {
    // Copies just recorded are visible to everything after (vertex input, shaders, later copies).
    VkMemoryBarrier2 barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2;
    barrier.srcStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.srcAccessMask = VK_ACCESS_2_MEMORY_WRITE_BIT;
    barrier.dstStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.dstAccessMask = VK_ACCESS_2_MEMORY_READ_BIT | VK_ACCESS_2_MEMORY_WRITE_BIT;
    VkDependencyInfo dependency{};
    dependency.sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO;
    dependency.memoryBarrierCount = 1U;
    dependency.pMemoryBarriers = &barrier;
    Vk().vkCmdPipelineBarrier2(mCommands, &dependency);
  }

  void DeviceVulkan::UploadBuffer(vulkan::TrackedBuffer& destination, const VkDeviceSize offset, const void* const data, const VkDeviceSize bytes)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const vulkan::UploadAllocation upload = AllocateUpload(bytes, 16U);
    std::memcpy(upload.cpu, data, static_cast<std::size_t>(bytes));
    EndRendering();
    // Earlier draws may still read the old contents (write-after-read).
    TransferBarrier();
    VkBufferCopy region{upload.offset, offset, bytes};
    Vk().vkCmdCopyBuffer(mCommands, upload.buffer, destination.buffer, 1U, &region);
    TransferBarrier();
  }

  bool DeviceVulkan::CopyVertexBufferRegion(
    VertexBuffer& destination, const std::uint32_t destinationOffset, VertexBuffer& source, const std::uint32_t sourceOffset,
    const std::uint32_t byteCount
  )
  {
    BufferStorageVulkan& to = static_cast<VertexBufferVulkan&>(destination).Storage();
    BufferStorageVulkan& from = static_cast<VertexBufferVulkan&>(source).Storage();
    vulkan::TrackedBuffer* const target = to.CopyDestination();
    // A dynamic destination lives in upload memory the CPU rewrites; only
    // device-local buffers take GPU copies.
    if (&to == &from || byteCount == 0U || target == nullptr || target->buffer == VK_NULL_HANDLE ||
        static_cast<std::uint64_t>(destinationOffset) + byteCount > to.ByteWidth() ||
        static_cast<std::uint64_t>(sourceOffset) + byteCount > from.ByteWidth()) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    // The source first: a dynamic buffer may take a new upload copy.
    VkBuffer sourceBuffer = VK_NULL_HANDLE;
    VkDeviceSize sourceBase = 0U;
    from.PrepareForDraw(*this, sourceBuffer, sourceBase);
    if (sourceBuffer == VK_NULL_HANDLE) {
      return false;
    }
    // Copies are not allowed inside dynamic rendering; the barriers order the
    // copy after earlier draws and writes (write-after-read on the
    // destination, read-after-write on the source) and before later draws.
    EndRendering();
    TransferBarrier();
    const VkBufferCopy region{sourceBase + sourceOffset, destinationOffset, byteCount};
    Vk().vkCmdCopyBuffer(mCommands, sourceBuffer, target->buffer, 1U, &region);
    TransferBarrier();
    return true;
  }

  void DeviceVulkan::TransitionForTransferWrite(vulkan::TrackedImage& image)
  {
    // Already TRANSFER_DST - an upload or copy wrote it earlier and nothing
    // read it since: Transition records no barrier then, so order the two
    // transfer writes here (write-after-write).
    if (image.image != VK_NULL_HANDLE && image.layout == VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL) {
      EndRendering();
      TransferBarrier();
      return;
    }
    Transition(image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
  }

  void DeviceVulkan::Transition(vulkan::TrackedImage& image, const VkImageLayout layout)
  {
    if (image.image == VK_NULL_HANDLE || image.layout == layout) {
      return;
    }
    EndRendering();
    VkImageMemoryBarrier2 barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER_2;
    barrier.srcStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.srcAccessMask = VK_ACCESS_2_MEMORY_WRITE_BIT;
    barrier.dstStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.dstAccessMask = VK_ACCESS_2_MEMORY_READ_BIT | VK_ACCESS_2_MEMORY_WRITE_BIT;
    barrier.oldLayout = image.layout;
    barrier.newLayout = layout;
    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.image = image.image;
    barrier.subresourceRange = {AspectOf(image.format), 0U, VK_REMAINING_MIP_LEVELS, 0U, VK_REMAINING_ARRAY_LAYERS};
    VkDependencyInfo dependency{};
    dependency.sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO;
    dependency.imageMemoryBarrierCount = 1U;
    dependency.pImageMemoryBarriers = &barrier;
    Vk().vkCmdPipelineBarrier2(mCommands, &dependency);
    image.layout = layout;
  }

  void DeviceVulkan::UploadImageLevel(
    vulkan::TrackedImage& destination, const DXGI_FORMAT format, const std::uint32_t level, const std::uint32_t layer, const void* const data
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const std::uint32_t width = std::max(1U, destination.width >> level);
    const std::uint32_t height = std::max(1U, destination.height >> level);
    const std::uint32_t depth = std::max(1U, destination.depth >> level);
    const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(format, width, height);
    const VkDeviceSize bytes = static_cast<VkDeviceSize>(layout.ByteSize()) * depth;
    const vulkan::UploadAllocation upload = AllocateUpload(bytes, 16U);
    std::memcpy(upload.cpu, data, static_cast<std::size_t>(bytes));
    EndRendering();
    TransitionForTransferWrite(destination);
    VkBufferImageCopy region{};
    region.bufferOffset = upload.offset;
    region.imageSubresource = {AspectOf(destination.format) & VK_IMAGE_ASPECT_COLOR_BIT, level, layer, 1U};
    region.imageExtent = {width, height, depth};
    Vk().vkCmdCopyBufferToImage(mCommands, upload.buffer, destination.image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1U, &region);
  }

  void DeviceVulkan::ReadImageLevel(
    vulkan::TrackedImage& source, const DXGI_FORMAT format, const std::uint32_t level, const std::uint32_t layer, std::vector<std::uint8_t>& bytes
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const std::uint32_t width = std::max(1U, source.width >> level);
    const std::uint32_t height = std::max(1U, source.height >> level);
    const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(format, width, height);
    vulkan::TrackedBuffer readback;
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = layout.ByteSize();
    info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateBuffer(mDevice, &info, nullptr, &readback.buffer));
    VkMemoryRequirements requirements{};
    Vk().vkGetBufferMemoryRequirements(mDevice, readback.buffer, &requirements);
    readback.memory = mMemory.Allocate(
      requirements, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, true
    );
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBindBufferMemory(mDevice, readback.buffer, readback.memory.memory, readback.memory.offset));

    EndRendering();
    Transition(source, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
    VkBufferImageCopy region{};
    region.imageSubresource = {AspectOf(source.format) & VK_IMAGE_ASPECT_COLOR_BIT, level, layer, 1U};
    region.imageExtent = {width, height, 1U};
    Vk().vkCmdCopyImageToBuffer(mCommands, source.image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readback.buffer, 1U, &region);
    Submit(true, false);
    bytes.assign(readback.memory.mapped, readback.memory.mapped + layout.ByteSize());
    Vk().vkDestroyBuffer(mDevice, readback.buffer, nullptr);
    mMemory.Free(readback.memory);
  }

  void DeviceVulkan::ReadImage(vulkan::TrackedImage& source, const DXGI_FORMAT format, imaging::Image& image)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    image.Allocate(format, source.width, source.height, source.mipLevels, source.layers);
    for (std::uint32_t layer = 0U; layer < source.layers; ++layer) {
      for (std::uint32_t level = 0U; level < source.mipLevels; ++level) {
        std::vector<std::uint8_t> bytes;
        ReadImageLevel(source, format, level, layer, bytes);
        const imaging::Image::Subresource& subresource = image.subresources[layer * source.mipLevels + level];
        std::memcpy(image.bytes.data() + subresource.offset, bytes.data(), std::min<std::size_t>(bytes.size(), subresource.slicePitch));
      }
    }
  }

  void DeviceVulkan::Retire(vulkan::TrackedImage& image, const VkImageView view)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    Garbage garbage;
    garbage.serial = RecordingSerial();
    garbage.view = view;
    if (image.owned) {
      garbage.image = image.image;
      garbage.memory = image.memory;
    }
    mGarbage.push_back(garbage);
  }

  void DeviceVulkan::Retire(vulkan::TrackedBuffer& buffer)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    Garbage garbage;
    garbage.serial = RecordingSerial();
    garbage.buffer = buffer.buffer;
    garbage.memory = buffer.memory;
    mGarbage.push_back(garbage);
    buffer = vulkan::TrackedBuffer{};
  }

  // ---------------------------------------------------------------------------
  // Rendering scope

  VkImageView DeviceVulkan::TargetView(VkFormat& format, vulkan::TrackedImage*& image, std::uint32_t& width, std::uint32_t& height)
  {
    if (outputContext_.surface == nullptr) {
      format = VK_FORMAT_UNDEFINED;
      image = nullptr;
      return VK_NULL_HANDLE;
    }
    auto* const target = static_cast<RenderTargetVulkan*>(outputContext_.surface.get());
    RenderTargetVulkan::Buffer& buffer = target->Current();
    format = buffer.image.format;
    image = &buffer.image;
    width = buffer.image.width;
    height = buffer.image.height;
    return buffer.view;
  }

  void DeviceVulkan::EndRendering()
  {
    if (mRendering) {
      Vk().vkCmdEndRendering(mCommands);
      mRendering = false;
    }
  }

  void DeviceVulkan::BeginRendering()
  {
    VkFormat colorFormat = VK_FORMAT_UNDEFINED;
    vulkan::TrackedImage* colorImage = nullptr;
    std::uint32_t width = 0x7FFFFFFFU;
    std::uint32_t height = 0x7FFFFFFFU;
    const VkImageView color = TargetView(colorFormat, colorImage, width, height);
    VkImageView depth = VK_NULL_HANDLE;
    vulkan::TrackedImage* depthImage = nullptr;
    if (outputContext_.depthStencil != nullptr) {
      auto* const target = static_cast<DepthStencilTargetVulkan*>(outputContext_.depthStencil.get());
      depth = target->View();
      depthImage = &target->Image();
      width = std::min(width, depthImage->width);
      height = std::min(height, depthImage->height);
    }
    if (mRendering && color == mRenderingColor && depth == mRenderingDepth) {
      return;
    }
    EndRendering();
    if (colorImage != nullptr) {
      Transition(*colorImage, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
    }
    if (depthImage != nullptr) {
      Transition(*depthImage, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL);
    }
    VkRenderingAttachmentInfo colorAttachment{};
    colorAttachment.sType = VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO;
    colorAttachment.imageView = color;
    colorAttachment.imageLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    colorAttachment.loadOp = VK_ATTACHMENT_LOAD_OP_LOAD;
    colorAttachment.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    VkRenderingAttachmentInfo depthAttachment{};
    depthAttachment.sType = VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO;
    depthAttachment.imageView = depth;
    depthAttachment.imageLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    depthAttachment.loadOp = VK_ATTACHMENT_LOAD_OP_LOAD;
    depthAttachment.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    VkRenderingInfo info{};
    info.sType = VK_STRUCTURE_TYPE_RENDERING_INFO;
    if (width == 0x7FFFFFFFU) {
      width = 1U;
      height = 1U;
    }
    info.renderArea = {{0, 0}, {width, height}};
    info.layerCount = 1U;
    info.colorAttachmentCount = (color != VK_NULL_HANDLE) ? 1U : 0U;
    info.pColorAttachments = (color != VK_NULL_HANDLE) ? &colorAttachment : nullptr;
    info.pDepthAttachment = (depth != VK_NULL_HANDLE) ? &depthAttachment : nullptr;
    info.pStencilAttachment = (depth != VK_NULL_HANDLE && depthImage != nullptr && vulkan::HasStencil(depthImage->format))
      ? &depthAttachment
      : nullptr;
    Vk().vkCmdBeginRendering(mCommands, &info);
    mRendering = true;
    mRenderingColor = color;
    mRenderingDepth = depth;
    mRenderingWidth = width;
    mRenderingHeight = height;
    mViewportDirty = true;
  }

  // ---------------------------------------------------------------------------
  // Device slots

  void* DeviceVulkan::GetLog()
  {
    return &mLog;
  }

  DeviceContext* DeviceVulkan::GetDeviceContext()
  {
    return &mDeviceContext;
  }

  int DeviceVulkan::GetCurThreadId()
  {
    return mCurThreadId;
  }

  void DeviceVulkan::Func1() const {}

  void DeviceVulkan::GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, const int adapterIndex)
  {
    static_cast<void>(adapterIndex);
    outModes.clear(); // windowed and borderless only: no exclusive modes on this backend
  }

  OutputContext* DeviceVulkan::GetHeadOutputContext(const unsigned int headIndex)
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  const OutputContext* DeviceVulkan::GetHeadOutputContext(const unsigned int headIndex) const
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  boost::shared_ptr<PipelineState> DeviceVulkan::GetPipelineState()
  {
    return mPipelineState;
  }

  boost::shared_ptr<Effect> DeviceVulkan::CreateEffect(const EffectContext& context)
  {
    if (context.mSourceType != 2U) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid source defined for effect");
    }
    EffectContext localContext(context);
    for (const MacroPair& macro : kInjectedMacros) {
      localContext.DefineMacro(macro.name, macro.value);
    }
    std::vector<D3D_SHADER_MACRO> defines;
    for (const EffectMacro& macro : localContext.mMacros) {
      defines.push_back(D3D_SHADER_MACRO{macro.keyText_.c_str(), macro.valueText_.c_str()});
    }
    defines.push_back(D3D_SHADER_MACRO{nullptr, nullptr});

    const DWORD started = ::GetTickCount();
    const char* const sourceName = context.mSourcePath.c_str();
    const std::size_t sourceBytes = static_cast<std::size_t>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
    Microsoft::WRL::ComPtr<ID3DBlob> preprocessed;
    Microsoft::WRL::ComPtr<ID3DBlob> errors;
    if (FAILED(::D3DPreprocess(context.mSourceBuffer.mBegin, sourceBytes, sourceName, defines.data(), nullptr, &preprocessed, &errors))) {
      const std::string message = std::string("unable to preprocess effect: ") + sourceName + " reason: " +
        ((errors != nullptr) ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize()) : std::string());
      ThrowError("DeviceVulkan.cpp", __LINE__, message.c_str());
    }
    d3d11::TranslatedEffectSource translated = d3d11::TranslateEffectSource(
      std::string_view(static_cast<const char*>(preprocessed->GetBufferPointer()), preprocessed->GetBufferSize() - 1U), true,
      // No original source: the D3D9 alpha test is applied by the effect layer (EffectDescription),
      // and running the translator's copy as well would test twice.
      std::string_view{}
    );
    std::shared_ptr<effects::EffectProgram> program;
    try {
      program = std::make_shared<effects::EffectProgram>(
        sourceName, std::move(translated.source), effects::ShaderTarget::Spirv,
        std::string_view(context.mSourceBuffer.mBegin, sourceBytes)
      );
    } catch (const std::exception& error) {
      const std::string message = std::string("unable to create effect: ") + sourceName + " reason: " + error.what();
      ThrowError("DeviceVulkan.cpp", __LINE__, message.c_str());
    }
    if (const char* const precompile = std::getenv("FAF_SHADER_PRECOMPILE"); precompile != nullptr && precompile[0] == '1') {
      program->CompileAll();
    }
    gpg::Logf(
      "Vulkan: effect %s: %u techniques, %u entry points, %u bytes of parameters (%lu ms)", sourceName,
      static_cast<unsigned>(program->Description().techniques.size()), static_cast<unsigned>(program->Modern().entries.size()),
      static_cast<unsigned>(program->Parameters().Constants().size()), ::GetTickCount() - started
    );
    return boost::shared_ptr<Effect>(new ProgramEffect(context, program, *this));
  }

  boost::shared_ptr<Texture> DeviceVulkan::CreateTexture(const TextureContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    imaging::Image image;
    DXGI_FORMAT dxgiFormat = DXGI_FORMAT_UNKNOWN;
    bool cube = false;
    bool contentsFromEngine = false;
    std::uint32_t width = 1U;
    std::uint32_t height = 1U;
    std::uint32_t depth = 1U;
    std::uint32_t levels = 1U;
    std::uint32_t layers = 1U;

    if (context->source_ == 2U) {
      dxgiFormat = dxgi::TextureFormatToDxgi(context->format_);
      width = std::max(context->width_, 1U);
      height = std::max(context->height_, 1U);
      levels = (context->mipmapLevels_ != 0U) ? context->mipmapLevels_ : 1U;
      contentsFromEngine = true;
    } else if (context->source_ == 1U) {
      if (context->dataBuffer_.mEnd == context->dataBuffer_.mBegin) {
        ThrowError("DeviceVulkan.cpp", __LINE__, "attempt to create texture from uninitialized memory");
      }
      imaging::DecodeOptions options;
      options.skipMipLevels = context->reserved0x44_ & 0x1FU;
      const HRESULT result = imaging::ImageCodec::Instance()->Decode(context->dataBuffer_.mBegin, context->DataSizeBytes(), options, image);
      if (FAILED(result)) {
        char message[640]{};
        std::snprintf(message, sizeof(message), "unable to load texture %s: HRESULT 0x%08lX", context->location_.c_str(),
                      static_cast<unsigned long>(result));
        ThrowError("DeviceVulkan.cpp", __LINE__, message);
      }
      dxgiFormat = image.format;
      width = image.width;
      height = image.height;
      depth = image.volume ? image.depth : 1U;
      levels = image.mipLevels;
      layers = image.volume ? 1U : image.arraySize;
      cube = image.cube;
    } else {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid source specified for texture data");
    }
    const vulkan::TextureFormat format = vulkan::ToVulkanTexture(dxgiFormat);
    if (format.format == VK_FORMAT_UNDEFINED) {
      char message[128]{};
      std::snprintf(message, sizeof(message), "unsupported texture format (DXGI %d)", static_cast<int>(dxgiFormat));
      ThrowError("DeviceVulkan.cpp", __LINE__, message);
    }

    vulkan::TrackedImage tracked;
    VkImageCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    info.imageType = (depth > 1U) ? VK_IMAGE_TYPE_3D : VK_IMAGE_TYPE_2D;
    info.format = format.format;
    info.extent = {width, height, depth};
    info.mipLevels = levels;
    info.arrayLayers = layers;
    info.flags = cube ? VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT : 0U;
    info.samples = VK_SAMPLE_COUNT_1_BIT;
    info.tiling = VK_IMAGE_TILING_OPTIMAL;
    info.usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImage(mDevice, &info, nullptr, &tracked.image));
    VkMemoryRequirements requirements{};
    Vk().vkGetImageMemoryRequirements(mDevice, tracked.image, &requirements);
    tracked.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, false);
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBindImageMemory(mDevice, tracked.image, tracked.memory.memory, tracked.memory.offset));
    tracked.format = format.format;
    tracked.width = width;
    tracked.height = height;
    tracked.depth = depth;
    tracked.mipLevels = levels;
    tracked.layers = layers;

    if (contentsFromEngine) {
      // Zeroed levels, matching the CPU copy TextureVulkan starts from.
      for (std::uint32_t level = 0U; level < levels; ++level) {
        const dxgi::LevelLayout layout =
          dxgi::ComputeLevelLayout(dxgiFormat, std::max(1U, width >> level), std::max(1U, height >> level));
        const std::vector<std::uint8_t> zeros(layout.ByteSize(), 0U);
        UploadImageLevel(tracked, dxgiFormat, level, 0U, zeros.data());
      }
    } else {
      for (std::uint32_t layer = 0U; layer < layers; ++layer) {
        for (std::uint32_t level = 0U; level < levels; ++level) {
          const imaging::Image::Subresource& subresource = image.subresources[layer * levels + level];
          UploadImageLevel(tracked, dxgiFormat, level, layer, image.bytes.data() + subresource.offset);
        }
      }
    }

    VkImageViewCreateInfo view{};
    view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view.image = tracked.image;
    view.viewType = (depth > 1U) ? VK_IMAGE_VIEW_TYPE_3D : cube ? VK_IMAGE_VIEW_TYPE_CUBE : (layers > 1U) ? VK_IMAGE_VIEW_TYPE_2D_ARRAY
                                                                                                         : VK_IMAGE_VIEW_TYPE_2D;
    view.format = format.format;
    view.components = format.swizzle;
    view.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, levels, 0U, layers};
    VkImageView imageView = VK_NULL_HANDLE;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImageView(mDevice, &view, nullptr, &imageView));
    return boost::shared_ptr<Texture>(new TextureVulkan(*context, tracked, imageView, dxgiFormat, cube, contentsFromEngine));
  }

  boost::shared_ptr<RenderTarget> DeviceVulkan::CreateRenderTarget(const RenderTargetContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const DXGI_FORMAT dxgiFormat = dxgi::RenderTargetFormatToDxgi(context->format_);
    const vulkan::TextureFormat format = vulkan::ToVulkanTexture(dxgiFormat);
    if (format.format == VK_FORMAT_UNDEFINED) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "unsupported render target format");
    }
    RenderTargetVulkan::Buffer buffer;
    VkImageCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    info.imageType = VK_IMAGE_TYPE_2D;
    info.format = format.format;
    info.extent = {std::max(context->width_, 1U), std::max(context->height_, 1U), 1U};
    info.mipLevels = 1U;
    info.arrayLayers = 1U;
    info.samples = VK_SAMPLE_COUNT_1_BIT;
    info.tiling = VK_IMAGE_TILING_OPTIMAL;
    info.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT |
      VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImage(mDevice, &info, nullptr, &buffer.image.image));
    VkMemoryRequirements requirements{};
    Vk().vkGetImageMemoryRequirements(mDevice, buffer.image.image, &requirements);
    buffer.image.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, false);
    CheckVk("DeviceVulkan.cpp", __LINE__,
            Vk().vkBindImageMemory(mDevice, buffer.image.image, buffer.image.memory.memory, buffer.image.memory.offset));
    buffer.image.format = format.format;
    buffer.image.width = info.extent.width;
    buffer.image.height = info.extent.height;
    VkImageViewCreateInfo view{};
    view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view.image = buffer.image.image;
    view.viewType = VK_IMAGE_VIEW_TYPE_2D;
    view.format = format.format;
    view.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 1U, 0U, 1U};
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImageView(mDevice, &view, nullptr, &buffer.view));

    D3DVIEWPORT9 viewport{};
    viewport.Width = info.extent.width;
    viewport.Height = info.extent.height;
    viewport.MaxZ = 1.0f;
    SetViewport(&viewport);

    std::vector<RenderTargetVulkan::Buffer> buffers{buffer};
    return boost::shared_ptr<RenderTarget>(new RenderTargetVulkan(std::move(buffers), dxgiFormat, -1));
  }

  boost::shared_ptr<CubeRenderTarget> DeviceVulkan::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
  {
    return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetVulkan(*context));
  }

  boost::shared_ptr<DepthStencilTarget> DeviceVulkan::CreateDepthStencilTarget(const DepthStencilTargetContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    VkFormat format = mDepthStencilFormat;
    if (context->format_ == 1U) {
      format = VK_FORMAT_D32_SFLOAT;
    } else if (context->format_ == 6U) {
      format = VK_FORMAT_D16_UNORM;
    }
    vulkan::TrackedImage image;
    VkImageCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    info.imageType = VK_IMAGE_TYPE_2D;
    info.format = format;
    info.extent = {std::max(context->width_, 1U), std::max(context->height_, 1U), 1U};
    info.mipLevels = 1U;
    info.arrayLayers = 1U;
    info.samples = VK_SAMPLE_COUNT_1_BIT;
    info.tiling = VK_IMAGE_TILING_OPTIMAL;
    info.usage = VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT | (context->field0x10_ ? VK_IMAGE_USAGE_SAMPLED_BIT : 0U);
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImage(mDevice, &info, nullptr, &image.image));
    VkMemoryRequirements requirements{};
    Vk().vkGetImageMemoryRequirements(mDevice, image.image, &requirements);
    image.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, false);
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkBindImageMemory(mDevice, image.image, image.memory.memory, image.memory.offset));
    image.format = format;
    image.aspect = AspectOf(format);
    image.width = info.extent.width;
    image.height = info.extent.height;
    VkImageViewCreateInfo view{};
    view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view.image = image.image;
    view.viewType = VK_IMAGE_VIEW_TYPE_2D;
    view.format = format;
    view.subresourceRange = {AspectOf(format), 0U, 1U, 0U, 1U};
    VkImageView imageView = VK_NULL_HANDLE;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateImageView(mDevice, &view, nullptr, &imageView));
    return boost::shared_ptr<DepthStencilTarget>(new DepthStencilTargetVulkan(*context, image, imageView));
  }

  boost::shared_ptr<VertexFormat> DeviceVulkan::CreateVertexFormat(const std::uint32_t formatCode)
  {
    if (formatCode >= d3d11::kVertexFormatCount || d3d11::VertexLayoutElements(formatCode).empty()) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid vertex format specified");
    }
    return boost::shared_ptr<VertexFormat>(new VertexFormatVulkan(formatCode));
  }

  boost::shared_ptr<VertexBuffer> DeviceVulkan::CreateVertexBuffer(const VertexBufferContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    return boost::shared_ptr<VertexBuffer>(new VertexBufferVulkan(*context));
  }

  boost::shared_ptr<IndexBuffer> DeviceVulkan::CreateIndexBuffer(const IndexBufferContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    return boost::shared_ptr<IndexBuffer>(new IndexBufferVulkan(*context));
  }

  void DeviceVulkan::CopyImage(
    vulkan::TrackedImage& source, vulkan::TrackedImage& destination, const RECT* const sourceRect, const RECT* const destinationRect,
    const bool scale
  )
  {
    EndRendering();
    Transition(source, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
    TransitionForTransferWrite(destination);
    if (!scale) {
      VkImageCopy region{};
      region.srcSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 0U, 1U};
      region.dstSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 0U, 1U};
      std::uint32_t width = std::min(source.width, destination.width);
      std::uint32_t height = std::min(source.height, destination.height);
      if (sourceRect != nullptr) {
        region.srcOffset = {sourceRect->left, sourceRect->top, 0};
        width = static_cast<std::uint32_t>(sourceRect->right - sourceRect->left);
        height = static_cast<std::uint32_t>(sourceRect->bottom - sourceRect->top);
      }
      if (destinationRect != nullptr) {
        region.dstOffset = {destinationRect->left, destinationRect->top, 0};
      }
      region.extent = {width, height, 1U};
      Vk().vkCmdCopyImage(mCommands, source.image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, destination.image,
                          VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1U, &region);
    } else {
      // As D3D10/11: a whole-target stretch, linear filtered.
      VkImageBlit region{};
      region.srcSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 0U, 1U};
      region.dstSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0U, 0U, 1U};
      region.srcOffsets[1] = {static_cast<std::int32_t>(source.width), static_cast<std::int32_t>(source.height), 1};
      region.dstOffsets[1] = {static_cast<std::int32_t>(destination.width), static_cast<std::int32_t>(destination.height), 1};
      Vk().vkCmdBlitImage(mCommands, source.image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, destination.image,
                          VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1U, &region, VK_FILTER_LINEAR);
    }
  }

  void DeviceVulkan::GetRenderTargetData(const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination)
  {
    if (source == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const target = static_cast<TextureVulkan*>(destination.get());
    CopyImage(static_cast<RenderTargetVulkan*>(source.get())->Current().image, target->Image(), nullptr, nullptr, false);
    target->DiscardCpuCopy();
  }

  void DeviceVulkan::StretchRect(
    const boost::shared_ptr<RenderTarget>& source,
    const boost::shared_ptr<RenderTarget>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const from = static_cast<RenderTargetVulkan*>(source.get());
    auto* const to = static_cast<RenderTargetVulkan*>(destination.get());
    vulkan::TrackedImage& fromImage = from->Current().image;
    vulkan::TrackedImage& toImage = to->Current().image;
    const bool same = fromImage.width == toImage.width && fromImage.height == toImage.height && fromImage.format == toImage.format;
    CopyImage(fromImage, toImage, same ? sourceRect : nullptr, same ? destinationRect : nullptr, !same);
  }

  void DeviceVulkan::UpdateSurface(
    const boost::shared_ptr<Texture>& source,
    const boost::shared_ptr<Texture>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const from = static_cast<TextureVulkan*>(source.get());
    auto* const to = static_cast<TextureVulkan*>(destination.get());
    if (from->Image().width == to->Image().width && from->Image().height == to->Image().height && from->DxgiFormat() == to->DxgiFormat()) {
      CopyImage(from->Image(), to->Image(), sourceRect, destinationRect, false);
      to->DiscardCpuCopy();
      return;
    }
    // Re-encoded and reloaded in the destination's shape (see DeviceD3D11::UpdateSurface).
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    imaging::Image sourceImage;
    ReadImage(from->Image(), from->DxgiFormat(), sourceImage);
    std::vector<std::uint8_t> encoded;
    CheckHresult("DeviceVulkan.cpp", __LINE__, codec->Encode(sourceImage, imaging::FileFormat::Dds, encoded));
    imaging::DecodeOptions options;
    options.format = to->DxgiFormat();
    options.width = to->Image().width;
    options.height = to->Image().height;
    options.mipLevels = to->Image().mipLevels;
    imaging::Image converted;
    CheckHresult("DeviceVulkan.cpp", __LINE__, codec->Decode(encoded.data(), encoded.size(), options, converted));
    for (std::uint32_t level = 0U; level < converted.mipLevels && level < to->Image().mipLevels; ++level) {
      UploadImageLevel(to->Image(), to->DxgiFormat(), level, 0U, converted.bytes.data() + converted.subresources[level].offset);
    }
    to->DiscardCpuCopy();
  }

  void DeviceVulkan::SaveCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const msvc8::string& filePath)
  {
    static_cast<void>(cubeTarget);
    static_cast<void>(filePath);
  }

  void DeviceVulkan::SaveRenderTarget(const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, const int fileFormat)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const target = static_cast<RenderTargetVulkan*>(renderTarget.get());
    imaging::Image image;
    ReadImage(target->Current().image, target->DxgiFormat(), image);
    CheckHresult(
      "DeviceVulkan.cpp", __LINE__,
      imaging::ImageCodec::Instance()->EncodeToFile(image, imaging::ImageCodec::FromGalFormat(fileFormat), filePath.c_str())
    );
  }

  void DeviceVulkan::SaveTexture(
    const boost::shared_ptr<Texture>& texture, const msvc8::string& filePath, const int fileFormat, gpg::MemBuffer<char>* const outBuffer
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const source = static_cast<TextureVulkan*>(texture.get());
    imaging::Image image;
    ReadImage(source->Image(), source->DxgiFormat(), image);
    image.cube = source->IsCube();
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    if (outBuffer == nullptr) {
      CheckHresult("DeviceVulkan.cpp", __LINE__, codec->EncodeToFile(image, imaging::ImageCodec::FromGalFormat(fileFormat), filePath.c_str()));
      return;
    }
    std::vector<std::uint8_t> encoded;
    CheckHresult("DeviceVulkan.cpp", __LINE__, codec->Encode(image, imaging::ImageCodec::FromGalFormat(fileFormat), encoded));
    if (outBuffer->Size() != encoded.size()) {
      *outBuffer = gpg::AllocMemBuffer(encoded.size());
    }
    std::copy(encoded.begin(), encoded.end(), outBuffer->GetPtr(0U, 0U));
  }

  void DeviceVulkan::GetTexture2D(
    const void* const sourceData, const std::uint32_t sourceBytes, gpg::MemBuffer<char>* const outTextureData, std::uint32_t* const outWidth,
    int* const outHeight
  )
  {
    if (sourceData == nullptr) {
      return;
    }
    imaging::DecodeOptions options;
    options.format = DXGI_FORMAT_BC3_UNORM;
    options.mipLevels = 1U;
    imaging::Image image;
    CheckHresult("DeviceVulkan.cpp", __LINE__, imaging::ImageCodec::Instance()->Decode(sourceData, sourceBytes, options, image));
    *outWidth = image.width;
    *outHeight = static_cast<int>(image.height);
    const imaging::Image::Subresource& top = image.subresources.front();
    if (outTextureData->Size() != top.slicePitch) {
      *outTextureData = gpg::AllocMemBuffer(top.slicePitch);
    }
    std::memcpy(outTextureData->GetPtr(0U, 0U), image.bytes.data() + top.offset, top.slicePitch);
  }

  boost::weak_ptr<void>* DeviceVulkan::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
  {
    static_cast<void>(temporarySharedHandle);
    outWeakHandle->reset();
    return outWeakHandle;
  }

  void DeviceVulkan::Reset(DeviceContext* const context)
  {
    if (mDevice == VK_NULL_HANDLE) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    gpg::Logf("Vulkan: Reset requested");
    if (context != nullptr && context != &mDeviceContext) {
      mDeviceContext.mVSync = context->mVSync;
      const int heads = std::min(context->GetHeadCount(), mDeviceContext.GetHeadCount());
      for (int headIndex = 0; headIndex < heads; ++headIndex) {
        const Head& requested = context->GetHead(static_cast<std::uint32_t>(headIndex));
        Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
        head.mWidth = requested.mWidth;
        head.mHeight = requested.mHeight;
      }
    }
    ReleaseRenderTargets();
    Vk().vkDeviceWaitIdle(mDevice);
    CollectCompleted();
    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
      std::uint32_t width = head.mWidth;
      std::uint32_t height = head.mHeight;
      if (width == 0U || height == 0U) {
        RECT client{};
        ::GetClientRect(static_cast<HWND>(head.mWindow), &client);
        width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }
      CreateSwapChain(mSwapChains[headIndex], width, height);
    }
    // The acquire semaphores of the old images may be signalled: start the frame over.
    Submit(true, false);
    AcquireNextImages();
    ResetState();
    CreateRenderTargets();
  }

  void DeviceVulkan::Reset()
  {
    Reset(&mDeviceContext);
  }

  int DeviceVulkan::TestCooperativeLevel()
  {
    return 0;
  }

  void DeviceVulkan::BeginScene() {}

  void DeviceVulkan::EndScene() {}

  void DeviceVulkan::Trace(const char* const format, ...)
  {
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    gpg::Logf("Vulkan trace f%u: %s", mFrameNumber, line);
  }

  void DeviceVulkan::DumpBackBufferIfDue()
  {
    static const char* const directory = std::getenv("FAF_GAL_DUMP_DIR");
    if (directory == nullptr || directory[0] == 0 || mHeadOutputContexts.empty() || !mSwapChains.front().hasImage) {
      return;
    }
    static const DWORD interval = [] {
      const char* const seconds = std::getenv("FAF_GAL_DUMP_SECONDS");
      const long value = (seconds != nullptr) ? std::strtol(seconds, nullptr, 10) : 10L;
      return static_cast<DWORD>((value > 0L) ? value * 1000L : 10000L);
    }();
    const DWORD now = ::GetTickCount();
    if (mLastDumpTick != 0U && now - mLastDumpTick < interval) {
      return;
    }
    if (mLastDumpTick == 0U) {
      mFirstDumpTick = now;
    }
    mLastDumpTick = now;
    char path[MAX_PATH]{};
    std::snprintf(path, sizeof(path), "%s/vulkan_%06lu.bmp", directory, static_cast<unsigned long>((now - mFirstDumpTick) / 1000U));
    auto* const target = static_cast<RenderTargetVulkan*>(mHeadOutputContexts.front().surface.get());
    imaging::Image image;
    ReadImage(target->Current().image, DXGI_FORMAT_B8G8R8A8_UNORM, image);
    WriteBmp(path, image);
  }

  void DeviceVulkan::Present()
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    ++mFrameNumber;
    {
      static const long start = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_START");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : -1L;
      }();
      static const long frames = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_FRAMES");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : 1L;
      }();
      mTracing = start >= 0L && static_cast<long>(mFrameNumber) >= start && static_cast<long>(mFrameNumber) < start + frames;
    }
    DumpBackBufferIfDue();

    for (std::size_t index = 0U; index < mHeadOutputContexts.size(); ++index) {
      if (mSwapChains[index].hasImage) {
        Transition(static_cast<RenderTargetVulkan*>(mHeadOutputContexts[index].surface.get())->Current().image,
                   VK_IMAGE_LAYOUT_PRESENT_SRC_KHR);
      }
    }
    EndProfileFrame();
    Submit(false, true);

    for (std::size_t index = 0U; index < mSwapChains.size(); ++index) {
      SwapChain& swapChain = mSwapChains[index];
      if (!swapChain.hasImage) {
        continue;
      }
      VkPresentInfoKHR present{};
      present.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
      present.waitSemaphoreCount = 1U;
      present.pWaitSemaphores = &swapChain.renderFinished[swapChain.acquired];
      present.swapchainCount = 1U;
      present.pSwapchains = &swapChain.swapchain;
      present.pImageIndices = &swapChain.acquired;
      const VkResult result = Vk().vkQueuePresentKHR(mQueue, &present);
      if (result == VK_ERROR_DEVICE_LOST) {
        CheckVk("DeviceVulkan.cpp", __LINE__, result);
      } else if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR) {
        static int logged = 0;
        if (logged++ < 8) {
          gpg::Warnf("Vulkan: present of head %u: %s", static_cast<unsigned>(index), vulkan::ResultName(result));
        }
      }
    }

    // The next frame slot: wait for what the GPU last did with it.
    mFrameIndex = (mFrameIndex + 1U) % vulkan::kFramesInFlight;
    ++mFrameCount;
    Frame& frame = mFrames[mFrameIndex];
    WaitForSerial(frame.serial);
    CollectCompleted();
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkResetCommandPool(mDevice, frame.pool, 0U));
    frame.used = 0U;
    for (VkDescriptorPool pool : frame.descriptorPools) {
      Vk().vkResetDescriptorPool(mDevice, pool, 0U);
    }
    frame.descriptorPool = 0U;
    for (VkDescriptorPool pool : frame.gpuPools) {
      Vk().vkResetDescriptorPool(mDevice, pool, 0U);
    }
    frame.gpuPool = 0U;
    AcquireNextImages();
    BeginCommandBuffer();
    if (mSkippedDraws != 0U) {
      static int logged = 0;
      if (logged++ < 10) {
        gpg::Warnf("Vulkan: %u draw(s) skipped in frame %u (pass without shaders or pipeline)", mSkippedDraws, mFrameNumber);
      }
      mSkippedDraws = 0U;
    }
  }

  void DeviceVulkan::SetCursor(const CursorContext* const context)
  {
    static_cast<void>(mCursor.SetCursor(*context));
  }

  void DeviceVulkan::InitCursor()
  {
    static_cast<void>(mCursor.InitCursor());
  }

  int DeviceVulkan::ShowCursor(const bool show)
  {
    return mCursor.ShowCursor(show);
  }

  void DeviceVulkan::SetViewport(const D3DVIEWPORT9* const viewport)
  {
    mViewport = *viewport;
    mViewportDirty = true;
  }

  void DeviceVulkan::GetViewport(D3DVIEWPORT9* const outViewport)
  {
    *outViewport = mViewport;
  }

  void DeviceVulkan::ClearTarget(const OutputContext* const context)
  {
    const RenderTarget* const previousSurface = outputContext_.surface.get();
    Device::ClearTarget(context);
    // D3D9's SetRenderTarget resets the viewport to the whole new target, and
    // DeviceD3D9::ClearTarget calls it only when the colour target changes
    // (0x008EDB37). The engine relies on both: it clears the 1024x1024
    // shadow map before setting any viewport, and it rebinds a target it is
    // already drawing into while keeping its own viewport. D3D10 dropped this.
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    if (outputContext_.surface != nullptr && outputContext_.surface.get() != previousSurface) {
      width = outputContext_.surface->GetContext()->width_;
      height = outputContext_.surface->GetContext()->height_;
    }
    if (width != 0U && height != 0U) {
      D3DVIEWPORT9 viewport{};
      viewport.Width = width;
      viewport.Height = height;
      viewport.MinZ = 0.0f;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceVulkan::Clear(
    const bool clearColor, const bool clearDepth, const bool clearStencil, const std::uint32_t packedColor, const float depth, const int stencil
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    BeginRendering();
    constexpr float kScale = 1.0f / 255.0f;
    VkClearAttachment attachments[2]{};
    std::uint32_t count = 0U;
    if (clearColor && mRenderingColor != VK_NULL_HANDLE) {
      VkClearAttachment& color = attachments[count++];
      color.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
      color.colorAttachment = 0U;
      color.clearValue.color.float32[0] = static_cast<float>((packedColor >> 16U) & 0xFFU) * kScale;
      color.clearValue.color.float32[1] = static_cast<float>((packedColor >> 8U) & 0xFFU) * kScale;
      color.clearValue.color.float32[2] = static_cast<float>(packedColor & 0xFFU) * kScale;
      color.clearValue.color.float32[3] = static_cast<float>((packedColor >> 24U) & 0xFFU) * kScale;
    }
    if ((clearDepth || clearStencil) && mRenderingDepth != VK_NULL_HANDLE) {
      VkClearAttachment& depthStencil = attachments[count++];
      auto* const target = static_cast<DepthStencilTargetVulkan*>(outputContext_.depthStencil.get());
      depthStencil.aspectMask = (clearDepth ? VK_IMAGE_ASPECT_DEPTH_BIT : 0U) |
        ((clearStencil && vulkan::HasStencil(target->Image().format)) ? VK_IMAGE_ASPECT_STENCIL_BIT : 0U);
      depthStencil.clearValue.depthStencil = {depth, static_cast<std::uint32_t>(stencil & 0xFF)};
      if (depthStencil.aspectMask == 0U) {
        --count;
      }
    }
    if (count == 0U) {
      return;
    }
    // D3D9's Clear covers the viewport, clipped to the targets.
    const std::int32_t left = std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.X), static_cast<std::int32_t>(mRenderingWidth));
    const std::int32_t top = std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.Y), static_cast<std::int32_t>(mRenderingHeight));
    const std::int32_t right =
      std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.X + mViewport.Width), static_cast<std::int32_t>(mRenderingWidth));
    const std::int32_t bottom =
      std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.Y + mViewport.Height), static_cast<std::int32_t>(mRenderingHeight));
    if (right <= left || bottom <= top) {
      return;
    }
    VkClearRect rect{};
    rect.rect = {{left, top}, {static_cast<std::uint32_t>(right - left), static_cast<std::uint32_t>(bottom - top)}};
    rect.baseArrayLayer = 0U;
    rect.layerCount = 1U;
    Vk().vkCmdClearAttachments(mCommands, count, attachments, 1U, &rect);
  }

  void DeviceVulkan::ClearTextures() {}

  void DeviceVulkan::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
  {
    RecordStateChange();
    mBoundFormat = vertexFormat->formatCode_;
  }

  void DeviceVulkan::SetVertexBuffer(
    const std::uint32_t streamSlot, const boost::shared_ptr<VertexBuffer> vertexBuffer, const int streamFrequencyToken, const int startVertex
  )
  {
    RecordStateChange();
    if (streamSlot >= std::size(mStreams)) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid vertex stream");
    }
    StreamBinding& stream = mStreams[streamSlot];
    stream.buffer = vertexBuffer;
    stream.stride = vertexBuffer->GetContext()->stride_;
    stream.offset = static_cast<std::uint32_t>(startVertex) * stream.stride;
    mStreamFrequencies[streamSlot] = streamFrequencyToken;
  }

  void DeviceVulkan::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
  {
    RecordStateChange();
    mIndexBuffer = indexBuffer;
  }

  void DeviceVulkan::SetFogState(const bool, const Matrix* const, const float, const float, const int) {}

  void DeviceVulkan::SetWireframeState(const bool enabled)
  {
    mWireframe = enabled;
  }

  void DeviceVulkan::SetColorWriteState(const bool writeColor, const bool writeAlpha)
  {
    if (writeColor) {
      mColorWriteMask = writeAlpha ? 0x0FU : 0x07U;
    } else {
      mColorWriteMask = writeAlpha ? 0x08U : 0x0FU;
    }
  }

  void DeviceVulkan::BeginTechnique()
  {
    mCurrent.blend = effects::BlendDesc{};
    mCurrent.depthStencil = effects::DepthStencilDesc{};
    mCurrent.rasterizer = effects::RasterizerDesc{};
    std::fill(std::begin(mCurrent.blendFactor), std::end(mCurrent.blendFactor), 0.0f);
    mCurrent.sampleMask = 0xFFFFFFFFU;
    mCurrent.stencilRef = 0U;
  }

  void DeviceVulkan::EndTechnique() {}

  // ---------------------------------------------------------------------------
  // Passes and draws

  VkSampler DeviceVulkan::SamplerFor(const effects::SamplerDesc& desc)
  {
    KeyWriter key;
    key.Add(desc.filter);
    key.Add(desc.addressU);
    key.Add(desc.addressV);
    key.Add(desc.addressW);
    key.Add(desc.maxAnisotropy);
    key.Add(desc.mipLodBias);
    key.Add(desc.borderColor);
    key.Add(desc.minLod);
    key.Add(desc.maxLod);
    const auto found = mSamplers.find(key.Key());
    if (found != mSamplers.end()) {
      return found->second;
    }
    // D3D11_FILTER: bit 0 mip linear, bit 2 mag linear, bit 4 min linear,
    // 0x40 anisotropic, 0x80 comparison.
    VkSamplerCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
    const bool anisotropic = (desc.filter & 0x40U) != 0U;
    info.magFilter = (anisotropic || (desc.filter & 0x04U) != 0U) ? VK_FILTER_LINEAR : VK_FILTER_NEAREST;
    info.minFilter = (anisotropic || (desc.filter & 0x10U) != 0U) ? VK_FILTER_LINEAR : VK_FILTER_NEAREST;
    info.mipmapMode = (anisotropic || (desc.filter & 0x01U) != 0U) ? VK_SAMPLER_MIPMAP_MODE_LINEAR : VK_SAMPLER_MIPMAP_MODE_NEAREST;
    info.addressModeU = AddressMode(desc.addressU);
    info.addressModeV = AddressMode(desc.addressV);
    info.addressModeW = AddressMode(desc.addressW);
    info.mipLodBias = desc.mipLodBias;
    info.anisotropyEnable = (anisotropic && mAnisotropy) ? VK_TRUE : VK_FALSE;
    info.maxAnisotropy = std::clamp(static_cast<float>(desc.maxAnisotropy), 1.0f, mProperties.limits.maxSamplerAnisotropy);
    info.compareEnable = VK_FALSE;
    info.minLod = std::max(desc.minLod, 0.0f);
    info.maxLod = std::max(desc.maxLod, info.minLod);
    // Vulkan has three border colours; the nearest stands in.
    const float brightness = desc.borderColor[0] + desc.borderColor[1] + desc.borderColor[2];
    info.borderColor = (brightness > 1.5f) ? VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE
      : (desc.borderColor[3] > 0.5f)       ? VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK
                                           : VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK;
    VkSampler sampler = VK_NULL_HANDLE;
    CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateSampler(mDevice, &info, nullptr, &sampler));
    mSamplers.emplace(key.Key(), sampler);
    return sampler;
  }

  DeviceVulkan::ProgramState& DeviceVulkan::StateFor(effects::EffectProgram& program)
  {
    std::shared_ptr<void>& slot = program.BackendState();
    if (slot == nullptr) {
      auto state = std::make_shared<ProgramState>();
      for (const effects::SamplerDesc& sampler : program.Description().samplers) {
        state->samplers.push_back(SamplerFor(sampler));
      }
      state->viewportParameter = program.FindParameter("faf_ViewportSize");
      slot = state;
    }
    return *static_cast<ProgramState*>(slot.get());
  }

  VkDescriptorSet DeviceVulkan::AllocateSet(const VkDescriptorSetLayout layout)
  {
    Frame& frame = mFrames[mFrameIndex];
    for (;;) {
      if (frame.descriptorPool == frame.descriptorPools.size()) {
        const VkDescriptorPoolSize sizes[3] = {
          {VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 4096U},
          {VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 4096U * 8U},
          {VK_DESCRIPTOR_TYPE_SAMPLER, 4096U * 8U},
        };
        VkDescriptorPoolCreateInfo info{};
        info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        info.maxSets = 4096U;
        info.poolSizeCount = 3U;
        info.pPoolSizes = sizes;
        VkDescriptorPool pool = VK_NULL_HANDLE;
        CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateDescriptorPool(mDevice, &info, nullptr, &pool));
        frame.descriptorPools.push_back(pool);
      }
      VkDescriptorSetAllocateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
      info.descriptorPool = frame.descriptorPools[frame.descriptorPool];
      info.descriptorSetCount = 1U;
      info.pSetLayouts = &layout;
      VkDescriptorSet set = VK_NULL_HANDLE;
      const VkResult result = Vk().vkAllocateDescriptorSets(mDevice, &info, &set);
      if (result == VK_SUCCESS) {
        return set;
      }
      if (result != VK_ERROR_OUT_OF_POOL_MEMORY && result != VK_ERROR_FRAGMENTED_POOL) {
        CheckVk("DeviceVulkan.cpp", __LINE__, result);
      }
      ++frame.descriptorPool; // this pool is full: the next one
    }
  }

  void DeviceVulkan::BindPass(effects::EffectProgram& program, const std::uint32_t technique, const std::uint32_t pass)
  {
    RecordStateChange();
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const effects::Pass& passDesc = program.Description().techniques[technique].passes[pass];
    if (passDesc.blend.has_value()) {
      mCurrent.blend = *passDesc.blend;
      std::copy(std::begin(passDesc.blendFactor), std::end(passDesc.blendFactor), std::begin(mCurrent.blendFactor));
      mCurrent.sampleMask = passDesc.sampleMask;
    }
    if (passDesc.depthStencil.has_value()) {
      mCurrent.depthStencil = *passDesc.depthStencil;
      mCurrent.stencilRef = passDesc.stencilRef;
    }
    if (passDesc.rasterizer.has_value()) {
      mCurrent.rasterizer = *passDesc.rasterizer;
    }

    BoundPass bound;
    bound.program = &program;
    bound.state = mCurrent;
    if (!passDesc.blend.has_value() && mColorWriteMask != 0x0FU && bound.state.blend.writeMask == 0x0FU) {
      bound.state.blend.writeMask = mColorWriteMask;
    }
    if (!passDesc.rasterizer.has_value() && mWireframe && bound.state.rasterizer.fillMode == 3U) {
      bound.state.rasterizer.fillMode = 2U;
    }
    const effects::PassEntries& entries = program.Entries(technique, pass);
    if (entries.vertex >= 0) {
      bound.vertexShader = &program.Shader(static_cast<std::uint32_t>(entries.vertex));
    }
    if (entries.pixel >= 0) {
      bound.pixelShader = &program.Shader(static_cast<std::uint32_t>(entries.pixel));
    }
    bound.valid = bound.vertexShader != nullptr && bound.vertexShader->succeeded &&
      (bound.pixelShader == nullptr || bound.pixelShader->succeeded);

    ProgramState& state = StateFor(program);
    effects::ParameterStore& parameters = program.Parameters();
    if (state.viewportParameter >= 0) {
      // The fixed-function vertex emulation adds the D3D10 half pixel itself,
      // so the origin takes the viewport's shift too.
      const float shift = backend::Direct3D9PixelCentreShift();
      const float size[4] = {
        static_cast<float>(mViewport.X) + shift, static_cast<float>(mViewport.Y) + shift,
        (mViewport.Width != 0U) ? 1.0f / static_cast<float>(mViewport.Width) : 0.0f,
        (mViewport.Height != 0U) ? 1.0f / static_cast<float>(mViewport.Height) : 0.0f,
      };
      if (!std::equal(std::begin(size), std::end(size), std::begin(state.lastViewport))) {
        std::copy(std::begin(size), std::end(size), std::begin(state.lastViewport));
        parameters.SetVector(static_cast<std::uint32_t>(state.viewportParameter), size);
      }
    }

    // $Globals in set 1, snapshotted as D3D9's BeginPass does.
    const std::span<const std::uint8_t> constants = parameters.Constants();
    if (!constants.empty()) {
      if (state.constants == VK_NULL_HANDLE || state.constantsVersion != parameters.Version() ||
          state.constantsSerial != RecordingSerial() || state.constantsFrame != mFrameCount) {
        const VkDeviceSize alignment = std::max<VkDeviceSize>(mProperties.limits.minUniformBufferOffsetAlignment, 16U);
        const vulkan::UploadAllocation upload = AllocateUpload(constants.size(), alignment);
        std::memcpy(upload.cpu, constants.data(), constants.size());
        const VkDescriptorSet set = AllocateSet(mConstantLayout);
        VkDescriptorBufferInfo buffer{upload.buffer, upload.offset, constants.size()};
        VkWriteDescriptorSet write{};
        write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        write.dstSet = set;
        write.dstBinding = 0U;
        write.descriptorCount = 1U;
        write.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
        write.pBufferInfo = &buffer;
        Vk().vkUpdateDescriptorSets(mDevice, 1U, &write, 0U, nullptr);
        state.constants = set;
        state.constantsVersion = parameters.Version();
        state.constantsSerial = RecordingSerial();
        state.constantsFrame = mFrameCount;
      }
      bound.constants = state.constants;
    }

    // Textures and samplers in set 0, rebuilt when a binding changed or the frame moved on.
    if (state.table == VK_NULL_HANDLE || state.tableFrame != mFrameCount || state.textureVersion != parameters.TextureVersion() ||
        state.tableSurface != outputContext_.surface.get()) {
      const auto& slots = program.Modern().textures;
      const auto& slotParameters = program.TextureSlotParameters();
      auto bindings = std::make_shared<std::vector<effects::TextureBinding>>();
      const VkDescriptorSet set = AllocateSet(mTextureLayout);
      std::vector<VkDescriptorImageInfo> images(slots.size());
      std::vector<VkDescriptorImageInfo> samplers(state.samplers.size());
      std::vector<VkWriteDescriptorSet> writes;
      for (std::size_t index = 0U; index < slots.size() && index < kTextureBindings; ++index) {
        const effects::TextureSlot& slot = slots[index];
        const std::int32_t parameter = slotParameters[index];
        effects::TextureBinding binding =
          (parameter >= 0) ? parameters.Binding(static_cast<std::uint32_t>(parameter)) : effects::TextureBinding{};
        VkImageView view = mNullViews[static_cast<int>(slot.dimension)];
        if (binding.texture != nullptr) {
          auto* const texture = static_cast<TextureVulkan*>(binding.texture.get());
          const bool matches = (slot.dimension == effects::TextureDimension::TextureCube) ? texture->IsCube()
            : (slot.dimension == effects::TextureDimension::Texture3D)                   ? texture->IsVolume()
                                                                                         : (!texture->IsCube() && !texture->IsVolume());
          if (matches) {
            view = texture->View();
          } else {
            binding = effects::TextureBinding{};
          }
        } else if (binding.renderTarget != nullptr && slot.dimension == effects::TextureDimension::Texture2D) {
          if (binding.renderTarget.get() == outputContext_.surface.get()) {
            binding = effects::TextureBinding{}; // a pass sampling its own target reads zero (D3D10/11)
          } else {
            view = static_cast<RenderTargetVulkan*>(binding.renderTarget.get())->Current().view;
          }
        } else {
          binding = effects::TextureBinding{};
        }
        images[index] = VkDescriptorImageInfo{VK_NULL_HANDLE, view, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
        VkWriteDescriptorSet write{};
        write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        write.dstSet = set;
        write.dstBinding = static_cast<std::uint32_t>(index);
        write.descriptorCount = 1U;
        write.descriptorType = VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE;
        write.pImageInfo = &images[index];
        writes.push_back(write);
        bindings->push_back(binding);
      }
      for (std::size_t index = 0U; index < state.samplers.size() && index < kSamplerBindings; ++index) {
        samplers[index] = VkDescriptorImageInfo{state.samplers[index], VK_NULL_HANDLE, VK_IMAGE_LAYOUT_UNDEFINED};
        VkWriteDescriptorSet write{};
        write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        write.dstSet = set;
        write.dstBinding = kTextureBindings + static_cast<std::uint32_t>(index);
        write.descriptorCount = 1U;
        write.descriptorType = VK_DESCRIPTOR_TYPE_SAMPLER;
        write.pImageInfo = &samplers[index];
        writes.push_back(write);
      }
      if (!writes.empty()) {
        Vk().vkUpdateDescriptorSets(mDevice, static_cast<std::uint32_t>(writes.size()), writes.data(), 0U, nullptr);
      }
      state.table = set;
      state.tableBindings = std::move(bindings);
      state.tableFrame = mFrameCount;
      state.textureVersion = parameters.TextureVersion();
      state.tableSurface = outputContext_.surface.get();
    }
    bound.textures = state.table;
    bound.sampled = state.tableBindings;
    if (mTracing) {
      Trace("BindPass %s technique %s pass %u valid %d", program.Name().c_str(),
            program.Description().techniques[technique].name.c_str(), pass, bound.valid ? 1 : 0);
    }
    mPass = std::move(bound);
  }

  void DeviceVulkan::UnbindPass() {}

  void DeviceVulkan::TransitionSampled(const std::vector<effects::TextureBinding>& bindings)
  {
    for (const effects::TextureBinding& binding : bindings) {
      if (binding.texture != nullptr) {
        Transition(static_cast<TextureVulkan*>(binding.texture.get())->Image(), VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
      } else if (binding.renderTarget != nullptr) {
        Transition(static_cast<RenderTargetVulkan*>(binding.renderTarget.get())->Current().image, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
      }
    }
  }

  const effects::SpirvInterface& DeviceVulkan::InterfaceOf(const effects::CompiledEntry& entry)
  {
    auto found = mInterfaces.find(entry.key);
    if (found == mInterfaces.end()) {
      found = mInterfaces.emplace(entry.key, effects::ReflectSpirvInterface(entry.code)).first;
    }
    return found->second;
  }

  VkShaderModule DeviceVulkan::ModuleFor(const effects::CompiledEntry& entry, const effects::CompiledEntry* const vertex)
  {
    const auto create = [&](const std::vector<std::uint8_t>& code) {
      const std::vector<std::uint8_t> stripped = effects::StripSpirvReflection(code);
      VkShaderModuleCreateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
      info.codeSize = stripped.size();
      info.pCode = reinterpret_cast<const std::uint32_t*>(stripped.data());
      VkShaderModule module = VK_NULL_HANDLE;
      CheckVk("DeviceVulkan.cpp", __LINE__, Vk().vkCreateShaderModule(mDevice, &info, nullptr, &module));
      return module;
    };
    if (vertex == nullptr) {
      auto found = mModules.find(entry.key);
      if (found == mModules.end()) {
        found = mModules.emplace(entry.key, create(entry.code)).first;
      }
      return found->second;
    }

    // A pixel shader: its inputs moved onto the vertex shader's output
    // locations, matched by semantic as Direct3D links stages.
    const std::pair<std::uint64_t, std::uint64_t> key{vertex->key, entry.key};
    auto found = mLinkedModules.find(key);
    if (found != mLinkedModules.end()) {
      return found->second;
    }
    const effects::SpirvInterface& vertexInterface = InterfaceOf(*vertex);
    const effects::SpirvInterface& pixelInterface = InterfaceOf(entry);
    std::map<std::uint32_t, std::uint32_t> locations;
    std::uint32_t spare = 31U;
    for (const effects::SpirvInterfaceVariable& input : pixelInterface.inputs) {
      if (input.builtIn) {
        continue;
      }
      std::uint32_t location = 0xFFFFFFFFU;
      for (const effects::SpirvInterfaceVariable& output : vertexInterface.outputs) {
        if (!output.builtIn && output.semantic == input.semantic && input.semanticIndex >= output.semanticIndex &&
            input.semanticIndex < output.semanticIndex + output.locations) {
          location = output.location + (input.semanticIndex - output.semanticIndex);
        }
      }
      if (location == 0xFFFFFFFFU) {
        location = spare--; // not written by the vertex shader: undefined, as on D3D
      }
      locations[input.id] = location;
    }
    const VkShaderModule module = create(effects::PatchSpirvInputLocations(entry.code, locations));
    mLinkedModules.emplace(key, module);
    return module;
  }

  VkPipeline DeviceVulkan::PipelineFor(const BoundPass& pass, const VkPrimitiveTopology topology)
  {
    VkFormat colorFormat = VK_FORMAT_UNDEFINED;
    vulkan::TrackedImage* colorImage = nullptr;
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    static_cast<void>(TargetView(colorFormat, colorImage, width, height));
    VkFormat depthFormat = VK_FORMAT_UNDEFINED;
    if (outputContext_.depthStencil != nullptr) {
      depthFormat = static_cast<DepthStencilTargetVulkan*>(outputContext_.depthStencil.get())->Image().format;
    }

    KeyWriter key;
    key.Add(pass.vertexShader->key);
    key.Add((pass.pixelShader != nullptr) ? pass.pixelShader->key : 0ULL);
    key.Add(mBoundFormat);
    for (std::uint32_t slot = 0U; slot < 16U; ++slot) {
      key.Add(mStreams[slot].stride);
    }
    const effects::BlendDesc& blend = pass.state.blend;
    const effects::DepthStencilDesc& depth = pass.state.depthStencil;
    const effects::RasterizerDesc& rasterizer = pass.state.rasterizer;
    key.Add(blend.alphaToCoverage);
    key.Add(blend.enable);
    key.Add(blend.srcBlend);
    key.Add(blend.destBlend);
    key.Add(blend.blendOp);
    key.Add(blend.srcBlendAlpha);
    key.Add(blend.destBlendAlpha);
    key.Add(blend.blendOpAlpha);
    key.Add(blend.writeMask);
    key.Add(pass.state.sampleMask);
    key.Add(depth.depthEnable);
    key.Add(depth.depthWrite);
    key.Add(depth.depthFunc);
    key.Add(depth.stencilEnable);
    key.Add(depth.stencilReadMask);
    key.Add(depth.stencilWriteMask);
    key.Add(depth.front);
    key.Add(depth.back);
    key.Add(rasterizer.fillMode);
    key.Add(rasterizer.cullMode);
    key.Add(rasterizer.frontCounterClockwise);
    key.Add(rasterizer.depthBias);
    key.Add(rasterizer.depthBiasClamp);
    key.Add(rasterizer.slopeScaledDepthBias);
    key.Add(colorFormat);
    key.Add(depthFormat);
    key.Add(topology);
    auto found = mPipelines.find(key.Key());
    if (found != mPipelines.end()) {
      return found->second;
    }

    // Vertex input: each shader input (by semantic) from the format's
    // element of that semantic, or from the zero buffer.
    const effects::SpirvInterface& vertexInterface = InterfaceOf(*pass.vertexShader);
    const std::span<const D3D11_INPUT_ELEMENT_DESC> elements =
      (mBoundFormat < d3d11::kVertexFormatCount) ? d3d11::VertexLayoutElements(mBoundFormat) : std::span<const D3D11_INPUT_ELEMENT_DESC>{};
    std::vector<VkVertexInputAttributeDescription> attributes;
    std::map<std::uint32_t, VkVertexInputBindingDescription> bindings;
    for (const effects::SpirvInterfaceVariable& input : vertexInterface.inputs) {
      if (input.builtIn) {
        continue;
      }
      for (std::uint32_t element = 0U; element < input.locations; ++element) {
        const std::uint32_t semanticIndex = input.semanticIndex + element;
        const D3D11_INPUT_ELEMENT_DESC* match = nullptr;
        for (const D3D11_INPUT_ELEMENT_DESC& candidate : elements) {
          if (candidate.SemanticIndex == semanticIndex && ::_stricmp(candidate.SemanticName, input.semantic.c_str()) == 0) {
            match = &candidate;
          }
        }
        VkVertexInputAttributeDescription attribute{};
        attribute.location = input.location + element;
        if (match != nullptr && vulkan::ToVulkanVertex(match->Format) != VK_FORMAT_UNDEFINED) {
          attribute.binding = match->InputSlot;
          attribute.format = vulkan::ToVulkanVertex(match->Format);
          attribute.offset = match->AlignedByteOffset;
          VkVertexInputBindingDescription& binding = bindings[match->InputSlot];
          binding.binding = match->InputSlot;
          binding.stride = mStreams[match->InputSlot].stride;
          binding.inputRate = (match->InputSlotClass == D3D11_INPUT_PER_INSTANCE_DATA) ? VK_VERTEX_INPUT_RATE_INSTANCE : VK_VERTEX_INPUT_RATE_VERTEX;
        } else {
          attribute.binding = kZeroBinding;
          attribute.format = (input.component == effects::SpirvInterfaceVariable::Component::Uint)   ? VK_FORMAT_R32G32B32A32_UINT
            : (input.component == effects::SpirvInterfaceVariable::Component::Sint)                    ? VK_FORMAT_R32G32B32A32_SINT
                                                                                                        : VK_FORMAT_R32G32B32A32_SFLOAT;
          attribute.offset = 0U;
          VkVertexInputBindingDescription& binding = bindings[kZeroBinding];
          binding.binding = kZeroBinding;
          binding.stride = 0U;
          binding.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;
        }
        attributes.push_back(attribute);
      }
    }
    std::vector<VkVertexInputBindingDescription> bindingList;
    for (const auto& [slot, binding] : bindings) {
      bindingList.push_back(binding);
    }

    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = ModuleFor(*pass.vertexShader, nullptr);
    stages[0].pName = pass.vertexShader->entryName.c_str(); // DXC keeps the HLSL entry name
    std::uint32_t stageCount = 1U;
    if (pass.pixelShader != nullptr) {
      stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
      stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
      stages[1].module = ModuleFor(*pass.pixelShader, pass.vertexShader);
      stages[1].pName = pass.pixelShader->entryName.c_str();
      stageCount = 2U;
    }

    VkPipelineVertexInputStateCreateInfo vertexInput{};
    vertexInput.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    vertexInput.vertexBindingDescriptionCount = static_cast<std::uint32_t>(bindingList.size());
    vertexInput.pVertexBindingDescriptions = bindingList.data();
    vertexInput.vertexAttributeDescriptionCount = static_cast<std::uint32_t>(attributes.size());
    vertexInput.pVertexAttributeDescriptions = attributes.data();
    VkPipelineInputAssemblyStateCreateInfo inputAssembly{};
    inputAssembly.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    inputAssembly.topology = topology;
    VkPipelineViewportStateCreateInfo viewport{};
    viewport.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    viewport.viewportCount = 1U;
    viewport.scissorCount = 1U;
    VkPipelineRasterizationStateCreateInfo raster{};
    raster.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    raster.depthClampEnable = VK_FALSE; // D3D9 clips to the near and far planes (see DeviceD3D12)
    raster.polygonMode = (rasterizer.fillMode == 2U && mWireframeSupported) ? VK_POLYGON_MODE_LINE : VK_POLYGON_MODE_FILL;
    raster.cullMode = (rasterizer.cullMode == 2U) ? VK_CULL_MODE_FRONT_BIT : (rasterizer.cullMode == 3U) ? VK_CULL_MODE_BACK_BIT
                                                                                                         : VK_CULL_MODE_NONE;
    // -fvk-invert-y keeps D3D's screen positions, so D3D's winding carries over.
    raster.frontFace = rasterizer.frontCounterClockwise ? VK_FRONT_FACE_COUNTER_CLOCKWISE : VK_FRONT_FACE_CLOCKWISE;
    raster.depthBiasEnable = (rasterizer.depthBias != 0 || rasterizer.slopeScaledDepthBias != 0.0f) ? VK_TRUE : VK_FALSE;
    raster.depthBiasConstantFactor = static_cast<float>(rasterizer.depthBias);
    raster.depthBiasClamp = rasterizer.depthBiasClamp;
    raster.depthBiasSlopeFactor = rasterizer.slopeScaledDepthBias;
    raster.lineWidth = 1.0f;
    VkPipelineMultisampleStateCreateInfo multisample{};
    multisample.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    multisample.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    const VkSampleMask sampleMask = pass.state.sampleMask;
    multisample.pSampleMask = &sampleMask;
    multisample.alphaToCoverageEnable = blend.alphaToCoverage ? VK_TRUE : VK_FALSE;
    VkPipelineDepthStencilStateCreateInfo depthStencil{};
    depthStencil.sType = VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
    if (depthFormat != VK_FORMAT_UNDEFINED) {
      depthStencil.depthTestEnable = depth.depthEnable ? VK_TRUE : VK_FALSE;
      depthStencil.depthWriteEnable = (depth.depthEnable && depth.depthWrite) ? VK_TRUE : VK_FALSE;
      depthStencil.depthCompareOp = CompareOp(depth.depthFunc);
      depthStencil.stencilTestEnable = (depth.stencilEnable && vulkan::HasStencil(depthFormat)) ? VK_TRUE : VK_FALSE;
      const auto face = [&](const effects::StencilFaceDesc& source) {
        VkStencilOpState state{};
        state.failOp = StencilOp(source.failOp);
        state.passOp = StencilOp(source.passOp);
        state.depthFailOp = StencilOp(source.depthFailOp);
        state.compareOp = CompareOp(source.func);
        state.compareMask = depth.stencilReadMask;
        state.writeMask = depth.stencilWriteMask;
        return state;
      };
      depthStencil.front = face(depth.front);
      depthStencil.back = face(depth.back);
    }
    VkPipelineColorBlendAttachmentState attachment{};
    attachment.blendEnable = blend.enable ? VK_TRUE : VK_FALSE;
    attachment.srcColorBlendFactor = BlendFactor(blend.srcBlend);
    attachment.dstColorBlendFactor = BlendFactor(blend.destBlend);
    attachment.colorBlendOp = BlendOp(blend.blendOp);
    attachment.srcAlphaBlendFactor = BlendFactor(blend.srcBlendAlpha);
    attachment.dstAlphaBlendFactor = BlendFactor(blend.destBlendAlpha);
    attachment.alphaBlendOp = BlendOp(blend.blendOpAlpha);
    attachment.colorWriteMask = blend.writeMask;
    VkPipelineColorBlendStateCreateInfo colorBlend{};
    colorBlend.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    colorBlend.attachmentCount = (colorFormat != VK_FORMAT_UNDEFINED) ? 1U : 0U;
    colorBlend.pAttachments = &attachment;
    const VkDynamicState dynamicStates[4] = {
      VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR, VK_DYNAMIC_STATE_BLEND_CONSTANTS, VK_DYNAMIC_STATE_STENCIL_REFERENCE,
    };
    VkPipelineDynamicStateCreateInfo dynamic{};
    dynamic.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dynamic.dynamicStateCount = 4U;
    dynamic.pDynamicStates = dynamicStates;
    VkPipelineRenderingCreateInfo rendering{};
    rendering.sType = VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO;
    rendering.colorAttachmentCount = (colorFormat != VK_FORMAT_UNDEFINED) ? 1U : 0U;
    rendering.pColorAttachmentFormats = &colorFormat;
    rendering.depthAttachmentFormat = depthFormat;
    rendering.stencilAttachmentFormat = vulkan::HasStencil(depthFormat) ? depthFormat : VK_FORMAT_UNDEFINED;

    VkGraphicsPipelineCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    info.pNext = &rendering;
    info.stageCount = stageCount;
    info.pStages = stages;
    info.pVertexInputState = &vertexInput;
    info.pInputAssemblyState = &inputAssembly;
    info.pViewportState = &viewport;
    info.pRasterizationState = &raster;
    info.pMultisampleState = &multisample;
    info.pDepthStencilState = &depthStencil;
    info.pColorBlendState = &colorBlend;
    info.pDynamicState = &dynamic;
    info.layout = mPipelineLayout;
    VkPipeline pipeline = VK_NULL_HANDLE;
    const VkResult result = Vk().vkCreateGraphicsPipelines(mDevice, mPipelineCache, 1U, &info, nullptr, &pipeline);
    if (result != VK_SUCCESS) {
      static int logged = 0;
      if (logged++ < 16) {
        gpg::Warnf("Vulkan: pipeline for %s (vertex format %u) failed: %s", pass.program->Name().c_str(), mBoundFormat,
                   vulkan::ResultName(result));
      }
      pipeline = VK_NULL_HANDLE;
    }
    mPipelines.emplace(std::move(key.Key()), pipeline);
    return pipeline;
  }

  bool DeviceVulkan::PrepareDraw(const std::uint32_t topologyToken, const bool indexed)
  {
    if (topologyToken == 0U || topologyToken >= std::size(kTopologyByToken)) {
      ThrowError("DeviceVulkan.cpp", __LINE__, "invalid topology specified");
    }
    if (!mPass.valid) {
      ++mSkippedDraws;
      return false;
    }
    const VkPrimitiveTopology topology = kTopologyByToken[topologyToken];

    // Buffers first (uploads), then image layouts, then the rendering scope.
    VkBuffer vertexBuffers[16]{};
    VkDeviceSize vertexOffsets[16]{};
    std::uint32_t slotCount = 0U;
    const std::span<const D3D11_INPUT_ELEMENT_DESC> elements =
      (mBoundFormat < d3d11::kVertexFormatCount) ? d3d11::VertexLayoutElements(mBoundFormat) : std::span<const D3D11_INPUT_ELEMENT_DESC>{};
    std::uint32_t instanceSlots = 0U;
    for (const D3D11_INPUT_ELEMENT_DESC& element : elements) {
      slotCount = std::max<std::uint32_t>(slotCount, element.InputSlot + 1U);
      if (element.InputSlotClass == D3D11_INPUT_PER_INSTANCE_DATA) {
        instanceSlots |= 1U << element.InputSlot;
      }
    }
    // The instances the per-instance streams hold from their bound offset.
    // Direct3D 12 binds each stream with its exact size and reads zeros past
    // it; here a stream runs on to the end of its buffer (an upload page for a
    // dynamic one), so an instance count larger than the data - the vision
    // pass replays the total circle count for every ring batch - would read
    // whatever follows and draw it. Those instances are not drawn instead.
    mDrawInstanceLimit = ~0U;
    for (std::uint32_t slot = 0U; slot < slotCount; ++slot) {
      const StreamBinding& stream = mStreams[slot];
      if ((instanceSlots & (1U << slot)) == 0U || stream.buffer == nullptr || stream.stride == 0U) {
        continue;
      }
      const std::uint32_t width = static_cast<VertexBufferVulkan*>(stream.buffer.get())->Storage().ByteWidth();
      mDrawInstanceLimit = std::min(mDrawInstanceLimit, (width > stream.offset) ? (width - stream.offset) / stream.stride : 0U);
    }
    for (std::uint32_t slot = 0U; slot < 16U; ++slot) {
      vertexBuffers[slot] = mZeroBuffer.buffer;
    }
    for (std::uint32_t slot = 0U; slot < slotCount; ++slot) {
      StreamBinding& stream = mStreams[slot];
      if (stream.buffer == nullptr) {
        continue;
      }
      VkBuffer buffer = VK_NULL_HANDLE;
      VkDeviceSize offset = 0U;
      static_cast<VertexBufferVulkan*>(stream.buffer.get())->Storage().PrepareForDraw(*this, buffer, offset);
      vertexBuffers[slot] = buffer;
      vertexOffsets[slot] = offset + stream.offset;
    }
    VkBuffer indexBuffer = VK_NULL_HANDLE;
    VkDeviceSize indexOffset = 0U;
    if (indexed) {
      static_cast<IndexBufferVulkan*>(mIndexBuffer.get())->Storage().PrepareForDraw(*this, indexBuffer, indexOffset);
    }
    if (mPass.sampled != nullptr) {
      TransitionSampled(*mPass.sampled);
    }
    const VkPipeline pipeline = PipelineFor(mPass, topology);
    if (pipeline == VK_NULL_HANDLE) {
      ++mSkippedDraws;
      return false;
    }
    BeginRendering();

    Vk().vkCmdBindPipeline(mCommands, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
    Vk().vkCmdBindDescriptorSets(mCommands, VK_PIPELINE_BIND_POINT_GRAPHICS, mPipelineLayout, 0U, 1U, &mPass.textures, 0U, nullptr);
    if (mPass.constants != VK_NULL_HANDLE) {
      Vk().vkCmdBindDescriptorSets(mCommands, VK_PIPELINE_BIND_POINT_GRAPHICS, mPipelineLayout, 1U, 1U, &mPass.constants, 0U, nullptr);
    }
    Vk().vkCmdBindVertexBuffers(mCommands, 0U, 16U, vertexBuffers, vertexOffsets);
    if (indexed) {
      Vk().vkCmdBindIndexBuffer(mCommands, indexBuffer, indexOffset, static_cast<IndexBufferVulkan*>(mIndexBuffer.get())->IndexType());
    }
    VkViewport viewport{
      static_cast<float>(mViewport.X), static_cast<float>(mViewport.Y), static_cast<float>(mViewport.Width),
      static_cast<float>(mViewport.Height), mViewport.MinZ, mViewport.MaxZ,
    };
    if (viewport.width <= 0.0f || viewport.height <= 0.0f) {
      viewport.width = static_cast<float>(mRenderingWidth);
      viewport.height = static_cast<float>(mRenderingHeight);
    }
    // Shifted by half a pixel: Direct3D 9's pixel centres (Direct3D9PixelCentreShift).
    viewport.x += backend::Direct3D9PixelCentreShift();
    viewport.y += backend::Direct3D9PixelCentreShift();
    Vk().vkCmdSetViewport(mCommands, 0U, 1U, &viewport);
    const std::int32_t right = std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.X + mViewport.Width), static_cast<std::int32_t>(mRenderingWidth));
    const std::int32_t bottom =
      std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.Y + mViewport.Height), static_cast<std::int32_t>(mRenderingHeight));
    VkRect2D scissor{};
    scissor.offset = {static_cast<std::int32_t>(mViewport.X), static_cast<std::int32_t>(mViewport.Y)};
    scissor.extent = {
      static_cast<std::uint32_t>(std::max(right - scissor.offset.x, 0)), static_cast<std::uint32_t>(std::max(bottom - scissor.offset.y, 0)),
    };
    Vk().vkCmdSetScissor(mCommands, 0U, 1U, &scissor);
    Vk().vkCmdSetBlendConstants(mCommands, mPass.state.blendFactor);
    Vk().vkCmdSetStencilReference(mCommands, VK_STENCIL_FACE_FRONT_AND_BACK, mPass.state.stencilRef);
    return true;
  }

  void DeviceVulkan::DrawIndexedPrimitive(const DrawIndexedContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    if (mIndexBuffer == nullptr) {
      return;
    }
    mPreparingDraw = true;
    const bool ready = PrepareDraw(static_cast<std::uint32_t>(context->topology_), true);
    mPreparingDraw = false;
    const std::uint32_t instances = std::min(InstanceCount(mStreamFrequencies[0]), mDrawInstanceLimit);
    if (!ready || instances == 0U) {
      return;
    }
    Vk().vkCmdDrawIndexed(mCommands, context->indexCount_, instances, context->startIndex_, context->baseVertexIndex_, 0U);
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  void DeviceVulkan::DrawPrimitive(const DrawContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    mPreparingDraw = true;
    const bool ready = PrepareDraw(static_cast<std::uint32_t>(context->topology_), false);
    mPreparingDraw = false;
    const std::uint32_t instances = std::min(InstanceCount(mStreamFrequencies[0]), mDrawInstanceLimit);
    if (!ready || instances == 0U) {
      return;
    }
    Vk().vkCmdDraw(mCommands, context->vertexCount_, instances, context->startVertex_, 0U);
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  bool DeviceVulkan::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
  {
    const vulkan::TextureFormat format = vulkan::ToVulkanTexture(dxgi::TextureFormatToDxgi(textureFormat));
    if (mPhysical == VK_NULL_HANDLE || format.format == VK_FORMAT_UNDEFINED) {
      return false;
    }
    VkFormatProperties properties{};
    Vk().vkGetPhysicalDeviceFormatProperties(mPhysical, format.format, &properties);
    return (properties.optimalTilingFeatures & VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT) != 0U;
  }
} // namespace gpg::gal
