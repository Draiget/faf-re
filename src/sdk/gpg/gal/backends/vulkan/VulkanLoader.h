#pragma once

// FAF addition, not in the shipped binary.
//
// The Vulkan entry points the Vulkan gal backend uses, loaded at run time
// from vulkan-1.dll (installed with the GPU driver), so the executable links
// no Vulkan import library and starts where there is none.

#ifndef VK_NO_PROTOTYPES
#define VK_NO_PROTOTYPES
#endif
#include <vulkan/vulkan.h>

#include <windows.h>

// Exported by the loader; resolved first.
#define FAF_VK_GLOBAL_FUNCTIONS(X) \
  X(vkCreateInstance)              \
  X(vkEnumerateInstanceExtensionProperties) \
  X(vkEnumerateInstanceLayerProperties) \
  X(vkEnumerateInstanceVersion)

#define FAF_VK_INSTANCE_FUNCTIONS(X)              \
  X(vkDestroyInstance)                            \
  X(vkEnumeratePhysicalDevices)                   \
  X(vkGetPhysicalDeviceProperties)                \
  X(vkGetPhysicalDeviceProperties2)               \
  X(vkGetPhysicalDeviceFeatures2)                 \
  X(vkGetPhysicalDeviceQueueFamilyProperties)     \
  X(vkGetPhysicalDeviceMemoryProperties)          \
  X(vkGetPhysicalDeviceMemoryProperties2)         \
  X(vkGetPhysicalDeviceFormatProperties)          \
  X(vkEnumerateDeviceExtensionProperties)         \
  X(vkCreateDevice)                               \
  X(vkGetDeviceProcAddr)                          \
  X(vkDestroySurfaceKHR)                          \
  X(vkGetPhysicalDeviceSurfaceSupportKHR)         \
  X(vkGetPhysicalDeviceSurfaceCapabilitiesKHR)    \
  X(vkGetPhysicalDeviceSurfaceFormatsKHR)         \
  X(vkGetPhysicalDeviceSurfacePresentModesKHR)

// The debug-utils messenger is optional (only with /vulkandebug).
#define FAF_VK_DEBUG_FUNCTIONS(X)    \
  X(vkCreateDebugUtilsMessengerEXT)  \
  X(vkDestroyDebugUtilsMessengerEXT)

#define FAF_VK_DEVICE_FUNCTIONS(X)    \
  X(vkDestroyDevice)                  \
  X(vkGetDeviceQueue)                 \
  X(vkDeviceWaitIdle)                 \
  X(vkQueueSubmit2)                   \
  X(vkQueueWaitIdle)                  \
  X(vkCreateSwapchainKHR)             \
  X(vkDestroySwapchainKHR)            \
  X(vkGetSwapchainImagesKHR)          \
  X(vkAcquireNextImageKHR)            \
  X(vkQueuePresentKHR)                \
  X(vkCreateCommandPool)              \
  X(vkDestroyCommandPool)             \
  X(vkResetCommandPool)               \
  X(vkAllocateCommandBuffers)         \
  X(vkBeginCommandBuffer)             \
  X(vkEndCommandBuffer)               \
  X(vkCreateFence)                    \
  X(vkDestroyFence)                   \
  X(vkWaitForFences)                  \
  X(vkResetFences)                    \
  X(vkGetFenceStatus)                 \
  X(vkCreateSemaphore)                \
  X(vkWaitSemaphores)                 \
  X(vkGetSemaphoreCounterValue)       \
  X(vkDestroySemaphore)               \
  X(vkAllocateMemory)                 \
  X(vkFreeMemory)                     \
  X(vkMapMemory)                      \
  X(vkUnmapMemory)                    \
  X(vkCreateBuffer)                   \
  X(vkDestroyBuffer)                  \
  X(vkGetBufferMemoryRequirements)    \
  X(vkBindBufferMemory)               \
  X(vkCreateImage)                    \
  X(vkDestroyImage)                   \
  X(vkGetImageMemoryRequirements)     \
  X(vkBindImageMemory)                \
  X(vkCreateImageView)                \
  X(vkDestroyImageView)               \
  X(vkCreateSampler)                  \
  X(vkDestroySampler)                 \
  X(vkCreateShaderModule)             \
  X(vkDestroyShaderModule)            \
  X(vkCreateDescriptorSetLayout)      \
  X(vkDestroyDescriptorSetLayout)     \
  X(vkCreatePipelineLayout)           \
  X(vkDestroyPipelineLayout)          \
  X(vkCreateGraphicsPipelines)        \
  X(vkDestroyPipeline)                \
  X(vkCreatePipelineCache)            \
  X(vkDestroyPipelineCache)           \
  X(vkCreateDescriptorPool)           \
  X(vkDestroyDescriptorPool)          \
  X(vkResetDescriptorPool)            \
  X(vkAllocateDescriptorSets)         \
  X(vkUpdateDescriptorSets)           \
  X(vkCmdPipelineBarrier2)            \
  X(vkCmdBeginRendering)              \
  X(vkCmdEndRendering)                \
  X(vkCmdBindPipeline)                \
  X(vkCmdBindDescriptorSets)          \
  X(vkCmdBindVertexBuffers)           \
  X(vkCmdBindIndexBuffer)             \
  X(vkCmdSetViewport)                 \
  X(vkCmdSetScissor)                  \
  X(vkCmdSetBlendConstants)           \
  X(vkCmdSetStencilReference)         \
  X(vkCmdDraw)                        \
  X(vkCmdDrawIndexed)                 \
  X(vkCmdClearAttachments)            \
  X(vkCmdCopyBuffer)                  \
  X(vkCmdCopyBufferToImage)           \
  X(vkCmdCopyImageToBuffer)           \
  X(vkCmdCopyImage)                   \
  X(vkCmdBlitImage)                   \
  X(vkCreateComputePipelines)         \
  X(vkCmdDispatch)                    \
  X(vkCmdDrawIndirect)                \
  X(vkCreateQueryPool)                \
  X(vkDestroyQueryPool)               \
  X(vkCmdResetQueryPool)              \
  X(vkCmdWriteTimestamp2)             \
  X(vkGetQueryPoolResults)

namespace gpg::gal::vulkan
{
  /** The loaded entry points. One instance per process (the backend is a singleton). */
  struct Functions
  {
    HMODULE module = nullptr;
    PFN_vkGetInstanceProcAddr vkGetInstanceProcAddr = nullptr;
#define FAF_VK_DECLARE(name) PFN_##name name = nullptr;
    FAF_VK_GLOBAL_FUNCTIONS(FAF_VK_DECLARE)
    FAF_VK_INSTANCE_FUNCTIONS(FAF_VK_DECLARE)
    FAF_VK_DEBUG_FUNCTIONS(FAF_VK_DECLARE)
    FAF_VK_DEVICE_FUNCTIONS(FAF_VK_DECLARE)
#undef FAF_VK_DECLARE

    /** Loads vulkan-1.dll and the global functions; false when there is no Vulkan. */
    [[nodiscard]] bool LoadGlobal();
    /** False when a required instance function is missing. */
    [[nodiscard]] bool LoadInstance(VkInstance instance);
    /** False when a required device function is missing (Vulkan 1.3 core). */
    [[nodiscard]] bool LoadDevice(VkDevice device);
    void Unload() noexcept;
  };

  /** The process's Vulkan functions. */
  [[nodiscard]] Functions& Vk();
} // namespace gpg::gal::vulkan
