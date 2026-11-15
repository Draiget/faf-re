// FAF addition: what DeviceVulkan::CheckFrame makes of the result of a call a frame stands on (getting, beginning,
// ending, submitting or waiting for a command buffer, and an acquire or a present that answers
// VK_ERROR_DEVICE_LOST), apart from the call that ends the program, so that tests/vulkan/FrameFailureTests.cpp
// checks it without a device.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include <vulkan/vulkan_core.h>

namespace gpg::gal::vulkan
{
  /** What becomes of the result of a call a frame stands on. */
  enum class FrameFailure : std::uint8_t
  {
    None,  // it succeeded
    Throw, // during Setup: the error reaches Device::Create, which falls back to Direct3D 9
    End,   // after Setup: the program ends with the cause
  };

  /**
   * After Setup a failure ends the program, as Direct3D 12 does on a removal (DeviceD3D12::CheckDeviceHresult): a
   * thrown error would reach CD3DDevice::Paint, which goes on with the next frame as after a lost Direct3D 9
   * device, which a reset brings back. A VkDevice comes back from none, and the next frame would record into a
   * command buffer in no state to take commands. During Setup it throws, as CheckVk does.
   */
  inline FrameFailure JudgeFrameResult(
    const VkResult result,
    const bool setUp
  ) noexcept
  {
    if (result >= VK_SUCCESS) {
      return FrameFailure::None;
    }
    return setUp ? FrameFailure::End : FrameFailure::Throw;
  }

  /** What the program ends with: the cause (`resultName`, VulkanCore.h's ResultName), the call and its line. */
  inline std::string FrameEndMessage(
    const VkResult result,
    const char* const resultName,
    const char* const during,
    const int line
  )
  {
    char message[256]{};
    if (result == VK_ERROR_DEVICE_LOST) {
      std::snprintf(
        message,
        sizeof(message),
        "The Vulkan device was lost while %s (DeviceVulkan.cpp(%d)). The graphics driver reset the GPU, so the "
        "game cannot continue.",
        during,
        line
      );
    } else {
      std::snprintf(
        message,
        sizeof(message),
        "Vulkan: %s (%d) while %s (DeviceVulkan.cpp(%d)), so the game cannot continue.",
        resultName,
        static_cast<int>(result),
        during,
        line
      );
    }
    return message;
  }
} // namespace gpg::gal::vulkan
