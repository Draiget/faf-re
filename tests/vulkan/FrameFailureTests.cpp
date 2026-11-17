// FAF addition: what DeviceVulkan::CheckFrame makes of a failed call a frame stands on
// (src/gpg/gal/backends/vulkan/VulkanFrameFailure.h): during Setup an error the engine falls back from, after it the
// end of the program with the cause.
#include "gpg/gal/backends/vulkan/VulkanFrameFailure.h"

#include <string>

#include <gtest/gtest.h>

namespace
{
  using gpg::gal::vulkan::FrameEndMessage;
  using gpg::gal::vulkan::FrameFailure;
  using gpg::gal::vulkan::JudgeFrameResult;
} // namespace

TEST(
  VulkanFrameFailure,
  SuccessAndItsStatusCodesAreNoFailure
)
{
  for (const bool setUp : {false, true}) {
    EXPECT_EQ(JudgeFrameResult(VK_SUCCESS, setUp), FrameFailure::None);
    EXPECT_EQ(JudgeFrameResult(VK_TIMEOUT, setUp), FrameFailure::None);
    EXPECT_EQ(JudgeFrameResult(VK_SUBOPTIMAL_KHR, setUp), FrameFailure::None);
  }
}

TEST(
  VulkanFrameFailure,
  AnErrorThrowsDuringSetupAndEndsTheProgramAfter
)
{
  for (const VkResult error :
       {VK_ERROR_DEVICE_LOST, VK_ERROR_OUT_OF_DEVICE_MEMORY, VK_ERROR_OUT_OF_HOST_MEMORY, VK_ERROR_UNKNOWN}) {
    EXPECT_EQ(JudgeFrameResult(error, false), FrameFailure::Throw) << error << ": Direct3D 9 takes over";
    EXPECT_EQ(JudgeFrameResult(error, true), FrameFailure::End) << error;
  }
}

TEST(
  VulkanFrameFailure,
  TheMessageNamesTheCauseTheCallAndItsLine
)
{
  EXPECT_EQ(
    FrameEndMessage(VK_ERROR_DEVICE_LOST, "VK_ERROR_DEVICE_LOST", "submitting", 1621),
    "The Vulkan device was lost while submitting (DeviceVulkan.cpp(1621)). The graphics driver reset the GPU, so "
    "the game cannot continue."
  );
  EXPECT_EQ(
    FrameEndMessage(VK_ERROR_OUT_OF_DEVICE_MEMORY, "VK_ERROR_OUT_OF_DEVICE_MEMORY", "beginning a command buffer", 1569),
    "Vulkan: VK_ERROR_OUT_OF_DEVICE_MEMORY (-2) while beginning a command buffer (DeviceVulkan.cpp(1569)), so the "
    "game cannot continue."
  );
}
