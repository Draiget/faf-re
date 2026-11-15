// FAF addition: what DeviceVulkan::CreateSwapChain makes a swap chain with (VulkanSwapChain.h), on a desktop
// surface and on surfaces as Android's are.
#include "gpg/gal/backends/vulkan/VulkanSwapChain.h"

#include <vector>

#include <gtest/gtest.h>

namespace
{
  using namespace gpg::gal::vulkan;

  constexpr VkColorSpaceKHR kSrgb = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

  VkSurfaceCapabilitiesKHR Capabilities(
    const VkImageUsageFlags usage,
    const VkCompositeAlphaFlagsKHR alpha,
    const VkSurfaceTransformFlagsKHR transforms,
    const VkSurfaceTransformFlagBitsKHR current
  )
  {
    VkSurfaceCapabilitiesKHR capabilities{};
    capabilities.supportedUsageFlags = usage;
    capabilities.supportedCompositeAlpha = alpha;
    capabilities.supportedTransforms = transforms;
    capabilities.currentTransform = current;
    return capabilities;
  }

  constexpr VkImageUsageFlags kAllCopies =
    VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;

  /** A surface whose current transform is `current` (the identity allowed too), of `currentExtent`. */
  VkSurfaceCapabilitiesKHR Sized(
    const VkSurfaceTransformFlagBitsKHR current,
    const VkExtent2D currentExtent
  )
  {
    VkSurfaceCapabilitiesKHR capabilities =
      Capabilities(kAllCopies, 1U, VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR | current, current);
    capabilities.currentExtent = currentExtent;
    capabilities.minImageExtent = {1U, 1U};
    capabilities.maxImageExtent = {4096U, 4096U};
    return capabilities;
  }
} // namespace

TEST(
  VulkanSwapChain,
  SurfaceFormatIsBgraWhereTheSurfaceHasIt
)
{
  const std::vector<VkSurfaceFormatKHR> desktop = {
    {VK_FORMAT_R8G8B8A8_UNORM, kSrgb}, {VK_FORMAT_B8G8R8A8_SRGB, kSrgb}, {VK_FORMAT_B8G8R8A8_UNORM, kSrgb}
  };
  EXPECT_EQ(ChooseSurfaceFormat(desktop, true).format, VK_FORMAT_B8G8R8A8_UNORM);
  EXPECT_EQ(ChooseSurfaceFormat(desktop, true).colorSpace, kSrgb);
  EXPECT_EQ(ChooseSurfaceFormat({}, true).format, VK_FORMAT_B8G8R8A8_UNORM) << "a surface that lists no format";
}

TEST(
  VulkanSwapChain,
  SurfaceFormatIsRgbaWhereTheSurfaceHasNoBgra
)
{
  // Android's window surfaces.
  const std::vector<VkSurfaceFormatKHR> android = {
    {VK_FORMAT_R8G8B8A8_UNORM, kSrgb}, {VK_FORMAT_R8G8B8A8_SRGB, kSrgb}, {VK_FORMAT_R5G6B5_UNORM_PACK16, kSrgb}
  };
  EXPECT_EQ(ChooseSurfaceFormat(android, true).format, VK_FORMAT_R8G8B8A8_UNORM);
  // Only sRGB's nonlinear colour space; neither format at all is no format.
  const std::vector<VkSurfaceFormatKHR> linearBgra = {
    {VK_FORMAT_B8G8R8A8_UNORM, VK_COLOR_SPACE_EXTENDED_SRGB_LINEAR_EXT}, {VK_FORMAT_R8G8B8A8_UNORM, kSrgb}
  };
  EXPECT_EQ(ChooseSurfaceFormat(linearBgra, true).format, VK_FORMAT_R8G8B8A8_UNORM);
  EXPECT_EQ(ChooseSurfaceFormat({{VK_FORMAT_R5G6B5_UNORM_PACK16, kSrgb}}, true).format, VK_FORMAT_UNDEFINED);
}

TEST(
  VulkanSwapChain,
  SurfaceFormatWithoutBgraIsRgbaOrNone
)
{
  // FAF_GAL_NO_BGRA on a desktop surface that has both takes Android's route.
  const std::vector<VkSurfaceFormatKHR> desktop = {
    {VK_FORMAT_B8G8R8A8_UNORM, kSrgb}, {VK_FORMAT_R8G8B8A8_UNORM, kSrgb}
  };
  EXPECT_EQ(ChooseSurfaceFormat(desktop, false).format, VK_FORMAT_R8G8B8A8_UNORM);
  // A surface with B8G8R8A8 alone has none left that will do, nor has one that lists no format.
  EXPECT_EQ(ChooseSurfaceFormat({{VK_FORMAT_B8G8R8A8_UNORM, kSrgb}}, false).format, VK_FORMAT_UNDEFINED);
  EXPECT_EQ(ChooseSurfaceFormat({}, false).format, VK_FORMAT_UNDEFINED);
}

TEST(
  VulkanSwapChain,
  UsageTheSurfaceLacksIsNamed
)
{
  const VkSurfaceTransformFlagBitsKHR identity = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
  EXPECT_EQ(kSwapChainUsage, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | kAllCopies);
  // Desktop and Android surfaces support all of it, and more.
  EXPECT_EQ(
    MissingSwapChainUsage(Capabilities(
      kAllCopies | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_STORAGE_BIT, 1U, identity, identity
    )),
    0U
  );
  EXPECT_EQ(
    MissingSwapChainUsage(
      Capabilities(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT, 1U, identity, identity)
    ),
    static_cast<VkImageUsageFlags>(VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT)
  );
}

TEST(
  VulkanSwapChain,
  CompositeAlphaIsOpaqueElseOneTheSurfaceHas
)
{
  const VkSurfaceTransformFlagBitsKHR identity = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
  EXPECT_EQ(
    SwapChainCompositeAlpha(Capabilities(
      kAllCopies, VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR | VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR, identity, identity
    )),
    VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR
  );
  // Android's surfaces have only INHERIT.
  EXPECT_EQ(
    SwapChainCompositeAlpha(Capabilities(kAllCopies, VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR, identity, identity)),
    VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR
  );
  EXPECT_EQ(
    SwapChainCompositeAlpha(Capabilities(
      kAllCopies, VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR | VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR, identity, identity
    )),
    VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR
  );
}

TEST(
  VulkanSwapChain,
  PreTransformIsTheIdentityWhereTheSurfaceAllowsIt
)
{
  // A phone held in landscape: its portrait panel's surface says the display is turned.
  const VkSurfaceTransformFlagsKHR phone = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR |
    VK_SURFACE_TRANSFORM_ROTATE_90_BIT_KHR | VK_SURFACE_TRANSFORM_ROTATE_180_BIT_KHR |
    VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR;
  EXPECT_EQ(
    SwapChainPreTransform(Capabilities(kAllCopies, 1U, phone, VK_SURFACE_TRANSFORM_ROTATE_90_BIT_KHR)),
    VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR
  );
  EXPECT_EQ(
    SwapChainPreTransform(
      Capabilities(kAllCopies, 1U, VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR, VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR)
    ),
    VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR
  ) << "a surface without the identity keeps its own";
}

TEST(
  VulkanSwapChain,
  ExtentIsTheSurfacesWithinItsBounds
)
{
  constexpr VkSurfaceTransformFlagBitsKHR identity = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
  VkExtent2D extent = SwapChainExtent(Sized(identity, {1280U, 720U}), 800U, 600U);
  EXPECT_EQ(extent.width, 1280U) << "the window's size, not the one asked for";
  EXPECT_EQ(extent.height, 720U);
  extent = SwapChainExtent(Sized(identity, {0xFFFFFFFFU, 0xFFFFFFFFU}), 800U, 600U);
  EXPECT_EQ(extent.width, 800U) << "a surface that leaves the size to the swap chain";
  EXPECT_EQ(extent.height, 600U);
  extent = SwapChainExtent(Sized(identity, {0xFFFFFFFFU, 0xFFFFFFFFU}), 8000U, 0U);
  EXPECT_EQ(extent.width, 4096U);
  EXPECT_EQ(extent.height, 1U);
  // A minimised Windows window: no area, and no extent allowed but none.
  VkSurfaceCapabilitiesKHR minimised = Sized(identity, {0U, 0U});
  minimised.minImageExtent = {0U, 0U};
  minimised.maxImageExtent = {0U, 0U};
  extent = SwapChainExtent(minimised, 1280U, 720U);
  EXPECT_EQ(extent.width, 0U);
  EXPECT_EQ(extent.height, 0U);
}

TEST(
  VulkanSwapChain,
  SuboptimalSwapChainIsMadeAgainWhereANewOneDiffers
)
{
  constexpr VkSurfaceTransformFlagBitsKHR identity = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
  constexpr VkSurfaceTransformFlagBitsKHR turned = VK_SURFACE_TRANSFORM_ROTATE_90_BIT_KHR;
  constexpr VkExtent2D size{2400U, 1080U};
  // A desktop surface answers suboptimal when the window's size changed: made again, as before.
  EXPECT_TRUE(RemakeSuboptimalSwapChain(Sized(identity, size), identity, size));
  EXPECT_TRUE(RemakeSuboptimalSwapChain(Sized(identity, {1280U, 720U}), identity, size));
  // A turned phone panel, whose surface answers it to every present of the upright swap chain: kept, unless the
  // window has a new size.
  EXPECT_FALSE(RemakeSuboptimalSwapChain(Sized(turned, size), identity, size));
  EXPECT_TRUE(RemakeSuboptimalSwapChain(Sized(turned, {1080U, 2400U}), identity, size));
  EXPECT_FALSE(RemakeSuboptimalSwapChain(Sized(VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR, size), identity, size))
    << "turned the other way: the compositor turns it";
  EXPECT_FALSE(RemakeSuboptimalSwapChain(Sized(turned, {0xFFFFFFFFU, 0xFFFFFFFFU}), identity, size))
    << "a surface that leaves the size to the swap chain";
  // On a surface without the identity the swap chain takes the current transform: made again, as before, and also
  // at the same size once that transform turned, as a new one takes the new transform.
  VkSurfaceCapabilitiesKHR ownTransform = Sized(turned, size);
  ownTransform.supportedTransforms = turned | VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR;
  EXPECT_TRUE(RemakeSuboptimalSwapChain(ownTransform, turned, size));
  ownTransform.currentTransform = VK_SURFACE_TRANSFORM_ROTATE_270_BIT_KHR;
  EXPECT_TRUE(RemakeSuboptimalSwapChain(ownTransform, turned, size)) << "turned since the swap chain was made";
}

TEST(
  VulkanSwapChain,
  RgbaAndBgraAreTheOtherChannelOrder
)
{
  EXPECT_TRUE(OtherChannelOrder(VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_B8G8R8A8_UNORM));
  EXPECT_TRUE(OtherChannelOrder(VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM));
  EXPECT_TRUE(OtherChannelOrder(VK_FORMAT_R8G8B8A8_SRGB, VK_FORMAT_B8G8R8A8_SRGB));
  EXPECT_FALSE(OtherChannelOrder(VK_FORMAT_R8G8B8A8_SRGB, VK_FORMAT_B8G8R8A8_UNORM)) << "a blit would convert sRGB";
  EXPECT_FALSE(OtherChannelOrder(VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_B8G8R8A8_UNORM));
  EXPECT_FALSE(OtherChannelOrder(VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_R8G8B8A8_SRGB));
  EXPECT_FALSE(OtherChannelOrder(VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_BC3_UNORM_BLOCK));
  EXPECT_FALSE(OtherChannelOrder(VK_FORMAT_R16G16B16A16_SFLOAT, VK_FORMAT_B8G8R8A8_UNORM));
}
