// FAF addition: when DeviceVulkan::TestCooperativeLevel lets go of a head's window surface and takes the next, and
// what it answers (src/gpg/gal/backends/vulkan/VulkanSurfaceLifecycle.h): the routes an Android activity's surface
// takes, played without a device or a window.
#include "gpg/gal/backends/vulkan/VulkanSurfaceLifecycle.h"

#include <cstdint>

#include <gtest/gtest.h>

namespace
{
  using gpg::gal::vulkan::SurfaceLifecycle;
  using Attach = SurfaceLifecycle::Attach;
  using Verdict = SurfaceLifecycle::Verdict;
} // namespace

TEST(
  VulkanSurfaceLifecycle,
  AHeadLetsGoOfASurfaceThatWentOrIsNoLongerTheWindows
)
{
  EXPECT_FALSE(SurfaceLifecycle::Releases(false, true)) << "a desktop window's surface stays";
  EXPECT_TRUE(SurfaceLifecycle::Releases(true, true)) << "an acquire or a present answered that it went";
  EXPECT_TRUE(SurfaceLifecycle::Releases(false, false)) << "the activity went to the back, or turned";
}

TEST(
  VulkanSurfaceLifecycle,
  OnlyAHeadThatDrawsIntoTheSwapChainTakesANewSize
)
{
  EXPECT_FALSE(SurfaceLifecycle::NewSize(false, 2400U, 1080U, 2400U, 1080U));
  EXPECT_TRUE(SurfaceLifecycle::NewSize(false, 2400U, 1080U, 1080U, 2400U));
  EXPECT_TRUE(SurfaceLifecycle::NewSize(false, 2400U, 1080U, 2400U, 1000U));
  EXPECT_FALSE(SurfaceLifecycle::NewSize(true, 2400U, 1080U, 1080U, 2400U)) << "a scaled head keeps its own image";
}

TEST(
  VulkanSurfaceLifecycle,
  TheAnswerIsTwoUntilEveryHeadHasASurface
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(1U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::NoSurface, false, 0U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Answer(false), 2);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Attached, false, 16U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Answer(true), 0) << "back at the same size: nothing to lay out anew";
}

TEST(
  VulkanSurfaceLifecycle,
  ANewSizeIsAnsweredOnceWithOne
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(1U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Attached, true, 0U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Answer(true), 1);
  EXPECT_EQ(lifecycle.Answer(true), 0);
}

TEST(
  VulkanSurfaceLifecycle,
  ANewSizeWaitsWhileAnotherHeadHasNoSurface
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(2U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Attached, true, 0U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Attempted(1U, Attach::NoSurface, false, 0U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Answer(false), 2);
  EXPECT_EQ(lifecycle.Attempted(1U, Attach::Attached, false, 16U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Answer(true), 1) << "the first head's new size, kept through the wait";
  EXPECT_EQ(lifecycle.Answer(true), 0);
}

TEST(
  VulkanSurfaceLifecycle,
  ASurfaceThatRefusesWarnsOnceAndEndsTheProgramAfterFiveSeconds
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(1U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 1000U), Verdict::Warn);
  EXPECT_EQ(lifecycle.Answer(false), 2);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 3000U), Verdict::Continue);
  EXPECT_EQ(
    lifecycle.Attempted(0U, Attach::Refused, false, 1000U + SurfaceLifecycle::kRefusalLimitMs), Verdict::Continue
  );
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 1001U + SurfaceLifecycle::kRefusalLimitMs), Verdict::End);
}

TEST(
  VulkanSurfaceLifecycle,
  AnyOtherOutcomeEndsARunOfRefusals
)
{
  for (const Attach between : {Attach::NoSurface, Attach::NoArea, Attach::Attached}) {
    SurfaceLifecycle lifecycle;
    lifecycle.SetHeadCount(1U);
    EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 0U), Verdict::Warn);
    EXPECT_EQ(lifecycle.Attempted(0U, between, false, 4000U), Verdict::Continue);
    EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 8000U), Verdict::Warn) << "a new run";
    EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 12000U), Verdict::Continue);
    EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 13001U), Verdict::End);
  }
}

TEST(
  VulkanSurfaceLifecycle,
  AMinimisedWindowAndOneWithoutASurfaceAreWaitedForWithoutEnd
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(1U);
  for (std::uint64_t now = 0U; now <= 600000U; now += 1000U) {
    EXPECT_EQ(
      lifecycle.Attempted(0U, (now % 2000U == 0U) ? Attach::NoArea : Attach::NoSurface, false, now), Verdict::Continue
    );
    EXPECT_EQ(lifecycle.Answer(false), 2);
  }
}

TEST(
  VulkanSurfaceLifecycle,
  EachHeadRefusesOnItsOwnClock
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(2U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 0U), Verdict::Warn);
  EXPECT_EQ(lifecycle.Attempted(1U, Attach::Refused, false, 4000U), Verdict::Warn);
  EXPECT_EQ(lifecycle.Attempted(1U, Attach::Refused, false, 5001U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 5001U), Verdict::End);
}

TEST(
  VulkanSurfaceLifecycle,
  SetHeadCountStartsAfresh
)
{
  SurfaceLifecycle lifecycle;
  lifecycle.SetHeadCount(1U);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Attached, true, 0U), Verdict::Continue);
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 0U), Verdict::Warn);
  lifecycle.SetHeadCount(1U);
  EXPECT_EQ(lifecycle.Answer(true), 0) << "a new device has no new size to lay out for";
  EXPECT_EQ(lifecycle.Attempted(0U, Attach::Refused, false, 1U), Verdict::Warn) << "nor a run of refusals";
}
