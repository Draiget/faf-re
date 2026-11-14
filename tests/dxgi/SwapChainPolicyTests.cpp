// Host test of the swap-chain decisions that need no device (src/gpg/gal/backends/dxgi/DxgiSwapChainPolicy.h): how a
// Present result is read, the Present flags, what a Reset does to a chain (a vsync-only change must do nothing) and the
// frame-latency clamp.

#include <cstdint>

#include <gtest/gtest.h>

#include "gpg/gal/backends/dxgi/DxgiSwapChainPolicy.h"

namespace
{
  using namespace gpg::gal::dxgi;

#define CHECK(cond) EXPECT_TRUE(cond)

  void CheckClassifyPresent()
  {
    CHECK(ClassifyPresent(S_OK) == PresentStatus::Presented);
    CHECK(ClassifyPresent(DXGI_STATUS_OCCLUDED) == PresentStatus::Occluded);
    CHECK(SUCCEEDED(DXGI_STATUS_OCCLUDED)); // the reason it must not reach a failure check
    // Other success codes are frames on their way to the screen.
    CHECK(ClassifyPresent(DXGI_STATUS_CLIPPED) == PresentStatus::Presented);
    CHECK(ClassifyPresent(DXGI_STATUS_MODE_CHANGED) == PresentStatus::Presented);
    CHECK(ClassifyPresent(DXGI_STATUS_NO_DESKTOP_ACCESS) == PresentStatus::Presented);
    CHECK(ClassifyPresent(DXGI_ERROR_DEVICE_REMOVED) == PresentStatus::DeviceLost);
    CHECK(ClassifyPresent(DXGI_ERROR_DEVICE_RESET) == PresentStatus::DeviceLost);
    CHECK(ClassifyPresent(DXGI_ERROR_DEVICE_HUNG) == PresentStatus::DeviceLost);
    CHECK(ClassifyPresent(DXGI_ERROR_DRIVER_INTERNAL_ERROR) == PresentStatus::DeviceLost);
    CHECK(ClassifyPresent(DXGI_ERROR_MODE_CHANGE_IN_PROGRESS) == PresentStatus::Skipped);
    CHECK(ClassifyPresent(DXGI_ERROR_WAS_STILL_DRAWING) == PresentStatus::Skipped);
    CHECK(ClassifyPresent(DXGI_ERROR_INVALID_CALL) == PresentStatus::InvalidCall);
    CHECK(ClassifyPresent(E_OUTOFMEMORY) == PresentStatus::Failed);
    CHECK(ClassifyPresent(E_FAIL) == PresentStatus::Failed);
  }

  void CheckPresentFlags()
  {
    // Tearing: only without vsync, on a chain made for it, outside exclusive full screen, until refused once.
    CHECK(PresentFlags(false, true, false, false) == DXGI_PRESENT_ALLOW_TEARING);
    CHECK(PresentFlags(true, true, false, false) == 0U);
    CHECK(PresentFlags(false, false, false, false) == 0U);
    CHECK(PresentFlags(false, true, true, false) == 0U);
    CHECK(PresentFlags(false, true, false, true) == 0U);

    // An INVALID_CALL with the tearing flag is retried once without it; without the flag it is not a tearing problem.
    CHECK(ShouldRetryWithoutTearing(PresentStatus::InvalidCall, DXGI_PRESENT_ALLOW_TEARING));
    CHECK(!ShouldRetryWithoutTearing(PresentStatus::InvalidCall, 0U));
    CHECK(!ShouldRetryWithoutTearing(PresentStatus::DeviceLost, DXGI_PRESENT_ALLOW_TEARING));
    CHECK(!ShouldRetryWithoutTearing(PresentStatus::Presented, DXGI_PRESENT_ALLOW_TEARING));
  }

  void CheckPlanReset()
  {
    const ChainState windowed{1600U, 900U, false, 0U};
    const ChainState fullscreen{1920U, 1080U, true, 60U};

    // Vsync is not part of the state: the same chain asked for again does nothing.
    CHECK(PlanReset(windowed, windowed, false, false) == ResetAction::None);
    CHECK(PlanReset(fullscreen, fullscreen, false, false) == ResetAction::None);

    // Windowed size change: ResizeBuffers.
    CHECK(PlanReset(windowed, ChainState{1280U, 720U, false, 0U}, false, false) == ResetAction::ResizeBuffers);
    CHECK(PlanReset(windowed, ChainState{1600U, 901U, false, 0U}, false, false) == ResetAction::ResizeBuffers);

    // Window mode change in either direction: a new chain (tearing flag and display mode are fixed at creation).
    CHECK(PlanReset(windowed, fullscreen, false, false) == ResetAction::Recreate);
    CHECK(PlanReset(fullscreen, windowed, false, false) == ResetAction::Recreate);

    // Full screen: the display mode follows size and refresh rate, so either change makes a new chain.
    CHECK(PlanReset(fullscreen, ChainState{1280U, 720U, true, 60U}, false, false) == ResetAction::Recreate);
    CHECK(PlanReset(fullscreen, ChainState{1920U, 1080U, true, 144U}, false, false) == ResetAction::Recreate);

    // A minimised window keeps its chain; recovery overrides everything.
    CHECK(PlanReset(windowed, ChainState{1280U, 720U, false, 0U}, true, false) == ResetAction::None);
    CHECK(PlanReset(windowed, windowed, false, true) == ResetAction::Recreate);
    CHECK(PlanReset(windowed, windowed, true, true) == ResetAction::Recreate);
  }

  void CheckFrameLatency()
  {
    CHECK(ClampFrameLatency(0, 2U) == 0U);
    CHECK(ClampFrameLatency(-5, 2U) == 0U);
    CHECK(ClampFrameLatency(1, 2U) == 1U);
    CHECK(ClampFrameLatency(2, 2U) == 2U);
    CHECK(ClampFrameLatency(3, 2U) == 2U); // never more frames than buffers
    CHECK(ClampFrameLatency(100, 3U) == 3U);
    CHECK(ClampFrameLatency(2, 0U) == 1U);
  }
} // namespace

TEST(
  SwapChainPolicy,
  ClassifyPresent
)
{
  CheckClassifyPresent();
}
TEST(
  SwapChainPolicy,
  PresentFlags
)
{
  CheckPresentFlags();
}
TEST(
  SwapChainPolicy,
  PlanReset
)
{
  CheckPlanReset();
}
TEST(
  SwapChainPolicy,
  FrameLatency
)
{
  CheckFrameLatency();
}
