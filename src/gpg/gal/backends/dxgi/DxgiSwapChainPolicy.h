#pragma once

// FAF addition, not in the shipped binary.
//
// The decisions of the DXGI swap chain that need no device: how a Present
// result is read, which flags a Present carries, and what a Reset has to do
// to a swap chain. Header-only and free of any COM object so that the host
// tests (tests/dxgi) can pin them down; DxgiSwapChain.cpp and the backends
// act on the answers.

#include <cstdint>

#include <dxgi.h>
#include <dxgi1_2.h>
#include <winerror.h>

namespace gpg::gal::dxgi
{
  /** What a Present result means for the frame loop. */
  enum class PresentStatus : std::uint8_t
  {
    Presented,   // on its way to the screen
    Occluded,    // DXGI_STATUS_OCCLUDED: success, nothing is shown, Present did not wait
    Skipped,     // a transient refusal (mode change in progress ...): drop this frame
    InvalidCall, // DXGI_ERROR_INVALID_CALL: a flag or state the chain does not allow
    DeviceLost,  // removed / reset / hung / driver fault: only the device recovery helps
    Failed,      // anything else
  };

  [[nodiscard]] constexpr PresentStatus ClassifyPresent(
    const HRESULT result
  ) noexcept
  {
    if (result == DXGI_STATUS_OCCLUDED) {
      return PresentStatus::Occluded;
    }
    if (SUCCEEDED(result)) {
      return PresentStatus::Presented;
    }
    switch (result) {
    case DXGI_ERROR_DEVICE_REMOVED:
    case DXGI_ERROR_DEVICE_RESET:
    case DXGI_ERROR_DEVICE_HUNG:
    case DXGI_ERROR_DRIVER_INTERNAL_ERROR:
      return PresentStatus::DeviceLost;
    case DXGI_ERROR_MODE_CHANGE_IN_PROGRESS:
    case DXGI_ERROR_WAS_STILL_DRAWING:
    case DXGI_ERROR_ACCESS_LOST:
      return PresentStatus::Skipped;
    case DXGI_ERROR_INVALID_CALL:
      return PresentStatus::InvalidCall;
    default:
      return PresentStatus::Failed;
    }
  }

  /**
   * The flags of one Present. The tearing flag is valid only without vsync,
   * on a chain created with ALLOW_TEARING that is not in exclusive full
   * screen; with anything else DXGI answers INVALID_CALL.
   */
  [[nodiscard]] constexpr UINT PresentFlags(
    const bool vsync,
    const bool chainAllowsTearing,
    const bool exclusiveFullscreen,
    const bool tearingDisabledAtRuntime
  ) noexcept
  {
    return (!vsync && chainAllowsTearing && !exclusiveFullscreen && !tearingDisabledAtRuntime)
      ? DXGI_PRESENT_ALLOW_TEARING
      : 0U;
  }

  /** Where one head's swap chain stands, or where the device context wants it. */
  struct ChainState
  {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    bool fullscreen = false;
    std::uint32_t refreshHz = 0; // full-screen only
  };

  enum class ResetAction : std::uint8_t
  {
    None,          // the chain already is what is asked for (a vsync-only change lands here)
    ResizeBuffers, // windowed size change
    Recreate,      // window mode or full-screen mode change: new chain, new flags
  };

  /**
   * What a Reset has to do to one chain. Vsync is only the present interval
   * and never part of this. `minimized` keeps the chain as it is: a minimised
   * window has no client area to resize to, and the first Reset after the
   * restore applies the change.
   */
  [[nodiscard]] constexpr ResetAction PlanReset(
    const ChainState& current,
    const ChainState& wanted,
    const bool minimized,
    const bool force
  ) noexcept
  {
    if (force) {
      return ResetAction::Recreate;
    }
    if (minimized) {
      return ResetAction::None;
    }
    if (current.fullscreen != wanted.fullscreen) {
      return ResetAction::Recreate;
    }
    if (wanted.fullscreen) {
      // The display mode follows the buffer size and the refresh rate at creation.
      return (current.width != wanted.width || current.height != wanted.height || current.refreshHz != wanted.refreshHz)
        ? ResetAction::Recreate
        : ResetAction::None;
    }
    return (current.width != wanted.width || current.height != wanted.height) ? ResetAction::ResizeBuffers
                                                                              : ResetAction::None;
  }

  /** Frame-latency waits that time out this many times in a row are switched off. */
  constexpr std::uint32_t kFrameLatencyTimeoutLimit = 3U;

  /** The Present retries without tearing at most once before the chain is called broken. */
  [[nodiscard]] constexpr bool ShouldRetryWithoutTearing(
    const PresentStatus status,
    const UINT flags
  ) noexcept
  {
    return status == PresentStatus::InvalidCall && (flags & DXGI_PRESENT_ALLOW_TEARING) != 0U;
  }

  /** `SetMaximumFrameLatency` argument from the setting: 0 = off, 1 and up = latency, clamped to the buffer count. */
  [[nodiscard]] constexpr std::uint32_t ClampFrameLatency(
    const std::int64_t setting,
    const std::uint32_t bufferCount
  ) noexcept
  {
    if (setting <= 0) {
      return 0U;
    }
    const std::uint32_t buffers = (bufferCount < 1U) ? 1U : bufferCount;
    return (static_cast<std::uint64_t>(setting) > buffers) ? buffers : static_cast<std::uint32_t>(setting);
  }
} // namespace gpg::gal::dxgi
