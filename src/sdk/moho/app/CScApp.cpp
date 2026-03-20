#include "CScApp.h"

#include <Windows.h>

#include <algorithm>
#include <array>

#include "gpg/gal/AppRuntimeView.h"
#include "moho/app/WinApp.h"

namespace gpg
{
  void Logf(const char* fmt, ...);
  void Warnf(const char* fmt, ...);
} // namespace gpg

namespace
{
  msvc8::string sCompanyName;
  msvc8::string sProductName;
  msvc8::string sAppPreferencePrefix;
  std::uint32_t sGameIdPart1 = 0;
  std::uint32_t sGameIdPart2 = 0;
  std::uint32_t sGameIdPart3 = 0;
  std::uint32_t sGameIdPart4 = 0;

  /**
   * Address: 0x008CE0A0 (FUN_008CE0A0)
   *
   * What it does:
   * Refreshes global app identity strings and fixed game-id dwords set by
   * the CScApp constructor path.
   */
  void InitializeGlobalAppIdentity()
  {
    sCompanyName.assign_owned("Gas Powered Games");
    sProductName.assign_owned("Supreme Commander Forged Alliance");
    sAppPreferencePrefix.assign_owned("SCFA");
    sGameIdPart1 = 0xFA42B43A;
    sGameIdPart2 = 0x68BC5B02;
    sGameIdPart3 = 0x4F701F15;
    sGameIdPart4 = 0x7C3E8FB0;
  }

  struct SupComFrameOverlay
  {
    std::uint8_t reserved[0x17B];
    std::uint8_t frameReady;
  };
  static_assert(
    offsetof(SupComFrameOverlay, frameReady) == 0x17B, "SupComFrameOverlay::frameReady offset must be 0x17B"
  );

  using WxDestroyMethod = void(__thiscall*)(void*);
  using WxGetHandleMethod = HWND(__thiscall*)(void*);

  struct WxWindowVTableOverlay
  {
    void* reserved00_28[0x0B];
    WxDestroyMethod Destroy; // +0x2C
  };
  static_assert(offsetof(WxWindowVTableOverlay, Destroy) == 0x2C, "WxWindowVTableOverlay::Destroy offset must be 0x2C");

  struct WxWindowOverlay
  {
    WxWindowVTableOverlay* vtable;
  };

  struct WxFrameVTableOverlay
  {
    void* reserved00_170[0x5D];
    WxGetHandleMethod GetHandle; // +0x174
  };
  static_assert(
    offsetof(WxFrameVTableOverlay, GetHandle) == 0x174, "WxFrameVTableOverlay::GetHandle offset must be 0x174"
  );

  struct WxFrameOverlay
  {
    WxFrameVTableOverlay* vtable;
  };

  constexpr float kMinimizedWakeHintMs = 50.0f;

  void PushFrameDelta(CScApp::RollingFrameRates& history, const float deltaSeconds)
  {
    const int next = (history.end + 1) % 10;
    if (next == history.start) {
      history.start = (history.start + 1) % 10;
    }

    history.vals[history.end] = deltaSeconds;
    history.end = next;
  }
} // namespace

/**
 * Address: 0x008D5280 (FUN_008D5280, sub_8D5280)
 *
 * What it does:
 * Flushes the ring and resets start/end indexes to zero.
 */
void CScApp::RollingFrameRates::Reset()
{
  if (start != end) {
    do {
      start = (start + 1) % 10;
    } while (start != end);
  }

  start = 0;
  end = 0;
}

/**
 * Address: 0x008D4B20 (FUN_008D4B20, struct_RollingFrameRates::median)
 *
 * What it does:
 * Copies the active ring window to a scratch buffer, sorts it,
 * and returns the middle sample.
 */
float CScApp::RollingFrameRates::Median() const
{
  std::array<float, 10> samples{};
  int cursor = start;
  int count = 0;

  while (cursor != end && count < 10) {
    samples[static_cast<std::size_t>(count)] = vals[cursor];
    cursor = (cursor + 1) % 10;
    ++count;
  }

  if (count == 0) {
    return 0.0f;
  }

  std::sort(samples.begin(), samples.begin() + count);
  return samples[static_cast<std::size_t>(count / 2)];
}

/**
 * Address: 0x008CE0A0 (FUN_008CE0A0)
 * Mangled context: constructor prologue used by app bootstrap.
 *
 * What it does:
 * Initializes core CScApp runtime fields after IWinApp base construction.
 */
CScApp::CScApp()
  : IWinApp("SupCom", "SupremeCommander")
  , usingScreensaver(0)
  , initialized(0)
  , isMinimized(0)
  , reserved4A{0, 0}
  , supcomFrame(nullptr)
  , frame(nullptr)
  , firstFramePending(1)
  , reserved55{0, 0, 0}
  , curTime()
  , framerates{}
{
  // FA ctor calls gpg::time::Timer::Timer/Reset at +0x58 and zeroes ring indexes.
  curTime.Reset();
  framerates.start = 0;
  framerates.end = 0;
  InitializeGlobalAppIdentity();
}

/**
 * Address: 0x008D1CB0 (FUN_008D1CB0, CScApp::Dtr scalar deleting dtor)
 *
 * What it does:
 * Clears rolling framerate state, then tears down IWinApp base state.
 */
CScApp::~CScApp()
{
  framerates.Reset();
}

/**
 * Address: 0x008CEDE0 (FUN_008CEDE0)
 * Mangled: ?Init@CScApp@@UAE_NXZ
 *
 * What it does:
 * Performs app startup bootstrap. This first-pass lift keeps the recovered
 * ordering around common-service init, timing/ring reset, and screensaver
 * suppression used by the render loop path.
 */
bool CScApp::Init()
{
  InitializeGlobalAppIdentity();
  framerates.Reset();
  curTime.Reset();
  firstFramePending = 1;
  initialized = 0;
  isMinimized = 0;

  if (!AppInitCommonServices()) {
    return false;
  }

  if (!::SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &usingScreensaver, 0)) {
    usingScreensaver = 0;
  }

  if (!::SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, 0, nullptr, 0)) {
    gpg::Warnf("unable to suppress screensaver");
  }

  return true;
}

/**
 * Address: 0x008D1470 (FUN_008D1470)
 * Mangled: ?Main@CScApp@@UAEXXZ
 *
 * What it does:
 * Drives per-frame app timing state. This first-pass lift reconstructs the
 * recovered timer/ring behavior and minimized-state wakeup hinting used by
 * the outer WinApp loop.
 */
void CScApp::Main()
{
  float frameSeconds = 0.0f;
  if (firstFramePending != 0) {
    firstFramePending = 0;
    curTime.Reset();
    PushFrameDelta(framerates, 0.0f);
  } else {
    frameSeconds = static_cast<float>(curTime.ElapsedMilliseconds() * 0.001);
    curTime.Reset();
    PushFrameDelta(framerates, frameSeconds);
  }

  const float smoothedFrameSeconds = framerates.Median();
  (void)smoothedFrameSeconds;

  bool minimizedNow = false;
  if (frame != nullptr) {
    const auto* const frameView = static_cast<const WxFrameOverlay*>(frame);
    if (frameView->vtable != nullptr && frameView->vtable->GetHandle != nullptr) {
      const HWND windowHandle = frameView->vtable->GetHandle(const_cast<WxFrameOverlay*>(frameView));
      minimizedNow = windowHandle != nullptr && ::IsIconic(windowHandle) != FALSE;
    }
  }

  if (minimizedNow) {
    moho::WIN_SetWakeupTimer(kMinimizedWakeHintMs);
  }

  if (minimizedNow != (isMinimized != 0)) {
    gpg::Logf("Minimized %s", minimizedNow ? "true" : "false");
  }

  if (initialized == 0) {
    initialized = 1;
  }

  isMinimized = minimizedNow ? 1 : 0;
}

/**
 * Address: 0x008D0F20 (FUN_008D0F20)
 * Mangled: ?Destroy@CScApp@@UAEXXZ
 *
 * What it does:
 * App shutdown teardown. This first-pass lift preserves screensaver restore,
 * frame-window destruction, cursor unclipping, and local runtime cleanup.
 */
void CScApp::Destroy()
{
  if (!::SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, usingScreensaver, nullptr, 0)) {
    gpg::Warnf("unable to reset screensaver");
  }

  if (supcomFrame != nullptr) {
    auto* const frameWindow = static_cast<WxWindowOverlay*>(supcomFrame);
    if (frameWindow->vtable != nullptr && frameWindow->vtable->Destroy != nullptr) {
      frameWindow->vtable->Destroy(frameWindow);
    }
    supcomFrame = nullptr;
  }

  if (frame != nullptr) {
    auto* const rootWindow = static_cast<WxWindowOverlay*>(frame);
    if (rootWindow->vtable != nullptr && rootWindow->vtable->Destroy != nullptr) {
      rootWindow->vtable->Destroy(rootWindow);
    }
    frame = nullptr;
  }

  ::ClipCursor(nullptr);
  framerates.Reset();
  firstFramePending = 1;
  initialized = 0;
  isMinimized = 0;
}

/**
 * Address: 0x008CE1D0 (FUN_008CE1D0, CScApp::HasFrame)
 * Mangled: ?AppDoSuppressWindowsKeys@CScApp@@UBE_NXZ
 *
 * What it does:
 * Returns whether low-level keyboard suppression should be active.
 */
bool CScApp::AppDoSuppressWindowsKeys() const
{
  if (!gpg::gal::DeviceAppView::IsReady()) {
    return false;
  }

  auto* const device = gpg::gal::DeviceAppView::GetInstance();
  if (device == nullptr) {
    return false;
  }

  auto* const context = device->GetDeviceContext();
  if (context == nullptr) {
    return false;
  }

  if (!context->GetHead(0).windowed) {
    return false;
  }

  if (supcomFrame == nullptr) {
    return false;
  }

  const auto* const frameState = static_cast<const SupComFrameOverlay*>(supcomFrame);
  return frameState->frameReady != 0;
}
