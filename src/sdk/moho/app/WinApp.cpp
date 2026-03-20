#include "WinApp.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "platform/Platform.h"

#include <float.h>
#include <commctrl.h>
#include <objbase.h>

#include "CWaitHandleSet.h"
#include "gpg/core/time/Timer.h"
#include "IWinApp.h"
#include "moho/core/Thread.h"

#pragma warning(push)
#pragma warning(disable : 4996)

int wxEntry(HINSTANCE hInstance, HINSTANCE hPrevInstance, char* pCmdLine, int nCmdShow, bool shouldInit);
class wxApp
{
public:
  static void CleanUp();
};
extern void* wxTheApp;

namespace moho
{
  void PLAT_Init();
  void PLAT_CatchStructuredExceptions();
  void PLAT_Exit();
  void RES_Exit();
  void WINX_Exit();
  void WIN_OkBox(gpg::StrArg caption, gpg::StrArg text);
} // namespace moho

namespace
{
  constexpr float kMaxFiniteTimeoutMs = 4294967300.0f;
  constexpr float kInfiniteWakeupMs = std::numeric_limits<float>::infinity();

  /**
   * Minimal wxApp vtable slice recovered from WIN_AppExecute (0x004F20B0):
   * - +0x38: OnExit
   * - +0x4C: Pending
   * - +0x50: Dispatch
   * - +0x58: ProcessIdle
   */
  using WxBoolMethod = bool(__thiscall*)(void*);
  using WxVoidMethod = void(__thiscall*)(void*);

  struct WxAppVTableOverlay
  {
    void* reserved00[0x0E];   // +0x00..+0x34
    WxVoidMethod OnExit;      // +0x38
    void* reserved3C;         // +0x3C
    void* reserved40;         // +0x40
    void* reserved44;         // +0x44
    void* reserved48;         // +0x48
    WxBoolMethod Pending;     // +0x4C
    WxVoidMethod Dispatch;    // +0x50
    void* reserved54;         // +0x54
    WxBoolMethod ProcessIdle; // +0x58
  };

  /**
   * Minimal wxApp object slice recovered from WIN_AppExecute (0x004F20B0):
   * - +0x44: m_exitOnFrameDelete
   * - +0x5C: m_keepGoing
   */
  struct WxAppOverlay
  {
    WxAppVTableOverlay* vtable;       // +0x00
    std::uint8_t reserved04_44[0x40]; // +0x04..+0x43
    std::int32_t exitOnFrameDelete;   // +0x44
    std::uint8_t reserved48_5C[0x14]; // +0x48..+0x5B
    std::uint8_t keepGoing;           // +0x5C
  };

#if defined(_M_IX86) || defined(__i386__)
  static_assert(offsetof(WxAppVTableOverlay, OnExit) == 0x38, "WxAppVTableOverlay::OnExit offset must be 0x38");
  static_assert(offsetof(WxAppVTableOverlay, Pending) == 0x4C, "WxAppVTableOverlay::Pending offset must be 0x4C");
  static_assert(offsetof(WxAppVTableOverlay, Dispatch) == 0x50, "WxAppVTableOverlay::Dispatch offset must be 0x50");
  static_assert(
    offsetof(WxAppVTableOverlay, ProcessIdle) == 0x58, "WxAppVTableOverlay::ProcessIdle offset must be 0x58"
  );
  static_assert(
    offsetof(WxAppOverlay, exitOnFrameDelete) == 0x44, "WxAppOverlay::exitOnFrameDelete offset must be 0x44"
  );
  static_assert(offsetof(WxAppOverlay, keepGoing) == 0x5C, "WxAppOverlay::keepGoing offset must be 0x5C");
#endif

  moho::IWinApp* sSupComApp = nullptr;
  HHOOK sWindowHook = nullptr;
  gpg::time::Timer wakeupTimer;
  float wakeupTimerDur = kInfiniteWakeupMs;

  bool HasCorrectPlatform()
  {
    OSVERSIONINFOW versionInfo{};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    return !::GetVersionExW(&versionInfo) || versionInfo.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS;
  }

  float ProbeWakeTimerMs()
  {
    return static_cast<float>(wakeupTimer.ElapsedMilliseconds());
  }

  [[nodiscard]]
  WxAppOverlay* GetWxApp()
  {
    return static_cast<WxAppOverlay*>(wxTheApp);
  }

  DWORD ComputeWaitTimeoutMs()
  {
    const float remainingMs = wakeupTimerDur - ProbeWakeTimerMs();
    if (remainingMs < 0.0f) {
      return 0;
    }

    if (remainingMs > kMaxFiniteTimeoutMs) {
      return INFINITE;
    }

    return static_cast<DWORD>(std::lround(remainingMs));
  }

  bool WxPending(WxAppOverlay* const wxApp)
  {
    return wxApp != nullptr && wxApp->vtable != nullptr && wxApp->vtable->Pending != nullptr &&
      wxApp->vtable->Pending(wxApp);
  }

  void WxDispatch(WxAppOverlay* const wxApp)
  {
    if (wxApp != nullptr && wxApp->vtable != nullptr && wxApp->vtable->Dispatch != nullptr) {
      wxApp->vtable->Dispatch(wxApp);
    }
  }

  bool WxProcessIdle(WxAppOverlay* const wxApp)
  {
    return wxApp != nullptr && wxApp->vtable != nullptr && wxApp->vtable->ProcessIdle != nullptr &&
      wxApp->vtable->ProcessIdle(wxApp);
  }

  void WxOnExit(WxAppOverlay* const wxApp)
  {
    if (wxApp != nullptr && wxApp->vtable != nullptr && wxApp->vtable->OnExit != nullptr) {
      wxApp->vtable->OnExit(wxApp);
    }
  }

  void WxSetLoopFlags(WxAppOverlay* const wxApp)
  {
    if (wxApp == nullptr) {
      return;
    }

    wxApp->exitOnFrameDelete = 1;
    wxApp->keepGoing = 1;
  }

  [[nodiscard]]
  bool WxKeepGoing(const WxAppOverlay* const wxApp)
  {
    return wxApp != nullptr && wxApp->keepGoing != 0;
  }

  void WxPumpToIdleAndExit()
  {
    WxAppOverlay* const wxApp = GetWxApp();
    if (wxApp == nullptr) {
      return;
    }

    bool keepIdle = true;
    for (;;) {
      if (WxPending(wxApp)) {
        WxDispatch(wxApp);
        continue;
      }

      if (!keepIdle) {
        break;
      }

      keepIdle = WxProcessIdle(wxApp);
    }

    WxOnExit(wxApp);
    wxApp::CleanUp();
  }

  LRESULT CALLBACK WindowHook(const int code, const WPARAM wParam, const LPARAM lParam)
  {
    if (code == HC_ACTION && sSupComApp != nullptr && sSupComApp->AppDoSuppressWindowsKeys() && wParam >= WM_KEYDOWN &&
        wParam <= WM_KEYUP) {
      const auto* const keyData = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
      if (keyData != nullptr && (keyData->vkCode == VK_LWIN || keyData->vkCode == VK_RWIN)) {
        return 1;
      }
    }

    return ::CallNextHookEx(sWindowHook, code, wParam, lParam);
  }
} // namespace

moho::CTaskStage* moho::WIN_GetBeforeEventsStage()
{
  // 0x011043CC
  static CTaskStage sBeforeEventsStage{};
  return &sBeforeEventsStage;
}

moho::CTaskStage* moho::WIN_GetBeforeWaitStage()
{
  // 0x011043B4
  static CTaskStage sBeforeWaitStage{};
  return &sBeforeWaitStage;
}

moho::CWaitHandleSet* moho::WIN_GetWaitHandleSet()
{
  // 0x011043E0
  static CWaitHandleSet sWaitHandleSet{};
  return &sWaitHandleSet;
}

/**
 * Address: 0x004F1FC0
 *
 * What it does:
 * Requests that the main wait loop wake no later than `milliseconds` from now.
 */
void moho::WIN_SetWakeupTimer(const float milliseconds)
{
  if (milliseconds < wakeupTimerDur) {
    wakeupTimerDur = milliseconds;
  }
}

/**
 * Address: 0x004F20B0 (FUN_004F20B0)
 *
 * IWinApp *
 *
 * What it does:
 * Drives app bootstrap, frame pumping, and shutdown around the IWinApp interface.
 */
void moho::WIN_AppExecute(IWinApp* const app)
{
  if (app == nullptr) {
    return;
  }

  sSupComApp = app;
  const HMODULE module = ::GetModuleHandleW(nullptr);
  sWindowHook = ::SetWindowsHookExW(WH_KEYBOARD_LL, &WindowHook, module, 0);

  HMODULE selfModule = nullptr;
  ::GetModuleHandleExW(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    reinterpret_cast<LPCWSTR>(&WindowHook),
    &selfModule
  );
  wxEntry(selfModule, nullptr, nullptr, 0, false);

  if (!HasCorrectPlatform()) {
    WIN_OkBox(
      "Old OS Version",
      "This application requires Windows NT, 2000, XP, or newer, to operate.\n"
      "Windows 95, 98, and ME are not supported."
    );
    sSupComApp = nullptr;
    return;
  }

  THREAD_SetAffinity(true);
  ::InitCommonControls();
  ::CoInitialize(nullptr);
  PLAT_Init();
  PLAT_CatchStructuredExceptions();
  wakeupTimer.Reset();
  wakeupTimerDur = kInfiniteWakeupMs;

  if (!app->Init()) {
    ::TerminateProcess(::GetCurrentProcess(), 1u);
  }

  if (WxAppOverlay* const wxApp = GetWxApp(); wxApp != nullptr) {
    WxSetLoopFlags(wxApp);
  }

  _controlfp(0x20000, 0x30000);

  bool success = true;
  bool acceptNewEvent = true;
  for (;;) {
    while (acceptNewEvent) {
      ::SleepEx(0, TRUE);
      WIN_GetBeforeEventsStage()->UserFrame();
      acceptNewEvent = false;
    }

    WxAppOverlay* const wxApp = GetWxApp();
    if (wxApp != nullptr && WxPending(wxApp)) {
      WxDispatch(wxApp);
      success = true;
      continue;
    }

    if (wxApp != nullptr && success) {
      success = WxProcessIdle(wxApp);
      continue;
    }

    if (wxApp == nullptr || !WxKeepGoing(wxApp)) {
      break;
    }

    app->Main();
    success = true;
    acceptNewEvent = true;

    WIN_GetBeforeWaitStage()->UserFrame();

    const DWORD timeoutMs = ComputeWaitTimeoutMs();
    wakeupTimerDur = kInfiniteWakeupMs;
    WIN_GetWaitHandleSet()->MsgWaitEx(timeoutMs);
  }

  app->Destroy();
  WINX_Exit();
  PLAT_Exit();
  WxPumpToIdleAndExit();

  if (sWindowHook != nullptr) {
    ::UnhookWindowsHookEx(sWindowHook);
    sWindowHook = nullptr;
  }

  RES_Exit();
  sSupComApp = nullptr;
}

#pragma warning(pop)
