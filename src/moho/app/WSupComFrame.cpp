#include "moho/app/AppPrivate.h"

#if FAFRE_PLATFORM_POSIX
#include "gpg/core/time/Timer.h"
#include "moho/app/WinApp.h"
#endif

namespace
{
#if FAFRE_PLATFORM_POSIX
  // A tiling window manager or a drag sends a size change every frame; the device follows once
  // they stop for kResizeSettleMs (WSupComFrame::ApplyPendingResize). A bind the device refuses is
  // tried again kResizeRetries times, then left until the next size change.
  constexpr float kResizeSettleMs = 150.0f;
  constexpr int kResizeRetries = 10;
  bool sResizePending = false;
  int sResizeFailures = 0;
  gpg::time::Timer sResizeTimer;
#endif

  // The system-menu items CScApp's AppendLuaDebuggerSystemMenu (0x008D42E0) adds.
  constexpr int kSupComFrameSysCommandToggleLogDialog = 1;
  constexpr int kSupComFrameSysCommandLuaDebugger = 2;

  constexpr const char* kSupComFrameXPreferenceKey = "Windows.Main.x";
  constexpr const char* kSupComFrameYPreferenceKey = "Windows.Main.y";
  constexpr const char* kSupComFrameWidthPreferenceKey = "Windows.Main.width";
  constexpr const char* kSupComFrameHeightPreferenceKey = "Windows.Main.height";
  constexpr const char* kSupComFrameMaximizedPreferenceKey = "Windows.Main.maximized";
  constexpr const char* kSupComFrameToggleLogDialogCommand = "WIN_ToggleLogDialog";
  constexpr const char* kSupComFrameLuaDebuggerCommand = "SC_LuaDebugger";
  constexpr const char* kSupComFrameCursorLockPreferenceKey = "lock_fullscreen_cursor_to_window";

  /**
   * Address: 0x008CDBE0 (FUN_008CDBE0)
   *
   * What it does:
   * Clamps SupCom frame client dimensions to drag minima, propagates size to
   * the active viewport, then rebuilds one GAL context head and reinitializes
   * D3D device state.
   *
   * Engine addition: returns InitContext's result (retail drops it), so the POSIX frame can try a
   * failed bind again. On POSIX the window system has already sized the window: the client size is
   * in pixels while SetClientSize takes the window system's points (SDL_SetWindowSize), so writing
   * it back would grow the window on a scaled display, and the minimum clamp would fight a tiling
   * window manager. A zero size (a window being unmapped) is skipped there.
   */
  bool SyncSupComFrameClientSizeAndViewport(
    WSupComFrame& frame
  )
  {
    int width = 0;
    int height = 0;
    frame.GetClientSize(&width, &height);

#if FAFRE_PLATFORM_POSIX
    if (width <= 0 || height <= 0) {
      return false;
    }
#else
    if (width < moho::wnd_MinDragWidth) {
      width = moho::wnd_MinDragWidth;
    }
    if (height < moho::wnd_MinDragHeight) {
      height = moho::wnd_MinDragHeight;
    }

    frame.SetClientSize(width, height);
#endif
    if (moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->SetSize(-1, -1, width, height, SHELL_SIZE_USE_EXISTING);
    }

    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return false;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return false;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() > 0) {
      gpg::gal::Head& head = context.GetHead(0);
      head.mWidth = width;
      head.mHeight = height;
    }

    moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice();
    if (d3dDevice == nullptr) {
      return false;
    }

    d3dDevice->Clear();
    return d3dDevice->InitContext(&context);
  }

  /**
   * Address: 0x008D1D70 (FUN_008D1D70)
   *
   * What it does:
   * Applies cursor clipping for active SupCom frame focus: locks to main
   * window rectangle when one windowed head is active and the cursor-lock
   * option is enabled, otherwise clears clip bounds.
   */
  void UpdateSupComCursorClipForActivation()
  {
    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() <= 0) {
      return;
    }

    const gpg::gal::Head& head = context.GetHead(0);
    RECT clipRect{};
    RECT* clipRectPtr = nullptr;
    if (
      context.GetHeadCount() == 1 && head.mWindowed && moho::OPTIONS_GetInt(kSupComFrameCursorLockPreferenceKey) == 1 &&
      moho::sMainWindow != nullptr
    ) {
      const HWND mainWindowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
      if (mainWindowHandle != nullptr) {
        ::GetWindowRect(mainWindowHandle, &clipRect);
        clipRectPtr = &clipRect;
      }
    }

    ::ClipCursor(clipRectPtr);
  }

  // True while the device's head 0 is a window (not full screen) the frame's size should follow.
  // Head::mWindowed is the full-screen flag (CScApp::CreateAppFrame picks the full-screen frame style
  // when it is set).
  [[nodiscard]] bool DeviceFollowsFrame()
  {
    if (moho::sDeviceLock || moho::ren_Viewport == nullptr || !gpg::gal::Device::IsReady()) {
      return false;
    }
    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceContext* const activeContext = galDevice != nullptr ? galDevice->GetDeviceContext() : nullptr;
    return activeContext != nullptr && activeContext->GetHeadCount() > 0 && !activeContext->GetHead(0).mWindowed;
  }

  // The device's head 0 size, or -1 when there is no device.
  void DeviceHeadSize(
    int& width,
    int& height
  )
  {
    width = -1;
    height = -1;
    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceContext* const activeContext = galDevice != nullptr ? galDevice->GetDeviceContext() : nullptr;
    if (activeContext != nullptr && activeContext->GetHeadCount() > 0) {
      width = activeContext->GetHead(0).mWidth;
      height = activeContext->GetHead(0).mHeight;
    }
  }
} // namespace

/**
 * Address: 0x008CD8C0 (FUN_008CD8C0)
 * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
 *
 * What it does:
 * Creates the frame (wxFrame at 0x008CD953, named wxFrameNameStr, the title
 * widened from UTF-8), clears the two maximize-sync flags, limits dragging to
 * wnd_MinDragWidth x wnd_MinDragHeight (0x00963560) and puts the
 * IDI_WIN_FAICON resource icon on it (0x009AA610, 0x0098C640). The first and
 * last flag bytes are left as they are.
 */
WSupComFrame::WSupComFrame(
  const char* const title,
  const ShellPoint& position,
  const ShellSize& size,
  const long style
)
  : ShellFrame(nullptr, -1, gpg::STR_Utf8ToWide(title).c_str(), position, size, style)
{
  mPendingMaximizeSync = 0;
  mPersistedMaximizeSync = 0;
  SetSizeHints(moho::wnd_MinDragWidth, moho::wnd_MinDragHeight);
  SetIcon(ShellIcon(SHELL_T("IDI_WIN_FAICON"), SHELL_BITMAP_TYPE_ICO_RESOURCE));
}

// Table 0x00DFE4EC = {&wxFrame::sm_eventTable (0x00D56F70), rows 0x00F5BB4C};
// GetEventTable (0x008CE090) comes with it. The deleting destructor
// (0x008CE060) is the compiler's.
BEGIN_EVENT_TABLE(
  WSupComFrame,
  ShellFrame
)
EVT_CLOSE(
  WSupComFrame::OnCloseWindow
)
EVT_MOVE(
  WSupComFrame::OnMove
)
EVT_SIZE(
  WSupComFrame::OnSize
)
EVT_ACTIVATE(
  WSupComFrame::OnActivate
)
END_EVENT_TABLE()

/**
 * Address: 0x008CDAA0 (FUN_008CDAA0, WSupComFrame::OnCloseWindow)
 *
 * What it does:
 * Exits the wx main loop when the frame is iconized; otherwise requests the
 * Moho escape dialog.
 */
void WSupComFrame::OnCloseWindow(
  ShellCloseEvent& event
)
{
  (void)event;

  if (IsIconized()) {
    gShellApp->ExitMainLoop();
    return;
  }

  (void)moho::ShowEscapeDialog(true);
}

/**
 * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
 *
 * What it does:
 * Persists SupCom frame position lanes to user preferences while device-lock
 * is disabled and the frame is not iconized.
 */
void WSupComFrame::OnMove(
  ShellMoveEvent& event
)
{
  (void)event;
  if (moho::sDeviceLock || IsIconized()) {
    return;
  }

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (preferences == nullptr) {
    return;
  }

  // x goes to Windows.Main.x and y to Windows.Main.y. An earlier revision
  // swapped them; CScApp::CreateDevice reads the keys straight back, so every
  // launch re-applied the swap until the window opened off every monitor.
  preferences->SetInteger(fa::string(kSupComFrameXPreferenceKey), GetPosition().x);
  preferences->SetInteger(fa::string(kSupComFrameYPreferenceKey), GetPosition().y);
}

/**
 * The size half of WSupComFrame::MSWWindowProc (0x008CDD40). The retail frame re-sized the
 * viewport and the device when Windows reported a maximize (WM_SIZE, SIZE_MAXIMIZED), a restore
 * from it, or the end of a drag of the frame's edge (WM_EXITSIZEMOVE after SC_SIZE), and saved
 * Windows.Main.width/height/maximized. The window system reports the finished size (one event for
 * a drag, WindowSdl.cpp); the frame follows it while the device is windowed.
 */
void WSupComFrame::OnSize(
  ShellSizeEvent& event
)
{
  (void)event;
#if FAFRE_PLATFORM_POSIX
  // ApplyPendingResize follows the size from the main loop once the changes stop.
  if (this == moho::sMainWindow) {
    sResizePending = true;
    sResizeFailures = 0;
    sResizeTimer.Reset();
  }
#else
  (void)FollowClientSize();
#endif
}

#if FAFRE_PLATFORM_POSIX
void WSupComFrame::ApplyPendingResize()
{
  if (!sResizePending) {
    return;
  }
  const float elapsedMs = sResizeTimer.ElapsedMilliseconds();
  if (moho::sDeviceLock || elapsedMs < kResizeSettleMs) {
    // The main loop may wait for messages without a timeout (an idle menu, a paused game): ask it
    // to come back when the size has settled.
    moho::WIN_SetWakeupTimer(moho::sDeviceLock ? kResizeSettleMs : kResizeSettleMs - elapsedMs);
    return;
  }
  auto* const frame = dynamic_cast<WSupComFrame*>(moho::sMainWindow);
  if (frame == nullptr) {
    sResizePending = false;
    return;
  }
  if (frame->FollowClientSize() || ++sResizeFailures > kResizeRetries) {
    sResizePending = false;
    return;
  }
  // The device didn't take the size (a lost or busy swap chain): try again after another wait.
  sResizeTimer.Reset();
  moho::WIN_SetWakeupTimer(kResizeSettleMs);
}
#endif

bool WSupComFrame::FollowClientSize()
{
  if (!DeviceFollowsFrame() || IsIconized()) {
    return true;
  }

  int headWidth = 0;
  int headHeight = 0;
  DeviceHeadSize(headWidth, headHeight);
  const ShellSize clientSize = GetClientSize();
  const bool maximized = IsMaximized();
  const bool sizeChanged = clientSize.x != headWidth || clientSize.y != headHeight;
  if (!sizeChanged && (maximized ? 1 : 0) == mPersistedMaximizeSync) {
    return true;
  }

  // Retail went on to the preferences whatever InitContext returned; so does Windows here.
  [[maybe_unused]] const bool bound = !sizeChanged || SyncSupComFrameClientSizeAndViewport(*this);
#if FAFRE_PLATFORM_POSIX
  if (!bound) {
    return false;
  }
#endif

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (preferences != nullptr) {
    if (!maximized) {
      const ShellSize savedSize = GetClientSize();
      preferences->SetInteger(fa::string(kSupComFrameWidthPreferenceKey), savedSize.x);
      preferences->SetInteger(fa::string(kSupComFrameHeightPreferenceKey), savedSize.y);
    }
    preferences->SetBoolean(fa::string(kSupComFrameMaximizedPreferenceKey), maximized);
  }
  mPersistedMaximizeSync = maximized ? 1 : 0;
  mPendingMaximizeSync = 0;
  return true;
}

/**
 * WM_ACTIVATEAPP in WSupComFrame::MSWWindowProc (0x008CDD40).
 */
void WSupComFrame::OnActivate(
  ShellActivateEvent& event
)
{
  const bool isActive = event.GetActive();
  mIsApplicationActive = isActive ? 1 : 0;
  if (isActive) {
    UpdateSupComCursorClipForActivation();
  } else {
    ::ClipCursor(nullptr);
  }
}

/**
 * WM_SYSCOMMAND in WSupComFrame::MSWWindowProc (0x008CDD40): the log window and the Lua debugger
 * items of the system menu.
 */
void WSupComFrame::OnSystemCommand(
  const int command
)
{
  if (command == kSupComFrameSysCommandToggleLogDialog) {
    moho::CON_Execute(kSupComFrameToggleLogDialogCommand);
  } else if (command == kSupComFrameSysCommandLuaDebugger) {
    moho::CON_Execute(kSupComFrameLuaDebuggerCommand);
  }
}
