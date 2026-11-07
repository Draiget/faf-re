#include "moho/app/WxPrivate.h"

namespace
{
  constexpr unsigned int kSupComFrameMessageSize = WM_SIZE;
  constexpr unsigned int kSupComFrameMessageActivateApp = WM_ACTIVATEAPP;
  constexpr unsigned int kSupComFrameMessageSysCommand = WM_SYSCOMMAND;
  constexpr unsigned int kSupComFrameMessageExitSizeMove = WM_EXITSIZEMOVE;
  constexpr unsigned int kSupComFrameSysCommandSize = SC_SIZE;
  constexpr unsigned int kSupComFrameSysCommandToggleLogDialog = 0x1u;
  constexpr unsigned int kSupComFrameSysCommandLuaDebugger = 0x2u;
  constexpr unsigned int kSupComFrameSysCommandKeyMenu = SC_KEYMENU;

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
   */
  void SyncSupComFrameClientSizeAndViewport(
    WSupComFrame& frame
  )
  {
    int width = 0;
    int height = 0;
    frame.GetClientSize(&width, &height);

    if (width < moho::wnd_MinDragWidth) {
      width = moho::wnd_MinDragWidth;
    }
    if (height < moho::wnd_MinDragHeight) {
      height = moho::wnd_MinDragHeight;
    }

    frame.SetClientSize(width, height);
    if (moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->SetSize(-1, -1, width, height, wxSIZE_USE_EXISTING);
    }

    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() > 0) {
      gpg::gal::Head& head = context.GetHead(0);
      head.mWidth = width;
      head.mHeight = height;
    }

    moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice();
    if (d3dDevice == nullptr) {
      return;
    }

    d3dDevice->Clear();
    d3dDevice->InitContext(&context);
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
}


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
  const wxPoint& position,
  const wxSize& size,
  const long style
)
  : wxFrame(nullptr, -1, gpg::STR_Utf8ToWide(title).c_str(), position, size, style)
{
  mPendingMaximizeSync = 0;
  mPersistedMaximizeSync = 0;
  SetSizeHints(moho::wnd_MinDragWidth, moho::wnd_MinDragHeight);
  SetIcon(wxIcon(wxT("IDI_WIN_FAICON"), wxBITMAP_TYPE_ICO_RESOURCE));
}

// Table 0x00DFE4EC = {&wxFrame::sm_eventTable (0x00D56F70), rows 0x00F5BB4C};
// GetEventTable (0x008CE090) comes with it. The deleting destructor
// (0x008CE060) is the compiler's.
BEGIN_EVENT_TABLE(WSupComFrame, wxFrame)
  EVT_CLOSE(WSupComFrame::OnCloseWindow)
  EVT_MOVE(WSupComFrame::OnMove)
END_EVENT_TABLE()

/**
 * Address: 0x008CDAA0 (FUN_008CDAA0, WSupComFrame::OnCloseWindow)
 *
 * What it does:
 * Exits the wx main loop when the frame is iconized; otherwise requests the
 * Moho escape dialog.
 */
void WSupComFrame::OnCloseWindow(
  wxCloseEvent& event
)
{
  (void)event;

  if (IsIconized()) {
    wxTheApp->ExitMainLoop();
    return;
  }

  (void)moho::ShowEscapeDialog(true);
}

/**
 * Address: 0x008CDCD0 (FUN_008CDCD0, WSupComFrame::MSWDefWindowProc)
 *
 * What it does:
 * Handles SupCom system-command defaults, including pending-maximize sync
 * priming and Alt-menu suppression, then forwards remaining lanes through
 * base wx default-window-proc dispatch.
 */
long WSupComFrame::MSWDefWindowProc(
  const WXUINT message,
  const WXWPARAM wParam,
  const WXLPARAM lParam
)
{
  auto dispatchBase = [this, message, wParam, lParam]() -> long {
    return wxFrame::MSWDefWindowProc(message, wParam, lParam);
  };

  if (message != kSupComFrameMessageSysCommand) {
    return dispatchBase();
  }

  if ((wParam & 0xFFF0u) == kSupComFrameSysCommandSize) {
    mPendingMaximizeSync = 1;
    if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
      (void)device->Clear2(true);
    }
  }

  if (wParam == kSupComFrameSysCommandKeyMenu && lParam == 0) {
    return 0;
  }

  return dispatchBase();
}

/**
 * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
 *
 * What it does:
 * Persists SupCom frame position lanes to user preferences while device-lock
 * is disabled and the frame is not iconized.
 */
void WSupComFrame::OnMove(
  wxMoveEvent& event
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
 * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
 * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
 *
 * What it does:
 * Handles SupCom frame resize/maximize/app-activation/system-command routing,
 * persists window preference keys, and forwards unhandled messages to base
 * frame dispatch.
 */
long WSupComFrame::MSWWindowProc(
  const WXUINT message,
  const WXWPARAM wParam,
  const WXLPARAM lParam
)
{
  auto dispatchBase = [this, message, wParam, lParam]() -> long {
    return wxFrame::MSWWindowProc(message, wParam, lParam);
  };

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (!moho::sDeviceLock && moho::ren_Viewport != nullptr && gpg::gal::Device::IsReady()) {
    if (gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance(); galDevice != nullptr) {
      if (
        gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
        activeContext != nullptr && activeContext->GetHeadCount() > 0
      ) {
        (void)activeContext->GetHead(0);
      }
    }

    if (mPendingMaximizeSync != 0 && message == kSupComFrameMessageExitSizeMove) {
      SyncSupComFrameClientSizeAndViewport(*this);

      if (preferences != nullptr) {
        const wxSize clientSize = GetClientSize();
        preferences->SetInteger(fa::string(kSupComFrameWidthPreferenceKey), clientSize.x);
        preferences->SetInteger(fa::string(kSupComFrameHeightPreferenceKey), clientSize.y);
      }

      if (moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice(); d3dDevice != nullptr) {
        (void)d3dDevice->Clear2(false);
      }

      mPendingMaximizeSync = 0;
    } else if (message == kSupComFrameMessageSize && wParam == SIZE_MAXIMIZED) {
      SyncSupComFrameClientSizeAndViewport(*this);
      if (preferences != nullptr) {
        preferences->SetBoolean(fa::string(kSupComFrameMaximizedPreferenceKey), true);
      }
      mPersistedMaximizeSync = 1;
    }

    if (mPendingMaximizeSync == 0 && message == kSupComFrameMessageSize) {
      if (wParam == SIZE_RESTORED && mPersistedMaximizeSync != 0) {
        SyncSupComFrameClientSizeAndViewport(*this);
        if (preferences != nullptr) {
          const wxSize clientSize = GetClientSize();
          preferences->SetInteger(fa::string(kSupComFrameWidthPreferenceKey), clientSize.x);
          preferences->SetInteger(fa::string(kSupComFrameHeightPreferenceKey), clientSize.y);
          preferences->SetBoolean(fa::string(kSupComFrameMaximizedPreferenceKey), false);
        }
        mPersistedMaximizeSync = 0;
      }

      return dispatchBase();
    }
  }

  if (message == kSupComFrameMessageActivateApp) {
    const bool isActive = wParam != 0;
    mIsApplicationActive = isActive ? 1 : 0;
    if (isActive) {
      UpdateSupComCursorClipForActivation();
    } else {
      ::ClipCursor(nullptr);
    }
    return dispatchBase();
  }

  if (message != kSupComFrameMessageSysCommand) {
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandToggleLogDialog) {
    moho::CON_Execute(kSupComFrameToggleLogDialogCommand);
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandLuaDebugger) {
    moho::CON_Execute(kSupComFrameLuaDebuggerCommand);
    return dispatchBase();
  }

  if (wParam != kSupComFrameSysCommandKeyMenu) {
    return dispatchBase();
  }

  gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
  if (galDevice == nullptr) {
    return dispatchBase();
  }

  gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
  if (activeContext == nullptr || activeContext->GetHeadCount() <= 0 || !activeContext->GetHead(0).mWindowed) {
    return dispatchBase();
  }

  return 0;
}
