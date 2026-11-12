#include "moho/app/WxPrivate.h"
#include "moho/app/NetworkPanel.h"
#include "platform/Window.h"

#include <cmath>

// ---------------------------------------------------------------------------
// WD3DViewport
// ---------------------------------------------------------------------------

BEGIN_EVENT_TABLE(
  moho::WD3DViewport,
  wxWindow
)
EVT_PAINT(
  moho::WD3DViewport::OnPaint
)
EVT_ERASE_BACKGROUND(
  moho::WD3DViewport::OnEraseBackground
)
END_EVENT_TABLE()

/**
 * Address: 0x00430980 (FUN_00430980)
 * Mangled: ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
 *
 * What it does:
 * Creates the native window over `parent` - the name is the title widened
 * from UTF-8 (gpg::STR_Utf8ToWide, 0x00938720) - and starts without a
 * background image. The binary passes wxDefaultPosition, not `position`.
 */
moho::WD3DViewport::WD3DViewport(
  wxWindow* const parent,
  const gpg::StrArg title,
  const wxPoint& position,
  const wxSize& size
)
  : wxWindow(parent, -1, wxDefaultPosition, size, 0, gpg::STR_Utf8ToWide(title).c_str())
  , mBackgroundImage(nullptr)
{
  (void)position;
  InstallWindowHooks();
}

/**
 * Address: 0x0042BA90 (FUN_0042BA90)
 * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
 *
 * What it does:
 * Deletes the background image, then ~wxWindow (0x0096BF40).
 */
moho::WD3DViewport::~WD3DViewport()
{
  delete mBackgroundImage;
}

/**
 * Address: 0x0042BAF0 (FUN_0042BAF0)
 */
void moho::WD3DViewport::D3DWindowOnDeviceInit(
  const bool createBatchers
)
{
  (void)createBatchers;
}

/**
 * Address: 0x0042BB00 (FUN_0042BB00)
 */
void moho::WD3DViewport::D3DWindowOnDeviceRender() {}

/**
 * Address: 0x0042BB10 (FUN_0042BB10)
 */
void moho::WD3DViewport::D3DWindowOnDeviceExit(
  const bool fullShutdown
)
{
  (void)fullShutdown;
}

/**
 * Address: 0x0042BB20 (FUN_0042BB20)
 */
void moho::WD3DViewport::RenderPreviewImage(
  const bool forceRegenerate
)
{
  (void)forceRegenerate;
}

/**
 * Address: 0x0042BB30 (FUN_0042BB30)
 */
boost::shared_ptr<moho::ID3DTextureSheet> moho::WD3DViewport::GetPreviewImage()
{
  return {};
}

/**
 * Address: 0x0042BB50 (FUN_0042BB50)
 */
moho::CD3DPrimBatcher* moho::WD3DViewport::GetPrimBatcher() const
{
  return nullptr;
}

/**
 * Address: 0x00430A60 (FUN_00430A60)
 * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
 *
 * What it does:
 * SetBrush(wxBLACK_BRUSH), fill the DC's extent, SetBrush(wxNullBrush).
 */
void moho::WD3DViewport::DrawBackgroundImage(
  wxDC& dc
)
{
  int width = 0;
  int height = 0;
  dc.SetBrush(*wxBLACK_BRUSH);
  dc.GetSize(&width, &height);
  dc.DrawRectangle(0, 0, width, height);
  dc.SetBrush(wxNullBrush);
}

/**
 * Address: 0x00430B70 (FUN_00430B70)
 *
 * What it does:
 * Paints the background on WM_ERASEBKGND while there is no device, or while
 * the device asks for it; once it presents, erasing would only flicker.
 */
void moho::WD3DViewport::OnEraseBackground(
  wxEraseEvent& event
)
{
  CD3DDevice* const device = D3D_GetDevice();
  if (device != nullptr && !device->ShouldDrawViewportBackground()) {
    return;
  }

  DrawBackgroundImage(*event.GetDC());
}

/**
 * Address: 0x00430AC0 (FUN_00430AC0)
 * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
 *
 * What it does:
 * The wxPaintDC validates the update region whatever happens next; then the
 * device presents - the background image is no longer needed - or, without
 * one, the background is painted by hand.
 */
void moho::WD3DViewport::OnPaint(
  wxPaintEvent& event
)
{
  (void)event;
  wxPaintDC dc(this);

  CD3DDevice* const device = D3D_GetDevice();
  if (gpg::gal::Device::IsReady() && device != nullptr) {
    wxBitmap* const image = mBackgroundImage;
    mBackgroundImage = nullptr;
    delete image;
    device->Paint();
    return;
  }

  DrawBackgroundImage(dc);
}

void moho::WD3DViewport::PaintWithoutMessage()
{
  wxBitmap* const image = mBackgroundImage;
  mBackgroundImage = nullptr;
  delete image;
  D3D_GetDevice()->Paint();
}

namespace
{
  /**
   * Address: 0x00430B90 (FUN_00430B90, WD3DViewport::MSWWindowProc), its WM_SETCURSOR half.
   *
   * The window system asks for the cursor over the client area (WindowSdlWindows.cpp passes
   * WM_SETCURSOR with HTCLIENT here): with d3d_WindowsCursor the device shows its own cursor once
   * its pixels are ready; otherwise the system cursor is cleared first, for Direct3D 9's
   * hardware cursor.
   */
  bool ViewportCursorRequest(
    platform::window::Handle const window
  )
  {
    (void)window;
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return false;
    }
    if (moho::d3d_WindowsCursor) {
      if (device->IsCursorPixelSourceReady()) {
        moho::D3D_InitCursor();
        (void)device->ShowCursor(device->IsCursorShowing());
        return true;
      }
      return false;
    }
    if (device->IsCursorPixelSourceReady() || !device->IsCursorShowing()) {
      ::SetCursor(nullptr);
      moho::D3D_InitCursor();
      (void)device->ShowCursor(device->IsCursorShowing());
      return true;
    }
    return false;
  }

  // The window procedure's mouse messages, for the network panel (NetworkPanel.h).
  [[nodiscard]] unsigned MouseMessageOf(
    const platform::window::Event& event
  )
  {
    using platform::window::EventType;
    const bool doubleClick = event.clicks >= 2;
    switch (event.type) {
    case EventType::MouseMove:
      return WM_MOUSEMOVE;
    case EventType::MouseWheel:
      return WM_MOUSEWHEEL;
    case EventType::MouseDown:
      switch (event.button) {
      case platform::window::kButtonLeft:
        return doubleClick ? WM_LBUTTONDBLCLK : WM_LBUTTONDOWN;
      case platform::window::kButtonMiddle:
        return doubleClick ? WM_MBUTTONDBLCLK : WM_MBUTTONDOWN;
      case platform::window::kButtonRight:
        return doubleClick ? WM_RBUTTONDBLCLK : WM_RBUTTONDOWN;
      default:
        return 0;
      }
    case EventType::MouseUp:
      switch (event.button) {
      case platform::window::kButtonLeft:
        return WM_LBUTTONUP;
      case platform::window::kButtonMiddle:
        return WM_MBUTTONUP;
      case platform::window::kButtonRight:
        return WM_RBUTTONUP;
      default:
        return 0;
      }
    default:
      return 0;
    }
  }

  /**
   * The rest of WD3DViewport::MSWWindowProc (0x00430B90): what the game window's events meet
   * before the UI does.
   */
  bool ViewportEventFilter(
    const platform::window::Event& event
  )
  {
    using platform::window::EventType;
    if (moho::sMainWindow == nullptr || event.window != moho::sMainWindow->GetPlatformWindow()) {
      return false;
    }

    // Engine addition (issue #322): Ctrl+Shift+F11 flips the network panel, here so it works
    // in the lobby, in a game and in fullscreen without the Lua key map. F11 alone is FAF's
    // connectivity screen. Only the first press of a held key counts.
    if (
      event.type == EventType::KeyDown && event.virtualKey == VK_F11 && !event.repeat &&
      (event.modifiers & platform::window::kModifierControl) != 0 &&
      (event.modifiers & platform::window::kModifierShift) != 0
    ) {
      moho::NETPANEL_Toggle();
      return true;
    }

    // Engine addition (issue #322): presses on the open network panel go to the panel, with
    // the release that ends them; the game never sees them. Moves still reach the game.
    if (const unsigned message = MouseMessageOf(event); message != 0) {
      int clientWidth = 0;
      int clientHeight = 0;
      platform::window::GetBounds(event.window, nullptr, nullptr, &clientWidth, &clientHeight);
      const int wheel = event.type == EventType::MouseWheel ? static_cast<int>(std::lround(event.wheel * 120.0f)) : 0;
      return moho::NETPANEL_OnMouse(
        platform::window::NativeHandle(event.window), message, event.x, event.y, clientWidth, clientHeight, wheel
      );
    }
    return false;
  }
} // namespace

/**
 * Engine addition (issue #407): the viewport's share of the retail window procedure goes to the
 * window system's cursor request and event filter (platform/Window.h), on every platform.
 */
void moho::WD3DViewport::InstallWindowHooks()
{
  platform::window::SetCursorRequestHandler(&ViewportCursorRequest);
  platform::window::SetEventFilter(&ViewportEventFilter);
}
