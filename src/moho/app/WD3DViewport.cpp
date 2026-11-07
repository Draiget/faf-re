#include "moho/app/WxPrivate.h"
#include "moho/app/NetworkPanel.h"


// ---------------------------------------------------------------------------
// WD3DViewport
// ---------------------------------------------------------------------------

BEGIN_EVENT_TABLE(moho::WD3DViewport, wxWindow)
  EVT_PAINT(moho::WD3DViewport::OnPaint)
  EVT_ERASE_BACKGROUND(moho::WD3DViewport::OnEraseBackground)
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
void moho::WD3DViewport::D3DWindowOnDeviceInit(const bool createBatchers)
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
void moho::WD3DViewport::D3DWindowOnDeviceExit(const bool fullShutdown)
{
  (void)fullShutdown;
}

/**
 * Address: 0x0042BB20 (FUN_0042BB20)
 */
void moho::WD3DViewport::RenderPreviewImage(const bool forceRegenerate)
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
void moho::WD3DViewport::DrawBackgroundImage(wxDC& dc)
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
void moho::WD3DViewport::OnEraseBackground(wxEraseEvent& event)
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
void moho::WD3DViewport::OnPaint(wxPaintEvent& event)
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
  constexpr std::uint16_t kClientHitTestCode = HTCLIENT;
}


/**
 * Address: 0x00430B90 (FUN_00430B90)
 * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
 *
 * What it does:
 * Takes WM_SETCURSOR over the client area: with d3d_WindowsCursor the device
 * shows its own cursor once its pixels are ready; otherwise the Win32 cursor
 * is cleared first. Every other message goes to wxWindow::MSWWindowProc (the
 * FAF-patched image routes that call through a hook at 0x01291029).
 */
long moho::WD3DViewport::MSWWindowProc(
  const WXUINT message,
  const WXWPARAM wParam,
  const WXLPARAM lParam
)
{
  CD3DDevice* const device = D3D_GetDevice();
  if (device != nullptr) {
    const bool setCursorMessage = message == WM_SETCURSOR;
    const bool clientHit = static_cast<std::uint16_t>(lParam & 0xFFFF) == kClientHitTestCode;

    if (d3d_WindowsCursor) {
      if (setCursorMessage && clientHit && device->IsCursorPixelSourceReady()) {
        D3D_InitCursor();
        (void)device->ShowCursor(device->IsCursorShowing());
        return 1;
      }
    } else if (setCursorMessage && clientHit && (device->IsCursorPixelSourceReady() || !device->IsCursorShowing())) {
      ::SetCursor(nullptr);
      D3D_InitCursor();
      (void)device->ShowCursor(device->IsCursorShowing());
      return 1;
    }
  }

  // Engine addition (issue #322): Ctrl+Shift+F11 flips the network panel, here so it works
  // in the lobby, in a game and in fullscreen without the Lua key map. F11 alone is FAF's
  // connectivity screen. Only the first press of a held key counts (lParam bit 30).
  if (message == WM_KEYDOWN && wParam == VK_F11 && (lParam & 0x40000000) == 0 &&
      (::GetKeyState(VK_CONTROL) & 0x8000) != 0 && (::GetKeyState(VK_SHIFT) & 0x8000) != 0) {
    NETPANEL_Toggle();
    return 0;
  }

  // Engine addition (issue #322): presses on the open network panel go to the panel, with
  // the release that ends them; the game never sees them. Moves still reach the game.
  if ((message >= WM_MOUSEMOVE && message <= WM_MBUTTONDBLCLK) || message == WM_MOUSEWHEEL) {
    const HWND window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(GetHandle()));
    POINT at{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
    if (message == WM_MOUSEWHEEL) {
      ::ScreenToClient(window, &at); // the wheel's position is on the screen
    }
    RECT client{};
    ::GetClientRect(window, &client);
    const int wheel = message == WM_MOUSEWHEEL ? static_cast<short>(HIWORD(wParam)) : 0;
    if (NETPANEL_OnMouse(window, message, at.x, at.y, client.right, client.bottom, wheel)) {
      return 0;
    }
  }

  // FAF hot-patch (FA-Binary-Patches OnWindowMessage): 0x00430C0E calls 0x01291029 instead of
  // wxWindow::MSWWindowProc, which hands the side mouse buttons to wx as key presses of
  // VK_XBUTTON1/VK_XBUTTON2, so they can be bound like keys. lParam: repeat count 1, scan
  // code 0xFF, and for the release the previous-state and transition bits.
  if (message == WM_XBUTTONDOWN || message == WM_XBUTTONUP) {
    const bool pressed = message == WM_XBUTTONDOWN;
    const WXWPARAM virtualKey = static_cast<WXWPARAM>(HIWORD(wParam)) + 4u;
    const WXLPARAM keyInfo = static_cast<WXLPARAM>(pressed ? 0x00FF0001u : 0xC0FF0001u);
    return wxWindow::MSWWindowProc(pressed ? WM_KEYDOWN : WM_KEYUP, virtualKey, keyInfo);
  }

  return wxWindow::MSWWindowProc(message, wParam, lParam);
}
