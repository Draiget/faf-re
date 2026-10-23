#pragma once

#include <cstddef>

#include "platform/WxWidgets.h"

#include <wx/event.h>
#include <wx/window.h>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"

class wxBitmap;
class wxDC;

namespace moho
{
  class CD3DPrimBatcher;
  class ID3DTextureSheet;

  /**
   * The wx window the D3D device presents into.
   *
   * vftable 0x00E01FDC: wxWindow's 131 slots, then the six device hooks this
   * class adds (slots 131-136), whose bodies here are all empty defaults -
   * `WRenViewport` is the viewport that overrides them. Slot 124 is its own
   * `MSWWindowProc`; slot 6 is the `GetEventTable` DECLARE_EVENT_TABLE emits
   * (0x00430970, table 0x00DFFC84 = {&wxWindow::sm_eventTable, rows
   * 0x00F59078}).
   *
   * sizeof 0x128: wxWindow is 0x124, and the one member this class adds sits
   * right after it.
   */
  class WD3DViewport : public wxWindow
  {
  public:
    /**
     * Address: 0x00430980 (FUN_00430980)
     * Mangled: ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
     *
     * What it does:
     * Creates the native window: `wxWindow(parent, -1, wxDefaultPosition, size,
     * 0, name)`, the name being `title` widened from UTF-8. The position
     * argument is not used - the binary pushes wxDefaultPosition (0x00F33E00)
     * whatever the caller passes.
     */
    WD3DViewport(wxWindow* parent, gpg::StrArg title, const wxPoint& position, const wxSize& size);

    /**
     * Address: 0x0042BA90 (FUN_0042BA90)
     * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
     *
     * What it does:
     * Deletes the background image, if any, then runs `wxWindow::~wxWindow`
     * (0x0096BF40). The scalar deleting destructor at 0x0042BB60 is the
     * compiler's.
     */
    ~WD3DViewport() override;

    /**
     * Address: 0x0042BAF0 (FUN_0042BAF0)
     * Mangled: ?D3DWindowOnDeviceInit@WD3DViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * Nothing. Slot 131: `CD3DDevice::SetRenViewport` and `InitContext` call
     * it after the device (re)binds this window.
     */
    virtual void D3DWindowOnDeviceInit(bool createBatchers);

    /**
     * Address: 0x0042BB00 (FUN_0042BB00)
     * Mangled: ?D3DWindowOnDeviceRender@WD3DViewport@Moho@@UAEXXZ
     *
     * What it does:
     * Nothing. Slot 132: `CD3DDevice::Paint` calls it once per presented frame.
     */
    virtual void D3DWindowOnDeviceRender();

    /**
     * Address: 0x0042BB10 (FUN_0042BB10)
     * Mangled: ?D3DWindowOnDeviceExit@WD3DViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * Nothing. Slot 133: `CD3DDevice::InitContext` and `Destroy` call it
     * before the device releases its resources.
     */
    virtual void D3DWindowOnDeviceExit(bool fullShutdown);

    /**
     * Address: 0x0042BB20 (FUN_0042BB20)
     * Mangled: ?RenderPreviewImage@WD3DViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * Nothing (`retn 4`). Slot 134.
     */
    virtual void RenderPreviewImage(bool forceRegenerate);

    /**
     * Address: 0x0042BB30 (FUN_0042BB30)
     * Mangled: ?GetPreviewImage@WD3DViewport@Moho@@UAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
     *
     * What it does:
     * Returns an empty sheet. Slot 135.
     */
    virtual boost::shared_ptr<ID3DTextureSheet> GetPreviewImage();

    /**
     * Address: 0x0042BB50 (FUN_0042BB50)
     * Mangled: ?GetPrimBatcher@WD3DViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ
     *
     * What it does:
     * Returns null. Slot 136.
     */
    virtual CD3DPrimBatcher* GetPrimBatcher() const;

    /**
     * Address: 0x00430B90 (FUN_00430B90)
     * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
     *
     * What it does:
     * Answers WM_SETCURSOR over the client area itself, handing the cursor to
     * the D3D device; every other message goes to `wxWindow::MSWWindowProc`.
     */
    long MSWWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam) override;

    /**
     * Address: 0x00430AC0 (FUN_00430AC0)
     * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
     *
     * What it does:
     * Opens a wxPaintDC (0x0097E220) - which validates the update region - and
     * then either lets the D3D device present, dropping the background image,
     * or paints the background itself while there is no device yet.
     */
    void OnPaint(wxPaintEvent& event);

    /**
     * Address: 0x00430B70 (FUN_00430B70)
     *
     * What it does:
     * Paints the background on WM_ERASEBKGND until the device is presenting;
     * after that, erasing underneath it would only flicker.
     */
    void OnEraseBackground(wxEraseEvent& event);

  private:
    /**
     * Address: 0x00430A60 (FUN_00430A60)
     * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
     *
     * What it does:
     * Fills the DC's extent with wxBLACK_BRUSH, then selects wxNullBrush back.
     * The body never touches `this` - the binary passes the DC in esi.
     */
    void DrawBackgroundImage(wxDC& dc);

  public:
    // +0x124. Owned: the destructor deletes it, and OnPaint deletes and clears
    // it once the device is presenting (load, store 0, then the virtual
    // deleting destructor - slot 1, which makes it a wxObject). The binary
    // only ever stores 0 here; the type is inferred from DrawBackgroundImage's
    // name, which is what would have drawn it.
    wxBitmap* mBackgroundImage;

    DECLARE_EVENT_TABLE()
  };

  static_assert(sizeof(wxWindow) == 0x124, "wxWindow size must be 0x124");
  static_assert(
    offsetof(WD3DViewport, mBackgroundImage) == 0x124, "moho::WD3DViewport::mBackgroundImage offset must be 0x124"
  );
  static_assert(sizeof(WD3DViewport) == 0x128, "moho::WD3DViewport size must be 0x128");
} // namespace moho
