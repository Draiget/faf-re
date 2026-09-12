// The one translation unit in this tree that includes the real wxWidgets
// headers. Nothing from `src/sdk` may be included here beyond the bridge
// header itself: wx redeclares `wxPoint` / `wxSize` / `wxEventTable` at global
// scope, and this project reconstructs those same names, so pulling both into
// one TU does not compile. Keeping this file wx-only is what makes the bridges
// definable at all - see ScrDebugWxBridges.h for why they had no definition
// before.

#include <wx/wxprec.h>

#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif

#include <wx/frame.h>
#include <wx/menu.h>
#include <wx/splitter.h>
#include <wx/toolbar.h>

// wx/memory.h does `#define new WXDEBUG_NEW` whenever __WXDEBUG__ is on, which
// _DEBUG turns on for us (wx/debug.h:26) even though the shipped game linked wx
// with it off. That macro rewrites the placement-new below into a three-argument
// call that has no overload. Drop it; this file wants the real operator.
#ifdef new
#undef new
#endif

#include <new>

#include "moho/misc/ScrDebugWxBridges.h"

namespace moho::scrdebug
{
  /**
   * Address: 0x00998B90 (??0wxMenuBar@@QAE@Z, wxMenuBar::wxMenuBar)
   *
   * The call site allocates the storage itself - `operator new(0x160)` in
   * `ScrDebugWindow`'s constructor - and passes it in, matching the binary's
   * split of allocation from construction, so this placement-news into it.
   */
  void* ConstructWxMenuBar(void* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) wxMenuBar();
  }

  /**
   * Address: 0x009A9570 (?SetMenuBar@wxFrameBase@@UAEXPAVwxMenuBar@@@Z)
   *
   * Virtual on `wxFrameBase`; the debug window is a real `wxFrame` as far as
   * the library is concerned, so this dispatches through wx's own vtable
   * rather than an offset.
   */
  void SetFrameMenuBar(void* const frameThis, void* const menuBar)
  {
    if (frameThis == nullptr) {
      return;
    }

    static_cast<wxFrame*>(frameThis)->SetMenuBar(static_cast<wxMenuBar*>(menuBar));
  }

  /**
   * Address: 0x004BB050 (??0wxMenu@@QAE@@Z, wxMenu::wxMenu)
   *
   * Same split as the menu bar: the caller owns the 0x74-byte allocation.
   */
  void* ConstructWxMenu(void* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) wxMenu();
  }

  /** wxMenu::Append(wxMenuItem*) - a virtual on wxMenuBase. */
  void AppendWxMenuItem(void* const menu, void* const menuItem)
  {
    if (menu == nullptr || menuItem == nullptr) {
      return;
    }

    static_cast<wxMenu*>(menu)->Append(static_cast<wxMenuItem*>(menuItem));
  }

  /** Address: 0x004BAF20 (wxMenu::AppendSeparator) */
  void AppendWxMenuSeparator(void* const menu)
  {
    if (menu == nullptr) {
      return;
    }

    static_cast<wxMenu*>(menu)->AppendSeparator();
  }

  /** wxToolBar::AddSeparator() - vtable dispatch (+0x228) at the call site. */
  void AddToolBarSeparator(void* const toolbar)
  {
    if (toolbar == nullptr) {
      return;
    }

    static_cast<wxToolBar*>(toolbar)->AddSeparator();
  }

  /** wxToolBar::Realize() - vtable dispatch (+0x240) at the call site. */
  void RealizeToolBar(void* const toolbar)
  {
    if (toolbar == nullptr) {
      return;
    }

    (void)static_cast<wxToolBar*>(toolbar)->Realize();
  }

  /**
   * Address: 0x00975B00 (??1wxBitmap@@UAE@XZ, wxBitmap::~wxBitmap)
   *
   * Destroys without freeing: the call site builds its bitmap into storage it
   * owns, so the storage outlives this and is released by the caller.
   */
  void DestroyWxBitmap(void* const bitmap)
  {
    if (bitmap == nullptr) {
      return;
    }

    static_cast<wxBitmap*>(bitmap)->~wxBitmap();
  }

  /** wxSplitterWindow::SplitVertically(wxWindow*, wxWindow*, int) - virtual, +0x20C. */
  bool SplitWxSplitterWindowVertically(
    void* const splitter,
    void* const leftPane,
    void* const rightPane,
    const int sashPosition
  )
  {
    if (splitter == nullptr) {
      return false;
    }

    return static_cast<wxSplitterWindow*>(splitter)->SplitVertically(
      static_cast<wxWindow*>(leftPane), static_cast<wxWindow*>(rightPane), sashPosition
    );
  }
} // namespace moho::scrdebug
