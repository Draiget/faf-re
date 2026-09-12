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
#include <wx/notebook.h>
#include <wx/listctrl.h>
#include <wx/dirctrl.h>
#include <wx/bitmap.h>

// wx/memory.h does `#define new WXDEBUG_NEW` whenever __WXDEBUG__ is on, which
// _DEBUG turns on for us (wx/debug.h:26) even though the shipped game linked wx
// with it off. That macro rewrites the placement-new below into a three-argument
// call that has no overload, and rewrites plain `new` into wx's debug
// allocator. Drop it; this file wants the real operator.
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
   * The binary split allocation from construction and its call site passed in
   * `operator new(0x160)`; that byte count is not this wx build's, so the
   * allocation lives here instead. See the header.
   */
  void* ConstructWxMenuBar()
  {
    return new wxMenuBar();
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
   */
  void* ConstructWxMenu()
  {
    return new wxMenu();
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
   * Paired with ConstructWxBitmapFromFile, which allocates - so this deletes.
   */
  void DestroyWxBitmap(void* const bitmap)
  {
    if (bitmap == nullptr) {
      return;
    }

    delete static_cast<wxBitmap*>(bitmap);
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

  /** Address: 0x009A6240 (??2wxMenuItem@@QAE@@Z, wxMenuItem::wxMenuItem) */
  void* ConstructWxMenuItem(
    void* const parentMenu,
    const int id,
    const wchar_t* const text,
    const wchar_t* const helpString,
    const bool isCheckable,
    void* const subMenu
  )
  {
    const wxString text_(text != nullptr ? text : L"");
    const wxString helpString_(helpString != nullptr ? helpString : L"");
    return new wxMenuItem(
      static_cast<wxMenu*>(parentMenu), id, text_, helpString_,
      isCheckable ? wxITEM_CHECK : wxITEM_NORMAL, static_cast<wxMenu*>(subMenu)
    );
  }

  /** wxMenuBar::Append(wxMenu*, const wxString&) */
  void AppendWxMenuBarMenu(void* const menuBar, void* const menu, const wchar_t* const title)
  {
    if (menuBar == nullptr || menu == nullptr) {
      return;
    }

    const wxString title_(title != nullptr ? title : L"");
    (void)static_cast<wxMenuBar*>(menuBar)->Append(static_cast<wxMenu*>(menu), title_);
  }

  /** Address: 0x0099EE20 (?CreateToolBar@wxFrame@@UAEPAVwxToolBar@@JHABVwxString@@@Z) */
  void* CreateFrameToolBar(void* const frameThis, const int style, const int id, const wchar_t* const name)
  {
    if (frameThis == nullptr) {
      return nullptr;
    }

    const wxString name_(name != nullptr ? name : wxToolBarNameStr);
    return static_cast<wxFrame*>(frameThis)->CreateToolBar(static_cast<long>(style), id, name_);
  }

  /** Address: 0x004BB2D0 (wxToolBarBase::AddTool convenience overload) */
  void AddToolBarTool(
    void* const toolbar,
    const int id,
    const wchar_t* const label,
    void* const bitmap,
    const wchar_t* const shortHelp
  )
  {
    if (toolbar == nullptr || bitmap == nullptr) {
      return;
    }

    const wxString label_(label != nullptr ? label : L"");
    const wxString shortHelp_(shortHelp != nullptr ? shortHelp : L"");
    (void)static_cast<wxToolBar*>(toolbar)->AddTool(
      id, label_, *static_cast<wxBitmap*>(bitmap), shortHelp_
    );
  }

  /** Address: 0x00977BF0 (wxBitmap::wxBitmap(const wxString&, wxBitmapType)) */
  void* ConstructWxBitmapFromFile(const wchar_t* const path, const int type)
  {
    const wxString path_(path != nullptr ? path : L"");
    return new wxBitmap(path_, static_cast<wxBitmapType>(type));
  }

  /** Address: 0x004BB380 (wxSplitterWindow::wxSplitterWindow) */
  void* ConstructWxSplitterWindow(void* const parent, const int id, const wchar_t* const name)
  {
    const wxString name_(name != nullptr ? name : L"splitterWindow");
    return new wxSplitterWindow(
      static_cast<wxWindow*>(parent), id, wxDefaultPosition, wxDefaultSize, wxSP_3D, name_
    );
  }

  /** Address: 0x004BB4A0 (wxGenericDirCtrl::wxGenericDirCtrl) */
  void* ConstructWxGenericDirCtrl(
    void* const parent,
    const wchar_t* const defaultPath,
    const wchar_t* const filter,
    const wchar_t* const name
  )
  {
    const wxString defaultPath_(defaultPath != nullptr ? defaultPath : L"");
    const wxString filter_(filter != nullptr ? filter : L"");
    const wxString name_(name != nullptr ? name : wxTreeCtrlNameStr);
    return new wxGenericDirCtrl(
      static_cast<wxWindow*>(parent), wxID_ANY, defaultPath_, wxDefaultPosition, wxDefaultSize,
      wxDIRCTRL_3D_INTERNAL, filter_, 0, name_
    );
  }

  /** Address: 0x009A7740 (wxNotebook::wxNotebook) */
  void* ConstructWxNotebook(
    void* const parent,
    const int id,
    const int x,
    const int y,
    const int width,
    const int height,
    const int style,
    const wchar_t* const name
  )
  {
    const wxString name_(name != nullptr ? name : L"notebook");
    return new wxNotebook(
      static_cast<wxWindow*>(parent), id, wxPoint(x, y), wxSize(width, height),
      static_cast<long>(style), name_
    );
  }

  /** wxNotebook::AddPage(wxWindow*, const wxString&, bool, int) */
  void AddNotebookPage(
    void* const notebook,
    void* const page,
    const wchar_t* const title,
    const bool select,
    const int imageId
  )
  {
    if (notebook == nullptr || page == nullptr) {
      return;
    }

    const wxString title_(title != nullptr ? title : L"");
    (void)static_cast<wxNotebook*>(notebook)->AddPage(
      static_cast<wxWindow*>(page), title_, select, imageId
    );
  }

  /** wxListCtrl::wxListCtrl(parent, id, pos, size, style, validator, name) */
  void* ConstructWxListCtrl(
    void* const parent,
    const int id,
    const int x,
    const int y,
    const int width,
    const int height,
    const int style,
    const wchar_t* const name
  )
  {
    const wxString name_(name != nullptr ? name : L"listCtrl");
    return new wxListCtrl(
      static_cast<wxWindow*>(parent), id, wxPoint(x, y), wxSize(width, height),
      static_cast<long>(style), wxDefaultValidator, name_
    );
  }
} // namespace moho::scrdebug
