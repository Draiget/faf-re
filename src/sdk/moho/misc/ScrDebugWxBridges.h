#pragma once

namespace moho::scrdebug
{
  /**
   * Trampolines into the statically-linked wxWidgets-2.4.2 library for the
   * script debug window.
   *
   * `ScrDebugWindow.cpp` and `ScrWatchCtrl.cpp` cannot include the real wx
   * headers: those redeclare `wxPoint` / `wxSize` / `wxEventTable` at global
   * scope and collide with this project's reconstructions of the same names.
   * The bridges were therefore declared there with no definition anywhere, and
   * being in an anonymous namespace they could not be defined in another
   * translation unit either. `main.vcxproj` links with `/FORCE`, so each one
   * resolved to RVA 0 and would have jumped to the image base the first time
   * the debug window was opened - the same failure the frame-probe hooks hit
   * in 2a63b8be.
   *
   * The way out is this header: every signature is opaque (`void*`, integers,
   * plain `wchar_t` strings) and it pulls in no project type at all, so
   * `ScrDebugWxBridges.cpp` can include the real wx headers and nothing else,
   * while the callers keep including only their own.
   *
   * The constructors allocate for themselves. The shipped binary split
   * allocation from construction and the call sites carried its byte counts
   * (0x74 wxMenu, 0x160 wxMenuBar, 0x1A4 wxSplitterWindow, ...), but a
   * static_assert showed sizeof(wxMenuItem) in this vendored wx build already
   * exceeds the 0x74 it was given - those numbers describe the wx Gas Powered
   * Games linked, not the one we link, and reusing them was a heap overflow.
   *
   * Each entry cites the wx library body its call site dispatches to, read
   * from the disassembly of `ScrDebugWindow`'s constructor (`FUN_004BC110`).
   */

  /** Address: 0x00998B90 (??0wxMenuBar@@QAE@Z, wxMenuBar::wxMenuBar) */
  void* ConstructWxMenuBar();

  /** Address: 0x009A9570 (?SetMenuBar@wxFrameBase@@UAEXPAVwxMenuBar@@@Z) */
  void SetFrameMenuBar(void* frameThis, void* menuBar);

  /** Address: 0x004BB050 (??0wxMenu@@QAE@@Z, wxMenu::wxMenu) */
  void* ConstructWxMenu();

  /** wxMenu::Append(wxMenuItem*) - vtable dispatch at the call site. */
  void AppendWxMenuItem(void* menu, void* menuItem);

  /** Address: 0x004BAF20 (wxMenu::AppendSeparator) */
  void AppendWxMenuSeparator(void* menu);

  /** wxToolBar::AddSeparator() - vtable dispatch (+0x228) at the call site. */
  void AddToolBarSeparator(void* toolbar);

  /** wxToolBar::Realize() - vtable dispatch (+0x240) at the call site. */
  void RealizeToolBar(void* toolbar);

  /** Address: 0x00975B00 (??1wxBitmap@@UAE@XZ, wxBitmap::~wxBitmap) */
  void DestroyWxBitmap(void* bitmap);

  /** wxSplitterWindow::SplitVertically(wxWindow*, wxWindow*, int) - vtable dispatch (+0x20C). */
  bool SplitWxSplitterWindowVertically(void* splitter, void* leftPane, void* rightPane, int sashPosition);

  // The wx string/geometry types cannot cross this boundary either, so these
  // take plain `wchar_t` text and loose integers and rebuild wxString /
  // wxPoint / wxSize on the far side. `wxStringRuntime` is a single
  // `wchar_t* m_pchData` - wx 2.4.2's own wxString layout - so nothing is
  // lost in the narrowing.

  /** Address: 0x009A6240 (??2wxMenuItem@@QAE@@Z, wxMenuItem::wxMenuItem) */
  void* ConstructWxMenuItem(
    void* parentMenu,
    int id,
    const wchar_t* text,
    const wchar_t* helpString,
    bool isCheckable,
    void* subMenu
  );

  /** wxMenuBar::Append(wxMenu*, const wxString&) - vtable dispatch at the call site. */
  void AppendWxMenuBarMenu(void* menuBar, void* menu, const wchar_t* title);

  /** Address: 0x0099EE20 (?CreateToolBar@wxFrame@@UAEPAVwxToolBar@@JHABVwxString@@@Z) */
  void* CreateFrameToolBar(void* frameThis, int style, int id, const wchar_t* name);

  /** Address: 0x004BB2D0 (wxToolBarBase::AddTool convenience overload) */
  void AddToolBarTool(void* toolbar, int id, const wchar_t* label, void* bitmap, const wchar_t* shortHelp);

  /** Address: 0x00977BF0 (wxBitmap::wxBitmap(const wxString&, wxBitmapType)) */
  void* ConstructWxBitmapFromFile(const wchar_t* path, int type);

  /** Address: 0x004BB380 (wxSplitterWindow::wxSplitterWindow) */
  void* ConstructWxSplitterWindow(void* parent, int id, const wchar_t* name);

  /** Address: 0x004BB4A0 (wxGenericDirCtrl::wxGenericDirCtrl) */
  void* ConstructWxGenericDirCtrl(
    void* parent,
    const wchar_t* defaultPath,
    const wchar_t* filter,
    const wchar_t* name
  );

  /**
   * Address: 0x004BE56E-0x004BE57E (wxGenericDirCtrl::GetTreeCtrl, vtable
   * slot +0x250, then the returned control's window id at +0x28)
   *
   * The id the debug window's tree-activation binding matches on: the events
   * are raised by the dir control's inner wxTreeCtrl, not by the dir control
   * itself, so the binding names the inner control's id.
   */
  int GetWxGenericDirCtrlTreeControlId(void* dirCtrl);

  /** Address: 0x009A7740 (wxNotebook::wxNotebook) */
  void* ConstructWxNotebook(
    void* parent,
    int id,
    int x,
    int y,
    int width,
    int height,
    int style,
    const wchar_t* name
  );

  /** wxNotebook::AddPage(wxWindow*, const wxString&, bool, int) - vtable dispatch. */
  void AddNotebookPage(void* notebook, void* page, const wchar_t* title, bool select, int imageId);

  /** wxListCtrl::wxListCtrl(parent, id, pos, size, style, validator, name) */
  void* ConstructWxListCtrl(
    void* parent,
    int id,
    int x,
    int y,
    int width,
    int height,
    int style,
    const wchar_t* name
  );

  /**
   * Address: 0x00974B50 (wxAcceleratorTable::wxAcceleratorTable(int, const
   * wxAcceleratorEntry*)), which builds the `ACCEL` array
   * (`operator new(6 * cAccel)` at 0x00974B92), maps each entry's modifier
   * bits to FALT/FSHIFT/FCONTROL|FVIRTKEY (0x00974BAB..0x00974BBC), calls
   * `wxCharCodeWXToMSW` per key (0x00974BD1) and hands the result to
   * `CreateAcceleratorTable` (0x00974C0E).
   *
   * `entries` points at an array of `wxAcceleratorEntry`: {flags, keyCode,
   * command, menuItem}, four words per entry.
   */
  void* ConstructWxAcceleratorTable(int entryCount, const void* entries);

  /**
   * Address: 0x00974AB0 (wxAcceleratorTable::~wxAcceleratorTable), which
   * tail-calls `wxObject::UnRef` (0x00977F40); the last reference destroys the
   * ref-data block and with it the `HACCEL`.
   */
  void DestroyWxAcceleratorTable(void* acceleratorTable);
} // namespace moho::scrdebug
