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
   * Each entry cites the wx library body its call site dispatches to, read
   * from the disassembly of `ScrDebugWindow`'s constructor (`FUN_004BC110`).
   */

  /** Address: 0x00998B90 (??0wxMenuBar@@QAE@Z, wxMenuBar::wxMenuBar) */
  void* ConstructWxMenuBar(void* storage);

  /** Address: 0x009A9570 (?SetMenuBar@wxFrameBase@@UAEXPAVwxMenuBar@@@Z) */
  void SetFrameMenuBar(void* frameThis, void* menuBar);

  /** Address: 0x004BB050 (??0wxMenu@@QAE@@Z, wxMenu::wxMenu) */
  void* ConstructWxMenu(void* storage);

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
} // namespace moho::scrdebug
