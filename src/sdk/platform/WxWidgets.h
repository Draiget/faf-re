#pragma once

/**
 * Configures wxWidgets 2.4.2 for the engine. Include this before any wx header,
 * then include the wx headers the file uses.
 *
 * The engine links the real library: `dependencies/wxWindows-2.4.2/lib/wxmswu.lib`,
 * a static Unicode build made with `nmake FINAL=1` (see
 * `docker/scripts/Build-Deps.ps1`). Every class the shipped binary allocates or
 * derives from has the same size in those headers as in the binary: wxFrame
 * 0x178 and wxDialog 0x170 (WeakObject sits right after them in
 * WWinManagedFrame / WWinManagedDialog), wxPanel 0x134, wxNotebook 0x148,
 * wxMenu 0x74, wxMenuBar 0x160, wxSplitterWindow 0x1A4, wxEvent 0x20,
 * wxCommandEvent 0x34, wxTreeItemData 0x08, wxColourDatabase 0x1C.
 *
 * FINAL=1 means the library was compiled without `__WXDEBUG__`, and a Debug
 * engine TU has to see the headers the same way. `wx/debug.h` turns `_DEBUG`
 * into `__WXDEBUG__`, which changes three things the library never agreed to:
 *
 *   - `wxAppBase` gains `virtual OnAssert`, so every vtable from wxApp down
 *     (MohoApp included) would be one slot off from the one the library
 *     dispatches through;
 *   - `wxASSERT` and friends expand to calls of `wxAssert`, which a FINAL
 *     library does not define - under /FORCE that links as a call to address 0;
 *   - `wx/memory.h` redefines `new` as `WXDEBUG_NEW`.
 *
 * Class sizes are the same either way; it is the vtable and the calls that
 * differ. `wx/debug.h` honours `NDEBUG` over `_DEBUG`, so NDEBUG is held while
 * `wx/defs.h` (which includes `wx/debug.h`) is read, and `assert()` is re-armed
 * afterwards. The check at the bottom catches a TU that reached a wx header some
 * other way first.
 */

#if defined(_DEBUG) && !defined(NDEBUG)
  #define MOHO_WX_HELD_NDEBUG
  #define NDEBUG
#endif

#include <wx/defs.h>

#ifdef MOHO_WX_HELD_NDEBUG
  #undef NDEBUG
  #undef MOHO_WX_HELD_NDEBUG
  // wx/debug.h included <assert.h> while NDEBUG was held; this re-evaluates it.
  #include <assert.h>
#endif

#ifdef __WXDEBUG__
  #error "a wx header was read in __WXDEBUG__ mode before platform/WxWidgets.h - include it first; wxmswu.lib is a FINAL build"
#endif
