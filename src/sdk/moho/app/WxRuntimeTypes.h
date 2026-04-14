#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "boost/mutex.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct _RTL_CRITICAL_SECTION;

/**
 * Minimal recovered wx runtime types used by app/sim loop code.
 *
 * These declarations keep recovered dependencies centralized so loop/shutdown
 * code can use typed members instead of local ad-hoc overlay structs.
 */

struct wxPoint
{
  std::int32_t x = 0;
  std::int32_t y = 0;
};

static_assert(sizeof(wxPoint) == 0x8, "wxPoint size must be 0x8");

struct wxSize
{
  std::int32_t x = 0;
  std::int32_t y = 0;
};

static_assert(sizeof(wxSize) == 0x8, "wxSize size must be 0x8");

struct wxStringRuntime;
struct wxColourRuntime;
class wxMoveEventRuntime;
class wxCursor;

/**
 * Address: 0x009ACE50 (FUN_009ACE50, wxENTER_CRIT_SECT)
 *
 * What it does:
 * Enters one Win32 critical-section lane.
 */
void wxENTER_CRIT_SECT(_RTL_CRITICAL_SECTION* criticalSection);

/**
 * Address: 0x009ACE60 (FUN_009ACE60, wxLEAVE_CRIT_SECT)
 *
 * What it does:
 * Leaves one Win32 critical-section lane.
 */
void wxLEAVE_CRIT_SECT(_RTL_CRITICAL_SECTION* criticalSection);

/**
 * Address: 0x009AD330 (FUN_009AD330, wxThread::IsMain)
 *
 * What it does:
 * Returns whether the current Win32 thread matches the stored wx main-thread id.
 */
[[nodiscard]] bool wxThreadIsMain();

/**
 * Address: 0x009AD660 (FUN_009AD660, wxGuiOwnedByMainThread)
 *
 * What it does:
 * Returns the wx GUI-ownership flag managed by the GUI mutex helpers.
 */
[[nodiscard]] bool wxGuiOwnedByMainThread();

/**
 * Address: 0x009AD670 (FUN_009AD670, wxWakeUpMainThread)
 *
 * What it does:
 * Posts one wake-up message (`WM_NULL`) to the stored wx main-thread id.
 */
[[nodiscard]] bool wxWakeUpMainThread();

/**
 * Address: 0x009ADC20 (FUN_009ADC20, wxMutexGuiLeave)
 *
 * What it does:
 * Releases GUI ownership for the calling lane and unlocks wx GUI/waiting
 * critical sections with the original runtime ordering.
 */
void wxMutexGuiLeave();

/**
 * Address: 0x009ADC70 (FUN_009ADC70, wxMutexGuiLeaveOrEnter)
 *
 * What it does:
 * Reconciles GUI ownership against waiting-thread state, leaving or entering
 * the wx GUI critical section as required by the original runtime contract.
 */
void wxMutexGuiLeaveOrEnter();

/**
 * Address: 0x009C7540 (FUN_009C7540, wxGetOsVersion)
 *
 * What it does:
 * Caches Win32 platform-id and major/minor version lanes and returns the wx
 * OS-family enum value.
 */
int wxGetOsVersion(int* majorVsn, int* minorVsn);

/**
 * Address: 0x00962900 (FUN_00962900, wxLogDebug)
 *
 * What it does:
 * Preserves the wx debug-log call lane as a deliberate no-op.
 */
void wxLogDebug(...);

/**
 * Address: 0x009C7BB0 (FUN_009C7BB0, wxBeginBusyCursor)
 *
 * What it does:
 * Increments busy-cursor nesting depth and, on first entry, swaps the active
 * Win32 cursor to the provided wx cursor handle (or null cursor when refdata
 * is absent), while saving the previous cursor lane.
 */
void wxBeginBusyCursor(wxCursor* cursor);

namespace wx
{
  /**
   * Address: 0x009CD1D0 (FUN_009CD1D0, wx::copystring)
   *
   * What it does:
   * Allocates and returns one heap-owned wide-string copy, treating `nullptr`
   * as an empty string source.
   */
  [[nodiscard]] wchar_t* copystring(const wchar_t* text);
}

class wxWindowBase
{
public:
  /**
   * Address: 0x0042B770 (FUN_0042B770)
   * Mangled: ?GetClassInfo@wxWindowBase@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxWindowBase runtime RTTI checks.
   */
  virtual void* GetClassInfo() const;
  virtual void DeleteObject() {}
  virtual void* CreateRefData() const { return nullptr; }
  virtual void* CloneRefData(const void* sourceRefData) const
  {
    (void)sourceRefData;
    return nullptr;
  }
  virtual bool ProcessEvent(void* event)
  {
    (void)event;
    return false;
  }
  virtual bool SearchEventTable(void* eventTable, void* event)
  {
    (void)eventTable;
    (void)event;
    return false;
  }
  virtual const void* GetEventTable() const { return nullptr; }
  virtual void DoSetClientObject(void* clientObject) { (void)clientObject; }
  virtual void* DoGetClientObject() const { return nullptr; }
  virtual void DoSetClientData(void* clientData) { (void)clientData; }
  virtual void* DoGetClientData() const { return nullptr; }

  /**
   * Address: 0x00963210
   * Mangled: ?Destroy@wxWindowBase@@UAE_NXZ
   */
  virtual bool Destroy() { return false; }
  /**
   * Address: 0x0042B3E0 (FUN_0042B3E0)
   * Mangled: ?SetTitle@wxWindowBase@@UAEXPBG@Z
   *
   * What it does:
   * Base implementation accepts but ignores title updates.
   */
  virtual void SetTitle(const wxStringRuntime& title);

  /**
   * Address: 0x0042B3F0 (FUN_0042B3F0)
   * Mangled: ?GetTitle@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Returns an empty runtime wx string for base windows.
   */
  [[nodiscard]] virtual wxStringRuntime GetTitle() const;
  /**
   * Address: 0x0042B420 (FUN_0042B420)
   * Mangled: ?SetLabel@wxWindowBase@@UAEXABVwxString@@@Z
   *
   * What it does:
   * Forwards label updates to `SetTitle`.
   */
  virtual void SetLabel(const wxStringRuntime& label);

  /**
   * Address: 0x0042B430 (FUN_0042B430)
   * Mangled: ?GetLabel@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Forwards label reads to `GetTitle`.
   */
  [[nodiscard]] virtual wxStringRuntime GetLabel() const;

  /**
   * Address: 0x0042B450 (FUN_0042B450)
   * Mangled: ?SetName@wxWindowBase@@UAEXABVwxString@@@Z
   *
   * What it does:
   * Stores one runtime window-name value.
   */
  virtual void SetName(const wxStringRuntime& name);

  /**
   * Address: 0x0042B460 (FUN_0042B460)
   * Mangled: ?GetName@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Returns the current runtime window-name value.
   */
  [[nodiscard]] virtual wxStringRuntime GetName() const;

  /**
   * Address: 0x00967200 (FUN_00967200)
   * Mangled: ?GetBackgroundColour@wxWindowBase@@QBE?AVwxColour@@XZ
   *
   * What it does:
   * Returns one copy of the current window background-colour runtime lane.
   */
  [[nodiscard]] wxColourRuntime GetBackgroundColour() const;

  virtual void Raise() {}
  virtual void Lower() {}
  /**
   * Address: 0x00963540 (FUN_00963540)
   * Mangled: ?GetClientAreaOrigin@wxWindowBase@@UBE?AVwxPoint@@XZ
   *
   * What it does:
   * Returns the default client-area origin `(0, 0)` for base window lanes.
   */
  [[nodiscard]] virtual wxPoint GetClientAreaOrigin() const;
  virtual void Fit() {}
  virtual void FitInside() {}
  /**
   * Address: 0x00963560
   * Mangled: ?SetSizeHints@wxWindowBase@@UAEXHHHHHH@Z
   */
  virtual void SetSizeHints(
    std::int32_t minWidth,
    std::int32_t minHeight,
    std::int32_t maxWidth,
    std::int32_t maxHeight,
    std::int32_t incWidth,
    std::int32_t incHeight
  )
  {
    (void)minWidth;
    (void)minHeight;
    (void)maxWidth;
    (void)maxHeight;
    (void)incWidth;
    (void)incHeight;
  }
  virtual void SetVirtualSizeHints(
    std::int32_t minWidth, std::int32_t minHeight, std::int32_t maxWidth, std::int32_t maxHeight
  )
  {
    (void)minWidth;
    (void)minHeight;
    (void)maxWidth;
    (void)maxHeight;
  }
  /**
   * Address: 0x0042B4F0 (FUN_0042B4F0)
   * Mangled: ?GetMinWidth@wxWindowBase@@UBEHXZ
   */
  [[nodiscard]] virtual std::int32_t GetMinWidth() const;

  /**
   * Address: 0x0042B500 (FUN_0042B500)
   * Mangled: ?GetMinHeight@wxWindowBase@@UBEHXZ
   */
  [[nodiscard]] virtual std::int32_t GetMinHeight() const;

  /**
   * Address: 0x0042B510 (FUN_0042B510)
   * Mangled: ?GetMaxSize@wxWindowBase@@UBE?AVwxSize@@XZ
   */
  [[nodiscard]] virtual wxSize GetMaxSize() const;
  virtual void DoSetVirtualSize(std::int32_t width, std::int32_t height)
  {
    (void)width;
    (void)height;
  }
  virtual wxSize DoGetVirtualSize() const { return wxSize{}; }

  /**
   * Address: 0x0042B4A0 (FUN_0042B4A0)
   *
   * What it does:
   * Returns client size by forwarding to `DoGetClientSize`.
   */
  [[nodiscard]] wxSize GetClientSize() const;

  /**
   * Address: 0x0042B4D0 (FUN_0042B4D0)
   *
   * What it does:
   * Returns best size by forwarding to `DoGetBestSize`.
   */
  [[nodiscard]] wxSize GetBestSize() const;

  /**
   * Address: 0x0042B530 (FUN_0042B530)
   * Mangled: ?GetBestVirtualSize@wxWindowBase@@UBE?AVwxSize@@XZ
   */
  [[nodiscard]] virtual wxSize GetBestVirtualSize() const;

  /**
   * Address: 0x00963660 (FUN_00963660)
   * Mangled: ?Show@wxWindowBase@@UAE_N_N@Z
   *
   * What it does:
   * Toggles the base visibility bit in window runtime state and reports
   * whether the visibility lane changed.
   */
  virtual bool Show(bool show);

  /**
   * Address: 0x009636A0 (FUN_009636A0)
   * Mangled: ?Enable@wxWindowBase@@UAE_N_N@Z
   *
   * What it does:
   * Toggles the base enabled bit in window runtime state and reports whether
   * the enabled lane changed.
   */
  virtual bool Enable(bool enable);
  /**
   * Address: 0x0042B5B0 (FUN_0042B5B0)
   * Mangled: ?SetWindowStyleFlag@wxWindowBase@@UAEXJ@Z
   */
  virtual void SetWindowStyleFlag(long style);

  /**
   * Address: 0x0042B5C0 (FUN_0042B5C0)
   * Mangled: ?GetWindowStyleFlag@wxWindowBase@@UBEJXZ
   */
  [[nodiscard]] virtual long GetWindowStyleFlag() const;

  /**
   * Address: 0x0042B5F0 (FUN_0042B5F0)
   * Mangled: ?IsRetained@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool IsRetained() const;

  /**
   * Address: 0x0042B600 (FUN_0042B600)
   * Mangled: ?SetExtraStyle@wxWindowBase@@UAEXJ@Z
   */
  virtual void SetExtraStyle(long style);
  virtual void MakeModal(bool modal) { (void)modal; }
  /**
   * Address: 0x0042B610 (FUN_0042B610)
   * Mangled: ?SetThemeEnabled@wxWindowBase@@UAEX_N@Z
   */
  virtual void SetThemeEnabled(bool enabled);

  /**
   * Address: 0x0042B620 (FUN_0042B620)
   * Mangled: ?GetThemeEnabled@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool GetThemeEnabled() const;

  /**
   * Address: 0x00967650
   * Mangled: ?SetFocus@wxWindow@@UAEXXZ
   */
  virtual void SetFocus() {}
  /**
   * Address: 0x0042B630 (FUN_0042B630)
   * Mangled: ?SetFocusFromKbd@wxWindowBase@@UAEXXZ
   */
  virtual void SetFocusFromKbd();

  /**
   * Address: 0x0042B640 (FUN_0042B640)
   * Mangled: ?AcceptsFocus@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool AcceptsFocus() const;

  /**
   * Address: 0x0042B660 (FUN_0042B660)
   * Mangled: ?AcceptsFocusFromKeyboard@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool AcceptsFocusFromKeyboard() const;

  /**
   * Address: 0x0042B670 (FUN_0042B670)
   * Mangled: ?GetDefaultItem@wxWindowBase@@UBEPAVwxWindow@@XZ
   */
  [[nodiscard]] virtual void* GetDefaultItem() const;
  /**
   * Address: 0x0042B680 (FUN_0042B680)
   * Mangled: ?SetDefaultItem@wxWindowBase@@UAEPAVwxWindow@@PAV2@@Z
   */
  virtual void* SetDefaultItem(void* defaultItem);

  /**
   * Address: 0x0042B690 (FUN_0042B690)
   * Mangled: ?SetTmpDefaultItem@wxWindowBase@@UAEXPAVwxWindow@@@Z
   */
  virtual void SetTmpDefaultItem(void* defaultItem);
  virtual bool IsTopLevel() const { return false; }
  virtual bool Reparent(wxWindowBase* parent)
  {
    (void)parent;
    return false;
  }
  virtual void AddChild(wxWindowBase* child) { (void)child; }
  virtual void RemoveChild(wxWindowBase* child) { (void)child; }
  virtual void SetValidator(const void* validator) { (void)validator; }
  virtual void* GetValidator() { return nullptr; }
  virtual bool Validate() { return false; }
  virtual bool TransferDataToWindow() { return false; }
  virtual bool TransferDataFromWindow() { return false; }
  virtual void InitDialog() {}
  virtual void SetAcceleratorTable(const void* acceleratorTable) { (void)acceleratorTable; }
  virtual void WarpPointer(std::int32_t x, std::int32_t y)
  {
    (void)x;
    (void)y;
  }
  /**
   * Address: 0x0042B6E0 (FUN_0042B6E0)
   * Mangled: ?HasCapture@wxWindowBase@@UBE_NXZ
   */
  virtual bool HasCapture() const;

  /**
   * What it does:
   * Returns the current runtime capture owner window, when tracked.
   */
  [[nodiscard]] static wxWindowBase* GetCapture();

  /**
   * Address: 0x00964CA0 (FUN_00964CA0)
   * Mangled: ?CaptureMouse@wxWindowBase@@QAEXXZ
   *
   * What it does:
   * Releases any previously captured window, pushes that window onto the
   * capture-history lane, then requests capture for this window.
   */
  void CaptureMouse();

  virtual void Refresh(bool eraseBackground, const void* updateRect)
  {
    (void)eraseBackground;
    (void)updateRect;
  }
  /**
   * Address: 0x0042B700 (FUN_0042B700)
   */
  virtual void Update();
  virtual void Clear() {}
  /**
   * Address: 0x0042B710 (FUN_0042B710)
   */
  virtual void Freeze();
  /**
   * Address: 0x0042B720 (FUN_0042B720)
   */
  virtual void Thaw();
  /**
   * Address: 0x0042B730 (FUN_0042B730)
   * Mangled: ?PrepareDC@wxWindowBase@@UAEXAAVwxDC@@@Z
   */
  virtual void PrepareDC(void* deviceContext);
  virtual bool SetBackgroundColour(const void* colour)
  {
    (void)colour;
    return false;
  }
  virtual bool SetForegroundColour(const void* colour)
  {
    (void)colour;
    return false;
  }
  virtual bool SetCursor(const void* cursor)
  {
    (void)cursor;
    return false;
  }
  virtual bool SetFont(const void* font)
  {
    (void)font;
    return false;
  }
  virtual std::int32_t GetCharHeight() const { return 0; }
  virtual std::int32_t GetCharWidth() const { return 0; }
  virtual void GetTextExtent(
    const void* text,
    std::int32_t* outWidth,
    std::int32_t* outHeight,
    std::int32_t* outDescent,
    std::int32_t* outExternalLeading,
    const void* font
  ) const
  {
    (void)text;
    (void)font;
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
    if (outDescent != nullptr) {
      *outDescent = 0;
    }
    if (outExternalLeading != nullptr) {
      *outExternalLeading = 0;
    }
  }
  virtual void SetScrollbar(
    std::int32_t orientation,
    std::int32_t position,
    std::int32_t thumbSize,
    std::int32_t range,
    bool refresh
  )
  {
    (void)orientation;
    (void)position;
    (void)thumbSize;
    (void)range;
    (void)refresh;
  }
  virtual void SetScrollPos(std::int32_t orientation, std::int32_t position, bool refresh)
  {
    (void)orientation;
    (void)position;
    (void)refresh;
  }
  virtual std::int32_t GetScrollPos(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual std::int32_t GetScrollThumb(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual std::int32_t GetScrollRange(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual void ScrollWindow(std::int32_t dx, std::int32_t dy, const void* rect)
  {
    (void)dx;
    (void)dy;
    (void)rect;
  }
  /**
   * Address: 0x0042B740 (FUN_0042B740)
   */
  virtual bool ScrollLines(std::int32_t lines);
  /**
   * Address: 0x0042B750 (FUN_0042B750)
   */
  virtual bool ScrollPages(std::int32_t pages);
  virtual void SetDropTarget(void* dropTarget);
  /**
   * Address: 0x0042B760 (FUN_0042B760)
   * Mangled: ?GetDropTarget@wxWindowBase@@UBEPAVwxDropTarget@@XZ
   */
  virtual void* GetDropTarget() const;
  virtual void SetConstraintSizes(bool recurse) { (void)recurse; }
  virtual bool LayoutPhase1(std::int32_t* flags)
  {
    (void)flags;
    return false;
  }
  virtual bool LayoutPhase2(std::int32_t* flags)
  {
    (void)flags;
    return false;
  }
  virtual bool DoPhase(std::int32_t phase)
  {
    (void)phase;
    return false;
  }
  virtual void SetSizeConstraint(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height)
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }
  virtual void MoveConstraint(std::int32_t x, std::int32_t y)
  {
    (void)x;
    (void)y;
  }
  virtual void GetSizeConstraint(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual void GetClientSizeConstraint(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual void GetPositionConstraint(std::int32_t* outX, std::int32_t* outY) const
  {
    if (outX != nullptr) {
      *outX = 0;
    }
    if (outY != nullptr) {
      *outY = 0;
    }
  }
  virtual bool Layout() { return false; }
  /**
   * Address: 0x0042B820
   * Mangled: ?GetHandle@wxWindow@@UBEKXZ
   */
  virtual unsigned long GetHandle() const { return 0; }
  virtual std::int32_t GetDefaultBorder() const { return 0; }
  virtual void DoClientToScreen(std::int32_t* x, std::int32_t* y) const
  {
    (void)x;
    (void)y;
  }
  virtual void DoScreenToClient(std::int32_t* x, std::int32_t* y) const
  {
    (void)x;
    (void)y;
  }
  virtual std::int32_t DoHitTest(std::int32_t x, std::int32_t y) const
  {
    (void)x;
    (void)y;
    return 0;
  }
  virtual void DoCaptureMouse() {}
  /**
   * Address: 0x00967930 (FUN_00967930)
   * Mangled: ?DoReleaseMouse@wxWindow@@MAEXXZ
   *
   * What it does:
   * Releases the current Win32 mouse capture lane.
   */
  virtual void DoReleaseMouse();
  virtual void DoGetPosition(std::int32_t* x, std::int32_t* y) const
  {
    if (x != nullptr) {
      *x = 0;
    }
    if (y != nullptr) {
      *y = 0;
    }
  }
  virtual void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }

  /**
   * Address: 0x0042B6B0 / 0x0098D180 family
   * Mangled (window/frame overrides):
   * - ?DoGetClientSize@wxWindow@@MBEXPAH0@Z
   * - ?DoGetClientSize@wxFrame@@MBEXPAH0@Z
   */
  virtual void DoGetClientSize(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual wxSize DoGetBestSize() const { return wxSize{}; }
  virtual void DoSetSize(
    std::int32_t x,
    std::int32_t y,
    std::int32_t width,
    std::int32_t height,
    std::int32_t sizeFlags
  )
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)sizeFlags;
  }

  /**
   * Address: 0x0042B6A0 / 0x0098D110 family
   * Mangled (window/frame overrides):
   * - ?DoSetClientSize@wxWindow@@MAEXHH@Z
   * - ?DoSetClientSize@wxFrame@@MAEXHH@Z
   */
  virtual void DoSetClientSize(std::int32_t width, std::int32_t height)
  {
    (void)width;
    (void)height;
  }
};

class wxWindowMswRuntime : public wxWindowBase
{
public:
  virtual void DoMoveWindow(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height)
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }
  virtual void DoSetToolTip(void* tooltip) { (void)tooltip; }
  virtual bool DoPopupMenu(void* menu, std::int32_t x, std::int32_t y)
  {
    (void)menu;
    (void)x;
    (void)y;
    return false;
  }
  virtual void AdjustForParentClientOrigin(std::int32_t& x, std::int32_t& y, std::int32_t sizeFlags) const
  {
    (void)x;
    (void)y;
    (void)sizeFlags;
  }
  virtual void DragAcceptFiles(bool accept) { (void)accept; }
  virtual bool LoadNativeDialogByName(void* parent, const void* dialogName)
  {
    (void)parent;
    (void)dialogName;
    return false;
  }
  virtual bool LoadNativeDialogById(void* parent, std::int32_t& dialogId)
  {
    (void)parent;
    (void)dialogId;
    return false;
  }
  /**
   * Address: 0x0042B830 (FUN_0042B830)
   * Mangled: ?ContainsHWND@wxWindow@@UBE_NK@Z
   *
   * What it does:
   * Base implementation reports the queried native handle as not contained.
   */
  virtual bool ContainsHWND(unsigned long nativeHandle) const;

  /**
   * Address: 0x0042B840 (FUN_0042B840)
   * Mangled: ?GetClassInfo@wxWindow@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxWindow runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;
  /**
   * Address: 0x00967EB0 (FUN_00967EB0)
   * Mangled: ?MSWGetStyle@wxWindow@@UBEKJPAK@Z
   *
   * What it does:
   * Translates one wx style-bit lane into Win32 style and extended-style
   * masks, including 3D-control and top-level adjustments.
   */
  [[nodiscard]] unsigned long MSWGetStyle(long style, unsigned long* extendedStyle) const;
  virtual unsigned long MSWGetParent() const { return 0; }
  virtual bool MSWCommand(unsigned int commandId, unsigned short notificationCode)
  {
    (void)commandId;
    (void)notificationCode;
    return false;
  }

  /**
   * Address: 0x00968B10 (FUN_00968B10, wxWindow::UnpackCommand)
   *
   * What it does:
   * Splits packed command-message params into command id, notification code,
   * and control handle lanes.
   */
  static unsigned short UnpackCommand(
    unsigned int packedWord,
    int controlHandle,
    unsigned short* outCommandId,
    unsigned int* outControlHandle,
    unsigned short* outNotificationCode
  );

  /**
   * Address: 0x00968B40 (FUN_00968B40, wxWindow::UnpackActivate)
   *
   * What it does:
   * Splits activation packed word into state/minimized lanes and forwards the
   * HWND parameter.
   */
  static unsigned int* UnpackActivate(
    int packedWord,
    int nativeWindowHandle,
    unsigned short* outState,
    unsigned short* outMinimized,
    unsigned int* outNativeWindowHandle
  );

  /**
   * Address: 0x00968B70 (FUN_00968B70, wxWindow::UnpackScroll)
   *
   * What it does:
   * Splits scroll packed word into position/request lanes and forwards the
   * scroll-bar HWND parameter.
   */
  static unsigned int* UnpackScroll(
    int packedWord,
    int scrollBarHandle,
    unsigned short* outRequest,
    unsigned short* outPosition,
    unsigned int* outScrollBarHandle
  );

  /**
   * Address: 0x00968BA0 (FUN_00968BA0, wxWindow::UnpackCtlColor)
   *
   * What it does:
   * Emits fixed control-colour id lane (`3`) and forwards `wParam/lParam`
   * into caller-provided output lanes.
   */
  static unsigned int* UnpackCtlColor(
    int wParam,
    int lParam,
    unsigned short* outControlId,
    unsigned int* outWParam,
    unsigned int* outLParam
  );

  /**
   * Address: 0x0097D080 (FUN_0097D080)
   * Mangled: ?CreateWindowFromHWND@wxWindow@@UAEPAV1@PAV1@K@Z
   *
   * What it does:
   * Adapts one native Win32 HWND into the closest recovered wx runtime
   * control wrapper and adopts HWND-derived attributes.
   */
  virtual void* CreateWindowFromHWND(void* parent, unsigned long nativeHandle);
  /**
   * Address: 0x0097CCC0 (FUN_0097CCC0)
   * Mangled: ?AdoptAttributesFromHWND@wxWindow@@UAEXXZ
   *
   * What it does:
   * Reads native Win32 scroll-style bits from the attached HWND and mirrors
   * them into the wx window-style lane.
   */
  virtual void AdoptAttributesFromHWND();
  /**
   * Address: 0x00969970 (FUN_00969970)
   *
   * What it does:
   * Dispatches one mouse-capture-changed event to this window's current
   * event-handler lane, resolving the previous native capture owner handle
   * into a runtime wx window pointer.
   */
  bool HandleCaptureChanged(int nativeHandle);
  /**
   * Address: 0x0096C5F0 (FUN_0096C5F0)
   * Mangled: ?HandleDropFiles@wxWindow@@MAE_NPAUHDROP__@@@Z
   *
   * What it does:
   * Converts one Win32 HDROP payload into a runtime drop-files event and
   * dispatches it through the current window event-handler lane.
   */
  bool HandleDropFiles(void* hDrop);
  virtual void SetupColours() {}
  virtual bool MSWOnScroll(
    std::int32_t orientation, unsigned short command, unsigned short position, unsigned long controlHandle
  )
  {
    (void)orientation;
    (void)command;
    (void)position;
    (void)controlHandle;
    return false;
  }
  virtual bool MSWOnNotify(std::int32_t controlId, long notificationCode, long* result)
  {
    (void)controlId;
    (void)notificationCode;
    (void)result;
    return false;
  }
  virtual bool MSWOnDrawItem(std::int32_t controlId, void** drawItemStruct)
  {
    (void)controlId;
    (void)drawItemStruct;
    return false;
  }
  virtual bool MSWOnMeasureItem(std::int32_t controlId, void** measureItemStruct)
  {
    (void)controlId;
    (void)measureItemStruct;
    return false;
  }
  virtual long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam)
  {
    (void)message;
    (void)wParam;
    (void)lParam;
    return 0;
  }
  virtual long MSWDefWindowProc(unsigned int message, unsigned int wParam, long lParam)
  {
    (void)message;
    (void)wParam;
    (void)lParam;
    return 0;
  }
  virtual bool MSWShouldPreProcessMessage(void** message)
  {
    (void)message;
    return false;
  }
  virtual bool MSWProcessMessage(void** message)
  {
    (void)message;
    return false;
  }
  virtual bool MSWTranslateMessage(void** message)
  {
    (void)message;
    return false;
  }
  /**
   * Address: 0x00968C60 (FUN_00968C60)
   * Mangled: ?MSWDestroyWindow@wxWindow@@UAEXXZ
   *
   * What it does:
   * Base implementation performs no additional HWND teardown work.
   */
  virtual void MSWDestroyWindow();
  virtual unsigned long OnCtlColor(
    unsigned long hdc,
    unsigned long hwnd,
    unsigned int nCtlColor,
    unsigned int message,
    unsigned int controlId,
    long result
  )
  {
    (void)hdc;
    (void)hwnd;
    (void)nCtlColor;
    (void)message;
    (void)controlId;
    (void)result;
    return 0;
  }
};

static_assert(sizeof(wxWindowMswRuntime) == 0x4, "wxWindowMswRuntime size must be 0x4");

class wxControlRuntime : public wxWindowMswRuntime
{
public:
  /**
   * Address: 0x004A3830 (FUN_004A3830)
   * Mangled: ?Command@wxControl@@UAEXAAVwxCommandEvent@@@Z
   *
   * What it does:
   * Forwards one command-event dispatch into `ProcessCommand`.
   */
  virtual void Command(void* commandEvent);

  virtual void ControlSlot131() {}

  /**
   * Address: 0x004A3840 (FUN_004A3840)
   * Mangled: ?MSWOnDraw@wxControl@@UAE_NPAPAX@Z
   *
   * What it does:
   * Base implementation reports that no owner-draw handling was performed.
   */
  virtual bool MSWOnDraw(void** drawStruct);

  /**
   * Address: 0x004A3850 (FUN_004A3850)
   * Mangled: ?MSWOnMeasure@wxControl@@UAE_NPAPAX@Z
   *
   * What it does:
   * Base implementation reports that no owner-measure handling was performed.
   */
  virtual bool MSWOnMeasure(void** measureStruct);

protected:
  virtual void ProcessCommand(void* commandEvent)
  {
    (void)commandEvent;
  }
};

static_assert(sizeof(wxControlRuntime) == 0x4, "wxControlRuntime size must be 0x4");

struct wxStringRuntime
{
  wchar_t* m_pchData = nullptr;

  [[nodiscard]] const wchar_t* c_str() const noexcept;
  [[nodiscard]] msvc8::string ToUtf8() const;
  [[nodiscard]] msvc8::string ToUtf8Lower() const;
  /**
   * Address: 0x0095FFD0 (FUN_0095FFD0, func_wstrFind)
   *
   * What it does:
   * Finds one wide-character lane from the left or right and returns its
   * zero-based index, or `-1` when absent.
   */
  [[nodiscard]] std::int32_t FindCharacterIndex(wchar_t needle, bool findFromRight) const noexcept;

  /**
   * Address: 0x009610B0 (FUN_009610B0, wxString::Empty)
   *
   * What it does:
   * Truncates one wx string to `newLength` when the target is shorter than the
   * current length and copy-on-write ownership checks pass.
   */
  wxStringRuntime* Empty(std::uint32_t newLength);

  [[nodiscard]] static wxStringRuntime Borrow(const wchar_t* text) noexcept;
};

static_assert(sizeof(wxStringRuntime) == 0x4, "wxStringRuntime size must be 0x4");

/**
 * Minimal recovered `wxStreamBase` lane used by input stream constructors.
 */
class wxStreamBase
{
public:
  wxStreamBase();
  virtual ~wxStreamBase() = default;

protected:
  std::uint8_t mStatusLane[0x8]{};
};

static_assert(sizeof(wxStreamBase) == 0xC, "wxStreamBase size must be 0xC");

class wxInputStream : public wxStreamBase
{
public:
  /**
   * Address: 0x009DCF40 (FUN_009DCF40)
   * Mangled: ??0wxInputStream@@QAE@@Z
   *
   * What it does:
   * Initializes pushback-lane counters to zero and binds the input-stream
   * runtime vtable.
   */
  wxInputStream();
  ~wxInputStream() override = default;

public:
  std::int32_t m_wback = 0;
  std::int32_t m_wbackcur = 0;
  std::int32_t m_wbacksize = 0;
};

static_assert(offsetof(wxInputStream, m_wback) == 0xC, "wxInputStream::m_wback offset must be 0xC");
static_assert(offsetof(wxInputStream, m_wbackcur) == 0x10, "wxInputStream::m_wbackcur offset must be 0x10");
static_assert(offsetof(wxInputStream, m_wbacksize) == 0x14, "wxInputStream::m_wbacksize offset must be 0x14");
static_assert(sizeof(wxInputStream) == 0x18, "wxInputStream size must be 0x18");

/**
 * Minimal recovered `wxFile` lane used by `wxFileInputStream`.
 */
class wxFile
{
public:
  enum OpenMode : std::int32_t
  {
    OpenRead = 0
  };

  /**
   * Address: 0x00A12870 (FUN_00A12870)
   * Mangled: ??0wxFile@@QAE@PBGW4OpenMode@0@@Z
   *
   * What it does:
   * Initializes one file lane and attempts to open the requested wide path.
   */
  wxFile(const wchar_t* fileName, OpenMode mode);
  ~wxFile();

  /**
   * Address: 0x00A11F50 (FUN_00A11F50)
   * Mangled: ?Exists@wxFile@@SA_NPB_W@Z
   *
   * What it does:
   * Probes one wide path and reports whether it exists as a non-directory file.
   */
  static bool Exists(const wchar_t* fileName);

  bool Open(const wchar_t* fileName, OpenMode mode, std::int32_t permissions);

public:
  std::int32_t m_fd = -1;
  std::uint8_t m_error = 0;
  std::uint8_t mPadding05[0x3]{};
};

static_assert(offsetof(wxFile, m_fd) == 0x0, "wxFile::m_fd offset must be 0x0");
static_assert(offsetof(wxFile, m_error) == 0x4, "wxFile::m_error offset must be 0x4");
static_assert(sizeof(wxFile) == 0x8, "wxFile size must be 0x8");

class wxFileInputStream : public wxInputStream
{
public:
  /**
   * Address: 0x009DBAF0 (FUN_009DBAF0)
   * Mangled: ??0wxFileInputStream@@QAE@@Z
   *
   * What it does:
   * Builds one file-backed input stream by constructing/opening `m_file` from
   * the provided wide path and marking stream-owned file destruction.
   */
  explicit wxFileInputStream(const wxStringRuntime& fileName);
  ~wxFileInputStream() override;

public:
  wxFile* m_file = nullptr;
  std::uint8_t m_file_destroy = 0;
  std::uint8_t mPadding1D[0x3]{};
};

static_assert(offsetof(wxFileInputStream, m_file) == 0x18, "wxFileInputStream::m_file offset must be 0x18");
static_assert(
  offsetof(wxFileInputStream, m_file_destroy) == 0x1C,
  "wxFileInputStream::m_file_destroy offset must be 0x1C"
);
static_assert(sizeof(wxFileInputStream) == 0x20, "wxFileInputStream size must be 0x20");

class wxFileName
{
public:
  static void SplitPath(
    const wxStringRuntime& input,
    wxStringRuntime* volume,
    wxStringRuntime* path,
    wxStringRuntime* name,
    wxStringRuntime* ext,
    const wchar_t* formatHint
  );

  /**
   * Address: 0x009F5820 (FUN_009F5820)
   * Mangled: ?SplitPath_0@wxFileName@@SAXABVwxString@@PAV2@00PA_W@Z
   *
   * What it does:
   * Splits a path into path/name/ext lanes and then prepends the normalized
   * volume-prefix lane onto the path output lane when present.
   */
  static void SplitPath_0(
    const wxStringRuntime& input,
    wxStringRuntime* path,
    wxStringRuntime* name,
    wxStringRuntime* ext,
    const wchar_t* formatHint
  );
};

/**
 * Address: 0x009F46E0 (FUN_009F46E0)
 * Mangled: ?wxGetVolumeString@@YA?AVwxString@@ABV1@W4wxPathFormat@@@Z
 *
 * What it does:
 * Formats one volume-prefix lane for `wxFileName::SplitPath_0` prepend usage.
 */
[[nodiscard]] wxStringRuntime wxGetVolumeString(const wxStringRuntime& volume, const wchar_t* formatHint);

class wxDCBase
{
public:
  wxDCBase();
  virtual ~wxDCBase() = default;
};

class wxDC : public wxDCBase
{
public:
  /**
   * Address: 0x009CA490 (FUN_009CA490)
   * Mangled: ??0wxDC@@QAE@@Z
   *
   * What it does:
   * Initializes base device-context lanes and clears selected object / native
   * handle state.
   */
  wxDC();
  ~wxDC() override = default;

  [[nodiscard]] void* GetNativeHandle() const noexcept { return m_hDC; }

protected:
  void* m_selectedBitmap = nullptr;
  std::uint8_t m_bOwnsDC = 0;
  std::uint8_t m_flags = 0;
  std::uint8_t mPadding0A[0x2]{};
  void* m_canvas = nullptr;
  void* m_oldBitmap = nullptr;
  void* m_oldPen = nullptr;
  void* m_oldBrush = nullptr;
  void* m_oldFont = nullptr;
  void* m_oldPalette = nullptr;
  void* m_hDC = nullptr;
};

class wxMemoryDC : public wxDC
{
public:
  /**
   * Address: 0x009D45B0 (FUN_009D45B0)
   * Mangled: ??0wxMemoryDC@@QAE@@Z
   *
   * What it does:
   * Initializes one memory-DC lane, creates a compatible native DC handle,
   * then applies default brush/pen/background draw state.
   */
  wxMemoryDC();

  /**
   * Address: 0x009D4430 (FUN_009D4430)
   * Mangled: ?CreateCompatible@wxMemoryDC@@QAE_NPAVwxDC@@@Z
   */
  bool CreateCompatible(wxDC* sourceDc);

  /**
   * Address: 0x009D43F0 (FUN_009D43F0)
   * Mangled: ?Init@wxMemoryDC@@AAEXXZ
   */
  void Init();

private:
  void SetBrush(void* brushToken);
  void SetPen(void* penToken);
};

/**
 * Minimal recovered `wxClientData` runtime object.
 */
class wxClientDataRuntime
{
public:
  /**
   * Address: 0x004A3690 (FUN_004A3690)
   * Mangled: ??0wxClientData@@QAE@@Z
   *
   * What it does:
   * Constructs one `wxClientData` runtime lane.
   */
  wxClientDataRuntime();

  virtual ~wxClientDataRuntime() = default;

  /**
   * Address: 0x004A36A0 (FUN_004A36A0)
   *
   * What it does:
   * Rebinds this object to the `wxClientData` runtime vtable lane.
   */
  void ResetRuntimeVTable() noexcept;

  /**
   * Address: 0x004A36B0 (FUN_004A36B0)
   *
   * What it does:
   * Implements the deleting-dtor thunk lane for `wxClientData`.
   */
  static wxClientDataRuntime* DeleteWithFlag(wxClientDataRuntime* object, std::uint8_t deleteFlags) noexcept;
};

static_assert(sizeof(wxClientDataRuntime) == 0x4, "wxClientDataRuntime size must be 0x4");

/**
 * Minimal recovered `wxImageHandler` runtime layout used by image codec startup
 * lanes and handler registration.
 */
class wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x0042B870 (FUN_0042B870)
   * Mangled: ??0wxImageHandler@@QAE@@Z
   *
   * What it does:
   * Initializes name/extension/mime string lanes and sets type to invalid.
   */
  wxImageHandlerRuntime();

  /**
   * Address: 0x0042B8F0 (FUN_0042B8F0)
   * Mangled: ?GetClassInfo@wxImageHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxImageHandler runtime RTTI checks.
   */
  [[nodiscard]] virtual void* GetClassInfo() const;

  /**
   * Address: 0x0042B920 (FUN_0042B920)
   *
   * What it does:
   * Releases runtime string lanes and clears shared ref-data ownership.
   */
  virtual ~wxImageHandlerRuntime();

protected:
  void SetDescriptor(
    const wchar_t* name, const wchar_t* extension, const wchar_t* mimeType, std::int32_t bitmapType
  ) noexcept;

private:
  static void ReleaseSharedWxString(wxStringRuntime& value) noexcept;

public:
  void* mRefData = nullptr;
  wxStringRuntime mName{};
  wxStringRuntime mExtension{};
  wxStringRuntime mMime{};
  std::int32_t mType = 0;
};

static_assert(offsetof(wxImageHandlerRuntime, mRefData) == 0x4, "wxImageHandlerRuntime::mRefData offset must be 0x4");
static_assert(offsetof(wxImageHandlerRuntime, mName) == 0x8, "wxImageHandlerRuntime::mName offset must be 0x8");
static_assert(
  offsetof(wxImageHandlerRuntime, mExtension) == 0xC,
  "wxImageHandlerRuntime::mExtension offset must be 0xC"
);
static_assert(offsetof(wxImageHandlerRuntime, mMime) == 0x10, "wxImageHandlerRuntime::mMime offset must be 0x10");
static_assert(offsetof(wxImageHandlerRuntime, mType) == 0x14, "wxImageHandlerRuntime::mType offset must be 0x14");
static_assert(sizeof(wxImageHandlerRuntime) == 0x18, "wxImageHandlerRuntime size must be 0x18");

class wxPngHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x0042B9E0 (FUN_0042B9E0)
   * Mangled: ??0wxPNGHandler@@QAE@XZ
   *
   * What it does:
   * Initializes the PNG handler descriptor (name, extension, mime, bitmap type).
   */
  wxPngHandlerRuntime();

  /**
   * Address: 0x0042BA50 (FUN_0042BA50)
   * Mangled: ?GetClassInfo@wxPNGHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxPNGHandler runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x0042BA60 (FUN_0042BA60)
   *
   * What it does:
   * Deleting-dtor thunk lane for `wxPNGHandler`; no extra teardown beyond base.
   */
  ~wxPngHandlerRuntime() override;
};

static_assert(sizeof(wxPngHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxPngHandlerRuntime size must stay 0x18");

/**
 * Minimal recovered `wxImage` runtime object lane.
 *
 * Keeps the wx ref-data pointer lane at `+0x4` and recovers the Create(width,
 * height) path used by image decode/load callsites.
 */
class wxImageRuntime
{
public:
  virtual ~wxImageRuntime();

  /**
   * Address: 0x00970600 (FUN_00970600)
   * Mangled: ?Create@wxImage@@QAEXHH@Z
   *
   * What it does:
   * Releases existing image ref-data, allocates fresh ref-data storage, then
   * allocates/zeroes 24-bit RGB pixel storage for the requested dimensions.
   */
  void Create(std::int32_t width, std::int32_t height);

private:
  void ReleaseRefData() noexcept;

public:
  void* mRefData = nullptr;
};

static_assert(offsetof(wxImageRuntime, mRefData) == 0x4, "wxImageRuntime::mRefData offset must be 0x4");
static_assert(sizeof(wxImageRuntime) == 0x8, "wxImageRuntime size must be 0x8");

struct wxColourRuntime
{
  std::uint8_t mStorage[0x10]{};

  [[nodiscard]] static wxColourRuntime FromRgb(
    std::uint8_t red, std::uint8_t green, std::uint8_t blue
  ) noexcept;
  [[nodiscard]] static const wxColourRuntime& Null() noexcept;
};

static_assert(sizeof(wxColourRuntime) == 0x10, "wxColourRuntime size must be 0x10");

struct wxFontRuntime
{
  std::uint8_t mStorage[0xC]{};

  [[nodiscard]] static const wxFontRuntime& Null() noexcept;
};

static_assert(sizeof(wxFontRuntime) == 0xC, "wxFontRuntime size must be 0xC");

/**
 * Text style object used by `WWinLogWindow` output-color paths.
 *
 * Evidence:
 * - `FUN_004F36A0` constructs:
 *   - foreground `wxColour` at `+0x00`
 *   - background `wxColour` at `+0x10`
 *   - font `wxFont` at `+0x20`
 * - `FUN_004F63B0` destroys the same lanes in reverse order.
 */
struct wxTextAttrRuntime
{
  wxTextAttrRuntime() = default;

  /**
   * Address: 0x004F36A0 (FUN_004F36A0)
   *
   * What it does:
   * Initializes text-style lanes from foreground/background/font values.
   */
  wxTextAttrRuntime(
    const wxColourRuntime& foreground, const wxColourRuntime& background, const wxFontRuntime& font
  );

  /**
   * Address: 0x004F63B0 (FUN_004F63B0)
   *
   * What it does:
   * Tears down style lanes in reverse subobject order.
   */
  ~wxTextAttrRuntime();

  wxColourRuntime mForegroundColour{};
  wxColourRuntime mBackgroundColour{};
  wxFontRuntime mFont{};
};

static_assert(
  offsetof(wxTextAttrRuntime, mForegroundColour) == 0x0,
  "wxTextAttrRuntime::mForegroundColour offset must be 0x0"
);
static_assert(
  offsetof(wxTextAttrRuntime, mBackgroundColour) == 0x10,
  "wxTextAttrRuntime::mBackgroundColour offset must be 0x10"
);
static_assert(offsetof(wxTextAttrRuntime, mFont) == 0x20, "wxTextAttrRuntime::mFont offset must be 0x20");
static_assert(sizeof(wxTextAttrRuntime) == 0x2C, "wxTextAttrRuntime size must be 0x2C");

enum wxListKeyTypeRuntime : std::int32_t
{
  wxKEY_NONE_RUNTIME = 0,
  wxKEY_INTEGER_RUNTIME = 1,
  wxKEY_STRING_RUNTIME = 2,
};

struct wxListKeyRuntime
{
  wxListKeyTypeRuntime mKeyType = wxKEY_NONE_RUNTIME;
  union
  {
    std::uintptr_t integer;
    const wchar_t* string;
  } mKey{};
};

static_assert(offsetof(wxListKeyRuntime, mKeyType) == 0x0, "wxListKeyRuntime::mKeyType offset must be 0x0");
static_assert(offsetof(wxListKeyRuntime, mKey) == 0x4, "wxListKeyRuntime::mKey offset must be 0x4");
static_assert(sizeof(wxListKeyRuntime) == 0x8, "wxListKeyRuntime size must be 0x8");

/**
 * Recovered `wxNodeBase` runtime projection.
 */
class wxNodeBaseRuntime
{
public:
  virtual ~wxNodeBaseRuntime() = default;

  std::uintptr_t mKeyStorage = 0;
  void* mValue = nullptr;
  wxNodeBaseRuntime* mNext = nullptr;
  wxNodeBaseRuntime* mPrevious = nullptr;
  void* mListOwner = nullptr;
};

static_assert(offsetof(wxNodeBaseRuntime, mKeyStorage) == 0x4, "wxNodeBaseRuntime::mKeyStorage offset must be 0x4");
static_assert(offsetof(wxNodeBaseRuntime, mValue) == 0x8, "wxNodeBaseRuntime::mValue offset must be 0x8");
static_assert(offsetof(wxNodeBaseRuntime, mNext) == 0xC, "wxNodeBaseRuntime::mNext offset must be 0xC");
static_assert(offsetof(wxNodeBaseRuntime, mPrevious) == 0x10, "wxNodeBaseRuntime::mPrevious offset must be 0x10");
static_assert(offsetof(wxNodeBaseRuntime, mListOwner) == 0x14, "wxNodeBaseRuntime::mListOwner offset must be 0x14");
static_assert(sizeof(wxNodeBaseRuntime) == 0x18, "wxNodeBaseRuntime size must be 0x18");

/**
 * Address: 0x00978190 (FUN_00978190, func_wxNodeBaseInit)
 *
 * What it does:
 * Initializes one `wxNodeBase` node with key/data/owner lanes and links it
 * between optional neighboring nodes.
 */
wxNodeBaseRuntime* wxNodeBaseInit(
  wxNodeBaseRuntime* node,
  void* listOwner,
  wxNodeBaseRuntime* previous,
  wxNodeBaseRuntime* next,
  void* value,
  const wxListKeyRuntime* key
);

/**
 * Recovered `wxListItemAttr` runtime projection.
 *
 * Evidence:
 * - `FUN_00980B70` destroys two `wxColour` lanes at `+0x00/+0x10` and one
 *   `wxFont` lane at `+0x20`.
 */
struct wxListItemAttrRuntime
{
  wxColourRuntime mTextColour{};
  wxColourRuntime mBackgroundColour{};
  wxFontRuntime mFont{};
};

static_assert(
  offsetof(wxListItemAttrRuntime, mTextColour) == 0x0,
  "wxListItemAttrRuntime::mTextColour offset must be 0x0"
);
static_assert(
  offsetof(wxListItemAttrRuntime, mBackgroundColour) == 0x10,
  "wxListItemAttrRuntime::mBackgroundColour offset must be 0x10"
);
static_assert(
  offsetof(wxListItemAttrRuntime, mFont) == 0x20,
  "wxListItemAttrRuntime::mFont offset must be 0x20"
);

/**
 * Recovered `wxListItem` runtime object used by `wxListCtrl` get/set-item
 * paths.
 *
 * Evidence:
 * - `FUN_00987D00` destroys optional attribute storage from `+0x30`.
 * - `FUN_00987D00` releases the shared `wxString` payload at `+0x1C`.
 * - `FUN_009880E0` (`wxListEvent::~wxListEvent`) destroys embedded list-item
 *   payloads.
 */
class wxListItemRuntime
{
public:
  /**
   * Address: 0x00987D00 (FUN_00987D00, ??1wxListItem@@QAE@@Z)
   * Mangled: ??1wxListItem@@QAE@@Z
   *
   * What it does:
   * Releases optional list-item attribute storage, releases shared string
   * payload ownership, and clears base wxObject ref-data ownership lanes.
   */
  virtual ~wxListItemRuntime();

  void* mRefData = nullptr;
  std::int32_t mMask = 0;
  std::int32_t mItemId = 0;
  std::int32_t mColumn = 0;
  std::int32_t mState = 0;
  std::int32_t mStateMask = 0;
  wxStringRuntime mText = wxStringRuntime::Borrow(L"");
  std::int32_t mImage = -1;
  long mData = 0;
  std::int32_t mWidth = -1;
  std::int32_t mFormat = 0;
  wxListItemAttrRuntime* mAttr = nullptr;
};

static_assert(
  offsetof(wxListItemRuntime, mRefData) == 0x4,
  "wxListItemRuntime::mRefData offset must be 0x4"
);
static_assert(
  offsetof(wxListItemRuntime, mText) == 0x1C,
  "wxListItemRuntime::mText offset must be 0x1C"
);
static_assert(
  offsetof(wxListItemRuntime, mAttr) == 0x30,
  "wxListItemRuntime::mAttr offset must be 0x30"
);
static_assert(sizeof(wxListItemRuntime) == 0x34, "wxListItemRuntime size must be 0x34");

class wxListCtrlRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x0099C480 (FUN_0099C480, xListCtrl::GetItem)
   *
   * What it does:
   * Populates one `wxListItem` payload lane for the requested row.
   */
  [[nodiscard]] virtual bool GetItem(wxListItemRuntime* item);

  /**
   * Address: 0x0099D120 (FUN_0099D120, wxListCtrl::GetItemData)
   *
   * What it does:
   * Requests one list row through `GetItem` and returns the row user-data lane
   * when available.
   */
  [[nodiscard]] long GetItemData(std::int32_t itemId);
};

class wxCheckBoxRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x009ACBE0 (slot 134 in `wxCheckBox`)
   * Mangled: ?SetValue@wxCheckBox@@UAEX_N@Z
   */
  virtual void SetValue(bool checked)
  {
    (void)checked;
  }

  /**
   * Address: 0x009ACC00 (slot 135 in `wxCheckBox`)
   * Mangled: ?GetValue@wxCheckBox@@UBE_NXZ
   */
  [[nodiscard]] virtual bool GetValue() const { return false; }
};

static_assert(sizeof(wxCheckBoxRuntime) == 0x4, "wxCheckBoxRuntime size must be 0x4");

class wxTextCtrlRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x00993670 (FUN_00993670)
   * Mangled: ?AdoptAttributesFromHWND@wxTextCtrl@@UAEXXZ
   *
   * What it does:
   * Extends base HWND style adoption with text-control specific style flags and
   * RichEdit version probing from class name.
   */
  void AdoptAttributesFromHWND() override;

  /**
   * Address: 0x00994510 (FUN_00994510)
   * Mangled: ?OnCtlColor@wxTextCtrl@@UAEKKKIIIJ@Z
   *
   * What it does:
   * Applies text-control background/foreground paint lanes for one ctl-color
   * request and returns the brush handle to use.
   */
  unsigned long OnCtlColor(
    unsigned long hdc,
    unsigned long hwnd,
    unsigned int nCtlColor,
    unsigned int message,
    unsigned int controlId,
    long result
  ) override;

  /**
   * Address: 0x009938A0 (slot 134 in `wxTextCtrl`)
   * Mangled: ?GetValue@wxTextCtrl@@UBE?AVwxString@@XZ
   */
  [[nodiscard]] virtual wxStringRuntime GetValue() const { return wxStringRuntime{}; }

  /**
   * Address: 0x009962A0 (slot 135 in `wxTextCtrl`)
   * Mangled: ?SetValue@wxTextCtrl@@UAEXABVwxString@@@Z
   */
  virtual void SetValue(const wxStringRuntime& value) { (void)value; }

  virtual void TextCtrlSlot136() {}
  virtual void TextCtrlSlot137() {}
  virtual void TextCtrlSlot138() {}
  virtual void TextCtrlSlot139() {}
  virtual void TextCtrlSlot140() {}
  virtual void TextCtrlSlot141() {}
  virtual void TextCtrlSlot142() {}
  virtual void TextCtrlSlot143() {}
  virtual void TextCtrlSlot144() {}
  virtual void TextCtrlSlot145() {}
  virtual void TextCtrlSlot146() {}
  virtual void TextCtrlSlot147() {}
  virtual void TextCtrlSlot148() {}
  virtual void TextCtrlSlot149() {}
  virtual void TextCtrlSlot150() {}

  /**
   * Address: 0x009938D0 (slot 151 in `wxTextCtrl`)
   * Mangled: ?AppendText@wxTextCtrl@@UAEXABVwxString@@@Z
   */
  virtual void AppendText(const wxStringRuntime& text) { (void)text; }

  virtual void TextCtrlSlot152() {}
  virtual void TextCtrlSlot153() {}

  /**
   * Address: 0x009954C0 (slot 154 in `wxTextCtrl`)
   * Mangled: ?SetDefaultStyle@wxTextCtrl@@UAE_NABVwxTextAttr@@@Z
   */
  [[nodiscard]] virtual bool SetDefaultStyle(const wxTextAttrRuntime& style)
  {
    (void)style;
    return false;
  }

  virtual void TextCtrlSlot155() {}
  virtual void TextCtrlSlot156() {}
  virtual void TextCtrlSlot157() {}

  /**
   * Address: 0x00993F90 (slot 158 in `wxTextCtrl`)
   * Mangled: ?ShowPosition@wxTextCtrl@@UAEXJ@Z
   */
  virtual void ShowPosition(std::int32_t position) { (void)position; }

  virtual void TextCtrlSlot159() {}
  virtual void TextCtrlSlot160() {}
  virtual void TextCtrlSlot161() {}
  virtual void TextCtrlSlot162() {}
  virtual void TextCtrlSlot163() {}
  virtual void TextCtrlSlot164() {}
  virtual void TextCtrlSlot165() {}
  virtual void TextCtrlSlot166() {}
  virtual void TextCtrlSlot167() {}
  virtual void TextCtrlSlot168() {}
  virtual void TextCtrlSlot169() {}
  virtual void TextCtrlSlot170() {}
  virtual void TextCtrlSlot171() {}

  /**
   * Address: 0x00995F30 (slot 172 in `wxTextCtrl`)
   * Mangled: ?GetLastPosition@wxTextCtrl@@UBEJXZ
   */
  [[nodiscard]] virtual std::int32_t GetLastPosition() const { return 0; }

  virtual void TextCtrlSlot173() {}
  virtual void TextCtrlSlot174() {}
  virtual void TextCtrlSlot175() {}

  [[nodiscard]] msvc8::string GetValueUtf8() const;
  [[nodiscard]] msvc8::string GetValueUtf8Lower() const;
  void SetValueUtf8(const msvc8::string& value);
  void AppendUtf8(const msvc8::string& text);
  void AppendWide(const std::wstring& text);
  void ScrollToLastPosition();
};

static_assert(sizeof(wxTextCtrlRuntime) == 0x4, "wxTextCtrlRuntime size must be 0x4");

class wxTopLevelWindowRuntime : public wxWindowMswRuntime
{
public:
  /**
   * Address: 0x004A3710 (FUN_004A3710)
   * Mangled: ??0wxTopLevelWindowMSW@@QAE@@Z
   *
   * What it does:
   * Constructs one top-level-window runtime base lane and resets fullscreen
   * state bookkeeping.
   */
  wxTopLevelWindowRuntime();

  /**
   * Address: 0x0098C280 (FUN_0098C280, wxTopLevelWindowMSW::Show)
   * Mangled: ?Show@wxTopLevelWindowMSW@@UAE_N_N@Z
   *
   * What it does:
   * Applies base visibility toggle and promotes this window (or parent on
   * hide) in Z-order when a native handle lane is available.
   */
  bool Show(bool show) override;

  /**
   * Address: 0x0098C1E0 family
   * Mangled: ?Maximize@wxTopLevelWindowMSW@@UAEX_N@Z
   */
  virtual void Maximize(bool maximize) { (void)maximize; }
  virtual void Restore() {}
  virtual void Iconize(bool iconize) { (void)iconize; }
  virtual bool IsMaximized() const { return false; }
  virtual bool IsIconized() const { return false; }
  virtual void SetIcon(const void* icon) { (void)icon; }
  virtual void SetIcons(const void* iconBundle) { (void)iconBundle; }
  virtual bool ShowFullScreen(bool show, long style)
  {
    (void)show;
    (void)style;
    return false;
  }

  /**
   * Address: 0x004A3770 (FUN_004A3770)
   * Mangled: ?IsFullScreen@wxTopLevelWindowMSW@@UBE_NXZ
   *
   * What it does:
   * Returns one cached fullscreen-visible flag.
   */
  [[nodiscard]] bool IsFullScreen() const;

  /**
   * Address: 0x004A3700 (FUN_004A3700)
   * Mangled: ?IsOneOfBars@wxTopLevelWindowBase@@MBE_NPBVwxWindow@@@Z
   *
   * What it does:
   * Base implementation reports the queried window as not one of frame bars.
   */
  [[nodiscard]] virtual bool IsOneOfBars(const void* window) const;

  /**
   * Address: 0x004A36F0 (FUN_004A36F0)
   * Mangled: ?IsTopLevel@wxTopLevelWindowBase@@UBE_NXZ
   *
   * What it does:
   * Reports this runtime lane as a top-level wx window.
   */
  [[nodiscard]] bool IsTopLevel() const override;

  /**
   * Address: 0x004A3780 (FUN_004A3780)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for top-level-window runtime
   * lanes.
   */
  static wxTopLevelWindowRuntime* DeleteWithFlag(wxTopLevelWindowRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  /**
   * Address: 0x004A36E0 (FUN_004A36E0)
   *
   * What it does:
   * Resets one top-level-window runtime flag lane.
   */
  void ResetTopLevelFlag34() noexcept;
};

static_assert(sizeof(wxWindowBase) == 0x4, "wxWindowBase size must be 0x4");
static_assert(sizeof(wxTopLevelWindowRuntime) == 0x4, "wxTopLevelWindowRuntime size must be 0x4");

/**
 * Minimal recovered `wxTopLevelWindow` runtime lane used for shared class-info
 * ownership.
 */
class wxTopLevelWindowRootRuntime : public wxTopLevelWindowRuntime
{
public:
  /**
   * Address: 0x004A37A0 (FUN_004A37A0)
   * Mangled: ??0wxTopLevelWindow@@QAE@@Z
   *
   * What it does:
   * Constructs one `wxTopLevelWindow` runtime layer and reapplies base
   * top-level init.
   */
  wxTopLevelWindowRootRuntime();

  /**
   * Address: 0x004A3800 (FUN_004A3800)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for `wxTopLevelWindow`.
   */
  static wxTopLevelWindowRootRuntime* DeleteWithFlag(
    wxTopLevelWindowRootRuntime* object,
    std::uint8_t deleteFlags
  ) noexcept;

  /**
   * Address: 0x004A3820 (FUN_004A3820)
   *
   * What it does:
   * Runs the non-deleting top-level-window teardown thunk.
   */
  static wxTopLevelWindowRootRuntime* DestroyWithoutDelete(wxTopLevelWindowRootRuntime* object) noexcept;

  static void* sm_classInfo[1];
};

static_assert(sizeof(wxTopLevelWindowRootRuntime) == 0x4, "wxTopLevelWindowRootRuntime size must be 0x4");

/**
 * Address: 0x004A37F0 (FUN_004A37F0)
 * Mangled: ?GetClassInfo@wxFrameBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the shared class-info lane used by frame/dialog/top-level
 * `GetClassInfo` slot-0 entries.
 */
[[nodiscard]] void** WX_FrameBaseGetClassInfo() noexcept;

/**
 * Address: 0x0099E8A0 (FUN_0099E8A0)
 *
 * What it does:
 * Runs non-deleting frame-runtime teardown for frame-derived windows.
 */
[[nodiscard]] wxTopLevelWindowRuntime* WX_FrameDestroyWithoutDelete(wxTopLevelWindowRuntime* frame) noexcept;

/**
 * Minimal recovered runtime projection for `wxControlContainer`.
 */
struct wxControlContainerRuntime
{
  std::uint8_t mAcceptsFocusRecursion = 0;
  std::uint8_t mPadding01To03[0x3]{};

  void Initialize(bool acceptsFocusRecursion) noexcept;
};

static_assert(
  sizeof(wxControlContainerRuntime) == 0x4,
  "wxControlContainerRuntime size must be 0x4"
);

/**
 * Minimal recovered `wxDialogBase` runtime view.
 */
class wxDialogBaseRuntime : public wxTopLevelWindowRootRuntime
{
public:
  /**
   * Address: 0x004A3860 (FUN_004A3860)
   * Mangled: ??0wxDialogBase@@QAE@@Z
   *
   * What it does:
   * Builds one dialog-base runtime lane, initializes control-container
   * storage, then runs dialog-base init.
   */
  wxDialogBaseRuntime();

  /**
   * Address: 0x004A38C0 (FUN_004A38C0)
   *
   * What it does:
   * Runs non-deleting teardown for dialog-base runtime lanes.
   */
  static wxDialogBaseRuntime* DestroyWithoutDelete(wxDialogBaseRuntime* object) noexcept;

  /**
   * Address: 0x004A38D0 (FUN_004A38D0)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for dialog-base runtime lanes.
   */
  static wxDialogBaseRuntime* DeleteWithFlag(wxDialogBaseRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  void InitRuntime() noexcept;

public:
  std::uint8_t mUnknown004To157[0x154]{};
  wxControlContainerRuntime mControlContainer{};
};

static_assert(
  offsetof(wxDialogBaseRuntime, mControlContainer) == 0x158,
  "wxDialogBaseRuntime::mControlContainer offset must be 0x158"
);

/**
 * Minimal recovered `wxDialog` runtime view.
 */
class wxDialogRuntime : public wxDialogBaseRuntime
{
public:
  /**
   * Address: 0x0098B870 (FUN_0098B870)
   * Mangled: ??0wxDialog@@QAE@XZ
   *
   * What it does:
   * Builds one dialog runtime lane and runs default dialog init state setup.
   */
  wxDialogRuntime();

  /**
   * Address: 0x004A3900 (FUN_004A3900)
   * Mangled: ??0wxDialog@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
   *
   * What it does:
   * Builds one dialog runtime lane, then applies create/init arguments.
   */
  wxDialogRuntime(
    void* parentWindow,
    std::int32_t windowId,
    const wxStringRuntime& title,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x004A3970 (FUN_004A3970)
   * Mangled: ?GetClassInfo@wxDialog@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for dialog runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x004A3980 (FUN_004A3980)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for dialog runtime lanes.
   */
  static wxDialogRuntime* DeleteWithFlag(wxDialogRuntime* object, std::uint8_t deleteFlags) noexcept;

  /**
   * Address: unknown (wxDialog::ShowModal)
   *
   * What it does:
   * Runs the dialog modal loop and returns the result code.
   */
  virtual std::int32_t ShowModal();

  static void* sm_classInfo[1];

  std::uint8_t mUnknown15CTo16F[0x14]{};
};

static_assert(sizeof(wxDialogRuntime) == 0x170, "wxDialogRuntime size must be 0x170");

/**
 * Minimal recovered `wxTreeItemId` runtime value wrapper.
 */
struct wxTreeItemIdRuntime
{
  /**
   * Address: 0x004A39A0 (FUN_004A39A0)
   *
   * What it does:
   * Clears this item-id to the null value.
   */
  void Reset() noexcept;

  /**
   * Address: 0x004A39B0 (FUN_004A39B0)
   *
   * What it does:
   * Reports whether this item-id currently references a valid node.
   */
  [[nodiscard]] bool IsValid() const noexcept;

  void* mNode = nullptr;
};

static_assert(sizeof(wxTreeItemIdRuntime) == 0x4, "wxTreeItemIdRuntime size must be 0x4");

/**
 * Minimal recovered `wxTreeItemData` runtime payload lane.
 */
class wxTreeItemDataRuntime : public wxClientDataRuntime
{
public:
  /**
   * Address: 0x004A39C0 (FUN_004A39C0)
   *
   * What it does:
   * Constructs one tree-item payload lane with null item data.
   */
  wxTreeItemDataRuntime();

  /**
   * Address: 0x004A39D0 (FUN_004A39D0)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-item payload lanes.
   */
  static wxTreeItemDataRuntime* DeleteWithFlag(wxTreeItemDataRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  /**
   * Address: 0x004A39F0 (FUN_004A39F0)
   *
   * What it does:
   * Rebinds this object to the `wxClientData` base vtable lane.
   */
  void ResetClientDataBaseVTable() noexcept;

public:
  void* mPayload = nullptr;
};

static_assert(offsetof(wxTreeItemDataRuntime, mPayload) == 0x4, "wxTreeItemDataRuntime::mPayload offset must be 0x4");
static_assert(sizeof(wxTreeItemDataRuntime) == 0x8, "wxTreeItemDataRuntime size must be 0x8");

/**
 * Minimal recovered `wxTreeListColumnInfo` runtime projection.
 */
class wxTreeListColumnInfoRuntime
{
public:
  /**
   * Address: 0x004A3A30 (FUN_004A3A30)
   *
   * What it does:
   * Initializes one tree-list column descriptor from title/width/align and
   * owner lane arguments.
   */
  wxTreeListColumnInfoRuntime(
    const wxStringRuntime& title,
    std::int32_t width,
    void* ownerTreeControl,
    std::uint8_t shown,
    std::uint8_t alignment,
    std::int32_t userData
  );

  /**
   * Address: 0x004A3AC0 (FUN_004A3AC0)
   *
   * What it does:
   * Runs non-deleting teardown for one tree-list column descriptor lane.
   */
  void DestroyWithoutDelete() noexcept;

  /**
   * Address: 0x004A3B30 (FUN_004A3B30)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-list column descriptors.
   */
  static wxTreeListColumnInfoRuntime* DeleteWithFlag(
    wxTreeListColumnInfoRuntime* object,
    std::uint8_t deleteFlags
  ) noexcept;

  virtual ~wxTreeListColumnInfoRuntime() = default;

  void* mRefData = nullptr;
  std::uint8_t mShown = 0;
  std::uint8_t mAlignment = 0;
  std::uint8_t mPadding0A = 0;
  std::uint8_t mPadding0B = 0;
  std::int32_t mUserData = 0;
  wxStringRuntime mText{};
  std::int32_t mWidth = -1;
  std::int32_t mImageIndex = -1;
  void* mOwnerTreeControl = nullptr;
};

static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mRefData) == 0x4,
  "wxTreeListColumnInfoRuntime::mRefData offset must be 0x4"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mText) == 0x10,
  "wxTreeListColumnInfoRuntime::mText offset must be 0x10"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mWidth) == 0x14,
  "wxTreeListColumnInfoRuntime::mWidth offset must be 0x14"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mImageIndex) == 0x18,
  "wxTreeListColumnInfoRuntime::mImageIndex offset must be 0x18"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mOwnerTreeControl) == 0x1C,
  "wxTreeListColumnInfoRuntime::mOwnerTreeControl offset must be 0x1C"
);
static_assert(sizeof(wxTreeListColumnInfoRuntime) == 0x20, "wxTreeListColumnInfoRuntime size must be 0x20");

/**
 * Minimal recovered `wxTreeListCtrl` runtime projection.
 */
class wxTreeListCtrlRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x004A3B50 (FUN_004A3B50)
   * Mangled: ??0wxTreeListCtrl@@QAE@PAVwxWindow@@HABVwxPoint@@ABVwxSize@@JABVwxValidator@@ABVwxString@@@Z
   *
   * What it does:
   * Initializes one tree-list control runtime lane with parent/style/name
   * creation arguments.
   */
  wxTreeListCtrlRuntime(
    wxWindowBase* parentWindow,
    std::int32_t windowId,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x004A3BD0 (FUN_004A3BD0)
   *
   * What it does:
   * Runs non-deleting teardown for one tree-list control runtime lane.
   */
  static wxTreeListCtrlRuntime* DestroyWithoutDelete(wxTreeListCtrlRuntime* object) noexcept;

  /**
   * Address: 0x004A3BE0 (FUN_004A3BE0)
   * Mangled: ?AddColumn@wxTreeListCtrl@@QAEXABVwxString@@I_NW4wxTreeListColumnAlign@@@Z
   *
   * What it does:
   * Appends one tree-list column descriptor to this control.
   */
  void AddColumn(const wxStringRuntime& title, std::uint32_t width, bool shown, std::uint8_t alignment = 0);

  /**
   * Address: 0x004A3C50 (FUN_004A3C50)
   * Mangled: ?GetWindowStyleFlag@wxTreeListCtrl@@UBEJXZ
   *
   * What it does:
   * Returns the cached window-style flags for this tree-list control.
   */
  [[nodiscard]] long GetWindowStyleFlag() const override;

  /**
   * Address: 0x004A3C70 (FUN_004A3C70)
   * Mangled: ?GetClassInfo@wxTreeListCtrl@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for tree-list runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x004A3C80 (FUN_004A3C80)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-list control runtime
   * lanes.
   */
  static wxTreeListCtrlRuntime* DeleteWithFlag(wxTreeListCtrlRuntime* object, std::uint8_t deleteFlags) noexcept;

  [[nodiscard]] wxTreeItemIdRuntime AddRoot(const wxStringRuntime& text);
  [[nodiscard]] wxTreeItemIdRuntime AppendItem(const wxTreeItemIdRuntime& parentItem, const wxStringRuntime& text);
  void Expand(const wxTreeItemIdRuntime& item) noexcept;
  void Collapse(const wxTreeItemIdRuntime& item) noexcept;
  [[nodiscard]] bool IsExpanded(const wxTreeItemIdRuntime& item) const noexcept;
  [[nodiscard]] bool HasChildren(const wxTreeItemIdRuntime& item) const noexcept;
  void SortChildren(const wxTreeItemIdRuntime& item);
  void SetItemData(const wxTreeItemIdRuntime& item, wxTreeItemDataRuntime* itemData);
  [[nodiscard]] wxTreeItemDataRuntime* GetItemData(const wxTreeItemIdRuntime& item) const noexcept;
  void SetItemHasChildren(const wxTreeItemIdRuntime& item, bool hasChildren) noexcept;
  void SetItemText(const wxTreeItemIdRuntime& item, std::uint32_t column, const wxStringRuntime& text);

  static void* sm_classInfo[1];

  std::uint8_t mUnknown04To13F[0x13C]{};
};

static_assert(sizeof(wxTreeListCtrlRuntime) == 0x140, "wxTreeListCtrlRuntime size must be 0x140");

class wxApp
{
public:
  enum ExitOnFrameDeleteMode : std::int32_t
  {
    kExitOnFrameDeleteLater = -1,
    kExitOnFrameDeleteNo = 0,
    kExitOnFrameDeleteYes = 1,
  };

  virtual void* GetClassInfo() const = 0;
  virtual void DeleteObject() = 0;
  virtual void* CreateRefData() const = 0;
  virtual void* CloneRefData(const void* sourceRefData) const = 0;
  virtual bool ProcessEvent(void* event) = 0;
  virtual bool SearchEventTable(void* eventTable, void* event) = 0;
  virtual const void* GetEventTable() const = 0;
  virtual void DoSetClientObject(void* clientObject) = 0;
  virtual void* DoGetClientObject() const = 0;
  virtual void DoSetClientData(void* clientData) = 0;
  virtual void* DoGetClientData() const = 0;
  virtual bool OnInit() = 0;
  virtual bool OnInitGui() = 0;
  virtual int OnRun() = 0;

  /**
   * Address: 0x009AA860
   * Mangled: ?OnExit@wxAppBase@@UAEHXZ
   */
  virtual int OnExit();

  virtual void OnFatalException() = 0;
  virtual int MainLoop() = 0;
  virtual void ExitMainLoop() = 0;
  virtual bool Initialized() = 0;

  /**
   * Address: 0x00992230
   * Mangled: ?Pending@wxApp@@UAE_NXZ
   */
  virtual bool Pending();

  /**
   * Address: 0x00992250
   * Mangled: ?Dispatch@wxApp@@UAEXXZ
   */
  virtual void Dispatch();

  /**
   * Address: 0x009923C0
   * Mangled: ?Yield@wxApp@@UAE_N_N@Z
   */
#ifdef Yield
#undef Yield
#endif
  virtual bool Yield(bool onlyIfNeeded) = 0;

  /**
   * Address: 0x00992190
   * Mangled: ?ProcessIdle@wxApp@@UAE_NXZ
   */
  virtual bool ProcessIdle();
  virtual bool IsActive() const = 0;
  virtual wxWindowBase* GetTopWindow() const = 0;
  virtual void OnInitCmdLine(void* cmdLineParser) = 0;
  virtual bool OnCmdLineParsed(void* cmdLineParser) = 0;
  virtual bool OnCmdLineHelp(void* cmdLineParser) = 0;
  virtual bool OnCmdLineError(void* cmdLineParser) = 0;
  virtual void* CreateLogTarget() = 0;
  virtual void* CreateMessageOutput() = 0;
  virtual void* GetStdIcon(std::int32_t iconId) const = 0;
  virtual void* GetDisplayMode() const = 0;
  virtual bool SetDisplayMode(const void* displayMode) = 0;
  virtual void SetPrintMode(std::int32_t mode) = 0;
  virtual void SetActive(bool isActive, wxWindowBase* topWindow) = 0;
  virtual std::int32_t FilterEvent(void* event) = 0;
  virtual void ProcessPendingEvents() = 0;
  virtual std::int32_t GetPrintMode() const = 0;

  /**
   * Address: 0x00993100 (FUN_00993100)
   * Mangled: ?DoMessage@wxApp@@UAE_NXZ
   *
   * What it does:
   * Pumps one Win32 message for the wx app loop, dispatching immediately on
   * the GUI owner thread and deferring cross-thread deliveries.
   */
  virtual bool DoMessage();
  virtual void DoMessage(void** message) = 0;
  virtual bool ProcessMessage(void** message) = 0;

  /**
   * Import thunk address: 0x00992E10
   * Mangled: __imp_?CleanUp@wxApp@@SAXXZ
   */
  static void CleanUp();

  // wxEvtHandler + wxAppConsole unknown/shared runtime lanes.
  std::uint8_t mUnknown04To27[0x24];
  std::uint8_t m_wantDebugOutput = 0;
  std::uint8_t mUnknown29To2B[0x3];

  std::int32_t argc = 0;
  char** argv = nullptr;

  wxStringRuntime m_className{};
  wxStringRuntime m_vendorName{};
  wxStringRuntime m_appName{};

  wxWindowBase* m_topWindow = nullptr;
  std::int32_t m_exitOnFrameDelete = kExitOnFrameDeleteLater;
  std::uint8_t m_useBestVisual = 0;
  std::uint8_t m_isActive = 0;
  std::uint8_t mUnknown4A = 0;
  std::uint8_t mUnknown4B = 0;

  std::uint8_t mUnknown4CTo4F[0x4];
  std::int32_t m_printMode = 0;
  std::uint8_t m_auto3D = 0;
  std::uint8_t mUnknown55To5B[0x7];
  std::uint8_t m_keepGoing = 0;
};

static_assert(
  offsetof(wxApp, m_wantDebugOutput) == 0x28,
  "wxApp::m_wantDebugOutput offset must be 0x28"
);
static_assert(
  offsetof(wxApp, argc) == 0x2C,
  "wxApp::argc offset must be 0x2C"
);
static_assert(
  offsetof(wxApp, argv) == 0x30,
  "wxApp::argv offset must be 0x30"
);
static_assert(
  offsetof(wxApp, m_className) == 0x34,
  "wxApp::m_className offset must be 0x34"
);
static_assert(
  offsetof(wxApp, m_vendorName) == 0x38,
  "wxApp::m_vendorName offset must be 0x38"
);
static_assert(
  offsetof(wxApp, m_appName) == 0x3C,
  "wxApp::m_appName offset must be 0x3C"
);
static_assert(
  offsetof(wxApp, m_topWindow) == 0x40,
  "wxApp::m_topWindow offset must be 0x40"
);
static_assert(
  offsetof(wxApp, m_exitOnFrameDelete) == 0x44,
  "wxApp::m_exitOnFrameDelete offset must be 0x44"
);
static_assert(
  offsetof(wxApp, m_useBestVisual) == 0x48,
  "wxApp::m_useBestVisual offset must be 0x48"
);
static_assert(
  offsetof(wxApp, m_isActive) == 0x49,
  "wxApp::m_isActive offset must be 0x49"
);
static_assert(
  offsetof(wxApp, m_printMode) == 0x50,
  "wxApp::m_printMode offset must be 0x50"
);
static_assert(
  offsetof(wxApp, m_auto3D) == 0x54,
  "wxApp::m_auto3D offset must be 0x54"
);
static_assert(
  offsetof(wxApp, m_keepGoing) == 0x5C,
  "wxApp::m_keepGoing offset must be 0x5C"
);

// wx global owned by wxWidgets runtime.
extern wxApp* wxTheApp;

/**
 * Recovered WSupComFrame runtime view used by CScApp keyboard-suppression
 * gating.
 *
 * Evidence:
 * - FUN_008CDF00 style window proc path in decomp/ForgedAlliance.exe.c:
 *   `*(bool *)((int)this + 0x17b) = (wParam != 0)` on message 0x1C
 *   (WM_ACTIVATEAPP).
 * - FUN_008CE1D0 checks `(supcomFrame + 0x17b) != 0`.
 *
 * Full complete-object size is not asserted yet because only the tail flag
 * lanes are currently validated by direct behavior evidence.
 */
class WSupComFrame : public wxTopLevelWindowRuntime
{
public:
  /**
   * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
   *
   * What it does:
   * Persists current top-level frame position lanes into user preferences
   * while the main frame is windowed and not device-locked.
   */
  void OnMove(wxMoveEventRuntime& event);

  /**
   * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
   * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
   *
   * What it does:
   * Handles SupCom frame resize/maximize/app-activation/system-command
   * routing, updates persisted window prefs, and forwards unhandled messages
   * to base frame dispatch.
   */
  long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

  std::uint8_t mUnknown004To178[0x175];
  std::uint8_t mPendingMaximizeSync;
  std::uint8_t mPersistedMaximizeSync;
  std::uint8_t mIsApplicationActive;
};

static_assert(
  offsetof(WSupComFrame, mPendingMaximizeSync) == 0x179,
  "WSupComFrame::mPendingMaximizeSync offset must be 0x179"
);
static_assert(
  offsetof(WSupComFrame, mPersistedMaximizeSync) == 0x17A,
  "WSupComFrame::mPersistedMaximizeSync offset must be 0x17A"
);
static_assert(
  offsetof(WSupComFrame, mIsApplicationActive) == 0x17B,
  "WSupComFrame::mIsApplicationActive offset must be 0x17B"
);
static_assert(sizeof(WSupComFrame) == 0x17C, "WSupComFrame size must be 0x17C");

/**
 * Recovered wxEvent runtime layout shared by log-window event payloads.
 *
 * Evidence:
 * - `FUN_00978FF0` initializes runtime lanes:
 *   - type at `+0xC`
 *   - id at `+0x14`
 *   - bool flags at `+0x1C/+0x1D`
 * - `FUN_00979050` copy-clones all lanes `+0x8..+0x1D`.
 * - `FUN_00979020` is the deleting-dtor thunk family used by wxEvent-derived
 *   payloads.
 */
class wxEventRuntime
{
public:
  /**
   * Address: 0x00978FF0 (FUN_00978FF0, ??0wxEvent@@QAE@@Z)
   *
   * What it does:
   * Initializes core wxEvent runtime lanes (`type`, `id`, object/ref pointers,
   * timestamp, skip flag, callback user-data, and command-event flag).
   */
  explicit wxEventRuntime(std::int32_t eventId = 0, std::int32_t eventType = 0);

  virtual void* GetClassInfo() const { return nullptr; }
  virtual void DeleteObject() {}
  virtual void* CreateRefData() const { return nullptr; }
  virtual void* CloneRefData(const void* sourceRefData) const
  {
    (void)sourceRefData;
    return nullptr;
  }
  virtual wxEventRuntime* Clone() const = 0;

  void* mRefData = nullptr;
  void* mEventObject = nullptr;
  std::int32_t mEventType = 0;
  std::int32_t mEventTimestamp = 0;
  std::int32_t mEventId = 0;
  void* mCallbackUserData = nullptr;
  std::uint8_t mSkipped = 0;
  std::uint8_t mIsCommandEvent = 0;
  std::uint8_t mReserved1E = 0;
  std::uint8_t mReserved1F = 0;
};

static_assert(offsetof(wxEventRuntime, mRefData) == 0x4, "wxEventRuntime::mRefData offset must be 0x4");
static_assert(offsetof(wxEventRuntime, mEventObject) == 0x8, "wxEventRuntime::mEventObject offset must be 0x8");
static_assert(offsetof(wxEventRuntime, mEventType) == 0xC, "wxEventRuntime::mEventType offset must be 0xC");
static_assert(offsetof(wxEventRuntime, mEventTimestamp) == 0x10, "wxEventRuntime::mEventTimestamp offset must be 0x10");
static_assert(offsetof(wxEventRuntime, mEventId) == 0x14, "wxEventRuntime::mEventId offset must be 0x14");
static_assert(
  offsetof(wxEventRuntime, mCallbackUserData) == 0x18,
  "wxEventRuntime::mCallbackUserData offset must be 0x18"
);
static_assert(offsetof(wxEventRuntime, mSkipped) == 0x1C, "wxEventRuntime::mSkipped offset must be 0x1C");
static_assert(
  offsetof(wxEventRuntime, mIsCommandEvent) == 0x1D,
  "wxEventRuntime::mIsCommandEvent offset must be 0x1D"
);
static_assert(sizeof(wxEventRuntime) == 0x20, "wxEventRuntime size must be 0x20");

/**
 * Minimal recovered `wxCommandEvent` runtime projection.
 *
 * Evidence:
 * - `FUN_00979090` constructor writes one `wxString` lane at `+0x20` and
 *   clears command/client payload lanes (`+0x24..+0x30`).
 * - `FUN_006609B0` releases shared `mCommandString` storage then runs the
 *   `wxEvent::UnRef` tail.
 */
class wxCommandEventRuntime : public wxEventRuntime
{
public:
  /**
   * Address: 0x00979090 (FUN_00979090, ??0wxCommandEvent@@QAE@@Z)
   *
   * What it does:
   * Initializes command-event payload lanes and marks this event as a command
   * event.
   */
  explicit wxCommandEventRuntime(std::int32_t commandType = 0, std::int32_t eventId = 0);

  /**
   * Address: 0x006609B0 (FUN_006609B0, ??1wxCommandEvent@@QAE@@Z)
   *
   * What it does:
   * Releases one shared command-string payload and clears wxEvent ref-data
   * ownership via the base unref tail.
   */
  ~wxCommandEventRuntime();

  wxStringRuntime mCommandString{};
  std::int32_t mCommandInt = 0;
  std::int32_t mExtraLong = 0;
  void* mClientData = nullptr;
  wxClientDataRuntime* mClientObject = nullptr;
};

static_assert(
  offsetof(wxCommandEventRuntime, mCommandString) == 0x20,
  "wxCommandEventRuntime::mCommandString offset must be 0x20"
);
static_assert(
  offsetof(wxCommandEventRuntime, mCommandInt) == 0x24,
  "wxCommandEventRuntime::mCommandInt offset must be 0x24"
);
static_assert(
  offsetof(wxCommandEventRuntime, mExtraLong) == 0x28,
  "wxCommandEventRuntime::mExtraLong offset must be 0x28"
);
static_assert(
  offsetof(wxCommandEventRuntime, mClientData) == 0x2C,
  "wxCommandEventRuntime::mClientData offset must be 0x2C"
);
static_assert(
  offsetof(wxCommandEventRuntime, mClientObject) == 0x30,
  "wxCommandEventRuntime::mClientObject offset must be 0x30"
);
static_assert(sizeof(wxCommandEventRuntime) == 0x34, "wxCommandEventRuntime size must be 0x34");

/**
 * Minimal recovered `wxTreeEvent` runtime projection.
 */
class wxTreeEventRuntime : public wxEventRuntime
{
public:
  /**
   * Address: 0x004A3A00 (FUN_004A3A00)
   *
   * What it does:
   * Copies the primary tree-item-id lane into `outItem`.
   */
  void GetItem(wxTreeItemIdRuntime* outItem) const noexcept;

  /**
   * Address: 0x004A3A10 (FUN_004A3A10)
   *
   * What it does:
   * Returns the label storage lane for this tree event.
   */
  [[nodiscard]] wxStringRuntime* GetLabelStorage() noexcept;

  /**
   * Address: 0x004A3A20 (FUN_004A3A20)
   *
   * What it does:
   * Returns the edit-cancelled flag lane for this tree event.
   */
  [[nodiscard]] bool IsEditCancelled() const noexcept;

  std::uint8_t mUnknown20To73[0x54]{};
  wxTreeItemIdRuntime mItem{};
  wxTreeItemIdRuntime mPreviousItem{};
  wxPoint mDragPoint{};
  wxStringRuntime mLabel{};
  std::uint8_t mEditCancelled = 0;
};

static_assert(offsetof(wxTreeEventRuntime, mItem) == 0x74, "wxTreeEventRuntime::mItem offset must be 0x74");
static_assert(offsetof(wxTreeEventRuntime, mLabel) == 0x84, "wxTreeEventRuntime::mLabel offset must be 0x84");
static_assert(
  offsetof(wxTreeEventRuntime, mEditCancelled) == 0x88,
  "wxTreeEventRuntime::mEditCancelled offset must be 0x88"
);

namespace moho
{
  struct ManagedWindowSlot;
  struct WWinManagedDialog;
  class IUserPrefs;
  class CWinLogTarget;
  struct WWinLogWindow;
  class WWinLogTextBuilder;
  struct CWinLogLine;

  /**
   * Runtime wxEvent-derived payload used by `CWinLogTarget::OnMessage` when
   * notifying the log dialog.
   *
   * Evidence:
   * - `FUN_004F6860` stack-constructs one event and assigns
   *   `CLogAdditionEvent` vftable before dispatch to the dialog handler.
   * - `FUN_004F37F0` allocates one `0x20`-byte clone object.
   */
  class CLogAdditionEvent final : public wxEventRuntime
  {
  public:
    /**
     * Address: 0x004F38E0 (FUN_004F38E0)
     *
     * What it does:
     * Returns the static wx class-info lane for this event payload type.
     */
    [[nodiscard]] void* GetClassInfo() const override;

    /**
     * Address: 0x004F3850 (FUN_004F3850)
     *
     * What it does:
     * Deleting-dtor entry for this event payload type.
     */
    void DeleteObject() override;

    /**
     * Address: 0x004F37F0 (FUN_004F37F0)
     *
     * What it does:
     * Allocates and copy-clones one `CLogAdditionEvent` object.
     */
    CLogAdditionEvent* Clone() const override;
  };

  static_assert(sizeof(CLogAdditionEvent) == 0x20, "moho::CLogAdditionEvent size must be 0x20");

  /**
   * Wide text-builder helper used by `WWinLogWindow` replay/message formatting.
   *
   * Evidence:
   * - ctor/finalize: `FUN_004F73B0` / `FUN_004F74D0`
   * - write helpers:
   *   - `FUN_004F98F0` one code-point emission with stream width/reset
   *   - `FUN_004F9B80` wide-string emission with stream width/reset
   *   - `FUN_004F9DF0` wide-literal emission with stream width/reset
   *   - `FUN_004FA000` narrow-to-wide emission with stream width/reset
   *   - `FUN_004FA2C0` one decoded code-point emission
   * - spacing helper family: `FUN_004F5AB0`.
   */
  class WWinLogTextBuilder
  {
  public:
    /**
     * Address: 0x004F73B0 (FUN_004F73B0)
     *
     * What it does:
     * Constructs one wide stream/buffer builder used by log-window formatting.
     */
    WWinLogTextBuilder();

    /**
     * Address: 0x004F74D0 (FUN_004F74D0)
     *
     * What it does:
     * Finalizes current stream state and returns the accumulated wide text.
     */
    [[nodiscard]] const std::wstring& Finalize() const noexcept;

    /**
     * Address: 0x004F98F0 (FUN_004F98F0)
     *
     * What it does:
     * Emits one wide code-point and clears transient field width.
     */
    void WriteCodePoint(wchar_t codePoint);

    /**
     * Address: 0x004F9B80 (FUN_004F9B80)
     *
     * What it does:
     * Emits one wide string and clears transient field width.
     */
    void WriteWideText(const std::wstring& text);

    /**
     * Address: 0x004F9DF0 (FUN_004F9DF0)
     *
     * What it does:
     * Emits one wide literal and clears transient field width.
     */
    void WriteWideLiteral(const wchar_t* text);

    /**
     * Address: 0x004FA000 (FUN_004FA000)
     *
     * What it does:
     * Emits one UTF-8/narrow text fragment as widened output.
     */
    void WriteUtf8Text(const msvc8::string& text);

    /**
     * Address: 0x004FA2C0 (FUN_004FA2C0)
     *
     * What it does:
     * Emits one decoded wide code-point and clears transient field width.
     */
    void WriteDecodedCodePoint(wchar_t codePoint);

    /**
     * Address: 0x004F5AB0 (FUN_004F5AB0)
     *
     * What it does:
     * Emits `count` space code-points.
     */
    void WriteSpaces(std::size_t count);

    void SetFieldWidth(std::size_t width) noexcept;
    void Clear() noexcept;

  private:
    std::wstring mText{};
    std::size_t mFieldWidth = 0;
    wchar_t mFillCodePoint = L' ';
    bool mLeftAlign = false;
  };

  /**
   * Runtime splash-screen base used by WinMain startup/shutdown paths.
   *
   * Evidence:
   * - `WINX_ExitSplash` (`0x004F3F30`) dispatches the deleting-dtor slot with
   *   flag `1` then clears the global pointer.
   */
  struct SplashScreenRuntime
  {
    virtual void GetClassInfo() = 0;
    virtual void DeleteObject(std::uint32_t flags) = 0;
  };

  /**
   * Address dependency: 0x004F3CE0 (FUN_004F3CE0, WINX_InitSplash)
   *
   * What it does:
   * Initializes one-time PNG splash handler state used before splash bitmap
   * load attempts.
   */
  bool WX_EnsureSplashPngHandler();

  /**
   * Address dependency: 0x004F3CE0 (FUN_004F3CE0, WINX_InitSplash)
   *
   * What it does:
   * Creates one splash runtime object from a UTF-8 file path and target splash
   * size when the image path can be resolved.
   */
  [[nodiscard]] SplashScreenRuntime* WX_CreateSplashScreen(const char* filename, const wxSize& size);

  /**
   * Runtime line-entry record used by `CWinLogTarget` vectors.
   *
   * Evidence:
   * - `FUN_004F6860` / `FUN_004F6F40` construct and append one `0x28`-byte
   *   record with `[isReplay,index,category,text]`.
   */
  struct CWinLogLine
  {
    std::uint32_t isReplayEntry = 0;
    std::uint32_t sequenceIndex = 0;
    std::uint32_t categoryMask = 0;
    msvc8::string text;

    [[nodiscard]] bool IsReplayEntry() const noexcept;
    [[nodiscard]] bool IsMessageEntry() const noexcept;
    [[nodiscard]] const wchar_t* SeverityPrefix() const noexcept;
  };

  static_assert(
    offsetof(CWinLogLine, isReplayEntry) == 0x0,
    "moho::CWinLogLine::isReplayEntry offset must be 0x0"
  );
  static_assert(
    offsetof(CWinLogLine, sequenceIndex) == 0x4,
    "moho::CWinLogLine::sequenceIndex offset must be 0x4"
  );
  static_assert(
    offsetof(CWinLogLine, categoryMask) == 0x8,
    "moho::CWinLogLine::categoryMask offset must be 0x8"
  );
  static_assert(
    offsetof(CWinLogLine, text) == 0xC,
    "moho::CWinLogLine::text offset must be 0xC"
  );
  static_assert(sizeof(CWinLogLine) == 0x28, "moho::CWinLogLine size must be 0x28");

  /**
   * Runtime owner for the global log-window target (`sLogWindowTarget`).
   *
   * Evidence:
   * - `FUN_004F38F0` (`CWinLogTarget` ctor) initializes:
   *   - dialog pointer at `+0x8`
   *   - committed line vector lanes at `+0x10/+0x14/+0x18`
   *   - lock at `+0x1C`
   *   - pending line vector lanes at `+0x28/+0x2C/+0x30`.
   * - `FUN_004F6A50` / `FUN_004F6860` append/merge pending lines into the
   *   committed line set under the same lock.
   */
  class CWinLogTarget : public gpg::LogTarget
  {
  public:
    /**
     * Address: 0x004F38F0 (FUN_004F38F0, ??0CWinLogTarget@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the global log-target owner and auto-registers it with gpg logging.
     */
    CWinLogTarget();

    /**
     * Address: 0x004F39B0 (FUN_004F39B0)
     * Mangled deleting-dtor thunk: 0x004F3990 (FUN_004F3990)
     *
     * What it does:
     * Releases pending/committed vectors and tears down base log-target registration.
     */
    ~CWinLogTarget() override;

    /**
     * Address: 0x004F6860 (FUN_004F6860)
     *
     * gpg::LogSeverity level, msvc8::string const &, msvc8::vector<msvc8::string> const &, int
     *
     * What it does:
     * Queues replay/context lines plus the current line into the pending log queue.
     */
    void OnMessage(
      gpg::LogSeverity level,
      const msvc8::string& message,
      const msvc8::vector<msvc8::string>& context,
      int previousDepth
    ) override;

    /**
     * Address: 0x004F6A50 (FUN_004F6A50)
     *
     * What it does:
     * Merges pending lines into committed history and enforces the 10,000 line cap.
     */
    void MergePendingLines();

    /**
     * Address: 0x004F6F10 (FUN_004F6F10)
     *
     * What it does:
     * Returns committed line count.
     */
    [[nodiscard]] std::size_t CommittedLineCount() const;
    [[nodiscard]] const msvc8::vector<CWinLogLine>& CommittedLines() const;
    void SnapshotCommittedLines(msvc8::vector<CWinLogLine>* outLines);
    void ResetCommittedLinesFromReplayBuffer(const msvc8::vector<msvc8::string>& replayLines);

    WWinLogWindow* dialog = nullptr;
    msvc8::vector<CWinLogLine> mCommittedLines;
    boost::mutex lock{};
    msvc8::vector<CWinLogLine> mPendingLines;

  private:
    /**
     * Address: 0x004F6FD0 (FUN_004F6FD0)
     *
     * What it does:
     * Replaces committed-line storage with a copy of `nextCommittedLines`.
     */
    void ReplaceCommittedLines(const msvc8::vector<CWinLogLine>& nextCommittedLines);

    /**
     * Address: 0x004F6F40 (FUN_004F6F40)
     *
     * What it does:
     * Appends one line record into the pending queue.
     */
    void AppendPendingLine(const CWinLogLine& line);
  };

  static_assert(
    offsetof(CWinLogTarget, dialog) == 0x8,
    "moho::CWinLogTarget::dialog offset must be 0x8"
  );
  static_assert(
    offsetof(CWinLogTarget, mCommittedLines) == 0xC,
    "moho::CWinLogTarget::mCommittedLines offset must be 0xC"
  );
  static_assert(
    offsetof(CWinLogTarget, lock) == 0x1C,
    "moho::CWinLogTarget::lock offset must be 0x1C"
  );
  static_assert(
    offsetof(CWinLogTarget, mPendingLines) == 0x24,
    "moho::CWinLogTarget::mPendingLines offset must be 0x24"
  );
  static_assert(sizeof(CWinLogTarget) == 0x34, "moho::CWinLogTarget size must be 0x34");
} // namespace moho

/**
 * Address: 0x008CD8C0 (FUN_008CD8C0)
 * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
 *
 * What it does:
 * Allocates/constructs one SupCom frame shell with startup style/size lanes.
 */
[[nodiscard]] WSupComFrame* WX_CreateSupComFrame(
  const char* title, const wxPoint& position, const wxSize& size, std::int32_t style
);

namespace moho
{
  // Main owner window used by WinMain lifecycle paths (`WIN_OkBox`,
  // crash handling, and startup viewport bootstrap).
  //
  // Evidence:
  // - `FUN_004F2800` (`WIN_OkBox`) resolves owner with `sMainWindow->GetHandle()`.
  // - startup frame/bootstrap passes `WSupComFrame` through this global.
  //
  // Keep this typed as the shared wx window base to avoid duplicating ad-hoc
  // runtime-view overlays for each caller.

  /**
   * Runtime viewport base used by startup/device and UI manager bindings.
   *
   * Evidence:
   * - `CScApp::CreateAppFrame` (0x008CF8C0) reads `viewport->m_parent`
   *   before calling `GetHandle()` on both parent and viewport.
   */
  struct WRenViewport : wxWindowMswRuntime
  {
    std::uint8_t mUnknown04To0C[0x08];
    std::int32_t mRenderState0C = -1;
    std::uint8_t mUnknown10To1D[0x0D];
    std::uint8_t mEnabled = 0;
    std::uint8_t mUnknown1ETo2B[0x0E];
    wxWindowBase* m_parent;

    /**
     * Address: 0x00453AA0 (FUN_00453AA0, sub_453AA0)
     *
     * What it does:
     * Resets `mRenderState0C` to `-1` as part of the viewport's
     * per-frame render prep; callers live in the render-camera
     * outline path (`RenderCameraOutline` at 0x007F98A0).
     */
    void ResetRenderState0C() noexcept;

    /**
     * Address: 0x007F8290 (FUN_007F8290, Moho::WRenViewport::RenderMeshes)
     *
     * What it does:
     * Sets the render target, viewport, and color-write state for one viewport
     * mesh pass, then dispatches either skeleton-debug rendering or the normal
     * mesh batch renderer depending on `ren_ShowSkeletons`.
     */
    void RenderMeshes(int meshFlags, bool mirrored);
  };

  static_assert(offsetof(WRenViewport, mRenderState0C) == 0x0C, "moho::WRenViewport::mRenderState0C offset must be 0x0C");
  static_assert(offsetof(WRenViewport, mEnabled) == 0x1D, "moho::WRenViewport::mEnabled offset must be 0x1D");
  static_assert(offsetof(WRenViewport, m_parent) == 0x2C, "moho::WRenViewport::m_parent offset must be 0x2C");

  struct wxPaintEventRuntime
  {
    std::uint8_t mStorage[0x24];
  };

  static_assert(sizeof(wxPaintEventRuntime) == 0x24, "moho::wxPaintEventRuntime size must be 0x24");

  struct wxDCRuntime
  {
    explicit wxDCRuntime(wxWindowBase* ownerWindow) noexcept;

    void SetBrush(const void* brushToken) noexcept;
    void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const noexcept;
    void DoDrawRectangle(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height) noexcept;

  private:
    wxWindowBase* mOwnerWindow = nullptr;
    const void* mActiveBrush = nullptr;
  };

  struct wxPaintDCRuntime : wxDCRuntime
  {
    explicit wxPaintDCRuntime(wxWindowBase* ownerWindow) noexcept;
    ~wxPaintDCRuntime();
  };

  struct WPreviewImageRuntime
  {
    void* lane0 = nullptr;
    void* lane1 = nullptr;
  };

  static_assert(sizeof(WPreviewImageRuntime) == 0x8, "moho::WPreviewImageRuntime size must be 0x8");

  struct WD3DViewport : WRenViewport
  {
    /**
     * Address: 0x00430980 (FUN_00430980)
     * Mangled:
     * ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
     *
     * What it does:
     * Initializes viewport runtime ownership from parent/title/size startup
     * lanes and clears retained D3D-device reference storage.
     */
    WD3DViewport(wxWindowBase* parentWindow, const char* title, const wxPoint& position, const wxSize& size);

    /**
     * Address: 0x00430970 (FUN_00430970)
     * Mangled: ?GetEventTable@WD3DViewport@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this viewport runtime type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x0042BA90 (FUN_0042BA90)
     * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
     *
     * What it does:
     * Releases one held D3D-device reference before base window teardown.
     */
    virtual ~WD3DViewport();

    /**
     * Address: 0x0042BAF0 (FUN_0042BAF0)
     */
    virtual void D3DWindowOnDeviceInit();

    /**
     * Address: 0x0042BB00 (FUN_0042BB00)
     */
    virtual void D3DWindowOnDeviceRender();

    /**
     * Address: 0x0042BB10 (FUN_0042BB10)
     */
    virtual void D3DWindowOnDeviceExit();

    /**
     * Address: 0x0042BB20 (FUN_0042BB20)
     */
    virtual void RenderPreviewImage();

    /**
     * Address: 0x0042BB30 (FUN_0042BB30)
     */
    [[nodiscard]] virtual WPreviewImageRuntime GetPreviewImage() const;

    /**
     * Address: 0x0042BB50 (FUN_0042BB50)
     */
    [[nodiscard]] virtual void* GetPrimBatcher() const;

    /**
     * Address: 0x00430AC0
     * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
     *
     * What it does:
     * Builds one paint-DC for this viewport, then either paints via active
     * D3D device path or draws fallback background.
     */
    void OnPaint(wxPaintEventRuntime& paintEvent);

    /**
     * Address: 0x00430A60 (FUN_00430A60)
     * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
     *
     * What it does:
     * Draws a solid black background over the viewport DC extents.
     */
    void DrawBackgroundImage(wxDCRuntime& deviceContext);

    /**
     * Address: 0x00430B90 (FUN_00430B90)
     * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
     *
     * What it does:
     * Handles cursor message routing for D3D cursor ownership and forwards
     * unhandled messages to base wx window dispatch.
     */
    long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

    static void* sm_eventTable[1];
    void* mD3DDevice = nullptr;
  };

  /**
   * Address: 0x007FA230
   * Mangled:
   * ?REN_CreateGameViewport@Moho@@YAPAVWD3DViewport@1@PAVwxWindow@@VStrArg@gpg@@ABV?$IVector2@H@Wm3@@_N@Z
   */
  [[nodiscard]] WD3DViewport* REN_CreateGameViewport(
    wxWindowBase* parentWindow, const char* title, const wxSize& size, bool hasSecondHead
  );

  // 0x010A6428 in FA.
  extern WRenViewport* ren_Viewport;

  /**
   * Entry stored in the legacy `managedWindows` / `managedFrames` vectors.
   *
   * The first field points to the owning window's head-link slot
   * (`WWinManaged*::mManagedSlotsHead`), and the second field chains all
   * slots associated with the owner.
   */
  struct ManagedWindowSlot
  {
    ManagedWindowSlot** ownerHeadLink = nullptr;
    ManagedWindowSlot* nextInOwnerChain = nullptr;

    /**
     * Address family:
     * - 0x004F7210 (FUN_004F7210)
     * - 0x004F72D0 (FUN_004F72D0)
     *
     * What it does:
     * Detaches this slot from its owner-managed slot chain.
     *
     * Behavior is shared by constructor unwind + explicit owner-unlink paths.
     */
    void UnlinkFromOwner() noexcept;

    /**
     * Address context:
     * - 0x004F40A0 (dialog dtor core)
     * - 0x004F4230 (frame dtor core)
     *
     * What it does:
     * Clears both slot links to the inert state.
     */
    void Clear() noexcept;
  };

  static_assert(sizeof(ManagedWindowSlot) == 0x8, "moho::ManagedWindowSlot size must be 0x8");
  static_assert(
    offsetof(ManagedWindowSlot, ownerHeadLink) == 0x0,
    "moho::ManagedWindowSlot::ownerHeadLink offset must be 0x0"
  );
  static_assert(
    offsetof(ManagedWindowSlot, nextInOwnerChain) == 0x4,
    "moho::ManagedWindowSlot::nextInOwnerChain offset must be 0x4"
  );

  /**
   * Runtime sub-layout used by `WINX_Exit` owner recovery.
   *
   * `mManagedSlotsHead` is the owner anchor used by `managedWindows`.
   */
  struct WWinManagedDialog : wxWindowBase
  {
    std::uint8_t mUnknown04To16F[0x16C];
    ManagedWindowSlot* mManagedSlotsHead = nullptr;

    static WWinManagedDialog* FromManagedSlotHeadLink(ManagedWindowSlot** ownerHeadLink) noexcept;
    static ManagedWindowSlot** NullManagedSlotHeadLinkSentinel() noexcept;

    /**
     * Address: 0x004F7070 (FUN_004F7070)
     *
     * What it does:
     * Returns the current number of dialog-managed registry slots.
     */
    static std::size_t ManagedSlotCount();

    /**
     * Address: 0x004F70A0 (FUN_004F70A0)
     *
     * What it does:
     * Appends one dialog-managed registry slot and links it to `ownerHeadLink`,
     * preserving slot-chain ownership links across vector growth.
     */
    static void AppendManagedSlotForOwner(ManagedWindowSlot** ownerHeadLink);

    /**
     * Address: 0x004F3F50 (FUN_004F3F50, WWinManagedDialog ctor tail)
     *
     * What it does:
     * Registers this dialog's owner-chain head in `managedWindows`.
     */
    void RegisterManagedOwnerSlot();

    /**
     * Address: 0x004F40A0 (FUN_004F40A0, WWinManagedDialog dtor core)
     *
     * What it does:
     * Unlinks and clears all slots currently chained under this dialog owner.
     */
    void ReleaseManagedOwnerSlots();

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);
  };

  static_assert(
    offsetof(WWinManagedDialog, mManagedSlotsHead) == 0x170,
    "moho::WWinManagedDialog::mManagedSlotsHead offset must be 0x170"
  );
  static_assert(sizeof(WWinManagedDialog) == 0x174, "moho::WWinManagedDialog size must be 0x174");

  /**
   * Runtime owner for the precreated log dialog object.
   *
   * Evidence:
   * - constructor body `FUN_004F4270` builds this object on top of
   *   `WWinManagedDialog` and wires all downstream controls/lanes.
   * - dtor body `FUN_004F5380` detaches from target, tears down local
   *   string/vector lanes, and releases managed-owner slots.
   */
  struct WWinLogWindow : WWinManagedDialog
  {
    std::uint8_t mIsInitializingControls = 0;
    std::uint8_t mUnknown175To177[0x3];
    CWinLogTarget* mOwnerTarget = nullptr;
    wxTextCtrlRuntime* mOutputTextControl = nullptr;
    wxTextCtrlRuntime* mFilterTextControl = nullptr;
    std::uint32_t mEnabledCategoriesMask = 0;
    msvc8::string mFilterText;
    wxCheckBoxRuntime* mDebugCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mInfoCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mWarnCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mErrorCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mCustomCategoryCheckBox = nullptr;
    msvc8::vector<msvc8::string> mBufferedLines;
    std::uint32_t mFirstVisibleLine = 0;

    /**
     * Address: 0x004F4270 (FUN_004F4270)
     *
     * What it does:
     * Constructs one managed log-window object and seeds downstream control
     * state lanes.
     */
    WWinLogWindow();

    /**
     * Address: 0x004F5380 (FUN_004F5380)
     * Mangled deleting-dtor thunk: 0x004F5360 (FUN_004F5360)
     *
     * What it does:
     * Detaches from the log-target owner, releases local lane storage, and
     * unlinks managed-owner slots.
     */
    ~WWinLogWindow();

    /**
     * Binds this window instance to one `CWinLogTarget` owner.
     *
     * Used by `WINX_PrecreateLogWindow` publication paths.
     */
    void SetOwnerTarget(CWinLogTarget* ownerTarget) noexcept;

    [[nodiscard]] std::array<wxCheckBoxRuntime*, 5> CategoryCheckBoxes() noexcept;
    [[nodiscard]] std::array<const wxCheckBoxRuntime*, 5> CategoryCheckBoxes() const noexcept;

    /**
     * Address: 0x004F5440 (FUN_004F5440)
     *
     * What it does:
     * Clears output and repopulates committed target lines from buffered replay
     * text entries.
     */
    void ResetCommittedLinesFromBuffer();

    /**
     * Address: 0x004F5840 (FUN_004F5840)
     *
     * What it does:
     * Rebuilds enabled category/filter state from controls and replays matching
     * committed target lines into output.
     */
    void RebuildVisibleLinesFromControls();

    /**
     * Address: 0x004F5AE0 (FUN_004F5AE0)
     *
     * What it does:
     * Applies one committed line against filter/category state and appends it to
     * output and replay buffer state.
     */
    void AppendCommittedLine(const CWinLogLine& line);

    void OnTargetPendingLinesChanged();

    /**
     * Address: 0x004F6470 (FUN_004F6470)
     *
     * What it does:
     * Merges pending target lines and refreshes visible output when committed
     * line count changed.
     */
    void OnTargetPendingLinesChanged(const CLogAdditionEvent& event);

    /**
     * Address: 0x004F6760 (FUN_004F6760)
     *
     * What it does:
     * Clears `mOwnerTarget->dialog` under the target lock.
     */
    void DetachFromTarget();

    [[nodiscard]] bool ShouldDisplayCommittedLine(const CWinLogLine& line) const;
    [[nodiscard]] std::wstring BuildReplayFlushText(std::size_t startIndex) const;
    [[nodiscard]] std::wstring BuildFormattedCommittedLineText(const CWinLogLine& line) const;

  private:
    void InitializeFromUserPreferences();
    void RestoreCategoryStateFromPreferences(IUserPrefs* preferences);
    void RestoreFilterFromPreferences(IUserPrefs* preferences);
    void RestoreGeometryFromPreferences(IUserPrefs* preferences);
  };

  static_assert(
    offsetof(WWinLogWindow, mOwnerTarget) == 0x178,
    "moho::WWinLogWindow::mOwnerTarget offset must be 0x178"
  );
  static_assert(
    offsetof(WWinLogWindow, mOutputTextControl) == 0x17C,
    "moho::WWinLogWindow::mOutputTextControl offset must be 0x17C"
  );
  static_assert(
    offsetof(WWinLogWindow, mFilterTextControl) == 0x180,
    "moho::WWinLogWindow::mFilterTextControl offset must be 0x180"
  );
  static_assert(
    offsetof(WWinLogWindow, mEnabledCategoriesMask) == 0x184,
    "moho::WWinLogWindow::mEnabledCategoriesMask offset must be 0x184"
  );
  static_assert(
    offsetof(WWinLogWindow, mFilterText) == 0x188,
    "moho::WWinLogWindow::mFilterText offset must be 0x188"
  );
  static_assert(
    offsetof(WWinLogWindow, mDebugCategoryCheckBox) == 0x1A4,
    "moho::WWinLogWindow::mDebugCategoryCheckBox offset must be 0x1A4"
  );
  static_assert(
    offsetof(WWinLogWindow, mCustomCategoryCheckBox) == 0x1B4,
    "moho::WWinLogWindow::mCustomCategoryCheckBox offset must be 0x1B4"
  );
  static_assert(
    offsetof(WWinLogWindow, mBufferedLines) == 0x1B8,
    "moho::WWinLogWindow::mBufferedLines offset must be 0x1B8"
  );
  static_assert(
    offsetof(WWinLogWindow, mFirstVisibleLine) == 0x1C8,
    "moho::WWinLogWindow::mFirstVisibleLine offset must be 0x1C8"
  );
  static_assert(sizeof(WWinLogWindow) == 0x1CC, "moho::WWinLogWindow size must be 0x1CC");

  /**
   * Runtime sub-layout used by `WINX_Exit` owner recovery.
   *
   * `mManagedSlotsHead` is the owner anchor used by `managedFrames`.
   */
  struct WWinManagedFrame : wxWindowBase
  {
    std::uint8_t mUnknown04To177[0x174];
    ManagedWindowSlot* mManagedSlotsHead = nullptr;

    static WWinManagedFrame* FromManagedSlotHeadLink(ManagedWindowSlot** ownerHeadLink) noexcept;
    static ManagedWindowSlot** NullManagedSlotHeadLinkSentinel() noexcept;

    /**
     * Address: 0x004F7140 (FUN_004F7140)
     *
     * What it does:
     * Returns the current number of frame-managed registry slots.
     */
    static std::size_t ManagedSlotCount();

    /**
     * Address: 0x004F7170 (FUN_004F7170)
     *
     * What it does:
     * Appends one frame-managed registry slot and links it to `ownerHeadLink`,
     * preserving slot-chain ownership links across vector growth.
     */
    static void AppendManagedSlotForOwner(ManagedWindowSlot** ownerHeadLink);

    /**
     * Address: 0x004F40E0 (FUN_004F40E0, WWinManagedFrame ctor tail)
     *
     * What it does:
     * Registers this frame's owner-chain head in `managedFrames`.
     */
    void RegisterManagedOwnerSlot();

    /**
     * Address: 0x004F4230 (FUN_004F4230, WWinManagedFrame dtor core)
     *
     * What it does:
     * Unlinks and clears all slots currently chained under this frame owner.
     */
    void ReleaseManagedOwnerSlots();

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);
  };

  static_assert(
    offsetof(WWinManagedFrame, mManagedSlotsHead) == 0x178,
    "moho::WWinManagedFrame::mManagedSlotsHead offset must be 0x178"
  );
  static_assert(sizeof(WWinManagedFrame) == 0x17C, "moho::WWinManagedFrame size must be 0x17C");

  // Compatibility aliases while older call sites transition to owning names.
  using WWinManagedDialogRuntime = WWinManagedDialog;
  using WWinManagedFrameRuntime = WWinManagedFrame;

  // 0x010A9B94 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedWindows;
  // 0x010A9BD8 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedFrames;
  // 0x010A63B8 in FA.
  extern wxWindowBase* sMainWindow;
} // namespace moho
