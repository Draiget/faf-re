#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "boost/mutex.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

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

class wxWindowBase
{
public:
  virtual void* GetClassInfo() const { return nullptr; }
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
  virtual void SetTitle(const void* title) { (void)title; }
  virtual void* GetTitle() const { return nullptr; }
  virtual void SetLabel(const void* label) { (void)label; }
  virtual void* GetLabel() const { return nullptr; }
  virtual void SetName(const void* name) { (void)name; }
  virtual void* GetName() const { return nullptr; }
  virtual void Raise() {}
  virtual void Lower() {}
  virtual wxPoint GetClientAreaOrigin() const { return wxPoint{}; }
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
  virtual std::int32_t GetMinWidth() const { return 0; }
  virtual std::int32_t GetMinHeight() const { return 0; }
  virtual wxSize GetMaxSize() const { return wxSize{}; }
  virtual void DoSetVirtualSize(std::int32_t width, std::int32_t height)
  {
    (void)width;
    (void)height;
  }
  virtual wxSize DoGetVirtualSize() const { return wxSize{}; }
  virtual wxSize GetBestVirtualSize() const { return wxSize{}; }

  /**
   * Address: 0x00967820
   * Mangled: ?Show@wxWindow@@UAE_N_N@Z
   */
  virtual bool Show(bool show)
  {
    (void)show;
    return false;
  }
  virtual bool Enable(bool enable)
  {
    (void)enable;
    return false;
  }
  virtual void SetWindowStyleFlag(long style) { (void)style; }
  virtual long GetWindowStyleFlag() const { return 0; }
  virtual bool IsRetained() const { return false; }
  virtual void SetExtraStyle(long style) { (void)style; }
  virtual void MakeModal(bool modal) { (void)modal; }
  virtual void SetThemeEnabled(bool enabled) { (void)enabled; }
  virtual bool GetThemeEnabled() const { return false; }

  /**
   * Address: 0x00967650
   * Mangled: ?SetFocus@wxWindow@@UAEXXZ
   */
  virtual void SetFocus() {}
  virtual void SetFocusFromKbd() {}
  virtual bool AcceptsFocus() const { return false; }
  virtual bool AcceptsFocusFromKeyboard() const { return false; }
  virtual void* GetDefaultItem() const { return nullptr; }
  virtual void* SetDefaultItem(void* defaultItem)
  {
    return defaultItem;
  }
  virtual void SetTmpDefaultItem(void* defaultItem) { (void)defaultItem; }
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
  virtual bool HasCapture() const { return false; }
  virtual void Refresh(bool eraseBackground, const void* updateRect)
  {
    (void)eraseBackground;
    (void)updateRect;
  }
  virtual void Update() {}
  virtual void Clear() {}
  virtual void Freeze() {}
  virtual void Thaw() {}
  virtual void PrepareDC(void* deviceContext) { (void)deviceContext; }
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
  virtual bool ScrollLines(std::int32_t lines)
  {
    (void)lines;
    return false;
  }
  virtual bool ScrollPages(std::int32_t pages)
  {
    (void)pages;
    return false;
  }
  virtual void SetDropTarget(void* dropTarget) { (void)dropTarget; }
  virtual void* GetDropTarget() const { return nullptr; }
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
  virtual void DoReleaseMouse() {}
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
  virtual void DoGetClientSize(std::int32_t* outWidth, std::int32_t* outHeight)
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
  virtual bool ContainsHWND(unsigned long nativeHandle) const
  {
    (void)nativeHandle;
    return false;
  }
  virtual unsigned long MSWGetStyle(long style, unsigned long* extendedStyle) const
  {
    (void)style;
    (void)extendedStyle;
    return 0;
  }
  virtual unsigned long MSWGetParent() const { return 0; }
  virtual bool MSWCommand(unsigned int commandId, unsigned short notificationCode)
  {
    (void)commandId;
    (void)notificationCode;
    return false;
  }
  virtual void* CreateWindowFromHWND(void* parent, unsigned long nativeHandle)
  {
    (void)parent;
    (void)nativeHandle;
    return nullptr;
  }
  virtual void AdoptAttributesFromHWND() {}
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
  virtual void MSWDestroyWindow() {}
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
  virtual void ControlSlot131() {}
  virtual bool MSWOnDraw(void** drawStruct)
  {
    (void)drawStruct;
    return false;
  }
  virtual bool MSWOnMeasure(void** measureStruct)
  {
    (void)measureStruct;
    return false;
  }
};

static_assert(sizeof(wxControlRuntime) == 0x4, "wxControlRuntime size must be 0x4");

struct wxStringRuntime
{
  wchar_t* m_pchData = nullptr;

  [[nodiscard]] const wchar_t* c_str() const noexcept;
  [[nodiscard]] msvc8::string ToUtf8() const;
  [[nodiscard]] msvc8::string ToUtf8Lower() const;

  [[nodiscard]] static wxStringRuntime Borrow(const wchar_t* text) noexcept;
};

static_assert(sizeof(wxStringRuntime) == 0x4, "wxStringRuntime size must be 0x4");

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
  virtual bool IsFullScreen() const { return false; }
  virtual bool IsOneOfBars(const void* window) const
  {
    (void)window;
    return false;
  }
};

static_assert(sizeof(wxWindowBase) == 0x4, "wxWindowBase size must be 0x4");
static_assert(sizeof(wxTopLevelWindowRuntime) == 0x4, "wxTopLevelWindowRuntime size must be 0x4");

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
  virtual int OnExit() = 0;

  virtual void OnFatalException() = 0;
  virtual int MainLoop() = 0;
  virtual void ExitMainLoop() = 0;
  virtual bool Initialized() = 0;

  /**
   * Address: 0x00992230
   * Mangled: ?Pending@wxApp@@UAE_NXZ
   */
  virtual bool Pending() = 0;

  /**
   * Address: 0x00992250
   * Mangled: ?Dispatch@wxApp@@UAEXXZ
   */
  virtual void Dispatch() = 0;

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
  virtual bool ProcessIdle() = 0;
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
  virtual bool DoMessage() = 0;
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

namespace moho
{
  struct ManagedWindowSlot;
  struct WWinManagedDialog;
  class IUserPrefs;
  class CWinLogTarget;
  class WWinLogWindow;
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
  struct WRenViewport : wxWindowBase
  {
    std::uint8_t mUnknown04To2B[0x28];
    wxWindowBase* m_parent;
  };

  static_assert(offsetof(WRenViewport, m_parent) == 0x2C, "moho::WRenViewport::m_parent offset must be 0x2C");

  struct wxPaintEventRuntime
  {
    std::uint8_t mStorage[0x24];
  };

  static_assert(sizeof(wxPaintEventRuntime) == 0x24, "moho::wxPaintEventRuntime size must be 0x24");

  struct WD3DViewport : WRenViewport
  {
    /**
     * Address: 0x00430AC0
     * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
     */
    void OnPaint(wxPaintEventRuntime& paintEvent);
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
