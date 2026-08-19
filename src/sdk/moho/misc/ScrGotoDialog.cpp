#include "moho/misc/ScrGotoDialog.h"

#include <cstdint>
#include <cstdlib>
#include <map>
#include <vector>

#include "moho/misc/StartupHelpers.h"

namespace
{
  // -------------------------------------------------------------------------
  // Literals and constants the constructor at 0x004BB730 references.
  // -------------------------------------------------------------------------

  // `aWindowsDebugGo_0` (0x00E07EFC) and `aWindowsDebugGo` (0x00E07EE4).
  constexpr char kGotoWindowXPreferenceKey[] = "Windows.Debug.Goto.x";
  constexpr char kGotoWindowYPreferenceKey[] = "Windows.Debug.Goto.y";

  // `aScrgotodialog` (0x00E07EC8) - the wx window name of the dialog itself.
  constexpr wchar_t kGotoDialogWindowName[] = L"ScrGotoDialog";

  // `aGoto_0` (0x00E07F14). The binary folds all three uses onto the one
  // literal: the dialog title, the prompt label and the default button label.
  constexpr wchar_t kGotoText[] = L"Goto";

  // `aCancel` (0x00E07F20).
  constexpr wchar_t kCancelText[] = L"Cancel";

  // wx's shared default control names, from `wxWindows-2.4.2/src/msw/data.cpp`.
  // The binary passes the exported globals `wxStaticTextNameStr`,
  // `wxTextCtrlNameStr` and `wxButtonNameStr`, not literals.
  constexpr wchar_t kWxStaticTextNameStr[] = L"message";
  constexpr wchar_t kWxTextCtrlNameStr[] = L"text";
  constexpr wchar_t kWxButtonNameStr[] = L"button";
  constexpr wchar_t kWxEmptyString[] = L"";

  // `wxValidator const wxDefaultValidator` (0x00F8F7C4). This tree does not
  // model wxValidator, and `wxWindowBase::SetValidator` takes an opaque lane,
  // so the shared "no validator installed" value is spelled out here.
  constexpr const void* kWxDefaultValidator = nullptr;

  // 20000800h, pushed at 0x004BB820: wxCAPTION (0x20000000) | wxSYSTEM_MENU
  // (0x0800) from `wx/defs.h`. No resize border and no close box.
  constexpr long kGotoDialogStyle = 0x20000800L;
  constexpr long kNoWindowStyle = 0L;

  // wxID_ANY / wxDefaultCoord, and the wxID_OK / wxID_CANCEL command ids the
  // binary pushes as 13ECh (0x004BBC7A) and 13EDh (0x004BBDB0). The modal
  // result the debug window tests for is the same 13ECh.
  constexpr std::int32_t kWxIdAny = -1;
  constexpr std::int32_t kWxIdOk = 5100;
  constexpr std::int32_t kWxIdCancel = 5101;
  constexpr std::int32_t kNoStoredCoordinate = -1;

  constexpr wxPoint kWxDefaultPosition{-1, -1};
  constexpr wxSize kWxDefaultSize{-1, -1};

  // The two explicit control extents: 60h x -1 for the line entry
  // (0x004BBB58) and 30h x -1 for both push buttons (0x004BBC89, 0x004BBDC2).
  constexpr wxSize kLineEntrySize{96, -1};
  constexpr wxSize kDialogButtonSize{48, -1};

  // `wx/defs.h` orientations and directions. The three layout flag words the
  // binary pushes are 50h, 70h and D0h.
  constexpr std::int32_t kWxHorizontal = 0x0004;
  constexpr std::int32_t kWxVertical = 0x0008;
  constexpr std::int32_t kWxLeft = 0x0010;
  constexpr std::int32_t kWxRight = 0x0020;
  constexpr std::int32_t kWxTop = 0x0040;
  constexpr std::int32_t kWxBottom = 0x0080;

  constexpr std::int32_t kNoStretch = 0;
  constexpr std::int32_t kNoLayoutFlags = 0;
  constexpr std::int32_t kNoBorder = 0;
  constexpr std::int32_t kControlBorderPixels = 10;

  // -------------------------------------------------------------------------
  // wx pieces this dialog builds that the SDK does not model yet.
  //
  // Every object below lives in the wxWidgets half of the binary, reached
  // through `wxBoxSizer::wxBoxSizer` (an import), `sub_4BB0F0`
  // (`wxStaticText::wxStaticText`, `wxControl::wxControl` + `Create`) and
  // `sub_4BAC30` (`wxButton::wxButton`, same shape). wx object layout is not
  // mirrored in this tree - see the note on `wxIcon` in `WxRuntimeTypes.h` -
  // so the allocation sizes the binary passes to `operator new` are recorded
  // in comments and the create arguments are held by name.
  //
  // Ownership follows wx exactly: raw pointers throughout, released by
  // `~wxSizer` / `~wxWindow`, neither of which this tree models.
  // -------------------------------------------------------------------------

  /**
   * Minimal recovered `wxStaticText` runtime view.
   *
   * `operator new(0x130)` at 0x004BB9B1, then `sub_4BB0F0(parent, id, label,
   * pos, size, style, name)` at 0x004BBA39.
   */
  class wxStaticTextRuntimeView final : public wxControlRuntime
  {
  public:
    wxStaticTextRuntimeView(
      wxWindowBase* const parentWindow,
      const std::int32_t controlId,
      const wchar_t* const labelText,
      const wxPoint& position,
      const wxSize& size,
      const long style,
      const wchar_t* const windowName
    )
    {
      // `wxControlBase::CreateControl`: shared window state, then the parent
      // takes the control into its child list.
      (void)CreateBase(parentWindow, controlId, position, size, style, wxStringRuntime::Borrow(windowName));
      SetLabel(wxStringRuntime::Borrow(labelText));
      if (parentWindow != nullptr) {
        parentWindow->AddChild(this);
      }
    }
  };

  /**
   * Minimal recovered `wxButton` runtime view.
   *
   * `operator new(0x130)` at 0x004BBBF7 and 0x004BBD2D, then `sub_4BAC30(
   * parent, id, label, pos, size, style, validator, name)` at 0x004BBC99 and
   * 0x004BBDD2.
   */
  class wxButtonRuntimeView final : public wxControlRuntime
  {
  public:
    wxButtonRuntimeView(
      wxWindowBase* const parentWindow,
      const std::int32_t controlId,
      const wchar_t* const labelText,
      const wxPoint& position,
      const wxSize& size,
      const long style,
      const void* const validator,
      const wchar_t* const windowName
    )
      : mParentWindow(parentWindow)
    {
      (void)CreateBase(parentWindow, controlId, position, size, style, wxStringRuntime::Borrow(windowName));
      SetValidator(validator);
      SetLabel(wxStringRuntime::Borrow(labelText));
      if (parentWindow != nullptr) {
        parentWindow->AddChild(this);
      }
    }

    /**
     * `wxButton::SetDefault`, the slot `+0x220` virtual the constructor
     * dispatches to at 0x004BBD16. wx hands the button to the owning dialog,
     * which is what makes Return activate it.
     */
    void SetDefault()
    {
      if (mParentWindow != nullptr) {
        (void)mParentWindow->SetDefaultItem(this);
      }
    }

  private:
    wxWindowBase* mParentWindow = nullptr;
  };

  /**
   * Minimal recovered `wxBoxSizer` runtime view.
   *
   * Three of these are built - `operator new(0x60)` at 0x004BB8CD,
   * 0x004BB91B and 0x004BB950, each followed by the
   * `wxBoxSizer::wxBoxSizer(int orientation)` import. The two `Add` overloads
   * are the `wxSizer` vtable slots the constructor dispatches through: `+0x14`
   * takes a nested sizer, `+0x18` takes a window. Naming them keeps the
   * recovered body free of slot arithmetic.
   */
  class wxBoxSizerRuntimeView final
  {
  public:
    struct Item
    {
      wxBoxSizerRuntimeView* childSizer = nullptr;
      wxWindowBase* window = nullptr;
      std::int32_t proportion = 0;
      std::int32_t layoutFlags = 0;
      std::int32_t borderPixels = 0;
      void* userData = nullptr;
    };

    explicit wxBoxSizerRuntimeView(const std::int32_t orientation) noexcept
      : mOrientation(orientation)
    {
    }

    void Add(
      wxBoxSizerRuntimeView* const childSizer,
      const std::int32_t proportion,
      const std::int32_t layoutFlags,
      const std::int32_t borderPixels,
      void* const userData
    )
    {
      mItems.push_back(Item{childSizer, nullptr, proportion, layoutFlags, borderPixels, userData});
    }

    void Add(
      wxWindowBase* const window,
      const std::int32_t proportion,
      const std::int32_t layoutFlags,
      const std::int32_t borderPixels,
      void* const userData
    )
    {
      mItems.push_back(Item{nullptr, window, proportion, layoutFlags, borderPixels, userData});
    }

    /**
     * `wxSizer::SetSizeHints(wxWindow*)`, the import called at 0x004BBE65:
     * the sizer's minimum becomes the window's minimum, so the dialog cannot
     * be shrunk below its contents.
     */
    void SetSizeHints(wxWindowBase* const window) noexcept
    {
      mSizeHintWindow = window;
    }

    // wxBOXSIZER's `m_orient`, wx's `m_children` list, and the window
    // `SetSizeHints` was pointed at. Held in the open the way the other
    // file-local wx state views in this tree are.
    std::int32_t mOrientation = 0;
    wxWindowBase* mSizeHintWindow = nullptr;
    std::vector<Item> mItems{};
  };

  /**
   * `wxWindowBase::SetSizer(wxSizer*, bool deleteOld)`, the import called at
   * 0x004BBE6F with `deleteOld = true`.
   *
   * wx parks the top-level sizer in `wxWindowBase::m_windowSizer`; this tree's
   * `wxWindowBase` view carries no sizer lane, so the pointer lives beside the
   * window in the same side-table shape `WxRuntimeTypes.cpp` uses for every
   * other piece of unmodelled wx state.
   */
  void SetWindowSizer(
    wxWindowBase* const window,
    wxBoxSizerRuntimeView* const sizer,
    const bool deleteOldSizer
  )
  {
    static std::map<const wxWindowBase*, wxBoxSizerRuntimeView*> sizerByWindow;

    const auto existing = sizerByWindow.find(window);
    if (existing == sizerByWindow.end()) {
      sizerByWindow.emplace(window, sizer);
      return;
    }

    if (deleteOldSizer) {
      delete existing->second;
    }
    existing->second = sizer;
  }

  /**
   * Builds the line-number entry field.
   *
   * `operator new(0x16C)` at 0x004BBAC7 then `wxTextCtrl::wxTextCtrl(parent,
   * -1, wxEmptyString, wxDefaultPosition, wxSize(96, -1), 0,
   * wxDefaultValidator, wxTextCtrlNameStr)` at 0x004BBB68. `wxTextCtrlRuntime`
   * already exists in this tree but carries no create-argument constructor, so
   * the wx `Create` sequence is spelled out here.
   */
  [[nodiscard]] wxTextCtrlRuntime* CreateLineEntryControl(
    wxWindowBase* const parentWindow,
    const std::int32_t controlId,
    const wchar_t* const initialValue,
    const wxPoint& position,
    const wxSize& size,
    const long style,
    const void* const validator,
    const wchar_t* const windowName
  )
  {
    auto* const control = new wxTextCtrlRuntime();
    (void)control->CreateBase(parentWindow, controlId, position, size, style, wxStringRuntime::Borrow(windowName));
    control->SetValidator(validator);
    if (initialValue != nullptr && initialValue[0] != L'\0') {
      control->SetValue(wxStringRuntime::Borrow(initialValue));
    }
    if (parentWindow != nullptr) {
      parentWindow->AddChild(control);
    }
    return control;
  }

  /**
   * The two `Moho::USER_GetPreferences()->GetInteger(...)` reads between
   * 0x004BB7A6 and 0x004BB80E.
   *
   * The binary asks the preference singleton once per axis and defaults both
   * to -1 (wxDefaultCoord), so a dialog that has never been moved opens
   * wherever wx decides to put it. The y read is issued first; both are pure
   * lookups, so the order only matters for faithfulness.
   */
  [[nodiscard]] wxPoint ReadPersistedDialogPosition()
  {
    const std::int32_t positionY = moho::USER_GetPreferences()->GetInteger(
      msvc8::string(kGotoWindowYPreferenceKey),
      kNoStoredCoordinate
    );
    const std::int32_t positionX = moho::USER_GetPreferences()->GetInteger(
      msvc8::string(kGotoWindowXPreferenceKey),
      kNoStoredCoordinate
    );
    return wxPoint{positionX, positionY};
  }
} // namespace

wxEventTable moho::ScrGotoDialog::sm_eventTable = {nullptr, nullptr};

/**
 * Address: 0x004BB730 (FUN_004BB730)
 * Mangled: ??0ScrGotoDialog@Moho@@QAE@@Z
 *
 * IDA signature:
 * Moho::ScrGotoDialog *__thiscall Moho::ScrGotoDialog::ScrGotoDialog(Moho::ScrGotoDialog *this);
 *
 * What it does:
 * Builds the script-debugger "Goto line" dialog. Restores the last screen
 * position from the `Windows.Debug.Goto.x` / `Windows.Debug.Goto.y` user
 * preferences, runs the `wxDialog` base with title "Goto", window name
 * "ScrGotoDialog" and style `wxCAPTION|wxSYSTEM_MENU`, then fills it with a
 * vertical box sizer holding two horizontal rows: a "Goto" prompt label plus
 * the line-number entry field, and the default "Goto" button plus "Cancel".
 * `mIsInitializing` stays set for the whole build so the move handler at
 * 0x004BBEB0 does not write the transient placement back to preferences.
 */
moho::ScrGotoDialog::ScrGotoDialog()
  : wxDialogRuntime(
      nullptr,
      kWxIdAny,
      wxStringRuntime::Borrow(kGotoText),
      ReadPersistedDialogPosition(),
      kWxDefaultSize,
      kGotoDialogStyle,
      wxStringRuntime::Borrow(kGotoDialogWindowName)
    )
{
  mIsInitializing = 1u;

  auto* const frameSizer = new wxBoxSizerRuntimeView(kWxVertical);
  auto* const promptRowSizer = new wxBoxSizerRuntimeView(kWxHorizontal);
  auto* const buttonRowSizer = new wxBoxSizerRuntimeView(kWxHorizontal);

  frameSizer->Add(promptRowSizer, kNoStretch, kNoLayoutFlags, kNoBorder, nullptr);
  frameSizer->Add(buttonRowSizer, kNoStretch, kNoLayoutFlags, kNoBorder, nullptr);

  auto* const promptLabel = new wxStaticTextRuntimeView(
    this,
    kWxIdAny,
    kGotoText,
    kWxDefaultPosition,
    kWxDefaultSize,
    kNoWindowStyle,
    kWxStaticTextNameStr
  );
  promptRowSizer->Add(promptLabel, kNoStretch, kWxTop | kWxLeft, kControlBorderPixels, nullptr);

  mLineTextControl = CreateLineEntryControl(
    this,
    kWxIdAny,
    kWxEmptyString,
    kWxDefaultPosition,
    kLineEntrySize,
    kNoWindowStyle,
    kWxDefaultValidator,
    kWxTextCtrlNameStr
  );
  promptRowSizer->Add(mLineTextControl, kNoStretch, kWxTop | kWxRight | kWxLeft, kControlBorderPixels, nullptr);

  auto* const gotoButton = new wxButtonRuntimeView(
    this,
    kWxIdOk,
    kGotoText,
    kWxDefaultPosition,
    kDialogButtonSize,
    kNoWindowStyle,
    kWxDefaultValidator,
    kWxButtonNameStr
  );
  gotoButton->SetDefault();
  buttonRowSizer->Add(gotoButton, kNoStretch, kWxBottom | kWxTop | kWxLeft, kControlBorderPixels, nullptr);

  auto* const cancelButton = new wxButtonRuntimeView(
    this,
    kWxIdCancel,
    kCancelText,
    kWxDefaultPosition,
    kDialogButtonSize,
    kNoWindowStyle,
    kWxDefaultValidator,
    kWxButtonNameStr
  );
  buttonRowSizer->Add(cancelButton, kNoStretch, kWxBottom | kWxTop | kWxLeft, kControlBorderPixels, nullptr);

  frameSizer->SetSizeHints(this);
  SetWindowSizer(this, frameSizer, true);

  mIsInitializing = 0u;
}

/**
 * Address: 0x004BBEA0 (FUN_004BBEA0)
 *
 * What it does:
 * Runs non-deleting teardown for one script goto dialog instance.
 */
moho::ScrGotoDialog* moho::ScrGotoDialog::DestroyWithoutDelete(ScrGotoDialog* const object) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  return reinterpret_cast<ScrGotoDialog*>(
    wxDialogRuntime::DeleteWithFlag(static_cast<wxDialogRuntime*>(object), 0u)
  );
}

/**
 * Address: 0x004BC0C0 (FUN_004BC0C0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for one script goto dialog.
 */
moho::ScrGotoDialog* moho::ScrGotoDialog::DeleteWithFlag(
  ScrGotoDialog* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  DestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004BC0F0 (FUN_004BC0F0)
 *
 * What it does:
 * Returns this dialog runtime event-table lane.
 */
const void* moho::ScrGotoDialog::GetEventTable() const
{
  return &sm_eventTable;
}

/**
 * Address: 0x004BBEB0 (FUN_004BBEB0)
 *
 * What it does:
 * Persists goto-dialog window position to user preferences after move
 * handling when startup initialization has completed.
 */
void moho::ScrGotoDialog::PersistWindowPositionToPreferences()
{
  if (mIsInitializing != 0u) {
    return;
  }

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (preferences == nullptr) {
    return;
  }

  std::int32_t windowX = 0;
  std::int32_t windowY = 0;
  DoGetPosition(&windowX, &windowY);

  preferences->SetInteger(msvc8::string(kGotoWindowXPreferenceKey), windowX);
  preferences->SetInteger(msvc8::string(kGotoWindowYPreferenceKey), windowY);
}

/**
 * Address: 0x004BBFF0 (FUN_004BBFF0)
 *
 * What it does:
 * Reads goto-line text input and converts it to an integer line index.
 */
int moho::ScrGotoDialog::ParseRequestedLineNumber() const
{
  const msvc8::string lineTextUtf8 = mLineTextControl->GetValueUtf8();
  return std::atoi(lineTextUtf8.c_str());
}

