#include "moho/app/WxPrivate.h"


/**
 * The managed-window registries (elements at 0x010A9B94 / 0x010A9BD8).
 *
 * Everything else about them is compiler-generated: the exit-time destructor
 * registrations 0x00BC7320 / 0x00BC7330, their thunks 0x00BF18B0 /
 * 0x00BF18C0, and the vector destructor bodies 0x004F8180 / 0x004F82D0,
 * whose WeakPtr destructors unlink each slot from its window.
 */
fa::vector<moho::WeakPtr<moho::WWinManagedDialog>> moho::managedWindows;
fa::vector<moho::WeakPtr<moho::WWinManagedFrame>> moho::managedFrames;
wxWindow* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;

/**
 * Address: 0x004F3F50 (FUN_004F3F50)
 *
 * What it does:
 * Creates the dialog through wxDialog's constructor (the inline copy at
 * 0x004A3900), then files it in the first free `managedWindows` slot or a new
 * one.
 */
moho::WWinManagedDialog::WWinManagedDialog(
  wxWindow* const parent,
  const wxWindowID id,
  const wxString& title,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxString& name
)
  : wxDialog(parent, id, title, position, size, style, name)
  , WeakObject()
{
  for (std::size_t index = 0; index < managedWindows.size(); ++index) {
    if (managedWindows[index].GetObjectPtr() == nullptr) {
      managedWindows[index].Set(this);
      return;
    }
  }
  managedWindows.push_back(WeakPtr<WWinManagedDialog>(this));
}

/**
 * Address: 0x004F40A0 (FUN_004F40A0)
 *
 * What it does:
 * Nothing of its own: the `WeakObject` base drops the weak references
 * (0x004F40AE), then ~wxDialog follows.
 */
moho::WWinManagedDialog::~WWinManagedDialog() = default;

/**
 * Address: 0x004F40E0 (FUN_004F40E0)
 * Mangled: ??0WWinManagedFrame@Moho@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
 *
 * What it does:
 * Creates the frame through wxFrame's constructor (the inline copy at
 * 0x004BAB30), then files it in the first free `managedFrames` slot or a new
 * one.
 */
moho::WWinManagedFrame::WWinManagedFrame(
  wxWindow* const parent,
  const wxWindowID id,
  const wxString& title,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxString& name
)
  : wxFrame(parent, id, title, position, size, style, name)
  , WeakObject()
{
  for (std::size_t index = 0; index < managedFrames.size(); ++index) {
    if (managedFrames[index].GetObjectPtr() == nullptr) {
      managedFrames[index].Set(this);
      return;
    }
  }
  managedFrames.push_back(WeakPtr<WWinManagedFrame>(this));
}

/**
 * Address: 0x004F4230 (FUN_004F4230)
 *
 * What it does:
 * Nothing of its own: the `WeakObject` base drops the weak references
 * (0x004F423E), then ~wxFrame follows.
 */
moho::WWinManagedFrame::~WWinManagedFrame() = default;

// MohoApp's constructor (0x004F1F10) and destructor are the compiler's; the
// argv release at 0x00992070 is wxApp::~wxApp. It overrides only OnInit
// (slot 11) and ExitMainLoop (slot 17) of wxApp's 42: slot 14, OnExit, is
// still wxAppBase::OnExit (0x009AA860). 0x007FA110 - D3D_Exit then clear
// sMainWindow and ren_Viewport - is not in the vtable and nothing in the
// image references it.

/**
 * Address: 0x004F1E50 (FUN_004F1E50)
 * Mangled: ?OnInit@MohoApp@Moho@@UAE_NXZ
 *
 * What it does:
 * Returns true: the engine initialises itself after wxEntry returns.
 */
bool moho::MohoApp::OnInit()
{
  return true;
}

/**
 * Address: 0x004F1E80 (FUN_004F1E80)
 * Mangled: ?ExitMainLoop@MohoApp@Moho@@UAEXXZ
 *
 * What it does:
 * Clears wxApp::m_keepGoing, which WIN_AppExecute's loop polls.
 */
void moho::MohoApp::ExitMainLoop()
{
  m_keepGoing = FALSE;
}
namespace
{

// ---------------------------------------------------------------------------
// WBitmapPanel
// ---------------------------------------------------------------------------

  /**
   * Address: 0x004FBC20 (FUN_004FBC20)
   *
   * What it does:
   * Draws `bitmap` over `rect` in tiles, column by column (the wxWidgets
   * sample's TileBitmap). The DC and the rectangle arrive in registers.
   */
  void TileBitmap(const wxRect& rect, wxDC& dc, wxBitmap& bitmap)
  {
    const int width = bitmap.GetWidth();
    const int height = bitmap.GetHeight();
    for (int x = rect.x; x < rect.x + rect.width; x += width) {
      for (int y = rect.y; y < rect.y + rect.height; y += height) {
        dc.DrawBitmap(bitmap, x, y);
      }
    }
  }
}


/**
 * Address: 0x004FBCC0 (FUN_004FBCC0)
 * Mangled: ??0WBitmapPanel@Moho@@QAE@PAVwxWindow@@PAVwxBitmap@@@Z
 *
 * What it does:
 * Creates the panel with wxPanel's defaults (the inline copy at 0x004FB890)
 * and keeps `bitmap`.
 */
moho::WBitmapPanel::WBitmapPanel(
  wxWindow* const parentWindow,
  wxBitmap* const bitmap
)
  : wxPanel(parentWindow)
  , mBitmap(bitmap)
{}

// Table 0x00DFF48C = {&wxPanel::sm_eventTable (0x00D5A910), rows 0x00F59814};
// GetEventTable (0x004FBCB0) comes with it.
BEGIN_EVENT_TABLE(moho::WBitmapPanel, wxPanel)
  EVT_ERASE_BACKGROUND(moho::WBitmapPanel::OnEraseBackground)
END_EVENT_TABLE()

/**
 * Address: 0x004FBD90 (FUN_004FBD90)
 * Mangled: ?OnEraseBackground@WBitmapPanel@Moho@@IAEXAAVwxEraseEvent@@@Z
 *
 * What it does:
 * Tiles the bitmap over the client area into the erase event's DC; without a
 * usable bitmap the event is skipped so the default erase runs.
 */
void moho::WBitmapPanel::OnEraseBackground(wxEraseEvent& eraseEvent)
{
  if (mBitmap == nullptr || !mBitmap->Ok()) {
    eraseEvent.Skip();
    return;
  }

  int width = 0;
  int height = 0;
  GetClientSize(&width, &height);
  TileBitmap(wxRect(0, 0, width, height), *eraseEvent.GetDC(), *mBitmap);
}

// ---------------------------------------------------------------------------
// WBitmapCheckBox
// ---------------------------------------------------------------------------

/**
 * Address: 0x004FBE30 (FUN_004FBE30)
 * Mangled: ??0WBitmapCheckBox@Moho@@QAE@PAVwxWindow@@HABVwxBitmap@@@Z
 *
 * What it does:
 * Creates the button with style 0 (not wxBU_AUTODRAW; the inline copy of
 * wxBitmapButton's constructor at 0x004FBB60) and starts unchecked.
 */
moho::WBitmapCheckBox::WBitmapCheckBox(
  wxWindow* const parentWindow,
  const int controlId,
  const wxBitmap& bitmap
)
  : wxBitmapButton(parentWindow, controlId, bitmap, wxDefaultPosition, wxDefaultSize, 0)
  , mIsChecked(0)
{}

// Table 0x00DFF494 = {&wxBitmapButton::sm_eventTable - wxControl's, 0x00D54D70
// - rows 0x00F5983C}; GetEventTable (0x004FBE20) comes with it.
BEGIN_EVENT_TABLE(moho::WBitmapCheckBox, wxBitmapButton)
  EVT_LEFT_UP(moho::WBitmapCheckBox::OnLeftUp)
END_EVENT_TABLE()

/**
 * Address: 0x004FBF10 (FUN_004FBF10, ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ)
 * Mangled: ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ
 *
 * What it does:
 * Returns whether the button is checked.
 */
bool moho::WBitmapCheckBox::IsChecked()
{
  return mIsChecked != 0;
}

/**
 * Address: 0x004FBF20 (FUN_004FBF20, ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z)
 * Mangled: ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z
 *
 * What it does:
 * On a change of state, swaps the label and selected bitmaps - each set lets
 * the button pick its bitmap again (OnSetBitmap) - repaints, and stores the
 * new state.
 */
void moho::WBitmapCheckBox::SetChecked(const bool checked)
{
  if (static_cast<std::uint8_t>(checked) == mIsChecked) {
    return;
  }

  const wxBitmap selected(GetBitmapSelected());
  const wxBitmap label(GetBitmapLabel());
  SetBitmapLabel(selected);
  SetBitmapSelected(label);
  Refresh();
  mIsChecked = checked ? 1 : 0;
}

/**
 * Address: 0x004FC010 (FUN_004FC010)
 *
 * What it does:
 * Toggles the checked state on button-up, then lets the event carry on to
 * the button's own handling.
 */
void moho::WBitmapCheckBox::OnLeftUp(wxMouseEvent& event)
{
  SetChecked(mIsChecked == 0);
  event.Skip();
}

// ---------------------------------------------------------------------------
// WWxInputBox
// ---------------------------------------------------------------------------

/**
 * Address: 0x004FC040 (FUN_004FC040)
 * Mangled: ??0WWxInputBox@Moho@@QAE@PBDPBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@msvc8@@00PAV40@@Z
 *
 * What it does:
 * Creates the dialog (wxDialog's inline copy at 0x004A3900) and lays it out
 * top to bottom, at least 500 wide: the centred label, the text control
 * seeded with the default value, and a centred OK (the default button) /
 * Cancel row; then sizes itself to that.
 */
moho::WWxInputBox::WWxInputBox(
  const char* const dialogTitle,
  const char* const defaultValue,
  const char* const labelText,
  fa::string* const resultString
)
  : wxDialog(
      nullptr,
      -1,
      gpg::STR_Utf8ToWide(dialogTitle).c_str(),
      wxDefaultPosition,
      wxDefaultSize,
      wxDEFAULT_DIALOG_STYLE
    )
  , mResultString(resultString)
{
  wxBoxSizer* const topSizer = new wxBoxSizer(wxVERTICAL);
  topSizer->SetMinSize(500, 0);

  topSizer->Add(
    new wxStaticText(this, -1, gpg::STR_Utf8ToWide(labelText).c_str(), wxDefaultPosition, wxDefaultSize, 0),
    0,
    wxALL | wxALIGN_CENTER,
    10
  );

  mTextCtrl = new wxTextCtrl(this, -1, gpg::STR_Utf8ToWide(defaultValue).c_str(), wxDefaultPosition, wxDefaultSize, 0);
  topSizer->Add(mTextCtrl, 1, wxALL | wxEXPAND, 10);

  wxBoxSizer* const buttonSizer = new wxBoxSizer(wxHORIZONTAL);
  wxButton* const okButton = new wxButton(this, wxID_OK, wxT("OK"), wxDefaultPosition, wxDefaultSize, 0);
  buttonSizer->Add(okButton, 0, wxALL, 10);
  buttonSizer->Add(
    new wxButton(this, wxID_CANCEL, wxT("Cancel"), wxDefaultPosition, wxDefaultSize, 0), 0, wxALL, 10
  );
  topSizer->Add(buttonSizer, 0, wxALIGN_CENTER, 0);

  okButton->SetDefault();
  SetSizer(topSizer);
  topSizer->SetSizeHints(this);
}

/**
 * Address: 0x004FC7B0 (FUN_004FC7B0)
 *
 * What it does:
 * Writes the text control's value, UTF-8 encoded (gpg::STR_WideToUtf8,
 * 0x00938680), into the caller's string and lets wxDialog::OnOK close.
 */
bool moho::WWxInputBox::TransferDataFromWindow()
{
  *mResultString = gpg::STR_WideToUtf8(mTextCtrl->GetValue().c_str());
  return true;
}

/**
 * Address: 0x004FC870 (FUN_004FC870)
 *
 * What it does:
 * Runs one modal WWxInputBox (0x178 bytes) and destroys it; true when the
 * user pressed OK.
 */
bool moho::WxInputBox(
  const char* const dialogTitle,
  const char* const defaultValue,
  const char* const labelText,
  fa::string* const resultString
)
{
  WWxInputBox* const dialog = new WWxInputBox(dialogTitle, defaultValue, labelText, resultString);
  const bool accepted = dialog->ShowModal() == wxID_OK;
  dialog->Destroy();
  return accepted;
}

/**
 * Address: 0x004FC900 (FUN_004FC900, ?CON_WxInputBox@Moho@@YAXPAX@Z)
 *
 * What it does:
 * Console-command callback registered as `WxInputBox`. Pops up a modal
 * input box with the fixed prompt "What?", default "default", and label
 * "Type your answer below.", then prints the entered text (or "Canceled"
 * when dismissed) through `Moho::CON_Printf`.
 */
void moho::CON_WxInputBox(const fa::vector<fa::string>& args)
{
  (void)args;

  fa::string enteredText;
  if (WxInputBox("What?", "default", "Type your answer below.", &enteredText)) {
    CON_Printf("You entered \"%s\"", enteredText.c_str());
  } else {
    CON_Printf("Canceled");
  }
}
namespace moho
{

  /**
   * The active world session (`Moho::sWldSession`, 0x010A6470). Read directly
   * (not through `WLD_GetActiveSession()`) by `RenderCartographic`
   * (0x007F8C96 `mov eax, Moho__sWldSession`) to gate the fog-of-war
   * `VisionRenderer` selection. Declared locally the same way
   * `Cartographic.cpp` declares it - no owning header for this global exists
   * in this tree yet.
   */
  extern CWldSession* sWldSession;
}

