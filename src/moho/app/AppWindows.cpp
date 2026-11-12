#include "moho/app/AppPrivate.h"

#include "imgui.h"

// The managed-window registries (managedWindows 0x010A9B94, managedFrames 0x010A9BD8) held the
// developer windows for WINX_Exit; those are Dear ImGui windows now (issue #412), which WINX_Exit
// closes itself.
ShellWindow* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;

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
/**
 * Address: 0x004FC040 (FUN_004FC040, WWxInputBox::WWxInputBox)
 *
 * What it does:
 * The input box: the label above an edit box holding the default value, then OK and Cancel.
 * wx laid them out with box sizers; Dear ImGui draws them (issue #412).
 */
moho::WInputBox::WInputBox(
  const char* const dialogTitle,
  const char* const defaultValue,
  const char* const labelText
)
  : platform::tools::ToolWindow(dialogTitle, 360, 140)
  , mLabel(labelText != nullptr ? labelText : "")
{
  std::snprintf(mText.data(), mText.size(), "%s", defaultValue != nullptr ? defaultValue : "");
}

void moho::WInputBox::Draw()
{
  ImGui::TextUnformatted(mLabel.c_str());
  ImGui::SetNextItemWidth(-1.0f);
  if (mFocusText) {
    ImGui::SetKeyboardFocusHere();
    mFocusText = false;
  }
  const bool entered = ImGui::InputText("##answer", mText.data(), mText.size(), ImGuiInputTextFlags_EnterReturnsTrue);
  if (ImGui::Button("OK") || entered) {
    mAccepted = true;
    mDone = true;
  }
  ImGui::SameLine();
  if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
    mDone = true;
  }
}

void moho::WInputBox::OnCloseRequested()
{
  mDone = true;
}

/**
 * Address: 0x004FC7B0 (FUN_004FC7B0, WWxInputBox::TransferDataFromWindow) and wxDialog::ShowModal
 *
 * What it does:
 * Shows the box and runs the window system until OK, Cancel or the close button; with OK the
 * edit box's text goes to `result`.
 */
bool moho::WInputBox::RunModal(
  fa::string* const result
)
{
  if (!IsValid()) {
    return false;
  }
  Show(true);
  WINX_RunModal([this]() {
    return mDone;
  });
  Show(false);
  if (mAccepted && result != nullptr) {
    *result = mText.data();
  }
  return mAccepted;
}

/**
 * Address: 0x004FC870 (FUN_004FC870, WxInputBox)
 *
 * What it does:
 * Runs one modal input box and destroys it; true when the user pressed OK.
 */
bool moho::InputBox(
  const char* const dialogTitle,
  const char* const defaultValue,
  const char* const labelText,
  fa::string* const resultString
)
{
  WInputBox dialog(dialogTitle, defaultValue, labelText);
  return dialog.RunModal(resultString);
}

/**
 * Address: 0x004FC900 (FUN_004FC900, ?CON_WxInputBox@Moho@@YAXPAX@Z)
 *
 * What it does:
 * Console-command callback registered as `InputBox` (`WxInputBox` in the binary). Pops up a modal
 * input box with the fixed prompt "What?", default "default", and label "Type your answer
 * below.", then prints the entered text (or "Canceled" when dismissed) through `Moho::CON_Printf`.
 */
void moho::CON_InputBox(
  const fa::vector<fa::string>& args
)
{
  (void)args;

  fa::string enteredText;
  if (InputBox("What?", "default", "Type your answer below.", &enteredText)) {
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
} // namespace moho
