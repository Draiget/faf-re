#include "moho/misc/ScrGotoDialog.h"

#include <cstdlib>

#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/StartupHelpers.h"

// Table 0x00DFF658 = {&wxDialog::sm_eventTable (0x00D540E8), rows 0x00F59448};
// GetEventTable (0x004BC0F0) comes with it.
BEGIN_EVENT_TABLE(moho::ScrGotoDialog, wxDialog)
  EVT_BUTTON(wxID_OK, moho::ScrGotoDialog::OnOK)
  EVT_MOVE(moho::ScrGotoDialog::OnMove)
END_EVENT_TABLE()

/**
 * Address: 0x004BB730 (FUN_004BB730, ??0ScrGotoDialog@Moho@@QAE@@Z)
 */
moho::ScrGotoDialog::ScrGotoDialog()
  : wxDialog(
      nullptr, -1, wxT("Goto"),
      wxPoint(
        USER_GetPreferences()->GetInteger("Windows.Debug.Goto.x", -1),
        USER_GetPreferences()->GetInteger("Windows.Debug.Goto.y", -1)
      ),
      wxDefaultSize, wxDEFAULT_DIALOG_STYLE, wxT("ScrGotoDialog")
    )
{
  mInitializing = true;

  wxBoxSizer* const dialogSizer = new wxBoxSizer(wxVERTICAL);
  wxBoxSizer* const lineSizer = new wxBoxSizer(wxHORIZONTAL);
  wxBoxSizer* const buttonSizer = new wxBoxSizer(wxHORIZONTAL);
  dialogSizer->Add(lineSizer);
  dialogSizer->Add(buttonSizer);

  lineSizer->Add(new wxStaticText(this, -1, wxT("Goto")), 0, wxLEFT | wxTOP, 10);
  mLineText = new wxTextCtrl(this, -1, wxEmptyString, wxDefaultPosition, wxSize(96, -1));
  lineSizer->Add(mLineText, 0, wxLEFT | wxRIGHT | wxTOP, 10);

  wxButton* const gotoButton = new wxButton(this, wxID_OK, wxT("Goto"), wxDefaultPosition, wxSize(48, -1));
  gotoButton->SetDefault();
  buttonSizer->Add(gotoButton, 0, wxLEFT | wxTOP | wxBOTTOM, 10);
  buttonSizer->Add(
    new wxButton(this, wxID_CANCEL, wxT("Cancel"), wxDefaultPosition, wxSize(48, -1)), 0, wxLEFT | wxTOP | wxBOTTOM, 10
  );

  dialogSizer->SetSizeHints(this);
  SetSizer(dialogSizer);

  mInitializing = false;
}

/**
 * Address: 0x004BBFF0 (FUN_004BBFF0)
 */
int moho::ScrGotoDialog::GetLine() const
{
  return std::atoi(gpg::STR_WideToUtf8(mLineText->GetValue().c_str()).c_str());
}

/**
 * Address: 0x004BBFD0 (FUN_004BBFD0)
 */
void moho::ScrGotoDialog::OnOK(wxCommandEvent& event)
{
  EndModal(wxID_OK);
}

/**
 * Address: 0x004BBEB0 (FUN_004BBEB0)
 */
void moho::ScrGotoDialog::OnMove(wxMoveEvent& event)
{
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.Goto.x", GetPosition().x);
  prefs->SetInteger("Windows.Debug.Goto.y", GetPosition().y);
}
