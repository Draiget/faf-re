#pragma once

// Engine addition (issue #255): wx 2.4.2's modal dialog base (wx/dialog.h), for the Linux
// client. See wx/defs.h in this folder. Dialogs need the window system (issue #256); until then
// ShowModal answers wxID_CANCEL, as a user closing the dialog would.

#include <wx/window.h>

class wxDialog : public wxWindow
{
public:
  wxDialog() = default;
  virtual int ShowModal() { return wxID_CANCEL; }
};
