#pragma once

// Engine addition (issue #255): wx 2.4.2's directory chooser (wx/dirdlg.h), for the Linux
// client. See wx/defs.h in this folder. It is cancelled until the window system (issue #256)
// can show it.

#include <string>

#include <wx/dialog.h>

class wxDirDialog : public wxDialog
{
public:
  wxDirDialog(
    wxWindow* const parent,
    const wchar_t* const message,
    const wchar_t* const defaultPath = L"",
    const long style = 0
  )
    : m_path(defaultPath != nullptr ? defaultPath : L"")
  {
    (void)parent;
    (void)message;
    (void)style;
  }

  const std::wstring& GetPath() const { return m_path; }

private:
  std::wstring m_path;
};
