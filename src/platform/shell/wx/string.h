#pragma once

// Engine addition (issue #255): wx 2.4.2's string (wx/string.h) as the Linux client's shell uses
// it: built from wide text, read back with c_str(). See wx/defs.h in this folder.

#include <string>

#include <wx/defs.h>

class wxString : public std::wstring
{
public:
  wxString() = default;
  wxString(
    const wchar_t* const text
  )
    : std::wstring(text != nullptr ? text : L"")
  {}
  wxString(
    const std::wstring& text
  )
    : std::wstring(text)
  {}

  const wchar_t* c_str() const
  {
    return std::wstring::c_str();
  }
  bool IsEmpty() const
  {
    return empty();
  }
  std::size_t Len() const
  {
    return size();
  }
};

extern const wxString wxEmptyString;
