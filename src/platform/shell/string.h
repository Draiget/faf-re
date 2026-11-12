#pragma once

// Engine addition (issues #255, #407): the shell's string: built from wide text, read back with
// c_str(). See defs.h.

#include <string>

#include "platform/shell/defs.h"

class ShellString : public std::wstring
{
public:
  ShellString() = default;
  ShellString(
    const wchar_t* const text
  )
    : std::wstring(text != nullptr ? text : L"")
  {}
  ShellString(
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

extern const ShellString kShellEmptyString;
