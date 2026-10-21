#pragma once

// FAF addition, not in the shipped binary: error reporting shared by the
// gal backends added for Direct3D 11, Direct3D 12 and Vulkan.

#include <windows.h>

namespace gpg::gal::backend
{
  /** Throws a `gpg::gal::Error` naming `file` and `line`. */
  [[noreturn]] void ThrowError(const char* file, int line, const char* message);

  /** Throws a `gpg::gal::Error` carrying the HRESULT in hex and as text. */
  [[noreturn]] void ThrowHresult(const char* file, int line, HRESULT result);

  /** `ThrowHresult` when `result` failed. */
  inline void CheckHresult(const char* const file, const int line, const HRESULT result)
  {
    if (FAILED(result)) {
      ThrowHresult(file, line, result);
    }
  }
} // namespace gpg::gal::backend
