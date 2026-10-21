// FAF addition, not in the shipped binary: see BackendErrors.h.

#include "BackendErrors.h"

#include <cstdio>

#include "gpg/gal/Error.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal::backend
{
  void ThrowError(const char* const file, const int line, const char* const message)
  {
    throw Error(msvc8::string(file != nullptr ? file : ""), line, msvc8::string(message != nullptr ? message : ""));
  }

  void ThrowHresult(const char* const file, const int line, const HRESULT result)
  {
    char message[256]{};
    std::snprintf(
      message,
      sizeof(message),
      "HRESULT 0x%08lX (%s)",
      static_cast<unsigned long>(result),
      ::gpg::D3DErrorToString(static_cast<long>(result))
    );
    ThrowError(file, line, message);
  }

} // namespace gpg::gal::backend
