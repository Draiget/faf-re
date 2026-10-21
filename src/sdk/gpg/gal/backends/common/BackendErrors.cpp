// FAF addition, not in the shipped binary: see BackendErrors.h.

#include "BackendErrors.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

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

  bool SetupFailureRequested(const char* const name)
  {
    const char* const value = std::getenv("FAF_GAL_FAIL_SETUP");
    if (value == nullptr || value[0] == '\0' || name == nullptr) {
      return false;
    }
    if (value[0] == '1' && value[1] == '\0') {
      return true;
    }
    const std::string list = value;
    const std::size_t length = std::strlen(name);
    for (std::size_t at = list.find(name); at != std::string::npos; at = list.find(name, at + 1U)) {
      const bool startsItem = (at == 0U) || list[at - 1U] == ',' || list[at - 1U] == ';' || list[at - 1U] == ' ';
      const std::size_t end = at + length;
      const bool endsItem = (end == list.size()) || list[end] == ',' || list[end] == ';' || list[end] == ' ';
      if (startsItem && endsItem) {
        return true;
      }
    }
    return false;
  }
} // namespace gpg::gal::backend
