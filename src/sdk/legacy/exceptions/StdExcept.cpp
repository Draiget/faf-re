#include "legacy/exceptions/StdExcept.h"

namespace msvc8
{
  exception::~exception() = default;

  /**
   * What it does:
   * Returns the borrowed message, or the CRT's placeholder when there is
   * none. `message_exception` overrides this and answers from its own
   * string, which is the only form anything here constructs.
   */
  const char* exception::what() const noexcept
  {
    return mWhat != nullptr ? mWhat : "Unknown exception";
  }
} // namespace msvc8
