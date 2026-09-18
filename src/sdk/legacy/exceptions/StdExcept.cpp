#include "legacy/exceptions/StdExcept.h"

namespace msvc8
{
  exception::~exception() = default;

  /**
   * What it does:
   * Returns the borrowed message, or the CRT's placeholder when there is
   * none. `runtime_error` overrides this and answers from its own string.
   */
  const char* exception::what() const noexcept
  {
    return mWhat != nullptr ? mWhat : "Unknown exception";
  }

  /**
   * Address: 0x00405130 (FUN_00405130, std::runtime_error::runtime_error)
   * Mangled: ??0runtime_error@std@@Z
   *
   * IDA signature:
   * runtime_error *__thiscall runtime_error(runtime_error *this, const string *message);
   *
   * What it does:
   * Runs the `exception` base constructor, then copies the message into the
   * embedded string. The binary open-codes that copy as an empty-string
   * initialization (`_Mysize = 0`, `_Myres = 0xF`, `_Bx._Buf[0] = 0`)
   * followed by `string::assign(message, 0, npos)` at 0x004056B0, which is
   * what MSVC emits for a member-initializer of a `string` from a `string`.
   */
  runtime_error::runtime_error(const string& message) noexcept
    : exception(), mStr(message)
  {
  }

  runtime_error::~runtime_error() = default;

  /**
   * What it does:
   * Answers from the embedded string rather than the base's borrowed
   * pointer, which is why this type exists in the first place.
   */
  const char* runtime_error::what() const noexcept
  {
    return mStr.c_str();
  }
} // namespace msvc8
