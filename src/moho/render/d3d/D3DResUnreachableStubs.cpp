// Recovered default virtual-method implementations for the
// (still unrecovered) `D3DRes` runtime owner. The binary emits five
// distinct "supposably unreachable" assert thunks at consecutive
// line numbers in `c:\work\rts\main\code\src\core\D3DRes.cpp`,
// corresponding to five different virtual slots in the owning
// interface that fall back to a hard assert when not overridden.
//
// Each thunk is 1:1 a single call to `gpg::HandleAssertFailure`
// with a fixed "Reached the supposably unreachable." message, the
// same source path, and a distinct line number. They are exposed
// here as discrete functions so the eventual owner-class recovery
// can wire each vtable slot to its matching body; until then these
// bodies keep the binary's observable control flow (`__noreturn`
// + HandleAssertFailure) preserved and callable.

#include "gpg/core/utils/Global.h"

namespace moho
{
  namespace
  {
    constexpr const char* kUnreachableMessage = "Reached the supposably unreachable.";
    constexpr const char* kD3DResSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\D3DRes.cpp";

    [[noreturn]] void InvokeD3DResUnreachableAt(
      const int lineNumber
    )
    {
      gpg::HandleAssertFailure(kUnreachableMessage, lineNumber, kD3DResSourcePath);
      // HandleAssertFailure is declared `noreturn` in the binary but the
      // SDK declaration does not carry that annotation; fall back to an
      // infinite loop so the C++20 `noreturn` contract is satisfied on
      // the off-chance HandleAssertFailure ever returns.
      for (;;) {}
    }
  } // namespace

} // namespace moho
