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

    [[noreturn]] void InvokeD3DResUnreachableAt(const int lineNumber)
    {
      gpg::HandleAssertFailure(kUnreachableMessage, lineNumber, kD3DResSourcePath);
      // HandleAssertFailure is declared `noreturn` in the binary but the
      // SDK declaration does not carry that annotation; fall back to an
      // infinite loop so the C++20 `noreturn` contract is satisfied on
      // the off-chance HandleAssertFailure ever returns.
      for (;;) {
      }
    }
  } // namespace

  /**
   * Address: 0x0043E590 (FUN_0043E590, sub_43E590)
   *
   * IDA signature:
   * void __noreturn sub_43E590();
   *
   * What it does:
   * Default-virtual "unreachable" thunk for the D3DRes owner at
   * source line 361; hard-asserts through `gpg::HandleAssertFailure`
   * and never returns.
   */
  [[noreturn]] void D3DResUnreachableVirtualFirst()
  {
    InvokeD3DResUnreachableAt(361);
  }

  /**
   * Address: 0x0043E5B0 (FUN_0043E5B0, sub_43E5B0)
   *
   * IDA signature:
   * void __noreturn sub_43E5B0();
   *
   * What it does:
   * Default-virtual "unreachable" thunk for the D3DRes owner at
   * source line 366.
   */
  [[noreturn]] void D3DResUnreachableVirtualSecond()
  {
    InvokeD3DResUnreachableAt(366);
  }

  /**
   * Address: 0x0043E5D0 (FUN_0043E5D0, sub_43E5D0)
   *
   * IDA signature:
   * void __noreturn sub_43E5D0();
   *
   * What it does:
   * Default-virtual "unreachable" thunk for the D3DRes owner at
   * source line 371.
   */
  [[noreturn]] void D3DResUnreachableVirtualThird()
  {
    InvokeD3DResUnreachableAt(371);
  }

  /**
   * Address: 0x0043E5F0 (FUN_0043E5F0, sub_43E5F0)
   *
   * IDA signature:
   * void __noreturn sub_43E5F0();
   *
   * What it does:
   * Default-virtual "unreachable" thunk for the D3DRes owner at
   * source line 376.
   */
  [[noreturn]] void D3DResUnreachableVirtualFourth()
  {
    InvokeD3DResUnreachableAt(376);
  }

  /**
   * Address: 0x0043E610 (FUN_0043E610, sub_43E610)
   *
   * IDA signature:
   * void __noreturn sub_43E610();
   *
   * What it does:
   * Default-virtual "unreachable" thunk for the D3DRes owner at
   * source line 381.
   */
  [[noreturn]] void D3DResUnreachableVirtualFifth()
  {
    InvokeD3DResUnreachableAt(381);
  }
} // namespace moho
