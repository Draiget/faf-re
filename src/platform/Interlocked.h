#pragma once

// Engine addition (dedicated-server plan WPL.5, WPL.6): the operand type of the MSVC
// interlocked intrinsics (_InterlockedExchangeAdd, _InterlockedIncrement, ...). They work
// on Windows' 32-bit `long`. clang provides the same intrinsics on Linux (-fms-extensions)
// on a 32-bit `int` there, since `long` is 64-bit (LP64). Code that casts a 32-bit field
// for them casts to this type.

namespace platform
{
#if defined(_WIN32)
  using InterlockedLong = long;
#else
  using InterlockedLong = int;
#endif
  static_assert(sizeof(InterlockedLong) == 4, "the interlocked intrinsics operate on 32-bit values");
} // namespace platform
