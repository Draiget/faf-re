#pragma once

// The direct-call lane for the spec rows: builds one machine-code stub per
// selected spec entry and calls the mapped retail function through it, with
// no hand-written thunk per function. MSVC x86 only.

#include "spec_rows.h"

#include <cstdint>

namespace difffuzz
{
  namespace spec
  {
    /// Writes the machine code that calls `entry` with the argument words in
    /// `in` (a cdecl `const u32*`, so the stub dereferences it) and stores
    /// the result words into `outWords` (a cdecl `u32*`): eax, edx:eax, or
    /// st0 stored as a float/double. The retail image must be mapped at the
    /// VAs the spec names (0x00400000) before the stub runs.
    /// Registers ebx/esi/edi/ebp are preserved; ecx and edx are free.
    /// Returns the code length in bytes (the caller provides the buffer).
    /// A stub BuildStub built, as the cdecl function it is: the argument
    /// words in, the result words out.
    using StubFn = void(__cdecl*)(const std::uint32_t* in, std::uint32_t* outWords);

    int BuildStub(const Entry& entry, unsigned char* code);
  } // namespace spec
} // namespace difffuzz
