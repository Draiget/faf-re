// SPDX: faf engine recovery
//
// CrtRuntimeExportedHelpers.cpp
//
// The CRT helpers the engine calls by name. The binary has them at adjacent
// addresses to the rest of its statically linked CRT (0x00A8FB50, 0x00A8FC4B,
// 0x00A8FC71). The build takes the CRT from the toolchain, so only these,
// whose engine-specific names the toolchain doesn't supply, are defined here.

#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <stdexcept>

/**
 * Address: (paired with the `_Xlen` throw sites across the legacy containers)
 *
 * What it does:
 * Raises the standard "container too long" length error.
 *
 * The parameter must be spelled `const char*`, not `const char* const`: MSVC's
 * 32-bit decorated name encodes a top-level const on a by-value pointer
 * parameter (`QBD` instead of `PBD`), so the two spellings are different link
 * symbols even though they are the same C++ overload. Unit.cpp,
 * CWldSession.cpp and PathTables.cpp all forward-declare the plain form.
 */
[[noreturn]] void EngineThrowContainerTooLong(
  const char* message
)
{
  throw std::length_error(message);
}
