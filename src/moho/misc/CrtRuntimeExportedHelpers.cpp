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
[[noreturn]] void EngineThrowContainerTooLong(const char* message)
{
  throw std::length_error(message);
}

/**
 * Address: 0x00A8FB50 (FUN_00A8FB50, EngineToLowerWideWithCurrentLocale)
 *
 * What it does:
 * Lowercases one wide character under the current CRT locale lane. Called per
 * character by the typed wxString lowercase loop in `WxRuntimeTypes.cpp`.
 */
int EngineToLowerWideWithCurrentLocale(const wchar_t character)
{
  return static_cast<int>(_towlower_l(static_cast<wint_t>(character), nullptr));
}

/**
 * Address: 0x00A8FC4B (FUN_00A8FC4B, `_wtoi` wrapper lane)
 *
 * What it does:
 * Parses one base-10 signed wide integer by forwarding to `wcstol`.
 */
extern "C" int __cdecl EngineWtoiFromWide(const wchar_t* const text)
{
  return static_cast<int>(::wcstol(text, nullptr, 10));
}

/**
 * Address: 0x00A8FC71 (FUN_00A8FC71, `_wtoi` thunk lane)
 *
 * What it does:
 * Tail-forwards one `_wtoi` thunk lane into `EngineWtoiFromWide`.
 */
extern "C" int __cdecl EngineWtoiFromWideThunk(const wchar_t* const text)
{
  return EngineWtoiFromWide(text);
}

/**
 * Address: 0x00A8xxxx (func_wstrFindLast)
 *
 * IDA signature:
 * _WORD *__cdecl func_wstrFindLast(_WORD *a1, __int16 a2);
 *
 * What it does:
 * `wcsrchr`: walks to the terminator, then scans back for `needle` and returns
 * that position, or null when absent. Searching for the terminator itself
 * finds it, because the backward scan starts there.
 */
extern "C" wchar_t* __cdecl EngineWideStringFindLast(wchar_t* const text, const wchar_t needle)
{
  wchar_t* cursor = text;
  while (*cursor++ != L'\0') {
  }

  do {
    --cursor;
  } while (cursor != text && *cursor != needle);

  return (*cursor == needle) ? cursor : nullptr;
}
