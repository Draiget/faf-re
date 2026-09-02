// SPDX: faf engine recovery
//
// CrtRuntimeExportedHelpers.cpp
//
// A small slice of the CRT-helper translation unit that has to stay in the
// build.
//
// These bodies were recovered as part of `CrtRuntimeHelpers.cpp` and sit at
// adjacent addresses to the rest of it (0x00A8FB50, 0x00A8FC4B, 0x00A8FC71),
// so by spatial locality they belong there. They live here only because that
// file is `<ExcludedFromBuild>`: it redefines a cluster of reserved CRT/EH-ABI
// symbols under their real names (`__CxxFrameHandler3`, `_CallCatchBlock2`,
// `_UnwindNestedFrames`, `_XcptFilter`, ...) which the modern toolchain also
// supplies, and re-enabling it needs the dedicated renaming pass described in
// `main.vcxproj`.
//
// Meanwhile the four helpers below have engine-specific names that collide
// with nothing, and each has a live caller that was left as an unresolved
// external. The project links with `/FORCE`, so those unresolved call sites
// were not build failures - they survived into `main.exe` as calls into
// nothing.
//
// When `CrtRuntimeHelpers.cpp` is re-enabled, fold these back into it and
// delete this file; keeping both would be a duplicate-symbol error.

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
[[noreturn]] void RuntimeThrowContainerTooLong(const char* message)
{
  throw std::length_error(message);
}

/**
 * Address: 0x00A8FB50 (FUN_00A8FB50, RuntimeToLowerWideWithCurrentLocale)
 *
 * What it does:
 * Lowercases one wide character under the current CRT locale lane. Called per
 * character by the typed wxString lowercase loop in `WxRuntimeTypes.cpp`.
 */
int RuntimeToLowerWideWithCurrentLocale(const wchar_t character)
{
  return static_cast<int>(_towlower_l(static_cast<wint_t>(character), nullptr));
}

/**
 * Address: 0x00A8FC4B (FUN_00A8FC4B, `_wtoi` wrapper lane)
 *
 * What it does:
 * Parses one base-10 signed wide integer by forwarding to `wcstol`.
 */
extern "C" int __cdecl RuntimeWtoiFromWide(const wchar_t* const text)
{
  return static_cast<int>(::wcstol(text, nullptr, 10));
}

/**
 * Address: 0x00A8FC71 (FUN_00A8FC71, `_wtoi` thunk lane)
 *
 * What it does:
 * Tail-forwards one `_wtoi` thunk lane into `RuntimeWtoiFromWide`.
 */
extern "C" int __cdecl RuntimeWtoiFromWideThunk(const wchar_t* const text)
{
  return RuntimeWtoiFromWide(text);
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
extern "C" wchar_t* __cdecl RuntimeWideStringFindLast(wchar_t* const text, const wchar_t needle)
{
  wchar_t* cursor = text;
  while (*cursor++ != L'\0') {
  }

  do {
    --cursor;
  } while (cursor != text && *cursor != needle);

  return (*cursor == needle) ? cursor : nullptr;
}
