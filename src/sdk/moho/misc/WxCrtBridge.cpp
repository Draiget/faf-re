// SPDX: faf engine recovery
//
// WxCrtBridge.cpp
//
// Real implementations of the three small CRT-style helpers that the wx*
// recovered code in `WxRuntimeTypes.cpp` calls into. The canonical recovered
// bodies live in `moho/misc/CrtRuntimeHelpers.cpp`, but that TU is currently
// `<ExcludedFromBuild>` while wider CRT recovery stabilizes; without these
// definitions the wx* callers (`wxAppendSystemErrorSuffixAndDispatchRuntime`,
// `wxFile::Length`, `wxFFileOpenFromWidePathRuntime`) leave the linker with
// unresolved externals.
//
// Each body below mirrors the binary's behavior (FUN_00A90F12 for
// `RuntimeSnwprintf`, FUN_00A94C36 for `RuntimeFileLength`, FUN_009EFF10 for
// `RuntimeWcsToMbs`) by validating the same pre-condition lanes the original
// performed and then delegating the heavy work to the host CRT routine that
// the binary itself called underneath. When `CrtRuntimeHelpers.cpp` is
// re-enabled, this bridge TU should be removed from `main.vcxproj` to avoid
// duplicate symbol definitions.

#include <cerrno>
#include <cstddef>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <io.h>

/**
 * Address: 0x00A90F12 (FUN_00A90F12, _snwprintf)
 *
 * What it does:
 * Rejects null `format` or (non-zero `count` with null `buffer`) with
 * `errno=EINVAL` and `_invalid_parameter_noinfo()`; otherwise forwards to
 * `_vsnwprintf` with the unpacked variadic argument list. Returns the wide
 * character count emitted (terminator excluded) or `-1` on validation
 * failure.
 */
extern "C" int __cdecl RuntimeSnwprintf(
  wchar_t* const buffer,
  const std::size_t count,
  const wchar_t* const format,
  ...
)
{
  if (format == nullptr || (count != 0u && buffer == nullptr)) {
    *_errno() = EINVAL;
    ::_invalid_parameter_noinfo();
    return -1;
  }

  std::va_list args;
  va_start(args, format);
  const int result = ::_vsnwprintf(buffer, count, format, args);
  va_end(args);
  return result;
}

/**
 * Address: 0x00A94C36 (FUN_00A94C36, _filelength)
 *
 * What it does:
 * Returns the total length of the open file descriptor's underlying file as
 * a signed long, or `-1` on error. Rejects the CRT sentinel pseudo-handle
 * `-2` with `errno=EBADF`, then forwards to `_filelength` which performs
 * the per-fd spinlock + `_lseek_nolock` dance internally and restores the
 * original file position on completion. The `_doserrno`/`__pioinfo` lanes
 * the recovered binary touched are owned by the same CRT routine, so the
 * delegated call preserves observable behavior.
 */
extern "C" long __cdecl RuntimeFileLength(const int fileHandle)
{
  if (fileHandle == -2) {
    *_errno() = EBADF;
    return -1L;
  }
  return ::_filelength(fileHandle);
}

/**
 * Address: 0x009EFF10 (FUN_009EFF10, wcstombs)
 *
 * What it does:
 * Pre-validates the standard CRT `wcstombs()` fast paths:
 *   - null destination -> zero the count lane and let the converter perform
 *     the size-query call,
 *   - non-null destination + zero count -> return 0 directly,
 *   - empty source -> write one narrow terminator and return 0,
 *   - otherwise forward to `std::wcstombs`.
 */
extern "C" std::size_t __cdecl RuntimeWcsToMbs(
  char* destination,
  const wchar_t* const wideSource,
  std::size_t maxNarrowBytes
)
{
  if (destination == nullptr) {
    maxNarrowBytes = 0;
  } else {
    if (maxNarrowBytes == 0u) {
      return 0u;
    }
    if (*wideSource == L'\0') {
      *destination = '\0';
      return 0u;
    }
  }

  return std::wcstombs(destination, wideSource, maxNarrowBytes);
}
