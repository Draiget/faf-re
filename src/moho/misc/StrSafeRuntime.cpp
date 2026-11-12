#include <Windows.h>

#include <cstdarg>
#include <climits>
#include <cstdio>
#include <cwchar>

namespace moho::runtime
{
  namespace
  {
    constexpr HRESULT kHrOk = 0;
    constexpr HRESULT kHrInvalidArg = static_cast<HRESULT>(0x80070057u);
    constexpr HRESULT kHrInsufficientBuffer = static_cast<HRESULT>(0x8007007Au);

  } // namespace

  /**
   * Address: 0x00B2CCDC (FUN_00B2CCDC)
   *
   * What it does:
   * Copies one narrow string into a bounded destination and always writes a
   * trailing NUL when destination capacity is non-zero.
   */
  HRESULT __stdcall StrSafeCopyNarrowWorker(
    char* destination,
    int destinationChars,
    const char* source
  )
  {
    HRESULT result = kHrOk;
    if (destinationChars == 0) {
      return kHrInvalidArg;
    }

    do {
      if (*source == '\0') {
        break;
      }

      *destination = *source;
      ++destination;
      ++source;
      --destinationChars;
    } while (destinationChars != 0);

    if (destinationChars == 0) {
      --destination;
      result = kHrInsufficientBuffer;
    }

    *destination = '\0';
    return result;
  }

  /**
   * Address: 0x00B2CD19 (FUN_00B2CD19)
   *
   * What it does:
   * Copies one wide string into a bounded destination and always writes a
   * trailing NUL when destination capacity is non-zero.
   */
  HRESULT __stdcall StrSafeCopyWideWorker(
    wchar_t* destination,
    int destinationChars,
    const wchar_t* source
  )
  {
    HRESULT result = kHrOk;
    if (destinationChars == 0) {
      return kHrInvalidArg;
    }

    do {
      if (*source == L'\0') {
        break;
      }

      *destination = *source;
      ++destination;
      ++source;
      --destinationChars;
    } while (destinationChars != 0);

    if (destinationChars == 0) {
      --destination;
      result = kHrInsufficientBuffer;
    }

    *destination = L'\0';
    return result;
  }

  /**
   * Address: 0x00B2CD5D (FUN_00B2CD5D)
   *
   * What it does:
   * Narrow `vsnprintf` worker for strsafe formatting with explicit last-lane
   * NUL clamp on full/truncated writes.
   */
  HRESULT __stdcall StrSafeVPrintfNarrowWorker(
    char* buffer,
    int bufferChars,
    const char* format,
    va_list args
  )
  {
    HRESULT result = kHrOk;
    if (bufferChars == 0) {
      return kHrInvalidArg;
    }

    const unsigned int lastIndex = static_cast<unsigned int>(bufferChars - 1);
    const int formattedChars = _vsnprintf(buffer, static_cast<std::size_t>(bufferChars - 1), format, args);

    if (formattedChars < 0 || static_cast<unsigned int>(formattedChars) > lastIndex) {
      result = kHrInsufficientBuffer;
    } else if (static_cast<unsigned int>(formattedChars) != lastIndex) {
      return result;
    }

    buffer[lastIndex] = '\0';
    return result;
  }

  /**
   * Address: 0x00B2CDA9 (FUN_00B2CDA9)
   *
   * What it does:
   * Wide `vsnwprintf` worker for strsafe formatting with explicit last-lane
   * NUL clamp on full/truncated writes.
   */
  HRESULT __stdcall StrSafeVPrintfWideWorker(
    wchar_t* buffer,
    int bufferChars,
    const wchar_t* format,
    va_list args
  )
  {
    HRESULT result = kHrOk;
    if (bufferChars == 0) {
      return kHrInvalidArg;
    }

    const unsigned int lastIndex = static_cast<unsigned int>(bufferChars - 1);
    const int formattedChars = _vsnwprintf(buffer, static_cast<std::size_t>(bufferChars - 1), format, args);

    if (formattedChars < 0 || static_cast<unsigned int>(formattedChars) > lastIndex) {
      result = kHrInsufficientBuffer;
    } else if (static_cast<unsigned int>(formattedChars) != lastIndex) {
      return result;
    }

    buffer[lastIndex] = L'\0';
    return result;
  }

  /**
   * Address: 0x00B2CDF6 (FUN_00B2CDF6)
   *
   * What it does:
   * Scans one bounded narrow string for its terminator and optionally reports
   * the character count before NUL.
   */
  HRESULT __stdcall StrSafeLengthNarrowWorker(
    const char* text,
    int maxChars,
    unsigned int* outLength
  )
  {
    int remaining = maxChars;
    if (maxChars == 0) {
      return kHrInvalidArg;
    }

    do {
      if (*text == '\0') {
        break;
      }

      ++text;
      --remaining;
    } while (remaining != 0);

    if (remaining == 0) {
      return kHrInvalidArg;
    }

    if (outLength != nullptr) {
      *outLength = static_cast<unsigned int>(maxChars - remaining);
    }

    return kHrOk;
  }

  /**
   * Address: 0x00B2CE2D (FUN_00B2CE2D)
   *
   * What it does:
   * Scans one bounded wide string for its terminator and optionally reports
   * the character count before NUL.
   */
  HRESULT __stdcall StrSafeLengthWideWorker(
    const wchar_t* text,
    int maxChars,
    unsigned int* outLength
  )
  {
    int remaining = maxChars;
    if (maxChars == 0) {
      return kHrInvalidArg;
    }

    do {
      if (*text == L'\0') {
        break;
      }

      ++text;
      --remaining;
    } while (remaining != 0);

    if (remaining == 0) {
      return kHrInvalidArg;
    }

    if (outLength != nullptr) {
      *outLength = static_cast<unsigned int>(maxChars - remaining);
    }

    return kHrOk;
  }

} // namespace moho::runtime
