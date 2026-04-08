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

    [[nodiscard]] const char* LookupWinErrorStringNarrow(const HRESULT errorCode)
    {
      thread_local char errorText[512]{};
      errorText[0] = '\0';

      const DWORD formatChars = ::FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(errorCode),
        0,
        errorText,
        static_cast<DWORD>(sizeof(errorText)),
        nullptr
      );
      if (formatChars == 0) {
        return "Unknown";
      }

      DWORD trimCursor = formatChars;
      while (trimCursor > 0) {
        const char tail = errorText[trimCursor - 1];
        if (tail != '\r' && tail != '\n' && tail != '\t' && tail != ' ') {
          break;
        }
        errorText[trimCursor - 1] = '\0';
        --trimCursor;
      }

      return (errorText[0] != '\0') ? errorText : "Unknown";
    }

    [[nodiscard]] const wchar_t* LookupWinErrorStringWide(const HRESULT errorCode)
    {
      thread_local wchar_t errorText[512]{};
      errorText[0] = L'\0';

      const DWORD formatChars = ::FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(errorCode),
        0,
        errorText,
        static_cast<DWORD>(sizeof(errorText) / sizeof(errorText[0])),
        nullptr
      );
      if (formatChars == 0) {
        return L"Unknown";
      }

      DWORD trimCursor = formatChars;
      while (trimCursor > 0) {
        const wchar_t tail = errorText[trimCursor - 1];
        if (tail != L'\r' && tail != L'\n' && tail != L'\t' && tail != L' ') {
          break;
        }
        errorText[trimCursor - 1] = L'\0';
        --trimCursor;
      }

      return (errorText[0] != L'\0') ? errorText : L"Unknown";
    }
  }

  /**
   * Address: 0x00B2CCDC (FUN_00B2CCDC)
   *
   * What it does:
   * Copies one narrow string into a bounded destination and always writes a
   * trailing NUL when destination capacity is non-zero.
   */
  HRESULT __stdcall StrSafeCopyNarrowWorker(char* destination, int destinationChars, const char* source)
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
  HRESULT __stdcall StrSafeCopyWideWorker(wchar_t* destination, int destinationChars, const wchar_t* source)
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

  /**
   * Address: 0x00B5760A (FUN_00B5760A)
   *
   * What it does:
   * Validates narrow destination-count range and forwards to the strsafe copy
   * worker.
   */
  HRESULT __stdcall StrSafeCopyNarrow(char* destination, unsigned int destinationChars, const char* source)
  {
    if (destinationChars <= static_cast<unsigned int>(INT_MAX)) {
      return StrSafeCopyNarrowWorker(destination, static_cast<int>(destinationChars), source);
    }

    return kHrInvalidArg;
  }

  /**
   * Address: 0x00B57627 (FUN_00B57627)
   *
   * What it does:
   * Validates wide destination-count range and forwards to the strsafe copy
   * worker.
   */
  HRESULT __stdcall StrSafeCopyWide(wchar_t* destination, unsigned int destinationChars, const wchar_t* source)
  {
    if (destinationChars <= static_cast<unsigned int>(INT_MAX)) {
      return StrSafeCopyWideWorker(destination, static_cast<int>(destinationChars), source);
    }

    return kHrInvalidArg;
  }

  /**
   * Address: 0x00B57644 (FUN_00B57644)
   *
   * What it does:
   * Narrow variadic strsafe printf wrapper.
   */
  HRESULT __cdecl StrSafePrintfNarrow(char* destination, unsigned int destinationChars, const char* format, ...)
  {
    va_list args;
    va_start(args, format);

    HRESULT result = kHrInvalidArg;
    if (destinationChars <= static_cast<unsigned int>(INT_MAX)) {
      result = StrSafeVPrintfNarrowWorker(destination, static_cast<int>(destinationChars), format, args);
    }

    va_end(args);
    return result;
  }

  /**
   * Address: 0x00B5766D (FUN_00B5766D)
   *
   * What it does:
   * Wide variadic strsafe printf wrapper.
   */
  HRESULT __cdecl StrSafePrintfWide(wchar_t* destination, unsigned int destinationChars, const wchar_t* format, ...)
  {
    va_list args;
    va_start(args, format);

    HRESULT result = kHrInvalidArg;
    if (destinationChars <= static_cast<unsigned int>(INT_MAX)) {
      result = StrSafeVPrintfWideWorker(destination, static_cast<int>(destinationChars), format, args);
    }

    va_end(args);
    return result;
  }

  /**
   * Address: 0x00B57696 (FUN_00B57696)
   *
   * What it does:
   * Validates narrow pointer/count lanes and forwards to bounded length worker.
   */
  HRESULT __stdcall StrSafeLengthNarrow(const char* text, unsigned int maxChars, unsigned int* outLength)
  {
    if (text != nullptr && maxChars <= static_cast<unsigned int>(INT_MAX)) {
      return StrSafeLengthNarrowWorker(text, static_cast<int>(maxChars), outLength);
    }

    return kHrInvalidArg;
  }

  /**
   * Address: 0x00B576B9 (FUN_00B576B9)
   *
   * What it does:
   * Validates wide pointer/count lanes and forwards to bounded length worker.
   */
  HRESULT __stdcall StrSafeLengthWide(const wchar_t* text, unsigned int maxChars, unsigned int* outLength)
  {
    if (text != nullptr && maxChars <= static_cast<unsigned int>(INT_MAX)) {
      return StrSafeLengthWideWorker(text, static_cast<int>(maxChars), outLength);
    }

    return kHrInvalidArg;
  }

  /**
   * Address: 0x00B576DC (FUN_00B576DC)
   *
   * What it does:
   * Reports one wide runtime failure lane to debug output, with optional
   * interactive debug prompt.
   */
  HRESULT __stdcall RuntimeReportHResultWide(
    const char* sourceFilePath,
    int sourceLine,
    HRESULT result,
    const wchar_t* callingExpression,
    int promptForDebug
  )
  {
    wchar_t lineText[128]{};
    StrSafePrintfWide(lineText, 128u, L"%ld", sourceLine);

    wchar_t debugLine[3000]{};
    if (sourceFilePath != nullptr) {
      StrSafePrintfWide(debugLine, 3000u, L"%S(%s): ", sourceFilePath, lineText);
      ::OutputDebugStringW(debugLine);
    }

    unsigned int expressionLength = 0;
    if (callingExpression != nullptr) {
      StrSafeLengthWide(callingExpression, 1024u, &expressionLength);
      if (expressionLength > 0) {
        ::OutputDebugStringW(callingExpression);
        ::OutputDebugStringW(L" ");
      }
    }

    wchar_t errorText[256]{};
    StrSafePrintfWide(errorText, 256u, L"%s (0x%0.8x)", LookupWinErrorStringWide(result), result);
    StrSafePrintfWide(debugLine, 3000u, L"hr=%s", errorText);
    ::OutputDebugStringW(debugLine);
    ::OutputDebugStringW(L"\n");

    if (promptForDebug != 0) {
      char fileText[260]{};
      StrSafeCopyNarrow(fileText, 260u, "");
      if (sourceFilePath != nullptr) {
        StrSafeCopyNarrow(fileText, 260u, sourceFilePath);
      }

      wchar_t callingText[1024]{};
      StrSafeCopyWide(callingText, 1024u, L"");
      if (expressionLength > 0) {
        StrSafePrintfWide(callingText, 1024u, L"Calling: %s\n", callingExpression);
      }

      StrSafePrintfWide(
        debugLine,
        3000u,
        L"File: %S\nLine: %s\nError Code: %s\n%sDo you want to debug the application?",
        fileText,
        lineText,
        errorText,
        callingText
      );

      if (::MessageBoxW(
            ::GetForegroundWindow(),
            debugLine,
            L"Unexpected error encountered",
            MB_YESNO | MB_ICONQUESTION
          ) == IDYES)
      {
        ::DebugBreak();
      }
    }

    return result;
  }

  /**
   * Address: 0x00B578BA (FUN_00B578BA)
   *
   * What it does:
   * Reports one narrow runtime failure lane to debug output, with optional
   * interactive debug prompt.
   */
  HRESULT __stdcall RuntimeReportHResultNarrow(
    const char* sourceFilePath,
    int sourceLine,
    HRESULT result,
    const char* callingExpression,
    int promptForDebug
  )
  {
    char lineText[128]{};
    StrSafePrintfNarrow(lineText, 128u, "%ld", sourceLine);

    char debugLine[3000]{};
    if (sourceFilePath != nullptr) {
      StrSafePrintfNarrow(debugLine, 3000u, "%s(%s): ", sourceFilePath, lineText);
      ::OutputDebugStringA(debugLine);
    }

    unsigned int expressionLength = 0;
    if (callingExpression != nullptr) {
      StrSafeLengthNarrow(callingExpression, 1024u, &expressionLength);
      if (expressionLength > 0) {
        ::OutputDebugStringA(callingExpression);
        ::OutputDebugStringA(" ");
      }
    }

    char errorText[256]{};
    StrSafePrintfNarrow(errorText, 256u, "%s (0x%0.8x)", LookupWinErrorStringNarrow(result), result);
    StrSafePrintfNarrow(debugLine, 3000u, "hr=%s", errorText);
    ::OutputDebugStringA(debugLine);
    ::OutputDebugStringA("\n");

    if (promptForDebug != 0) {
      char fileText[260]{};
      StrSafeCopyNarrow(fileText, 260u, "");
      if (sourceFilePath != nullptr) {
        StrSafeCopyNarrow(fileText, 260u, sourceFilePath);
      }

      char callingText[1024]{};
      StrSafeCopyNarrow(callingText, 1024u, "");
      if (expressionLength > 0) {
        StrSafePrintfNarrow(callingText, 1024u, "Calling: %s\n", callingExpression);
      }

      StrSafePrintfNarrow(
        debugLine,
        3000u,
        "File: %S\nLine: %s\nError Code: %s\n%sDo you want to debug the application?",
        fileText,
        lineText,
        errorText,
        callingText
      );

      if (::MessageBoxA(
            ::GetForegroundWindow(),
            debugLine,
            "Unexpected error encountered",
            MB_YESNO | MB_ICONQUESTION
          ) == IDYES)
      {
        ::DebugBreak();
      }
    }

    return result;
  }
} // namespace moho::runtime
