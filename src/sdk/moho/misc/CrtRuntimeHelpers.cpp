#include <Windows.h>

#include <cctype>
#include <cerrno>
#include <clocale>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <exception>
#include <io.h>
#include <locale>
#include <new>
#include <streambuf>
#include <stdexcept>
#include <string>
#include <sys/timeb.h>

extern "C" void __cdecl _lock(int locknum);
extern "C" void __cdecl _unlock(int locknum);
extern "C" void __cdecl _lock_file(std::FILE* stream);
extern "C" void __cdecl __lock_file2(int streamIndex, std::FILE* stream);
extern "C" void __cdecl __unlock_file2(int streamIndex, std::FILE* stream);
extern "C" int __cdecl _fflush_nolock(std::FILE* stream);
extern "C" int __cdecl _fclose_nolock(std::FILE* stream);
extern "C" int __cdecl _getdrive();
extern "C" void __cdecl _dosmaperr(unsigned long osErrorCode);
extern "C" void __cdecl _get_winmajor(unsigned int* majorVersion);
extern "C" int _nhandle;
extern "C" int _commode;
extern "C" int _cflush;
extern "C" unsigned int _nstream;
extern "C" std::FILE** __piob;
extern "C" std::FILE* __cdecl _getstream();
extern "C" void __cdecl __alloca_probe();
extern "C" int __cdecl _vsnwprintf_l(
  wchar_t* buffer,
  std::size_t bufferCount,
  const wchar_t* format,
  _locale_t locale,
  va_list argList
);
extern "C" int __cdecl _stricmp(const char* lhs, const char* rhs);
extern "C" void* __cdecl _calloc_crt(std::size_t num, std::size_t size);
extern "C" void* __cdecl _decode_pointer(void* encodedPointer);
extern "C" unsigned long __flsindex;
extern "C" void* gpFlsSetValue;
using RuntimeFlsGetValueFn = void* (__stdcall*)(unsigned long flsIndex);
extern "C" RuntimeFlsGetValueFn __cdecl __set_flsgetvalue();
extern "C" void __cdecl __initptd(void* ptd, void* initData);
extern "C" void __cdecl _free_crt(void* ptr);
extern "C" void __cdecl _tzset_nolock();
extern "C" int __mbctype_initialized;
extern "C" void __cdecl __initmbctable();
extern "C" char* _aenvptr;
extern "C" char** _environ;
extern "C" int __env_initialized;
extern "C" __declspec(dllimport) LPCH WINAPI GetEnvironmentStringsA(void);
struct RuntimeIoInfo
{
  std::intptr_t osfhnd;        // +0x00
  std::uint8_t osfile;         // +0x04
  std::uint8_t reserved05[0x1F];
  std::int8_t textmodeUnicode; // +0x24
  std::uint8_t reserved25[0x13];
};
static_assert(offsetof(RuntimeIoInfo, osfhnd) == 0x00, "RuntimeIoInfo::osfhnd offset must be 0x00");
static_assert(offsetof(RuntimeIoInfo, osfile) == 0x04, "RuntimeIoInfo::osfile offset must be 0x04");
static_assert(offsetof(RuntimeIoInfo, textmodeUnicode) == 0x24, "RuntimeIoInfo::textmodeUnicode offset must be 0x24");
static_assert(sizeof(RuntimeIoInfo) == 0x38, "RuntimeIoInfo size must be 0x38");
extern "C" RuntimeIoInfo __badioinfo;
extern "C" RuntimeIoInfo* __pioinfo[];
struct RuntimeThreadLocInfo
{
  volatile long refcount;
};

struct RuntimeLcTimeData
{
  std::uint8_t reserved00[0xB4];
  std::int32_t refcount;
};
static_assert(offsetof(RuntimeLcTimeData, refcount) == 0xB4, "RuntimeLcTimeData::refcount offset must be 0xB4");

struct RuntimeThreadMbcInfo
{
  volatile long refcount;
};

struct RuntimeLocaleHandle
{
  RuntimeThreadLocInfo* locinfo;
  RuntimeThreadMbcInfo* mbcinfo;
};

extern "C" void __cdecl __removelocaleref(RuntimeThreadLocInfo* locinfo);
/**
 * Address: 0x00A8C257 (FUN_00A8C257, ___freetlocinfo)
 *
 * What it does:
 * Releases one CRT thread-locale payload by checking lane-level refcounts and
 * freeing owned locale/category buffers that are no longer shared.
 */
extern "C" void __cdecl __freetlocinfo(RuntimeThreadLocInfo* locinfo);
extern "C" RuntimeThreadLocInfo __initiallocinfo;
extern "C" RuntimeThreadMbcInfo __initialmbcinfo;
extern "C" RuntimeLcTimeData __lc_time_c;
extern "C" lconv __lconv_c;
extern "C" char* __clocalestr;
extern "C" int __cdecl _get_lc_time(RuntimeThreadLocInfo* locinfo, RuntimeLcTimeData* lcTimeData);
extern "C" void __cdecl __free_lc_time(void* lcTimeData);
extern "C" void __cdecl __free_lconv_num(lconv* localeConv);
extern "C" void __cdecl __free_lconv_mon(lconv* localeConv);
extern "C" int __cdecl __getlocaleinfo(
  RuntimeLocaleHandle* localeHandle,
  int localeType,
  LCID localeId,
  int localeField,
  void* output
);
extern "C" LCID* __cdecl __lc_handle_func();
extern "C" int __cdecl __lc_codepage_func();
extern "C" const std::uint16_t* __cdecl __pctype_func();
extern "C" int __cdecl __crtLCMapStringA(
  int localeType,
  LCID locale,
  unsigned int mapFlags,
  LPCCH multiByteString,
  int multiByteCount,
  LPWSTR wideDestination,
  int destinationCount,
  int codePage,
  int errorControl
);
extern "C" int __cdecl __crtLCMapStringW(
  int localeType,
  LCID locale,
  unsigned int mapFlags,
  LPCWSTR wideSource,
  int sourceCount,
  LPWSTR wideDestination,
  int destinationCount,
  int codePage
);
extern "C" int __cdecl __crtGetStringTypeW(
  int localeType,
  unsigned int infoType,
  LPCWCH sourceText,
  int sourceCount,
  LPWORD charTypeOutput,
  int codePage,
  LCID locale
);
extern "C" int __cdecl __crtGetStringTypeA(
  int localeType,
  unsigned int infoType,
  LPCCH sourceText,
  int sourceCount,
  LPWORD charTypeOutput,
  int codePage,
  LCID locale,
  int errorControl
);
struct RuntimeLocaleCodePageView
{
  std::int32_t reserved00;
  std::int32_t codepage;
};
static_assert(offsetof(RuntimeLocaleCodePageView, codepage) == 0x4, "RuntimeLocaleCodePageView::codepage offset must be 0x4");

struct RuntimeLocaleHandleView
{
  std::uint8_t reserved00_0B[0x0C];
  LCID lcHandle[6];
};
static_assert(
  offsetof(RuntimeLocaleHandleView, lcHandle) == 0x0C,
  "RuntimeLocaleHandleView::lcHandle offset must be 0x0C"
);

struct RuntimeSetLocLocaleView
{
  char* pchLanguage;            // +0x00
  char* pchCountry;             // +0x04
  std::int32_t iLcidState;      // +0x08
  std::int32_t iPrimaryLen;     // +0x0C
  std::int32_t bAbbrevLanguage; // +0x10
  std::int32_t bAbbrevCountry;  // +0x14
  LCID lcidLanguage;            // +0x18
  LCID lcidCountry;             // +0x1C
};
static_assert(offsetof(RuntimeSetLocLocaleView, pchLanguage) == 0x0, "RuntimeSetLocLocaleView::pchLanguage offset must be 0x0");
static_assert(offsetof(RuntimeSetLocLocaleView, pchCountry) == 0x4, "RuntimeSetLocLocaleView::pchCountry offset must be 0x4");
static_assert(offsetof(RuntimeSetLocLocaleView, iLcidState) == 0x8, "RuntimeSetLocLocaleView::iLcidState offset must be 0x8");
static_assert(offsetof(RuntimeSetLocLocaleView, iPrimaryLen) == 0xC, "RuntimeSetLocLocaleView::iPrimaryLen offset must be 0xC");
static_assert(offsetof(RuntimeSetLocLocaleView, bAbbrevLanguage) == 0x10, "RuntimeSetLocLocaleView::bAbbrevLanguage offset must be 0x10");
static_assert(offsetof(RuntimeSetLocLocaleView, bAbbrevCountry) == 0x14, "RuntimeSetLocLocaleView::bAbbrevCountry offset must be 0x14");
static_assert(offsetof(RuntimeSetLocLocaleView, lcidLanguage) == 0x18, "RuntimeSetLocLocaleView::lcidLanguage offset must be 0x18");
static_assert(offsetof(RuntimeSetLocLocaleView, lcidCountry) == 0x1C, "RuntimeSetLocLocaleView::lcidCountry offset must be 0x1C");
static_assert(sizeof(RuntimeSetLocLocaleView) == 0x20, "RuntimeSetLocLocaleView size must be 0x20");

struct RuntimeTidDataLocaleView
{
  std::uint8_t reserved00[0x6C];
  RuntimeLocaleCodePageView* ptlocinfo;
  std::int32_t ownlocale;
  std::uint8_t reserved74[0x28];
  RuntimeSetLocLocaleView setlocData;
};
static_assert(offsetof(RuntimeTidDataLocaleView, ptlocinfo) == 0x6C, "RuntimeTidDataLocaleView::ptlocinfo offset must be 0x6C");
static_assert(offsetof(RuntimeTidDataLocaleView, ownlocale) == 0x70, "RuntimeTidDataLocaleView::ownlocale offset must be 0x70");
static_assert(offsetof(RuntimeTidDataLocaleView, setlocData) == 0x9C, "RuntimeTidDataLocaleView::setlocData offset must be 0x9C");

struct RuntimeThreadMbcInfoCaseView
{
  std::uint8_t reserved00_03[0x4];
  std::uint32_t mbcodepage;
  std::uint8_t reserved08_0B[0x4];
  LCID mblcid;
  std::uint8_t reserved10_1B[0xC];
  std::uint8_t mbctype[0x101];
  std::uint8_t mbcasemap[0x100];
};
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbcodepage) == 0x4, "RuntimeThreadMbcInfoCaseView::mbcodepage offset must be 0x4");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mblcid) == 0xC, "RuntimeThreadMbcInfoCaseView::mblcid offset must be 0xC");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbctype) == 0x1C, "RuntimeThreadMbcInfoCaseView::mbctype offset must be 0x1C");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbcasemap) == 0x11D, "RuntimeThreadMbcInfoCaseView::mbcasemap offset must be 0x11D");

extern "C" RuntimeLocaleCodePageView* __ptlocinfo;
extern "C" std::int32_t __globallocalestatus;
extern "C" RuntimeTidDataLocaleView* __cdecl __getptd();
extern "C" RuntimeLocaleCodePageView* __cdecl __updatetlocinfo();
extern "C" int _getvalueindex;
extern "C" void __cdecl _freefls(void* ptd);
extern "C" int __cdecl _flsbuf(int character, std::FILE* stream);
extern "C" void __cdecl _invalid_parameter(
  const wchar_t* expression,
  const wchar_t* functionName,
  const wchar_t* fileName,
  unsigned int lineNumber,
  std::uintptr_t reserved
);
extern "C" void __cdecl _invoke_watson(
  const wchar_t* expression,
  const wchar_t* functionName,
  const wchar_t* fileName,
  unsigned int lineNumber,
  std::uintptr_t reserved
);
extern "C" int __cdecl _memicmp_l(
  const void* lhsBuffer,
  const void* rhsBuffer,
  std::size_t byteCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _strnicoll_l(
  const char* lhsText,
  const char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _mbsicmp_l(const unsigned char* lhsText, const unsigned char* rhsText, _locale_t localeInfo);
extern "C" int __cdecl _mbsnbicoll_l(
  const unsigned char* lhsText,
  const unsigned char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" void* __cdecl _recalloc(void* memblock, std::size_t count, std::size_t size);
extern "C" unsigned long _maxwait;
extern "C" unsigned int _osplatform;
extern "C" long _timezone;
extern "C" long _dstbias;
extern "C" int daylight;
extern "C" HANDLE _crtheap;
extern "C" int _active_heap;
extern "C" int __app_type;
extern "C" wchar_t** _wenviron;
extern "C" int __cdecl __crtsetenv(const unsigned char** option, int primary);
extern "C" int __cdecl _heap_select();
extern "C" int __cdecl _sbh_heap_init(std::size_t regionSize);
extern "C" unsigned long* __cdecl doserrno();
extern "C" __time64_t __cdecl __loctotime64_t(
  int year,
  int month,
  int day,
  int hour,
  int minute,
  int second,
  int dstflag
);
/**
 * Address: 0x00A83523 (FUN_00A83523, atof)
 *
 * What it does:
 * Parses a null-terminated C string through the CRT `atof` lane and returns
 * the floating-point result.
 */
extern "C" double __cdecl RuntimeAtofForward(const char* text);

/**
 * Address: 0x00A83523 (FUN_00A83523, atof)
 *
 * What it does:
 * Parses a null-terminated C string through the CRT `atof` lane and returns
 * the floating-point result.
 */
extern "C" double __cdecl RuntimeAtofForward(const char* text)
{
  return std::atof(text);
}

/**
 * Address: 0x00A836A7 (FUN_00A836A7, _get_osplatform)
 *
 * What it does:
 * Returns one CRT platform id through `outPlatform` when both pointer and
 * runtime `_osplatform` lane are valid; otherwise reports invalid-parameter
 * semantics and returns `EINVAL`.
 */
extern "C" int __cdecl _get_osplatform(unsigned int* const outPlatform)
{
  if (outPlatform != nullptr && _osplatform != 0u) {
    *outPlatform = _osplatform;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00AAAE40 (FUN_00AAAE40, __heap_init)
 *
 * What it does:
 * Initializes CRT process heap state (`_crtheap`), selects active heap mode,
 * and conditionally initializes the small-block heap lane.
 */
extern "C" int __cdecl _heap_init(const int mtflag)
{
  _crtheap = ::HeapCreate((mtflag == 0) ? 1u : 0u, 0x1000u, 0u);
  if (_crtheap == nullptr) {
    return 0;
  }

  _active_heap = _heap_select();
  if (_active_heap == 3 && _sbh_heap_init(0x3F8u) == 0) {
    (void)::HeapDestroy(_crtheap);
    _crtheap = nullptr;
    return 0;
  }

  return 1;
}

/**
 * Address: 0x00A9CC78 (FUN_00A9CC78, __get_daylight)
 *
 * What it does:
 * Returns the CRT `daylight` lane through `outDaylight`; invalid output
 * pointers report `EINVAL` and invalid-parameter semantics.
 */
extern "C" int __cdecl _get_daylight(int* const outDaylight)
{
  if (outDaylight != nullptr) {
    *outDaylight = daylight;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00A9CCAC (FUN_00A9CCAC, _get_dstbias)
 *
 * What it does:
 * Returns the CRT daylight-saving bias lane through `outDstBias`; invalid
 * output pointers report `EINVAL` and invalid-parameter semantics.
 */
extern "C" int __cdecl _get_dstbias(long* const outDstBias)
{
  if (outDstBias != nullptr) {
    *outDstBias = _dstbias;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00A9CCE0 (FUN_00A9CCE0, _get_timezone)
 *
 * What it does:
 * Returns the CRT timezone lane through `outTimezone`; invalid output pointers
 * report `EINVAL` and invalid-parameter semantics.
 */
extern "C" int __cdecl _get_timezone(long* const outTimezone)
{
  if (outTimezone != nullptr) {
    *outTimezone = _timezone;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00AA64C8 (FUN_00AA64C8, ___lc_codepage_func)
 *
 * What it does:
 * Returns the active CRT locale codepage lane for the current thread, updating
 * thread-locale pointers when this thread is not in global-locale mode.
 */
extern "C" int __cdecl __lc_codepage_func()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  RuntimeLocaleCodePageView* locale = threadData->ptlocinfo;
  if (locale != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    locale = __updatetlocinfo();
  }
  return locale->codepage;
}

/**
 * Address: 0x00AA6514 (FUN_00AA6514, ___lc_handle_func)
 *
 * What it does:
 * Returns the active CRT locale-handle array lane for the current thread,
 * refreshing thread-locale state when not in global-locale mode.
 */
extern "C" LCID* __cdecl __lc_handle_func()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  RuntimeLocaleCodePageView* locale = threadData->ptlocinfo;
  if (locale != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    locale = __updatetlocinfo();
  }

  return reinterpret_cast<RuntimeLocaleHandleView*>(locale)->lcHandle;
}

namespace
{
  // Address: 0x00FB82B0 (`unk_FB82B0` in `getSystemCP` callers).
  std::int32_t gSetMbcpUsedSystemCodePage = 0;
}

/**
 * Address: 0x00A97C75 (FUN_00A97C75, ?getSystemCP@@YAHH@Z)
 * Mangled: ?getSystemCP@@YAHH@Z
 *
 * What it does:
 * Resolves `_setmbcp` sentinel inputs (-2/-3/-4) to active system codepages
 * and latches whether a system-codepage sentinel was consumed.
 */
extern "C" int __cdecl getSystemCP(const int codePage)
{
  gSetMbcpUsedSystemCodePage = 0;

  switch (codePage) {
  case -2:
    gSetMbcpUsedSystemCodePage = 1;
    return static_cast<int>(::GetOEMCP());
  case -3:
    gSetMbcpUsedSystemCodePage = 1;
    return static_cast<int>(::GetACP());
  case -4:
    gSetMbcpUsedSystemCodePage = 1;
    return __lc_codepage_func();
  default:
    return codePage;
  }
}

/**
 * Address: 0x00A84313 (FUN_00A84313, __time64_t_from_ft)
 *
 * What it does:
 * Converts one non-zero `FILETIME` to local broken-down time and then to
 * `__time64_t`; returns `-1` when conversion fails.
 */
extern "C" __time64_t __cdecl __time64_t_from_ft(FILETIME* const fileTime)
{
  FILETIME localFileTime{};
  SYSTEMTIME systemTime{};

  if ((fileTime->dwLowDateTime != 0u || fileTime->dwHighDateTime != 0u)
      && ::FileTimeToLocalFileTime(fileTime, &localFileTime) != 0
      && ::FileTimeToSystemTime(&localFileTime, &systemTime) != 0) {
    return __loctotime64_t(
      static_cast<int>(systemTime.wYear),
      static_cast<int>(systemTime.wMonth),
      static_cast<int>(systemTime.wDay),
      static_cast<int>(systemTime.wHour),
      static_cast<int>(systemTime.wMinute),
      static_cast<int>(systemTime.wSecond),
      -1
    );
  }

  return static_cast<__time64_t>(-1);
}

/**
 * Address: 0x00AB67E1 (FUN_00AB67E1, _ansicp)
 *
 * What it does:
 * Reads the locale's default ANSI codepage string and converts it to an
 * integer codepage value.
 */
extern "C" int __cdecl RuntimeAnsiCodePageFromLocale(const LCID locale)
{
  constexpr int kAnsiCodePageBufferLength = 6;
  char localeCodePage[8]{};
  localeCodePage[6] = '\0';

  if (::GetLocaleInfoA(locale, LOCALE_IDEFAULTANSICODEPAGE, localeCodePage, kAnsiCodePageBufferLength) != 0) {
    return static_cast<int>(std::atol(localeCodePage));
  }

  return -1;
}

/**
 * Address: 0x00A8554F (FUN_00A8554F, fopen)
 *
 * What it does:
 * Opens a narrow stream through the CRT `_fsopen` lane with the shared
 * read/write mode used by the binary thunk.
 */
extern "C" std::FILE* __cdecl RuntimeFopen(const char* const filePath, const char* const mode)
{
  return ::_fsopen(filePath, mode, 64);
}

/**
 * Address: 0x00A85562 (FUN_00A85562, fopen_0)
 *
 * What it does:
 * Writes one opened file handle to `outFile` using `_fsopen(..., 128)` and
 * returns CRT-style status (`0` or `errno`), with invalid-parameter semantics
 * when `outFile` is null.
 */
extern "C" int __cdecl RuntimeFopenS(std::FILE** const outFile, char* const filePath, char* const mode)
{
  if (outFile != nullptr) {
    std::FILE* const file = ::_fsopen(filePath, mode, 128);
    *outFile = file;
    return file != nullptr ? 0 : *_errno();
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00A85D8F (FUN_00A85D8F, _Getlconv)
 *
 * What it does:
 * Refreshes the active thread locale lane when needed, then returns the CRT
 * locale conversion table pointer.
 */
extern "C" lconv* __cdecl RuntimeGetlconv()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  if (threadData->ptlocinfo != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    (void)__updatetlocinfo();
  }
  return std::localeconv();
}

using RuntimeOutputFn = int(__cdecl*)(std::FILE* stream, const char* format, _locale_t localeInfo, va_list arguments);
using RuntimeWideOutputFn = int(__cdecl*)(std::FILE* stream, const wchar_t* format, _locale_t localeInfo, va_list arguments);

/**
 * Address: 0x00A95342 (FUN_00A95342, _vsnprintf_helper)
 *
 * What it does:
 * Executes one CRT vararg output callback over a stack `FILE` sink and applies
 * `_vsnprintf`-style truncation/terminator semantics.
 */
extern "C" int __cdecl _vsnprintf_helper(
  const RuntimeOutputFn outfn,
  char* const string,
  const std::size_t count,
  const char* const format,
  _locale_t const localeInfo,
  va_list arguments
)
{
  if (format == nullptr || (count != 0u && string == nullptr)) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  std::FILE outputFile{};
  outputFile._cnt = 0x7FFFFFFF;
  if (count <= 0x7FFFFFFFu) {
    outputFile._cnt = static_cast<int>(count);
  }
  outputFile._flag = 0x42;
  outputFile._base = string;
  outputFile._ptr = string;

  const int formatResult = outfn(&outputFile, format, localeInfo, arguments);
  if (string == nullptr) {
    return formatResult;
  }

  if (formatResult >= 0) {
    --outputFile._cnt;
    if (outputFile._cnt >= 0) {
      *outputFile._ptr = '\0';
      return formatResult;
    }
    if (_flsbuf(0, &outputFile) != -1) {
      return formatResult;
    }
  }

  const bool remainingIsNonNegative = outputFile._cnt >= 0;
  string[count - 1u] = '\0';
  return remainingIsNonNegative ? -1 : -2;
}

/**
 * Address: 0x00A9B437 (FUN_00A9B437, ___wtomb_environ)
 *
 * What it does:
 * Rebuilds narrow environment entries from `_wenviron` by converting each
 * string with `WideCharToMultiByte` and forwarding ownership to `__crtsetenv`.
 */
extern "C" int __cdecl __wtomb_environ()
{
  wchar_t** environmentWide = _wenviron;
  char* convertedEntry = nullptr;
  if (environmentWide == nullptr || *environmentWide == nullptr) {
    return 0;
  }

  while (*environmentWide != nullptr) {
    const int byteCount = ::WideCharToMultiByte(0, 0, *environmentWide, -1, nullptr, 0, nullptr, nullptr);
    if (byteCount == 0) {
      return -1;
    }

    convertedEntry = static_cast<char*>(_calloc_crt(static_cast<std::size_t>(byteCount), 1u));
    if (convertedEntry == nullptr) {
      return -1;
    }

    if (::WideCharToMultiByte(0, 0, *environmentWide, -1, convertedEntry, byteCount, nullptr, nullptr) == 0) {
      _free_crt(convertedEntry);
      return -1;
    }

    if (__crtsetenv(reinterpret_cast<const unsigned char**>(&convertedEntry), 0) < 0) {
      if (convertedEntry != nullptr) {
        _free_crt(convertedEntry);
        convertedEntry = nullptr;
      }
    }

    ++environmentWide;
  }

  return 0;
}

/**
 * Address: 0x00AAE426 (FUN_00AAE426, vwprintf_helper)
 *
 * What it does:
 * Builds one stack `FILE` sink for wide-format output callbacks; null format
 * uses CRT invalid-parameter failure semantics.
 */
extern "C" int __cdecl
vwprintf_helper(const RuntimeWideOutputFn woutfn, const wchar_t* const format, _locale_t const plocinfo, va_list ap)
{
  if (format == nullptr) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  std::FILE outputFile{};
  outputFile._cnt = 0x7FFFFFFF;
  outputFile._flag = 0x42;
  outputFile._base = nullptr;
  outputFile._ptr = nullptr;
  return woutfn(&outputFile, format, plocinfo, ap);
}

/**
 * Address: 0x00AAF2CF (FUN_00AAF2CF, _set_osfhnd)
 *
 * What it does:
 * Binds one OS handle to an unopened CRT fd slot and mirrors fd 0/1/2 to
 * Win32 standard handles for console apps.
 */
extern "C" int __cdecl _set_osfhnd(const int fileDescriptor, const std::intptr_t osHandle)
{
  if (fileDescriptor >= 0 && fileDescriptor < _nhandle) {
    RuntimeIoInfo* const ioBlock = __pioinfo[fileDescriptor >> 5];
    RuntimeIoInfo* const ioInfo = ioBlock + (fileDescriptor & 0x1F);
    if (ioInfo->osfhnd == static_cast<std::intptr_t>(-1)) {
      constexpr int kConsoleAppType = 1;
      const HANDLE handle = reinterpret_cast<HANDLE>(osHandle);

      if (__app_type == kConsoleAppType) {
        if (fileDescriptor == 0) {
          ::SetStdHandle(STD_INPUT_HANDLE, handle);
        } else if (fileDescriptor == 1) {
          ::SetStdHandle(STD_OUTPUT_HANDLE, handle);
        } else if (fileDescriptor == 2) {
          ::SetStdHandle(STD_ERROR_HANDLE, handle);
        }
      }

      ioInfo->osfhnd = osHandle;
      return 0;
    }
  }

  *_errno() = EBADF;
  *doserrno() = 0;
  return -1;
}

/**
 * Address: 0x00A95D4F (FUN_00A95D4F, _freeptd)
 *
 * What it does:
 * Releases one thread CRT `_tiddata` lane from FLS/TLS and clears TLS slots
 * used by `_getptd` accessors.
 */
extern "C" DWORD __cdecl _freeptd(void* threadData)
{
  if (__flsindex != 0xFFFFFFFFu) {
    void* dataToFree = threadData;
    if (dataToFree == nullptr && ::TlsGetValue(_getvalueindex) != nullptr) {
      using RuntimeFlsGetValueThunk = void* (__stdcall*)(unsigned long index);
      auto* const flsGetValueThunk = reinterpret_cast<RuntimeFlsGetValueThunk>(::TlsGetValue(_getvalueindex));
      dataToFree = flsGetValueThunk(__flsindex);
    }

    using RuntimeFlsSetValueThunk = void(__stdcall*)(unsigned long index, void* value);
    auto* const flsSetValueThunk = reinterpret_cast<RuntimeFlsSetValueThunk>(_decode_pointer(gpFlsSetValue));
    flsSetValueThunk(__flsindex, nullptr);
    _freefls(dataToFree);
  }

  if (_getvalueindex != -1) {
    return ::TlsSetValue(_getvalueindex, nullptr);
  }
  return static_cast<DWORD>(_getvalueindex);
}

/**
 * Address: 0x00A97A47 (FUN_00A97A47, setSBUpLow)
 *
 * What it does:
 * Builds single-byte uppercase/lowercase case-map lanes for one CRT multibyte
 * codepage descriptor, with ASCII fallback when codepage metadata is absent.
 */
extern "C" void __cdecl setSBUpLow(RuntimeThreadMbcInfoCaseView* const threadMbcInfo)
{
  if (threadMbcInfo == nullptr) {
    return;
  }

  CPINFO codePageInfo{};
  if (::GetCPInfo(threadMbcInfo->mbcodepage, &codePageInfo) != FALSE) {
    std::uint8_t singleByteVector[256]{};
    for (std::size_t index = 0; index < _countof(singleByteVector); ++index) {
      singleByteVector[index] = static_cast<std::uint8_t>(index);
    }
    singleByteVector[0] = static_cast<std::uint8_t>(' ');

    std::uint8_t leadStart = codePageInfo.LeadByte[0];
    if (leadStart != 0u) {
      std::uint8_t* leadRangeCursor = &codePageInfo.LeadByte[1];
      do {
        const std::uint8_t leadEnd = *leadRangeCursor;
        if (leadStart <= leadEnd) {
          std::memset(&singleByteVector[leadStart], ' ', static_cast<std::size_t>(leadEnd - leadStart + 1u));
        }

        leadStart = *++leadRangeCursor;
        ++leadRangeCursor;
      } while (leadStart != 0u);
    }

    WORD categoryVector[256]{};
    wchar_t lowerVector[128]{};
    wchar_t upperVector[128]{};
    __crtGetStringTypeA(
      0,
      1u,
      reinterpret_cast<LPCCH>(singleByteVector),
      256,
      categoryVector,
      static_cast<int>(threadMbcInfo->mbcodepage),
      threadMbcInfo->mblcid,
      0
    );
    __crtLCMapStringA(
      0,
      threadMbcInfo->mblcid,
      LCMAP_LOWERCASE,
      reinterpret_cast<LPCCH>(singleByteVector),
      256,
      lowerVector,
      256,
      static_cast<int>(threadMbcInfo->mbcodepage),
      0
    );
    __crtLCMapStringA(
      0,
      threadMbcInfo->mblcid,
      LCMAP_UPPERCASE,
      reinterpret_cast<LPCCH>(singleByteVector),
      256,
      upperVector,
      256,
      static_cast<int>(threadMbcInfo->mbcodepage),
      0
    );

    const auto* const lowerByteVector = reinterpret_cast<const std::uint8_t*>(lowerVector);
    const auto* const upperByteVector = reinterpret_cast<const std::uint8_t*>(upperVector);
    for (std::size_t index = 0; index < 256u; ++index) {
      const WORD category = categoryVector[index];
      if ((category & 0x0001u) != 0u) {
        threadMbcInfo->mbctype[index + 1u] |= 0x10u;
        threadMbcInfo->mbcasemap[index] = lowerByteVector[index];
      } else if ((category & 0x0002u) != 0u) {
        threadMbcInfo->mbctype[index + 1u] |= 0x20u;
        threadMbcInfo->mbcasemap[index] = upperByteVector[index];
      } else {
        threadMbcInfo->mbcasemap[index] = 0u;
      }
    }

    return;
  }

  for (std::uint32_t index = 0; index < 256u; ++index) {
    if (index >= static_cast<std::uint32_t>('A') && index <= static_cast<std::uint32_t>('Z')) {
      threadMbcInfo->mbctype[index + 1u] |= 0x10u;
      threadMbcInfo->mbcasemap[index] = static_cast<std::uint8_t>(index + ('a' - 'A'));
    } else if (index >= static_cast<std::uint32_t>('a') && index <= static_cast<std::uint32_t>('z')) {
      threadMbcInfo->mbctype[index + 1u] |= 0x20u;
      threadMbcInfo->mbcasemap[index] = static_cast<std::uint8_t>(index - ('a' - 'A'));
    } else {
      threadMbcInfo->mbcasemap[index] = 0u;
    }
  }
}

/**
 * Address: 0x00A9604C (FUN_00A9604C, __recalloc_crt)
 *
 * What it does:
 * Repeatedly retries CRT `_recalloc` with the legacy backoff lane until either
 * allocation succeeds, size is zero, or the wait budget is exhausted.
 */
extern "C" void* __cdecl __recalloc_crt(void* const ptr, const std::size_t count, const std::size_t size)
{
  DWORD seconds = 0;
  void* result = nullptr;
  DWORD nextSeconds = 0;

  do {
    result = _recalloc(ptr, count, size);
    if (result != nullptr || size == 0u || _maxwait == 0u) {
      break;
    }

    ::Sleep(seconds);
    nextSeconds = seconds + 1000u;
    if (seconds + 1000u > _maxwait) {
      nextSeconds = static_cast<DWORD>(-1);
    }
    seconds = nextSeconds;
  } while (nextSeconds != static_cast<DWORD>(-1));

  return result;
}

namespace
{
  using RuntimeSignalHandler = void(__cdecl*)(int);

  constexpr int kRuntimeEnvironmentLock = 7;
  constexpr int kRuntimeSetLocaleLock = 12;
  constexpr int kRuntimeIobScanLock = 1;
  constexpr int kRuntimeSignalLock = 0;
  constexpr int kRuntimeTimeLock = 6;
  constexpr int kRuntimeFileFlagFlushMask = 0x83;
  constexpr int kRuntimeFileFlagWritable = 0x02;
  constexpr std::uint64_t kFiletimeHundredNsPerMillisecond = 10000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerSecond = 10000000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerMinute = 600000000ull;
  constexpr std::uint64_t kFiletimeToUnixEpochOffset = 116444736000000000ull;
  constexpr std::size_t kRuntimeCodePageLocaleHashBucketCount = 0x3Eu;
  constexpr int kRuntimeOnExitFailureCode = 0x18;

  std::int64_t gRuntimeElapsedMinutesCache = 0;
  std::int32_t gRuntimeDstFlagCache = 0;
  std::int32_t gRuntimeTzsetFirstTime = 0;
  std::int32_t gRuntimeGetEnvironmentStringsEncodingMode = 0;
  void* gRuntimeCtrlCActionEncoded = nullptr;
  void* gRuntimeCtrlBreakActionEncoded = nullptr;
  volatile long gRuntimeStdLockInit = -1;
  CRITICAL_SECTION gRuntimeStdLockSlots[4]{};
  void* gRuntimeIosStdStreams[9]{};
  std::int8_t gRuntimeIosStdOpenCounts[9]{};
  struct RuntimeCodePageLocaleHashEntry;
  struct RuntimeLocaleLocimpView;
  RuntimeCodePageLocaleHashEntry* gRuntimeCodePageLocaleHash[kRuntimeCodePageLocaleHashBucketCount]{};
  RuntimeLocaleLocimpView* gRuntimeGlobalLocale = nullptr;
  RuntimeLocaleLocimpView* gRuntimeClassicLocale = nullptr;
  std::uint8_t gRuntimeGlobalLocaleAtexitRegistered = 0;
  std::int32_t gRuntimeLocaleIdCounter = 0;
  std::int32_t gRuntimeLocaleIdCtypeChar = 0;
  std::int32_t gRuntimeLocaleIdSlotA = 0;
  std::int32_t gRuntimeLocaleIdSlotB = 0;
  std::int32_t gRuntimeLocaleIdSlotC = 0;
  std::int32_t gRuntimeLocaleIdSlotD = 0;
  std::uintptr_t gRuntimeStaticStorageSlotA = 0;
  std::int32_t gRuntimeStaticStorageSlotB = 0;
  std::uintptr_t gRuntimeStaticStorageSlotC = 0;
  std::uintptr_t gRuntimeStaticStorageSlotD = 0;
  struct RuntimeStdLocaleObject
  {
    RuntimeLocaleLocimpView* ptr = nullptr;
  };
  static_assert(sizeof(RuntimeStdLocaleObject) == 0x4, "RuntimeStdLocaleObject size must be 0x4");
  RuntimeStdLocaleObject gRuntimeClassicLocaleObject{};
  struct RuntimeFacetNode
  {
    RuntimeFacetNode* next = nullptr;
    std::locale::facet* facet = nullptr;
  };
  static_assert(sizeof(RuntimeFacetNode) == 0x8, "RuntimeFacetNode size must be 0x8");
  RuntimeFacetNode* gRuntimeFacetHead = nullptr;

  struct RuntimeLockitState
  {
    std::int32_t slot = 0;
  };
  static_assert(sizeof(RuntimeLockitState) == 0x4, "RuntimeLockitState size must be 0x4");

  struct RuntimeMutexHandle
  {
    CRITICAL_SECTION* criticalSection = nullptr;
  };
  static_assert(sizeof(RuntimeMutexHandle) == 0x4, "RuntimeMutexHandle size must be 0x4");

  struct RuntimeCodePageLocaleHashEntry
  {
    RuntimeCodePageLocaleHashEntry* next = nullptr; // +0x00
    std::uint32_t codePage = 0;                     // +0x04
    RuntimeLocaleHandle* locale = nullptr;          // +0x08
  };
  static_assert(sizeof(RuntimeCodePageLocaleHashEntry) == 0xC, "RuntimeCodePageLocaleHashEntry size must be 0xC");

  [[nodiscard]] unsigned long* RuntimeDosErrno();

  [[nodiscard]] int RuntimeGetFileFlags(std::FILE* const stream) noexcept
  {
    if (stream == nullptr) {
      return 0;
    }

    int flags = 0;
    if (std::ferror(stream) != 0) {
      flags |= 0x20;
    }
    if (std::feof(stream) != 0) {
      flags |= 0x10;
    }
    if (::_fileno(stream) >= 0) {
      flags |= kRuntimeFileFlagFlushMask;
    }
    return flags;
  }

  void RuntimeMtxInit(CRITICAL_SECTION* const lock) noexcept
  {
    ::InitializeCriticalSection(lock);
  }

  int RuntimeMtxLock(CRITICAL_SECTION* const lock) noexcept
  {
    ::EnterCriticalSection(lock);
    return 0;
  }

  int RuntimeMtxUnlock(CRITICAL_SECTION* const lock) noexcept
  {
    ::LeaveCriticalSection(lock);
    return 0;
  }

  void RuntimeMtxDestroy(CRITICAL_SECTION* const lock) noexcept
  {
    ::DeleteCriticalSection(lock);
  }

  [[nodiscard]] CRITICAL_SECTION* RuntimeStdLockSlot(const int slot) noexcept
  {
    return &gRuntimeStdLockSlots[slot & 3];
  }

  struct RuntimeFileTmpNameView
  {
    std::uint8_t reserved00[0x1C];
    char* tmpName;
  };
  static_assert(offsetof(RuntimeFileTmpNameView, tmpName) == 0x1C, "RuntimeFileTmpNameView::tmpName offset must be 0x1C");

  struct RuntimeFileLockView
  {
    std::uint8_t reserved00[0x20];
    CRITICAL_SECTION lock;
  };
  static_assert(offsetof(RuntimeFileLockView, lock) == 0x20, "RuntimeFileLockView::lock offset must be 0x20");

  struct RuntimeLocaleLocimpView
  {
    void* vtable = nullptr;         // +0x00
    std::int32_t refs = 0;          // +0x04
    void* facetVector = nullptr;    // +0x08
    std::int32_t facetCount = 0;    // +0x0C
    std::int32_t categoryMask = 0;  // +0x10
    std::uint8_t isParent = 0;      // +0x14
    std::uint8_t reserved15[0x3]{}; // +0x15
    std::string name;               // +0x18
  };

  struct RuntimeLocaleCategoryView
  {
    const char* localeName = nullptr; // +0x00
    void* localeWideName = nullptr;   // +0x04
    int* localeRefcount = nullptr;    // +0x08
    int* wideRefcount = nullptr;      // +0x0C
  };
  static_assert(sizeof(RuntimeLocaleCategoryView) == 0x10, "RuntimeLocaleCategoryView size must be 0x10");

  struct RuntimeCtypeVec
  {
    LCID handle = 0;                        // +0x00
    std::int32_t codePage = 0;              // +0x04
    const std::uint16_t* table = nullptr;   // +0x08
    std::int32_t ownsCopiedTable = 0;       // +0x0C
  };
  static_assert(offsetof(RuntimeCtypeVec, handle) == 0x0, "RuntimeCtypeVec::handle offset must be 0x0");
  static_assert(offsetof(RuntimeCtypeVec, codePage) == 0x4, "RuntimeCtypeVec::codePage offset must be 0x4");
  static_assert(offsetof(RuntimeCtypeVec, table) == 0x8, "RuntimeCtypeVec::table offset must be 0x8");
  static_assert(offsetof(RuntimeCtypeVec, ownsCopiedTable) == 0xC, "RuntimeCtypeVec::ownsCopiedTable offset must be 0xC");
  static_assert(sizeof(RuntimeCtypeVec) == 0x10, "RuntimeCtypeVec size must be 0x10");

  struct RuntimeCvtVec
  {
    LCID handle = 0;           // +0x00
    std::int32_t codePage = 0; // +0x04
  };
  static_assert(sizeof(RuntimeCvtVec) == 0x8, "RuntimeCvtVec size must be 0x8");

  struct RuntimeThreadLocInfoView
  {
    volatile long refcount = 0;              // +0x00
    std::uint8_t reserved04[0x08]{};         // +0x04
    LCID lcHandle[6]{};                       // +0x0C
    std::uint8_t reserved24[0x08]{};          // +0x24
    LCID lcId[6]{};                           // +0x2C
    std::uint8_t reserved44[0x0C]{};          // +0x44
    RuntimeLocaleCategoryView categories[6];  // +0x50
    int* lconvIntlRefcount = nullptr;         // +0xB0
    int* lconvNumRefcount = nullptr;          // +0xB4
    int* lconvMonRefcount = nullptr;          // +0xB8
    lconv* localeConv = nullptr;              // +0xBC
    int* ctype1Refcount = nullptr;            // +0xC0
    std::uint16_t* ctype1 = nullptr;          // +0xC4
    std::uint8_t reservedC8[0x04]{};          // +0xC8
    unsigned char* pclmap = nullptr;          // +0xCC
    unsigned char* pcumap = nullptr;          // +0xD0
    RuntimeLcTimeData* lcTimeCurrent = nullptr; // +0xD4
  };
  static_assert(offsetof(RuntimeThreadLocInfoView, lcHandle) == 0x0C, "RuntimeThreadLocInfoView::lcHandle offset must be 0x0C");
  static_assert(offsetof(RuntimeThreadLocInfoView, lcId) == 0x2C, "RuntimeThreadLocInfoView::lcId offset must be 0x2C");
  static_assert((offsetof(RuntimeThreadLocInfoView, lcHandle) + sizeof(LCID) * 3u) == 0x18, "RuntimeThreadLocInfoView::lcHandle[3] offset must be 0x18");
  static_assert((offsetof(RuntimeThreadLocInfoView, lcHandle) + sizeof(LCID) * 4u) == 0x1C, "RuntimeThreadLocInfoView::lcHandle[4] offset must be 0x1C");
  static_assert((offsetof(RuntimeThreadLocInfoView, lcId) + sizeof(LCID) * 3u) == 0x38, "RuntimeThreadLocInfoView::lcId[3] offset must be 0x38");
  static_assert(offsetof(RuntimeThreadLocInfoView, categories) == 0x50, "RuntimeThreadLocInfoView::categories offset must be 0x50");
  static_assert(offsetof(RuntimeThreadLocInfoView, lconvIntlRefcount) == 0xB0, "RuntimeThreadLocInfoView::lconvIntlRefcount offset must be 0xB0");
  static_assert(offsetof(RuntimeThreadLocInfoView, lconvNumRefcount) == 0xB4, "RuntimeThreadLocInfoView::lconvNumRefcount offset must be 0xB4");
  static_assert(offsetof(RuntimeThreadLocInfoView, lconvMonRefcount) == 0xB8, "RuntimeThreadLocInfoView::lconvMonRefcount offset must be 0xB8");
  static_assert(offsetof(RuntimeThreadLocInfoView, localeConv) == 0xBC, "RuntimeThreadLocInfoView::localeConv offset must be 0xBC");
  static_assert(offsetof(RuntimeThreadLocInfoView, ctype1Refcount) == 0xC0, "RuntimeThreadLocInfoView::ctype1Refcount offset must be 0xC0");
  static_assert(offsetof(RuntimeThreadLocInfoView, ctype1) == 0xC4, "RuntimeThreadLocInfoView::ctype1 offset must be 0xC4");
  static_assert(offsetof(RuntimeThreadLocInfoView, pclmap) == 0xCC, "RuntimeThreadLocInfoView::pclmap offset must be 0xCC");
  static_assert(offsetof(RuntimeThreadLocInfoView, pcumap) == 0xD0, "RuntimeThreadLocInfoView::pcumap offset must be 0xD0");
  static_assert(offsetof(RuntimeThreadLocInfoView, lcTimeCurrent) == 0xD4, "RuntimeThreadLocInfoView::lcTimeCurrent offset must be 0xD4");

  struct RuntimeLcTimeStringTableView
  {
    const char* wdayAbbr[7];
    const char* wday[7];
    const char* monthAbbr[12];
    const char* month[12];
  };

  [[nodiscard]] RuntimeThreadLocInfoView* RuntimeResolveLocaleLocInfo(
    _locale_t const localeInfo,
    RuntimeTidDataLocaleView** const outThreadData,
    bool* const outUpdated
  )
  {
    if (outThreadData != nullptr) {
      *outThreadData = nullptr;
    }
    if (outUpdated != nullptr) {
      *outUpdated = false;
    }

    if (localeInfo != nullptr) {
      const auto* const localeHandle = reinterpret_cast<const RuntimeLocaleHandle*>(localeInfo);
      return reinterpret_cast<RuntimeThreadLocInfoView*>(localeHandle->locinfo);
    }

    RuntimeTidDataLocaleView* const threadData = __getptd();
    RuntimeLocaleCodePageView* localeView = threadData->ptlocinfo;
    bool updated = false;
    if (localeView != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
      localeView = __updatetlocinfo();
      updated = true;
    }

    if (outThreadData != nullptr) {
      *outThreadData = threadData;
    }
    if (outUpdated != nullptr) {
      *outUpdated = updated;
    }

    return reinterpret_cast<RuntimeThreadLocInfoView*>(localeView);
  }

  void RuntimeReleaseLocaleUpdate(RuntimeTidDataLocaleView* const threadData, const bool updated)
  {
    if (updated && threadData != nullptr) {
      threadData->ownlocale &= ~2;
    }
  }

  [[nodiscard]] char* RuntimeBuildColonDelimitedLocaleString(
    const char* const* const firstColumns,
    const char* const* const secondColumns,
    const std::size_t pairCount
  )
  {
    std::size_t payloadLength = 0;
    for (std::size_t index = 0; index < pairCount; ++index) {
      const char* const first = (firstColumns[index] != nullptr) ? firstColumns[index] : "";
      const char* const second = (secondColumns[index] != nullptr) ? secondColumns[index] : "";
      payloadLength += std::strlen(first) + std::strlen(second) + 2u;
    }

    char* const buffer = static_cast<char*>(std::malloc(payloadLength + 1u));
    if (buffer == nullptr) {
      return nullptr;
    }

    char* cursor = buffer;
    for (std::size_t index = 0; index < pairCount; ++index) {
      const char* const first = (firstColumns[index] != nullptr) ? firstColumns[index] : "";
      const char* const second = (secondColumns[index] != nullptr) ? secondColumns[index] : "";

      *cursor++ = ':';
      if (strcpy_s(cursor, payloadLength + 1u - static_cast<std::size_t>(cursor - buffer), first) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      cursor += std::strlen(cursor);

      *cursor++ = ':';
      if (strcpy_s(cursor, payloadLength + 1u - static_cast<std::size_t>(cursor - buffer), second) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      cursor += std::strlen(cursor);
    }

    *cursor = '\0';
    return buffer;
  }

  [[nodiscard]] RuntimeIoInfo* ResolveIoInfoFromStream(std::FILE* const stream) noexcept
  {
    const int fileDescriptor = ::_fileno(stream);
    if (fileDescriptor == -1 || fileDescriptor == -2) {
      return &__badioinfo;
    }

    RuntimeIoInfo* const block = __pioinfo[fileDescriptor >> 5];
    return reinterpret_cast<RuntimeIoInfo*>(
      reinterpret_cast<std::uint8_t*>(block) + ((fileDescriptor & 0x1F) * sizeof(RuntimeIoInfo))
    );
  }

  [[nodiscard]] std::uint8_t RuntimeGetOsFileFlags(const int fileDescriptor) noexcept
  {
    if (fileDescriptor < 0 || fileDescriptor >= _nhandle) {
      return 0u;
    }

    RuntimeIoInfo* const ioBlock = __pioinfo[fileDescriptor >> 5];
    if (ioBlock == nullptr) {
      return 0u;
    }

    const std::size_t blockOffset = static_cast<std::size_t>(fileDescriptor & 0x1F) * sizeof(RuntimeIoInfo);
    const auto* const ioBytes = reinterpret_cast<const std::uint8_t*>(ioBlock) + blockOffset;
    return ioBytes[4];
  }

  [[nodiscard]] constexpr unsigned char RuntimeAsciiToLower(const unsigned char value) noexcept
  {
    if (value >= 'A' && value <= 'Z') {
      return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
  }

  class RuntimeEnvironmentLockGuard
  {
  public:
    RuntimeEnvironmentLockGuard()
    {
      _lock(kRuntimeEnvironmentLock);
    }

    RuntimeEnvironmentLockGuard(const RuntimeEnvironmentLockGuard&) = delete;
    RuntimeEnvironmentLockGuard& operator=(const RuntimeEnvironmentLockGuard&) = delete;

    ~RuntimeEnvironmentLockGuard()
    {
      _unlock(kRuntimeEnvironmentLock);
    }
  };

  [[nodiscard]] std::uint64_t BuildUnsigned64(const std::uint32_t lowPart, const std::uint32_t highPart) noexcept
  {
    return (static_cast<std::uint64_t>(highPart) << 32u) | static_cast<std::uint64_t>(lowPart);
  }

  class RuntimeFileLock2Guard
  {
  public:
    RuntimeFileLock2Guard(const int streamIndex, std::FILE* const stream) : mStreamIndex(streamIndex), mStream(stream)
    {
      __lock_file2(mStreamIndex, mStream);
    }

    RuntimeFileLock2Guard(const RuntimeFileLock2Guard&) = delete;
    RuntimeFileLock2Guard& operator=(const RuntimeFileLock2Guard&) = delete;

    ~RuntimeFileLock2Guard()
    {
      __unlock_file2(mStreamIndex, mStream);
    }

  private:
    int mStreamIndex = 0;
    std::FILE* mStream = nullptr;
  };

  class RuntimeLockGuard
  {
  public:
    explicit RuntimeLockGuard(const int lockNumber) : mLockNumber(lockNumber)
    {
      _lock(mLockNumber);
    }

    RuntimeLockGuard(const RuntimeLockGuard&) = delete;
    RuntimeLockGuard& operator=(const RuntimeLockGuard&) = delete;

    ~RuntimeLockGuard()
    {
      _unlock(mLockNumber);
    }

  private:
    int mLockNumber = 0;
  };
} // namespace

/**
 * Address: 0x00AA2695 (FUN_00AA2695, func_test_PF_FLOATING_POINT_PRECISION_ERRATA_kludge)
 *
 * What it does:
 * Executes the legacy floating-point precision probe formula used when
 * `IsProcessorFeaturePresent` is unavailable.
 */
extern "C" int __cdecl RuntimeTestFloatingPointPrecisionErrataKludge()
{
  constexpr double kProbeValue = 4195835.0;
  constexpr double kProbeDivisor = 3145727.0;
  constexpr double kProbeThreshold = 1.0;
  const double probeResult = kProbeValue - (kProbeValue / kProbeDivisor) * kProbeDivisor;
  return (probeResult > kProbeThreshold) ? 1 : 0;
}

/**
 * Address: 0x00AA26D1 (FUN_00AA26D1, func_test_PF_FLOATING_POINT_PRECISION_ERRATA)
 *
 * What it does:
 * Dynamically resolves `IsProcessorFeaturePresent` from KERNEL32 and queries
 * `PF_FLOATING_POINT_PRECISION_ERRATA`; when unavailable, falls back to the
 * legacy floating-point precision probe helper.
 */
extern "C" int __cdecl RuntimeTestFloatingPointPrecisionErrata()
{
  const HMODULE kernel32Module = ::GetModuleHandleA("KERNEL32");
  if (kernel32Module != nullptr) {
    using IsProcessorFeaturePresentFn = BOOL(WINAPI*)(DWORD);
    const auto isProcessorFeaturePresent = reinterpret_cast<IsProcessorFeaturePresentFn>(
      ::GetProcAddress(kernel32Module, "IsProcessorFeaturePresent")
    );
    if (isProcessorFeaturePresent != nullptr) {
      return (isProcessorFeaturePresent(PF_FLOATING_POINT_PRECISION_ERRATA) != FALSE) ? 1 : 0;
    }
  }

  return RuntimeTestFloatingPointPrecisionErrataKludge();
}

/**
 * Address: 0x00A8C257 (FUN_00A8C257, ___freetlocinfo)
 *
 * What it does:
 * Releases one CRT thread-locale payload by checking lane-level refcounts and
 * freeing owned locale/category buffers that are no longer shared.
 */
extern "C" void __cdecl __freetlocinfo(RuntimeThreadLocInfo* const locinfo)
{
  auto* const localeInfo = reinterpret_cast<RuntimeThreadLocInfoView*>(locinfo);
  if (localeInfo == nullptr) {
    return;
  }

  lconv* const localeConv = localeInfo->localeConv;
  if (localeConv != nullptr && localeConv != &__lconv_c) {
    int* const intlRefcount = localeInfo->lconvIntlRefcount;
    if (intlRefcount != nullptr && *intlRefcount == 0) {
      int* const monetaryRefcount = localeInfo->lconvMonRefcount;
      if (monetaryRefcount != nullptr && *monetaryRefcount == 0) {
        _free_crt(monetaryRefcount);
        __free_lconv_mon(localeConv);
      }

      int* const numericRefcount = localeInfo->lconvNumRefcount;
      if (numericRefcount != nullptr && *numericRefcount == 0) {
        _free_crt(numericRefcount);
        __free_lconv_num(localeConv);
      }

      _free_crt(intlRefcount);
      _free_crt(localeConv);
    }
  }

  int* const ctypeRefcount = localeInfo->ctype1Refcount;
  if (ctypeRefcount != nullptr && *ctypeRefcount == 0) {
    void* const ctypeBase = localeInfo->ctype1 ? (localeInfo->ctype1 - 127) : nullptr;
    void* const lowerCaseMapBase = localeInfo->pclmap ? (localeInfo->pclmap - 128) : nullptr;
    void* const upperCaseMapBase = localeInfo->pcumap ? (localeInfo->pcumap - 128) : nullptr;
    _free_crt(ctypeBase);
    _free_crt(lowerCaseMapBase);
    _free_crt(upperCaseMapBase);
    _free_crt(ctypeRefcount);
  }

  RuntimeLcTimeData* const lcTime = localeInfo->lcTimeCurrent;
  if (lcTime != nullptr && lcTime != &__lc_time_c && lcTime->refcount == 0) {
    __free_lc_time(lcTime);
    _free_crt(lcTime);
  }

  for (int categoryIndex = 0; categoryIndex < 6; ++categoryIndex) {
    RuntimeLocaleCategoryView& category = localeInfo->categories[categoryIndex];
    if (category.localeName != __clocalestr && category.localeRefcount != nullptr && *category.localeRefcount == 0) {
      _free_crt(category.localeRefcount);
    }

    if (category.localeWideName != nullptr && category.wideRefcount != nullptr && *category.wideRefcount == 0) {
      _free_crt(category.wideRefcount);
    }
  }

  _free_crt(localeInfo);
}

/**
 * Address: 0x00AA5AC6 (FUN_00AA5AC6, _init_time)
 *
 * What it does:
 * Rebuilds one thread-locale time payload when category 5 is active, then
 * atomically swaps `lc_time_curr` with refcount-aware release of the previous
 * non-default lane.
 */
extern "C" int __cdecl _init_time(RuntimeThreadLocInfo* const locinfo)
{
  auto* const localeInfo = reinterpret_cast<RuntimeThreadLocInfoView*>(locinfo);

  RuntimeLcTimeData* lcTime = nullptr;
  if (localeInfo->lcHandle[5] != 0) {
    lcTime = static_cast<RuntimeLcTimeData*>(_calloc_crt(1u, 0xB8u));
    if (lcTime == nullptr) {
      return 1;
    }

    if (_get_lc_time(locinfo, lcTime) != 0) {
      __free_lc_time(lcTime);
      _free_crt(lcTime);
      return 1;
    }

    lcTime->refcount = 1;
  } else {
    lcTime = &__lc_time_c;
  }

  RuntimeLcTimeData* const current = localeInfo->lcTimeCurrent;
  if (current != &__lc_time_c) {
    (void)InterlockedDecrement(reinterpret_cast<volatile long*>(&current->refcount));
  }

  localeInfo->lcTimeCurrent = lcTime;
  return 0;
}

/**
 * Address: 0x00AA5E30 (FUN_00AA5E30, __init_monetary)
 *
 * What it does:
 * Rebuilds monetary `lconv` lanes for one thread locale from CRT locale-info
 * providers, normalizes grouping bytes, and swaps in updated refcount owners.
 */
extern "C" int __cdecl __init_monetary(RuntimeThreadLocInfo* const locinfo)
{
  constexpr int kLocaleMonetaryCategory = 3;
  constexpr int kLocaleNumericCategory = 4;
  constexpr int kLocaleStringField = 0;
  constexpr int kLocaleIntegerField = 1;

  auto* const localeInfo = reinterpret_cast<RuntimeThreadLocInfoView*>(locinfo);
  RuntimeLocaleHandle localeHandle{};
  localeHandle.locinfo = locinfo;
  localeHandle.mbcinfo = nullptr;

  long* newMonetaryRefcount = nullptr;
  long* newIntlRefcount = nullptr;
  lconv* newLocaleConv = nullptr;

  if (localeInfo->lcHandle[kLocaleMonetaryCategory] == 0 && localeInfo->lcHandle[kLocaleNumericCategory] == 0) {
    newLocaleConv = &__lconv_c;
  } else {
    newLocaleConv = static_cast<lconv*>(_calloc_crt(1u, 0x30u));
    if (newLocaleConv == nullptr) {
      return 1;
    }

    newIntlRefcount = static_cast<long*>(std::malloc(sizeof(long)));
    if (newIntlRefcount == nullptr) {
      _free_crt(newLocaleConv);
      return 1;
    }
    *newIntlRefcount = 0;

    if (localeInfo->lcHandle[kLocaleMonetaryCategory] == 0) {
      std::memcpy(newLocaleConv, &__lconv_c, sizeof(lconv));
      newLocaleConv->decimal_point = localeInfo->localeConv->decimal_point;
      newLocaleConv->thousands_sep = localeInfo->localeConv->thousands_sep;
      newLocaleConv->grouping = localeInfo->localeConv->grouping;
      *newIntlRefcount = 1;
    } else {
      newMonetaryRefcount = static_cast<long*>(std::malloc(sizeof(long)));
      if (newMonetaryRefcount == nullptr) {
        _free_crt(newLocaleConv);
        _free_crt(newIntlRefcount);
        return 1;
      }
      *newMonetaryRefcount = 0;

      const LCID localeCountry = static_cast<LCID>(static_cast<std::uint16_t>(localeInfo->lcId[kLocaleMonetaryCategory] & 0xFFFFu));
      int status = 0;
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SINTLSYMBOL, &newLocaleConv->int_curr_symbol);
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SCURRENCY, &newLocaleConv->currency_symbol);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SMONDECIMALSEP, &newLocaleConv->mon_decimal_point);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SMONTHOUSANDSEP, &newLocaleConv->mon_thousands_sep);
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SMONGROUPING, &newLocaleConv->mon_grouping);
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SPOSITIVESIGN, &newLocaleConv->positive_sign);
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SNEGATIVESIGN, &newLocaleConv->negative_sign);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_IINTLCURRDIGITS, &newLocaleConv->int_frac_digits);
      status |= __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_ICURRDIGITS, &newLocaleConv->frac_digits);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_IPOSSYMPRECEDES, &newLocaleConv->p_cs_precedes);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_IPOSSEPBYSPACE, &newLocaleConv->p_sep_by_space);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_INEGSYMPRECEDES, &newLocaleConv->n_cs_precedes);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_INEGSEPBYSPACE, &newLocaleConv->n_sep_by_space);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_IPOSSIGNPOSN, &newLocaleConv->p_sign_posn);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_INEGSIGNPOSN, &newLocaleConv->n_sign_posn);

      if (status != 0) {
        __free_lconv_mon(newLocaleConv);
        _free_crt(newLocaleConv);
        _free_crt(newIntlRefcount);
        _free_crt(newMonetaryRefcount);
        return 1;
      }

      char* monetaryGrouping = newLocaleConv->mon_grouping;
      while (monetaryGrouping != nullptr && *monetaryGrouping != '\0') {
        const char groupingChar = *monetaryGrouping;
        if (groupingChar >= '0' && groupingChar <= '9') {
          *monetaryGrouping = static_cast<char>(groupingChar - '0');
          ++monetaryGrouping;
          continue;
        }

        if (groupingChar == ';') {
          char* shiftCursor = monetaryGrouping;
          do {
            *shiftCursor = *(shiftCursor + 1);
            ++shiftCursor;
          } while (*shiftCursor != '\0');
          continue;
        }

        ++monetaryGrouping;
      }

      *newIntlRefcount = 1;
      *newMonetaryRefcount = 1;
    }
  }

  if (localeInfo->lconvMonRefcount != nullptr) {
    (void)InterlockedDecrement(reinterpret_cast<volatile long*>(localeInfo->lconvMonRefcount));
  }

  if (localeInfo->lconvIntlRefcount != nullptr) {
    if (InterlockedDecrement(reinterpret_cast<volatile long*>(localeInfo->lconvIntlRefcount)) == 0) {
      _free_crt(localeInfo->localeConv);
      _free_crt(localeInfo->lconvIntlRefcount);
    }
  }

  localeInfo->lconvMonRefcount = reinterpret_cast<int*>(newMonetaryRefcount);
  localeInfo->lconvIntlRefcount = reinterpret_cast<int*>(newIntlRefcount);
  localeInfo->localeConv = newLocaleConv;
  return 0;
}

namespace moho::runtime
{
  /**
   * Address: 0x00B57C4C (FUN_00B57C4C)
   *
   * What it does:
   * Emits base-N digits in reverse order, then in-place reverses the emitted
   * span (optional leading minus).
   */
  void LegacyToCharsReverseUnsigned32(unsigned int value, char* destination, unsigned int base, bool prependMinus)
  {
    if (prependMinus) {
      *destination = '-';
      ++destination;
      value = static_cast<unsigned int>(-static_cast<int>(value));
    }

    char* writeCursor = destination;
    do {
      const unsigned int digit = value % base;
      value /= base;

      char digitChar = '\0';
      if (digit <= 9) {
        digitChar = static_cast<char>(digit + static_cast<unsigned int>('0'));
      } else {
        digitChar = static_cast<char>(digit + static_cast<unsigned int>('W'));
      }

      *destination = digitChar;
      ++destination;
    } while (value != 0);

    *destination = '\0';

    char* reverseCursor = destination - 1;
    do {
      const char tail = *reverseCursor;
      *reverseCursor = *writeCursor;
      --reverseCursor;
      *writeCursor = tail;
      ++writeCursor;
    } while (writeCursor < reverseCursor);
  }

  /**
   * Address: 0x00B57C8C (FUN_00B57C8C)
   *
   * What it does:
   * Signed-int `to_chars` helper that only applies sign handling for base 10.
   */
  void LegacyToCharsSigned32Dispatch(int value, char* destination, unsigned int base)
  {
    if (base == 10 && value < 0) {
      LegacyToCharsReverseUnsigned32(static_cast<unsigned int>(value), destination, 10u, true);
      return;
    }

    LegacyToCharsReverseUnsigned32(static_cast<unsigned int>(value), destination, base, false);
  }

  /**
   * Address: 0x00B57CB4 (FUN_00B57CB4)
   *
   * What it does:
   * Returns destination pointer after formatting one signed integer.
   */
  char* LegacyToCharsSigned32(int value, char* destination, unsigned int base)
  {
    bool isNegative = false;
    if (base == 10) {
      isNegative = value < 0;
    }

    LegacyToCharsReverseUnsigned32(static_cast<unsigned int>(value), destination, base, isNegative);
    return destination;
  }

  /**
   * Address: 0x00B57CD9 (FUN_00B57CD9)
   *
   * What it does:
   * Returns destination pointer after formatting one unsigned integer.
   */
  char* LegacyToCharsUnsigned32(unsigned int value, char* destination, unsigned int base)
  {
    LegacyToCharsReverseUnsigned32(value, destination, base, false);
    return destination;
  }

  /**
   * Address: 0x00B57CF1 (FUN_00B57CF1)
   *
   * What it does:
   * Formats one 64-bit lane into base-N text using lowercase hex-alpha digits,
   * optional minus prefix, and in-place reversal.
   */
  char LegacyToCharsUnsigned64Worker(
    char* destination,
    std::uint64_t value,
    unsigned int base,
    bool prependMinus
  )
  {
    if (prependMinus) {
      *destination = '-';
      ++destination;
      value = static_cast<std::uint64_t>(-static_cast<std::int64_t>(value));
    }

    char* writeCursor = destination;
    do {
      const std::uint64_t quotient = value / static_cast<std::uint64_t>(base);
      const unsigned int remainder = static_cast<unsigned int>(value % static_cast<std::uint64_t>(base));

      char digitChar = '\0';
      if (remainder <= 9u) {
        digitChar = static_cast<char>(remainder + static_cast<unsigned int>('0'));
      } else {
        digitChar = static_cast<char>(remainder + 87u);
      }

      *destination = digitChar;
      ++destination;
      value = quotient;
    } while (value != 0u);

    *destination = '\0';

    char* reverseCursor = destination - 1;
    char result = '\0';
    do {
      result = *reverseCursor;
      *reverseCursor = *writeCursor;
      --reverseCursor;
      *writeCursor = result;
      ++writeCursor;
    } while (writeCursor < reverseCursor);

    return result;
  }

  /**
   * Address: 0x00B57D5E (FUN_00B57D5E)
   *
   * What it does:
   * Signed 64-bit formatting entry that returns the passthrough destination
   * pointer lane expected by the caller.
   */
  char* LegacyToCharsSigned64Parts(
    std::uint32_t lowPart,
    std::int32_t highPart,
    char* destination,
    unsigned int base
  )
  {
    bool isNegative = false;
    if (base == 10u && highPart <= 0) {
      isNegative = (highPart < 0) || (highPart == 0 && static_cast<std::int32_t>(lowPart) < 0);
    }

    const std::uint64_t rawValue =
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(highPart)) << 32u) | static_cast<std::uint64_t>(lowPart);
    LegacyToCharsUnsigned64Worker(destination, rawValue, base, isNegative);
    return destination;
  }

  /**
   * Address: 0x00B57D8F (FUN_00B57D8F)
   *
   * What it does:
   * Unsigned 64-bit formatting entry that returns the passthrough destination
   * pointer lane expected by the caller.
   */
  char* LegacyToCharsUnsigned64Parts(
    std::uint32_t lowPart,
    std::uint32_t highPart,
    char* destination,
    unsigned int base
  )
  {
    const std::uint64_t rawValue = (static_cast<std::uint64_t>(highPart) << 32u) | static_cast<std::uint64_t>(lowPart);
    LegacyToCharsUnsigned64Worker(destination, rawValue, base, false);
    return destination;
  }

  /**
   * Address: 0x00A96B96 (FUN_00A96B96, _unlock)
   *
   * What it does:
   * Releases one CRT lock-table lane.
   */
  void RuntimeUnlock(const int lockNumber)
  {
    ::_unlock(lockNumber);
  }

  /**
   * Address: 0x00A89F95 (FUN_00A89F95, __unlock_file)
   *
   * What it does:
   * Releases one CRT FILE lock lane for callers that use the CRT internal
   * `__unlock_file` helper contract.
   */
  void RuntimeUnlockFile(std::FILE* stream)
  {
    ::_unlock_file(stream);
  }

  /**
   * Address: 0x00B57DAA (FUN_00B57DAA)
   *
   * What it does:
   * `_eof` runtime helper lane for one CRT file descriptor.
   */
  int RuntimeFileDescriptorEof(int fileDescriptor)
  {
    return ::_eof(fileDescriptor);
  }

  /**
   * Address: 0x00A9BC49 (FUN_00A9BC49, _close)
   *
   * What it does:
   * Handles the special pseudo-handle lane (`-2`) and otherwise forwards to
   * CRT `_close` semantics.
   */
  int RuntimeClose(const int fileHandle)
  {
    if (fileHandle == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1;
    }

    return ::_close(fileHandle);
  }

  /**
   * Address: 0x00AA1807 (FUN_00AA1807, __read)
   *
   * What it does:
   * Handles the special pseudo-handle lane (`-2`), validates max byte count,
   * and forwards to CRT `_read` for normal descriptor processing.
   */
  int RuntimeRead(const int fileHandle, void* const destinationBuffer, const unsigned int maxCharCount)
  {
    if (fileHandle == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1;
    }

    if (maxCharCount > 0x7FFFFFFFu) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    return ::_read(fileHandle, destinationBuffer, maxCharCount);
  }

  /**
   * Address: 0x00AB631D (FUN_00AB631D, _lseeki64)
   *
   * What it does:
   * Handles the special pseudo-handle lane (`-2`) and otherwise forwards to
   * CRT `_lseeki64` semantics.
   */
  __int64 RuntimeLseekI64(const int fileHandle, const __int64 position, const int moveMethod)
  {
    if (fileHandle == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1;
    }

    return ::_lseeki64(fileHandle, position, moveMethod);
  }

  /**
   * Address: 0x00A8548B (FUN_00A8548B, _fsopen)
   *
   * What it does:
   * Validates narrow file path/mode arguments, then forwards to CRT `_fsopen`
   * for stream allocation/open semantics.
   */
  std::FILE* RuntimeFsopen(const char* const filePath, const char* const mode, const int shareFlag)
  {
    if (filePath == nullptr || mode == nullptr || mode[0] == '\0') {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    return ::_fsopen(filePath, mode, shareFlag);
  }

  /**
   * Address: 0x00A88E8F (FUN_00A88E8F, _wfsopen)
   *
   * What it does:
   * Validates wide file path/mode arguments, then forwards to CRT `_wfsopen`
   * for stream allocation/open semantics.
   */
  std::FILE* RuntimeWfsopen(const wchar_t* const filePath, const wchar_t* const mode, const int shareFlag)
  {
    if (filePath == nullptr || mode == nullptr || mode[0] == L'\0') {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    return ::_wfsopen(filePath, mode, shareFlag);
  }

  [[nodiscard]] int RuntimeGetOsPlatform(int* const outPlatform)
  {
    if (outPlatform == nullptr) {
      return EINVAL;
    }

    #pragma warning(push)
    #pragma warning(disable:4996)
    const DWORD version = ::GetVersion();
    #pragma warning(pop)
    *outPlatform = ((version & 0x80000000u) != 0u) ? 1 : 2;
    return 0;
  }

  /**
   * Address: 0x00A958E3 (FUN_00A958E3, use_encode_pointer)
   *
   * What it does:
   * Returns true on NT-class Windows, or on older systems that do not expose
   * a `.mixcrt` section in the current module image.
   */
  [[nodiscard]] bool RuntimeShouldUseEncodedPointers()
  {
    unsigned int platformMajorVersion = 0;
    _get_winmajor(&platformMajorVersion);
    if (platformMajorVersion > 5u) {
      return true;
    }

    const auto* const moduleBase = reinterpret_cast<const std::uint8_t*>(::GetModuleHandleA(nullptr));
    const auto* const dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    const auto* const ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + dosHeader->e_lfanew);
    const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (unsigned short index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index, ++sectionHeader) {
      if (std::strcmp(reinterpret_cast<const char*>(sectionHeader->Name), ".mixcrt") == 0) {
        return false;
      }
    }

    return true;
  }

  [[nodiscard]] void* RuntimeEncodedNullPointer()
  {
    return ::EncodePointer(nullptr);
  }

  [[nodiscard]] RuntimeSignalHandler RuntimeDecodeSignalAction(void*& encodedActionSlot)
  {
    if (encodedActionSlot == nullptr) {
      encodedActionSlot = RuntimeEncodedNullPointer();
    }
    return reinterpret_cast<RuntimeSignalHandler>(_decode_pointer(encodedActionSlot));
  }

  /**
   * Address: 0x00ABFAA0 (FUN_00ABFAA0, std::_Xfsopen)
   *
   * What it does:
   * Opens one wide path with fallback conversion on Win9x platform lanes:
   * uses `_wfsopen` on NT-class systems and `wcstombs_s` + `_fsopen` on Win9x.
   */
  std::FILE* RuntimeXfsopen(const wchar_t* const filePath, const wchar_t* const mode, const int shareFlag)
  {
    int osPlatform = 0;
    if (RuntimeGetOsPlatform(&osPlatform) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    if (osPlatform != 1) {
      return RuntimeWfsopen(filePath, mode, shareFlag);
    }

    char narrowFilePath[0x104]{};
    char narrowMode[0x14]{};
    if (::wcstombs_s(nullptr, narrowFilePath, 0x104u, filePath, 0x103u) != 0
        || ::wcstombs_s(nullptr, narrowMode, 0x14u, mode, 0x13u) != 0) {
      return nullptr;
    }

    return RuntimeFsopen(narrowFilePath, narrowMode, shareFlag);
  }

  /**
   * Address: 0x00ABFB55 (FUN_00ABFB55, std::_Fiopen(wchar_t const*,int,int))
   *
   * What it does:
   * Normalizes iostream openmode flags, resolves one CRT fopen mode string,
   * performs noreplace probe when requested, and opens the stream.
   */
  std::FILE* RuntimeFiopenWide(const wchar_t* const filePath, const int openMode, const int shareFlag)
  {
    static constexpr int kFiopenValidModes[] = {
      0x01, 0x02, 0x12, 0x0A, 0x21, 0x22, 0x32, 0x2A, 0x03, 0x13, 0x0B, 0x23, 0x33, 0x2B, 0x00
    };
    static constexpr const wchar_t* kFiopenModeStrings[] = {
      L"r",   L"w",   L"w",   L"a",   L"rb",  L"wb",  L"wb",
      L"ab",  L"r+",  L"w+",  L"a+",  L"r+b", L"w+b", L"a+b"
    };

    int normalizedMode = openMode;
    if ((openMode & 0x40) != 0) {
      normalizedMode |= 0x01;
    }
    if ((normalizedMode & 0x08) != 0) {
      normalizedMode |= 0x02;
    }

    const unsigned int fiopenMode = static_cast<unsigned int>(normalizedMode) & 0xFFFFFF3Bu;

    int modeIndex = 0;
    while (kFiopenValidModes[modeIndex] != 0 && static_cast<unsigned int>(kFiopenValidModes[modeIndex]) != fiopenMode) {
      ++modeIndex;
    }
    if (kFiopenValidModes[modeIndex] == 0) {
      return nullptr;
    }

    if ((openMode & 0x80) != 0 && (fiopenMode & 0x01u) != 0u) {
      if (std::FILE* const existing = RuntimeXfsopen(filePath, L"r", shareFlag); existing != nullptr) {
        std::fclose(existing);
        return nullptr;
      }
    }

    std::FILE* const file = RuntimeXfsopen(filePath, kFiopenModeStrings[modeIndex], shareFlag);
    if (file == nullptr) {
      return nullptr;
    }

    if ((openMode & 0x04) != 0 && std::fseek(file, 0, SEEK_END) != 0) {
      std::fclose(file);
      return nullptr;
    }

    return file;
  }

  /**
   * Address: 0x00ABFC0A (FUN_00ABFC0A, j_std::_Fiopen(wchar_t const*,int,int))
   *
   * What it does:
   * Thunk lane that forwards directly to wide `_Fiopen`.
   */
  std::FILE* RuntimeFiopenWideThunk(const wchar_t* const filePath, const int openMode, const int shareFlag)
  {
    return RuntimeFiopenWide(filePath, openMode, shareFlag);
  }

  /**
   * Address: 0x00ABFC0F (FUN_00ABFC0F, std::_Fiopen(char const*,int,int))
   *
   * What it does:
   * Converts a narrow path to wide form and forwards to wide `_Fiopen`.
   */
  std::FILE* RuntimeFiopenNarrow(const char* const filePath, const int openMode, const int shareFlag)
  {
    wchar_t wideFilePath[0x104]{};
    if (::mbstowcs_s(nullptr, wideFilePath, 0x104u, filePath, 0x103u) != 0) {
      return nullptr;
    }

    return RuntimeFiopenWide(wideFilePath, openMode, shareFlag);
  }

  struct RuntimeLegacyFileIoBufView
  {
    char* ptr = nullptr;      // +0x00
    std::int32_t cnt = 0;     // +0x04
    char* base = nullptr;     // +0x08
  };
  static_assert(offsetof(RuntimeLegacyFileIoBufView, ptr) == 0x00, "RuntimeLegacyFileIoBufView::ptr offset must be 0x00");
  static_assert(offsetof(RuntimeLegacyFileIoBufView, cnt) == 0x04, "RuntimeLegacyFileIoBufView::cnt offset must be 0x04");
  static_assert(offsetof(RuntimeLegacyFileIoBufView, base) == 0x08, "RuntimeLegacyFileIoBufView::base offset must be 0x08");
  static_assert(sizeof(RuntimeLegacyFileIoBufView) == 0x0C, "RuntimeLegacyFileIoBufView size must be 0x0C");

  struct RuntimeFilebufCharDispatch
  {
    std::uintptr_t unknown00 = 0;                            // +0x00
    std::int32_t(__thiscall* overflow)(void* self, int ch) = nullptr; // +0x04
  };
  static_assert(offsetof(RuntimeFilebufCharDispatch, overflow) == 0x04, "RuntimeFilebufCharDispatch::overflow offset must be 0x04");

  using RuntimeCodecvtCharFacet = std::codecvt<char, char, std::mbstate_t>;

  struct RuntimeFilebufCharView
  {
    RuntimeFilebufCharDispatch* dispatch = nullptr; // +0x00
    std::uint8_t reserved04_0F[0x0C]{};             // +0x04
    char** inputBase = nullptr;                     // +0x10
    char** outputBase = nullptr;                    // +0x14
    std::uint8_t reserved18_1F[0x08]{};             // +0x18
    char** inputPtr = nullptr;                      // +0x20
    char** outputPtr = nullptr;                     // +0x24
    std::uint8_t reserved28_2F[0x08]{};             // +0x28
    std::int32_t* inputCount = nullptr;             // +0x30
    std::int32_t* outputCount = nullptr;            // +0x34
    std::uint8_t reserved38_3B[0x04]{};             // +0x38
    const RuntimeCodecvtCharFacet* codecvtFacet = nullptr; // +0x3C
    std::uint8_t reserved40 = 0;                    // +0x40
    std::uint8_t wroteSome = 0;                     // +0x41
    std::uint8_t reserved42_43[0x02]{};             // +0x42
    std::int32_t stateWord = 0;                     // +0x44
    std::uint8_t closeOnClose = 0;                  // +0x48
    std::uint8_t reserved49_4B[0x03]{};             // +0x49
    std::FILE* myFile = nullptr;                    // +0x4C
  };
  static_assert(offsetof(RuntimeFilebufCharView, inputBase) == 0x10, "RuntimeFilebufCharView::inputBase offset must be 0x10");
  static_assert(offsetof(RuntimeFilebufCharView, outputBase) == 0x14, "RuntimeFilebufCharView::outputBase offset must be 0x14");
  static_assert(offsetof(RuntimeFilebufCharView, inputPtr) == 0x20, "RuntimeFilebufCharView::inputPtr offset must be 0x20");
  static_assert(offsetof(RuntimeFilebufCharView, outputPtr) == 0x24, "RuntimeFilebufCharView::outputPtr offset must be 0x24");
  static_assert(offsetof(RuntimeFilebufCharView, inputCount) == 0x30, "RuntimeFilebufCharView::inputCount offset must be 0x30");
  static_assert(offsetof(RuntimeFilebufCharView, outputCount) == 0x34, "RuntimeFilebufCharView::outputCount offset must be 0x34");
  static_assert(offsetof(RuntimeFilebufCharView, codecvtFacet) == 0x3C, "RuntimeFilebufCharView::codecvtFacet offset must be 0x3C");
  static_assert(offsetof(RuntimeFilebufCharView, wroteSome) == 0x41, "RuntimeFilebufCharView::wroteSome offset must be 0x41");
  static_assert(offsetof(RuntimeFilebufCharView, stateWord) == 0x44, "RuntimeFilebufCharView::stateWord offset must be 0x44");
  static_assert(offsetof(RuntimeFilebufCharView, closeOnClose) == 0x48, "RuntimeFilebufCharView::closeOnClose offset must be 0x48");
  static_assert(offsetof(RuntimeFilebufCharView, myFile) == 0x4C, "RuntimeFilebufCharView::myFile offset must be 0x4C");
  static_assert(sizeof(RuntimeFilebufCharView) == 0x50, "RuntimeFilebufCharView size must be 0x50");

  std::int32_t gRuntimeFilebufInitialStateWord = 0;

  void RuntimeFilebufResetIoLanes(RuntimeFilebufCharView* const filebuf)
  {
    filebuf->inputBase = nullptr;
    filebuf->outputBase = nullptr;
    filebuf->inputPtr = nullptr;
    filebuf->outputPtr = nullptr;
    filebuf->inputCount = nullptr;
    filebuf->outputCount = nullptr;
  }

  void RuntimeFilebufBindFileIoLanes(RuntimeFilebufCharView* const filebuf, std::FILE* const file)
  {
    auto* const ioView = reinterpret_cast<RuntimeLegacyFileIoBufView*>(file);
    filebuf->inputBase = &ioView->base;
    filebuf->outputBase = &ioView->base;
    filebuf->inputPtr = &ioView->ptr;
    filebuf->outputPtr = &ioView->ptr;
    filebuf->inputCount = &ioView->cnt;
    filebuf->outputCount = &ioView->cnt;
  }

  std::intptr_t RuntimeFilebufApplyCodecvtFacet(
    RuntimeFilebufCharView* filebuf,
    const RuntimeCodecvtCharFacet* codecvtFacet
  );

  RuntimeLockitState* RuntimeLockitConstruct(RuntimeLockitState* object, int requestedSlot);
  void RuntimeLockitDestroy(RuntimeLockitState* object);
  RuntimeMutexHandle* RuntimeMutexConstruct(RuntimeMutexHandle* object);
  RuntimeLocaleLocimpView* RuntimeGetGlobalLocale();
  RuntimeLocaleLocimpView* RuntimeLocaleInit();

  /**
   * Address: 0x004C52F0 (FUN_004C52F0, nullsub_802)
   *
   * What it does:
   * Legacy no-op CRT hook.
   */
  [[maybe_unused]] void RuntimeNoOpCrtHookA()
  {
  }

  /**
   * Address: 0x004C53A0 (FUN_004C53A0, nullsub_803)
   *
   * What it does:
   * Legacy no-op CRT hook.
   */
  [[maybe_unused]] void RuntimeNoOpCrtHookB()
  {
  }

  /**
   * Address: 0x004C53E0 (FUN_004C53E0, sub_4C53E0)
   *
   * What it does:
   * Fills one dword range with a repeated source dword and returns one-past-end
   * destination pointer.
   */
  [[maybe_unused]] std::uint32_t* RuntimeFillDwordRangeFromSource(
    const std::uint32_t* const sourceWord,
    std::uint32_t* const destination,
    const std::int32_t count
  )
  {
    std::uint32_t* writeCursor = destination;
    for (std::int32_t remaining = count; remaining > 0; --remaining) {
      *writeCursor++ = *sourceWord;
    }
    return destination + count;
  }

  /**
   * Address: 0x004C5410 (FUN_004C5410, nullsub_804)
   *
   * What it does:
   * Legacy stdcall no-op hook.
   */
  [[maybe_unused]] void __stdcall RuntimeNoOpStdcallInt(const int /*unused*/)
  {
  }

  /**
   * Address: 0x004C5420 (FUN_004C5420, nullsub_805)
   *
   * What it does:
   * Legacy no-op CRT hook.
   */
  [[maybe_unused]] void RuntimeNoOpCrtHookC()
  {
  }

  /**
   * Address: 0x004C5430 (FUN_004C5430, std::basic_filebuf<char,std::char_traits<char>>::_Init)
   *
   * What it does:
   * Initializes filebuf file-pointer lanes from one optional `FILE*` and resets
   * conversion state/cache words.
   */
  [[maybe_unused]] RuntimeFilebufCharView* RuntimeFilebufInit(RuntimeFilebufCharView* const filebuf, std::FILE* const file)
  {
    filebuf->closeOnClose = 0;
    filebuf->wroteSome = 0;
    RuntimeFilebufResetIoLanes(filebuf);
    if (file != nullptr) {
      RuntimeFilebufBindFileIoLanes(filebuf, file);
    }
    filebuf->myFile = file;
    filebuf->stateWord = gRuntimeFilebufInitialStateWord;
    filebuf->codecvtFacet = nullptr;
    return filebuf;
  }

  bool RuntimeFilebufEndWrite(RuntimeFilebufCharView* const filebuf)
  {
    if (filebuf->codecvtFacet == nullptr || filebuf->wroteSome == 0) {
      return true;
    }

    if (filebuf->dispatch == nullptr || filebuf->dispatch->overflow == nullptr) {
      return false;
    }
    if (filebuf->dispatch->overflow(filebuf, -1) == -1) {
      return false;
    }

    std::string converted(8u, '\0');
    while (true) {
      std::mbstate_t shiftState{};
      std::memcpy(&shiftState, &filebuf->stateWord, (std::min)(sizeof(shiftState), sizeof(filebuf->stateWord)));

      char* const outBegin = converted.data();
      char* const outEnd = outBegin + converted.size();
      char* outNext = outBegin;
      const std::codecvt_base::result result = filebuf->codecvtFacet->unshift(shiftState, outBegin, outEnd, outNext);

      std::memcpy(&filebuf->stateWord, &shiftState, (std::min)(sizeof(shiftState), sizeof(filebuf->stateWord)));

      if (result == std::codecvt_base::ok) {
        filebuf->wroteSome = 0;
      } else if (result == std::codecvt_base::noconv) {
        return true;
      } else if (result != std::codecvt_base::partial) {
        return false;
      }

      const std::size_t producedBytes = static_cast<std::size_t>(outNext - outBegin);
      if (producedBytes != 0u && std::fwrite(outBegin, 1u, producedBytes, filebuf->myFile) != producedBytes) {
        return false;
      }

      if (filebuf->wroteSome == 0) {
        return true;
      }
      if (producedBytes == 0u) {
        converted.append(8u, '\0');
      }
    }
  }

  /**
   * Address: 0x004C54A0 (FUN_004C54A0, std::basic_filebuf<char,std::char_traits<char>>::open)
   *
   * What it does:
   * Opens one narrow path via `_Fiopen`, binds `FILE` lane pointers into the
   * filebuf runtime view, and refreshes codecvt lane when conversion is needed.
   */
  [[maybe_unused]] RuntimeFilebufCharView* RuntimeFilebufOpen(
    RuntimeFilebufCharView* const filebuf,
    const char* const filename,
    const std::int32_t openMode,
    const std::int32_t shareMode
  )
  {
    if (filebuf->myFile != nullptr) {
      return nullptr;
    }

    std::FILE* const file = RuntimeFiopenNarrow(filename, openMode, shareMode);
    if (file == nullptr) {
      return nullptr;
    }

    filebuf->closeOnClose = 1;
    filebuf->wroteSome = 0;
    RuntimeFilebufResetIoLanes(filebuf);
    RuntimeFilebufBindFileIoLanes(filebuf, file);
    filebuf->myFile = file;
    filebuf->stateWord = gRuntimeFilebufInitialStateWord;
    filebuf->codecvtFacet = nullptr;

    const std::locale locale = std::locale();
    auto& codecvtFacet = std::use_facet<RuntimeCodecvtCharFacet>(locale);
    (void)RuntimeFilebufApplyCodecvtFacet(filebuf, &codecvtFacet);

    return filebuf;
  }

  /**
   * Address: 0x004C55A0 (FUN_004C55A0, std::basic_filebuf<char,std::char_traits<char>>::close)
   *
   * What it does:
   * Flushes pending conversion output lane, closes bound `FILE*`, then resets
   * filebuf file-pointer/conversion state lanes.
   */
  [[maybe_unused]] RuntimeFilebufCharView* RuntimeFilebufClose(RuntimeFilebufCharView* const filebuf)
  {
    RuntimeFilebufCharView* result = filebuf;
    if (filebuf->myFile != nullptr) {
      if (!RuntimeFilebufEndWrite(filebuf)) {
        result = nullptr;
      }
      if (std::fclose(filebuf->myFile) != 0) {
        result = nullptr;
      }
    } else {
      result = nullptr;
    }

    filebuf->closeOnClose = 0;
    filebuf->wroteSome = 0;
    RuntimeFilebufResetIoLanes(filebuf);
    filebuf->myFile = nullptr;
    filebuf->stateWord = gRuntimeFilebufInitialStateWord;
    filebuf->codecvtFacet = nullptr;
    return result;
  }

  /**
   * Address: 0x004C57B0 (FUN_004C57B0, sub_4C57B0)
   *
   * What it does:
   * Applies one codecvt facet lane to filebuf state, clearing `_Pcvt` when the
   * facet reports `always_noconv()`.
   */
  [[maybe_unused]] std::intptr_t RuntimeFilebufApplyCodecvtFacet(
    RuntimeFilebufCharView* const filebuf,
    const RuntimeCodecvtCharFacet* const codecvtFacet
  )
  {
    if (codecvtFacet->always_noconv()) {
      filebuf->codecvtFacet = nullptr;
      return 1;
    }

    filebuf->codecvtFacet = codecvtFacet;
    RuntimeFilebufResetIoLanes(filebuf);
    return reinterpret_cast<std::intptr_t>(filebuf);
  }

  /**
   * Address: 0x004C5880 (FUN_004C5880, nullsub_806)
   *
   * What it does:
   * Legacy stdcall no-op hook.
   */
  [[maybe_unused]] void __stdcall RuntimeNoOpStdcallInt2(const int /*unused*/)
  {
  }

  /**
   * Address: 0x004C5890 (FUN_004C5890, sub_4C5890)
   *
   * What it does:
   * Returns one dword from indirect pointer lane.
   */
  [[maybe_unused]] std::int32_t RuntimeReadIndirectDwordA(const std::int32_t* const valuePointer)
  {
    return *valuePointer;
  }

  /**
   * Address: 0x004C58B0 (FUN_004C58B0, sub_4C58B0)
   *
   * What it does:
   * Writes one dword through indirect pointer lane and returns that pointer.
   */
  [[maybe_unused]] std::int32_t* RuntimeWriteIndirectDword(std::int32_t* const outValuePointer, const std::int32_t value)
  {
    *outValuePointer = value;
    return outValuePointer;
  }

  /**
   * Address: 0x004C58E0 (FUN_004C58E0, sub_4C58E0)
   *
   * What it does:
   * Returns one dword from indirect pointer lane.
   */
  [[maybe_unused]] std::int32_t RuntimeReadIndirectDwordB(const std::int32_t* const valuePointer)
  {
    return *valuePointer;
  }

  struct RuntimeStreamPositionStateView
  {
    std::int32_t statusWord = 0;       // +0x00
    std::int32_t reservedWord04 = 0;   // +0x04
    std::int32_t positionLow = 0;      // +0x08
    std::int32_t positionHigh = 0;     // +0x0C
    std::int32_t stateTag = 0;         // +0x10
  };
  static_assert(offsetof(RuntimeStreamPositionStateView, statusWord) == 0x00, "RuntimeStreamPositionStateView::statusWord offset must be 0x00");
  static_assert(offsetof(RuntimeStreamPositionStateView, positionLow) == 0x08, "RuntimeStreamPositionStateView::positionLow offset must be 0x08");
  static_assert(offsetof(RuntimeStreamPositionStateView, positionHigh) == 0x0C, "RuntimeStreamPositionStateView::positionHigh offset must be 0x0C");
  static_assert(offsetof(RuntimeStreamPositionStateView, stateTag) == 0x10, "RuntimeStreamPositionStateView::stateTag offset must be 0x10");
  static_assert(sizeof(RuntimeStreamPositionStateView) == 0x14, "RuntimeStreamPositionStateView size must be 0x14");

  /**
   * Address: 0x004C5900 (FUN_004C5900, sub_4C5900)
   *
   * What it does:
   * Initializes one stream-position state lane triplet (`stateTag`, 64-bit
   * position split high/low) and clears status lane.
   */
  [[maybe_unused]] RuntimeStreamPositionStateView* RuntimeStreamPositionInitialize(
    RuntimeStreamPositionStateView* const positionState,
    const std::int32_t stateTag,
    const std::int32_t positionLow,
    const std::int32_t positionHigh
  )
  {
    positionState->positionLow = positionLow;
    positionState->statusWord = 0;
    positionState->positionHigh = positionHigh;
    positionState->stateTag = stateTag;
    return positionState;
  }

  /**
   * Address: 0x004C5920 (FUN_004C5920, sub_4C5920)
   *
   * What it does:
   * Returns stream-position state-tag lane.
   */
  [[maybe_unused]] std::int32_t RuntimeStreamPositionGetStateTag(const RuntimeStreamPositionStateView* const positionState)
  {
    return positionState->stateTag;
  }

  /**
   * Address: 0x004C5930 (FUN_004C5930, sub_4C5930)
   *
   * What it does:
   * Returns 64-bit stream-position payload from low/high dword lanes.
   */
  [[maybe_unused]] std::int64_t RuntimeStreamPositionGetOffset(const RuntimeStreamPositionStateView* const positionState)
  {
    const std::uint32_t low = static_cast<std::uint32_t>(positionState->positionLow);
    const std::uint32_t high = static_cast<std::uint32_t>(positionState->positionHigh);
    const std::uint64_t combined = low | (static_cast<std::uint64_t>(high) << 32u);
    return static_cast<std::int64_t>(combined);
  }

  class RuntimeFacetBaseVtableProbe final : public std::locale::facet
  {
  public:
    RuntimeFacetBaseVtableProbe()
      : std::locale::facet(0)
    {
    }

    static void* CaptureBaseVtable()
    {
      alignas(RuntimeFacetBaseVtableProbe) std::uint8_t storage[sizeof(RuntimeFacetBaseVtableProbe)]{};
      auto* const probe = new (storage) RuntimeFacetBaseVtableProbe();
      probe->std::locale::facet::~facet();
      return *reinterpret_cast<void**>(storage);
    }
  };

  [[nodiscard]] void* RuntimeGetLocaleFacetBaseVtable()
  {
    static void* const baseVtable = RuntimeFacetBaseVtableProbe::CaptureBaseVtable();
    return baseVtable;
  }

  /**
   * Address: 0x004C5960 (FUN_004C5960, sub_4C5960)
   *
   * What it does:
   * Rebinds one locale facet object to the base `std::locale::facet` vtable.
   */
  [[maybe_unused]] std::locale::facet* RuntimeLocaleFacetBindBaseVtable(std::locale::facet* const facet)
  {
    *reinterpret_cast<void**>(facet) = RuntimeGetLocaleFacetBaseVtable();
    return facet;
  }

  /**
   * Address: 0x004C5970 (FUN_004C5970, std::codecvt::do_in)
   *
   * What it does:
   * Reports `noconv`, copying input/output next-pointer lanes to begin pointers.
   */
  [[maybe_unused]] std::codecvt_base::result RuntimeCodecvtDoInNoConversion(
    const void* const /*codecvtSelf*/,
    const char* const fromBegin,
    const char* const /*fromEnd*/,
    const char** const fromNext,
    char* const toBegin,
    char* const /*toEnd*/,
    char** const toNext
  )
  {
    *fromNext = fromBegin;
    *toNext = toBegin;
    return std::codecvt_base::noconv;
  }

  /**
   * Address: 0x004C5990 (FUN_004C5990, std::codecvt::do_out)
   *
   * What it does:
   * Reports `noconv`, copying input/output next-pointer lanes to begin pointers.
   */
  [[maybe_unused]] std::codecvt_base::result RuntimeCodecvtDoOutNoConversion(
    const void* const /*codecvtSelf*/,
    const char* const fromBegin,
    const char* const /*fromEnd*/,
    const char** const fromNext,
    char* const toBegin,
    char* const /*toEnd*/,
    char** const toNext
  )
  {
    *fromNext = fromBegin;
    *toNext = toBegin;
    return std::codecvt_base::noconv;
  }

  /**
   * Address: 0x004C59B0 (FUN_004C59B0, std::codecvt::do_unshift)
   *
   * What it does:
   * Reports `noconv` and keeps output-next lane at output begin.
   */
  [[maybe_unused]] std::codecvt_base::result RuntimeCodecvtDoUnshiftNoConversion(
    const void* const /*codecvtSelf*/,
    char* const toBegin,
    char* const /*toEnd*/,
    char** const toNext
  )
  {
    *toNext = toBegin;
    return std::codecvt_base::noconv;
  }

  /**
   * Address: 0x004C59D0 (FUN_004C59D0, std::codecvt::do_length)
   *
   * What it does:
   * Returns min(maxCount, byte-span between begin/end input pointers).
   */
  [[maybe_unused]] std::uint32_t RuntimeCodecvtDoLengthNoConversion(
    const void* const /*codecvtSelf*/,
    const char* const fromBegin,
    const char* const fromEnd,
    const std::uint32_t maxCount
  )
  {
    const std::uint32_t spanBytes = static_cast<std::uint32_t>(
      reinterpret_cast<std::uintptr_t>(fromEnd) - reinterpret_cast<std::uintptr_t>(fromBegin)
    );
    if (maxCount < spanBytes) {
      return maxCount;
    }
    return spanBytes;
  }

  /**
   * Address: 0x004C59F0 (FUN_004C59F0, sub_4C59F0)
   *
   * What it does:
   * Runs base facet vtable rebinding and optionally frees storage when delete
   * flag bit0 is set.
   */
  [[maybe_unused]] std::locale::facet* RuntimeLocaleFacetDestroyMaybeDelete(
    std::locale::facet* const facet,
    const std::uint8_t deleteFlag
  )
  {
    RuntimeLocaleFacetBindBaseVtable(facet);
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(facet);
    }
    return facet;
  }

  /**
   * Address: 0x00479CC0 (FUN_00479CC0, std::locale::locale)
   *
   * What it does:
   * Initializes one locale object from the process-global locale implementation
   * and increments its reference count under `_Lockit(0)`.
   */
  [[maybe_unused]] RuntimeStdLocaleObject* RuntimeLocaleDefaultConstruct(RuntimeStdLocaleObject* const locale)
  {
    locale->ptr = RuntimeLocaleInit();
    RuntimeLocaleLocimpView* const globalLocale = RuntimeGetGlobalLocale();

    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);
    if (globalLocale != nullptr && globalLocale->refs != -1) {
      ++globalLocale->refs;
    }
    RuntimeLockitDestroy(&lockit);
    return locale;
  }

  class RuntimeWstreambufBaseVtableProbe final : public std::wstreambuf
  {
  public:
    RuntimeWstreambufBaseVtableProbe()
      : std::wstreambuf()
    {
    }

    static void* CaptureBaseVtable()
    {
      alignas(RuntimeWstreambufBaseVtableProbe) std::uint8_t storage[sizeof(RuntimeWstreambufBaseVtableProbe)]{};
      auto* const probe = new (storage) RuntimeWstreambufBaseVtableProbe();
      probe->std::basic_streambuf<wchar_t>::~basic_streambuf();
      return *reinterpret_cast<void**>(storage);
    }
  };

  [[nodiscard]] void* RuntimeGetWstreambufBaseVtable()
  {
    static void* const baseVtable = RuntimeWstreambufBaseVtableProbe::CaptureBaseVtable();
    return baseVtable;
  }

  struct RuntimeBasicWstreambufView
  {
    void* vtable = nullptr;                      // +0x00
    RuntimeMutexHandle mutex{};                  // +0x04
    std::uint32_t lane0Value = 0;                // +0x08
    std::uint32_t lane0Scratch = 0;              // +0x0C
    std::uint32_t* lane0Begin = nullptr;         // +0x10
    std::uint32_t* lane0End = nullptr;           // +0x14
    std::uint32_t lane1Value = 0;                // +0x18
    std::uint32_t lane1Scratch = 0;              // +0x1C
    std::uint32_t* lane1Begin = nullptr;         // +0x20
    std::uint32_t* lane1End = nullptr;           // +0x24
    std::uint32_t lane2Value = 0;                // +0x28
    std::uint32_t lane2Scratch = 0;              // +0x2C
    std::uint32_t* lane2Begin = nullptr;         // +0x30
    std::uint32_t* lane2End = nullptr;           // +0x34
    RuntimeStdLocaleObject* localeObject = nullptr; // +0x38
  };
  static_assert(offsetof(RuntimeBasicWstreambufView, vtable) == 0x00, "RuntimeBasicWstreambufView::vtable offset must be 0x00");
  static_assert(offsetof(RuntimeBasicWstreambufView, mutex) == 0x04, "RuntimeBasicWstreambufView::mutex offset must be 0x04");
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane0Begin) == 0x10,
    "RuntimeBasicWstreambufView::lane0Begin offset must be 0x10"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane0End) == 0x14,
    "RuntimeBasicWstreambufView::lane0End offset must be 0x14"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane1Begin) == 0x20,
    "RuntimeBasicWstreambufView::lane1Begin offset must be 0x20"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane1End) == 0x24,
    "RuntimeBasicWstreambufView::lane1End offset must be 0x24"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane2Begin) == 0x30,
    "RuntimeBasicWstreambufView::lane2Begin offset must be 0x30"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, lane2End) == 0x34,
    "RuntimeBasicWstreambufView::lane2End offset must be 0x34"
  );
  static_assert(
    offsetof(RuntimeBasicWstreambufView, localeObject) == 0x38,
    "RuntimeBasicWstreambufView::localeObject offset must be 0x38"
  );
  static_assert(sizeof(RuntimeBasicWstreambufView) == 0x3C, "RuntimeBasicWstreambufView size must be 0x3C");

  /**
   * Address: 0x004F95E0 (FUN_004F95E0, std::basic_streambuf<wchar_t,std::char_traits<wchar_t>>::_Init)
   *
   * What it does:
   * Rebinds the three internal pointer-lane pairs to local storage words and
   * clears those word lanes to zero.
   */
  [[maybe_unused]] std::uint32_t* RuntimeBasicWstreambufInit(RuntimeBasicWstreambufView* const streambuf)
  {
    streambuf->lane1Begin = &streambuf->lane1Value;
    streambuf->lane1End = &streambuf->lane1Scratch;
    streambuf->lane0Begin = &streambuf->lane0Value;
    streambuf->lane2Begin = &streambuf->lane2Value;
    streambuf->lane0End = &streambuf->lane0Scratch;
    streambuf->lane2End = &streambuf->lane2Scratch;

    streambuf->lane0Scratch = 0;
    *streambuf->lane1End = 0;
    *streambuf->lane2End = 0;
    *streambuf->lane0Begin = 0;
    *streambuf->lane1Begin = 0;
    *streambuf->lane2Begin = 0;
    return streambuf->lane2Begin;
  }

  /**
   * Address: 0x004F8820 (FUN_004F8820, std::basic_streambuf<wchar_t,std::char_traits<wchar_t>>::basic_streambuf)
   *
   * What it does:
   * Installs `wstreambuf` vtable, constructs mutex/locale lanes, and initializes
   * internal pointer-lane storage.
   */
  [[maybe_unused]] RuntimeBasicWstreambufView* RuntimeBasicWstreambufConstruct(RuntimeBasicWstreambufView* const streambuf)
  {
    streambuf->vtable = RuntimeGetWstreambufBaseVtable();
    RuntimeMutexConstruct(&streambuf->mutex);

    auto* const localeStorage = static_cast<RuntimeStdLocaleObject*>(::operator new(sizeof(RuntimeStdLocaleObject), std::nothrow));
    if (localeStorage != nullptr) {
      RuntimeLocaleDefaultConstruct(localeStorage);
    }
    streambuf->localeObject = localeStorage;

    (void)RuntimeBasicWstreambufInit(streambuf);
    return streambuf;
  }

  struct RuntimeBasicStreambufLocaleView
  {
    std::uint8_t reserved00_37[0x38]{};
    RuntimeStdLocaleObject* localeObject = nullptr; // +0x38
  };
  static_assert(offsetof(RuntimeBasicStreambufLocaleView, localeObject) == 0x38, "RuntimeBasicStreambufLocaleView::localeObject offset must be 0x38");
  static_assert(sizeof(RuntimeBasicStreambufLocaleView) == 0x3C, "RuntimeBasicStreambufLocaleView size must be 0x3C");

  /**
   * Address: 0x004C5A10 (FUN_004C5A10, std::basic_streambuf<wchar_t,std::char_traits<wchar_t>>::getloc)
   *
   * What it does:
   * Returns one locale object copied from streambuf locale lane and increments
   * `_Locimp::_Refs` under `_Lockit(0)` unless refs is `-1`.
   */
  [[maybe_unused]] RuntimeStdLocaleObject* RuntimeBasicStreambufGetLocale(
    const RuntimeBasicStreambufLocaleView* const streambuf,
    RuntimeStdLocaleObject* const outLocale
  )
  {
    RuntimeLocaleLocimpView* const localeImpl = streambuf->localeObject->ptr;
    outLocale->ptr = localeImpl;

    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);
    if (localeImpl->refs != -1) {
      ++localeImpl->refs;
    }
    RuntimeLockitDestroy(&lockit);
    return outLocale;
  }

  struct RuntimeStreambufPointerTripletView
  {
    std::uint8_t reserved00_0F[0x10]{};
    void* lane0Begin = nullptr;           // +0x10
    void* lane0End = nullptr;             // +0x14
    std::uint8_t reserved18_1F[0x08]{};
    void* lane1Begin = nullptr;           // +0x20
    void* lane1End = nullptr;             // +0x24
    std::uint8_t reserved28_2F[0x08]{};
    void* lane2Begin = nullptr;           // +0x30
    void* lane2End = nullptr;             // +0x34
  };
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane0Begin) == 0x10, "RuntimeStreambufPointerTripletView::lane0Begin offset must be 0x10");
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane0End) == 0x14, "RuntimeStreambufPointerTripletView::lane0End offset must be 0x14");
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane1Begin) == 0x20, "RuntimeStreambufPointerTripletView::lane1Begin offset must be 0x20");
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane1End) == 0x24, "RuntimeStreambufPointerTripletView::lane1End offset must be 0x24");
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane2Begin) == 0x30, "RuntimeStreambufPointerTripletView::lane2Begin offset must be 0x30");
  static_assert(offsetof(RuntimeStreambufPointerTripletView, lane2End) == 0x34, "RuntimeStreambufPointerTripletView::lane2End offset must be 0x34");
  static_assert(sizeof(RuntimeStreambufPointerTripletView) == 0x38, "RuntimeStreambufPointerTripletView size must be 0x38");

  /**
   * Address: 0x004C5A50 (FUN_004C5A50, sub_4C5A50)
   *
   * What it does:
   * Stores three begin/end pointer pairs into streambuf pointer-lane triplet
   * and returns the third begin pointer lane.
   */
  [[maybe_unused]] void* RuntimeStreambufSetPointerTriplets(
    RuntimeStreambufPointerTripletView* const streambuf,
    void* const lane0Begin,
    void* const lane1Begin,
    void* const lane2Begin,
    void* const lane0End,
    void* const lane1End,
    void* const lane2End
  )
  {
    streambuf->lane0Begin = lane0Begin;
    streambuf->lane0End = lane0End;
    streambuf->lane1Begin = lane1Begin;
    streambuf->lane1End = lane1End;
    streambuf->lane2Begin = lane2Begin;
    streambuf->lane2End = lane2End;
    return lane2Begin;
  }

  /**
   * Address: 0x00A99754 (FUN_00A99754, HandlerRoutine)
   *
   * What it does:
   * Dispatches console Ctrl-C / Ctrl-Break events through encoded signal
   * handlers under `_SIGNAL_LOCK`, clearing one-shot user handlers after decode.
   */
  BOOL __stdcall RuntimeConsoleControlHandler(const DWORD controlType)
  {
    _lock(kRuntimeSignalLock);

    void** encodedActionSlot = nullptr;
    RuntimeSignalHandler decodedHandler = nullptr;
    int signalNumber = 0;

    if (controlType == CTRL_C_EVENT) {
      encodedActionSlot = &gRuntimeCtrlCActionEncoded;
      decodedHandler = RuntimeDecodeSignalAction(gRuntimeCtrlCActionEncoded);
      signalNumber = 2;
    } else {
      encodedActionSlot = &gRuntimeCtrlBreakActionEncoded;
      decodedHandler = RuntimeDecodeSignalAction(gRuntimeCtrlBreakActionEncoded);
      signalNumber = 21;
    }

    if (decodedHandler != nullptr && decodedHandler != reinterpret_cast<RuntimeSignalHandler>(1)) {
      *encodedActionSlot = RuntimeEncodedNullPointer();
    }

    _unlock(kRuntimeSignalLock);

    if (decodedHandler == nullptr) {
      return FALSE;
    }

    if (decodedHandler != reinterpret_cast<RuntimeSignalHandler>(1)) {
      decodedHandler(signalNumber);
    }
    return TRUE;
  }

  /**
   * Address: 0x00ABF81C (FUN_00ABF81C, _Init_locks::_Init_locks)
   *
   * What it does:
   * Initializes one shared 4-slot CRT lock table on first init epoch.
   */
  void* RuntimeInitStdLocks(void* const object)
  {
    if (::InterlockedIncrement(&gRuntimeStdLockInit) == 0) {
      for (CRITICAL_SECTION& lock : gRuntimeStdLockSlots) {
        RuntimeMtxInit(&lock);
      }
    }
    return object;
  }

  /**
   * Address: 0x00ABF8DB (FUN_00ABF8DB, std::_Lockit::_Lockit)
   *
   * What it does:
   * Captures one lock-slot id (`arg & 3`) and enters that CRT lock slot.
   */
  RuntimeLockitState* RuntimeLockitConstruct(RuntimeLockitState* const object, const int requestedSlot)
  {
    const int slot = requestedSlot & 3;
    object->slot = slot;
    (void)RuntimeMtxLock(RuntimeStdLockSlot(slot));
    return object;
  }

  /**
   * Address: 0x00ABF8FC (FUN_00ABF8FC, std::_Lockit::~_Lockit)
   *
   * What it does:
   * Leaves the CRT lock slot captured by this `_Lockit` guard.
   */
  void RuntimeLockitDestroy(RuntimeLockitState* const object)
  {
    (void)RuntimeMtxUnlock(RuntimeStdLockSlot(object->slot));
  }

  /**
   * Address: 0x00ABF97B (FUN_00ABF97B, std::_Mutex::_Mutex)
   *
   * What it does:
   * Allocates one `CRITICAL_SECTION` object and initializes it.
   */
  RuntimeMutexHandle* RuntimeMutexConstruct(RuntimeMutexHandle* const object)
  {
    auto* const lock = static_cast<CRITICAL_SECTION*>(::operator new(sizeof(CRITICAL_SECTION)));
    object->criticalSection = lock;
    RuntimeMtxInit(lock);
    return object;
  }

  /**
   * Address: 0x00ABF993 (FUN_00ABF993, std::_Mutex::~_Mutex)
   *
   * What it does:
   * Destroys and frees one heap-allocated `CRITICAL_SECTION`.
   */
  void RuntimeMutexDestroy(RuntimeMutexHandle* const object)
  {
    if (object->criticalSection != nullptr) {
      RuntimeMtxDestroy(object->criticalSection);
      ::operator delete(object->criticalSection);
      object->criticalSection = nullptr;
    }
  }

  /**
   * Address: 0x00ABF9A8 (FUN_00ABF9A8, std::_Mutex::_Lock)
   *
   * What it does:
   * Enters the mutex critical section.
   */
  int RuntimeMutexLock(RuntimeMutexHandle* const object)
  {
    return RuntimeMtxLock(object->criticalSection);
  }

  /**
   * Address: 0x00ABF9B1 (FUN_00ABF9B1, std::_Mutex::_Unlock)
   *
   * What it does:
   * Leaves the mutex critical section.
   */
  int RuntimeMutexUnlock(RuntimeMutexHandle* const object)
  {
    return RuntimeMtxUnlock(object->criticalSection);
  }

  /**
   * Address: 0x00AAACB0 (FUN_00AAACB0, __crtGetEnvironmentStringsA)
   *
   * What it does:
   * Returns one heap-copied ANSI environment block, preferring the
   * wide-environment lane with explicit `WideCharToMultiByte` conversion when
   * available, and falling back to `GetEnvironmentStringsA` when required.
   */
  char* RuntimeGetEnvironmentStringsA()
  {
    wchar_t* environmentStringsWide = nullptr;
    char* environmentStringsAnsi = nullptr;
    int mode = gRuntimeGetEnvironmentStringsEncodingMode;

    if (mode == 0) {
      environmentStringsWide = ::GetEnvironmentStringsW();
      if (environmentStringsWide != nullptr) {
        gRuntimeGetEnvironmentStringsEncodingMode = 1;
        mode = 1;
      } else if (::GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
        gRuntimeGetEnvironmentStringsEncodingMode = 2;
        mode = 2;
      }
    }

    if (mode == 1) {
      if (environmentStringsWide == nullptr) {
        environmentStringsWide = ::GetEnvironmentStringsW();
        if (environmentStringsWide == nullptr) {
          return nullptr;
        }
      }

      const wchar_t* scan = environmentStringsWide;
      while (*scan != L'\0') {
        while (*scan != L'\0') {
          ++scan;
        }
        ++scan;
      }
      const int wideCharCount = static_cast<int>(scan - environmentStringsWide + 1);

      const int byteCount = ::WideCharToMultiByte(0, 0, environmentStringsWide, wideCharCount, nullptr, 0, nullptr, nullptr);
      if (byteCount > 0) {
        environmentStringsAnsi = static_cast<char*>(std::malloc(static_cast<std::size_t>(byteCount)));
        if (environmentStringsAnsi != nullptr) {
          if (::WideCharToMultiByte(0, 0, environmentStringsWide, wideCharCount, environmentStringsAnsi, byteCount, nullptr, nullptr)
              == 0) {
            _free_crt(environmentStringsAnsi);
            environmentStringsAnsi = nullptr;
          }
        }
      }

      ::FreeEnvironmentStringsW(environmentStringsWide);
      return environmentStringsAnsi;
    }

    if (mode != 2 && mode != 0) {
      return nullptr;
    }

    char* const systemBlock = ::GetEnvironmentStringsA();
    if (systemBlock == nullptr) {
      return nullptr;
    }

    char* scan = systemBlock;
    while (*scan != '\0') {
      while (*scan != '\0') {
        ++scan;
      }
      ++scan;
    }

    const std::size_t byteCount = static_cast<std::size_t>(scan - systemBlock + 1);
    environmentStringsAnsi = static_cast<char*>(std::malloc(byteCount));
    if (environmentStringsAnsi == nullptr) {
      ::FreeEnvironmentStringsA(systemBlock);
      return nullptr;
    }

    std::memcpy(environmentStringsAnsi, systemBlock, byteCount);
    ::FreeEnvironmentStringsA(systemBlock);
    return environmentStringsAnsi;
  }

  /**
   * Address: 0x00A86718 (FUN_00A86718, fseek)
   *
   * What it does:
   * Validates stream/origin and forwards to CRT `fseek`; invalid arguments
   * route through CRT invalid-parameter handling and return `-1`.
   */
  int RuntimeFseek(std::FILE* const stream, const long offset, const int origin)
  {
    if (stream != nullptr && static_cast<unsigned int>(origin) <= 2u) {
      return std::fseek(stream, offset, origin);
    }

    *RuntimeDosErrno() = 0;
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  /**
   * Address: 0x00A89B60 (FUN_00A89B60, strncpy)
   *
   * What it does:
   * Copies up to `count` chars from `source` into `destination`, stopping at
   * the first source NUL and zero-filling remaining destination bytes.
   */
  char* RuntimeStrncpy(char* const destination, const char* const source, const std::size_t count)
  {
    if (count == 0u) {
      return destination;
    }

    std::size_t writeIndex = 0u;
    while (writeIndex < count) {
      destination[writeIndex] = source[writeIndex];
      if (source[writeIndex] == '\0') {
        ++writeIndex;
        while (writeIndex < count) {
          destination[writeIndex++] = '\0';
        }
        return destination;
      }
      ++writeIndex;
    }

    return destination;
  }

  /**
   * Address: 0x00A8E0E0 (FUN_00A8E0E0, __CIpow)
   *
   * What it does:
   * Computes one power lane (`base^exponent`) for CRT inline-fpu callsites.
   */
  double RuntimeCIPow(const double base, const double exponent)
  {
    return std::pow(base, exponent);
  }

  /**
   * Address: 0x00AB99FD (FUN_00AB99FD, _memicmp_l)
   *
   * What it does:
   * Locale-aware case-insensitive memory compare lane; validates pointer/count
   * bounds and returns CRT invalid-parameter sentinel on misuse.
   */
  int RuntimeMemicmpLocale(
    const unsigned char* const lhsBytes,
    const unsigned char* const rhsBytes,
    const unsigned int byteCount,
    _locale_t const localeInfo
  )
  {
    if (byteCount == 0u) {
      return 0;
    }

    if (lhsBytes == nullptr || rhsBytes == nullptr || byteCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_memicmp_l(lhsBytes, rhsBytes, byteCount, localeInfo);
  }

  /**
   * Address: 0x00AB7F14 (FUN_00AB7F14, _strnicoll_l)
   *
   * What it does:
   * Locale-aware bounded case-insensitive collation compare with CRT argument
   * validation and `0x7FFFFFFF` failure sentinel behavior.
   */
  int RuntimeStrnicollLocale(
    const char* const lhsText,
    const char* const rhsText,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    if (maxCount == 0u) {
      return 0;
    }

    if (lhsText == nullptr || rhsText == nullptr || maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_strnicoll_l(lhsText, rhsText, maxCount, localeInfo);
  }

  /**
   * Address: 0x00A8B1C5 (FUN_00A8B1C5, _Getdays_l)
   *
   * What it does:
   * Builds one CRT weekday descriptor string in `:abbr:full` pairs for all
   * seven days using the active locale-time table.
   */
  char* RuntimeGetdaysLocale(_locale_t const localeInfo)
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    RuntimeThreadLocInfoView* const locInfo = RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    char* result = nullptr;
    if (locInfo != nullptr && locInfo->lcTimeCurrent != nullptr) {
      const auto* const lcTimeData = reinterpret_cast<const RuntimeLcTimeStringTableView*>(locInfo->lcTimeCurrent);
      result = RuntimeBuildColonDelimitedLocaleString(lcTimeData->wdayAbbr, lcTimeData->wday, 7u);
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00A8B2CC (FUN_00A8B2CC, _Getmonths_l)
   *
   * What it does:
   * Builds one CRT month descriptor string in `:abbr:full` pairs for all
   * twelve months using the active locale-time table.
   */
  char* RuntimeGetmonthsLocale(_locale_t const localeInfo)
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    RuntimeThreadLocInfoView* const locInfo = RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    char* result = nullptr;
    if (locInfo != nullptr && locInfo->lcTimeCurrent != nullptr) {
      const auto* const lcTimeData = reinterpret_cast<const RuntimeLcTimeStringTableView*>(locInfo->lcTimeCurrent);
      result = RuntimeBuildColonDelimitedLocaleString(lcTimeData->monthAbbr, lcTimeData->month, 12u);
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00A9B334 (FUN_00A9B334, __mbsnbicoll_l)
   *
   * What it does:
   * Bounded multibyte, case-insensitive collation compare with CRT argument
   * validation and `0x7FFFFFFF` invalid-parameter sentinel behavior.
   */
  int RuntimeMbsnbicollLocale(
    const unsigned char* const lhsText,
    const unsigned char* const rhsText,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    if (maxCount == 0u) {
      return 0;
    }

    if (lhsText == nullptr || rhsText == nullptr || maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_mbsnbicoll_l(lhsText, rhsText, maxCount, localeInfo);
  }

  /**
   * Address: 0x00AB85F6 (FUN_00AB85F6, _mbsicmp_l)
   *
   * What it does:
   * Multibyte case-insensitive compare with CRT invalid-parameter handling for
   * null input strings.
   */
  int RuntimeMbsicmpLocale(const unsigned char* const lhsText, const unsigned char* const rhsText, _locale_t const localeInfo)
  {
    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_mbsicmp_l(lhsText, rhsText, localeInfo);
  }

  /**
   * Address: 0x00AB9AED (FUN_00AB9AED, _memicmp)
   *
   * What it does:
   * ASCII case-insensitive memory compare lane with CRT-style invalid-argument
   * reporting on null or oversized requests.
   */
  int RuntimeMemicmp(const void* const lhsBuffer, const void* const rhsBuffer, const std::size_t byteCount)
  {
    if (lhsBuffer != nullptr && rhsBuffer != nullptr && byteCount <= 0x7FFFFFFFu) {
      const auto* const lhsBytes = static_cast<const unsigned char*>(lhsBuffer);
      const auto* const rhsBytes = static_cast<const unsigned char*>(rhsBuffer);

      for (std::size_t index = 0; index < byteCount; ++index) {
        const unsigned char lhsLower = RuntimeAsciiToLower(lhsBytes[index]);
        const unsigned char rhsLower = RuntimeAsciiToLower(rhsBytes[index]);
        if (lhsLower != rhsLower) {
          return static_cast<int>(lhsLower) - static_cast<int>(rhsLower);
        }
      }

      return 0;
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0x7FFFFFFF;
  }

  /**
   * Address: 0x00A8A880 (FUN_00A8A880, vfscanf worker lane)
   *
   * What it does:
   * Validates stream/format lanes, enforces CRT unicode-textmode exclusion for
   * narrow scanners, then dispatches one scanner worker under stream lock.
   */
  int RuntimeVfscanf(
    int(__cdecl* worker)(std::FILE*, int, int, int),
    std::FILE* const stream,
    const int format,
    const int arg3,
    const int arg4
  )
  {
    int result = 0;
    if (stream == nullptr || format == 0) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    _lock_file(stream);
    if ((RuntimeGetFileFlags(stream) & 0x40) == 0) {
      const RuntimeIoInfo* const ioInfo = ResolveIoInfoFromStream(stream);
      if (((ioInfo->textmodeUnicode & 0x7F) != 0) || ResolveIoInfoFromStream(stream)->textmodeUnicode < 0) {
        *_errno() = EINVAL;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        result = -1;
      }
    }

    if (result == 0) {
      result = worker(stream, format, arg3, arg4);
    }

    _unlock_file(stream);
    return result;
  }

  /**
   * Address: 0x00A8A3EB (FUN_00A8A3EB, fgets)
   *
   * What it does:
   * Validates destination/count/stream lanes, acquires stream lock, reads up
   * to newline or count-1 bytes, and NUL-terminates on success.
   */
  char* RuntimeFgets(char* const destination, const int maxCount, std::FILE* const stream)
  {
    if ((destination == nullptr && maxCount != 0) || maxCount < 0 || stream == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    if (maxCount == 0) {
      return nullptr;
    }

    _lock_file(stream);

    char* writeCursor = destination;
    char* result = destination;
    int remaining = maxCount;
    while (--remaining > 0) {
      const int nextChar = std::fgetc(stream);
      if (nextChar == EOF) {
        if (writeCursor == destination) {
          result = nullptr;
        }
        break;
      }

      *writeCursor = static_cast<char>(nextChar);
      ++writeCursor;
      if (nextChar == '\n') {
        break;
      }
    }

    if (result != nullptr) {
      *writeCursor = '\0';
    }

    _unlock_file(stream);
    return result;
  }

  /**
   * Address: 0x00AA4A1D (FUN_00AA4A1D, _strdup)
   *
   * What it does:
   * Duplicates one C string into CRT heap storage; null input yields null and
   * copy failure routes through Watson.
   */
  char* RuntimeStrdup(const char* const text)
  {
    if (text == nullptr) {
      return nullptr;
    }

    const std::size_t length = std::strlen(text) + 1u;
    char* const copy = static_cast<char*>(std::malloc(length));
    if (copy == nullptr) {
      return nullptr;
    }

    if (::strcpy_s(copy, length, text) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    return copy;
  }

  /**
   * Address: 0x00A9003B (FUN_00A9003B, _wcsdup)
   *
   * What it does:
   * Duplicates one wide string into CRT heap storage; null input yields null.
   * Copies route through checked `wcscpy_s`, invoking Watson on failure.
   */
  wchar_t* RuntimeWcsdup(const wchar_t* const text)
  {
    if (text == nullptr) {
      return nullptr;
    }

    const std::size_t length = std::wcslen(text) + 1u;
    auto* const copy = static_cast<wchar_t*>(std::calloc(length, sizeof(wchar_t)));
    if (copy == nullptr) {
      return nullptr;
    }

    if (::wcscpy_s(copy, length, text) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    return copy;
  }

  /**
   * Address: 0x00A84379 (FUN_00A84379, _findfirst64)
   *
   * What it does:
   * Validates wildcard/output arguments and forwards to CRT `_findfirst64`.
   */
  intptr_t RuntimeFindFirst64(const char* const wildcard, __finddata64_t* const findData)
  {
    if (wildcard == nullptr || findData == nullptr) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    return ::_findfirst64(wildcard, findData);
  }

  /**
   * Address: 0x00A994FB (FUN_00A994FB, terminate)
   *
   * What it does:
   * Invokes the active terminate handler and hard-aborts when control returns.
   */
  [[noreturn]] void RuntimeTerminate()
  {
    const std::terminate_handler terminateHandler = std::get_terminate();
    if (terminateHandler != nullptr) {
      terminateHandler();
    }

    std::abort();
  }

  /**
   * Address: 0x00A8EF77 (FUN_00A8EF77, func_wstrFindFirst)
   *
   * What it does:
   * Scans a NUL-terminated wide string and returns the first matching
   * character position; when searching for NUL, returns the terminator lane.
   */
  wchar_t* RuntimeFindFirstWideChar(wchar_t* text, const wchar_t needle)
  {
    wchar_t* cursor = text;
    while (*cursor != L'\0') {
      if (*cursor == needle) {
        return cursor;
      }
      ++cursor;
    }

    return (*cursor == needle) ? cursor : nullptr;
  }

  /**
   * Address: 0x00A8EF99 (FUN_00A8EF99, func_wstrFindLast)
   *
   * What it does:
   * Scans a NUL-terminated wide string from the tail and returns the last
   * matching character position; when searching for NUL, returns the
   * terminator lane.
   */
  wchar_t* RuntimeFindLastWideChar(wchar_t* text, const wchar_t needle)
  {
    wchar_t* cursor = text;
    while (*cursor++ != L'\0') {
    }

    do {
      --cursor;
    } while (cursor != text && *cursor != needle);

    return (*cursor == needle) ? cursor : nullptr;
  }

  /**
   * Address: 0x0095FAC0 (FUN_0095FAC0, j_func_wstrFindFirst)
   *
   * What it does:
   * Import thunk that forwards to the runtime first-match wide-char scan lane.
   */
  wchar_t* RuntimeFindFirstWideCharThunk(wchar_t* text, const wchar_t needle)
  {
    return RuntimeFindFirstWideChar(text, needle);
  }

  /**
   * Address: 0x0095FAD0 (FUN_0095FAD0, j_func_wstrFindLast)
   *
   * What it does:
   * Import thunk that forwards to the runtime last-match wide-char scan lane.
   */
  wchar_t* RuntimeFindLastWideCharThunk(wchar_t* text, const wchar_t needle)
  {
    return RuntimeFindLastWideChar(text, needle);
  }

  /**
   * Address: 0x00A48F20 (FUN_00A48F20, j_func_FileCloseSafe)
   *
   * What it does:
   * Import thunk that forwards to CRT `fclose`.
   */
  int RuntimeFileCloseSafe(std::FILE* stream)
  {
    return std::fclose(stream);
  }

  /**
   * Address: 0x00A835CE (FUN_00A835CE, __imp_atoi)
   *
   * What it does:
   * Legacy import thunk lane for `atoi` that forwards through CRT `atol`.
   */
  int RuntimeAtoiForward(const char* text)
  {
    return static_cast<int>(std::atol(text));
  }

  /**
   * Address: 0x00A86DE2 (FUN_00A86DE2, _ctime64)
   *
   * What it does:
   * Validates one epoch-seconds pointer/range, converts to local `tm`, then
   * formats and returns a thread-local 26-byte C time string.
   */
  char* RuntimeCtime64(const __time64_t* const epochSeconds)
  {
    if (epochSeconds == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    if (*epochSeconds < 0) {
      *_errno() = EINVAL;
      return nullptr;
    }

    std::tm localTime{};
    if (_localtime64_s(&localTime, epochSeconds) != 0) {
      return nullptr;
    }

    thread_local char threadLocalAsctimeBuffer[26]{};
    if (::asctime_s(threadLocalAsctimeBuffer, _countof(threadLocalAsctimeBuffer), &localTime) != 0) {
      return nullptr;
    }

    return threadLocalAsctimeBuffer;
  }

  /**
   * Address: 0x00A86D49 (FUN_00A86D49, localtime64)
   *
   * What it does:
   * Returns the thread-local `tm` view for one epoch-second input on success,
   * and null on conversion failure.
   */
  std::tm* RuntimeLocaltime64(const __time64_t* const epochSeconds)
  {
    thread_local std::tm threadLocalTime{};
    if (_localtime64_s(&threadLocalTime, epochSeconds) != 0) {
      return nullptr;
    }
    return &threadLocalTime;
  }

  /**
   * Address: 0x00A8A866 (FUN_00A8A866, mktime64)
   *
   * What it does:
   * Converts one local `tm` payload into epoch seconds using CRT 64-bit mktime
   * semantics.
   */
  extern "C" __time64_t mktime64(std::tm* const timeInfo)
  {
    if (timeInfo == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<__time64_t>(-1);
    }

    return ::_mktime64(timeInfo);
  }

  /**
   * Address: 0x00A89A03 (FUN_00A89A03, _ferror)
   *
   * What it does:
   * Returns one stream's error-flag lane; null streams report EINVAL and raise
   * CRT invalid-parameter handling.
   */
  int RuntimeFileError(std::FILE* const stream)
  {
    if (stream != nullptr) {
      return std::ferror(stream);
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0;
  }

  /**
   * Address: 0x00A899D4 (FUN_00A899D4, _feof)
   *
   * What it does:
   * Returns one stream's EOF-flag lane; null streams report EINVAL and raise
   * CRT invalid-parameter handling.
   */
  int RuntimeFileEof(std::FILE* const stream)
  {
    if (stream != nullptr) {
      return std::feof(stream);
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0;
  }

  /**
   * Address: 0x00A89F2B (FUN_00A89F2B, __lock_file)
   *
   * What it does:
   * Acquires one CRT FILE lock lane.
   */
  void RuntimeLockFile(std::FILE* const stream)
  {
    ::_lock_file(stream);
  }

  /**
   * Address: 0x00A824E7 (FUN_00A824E7, _memmove_s)
   *
   * What it does:
   * Validates secure-move arguments, reports CRT invalid-parameter errors, and
   * performs byte-wise overlapping move when bounds are valid.
   */
  errno_t RuntimeMemmoveS(
    void* const destination,
    const std::size_t destinationSize,
    const void* const source,
    const std::size_t sourceSize
  )
  {
    if (sourceSize == 0u) {
      return 0;
    }

    if (destination == nullptr || source == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    if (destinationSize < sourceSize) {
      *_errno() = ERANGE;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return ERANGE;
    }

    std::memmove(destination, source, sourceSize);
    return 0;
  }

  /**
   * Address: 0x00A82DF0 (FUN_00A82DF0, memchr)
   *
   * What it does:
   * Scans up to `maxCount` bytes for one target byte value and returns pointer
   * to the first match (or null when not found).
   */
  extern "C" void* __cdecl RuntimeMemchr(const void* const buffer, const int value, const std::size_t maxCount)
  {
    const auto* const bytes = static_cast<const std::uint8_t*>(buffer);
    const std::uint8_t needle = static_cast<std::uint8_t>(value);
    for (std::size_t index = 0; index < maxCount; ++index) {
      if (bytes[index] == needle) {
        return const_cast<std::uint8_t*>(&bytes[index]);
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00A83F03 (FUN_00A83F03, isnan)
   *
   * What it does:
   * Detects IEEE-754 NaN payload lanes from raw double bits and returns
   * non-zero when the input is NaN.
   */
  extern "C" int __cdecl RuntimeIsnan(const double value)
  {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));

    const std::uint16_t hiWord = static_cast<std::uint16_t>(bits >> 48);
    const std::uint32_t hiDword = static_cast<std::uint32_t>(bits >> 32);
    const std::uint32_t loDword = static_cast<std::uint32_t>(bits);

    const bool isPayloadNaN =
      ((hiWord & 0x7FF8u) == 0x7FF0u) && (((hiDword & 0x7FFFFu) != 0u) || (loDword != 0u));
    const bool isCanonicalNaN = ((hiWord & 0x7FF8u) == 0x7FF8u);
    return (isPayloadNaN || isCanonicalNaN) ? 1 : 0;
  }

  struct RuntimeTidDataDosErrnoView
  {
    unsigned long mThreadId;         // +0x00
    std::intptr_t mThreadHandle;     // +0x04
    std::uint8_t mReserved08_0B[0x4];
    unsigned long mDosErrno;         // +0x0C
  };
  static_assert(
    offsetof(RuntimeTidDataDosErrnoView, mDosErrno) == 0x0C,
    "RuntimeTidDataDosErrnoView::mDosErrno offset must be 0x0C"
  );

  unsigned long gRuntimeDosErrnoFallback = 0;

  /**
   * Address: 0x00A95B9F (FUN_00A95B9F, _getptd_noexit)
   *
   * What it does:
   * Returns per-thread CRT `_tiddata` storage from FLS, allocating and
   * initializing one record on first access without raising allocation
   * exceptions.
   */
  [[nodiscard]] RuntimeTidDataDosErrnoView* RuntimeGetPtdNoExit()
  {
    const unsigned long lastError = ::GetLastError();

    RuntimeTidDataDosErrnoView* threadData = nullptr;
    if (RuntimeFlsGetValueFn const flsGetValue = __set_flsgetvalue(); flsGetValue != nullptr) {
      threadData = static_cast<RuntimeTidDataDosErrnoView*>(flsGetValue(__flsindex));
    }

    if (threadData == nullptr) {
      threadData = static_cast<RuntimeTidDataDosErrnoView*>(_calloc_crt(1u, 0x214u));
      if (threadData != nullptr) {
        using RuntimeFlsSetValueFn = int(__stdcall*)(unsigned long flsIndex, void* value);
        auto* const flsSetValueRaw = _decode_pointer(gpFlsSetValue);
        auto* const flsSetValue = reinterpret_cast<RuntimeFlsSetValueFn>(flsSetValueRaw);
        if (flsSetValue != nullptr && flsSetValue(__flsindex, threadData) != 0) {
          __initptd(threadData, nullptr);
          threadData->mThreadHandle = -1;
          threadData->mThreadId = ::GetCurrentThreadId();
        } else {
          _free_crt(threadData);
          threadData = nullptr;
        }
      }
    }

    ::SetLastError(lastError);
    return threadData;
  }

  /**
   * Address: 0x00A833BF (FUN_00A833BF, doserrno)
   *
   * What it does:
   * Returns one pointer to the current thread's DOS errno lane (`_doserrno`),
   * or a process fallback lane when thread-local storage is unavailable.
   */
  [[nodiscard]] unsigned long* RuntimeDosErrno()
  {
    if (RuntimeTidDataDosErrnoView* const threadData = RuntimeGetPtdNoExit(); threadData != nullptr) {
      return &threadData->mDosErrno;
    }

    return &gRuntimeDosErrnoFallback;
  }

  /**
   * Address: 0x00A82B1A (FUN_00A82B1A, _validdrive)
   *
   * What it does:
   * Validates one 1-based DOS drive index by probing `X:\\` root type and
   * returns true only for mounted/usable drive types.
   */
  bool RuntimeValidDrive(const int drive)
  {
    if (drive == 0) {
      return true;
    }

    char driveIndicator[4]{};
    driveIndicator[0] = static_cast<char>(drive + '@');
    driveIndicator[1] = ':';
    driveIndicator[2] = '\\';
    driveIndicator[3] = '\0';

    const UINT driveType = ::GetDriveTypeA(driveIndicator);
    return driveType != DRIVE_UNKNOWN && driveType != DRIVE_NO_ROOT_DIR;
  }

  /**
   * Address: 0x00A82B51 (FUN_00A82B51, _getdcwd_nolock)
   *
   * What it does:
   * Resolves one drive working-directory path without taking outer CRT cwd
   * locks, supporting caller-provided buffers or internal allocation when
   * buffer is null.
   */
  char* RuntimeGetdcwdNoLock(int drive, char* buffer, int bufferLength)
  {
    if (drive != 0) {
      if (!RuntimeValidDrive(drive)) {
        *RuntimeDosErrno() = ERROR_INVALID_DRIVE;
        *_errno() = EACCES;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        return nullptr;
      }
    } else {
      drive = _getdrive();
    }

    if (buffer != nullptr) {
      if (bufferLength <= 0) {
        *_errno() = EINVAL;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        return nullptr;
      }
      buffer[0] = '\0';
    } else {
      bufferLength = 0;
    }

    char drivePathProbe[5]{};
    if (drive != 0) {
      drivePathProbe[0] = static_cast<char>(drive + '@');
      std::strcpy(&drivePathProbe[1], ":.");
    } else {
      std::strcpy(drivePathProbe, ".");
    }

    char* filePart = nullptr;
    DWORD fullPathLength = ::GetFullPathNameA(drivePathProbe, bufferLength, buffer, &filePart);
    if (fullPathLength == 0) {
      _dosmaperr(::GetLastError());
      return nullptr;
    }

    if (buffer == nullptr) {
      if (fullPathLength > static_cast<DWORD>(bufferLength)) {
        bufferLength = static_cast<int>(fullPathLength);
      }

      buffer = static_cast<char*>(std::calloc(static_cast<std::size_t>(bufferLength), 1u));
      if (buffer == nullptr) {
        *_errno() = ENOMEM;
        *RuntimeDosErrno() = ERROR_NOT_ENOUGH_MEMORY;
        return nullptr;
      }

      fullPathLength = ::GetFullPathNameA(drivePathProbe, bufferLength, buffer, &filePart);
      if (fullPathLength != 0 && fullPathLength < static_cast<DWORD>(bufferLength)) {
        return buffer;
      }

      _dosmaperr(::GetLastError());
      return nullptr;
    }

  if (fullPathLength < static_cast<DWORD>(bufferLength)) {
      return buffer;
    }

    *_errno() = ERANGE;
    buffer[0] = '\0';
    return nullptr;
  }

  /**
   * Address: 0x00A82C86 (FUN_00A82C86, _getdcwd_0)
   *
   * What it does:
   * Locks the CRT environment lane, resolves the current drive working
   * directory through the no-lock helper, then unlocks before returning the
   * caller buffer/result pointer.
   */
  char* __cdecl _getdcwd_0(char* const buffer, const int bufferLength)
  {
    RuntimeLockGuard lockGuard(kRuntimeEnvironmentLock);
    return RuntimeGetdcwdNoLock(0, buffer, bufferLength);
  }

  /**
   * Address: 0x00A89C90 (FUN_00A89C90, __alloca_probe_16)
   *
   * What it does:
   * Aligns the requested dynamic-stack allocation lane to 16 bytes in `eax`
   * and tail-jumps to the CRT stack-probe helper.
   */
  extern "C" __declspec(naked) void __cdecl __alloca_probe_16()
  {
    __asm
    {
      push ecx
      lea ecx, [esp + 8]
      sub ecx, eax
      and ecx, 0Fh
      add eax, ecx
      sbb ecx, ecx
      or eax, ecx
      pop ecx
      jmp __alloca_probe
    }
  }

  /**
   * Address: 0x00A8FC30 (FUN_00A8FC30, _vsnwprintf)
   *
   * What it does:
   * Forwards wide varargs formatting to `_vsnwprintf_l` with the locale lane
   * explicitly set to null.
   */
  int __cdecl _vsnwprintf(
    wchar_t* const buffer,
    const std::size_t bufferCount,
    const wchar_t* const format,
    va_list argList
  )
  {
    return _vsnwprintf_l(buffer, bufferCount, format, nullptr, argList);
  }

  /**
   * Address: 0x00A9566E (FUN_00A9566E, _strcpy_s)
   *
   * What it does:
   * Copies one C-string into caller buffer with CRT invalid-parameter/error
   * semantics (`EINVAL` and `ERANGE` lanes).
   */
  errno_t RuntimeStrcpyS(char* const destination, const std::size_t sizeInBytes, const char* const source)
  {
    if (destination == nullptr || sizeInBytes == 0u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    if (source == nullptr) {
      destination[0] = '\0';
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::size_t remainingBytes = sizeInBytes;
    char* destinationCursor = destination;
    const char* sourceCursor = source;
    while (remainingBytes != 0u) {
      const char value = *sourceCursor;
      *destinationCursor = value;
      ++destinationCursor;
      ++sourceCursor;

      if (value == '\0') {
        return 0;
      }

      --remainingBytes;
    }

    destination[0] = '\0';
    *_errno() = ERANGE;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return ERANGE;
  }

  /**
   * Address: 0x00AAC747 (FUN_00AAC747, wstrcpy)
   *
   * What it does:
   * Copies one wide string into caller storage with CRT invalid-parameter
   * semantics (`EINVAL`/`ERANGE`) and destination reset on overflow.
   */
  extern "C" errno_t wstrcpy(wchar_t* const destination, const int length, const wchar_t* const source)
  {
    if (destination == nullptr || length == 0) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    if (source == nullptr) {
      destination[0] = L'\0';
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    int remaining = length;
    wchar_t* destinationCursor = destination;
    const wchar_t* sourceCursor = source;
    while (remaining != 0) {
      const wchar_t value = *sourceCursor;
      *destinationCursor = value;
      ++destinationCursor;
      ++sourceCursor;
      if (value == L'\0') {
        return 0;
      }
      --remaining;
    }

    destination[0] = L'\0';
    *_errno() = ERANGE;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return ERANGE;
  }

  /**
   * Address: 0x00A956D3 (FUN_00A956D3, strcat_s)
   *
   * What it does:
   * Appends one C-string into a caller buffer with CRT invalid-parameter and
   * errno semantics for invalid arguments and overflow.
   */
  errno_t RuntimeStrcatS(char* const destination, const std::size_t sizeInBytes, const char* const source)
  {
    if (destination == nullptr || sizeInBytes == 0u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::size_t remainingBytes = sizeInBytes;
    char* destinationCursor = destination;
    while (remainingBytes != 0u && *destinationCursor != '\0') {
      ++destinationCursor;
      --remainingBytes;
    }

    if (remainingBytes == 0u) {
      destination[0] = '\0';
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    if (source == nullptr) {
      destination[0] = '\0';
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    const char* sourceCursor = source;
    while (remainingBytes != 0u) {
      const char value = *sourceCursor;
      *destinationCursor = value;
      ++destinationCursor;
      ++sourceCursor;

      if (value == '\0') {
        return 0;
      }

      --remainingBytes;
    }

    destination[0] = '\0';
    *_errno() = ERANGE;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return ERANGE;
  }

  /**
   * Address: 0x00A82227 (FUN_00A82227, std::exception copy-ctor import body)
   * Mangled: __imp_??0exception@std@@QAE@ABV01@@Z
   *
   * What it does:
   * Clones one `std::exception` payload lane, duplicating message storage when
   * the source owns its `_what` buffer.
   */
  std::exception* RuntimeStdExceptionCopyConstruct(
    std::exception* const destination,
    const std::exception* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    struct StdExceptionRuntimeView
    {
      void* mVtable;
      const char* mWhat;
      int mDoFree;
    };

    new (destination) std::exception();

    auto* const destinationView = reinterpret_cast<StdExceptionRuntimeView*>(destination);
    const auto* const sourceView = reinterpret_cast<const StdExceptionRuntimeView*>(source);

    destinationView->mDoFree = sourceView->mDoFree;
    const char* const sourceMessage = sourceView->mWhat;
    if (sourceView->mDoFree == 0) {
      destinationView->mWhat = sourceMessage;
      return destination;
    }

    if (sourceMessage == nullptr) {
      destinationView->mWhat = nullptr;
      return destination;
    }

    const std::size_t requiredBytes = std::strlen(sourceMessage) + 1u;
    char* const copiedMessage = static_cast<char*>(std::malloc(requiredBytes));
    destinationView->mWhat = copiedMessage;
    if (copiedMessage != nullptr) {
      (void)RuntimeStrcpyS(copiedMessage, requiredBytes, sourceMessage);
    }

    return destination;
  }

  /**
   * Address: 0x00A8C63A (FUN_00A8C63A, __free_locale)
   *
   * What it does:
   * Releases one CRT locale bundle by decrementing mbc/locinfo refcounts,
   * freeing non-initial blocks, and poisoning/freeing the locale handle.
   */
  void RuntimeFreeLocale(RuntimeLocaleHandle* const locale)
  {
    if (locale == nullptr) {
      return;
    }

    RuntimeThreadMbcInfo* const mbcInfo = locale->mbcinfo;
    if (mbcInfo != nullptr) {
      if (::InterlockedDecrement(&mbcInfo->refcount) == 0 && mbcInfo != &__initialmbcinfo) {
        ::_free_crt(mbcInfo);
      }
    }

    RuntimeThreadLocInfo* const locInfo = locale->locinfo;
    if (locInfo != nullptr) {
      RuntimeLockGuard setLocaleLock(kRuntimeSetLocaleLock);
      ::__removelocaleref(locInfo);
      if (locInfo->refcount == 0 && locInfo != &__initiallocinfo) {
        ::__freetlocinfo(locInfo);
      }
    }

    constexpr std::uintptr_t kFreedPointerPoison = 0xBAADF00Du;
    locale->locinfo = reinterpret_cast<RuntimeThreadLocInfo*>(kFreedPointerPoison);
    locale->mbcinfo = reinterpret_cast<RuntimeThreadMbcInfo*>(kFreedPointerPoison);
    ::_free_crt(locale);
  }

  /**
   * Address: 0x00A8C6D0 (FUN_00A8C6D0, j___free_locale)
   *
   * What it does:
   * Thunk wrapper that forwards locale-handle teardown to `RuntimeFreeLocale`.
   */
  void RuntimeFreeLocaleThunk(RuntimeLocaleHandle* const locale)
  {
    RuntimeFreeLocale(locale);
  }

  /**
   * Address: 0x00A8C7A3 (FUN_00A8C7A3, _lc_strtolc)
   *
   * What it does:
   * Parses one locale descriptor string into fixed 3-lane CRT locale parts
   * buffer (`language`, `country`, `codepage`) with legacy separator rules.
   */
  int RuntimeParseLocaleCompositeName(char* const outLocaleParts, const char* const localeText)
  {
    std::memset(outLocaleParts, 0, 144);

    const char* cursor = localeText;
    if (*cursor == '\0') {
      return 0;
    }

    if (cursor[0] == '.' && cursor[1] != '\0') {
      if (strncpy_s(outLocaleParts + 128, 16, cursor + 1, 15) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      outLocaleParts[143] = '\0';
      return 0;
    }

    int tokenIndex = 0;
    std::size_t tokenLength = std::strcspn(cursor, "_.,");
    while (tokenLength != 0u) {
      const char separator = cursor[tokenLength];
      const char* const nextToken = cursor + tokenLength + 1;

      errno_t copyResult = 0;
      if (tokenIndex == 0) {
        if (tokenLength >= 64u || separator == '.') {
          return -1;
        }
        copyResult = strncpy_s(outLocaleParts, 64, cursor, tokenLength);
      } else if (tokenIndex == 1) {
        if (tokenLength >= 64u || separator == '_') {
          return -1;
        }
        copyResult = strncpy_s(outLocaleParts + 64, 64, cursor, tokenLength);
      } else if (tokenIndex == 2) {
        if (tokenLength >= 16u || (separator != '\0' && separator != ',')) {
          return -1;
        }
        copyResult = strncpy_s(outLocaleParts + 128, 16, cursor, tokenLength);
      } else {
        return -1;
      }

      if (copyResult != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }

      if (separator == ',' || separator == '\0') {
        return 0;
      }

      ++tokenIndex;
      cursor = nextToken;
      tokenLength = std::strcspn(cursor, "_.,");
    }

    return -1;
  }

  /**
   * Address: 0x00ABF4DF (FUN_00ABF4DF, std::locale::_Locimp::_Locimp)
   * Mangled: ??0_Locimp@locale@std@@AAE@_N@Z
   *
   * What it does:
   * Initializes one locale implementation lane with default facet/category
   * state and seeds the locale name to `"*"`.
   */
  RuntimeLocaleLocimpView* RuntimeLocaleLocimpConstruct(RuntimeLocaleLocimpView* const localeImpl, const bool isParent)
  {
    localeImpl->refs = 1;
    localeImpl->facetVector = nullptr;
    localeImpl->facetCount = 0;
    localeImpl->categoryMask = 0;
    localeImpl->isParent = isParent ? 1u : 0u;
    new (&localeImpl->name) std::string("*");
    return localeImpl;
  }

  /**
   * Address: 0x00ABF013 (FUN_00ABF013, std::_String_base::_Xlen)
   * Mangled: ?_Xlen@_String_base@std@@SAXXZ
   *
   * What it does:
   * Throws one `std::length_error` with the CRT fixed diagnostic text
   * `"string too long"`.
   */
  [[noreturn]] void RuntimeThrowStringTooLong()
  {
    throw std::length_error("string too long");
  }

  /**
   * Address: 0x00ABF052 (FUN_00ABF052, std::_String_base::_Xran)
   *
   * What it does:
   * Throws one `std::out_of_range` with the CRT fixed diagnostic text
   * `"invalid string position"`.
   */
  [[noreturn]] void RuntimeThrowInvalidStringPosition()
  {
    throw std::out_of_range("invalid string position");
  }

  /**
   * Address: 0x00ABF091 (FUN_00ABF091)
   *
   * What it does:
   * Throws one `std::invalid_argument` instance with the CRT fixed diagnostic
   * text `"invalid string argument"`.
   */
  [[noreturn]] void RuntimeThrowInvalidStringArgument()
  {
    throw std::invalid_argument("invalid string argument");
  }

  struct RuntimeIosFnNode
  {
    RuntimeIosFnNode* next = nullptr;               // +0x00
    std::int32_t index = 0;                         // +0x04
    void(__cdecl* callback)(int, void*, int) = nullptr; // +0x08
  };
  static_assert(sizeof(RuntimeIosFnNode) == 0xC, "RuntimeIosFnNode size must be 0xC");

  struct RuntimeIosArrayNode
  {
    RuntimeIosArrayNode* next = nullptr; // +0x00
  };
  static_assert(sizeof(RuntimeIosArrayNode) == 0x4, "RuntimeIosArrayNode size must be 0x4");

  struct RuntimeIosBaseView
  {
    void* vtable = nullptr;                    // +0x00
    std::int32_t stdStreamSlot = 0;            // +0x04
    std::uint8_t reserved08[0x14]{};           // +0x08
    RuntimeIosArrayNode* arrayHead = nullptr;  // +0x1C
    RuntimeIosFnNode* callbackHead = nullptr;  // +0x20
    std::locale* localePtr = nullptr;          // +0x24
  };
  static_assert(offsetof(RuntimeIosBaseView, stdStreamSlot) == 0x4, "RuntimeIosBaseView::stdStreamSlot offset must be 0x4");
  static_assert(offsetof(RuntimeIosBaseView, arrayHead) == 0x1C, "RuntimeIosBaseView::arrayHead offset must be 0x1C");
  static_assert(offsetof(RuntimeIosBaseView, callbackHead) == 0x20, "RuntimeIosBaseView::callbackHead offset must be 0x20");
  static_assert(offsetof(RuntimeIosBaseView, localePtr) == 0x24, "RuntimeIosBaseView::localePtr offset must be 0x24");
  static_assert(sizeof(RuntimeIosBaseView) == 0x28, "RuntimeIosBaseView size must be 0x28");

  /**
   * Address: 0x00ABF0D0 (FUN_00ABF0D0, std::ios_base::_Callfns)
   *
   * What it does:
   * Walks one `ios_base` callback-node chain and invokes each callback with
   * `(event, ios_base, index)` parameters.
   */
  void RuntimeIosBaseCallFns(void* const iosBaseStorage, const int event)
  {
    auto* const iosBase = static_cast<RuntimeIosBaseView*>(iosBaseStorage);
    for (RuntimeIosFnNode* node = iosBase->callbackHead; node != nullptr; node = node->next) {
      node->callback(event, iosBaseStorage, node->index);
    }
  }

  /**
   * Address: 0x00ABF0F2 (FUN_00ABF0F2, std::ios_base::_Tidy)
   *
   * What it does:
   * Emits `erase_event` callbacks, then deletes linked ios-array and callback
   * nodes, clearing both head pointers.
   */
  void RuntimeIosBaseTidy(void* const iosBaseStorage)
  {
    auto* const iosBase = static_cast<RuntimeIosBaseView*>(iosBaseStorage);
    RuntimeIosBaseCallFns(iosBaseStorage, 0);

    RuntimeIosArrayNode* arrayNode = iosBase->arrayHead;
    while (arrayNode != nullptr) {
      RuntimeIosArrayNode* const nextNode = arrayNode->next;
      ::operator delete(arrayNode);
      arrayNode = nextNode;
    }

    iosBase->arrayHead = nullptr;

    RuntimeIosFnNode* callbackNode = iosBase->callbackHead;
    while (callbackNode != nullptr) {
      RuntimeIosFnNode* const nextNode = callbackNode->next;
      ::operator delete(callbackNode);
      callbackNode = nextNode;
    }

    iosBase->callbackHead = nullptr;
  }

  /**
   * Address: 0x00ABF150 (FUN_00ABF150, std::ios_base::_Addstd)
   *
   * What it does:
   * Registers one `ios_base` lane in CRT std-stream slot tables under
   * `_Lockit(2)` and increments the selected slot open-count byte.
   */
  void RuntimeIosBaseAddStd(void* const iosBaseStorage)
  {
    auto* const iosBase = static_cast<RuntimeIosBaseView*>(iosBaseStorage);
    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 2);

    iosBase->stdStreamSlot = 1;
    while (true) {
      void* const current = gRuntimeIosStdStreams[iosBase->stdStreamSlot];
      if (current == nullptr || current == iosBaseStorage) {
        break;
      }

      ++iosBase->stdStreamSlot;
      if (iosBase->stdStreamSlot >= 8) {
        break;
      }
    }

    gRuntimeIosStdStreams[iosBase->stdStreamSlot] = iosBaseStorage;
    ++gRuntimeIosStdOpenCounts[iosBase->stdStreamSlot];

    RuntimeLockitDestroy(&lockit);
  }

  /**
   * Address: 0x00ABF1A0 (FUN_00ABF1A0, std::ios_base::_Ios_base_dtor)
   * Mangled: ?_Ios_base_dtor@ios_base@std@@CAXPAV12@@Z
   *
   * What it does:
   * Runs one `ios_base` teardown lane: decrements std-stream open-count for
   * registered standard slots, calls `_Tidy` when this is the last opener (or
   * when no std slot is attached), then destroys/deletes the owned locale
   * object when present.
   */
  void RuntimeIosBaseDtor(void* const iosBaseStorage)
  {
    auto* const iosBase = static_cast<RuntimeIosBaseView*>(iosBaseStorage);

    const int stdStreamSlot = iosBase->stdStreamSlot;
    if (stdStreamSlot == 0 || --gRuntimeIosStdOpenCounts[stdStreamSlot] <= 0) {
      RuntimeIosBaseTidy(iosBaseStorage);
      if (std::locale* const locale = iosBase->localePtr; locale != nullptr) {
        locale->~locale();
        ::operator delete(locale);
      }
    }
  }

  /**
   * Address: 0x00ABF138 (FUN_00ABF138)
   *
   * What it does:
   * Returns one static storage-slot address used by CRT startup lane.
   */
  void* RuntimeGetStaticStorageSlotA()
  {
    return &gRuntimeStaticStorageSlotA;
  }

  /**
   * Address: 0x00ABF13E (FUN_00ABF13E)
   *
   * What it does:
   * Returns one static integer-storage address used by CRT startup lane.
   */
  std::int32_t* RuntimeGetStaticStorageSlotB()
  {
    return &gRuntimeStaticStorageSlotB;
  }

  /**
   * Address: 0x00ABF144 (FUN_00ABF144)
   *
   * What it does:
   * Returns one static storage-slot address used by CRT startup lane.
   */
  void* RuntimeGetStaticStorageSlotC()
  {
    return &gRuntimeStaticStorageSlotC;
  }

  /**
   * Address: 0x00ABF14A (FUN_00ABF14A)
   *
   * What it does:
   * Returns one static storage-slot address used by CRT startup lane.
   */
  void* RuntimeGetStaticStorageSlotD()
  {
    return &gRuntimeStaticStorageSlotD;
  }

  /**
   * Address: 0x00ABF61B (FUN_00ABF61B, std::_Locinfo::_Locinfo_ctor)
   *
   * What it does:
   * Captures current `LC_ALL` locale name into `_Locinfo::oldlocname`, then
   * applies optional incoming locale text and stores resulting name (or `"*"`)
   * into `_Locinfo::newlocname`.
   */
  void RuntimeLocinfoConstruct(void* const locinfoStorage, const char* const requestedLocaleText)
  {
    struct RuntimeLocinfoView
    {
      std::uint8_t reserved00[0x3C];
    };
    constexpr std::size_t kRuntimeLocinfoOldNameOffset = 0x3C;
    constexpr std::size_t kRuntimeLocinfoNewNameOffset = 0x58;
    static_assert(sizeof(RuntimeLocinfoView) == kRuntimeLocinfoOldNameOffset, "RuntimeLocinfoView size must be 0x3C");

    auto* const locinfo = reinterpret_cast<std::uint8_t*>(static_cast<RuntimeLocinfoView*>(locinfoStorage));
    auto& oldLocaleName = *reinterpret_cast<std::string*>(locinfo + kRuntimeLocinfoOldNameOffset);
    auto& newLocaleName = *reinterpret_cast<std::string*>(locinfo + kRuntimeLocinfoNewNameOffset);

    const char* previousLocaleName = std::setlocale(LC_ALL, nullptr);
    if (previousLocaleName == nullptr) {
      previousLocaleName = "";
    }
    oldLocaleName.assign(previousLocaleName);

    const char* appliedLocaleName = "*";
    if (requestedLocaleText != nullptr) {
      const char* const setLocaleResult = std::setlocale(LC_ALL, requestedLocaleText);
      if (setLocaleResult != nullptr) {
        appliedLocaleName = setLocaleResult;
      }
    }

    newLocaleName.assign(appliedLocaleName);
  }

  /**
   * Address: 0x00ABF4BC (FUN_00ABF4BC, std::_Locinfo::_Locinfo_dtor)
   *
   * What it does:
   * Restores `LC_ALL` to the saved old-locale string lane when that saved
   * locale text is non-empty.
   */
  const char* RuntimeLocinfoDtor(const char* const locinfoStorage)
  {
    struct RuntimeLegacyStringView
    {
      union
      {
        const char* heapPtr;
        char inlineBuffer[16];
      } storage{};
      std::uint32_t size = 0;
      std::uint32_t capacity = 0;
    };
    static_assert(sizeof(RuntimeLegacyStringView) == 0x18, "RuntimeLegacyStringView size must be 0x18");

    struct RuntimeLocinfoOldLocaleView
    {
      std::uint8_t reserved00[0x40];
      RuntimeLegacyStringView oldLocaleName;
    };
    static_assert(
      offsetof(RuntimeLocinfoOldLocaleView, oldLocaleName) == 0x40,
      "RuntimeLocinfoOldLocaleView::oldLocaleName offset must be 0x40"
    );

    const auto* const locinfo = reinterpret_cast<const RuntimeLocinfoOldLocaleView*>(locinfoStorage);
    if (locinfo->oldLocaleName.size > 0u) {
      const char* const localeText = (locinfo->oldLocaleName.capacity < 0x10u)
        ? locinfo->oldLocaleName.storage.inlineBuffer
        : locinfo->oldLocaleName.storage.heapPtr;
      return std::setlocale(LC_ALL, localeText);
    }

    return locinfoStorage;
  }

  /**
   * Address: 0x00ABF2F2 (FUN_00ABF2F2)
   *
   * What it does:
   * Returns incoming `this` pointer unchanged; ignores one trailing argument.
   */
  void* RuntimeReturnSelfIgnoringInt(void* const self, int /*unused*/)
  {
    return self;
  }

  /**
   * Address: 0x00ABF2F7 (FUN_00ABF2F7)
   *
   * What it does:
   * Writes one 32-bit value into `this[0]` and returns `this`.
   */
  std::int32_t* RuntimeAssignFirstInt(std::int32_t* const self, const std::int32_t value)
  {
    self[0] = value;
    return self;
  }

  /**
   * Address: 0x00ABF302 (FUN_00ABF302)
   *
   * What it does:
   * Writes two 32-bit values into `this[0..1]` and returns `this`.
   */
  std::int32_t* RuntimeAssignFirstTwoInts(
    std::int32_t* const self,
    const std::int32_t firstValue,
    const std::int32_t secondValue
  )
  {
    self[0] = firstValue;
    self[1] = secondValue;
    return self;
  }

  /**
   * Address: 0x00AA65B1 (FUN_00AA65B1, ProcessCodePage)
   *
   * What it does:
   * Resolves one CRT locale codepage token (`ACP`, `OCP`, or numeric) to an
   * integer codepage using the locale-country lane from `setloc_struct`.
   */
  int RuntimeProcessCodePage(char* const codePageText, RuntimeSetLocLocaleView* const locale)
  {
    char* codePageValue = codePageText;
    char localeCodePage[8] = {};

    if (codePageText == nullptr || codePageText[0] == '\0' || std::strcmp(codePageText, "ACP") == 0) {
      const int queryResult =
        ::GetLocaleInfoA(locale->lcidCountry, LOCALE_IDEFAULTANSICODEPAGE, localeCodePage, sizeof(localeCodePage));
      if (queryResult == 0) {
        return queryResult;
      }
      codePageValue = localeCodePage;
      return static_cast<int>(std::atol(codePageValue));
    }

    if (std::strcmp(codePageText, "OCP") == 0) {
      const int queryResult =
        ::GetLocaleInfoA(locale->lcidCountry, LOCALE_IDEFAULTCODEPAGE, localeCodePage, sizeof(localeCodePage));
      if (queryResult == 0) {
        return queryResult;
      }
      codePageValue = localeCodePage;
    }

    return static_cast<int>(std::atol(codePageValue));
  }

  /**
   * Address: 0x00AA6646 (FUN_00AA6646, LcidFromHexString)
   *
   * What it does:
   * Parses one null-terminated hexadecimal LCID token by folding ASCII hex
   * digits into a 16-based accumulator.
   */
  int RuntimeLcidFromHexString(const char* const hexText)
  {
    int value = 0;
    for (const char* cursor = hexText;;) {
      const unsigned char digit = static_cast<unsigned char>(*cursor);
      if (digit == 0u) {
        break;
      }

      ++cursor;
      unsigned char normalizedDigit = digit;
      if (normalizedDigit >= static_cast<unsigned char>('a') && normalizedDigit <= static_cast<unsigned char>('f')) {
        normalizedDigit = static_cast<unsigned char>(normalizedDigit - 39u);
      } else if (normalizedDigit >= static_cast<unsigned char>('A') && normalizedDigit <= static_cast<unsigned char>('F')) {
        normalizedDigit = static_cast<unsigned char>(normalizedDigit - 7u);
      }

      value = (value << 4) + static_cast<int>(normalizedDigit - static_cast<unsigned char>('0'));
    }
    return value;
  }

  /**
   * Address: 0x00AA6678 (FUN_00AA6678, GetPrimaryLen)
   *
   * What it does:
   * Counts the leading alphabetic run of one locale token until a non-letter
   * byte ends the prefix.
   */
  int RuntimeGetPrimaryLen(const char* const text)
  {
    int length = 0;
    for (const char* cursor = text;; ++length) {
      const unsigned char character = static_cast<unsigned char>(*cursor++);
      if (!((character >= static_cast<unsigned char>('A') && character <= static_cast<unsigned char>('Z')) ||
            (character >= static_cast<unsigned char>('a') && character <= static_cast<unsigned char>('z')))) {
        break;
      }
    }
    return length;
  }

  extern "C" const std::uint16_t __rglangidNotDefault[10];

  /**
   * Address: 0x00AA6628 (FUN_00AA6628, TestDefaultCountry)
   *
   * What it does:
   * Returns false for locale IDs that are explicitly listed as non-default
   * country/language matches and true otherwise.
   */
  int RuntimeTestDefaultCountry(const std::uint16_t languageId)
  {
    for (std::size_t index = 0; index < 10u; ++index) {
      if (languageId == __rglangidNotDefault[index]) {
        return 0;
      }
    }
    return 1;
  }

  /**
   * Address: 0x00AA6729 (FUN_00AA6729, TestDefaultLanguage)
   *
   * What it does:
   * Validates a locale against the current thread locale-name lane and only
   * accepts the exact primary-language match when the caller requests it.
   */
  BOOL RuntimeTestDefaultLanguage(
    RuntimeSetLocLocaleView* const setlocData,
    const LCID localeId,
    const int requireExactPrimaryMatch
  )
  {
    char localeName[120]{};
    if (!::GetLocaleInfoA((localeId & 0x3FFu) | 0x400u, LOCALE_ILANGUAGE, localeName, 120)) {
      return FALSE;
    }

    if (localeId == RuntimeLcidFromHexString(localeName)) {
      return TRUE;
    }

    if (!requireExactPrimaryMatch) {
      return TRUE;
    }

    const char* const languageName = setlocData->pchLanguage;
    const int primaryLength = RuntimeGetPrimaryLen(languageName);
    if (primaryLength != static_cast<int>(std::strlen(languageName))) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Address: 0x00AA6693 (FUN_00AA6693, CountryEnumProc)
   *
   * What it does:
   * Enumerates locale country names and latches the first matching country
   * LCID into the thread's locale-selection lane.
   */
  BOOL __stdcall RuntimeCountryEnumProc(LPSTR localeText)
  {
    auto* const setlocData = &__getptd()->setlocData;
    const LCID localeId = static_cast<LCID>(RuntimeLcidFromHexString(localeText));
    char localeName[120]{};

    if (!::GetLocaleInfoA(
          localeId,
          setlocData->bAbbrevCountry != 0 ? LOCALE_SABBREVCTRYNAME : LOCALE_SENGCOUNTRY,
          localeName,
          120)) {
      setlocData->iLcidState = 0;
      return TRUE;
    }

    if (_stricmp(setlocData->pchCountry, localeName) == 0) {
      if (RuntimeTestDefaultCountry(static_cast<std::uint16_t>(localeId)) != 0) {
        setlocData->iLcidState |= 4;
        setlocData->lcidCountry = localeId;
        setlocData->lcidLanguage = localeId;
      }
    }

    return (setlocData->iLcidState & 4) == 0;
  }

  /**
   * Address: 0x00AA696B (FUN_00AA696B, LanguageEnumProc)
   *
   * What it does:
   * Enumerates locale language names and latches the first matching language
   * LCID into the thread's locale-selection lane.
   */
  BOOL __stdcall RuntimeLanguageEnumProc(LPSTR localeText)
  {
    auto* const setlocData = &__getptd()->setlocData;
    const LCID localeId = static_cast<LCID>(RuntimeLcidFromHexString(localeText));
    char localeName[120]{};

    if (!::GetLocaleInfoA(
          localeId,
          setlocData->bAbbrevLanguage != 0 ? LOCALE_SABBREVLANGNAME : LOCALE_SENGLANGUAGE,
          localeName,
          120)) {
      setlocData->iLcidState = 0;
      return TRUE;
    }

    if (_stricmp(setlocData->pchLanguage, localeName) == 0) {
      if (setlocData->bAbbrevLanguage != 0) {
        setlocData->iLcidState |= 4;
        setlocData->lcidLanguage = localeId;
        setlocData->lcidCountry = localeId;
        return (setlocData->iLcidState & 4) == 0;
      }

      if (RuntimeTestDefaultLanguage(setlocData, localeId, 1) != 0) {
        setlocData->iLcidState |= 4;
        setlocData->lcidLanguage = localeId;
        setlocData->lcidCountry = localeId;
      }
      return (setlocData->iLcidState & 4) == 0;
    }

    if (setlocData->bAbbrevLanguage != 0 || setlocData->iPrimaryLen == 0 ||
        _stricmp(setlocData->pchLanguage, localeName) != 0) {
      return (setlocData->iLcidState & 4) == 0;
    }

    if (RuntimeTestDefaultLanguage(setlocData, localeId, 0) != 0) {
      setlocData->iLcidState |= 4;
      setlocData->lcidLanguage = localeId;
      setlocData->lcidCountry = localeId;
    }

    return (setlocData->iLcidState & 4) == 0;
  }

  struct RuntimeFacetRefView
  {
    void* vtable = nullptr;     // +0x00
    std::int32_t refs = 0;      // +0x04
  };
  static_assert(sizeof(RuntimeFacetRefView) == 0x8, "RuntimeFacetRefView size must be 0x8");

  struct RuntimeFacetDeleteDispatchBase
  {
    virtual ~RuntimeFacetDeleteDispatchBase() = default;
  };

  void RuntimeDestroyFacetPolymorphic(std::locale::facet* const facet)
  {
    auto* const dispatchBase = reinterpret_cast<RuntimeFacetDeleteDispatchBase*>(facet);
    delete dispatchBase;
  }

  [[nodiscard]] std::locale::facet* RuntimeLocaleFacetDecref(std::locale::facet* const facet)
  {
    auto* const view = reinterpret_cast<RuntimeFacetRefView*>(facet);
    --view->refs;
    if (view->refs == 0) {
      return facet;
    }
    return nullptr;
  }

  /**
   * Address: 0x00ABF314 (FUN_00ABF314)
   *
   * What it does:
   * Decrements the facet reference count stored in the second pointer lane of a
   * two-pointer record and deletes the facet when it reaches zero.
   */
  std::locale::facet* RuntimeReleaseSecondFacetInPair(void* const pairStorage)
  {
    auto** const pair = static_cast<std::locale::facet**>(pairStorage);
    std::locale::facet* const facet = pair[1];
    if (facet == nullptr) {
      return nullptr;
    }

    std::locale::facet* const releasedFacet = RuntimeLocaleFacetDecref(facet);
    if (releasedFacet != nullptr) {
      RuntimeDestroyFacetPolymorphic(releasedFacet);
      return releasedFacet;
    }
    return nullptr;
  }

  /**
   * Address: 0x00ABF440 (FUN_00ABF440, __Fac_tidy)
   *
   * What it does:
   * Under `_Lockit(0)`, drains the global facet registration list, releases
   * each facet lane, and deletes each list node.
   */
  void RuntimeFacetTidy()
  {
    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);

    while (gRuntimeFacetHead != nullptr) {
      RuntimeFacetNode* const node = gRuntimeFacetHead;
      gRuntimeFacetHead = node->next;
      RuntimeReleaseSecondFacetInPair(node);
      ::operator delete(node);
    }

    RuntimeLockitDestroy(&lockit);
  }

  /**
   * Address: 0x00ABF483 (FUN_00ABF483, std::locale::facet::facet_Register)
   *
   * What it does:
   * Registers one facet pointer in the global facet list and ensures list tidy
   * is scheduled at process-exit.
   */
  void RuntimeRegisterFacet(std::locale::facet* const facet)
  {
    if (gRuntimeFacetHead == nullptr) {
      std::atexit(RuntimeFacetTidy);
    }

    auto* node = static_cast<RuntimeFacetNode*>(::operator new(sizeof(RuntimeFacetNode), std::nothrow));
    if (node != nullptr) {
      node->next = gRuntimeFacetHead;
      node->facet = facet;
    } else {
      node = nullptr;
    }

    gRuntimeFacetHead = node;
  }

  /**
   * Address: 0x00ABF345 (FUN_00ABF345)
   *
   * What it does:
   * Decrements one facet pointer lane and deletes the facet when the reference
   * count reaches zero.
   */
  std::locale::facet* RuntimeReleaseFacetSlot(std::locale::facet** const facetSlot)
  {
    if (facetSlot == nullptr) {
      return nullptr;
    }

    std::locale::facet* const facet = *facetSlot;
    if (facet == nullptr) {
      return reinterpret_cast<std::locale::facet*>(facetSlot);
    }

    std::locale::facet* const releasedFacet = RuntimeLocaleFacetDecref(facet);
    if (releasedFacet != nullptr) {
      RuntimeDestroyFacetPolymorphic(releasedFacet);
      return releasedFacet;
    }
    return nullptr;
  }

  /**
   * Address: 0x00ABF361 (FUN_00ABF361, _tidy_global)
   *
   * What it does:
   * Under `_Lockit(0)`, releases one global locale facet lane and clears the
   * process-global locale pointer.
   */
  void RuntimeTidyGlobalLocale()
  {
    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);
    RuntimeReleaseFacetSlot(reinterpret_cast<std::locale::facet**>(&gRuntimeGlobalLocale));
    gRuntimeGlobalLocale = nullptr;
    RuntimeLockitDestroy(&lockit);
  }

  /**
   * Address: 0x00ABF38B (FUN_00ABF38B, std::locale::_Getgloballocale)
   *
   * What it does:
   * Returns the process-global locale implementation pointer.
   */
  RuntimeLocaleLocimpView* RuntimeGetGlobalLocale()
  {
    return gRuntimeGlobalLocale;
  }

  /**
   * Address: 0x00ABF391 (FUN_00ABF391, std::locale::_Setgloballocale)
   *
   * What it does:
   * One-time registers global locale tidy callback and updates the process
   * global locale implementation pointer.
   */
  RuntimeLocaleLocimpView* RuntimeSetGlobalLocale(RuntimeLocaleLocimpView* const localeImpl)
  {
    if (gRuntimeGlobalLocaleAtexitRegistered == 0) {
      gRuntimeGlobalLocaleAtexitRegistered = 1;
      std::atexit(RuntimeTidyGlobalLocale);
    }

    gRuntimeGlobalLocale = localeImpl;
    return localeImpl;
  }

  /**
   * Address: 0x00ABF3B6 (FUN_00ABF3B6, std::locale::_Locimp::_Clocptr_func)
   *
   * What it does:
   * Returns pointer-to-pointer storage for classic locale implementation lane.
   */
  RuntimeLocaleLocimpView** RuntimeGetClassicLocimpPointerSlot()
  {
    return &gRuntimeClassicLocale;
  }

  /**
   * Address: 0x00ABF3BC (FUN_00ABF3BC)
   *
   * What it does:
   * Returns storage for the locale-id global counter lane.
   */
  std::int32_t* RuntimeGetLocaleIdCounterSlot()
  {
    return &gRuntimeLocaleIdCounter;
  }

  /**
   * Address: 0x00ABF3C2 (FUN_00ABF3C2)
   *
   * What it does:
   * Returns storage for the `ctype<char>` locale-id lane.
   */
  std::int32_t* RuntimeGetCtypeCharIdSlot()
  {
    return &gRuntimeLocaleIdCtypeChar;
  }

  /**
   * Address: 0x00ABF3C8 (FUN_00ABF3C8)
   *
   * What it does:
   * Returns storage for one static locale-id lane.
   */
  std::int32_t* RuntimeGetLocaleIdSlotA()
  {
    return &gRuntimeLocaleIdSlotA;
  }

  /**
   * Address: 0x00ABF3CE (FUN_00ABF3CE)
   *
   * What it does:
   * Returns storage for one static locale-id lane.
   */
  std::int32_t* RuntimeGetLocaleIdSlotB()
  {
    return &gRuntimeLocaleIdSlotB;
  }

  /**
   * Address: 0x00ABF3D4 (FUN_00ABF3D4)
   *
   * What it does:
   * Returns storage for one static locale-id lane.
   */
  std::int32_t* RuntimeGetLocaleIdSlotC()
  {
    return &gRuntimeLocaleIdSlotC;
  }

  /**
   * Address: 0x00ABF3DA (FUN_00ABF3DA)
   *
   * What it does:
   * Returns storage for one static locale-id lane.
   */
  std::int32_t* RuntimeGetLocaleIdSlotD()
  {
    return &gRuntimeLocaleIdSlotD;
  }

  /**
   * Address: 0x00ABF3E0 (FUN_00ABF3E0)
   *
   * What it does:
   * Under `_Lockit(0)`, decrements refs/deletes each facet in one `_Locimp`
   * facet vector lane, then frees the facet vector storage.
   */
  void RuntimeReleaseLocimpFacetVector(RuntimeLocaleLocimpView* const localeImpl)
  {
    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);

    auto** const facets = static_cast<std::locale::facet**>(localeImpl->facetVector);
    for (int index = localeImpl->facetCount - 1; index >= 0; --index) {
      std::locale::facet* const facet = facets[index];
      if (facet != nullptr) {
        std::locale::facet* const releasedFacet = RuntimeLocaleFacetDecref(facet);
        if (releasedFacet != nullptr) {
          RuntimeDestroyFacetPolymorphic(releasedFacet);
        }
      }
    }

    _free_crt(localeImpl->facetVector);
    RuntimeLockitDestroy(&lockit);
  }

  /**
   * Address: 0x00ABF528 (FUN_00ABF528)
   *
   * What it does:
   * Runs non-deleting `_Locimp` destruction by releasing facet vector lanes and
   * destroying the embedded locale-name string.
   */
  RuntimeLocaleLocimpView* RuntimeDestroyLocimp(RuntimeLocaleLocimpView* const localeImpl)
  {
    RuntimeReleaseLocimpFacetVector(localeImpl);
    localeImpl->name.~basic_string();
    return localeImpl;
  }

  /**
   * Address: 0x00ABF565 (FUN_00ABF565)
   *
   * What it does:
   * Runs `_Locimp` destroy tail and conditionally deletes storage when the
   * scalar-deleting-destructor flag bit is set.
   */
  RuntimeLocaleLocimpView* RuntimeDestroyLocimpDeleting(
    RuntimeLocaleLocimpView* const localeImpl,
    const unsigned int deleteFlags
  )
  {
    RuntimeDestroyLocimp(localeImpl);
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(localeImpl);
    }
    return localeImpl;
  }

  /**
   * Address: 0x00ABF581 (FUN_00ABF581, std::locale::_Init)
   *
   * What it does:
   * Lazily initializes the process-global `"C"` locale implementation under
   * `_Lockit(0)`, seeds classic-locale pointers, and bumps facet refs.
   */
  RuntimeLocaleLocimpView* RuntimeLocaleInit()
  {
    RuntimeLocaleLocimpView* localeImpl = gRuntimeGlobalLocale;
    if (localeImpl != nullptr) {
      return localeImpl;
    }

    RuntimeLockitState lockit{};
    RuntimeLockitConstruct(&lockit, 0);

    localeImpl = gRuntimeGlobalLocale;
    if (localeImpl == nullptr) {
      auto* const storage = static_cast<RuntimeLocaleLocimpView*>(::operator new(sizeof(RuntimeLocaleLocimpView)));
      try {
        localeImpl = RuntimeLocaleLocimpConstruct(storage, false);
      } catch (...) {
        ::operator delete(storage);
        RuntimeLockitDestroy(&lockit);
        throw;
      }

      RuntimeSetGlobalLocale(localeImpl);
      localeImpl->categoryMask = 0x3F;
      localeImpl->name.assign("C");
      gRuntimeClassicLocale = localeImpl;
      ++localeImpl->refs;
      gRuntimeClassicLocaleObject.ptr = gRuntimeClassicLocale;
    }

    RuntimeLockitDestroy(&lockit);
    return localeImpl;
  }

  /**
   * Address: 0x00ABF665 (FUN_00ABF665, std::locale::classic)
   *
   * What it does:
   * Ensures global locale initialization and returns reference storage for the
   * process classic locale object.
   */
  RuntimeStdLocaleObject* RuntimeLocaleClassic()
  {
    RuntimeLocaleInit();
    return &gRuntimeClassicLocaleObject;
  }

  /**
   * Address: 0x00ABF670 (FUN_00ABF670, std::locale::empty)
   *
   * What it does:
   * Ensures global locale initialization, allocates one new `_Locimp` in
   * `isParent=true` mode, stores it into the destination locale object lane,
   * and returns that destination pointer.
   */
  RuntimeStdLocaleObject* RuntimeLocaleEmpty(RuntimeStdLocaleObject* const destinationLocale)
  {
    RuntimeLocaleInit();

    RuntimeLocaleLocimpView* localeImpl = nullptr;
    auto* const storage = static_cast<RuntimeLocaleLocimpView*>(::operator new(sizeof(RuntimeLocaleLocimpView), std::nothrow));
    if (storage != nullptr) {
      localeImpl = RuntimeLocaleLocimpConstruct(storage, true);
    }

    destinationLocale->ptr = localeImpl;
    return destinationLocale;
  }

  [[nodiscard]] std::size_t RuntimeCodePageHashBucket(const std::uint32_t codePage) noexcept
  {
    return static_cast<std::size_t>(codePage % static_cast<std::uint32_t>(kRuntimeCodePageLocaleHashBucketCount));
  }

  [[nodiscard]] int RuntimeGetCodePageMaxCharBytes(const RuntimeLocaleHandle* const locale, const UINT fallbackCodePage)
  {
    struct RuntimeThreadLocInfoMbCurMaxView
    {
      std::uint8_t reserved00[0xAC];
      std::int32_t mbCurMax;
    };
    static_assert(
      offsetof(RuntimeThreadLocInfoMbCurMaxView, mbCurMax) == 0xAC,
      "RuntimeThreadLocInfoMbCurMaxView::mbCurMax offset must be 0xAC"
    );

    if (locale != nullptr && locale->locinfo != nullptr) {
      const auto* const localeView = reinterpret_cast<const RuntimeThreadLocInfoMbCurMaxView*>(locale->locinfo);
      if (localeView->mbCurMax > 0) {
        return localeView->mbCurMax;
      }
    }

    CPINFO codePageInfo{};
    if (::GetCPInfo(fallbackCodePage, &codePageInfo) != FALSE && codePageInfo.MaxCharSize > 0u) {
      return static_cast<int>(codePageInfo.MaxCharSize);
    }
    return 1;
  }

  /**
   * Address: 0x00ABFCCD (FUN_00ABFCCD)
   *
   * What it does:
   * Builds one `".<codepage>"` locale descriptor and creates a CRT locale
   * bundle for that codepage lane.
   */
  RuntimeLocaleHandle* RuntimeCreateCodePageLocale(const std::uint32_t codePage)
  {
    char codePageText[31] = {};
    if (_ultoa_s(static_cast<unsigned long>(codePage), codePageText, _countof(codePageText), 10) != 0) {
      return nullptr;
    }

    char localeName[32] = ".";
    if (RuntimeStrcatS(localeName, _countof(localeName), codePageText) != 0) {
      return nullptr;
    }

    return reinterpret_cast<RuntimeLocaleHandle*>(_create_locale(LC_ALL, localeName));
  }

  /**
   * Address: 0x00ABFD0D (FUN_00ABFD0D)
   *
   * What it does:
   * Returns one cached CRT locale handle for a codepage lane, creating and
   * atomically publishing a new cache node when no match exists.
   */
  RuntimeLocaleHandle* RuntimeGetCachedCodePageLocale(const std::uint32_t codePage)
  {
    const std::size_t bucketIndex = RuntimeCodePageHashBucket(codePage);
    auto* const bucket = reinterpret_cast<PVOID volatile*>(&gRuntimeCodePageLocaleHash[bucketIndex]);

    RuntimeCodePageLocaleHashEntry* pendingEntry = nullptr;
    while (true) {
      auto* const bucketHead = static_cast<RuntimeCodePageLocaleHashEntry*>(*bucket);
      RuntimeCodePageLocaleHashEntry* probe = bucketHead;
      while (probe != nullptr) {
        if (probe->codePage == codePage) {
          if (pendingEntry != nullptr) {
            RuntimeFreeLocale(pendingEntry->locale);
            _free_crt(pendingEntry);
          }
          return probe->locale;
        }
        probe = probe->next;
      }

      if (pendingEntry == nullptr) {
        pendingEntry = static_cast<RuntimeCodePageLocaleHashEntry*>(std::malloc(sizeof(RuntimeCodePageLocaleHashEntry)));
        if (pendingEntry == nullptr) {
          return nullptr;
        }

        RuntimeLocaleHandle* const locale = RuntimeCreateCodePageLocale(codePage);
        pendingEntry->locale = locale;
        if (locale == nullptr) {
          _free_crt(pendingEntry);
          return nullptr;
        }
        pendingEntry->codePage = codePage;
      }

      pendingEntry->next = bucketHead;
      PVOID const priorHead = ::InterlockedCompareExchangePointer(bucket, pendingEntry, bucketHead);
      if (priorHead == bucketHead) {
        return pendingEntry->locale;
      }
    }
  }

  /**
   * Address: 0x00ABFD9F (FUN_00ABFD9F, _ReleaseCPLocHash)
   *
   * What it does:
   * Atomically drains all codepage-locale hash buckets and frees each cached
   * locale bundle and node.
   */
  void RuntimeReleaseCodePageLocaleHash()
  {
    for (std::size_t bucketIndex = 0; bucketIndex < kRuntimeCodePageLocaleHashBucketCount; ++bucketIndex) {
      auto* const bucket = reinterpret_cast<PVOID volatile*>(&gRuntimeCodePageLocaleHash[bucketIndex]);
      auto* entry = static_cast<RuntimeCodePageLocaleHashEntry*>(::InterlockedExchangePointer(bucket, nullptr));
      while (entry != nullptr) {
        RuntimeCodePageLocaleHashEntry* const nextEntry = entry->next;
        RuntimeFreeLocale(entry->locale);
        _free_crt(entry);
        entry = nextEntry;
      }
    }
  }

  /**
   * Address: 0x00ABFDDD (FUN_00ABFDDD, _InitCPLocHash)
   *
   * What it does:
   * Registers one process-exit cleanup hook for the codepage-locale hash and
   * returns CRT on-exit failure code semantics.
   */
  int RuntimeInitCodePageLocaleHash()
  {
    return std::atexit(RuntimeReleaseCodePageLocaleHash) != 0 ? kRuntimeOnExitFailureCode : 0;
  }

  /**
   * Address: 0x00ABFA01 (FUN_00ABFA01)
   *
   * What it does:
   * Converts one wide character to multibyte using `_Cvtvec` locale/codepage
   * lanes, reporting `EILSEQ` for conversion failure/default-char substitution.
   */
  int RuntimeWideCharToMultiByteLocale(
    char* const destination,
    const wchar_t sourceCharacter,
    int /*unused*/,
    const RuntimeCvtVec* const localeVector
  )
  {
    constexpr std::size_t kRuntimeCtypeIndexWideConvert = 2u;

    LCID localeHandle = 0;
    UINT codePage = 0;
    if (localeVector != nullptr) {
      localeHandle = localeVector->handle;
      codePage = static_cast<UINT>(localeVector->codePage);
    } else {
      localeHandle = __lc_handle_func()[kRuntimeCtypeIndexWideConvert];
      codePage = static_cast<UINT>(__lc_codepage_func());
    }

    if (localeHandle == 0) {
      if (static_cast<unsigned int>(sourceCharacter) <= 0xFFu) {
        *destination = static_cast<char>(sourceCharacter);
        return 1;
      }

      *_errno() = EILSEQ;
      return -1;
    }

    BOOL usedDefaultChar = FALSE;
    RuntimeLocaleHandle* const codePageLocale = RuntimeGetCachedCodePageLocale(codePage);
    const int destinationBytes = RuntimeGetCodePageMaxCharBytes(codePageLocale, codePage);

    wchar_t sourceWide = sourceCharacter;
    const int conversionResult =
      ::WideCharToMultiByte(codePage, 0, &sourceWide, 1, destination, destinationBytes, nullptr, &usedDefaultChar);
    if (conversionResult == 0 || usedDefaultChar != FALSE) {
      *_errno() = EILSEQ;
      return -1;
    }

    return conversionResult;
  }

  /**
   * Address: 0x00ABFA96 (FUN_00ABFA96)
   *
   * What it does:
   * Jump-thunk lane for `RuntimeWideCharToMultiByteLocale`.
   */
  int RuntimeWideCharToMultiByteLocaleThunk(
    char* const destination,
    const wchar_t sourceCharacter,
    const int unused,
    const RuntimeCvtVec* const localeVector
  )
  {
    return RuntimeWideCharToMultiByteLocale(destination, sourceCharacter, unused, localeVector);
  }

  /**
   * Address: 0x00ABFDF0 (FUN_00ABFDF0)
   *
   * What it does:
   * Converts one multibyte step to wide-char under `_Cvtvec` locale lanes,
   * including pending-lead-byte state handling and `EILSEQ` error semantics.
   */
  int RuntimeMultiByteToWideStep(
    wchar_t* const destinationWideChar,
    const char* const sourceBytes,
    const unsigned int sourceByteCount,
    char* const pendingStateBytes,
    const RuntimeCvtVec* const localeVector
  )
  {
    constexpr std::size_t kRuntimeCtypeIndexMultiByteConvert = 2u;
    constexpr DWORD kRuntimeMbToWideFlags = 9u;

    if (sourceBytes == nullptr || sourceByteCount == 0u) {
      return 0;
    }

    if (sourceBytes[0] == '\0') {
      if (destinationWideChar != nullptr) {
        *destinationWideChar = L'\0';
      }
      return 0;
    }

    LCID localeHandle = 0;
    UINT codePage = 0;
    if (localeVector != nullptr) {
      localeHandle = localeVector->handle;
      codePage = static_cast<UINT>(localeVector->codePage);
    } else {
      localeHandle = __lc_handle_func()[kRuntimeCtypeIndexMultiByteConvert];
      codePage = static_cast<UINT>(__lc_codepage_func());
    }

    if (localeHandle == 0) {
      if (destinationWideChar != nullptr) {
        *destinationWideChar = static_cast<wchar_t>(static_cast<unsigned char>(sourceBytes[0]));
      }
      return 1;
    }

    RuntimeLocaleHandle* const codePageLocale = RuntimeGetCachedCodePageLocale(codePage);
    auto* const pendingState = reinterpret_cast<std::uint32_t*>(pendingStateBytes);
    if (*pendingState != 0u) {
      pendingStateBytes[1] = sourceBytes[0];
      const int maxCharBytes = RuntimeGetCodePageMaxCharBytes(codePageLocale, codePage);
      if (maxCharBytes > 1
          && ::MultiByteToWideChar(
            codePage,
            kRuntimeMbToWideFlags,
            pendingStateBytes,
            2,
            destinationWideChar,
            (destinationWideChar != nullptr) ? 1 : 0
          ) != 0) {
        *pendingState = 0u;
        return maxCharBytes;
      }

      *pendingState = 0u;
      *_errno() = EILSEQ;
      return -1;
    }

    bool isLeadByte = false;
    if (codePageLocale != nullptr && codePageLocale->mbcinfo != nullptr) {
      struct RuntimeThreadMbcInfoLeadByteView
      {
        std::uint8_t reserved00[0x1D];
        std::uint8_t leadByteFlags[256];
      };
      const auto* const mbcView = reinterpret_cast<const RuntimeThreadMbcInfoLeadByteView*>(codePageLocale->mbcinfo);
      isLeadByte = (mbcView->leadByteFlags[static_cast<unsigned char>(sourceBytes[0])] & 0x4u) != 0u;
    } else {
      isLeadByte = (__pctype_func()[static_cast<unsigned char>(sourceBytes[0])] & 0x8000u) != 0u;
    }

    if (!isLeadByte) {
      if (::MultiByteToWideChar(
            codePage,
            kRuntimeMbToWideFlags,
            sourceBytes,
            1,
            destinationWideChar,
            (destinationWideChar != nullptr) ? 1 : 0
          ) != 0) {
        return 1;
      }

      *pendingState = 0u;
      *_errno() = EILSEQ;
      return -1;
    }

    const int maxCharBytes = RuntimeGetCodePageMaxCharBytes(codePageLocale, codePage);
    if (sourceByteCount < static_cast<unsigned int>(maxCharBytes)) {
      pendingStateBytes[0] = sourceBytes[0];
      return -2;
    }

    if (maxCharBytes > 1
        && ::MultiByteToWideChar(
          codePage,
          kRuntimeMbToWideFlags,
          sourceBytes,
          maxCharBytes,
          destinationWideChar,
          (destinationWideChar != nullptr) ? 1 : 0
        ) != 0) {
      *pendingState = 0u;
      return maxCharBytes;
    }

    if (sourceBytes[1] != '\0') {
      *pendingState = 0u;
      return maxCharBytes;
    }

    *pendingState = 0u;
    *_errno() = EILSEQ;
    return -1;
  }

  /**
   * Address: 0x00ABF1DE (FUN_00ABF1DE)
   *
   * What it does:
   * Converts one input character to uppercase using the CRT locale conversion
   * path (`__crtLCMapStringA`) and falls back to ASCII uppercasing when locale
   * handle lane is unset.
   */
  int RuntimeToupper(const int character, RuntimeCtypeVec* const localeVector)
  {
    constexpr std::size_t kRuntimeCtypeIndexToupper = 2u;

    RuntimeCtypeVec* const ctypeVector = localeVector;
    LCID localeHandle = 0;
    int codePage = 0;
    if (ctypeVector != nullptr) {
      localeHandle = ctypeVector->handle;
      codePage = ctypeVector->codePage;
    } else {
      localeHandle = __lc_handle_func()[kRuntimeCtypeIndexToupper];
      codePage = __lc_codepage_func();
    }

    if (localeHandle == 0) {
      if (character >= static_cast<int>('a') && character <= static_cast<int>('z')) {
        return character - static_cast<int>('a' - 'A');
      }
      return character;
    }

    if (static_cast<unsigned int>(character) < 0x100u) {
      if (ctypeVector == nullptr) {
        if (::islower(character) == 0) {
          return character;
        }
      } else if ((ctypeVector->table[static_cast<unsigned int>(character)] & 0x2u) == 0u) {
        return character;
      }
    }

    const int highByte = character >> 8;
    int hasLeadByteFlag = 0;
    if (ctypeVector == nullptr) {
      const unsigned int highByteIndex = static_cast<unsigned int>(highByte) & 0xFFu;
      hasLeadByteFlag = (__pctype_func()[highByteIndex] & 0x8000u) != 0u ? 1 : 0;
    } else {
      const unsigned int highByteIndex = static_cast<unsigned int>(highByte) & 0xFFu;
      hasLeadByteFlag = (ctypeVector->table[highByteIndex] >> 15) & 0x1;
    }

    char inputBuffer[3] = {};
    int inputLength = 1;
    inputBuffer[0] = static_cast<char>(character & 0xFF);
    if (hasLeadByteFlag != 0) {
      inputBuffer[0] = static_cast<char>(highByte & 0xFF);
      inputBuffer[1] = static_cast<char>(character & 0xFF);
      inputLength = 2;
    }

    char outputBuffer[3] = {};
    const int mappedLength = __crtLCMapStringA(
      0,
      localeHandle,
      LCMAP_UPPERCASE,
      inputBuffer,
      inputLength,
      reinterpret_cast<LPWSTR>(outputBuffer),
      3,
      codePage,
      1
    );
    if (mappedLength == 0) {
      return character;
    }
    if (mappedLength == 1) {
      return static_cast<unsigned char>(outputBuffer[0]);
    }

    return (static_cast<int>(static_cast<unsigned char>(outputBuffer[0])) << 8)
      | static_cast<int>(static_cast<unsigned char>(outputBuffer[1]));
  }

  /**
   * Address: 0x00ABF6B2 (FUN_00ABF6B2, _Tolower)
   *
   * What it does:
   * Converts one input character to lowercase using the CRT locale conversion
   * path (`__crtLCMapStringA`) and falls back to ASCII lowercasing when locale
   * handle lane is unset.
   */
  int RuntimeTolower(const int character, RuntimeCtypeVec* const localeVector)
  {
    constexpr std::size_t kRuntimeCtypeIndexTolower = 2u;

    RuntimeCtypeVec* const ctypeVector = localeVector;
    LCID localeHandle = 0;
    int codePage = 0;
    if (ctypeVector != nullptr) {
      localeHandle = ctypeVector->handle;
      codePage = ctypeVector->codePage;
    } else {
      localeHandle = __lc_handle_func()[kRuntimeCtypeIndexTolower];
      codePage = __lc_codepage_func();
    }

    if (localeHandle == 0) {
      if (character >= static_cast<int>('A') && character <= static_cast<int>('Z')) {
        return character + static_cast<int>('a' - 'A');
      }
      return character;
    }

    if (static_cast<unsigned int>(character) < 0x100u) {
      if (ctypeVector == nullptr) {
        if (::isupper(character) == 0) {
          return character;
        }
      } else if ((ctypeVector->table[static_cast<unsigned int>(character)] & 0x1u) == 0u) {
        return character;
      }
    }

    const int highByte = character >> 8;
    int hasLeadByteFlag = 0;
    if (ctypeVector == nullptr) {
      const unsigned int highByteIndex = static_cast<unsigned int>(highByte) & 0xFFu;
      hasLeadByteFlag = (__pctype_func()[highByteIndex] & 0x8000u) != 0u ? 1 : 0;
    } else {
      const unsigned int highByteIndex = static_cast<unsigned int>(highByte) & 0xFFu;
      hasLeadByteFlag = (ctypeVector->table[highByteIndex] >> 15) & 0x1;
    }

    char inputBuffer[3] = {};
    int inputLength = 1;
    inputBuffer[0] = static_cast<char>(character & 0xFF);
    if (hasLeadByteFlag != 0) {
      inputBuffer[0] = static_cast<char>(highByte & 0xFF);
      inputBuffer[1] = static_cast<char>(character & 0xFF);
      inputLength = 2;
    }

    char outputBuffer[3] = {};
    const int mappedLength = __crtLCMapStringA(
      0,
      localeHandle,
      LCMAP_LOWERCASE,
      inputBuffer,
      inputLength,
      reinterpret_cast<LPWSTR>(outputBuffer),
      3,
      codePage,
      1
    );
    if (mappedLength == 0) {
      return character;
    }
    if (mappedLength == 1) {
      return static_cast<unsigned char>(outputBuffer[0]);
    }

    return (static_cast<int>(static_cast<unsigned char>(outputBuffer[0])) << 8)
      | static_cast<int>(static_cast<unsigned char>(outputBuffer[1]));
  }

  /**
   * Address: 0x00ABF7C1 (FUN_00ABF7C1, _Getctype)
   *
   * What it does:
   * Builds one `_Ctypevec` lane from thread locale handle/codepage and either
   * clones the current CRT `_pctype` table or aliases it on allocation failure.
   */
  RuntimeCtypeVec* RuntimeGetctype(RuntimeCtypeVec* const ctypeVector)
  {
    constexpr std::size_t kRuntimeCtypeIndexGetctype = 1u;

    ctypeVector->handle = __lc_handle_func()[kRuntimeCtypeIndexGetctype];
    ctypeVector->codePage = __lc_codepage_func();

    auto* const tableCopy = static_cast<std::uint16_t*>(_calloc_crt(0x100u, sizeof(std::uint16_t)));
    ctypeVector->table = tableCopy;
    if (tableCopy != nullptr) {
      std::memcpy(tableCopy, __pctype_func(), 0x200u);
      ctypeVector->ownsCopiedTable = 1;
    } else {
      ctypeVector->ownsCopiedTable = 0;
      ctypeVector->table = __pctype_func();
    }

    return ctypeVector;
  }

  /**
   * Address: 0x00ABFA82 (FUN_00ABFA82, _Getcvt)
   *
   * What it does:
   * Returns one `_Cvtvec` pair containing thread locale conversion handle lane
   * and current locale codepage lane.
   */
  RuntimeCvtVec RuntimeGetcvt()
  {
    constexpr std::size_t kRuntimeCtypeIndexGetcvt = 2u;

    RuntimeCvtVec cvtVector{};
    cvtVector.handle = __lc_handle_func()[kRuntimeCtypeIndexGetcvt];
    cvtVector.codePage = __lc_codepage_func();
    return cvtVector;
  }

  /**
   * Address: 0x00ABFA9B (FUN_00ABFA9B, std::uncaught_exception)
   *
   * What it does:
   * Forwards to the CRT uncaught-exception state probe and returns one boolean
   * result lane.
   */
  bool RuntimeUncaughtException()
  {
    return __uncaught_exception();
  }

  /**
   * Address: 0x00ABFC6A (FUN_00ABFC6A)
   *
   * What it does:
   * Uppercases one wide-character lane with locale/codepage context from
   * `_Cvtvec`, with ASCII fallback when locale handle lane is zero.
   */
  int RuntimeToupperWide(const std::uint16_t sourceCharacter, const RuntimeCvtVec* const localeVector)
  {
    std::uint16_t destinationCharacter = sourceCharacter;
    if (sourceCharacter == 0xFFFFu) {
      return static_cast<int>(sourceCharacter);
    }

    if (localeVector->handle != 0 || sourceCharacter >= 0x100u) {
      wchar_t sourceWide = static_cast<wchar_t>(sourceCharacter);
      wchar_t destinationWide = sourceWide;
      const int mapResult = __crtLCMapStringW(
        0,
        localeVector->handle,
        LCMAP_UPPERCASE,
        &sourceWide,
        1,
        &destinationWide,
        1,
        localeVector->codePage
      );
      if (mapResult != 0) {
        destinationCharacter = static_cast<std::uint16_t>(destinationWide);
      }
      return static_cast<int>(destinationCharacter);
    }

    if (sourceCharacter >= static_cast<std::uint16_t>('a') && sourceCharacter <= static_cast<std::uint16_t>('z')) {
      destinationCharacter = static_cast<std::uint16_t>(sourceCharacter - static_cast<std::uint16_t>('a' - 'A'));
    }
    return static_cast<int>(destinationCharacter);
  }

  /**
   * Address: 0x00ABFF61 (FUN_00ABFF61)
   *
   * What it does:
   * Queries CRT wide-char type flags for one code unit under `_Cvtvec` locale
   * context and returns one signed 16-bit flag lane on success.
   */
  int RuntimeGetWideCharTypeSingle(const std::uint16_t sourceCharacter, const RuntimeCvtVec* const localeVector)
  {
    wchar_t sourceWide = static_cast<wchar_t>(sourceCharacter);
    WORD charType = 0;
    const int getTypeResult = __crtGetStringTypeW(
      0,
      1u,
      &sourceWide,
      1,
      &charType,
      localeVector->codePage,
      localeVector->handle
    );
    if (getTypeResult == 0) {
      return 0;
    }
    return static_cast<short>(charType);
  }

  /**
   * Address: 0x00ABFF8E (FUN_00ABFF8E)
   *
   * What it does:
   * Fills type flags for one wide-char span under `_Cvtvec` locale context and
   * returns the original end pointer lane.
   */
  const wchar_t* RuntimeGetWideCharTypeRange(
    const wchar_t* const sourceBegin,
    const wchar_t* const sourceEnd,
    WORD* const outCharTypes,
    const RuntimeCvtVec* const localeVector
  )
  {
    const int sourceCount = static_cast<int>(sourceEnd - sourceBegin);
    __crtGetStringTypeW(0, 1u, sourceBegin, sourceCount, outCharTypes, localeVector->codePage, localeVector->handle);
    return sourceEnd;
  }

  /**
   * Address: 0x00ABFFB9 (FUN_00ABFFB9)
   *
   * What it does:
   * Lowercases one wide-character lane with locale/codepage context from
   * `_Cvtvec`, with ASCII fallback when locale handle lane is zero.
   */
  int RuntimeTolowerWide(const std::uint16_t sourceCharacter, const RuntimeCvtVec* const localeVector)
  {
    std::uint16_t destinationCharacter = sourceCharacter;
    if (sourceCharacter == 0xFFFFu) {
      return static_cast<int>(sourceCharacter);
    }

    if (localeVector->handle != 0 || sourceCharacter >= 0x100u) {
      wchar_t sourceWide = static_cast<wchar_t>(sourceCharacter);
      wchar_t destinationWide = sourceWide;
      const int mapResult = __crtLCMapStringW(
        0,
        localeVector->handle,
        LCMAP_LOWERCASE,
        &sourceWide,
        1,
        &destinationWide,
        1,
        localeVector->codePage
      );
      if (mapResult != 0) {
        destinationCharacter = static_cast<std::uint16_t>(destinationWide);
      }
      return static_cast<int>(destinationCharacter);
    }

    if (sourceCharacter >= static_cast<std::uint16_t>('A') && sourceCharacter <= static_cast<std::uint16_t>('Z')) {
      destinationCharacter = static_cast<std::uint16_t>(sourceCharacter + static_cast<std::uint16_t>('a' - 'A'));
    }
    return static_cast<int>(destinationCharacter);
  }

  /**
   * Address: 0x00A868BB (FUN_00A868BB, ungetc)
   *
   * What it does:
   * Validates stream pointer lane and forwards pushback to CRT `ungetc`
   * behavior, returning `EOF` for invalid-parameter input.
   */
  int RuntimeUngetc(const int character, std::FILE* const stream)
  {
    if (stream == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EOF;
    }

    return std::ungetc(character, stream);
  }

  /**
   * Address: 0x00AA4974 (FUN_00AA4974, func_CloseAllFiles)
   *
   * What it does:
   * Walks CRT stream slots under `_IOB_SCAN_LOCK`, locks each active stream,
   * closes `_tmpfile` lanes via `_fclose_nolock`, and returns close count.
   */
  int RuntimeCloseAllTemporaryStreams()
  {
    int closedStreamCount = 0;

    RuntimeLockGuard scanLock(kRuntimeIobScanLock);
    for (int streamIndex = 0; streamIndex < static_cast<int>(_nstream); ++streamIndex) {
      std::FILE* const stream = __piob[streamIndex];
      if (stream == nullptr) {
        continue;
      }

      if ((RuntimeGetFileFlags(stream) & kRuntimeFileFlagFlushMask) == 0) {
        continue;
      }

      RuntimeFileLock2Guard streamLock(streamIndex, stream);
      if ((RuntimeGetFileFlags(stream) & kRuntimeFileFlagFlushMask) == 0) {
        continue;
      }

      auto* const tmpNameView = reinterpret_cast<RuntimeFileTmpNameView*>(stream);
      if (tmpNameView->tmpName == nullptr) {
        continue;
      }

      _fclose_nolock(stream);
      ++closedStreamCount;
    }

    return closedStreamCount;
  }

  /**
   * Address: 0x00AA3FCE (FUN_00AA3FCE, _fcloseall)
   *
   * What it does:
   * Closes active CRT stream lanes from index 3 to `_nstream - 1` under
   * `_IOB_SCAN_LOCK`, then tears down/free-caches dynamic stream slots
   * (`index >= 20`) and returns successful close count.
   */
  int RuntimeFcloseall()
  {
    int closedStreamCount = 0;

    RuntimeLockGuard scanLock(kRuntimeIobScanLock);
    for (int streamIndex = 3; streamIndex < static_cast<int>(_nstream); ++streamIndex) {
      std::FILE* const stream = __piob[streamIndex];
      if (stream == nullptr) {
        continue;
      }

      if ((RuntimeGetFileFlags(stream) & kRuntimeFileFlagFlushMask) != 0 && std::fclose(stream) != -1) {
        ++closedStreamCount;
      }

      if (streamIndex >= 20) {
        std::FILE* const cachedStream = __piob[streamIndex];
        auto* const fileView = reinterpret_cast<RuntimeFileLockView*>(cachedStream);
        ::DeleteCriticalSection(&fileView->lock);
        _free_crt(cachedStream);
        __piob[streamIndex] = nullptr;
      }
    }

    return closedStreamCount;
  }

  /**
   * Address: 0x00A863B9 (FUN_00A863B9, _flush)
   *
   * What it does:
   * Flushes one writable FILE buffer lane via `_write`, updates stream status
   * flags on success/failure, then rewinds `_ptr/_cnt` to the buffer base.
   */
  extern "C" int __cdecl _flush(std::FILE* const stream)
  {
    const int streamFlags = RuntimeGetFileFlags(stream);
    int flushStatus = 0;
    if ((streamFlags & 0x3) == 0x2 && (streamFlags & 0x108) != 0) {
      char* const base = stream->_base;
      const int pendingBytes = static_cast<int>(stream->_ptr - base);
      if (pendingBytes > 0) {
        const int fileDescriptor = ::_fileno(stream);
        if (::_write(fileDescriptor, base, static_cast<unsigned int>(pendingBytes)) == pendingBytes) {
          if ((stream->_flag & 0x80) != 0) {
            stream->_flag &= ~0x2;
          }
        } else {
          stream->_flag |= 0x20;
          flushStatus = -1;
        }
      }
    }

    stream->_cnt = 0;
    stream->_ptr = stream->_base;
    return flushStatus;
  }

  /**
   * Address: 0x00A8645D (FUN_00A8645D, flsall)
   *
   * What it does:
   * Walks CRT stream slots under `_IOB_SCAN_LOCK`, locks each active FILE lane
   * with `__lock_file2`, and performs mode-gated `_fflush_nolock` dispatch.
   */
  int RuntimeFlushAllStreams(const int mode)
  {
    int flushCount = 0;
    int flushFailure = 0;

    RuntimeLockGuard scanLock(kRuntimeIobScanLock);
    for (int streamIndex = 0; streamIndex < static_cast<int>(_nstream); ++streamIndex) {
      std::FILE* const stream = __piob[streamIndex];
      if (stream == nullptr) {
        continue;
      }

      if ((RuntimeGetFileFlags(stream) & kRuntimeFileFlagFlushMask) == 0) {
        continue;
      }

      RuntimeFileLock2Guard streamLock(streamIndex, stream);
      const int streamFlags = RuntimeGetFileFlags(stream);
      if ((streamFlags & kRuntimeFileFlagFlushMask) == 0) {
        continue;
      }

      if (mode == 1) {
        if (_fflush_nolock(stream) != -1) {
          ++flushCount;
        }
        continue;
      }

      if (mode == 0 && (streamFlags & kRuntimeFileFlagWritable) != 0 && _fflush_nolock(stream) == -1) {
        flushFailure = -1;
      }
    }

    if (mode == 1) {
      return flushCount;
    }
    return flushFailure;
  }

  /**
   * Address: 0x00A8641B (FUN_00A8641B, _fflush_nolock)
   *
   * What it does:
   * Flushes one stream through `_flush`, optionally commits the file descriptor
   * when the stream has commit-on-flush mode, or flushes all writable streams
   * when `stream == nullptr`.
   */
  extern "C" int __cdecl _fflush_nolock(std::FILE* const stream)
  {
    if (stream == nullptr) {
      return RuntimeFlushAllStreams(0);
    }

    if (_flush(stream) != 0) {
      return -1;
    }

    if ((stream->_flag & 0x4000) == 0) {
      return 0;
    }

    const int fileDescriptor = ::_fileno(stream);
    return (::_commit(fileDescriptor) == 0) ? 0 : -1;
  }

  namespace
  {
    char* gRuntimeStdTerminalBuffers[2] = {nullptr, nullptr};
  }

  /**
   * Address: 0x00A9C267 (FUN_00A9C267, _stbuf)
   *
   * What it does:
   * Enables line-buffered terminal buffering for stdout/stderr TTY streams,
   * lazily allocating one 4 KiB buffer per lane and falling back to FILE
   * charbuf storage when allocation fails.
   */
  int RuntimeStbuf(std::FILE* const stream)
  {
    if (stream == nullptr) {
      return 0;
    }

    const int fileDescriptor = ::_fileno(stream);
    if (::_isatty(fileDescriptor) == 0) {
      return 0;
    }

    int stdbufSlot = -1;
    if (stream == stdout) {
      stdbufSlot = 0;
    } else if (stream == stderr) {
      stdbufSlot = 1;
    } else {
      return 0;
    }

    ++_cflush;
    if ((stream->_flag & 0x10C) != 0) {
      return 0;
    }

    char*& bufferSlot = gRuntimeStdTerminalBuffers[stdbufSlot];
    if (bufferSlot == nullptr) {
      bufferSlot = static_cast<char*>(std::malloc(4096u));
    }

    if (bufferSlot != nullptr) {
      stream->_base = bufferSlot;
      stream->_ptr = bufferSlot;
      stream->_bufsiz = 4096;
      stream->_cnt = 4096;
    } else {
      stream->_base = reinterpret_cast<char*>(&stream->_charbuf);
      stream->_ptr = reinterpret_cast<char*>(&stream->_charbuf);
      stream->_bufsiz = 2;
      stream->_cnt = 2;
    }

    stream->_flag |= 0x1102u;
    return 1;
  }

  /**
   * Address: 0x00A86537 (FUN_00A86537, fflush)
   *
   * What it does:
   * Flushes one stream under CRT file lock, or all writable streams when
   * `stream == nullptr`.
   */
  int RuntimeFflush(std::FILE* const stream)
  {
    if (stream == nullptr) {
      return RuntimeFlushAllStreams(0);
    }

    _lock_file(stream);
    const int flushResult = _fflush_nolock(stream);
    _unlock_file(stream);
    return flushResult;
  }

  /**
   * Address: 0x00A9D4DE (FUN_00A9D4DE, __tzset)
   *
   * What it does:
   * Performs one-time timezone initialization under `_TIME_LOCK` and calls
   * `_tzset_nolock` on the first entry.
   */
  void RuntimeTzset()
  {
    if (gRuntimeTzsetFirstTime != 0) {
      return;
    }

    RuntimeLockGuard timeLock(kRuntimeTimeLock);
    if (gRuntimeTzsetFirstTime == 0) {
      _tzset_nolock();
      ++gRuntimeTzsetFirstTime;
    }
  }

  /**
   * Address: 0x00AA6F65 (FUN_00AA6F65, _tfdopen)
   *
   * What it does:
   * Validates fd + mode text, allocates one CRT stream lane, applies parsed
   * open flags, and returns unlocked `FILE*` storage.
   */
  std::FILE* RuntimeTfdopen(const int fileDescriptor, char* modeText)
  {
    if (modeText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    if (fileDescriptor == -2) {
      *_errno() = EBADF;
      return nullptr;
    }

    if (fileDescriptor < 0 || fileDescriptor >= _nhandle || (RuntimeGetOsFileFlags(fileDescriptor) & 0x01u) == 0u) {
      *_errno() = EBADF;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    while (*modeText == ' ') {
      ++modeText;
    }
    char* const parsedModeText = modeText;

    unsigned int openFlags = 0u;
    if (*modeText == 'a' || *modeText == 'w') {
      openFlags = 2u;
    } else if (*modeText == 'r') {
      openFlags = 1u;
    } else {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    openFlags |= static_cast<unsigned int>(_commode);
    bool parseValid = true;
    bool sawCommitFlag = false;
    bool sawTextBinaryFlag = false;
    while (parseValid && *++modeText != '\0') {
      const char modeChar = *modeText;
      if (modeChar == ' ') {
        continue;
      }

      switch (modeChar) {
        case '+':
          if ((openFlags & 0x80u) == 0u) {
            openFlags = (openFlags & 0xFFFFFF7Cu) | 0x80u;
          } else {
            parseValid = false;
          }
          break;
        case 'b':
        case 't':
          if (sawTextBinaryFlag) {
            parseValid = false;
          } else {
            sawTextBinaryFlag = true;
          }
          break;
        case 'c':
          if (sawCommitFlag) {
            parseValid = false;
          } else {
            sawCommitFlag = true;
            openFlags |= 0x4000u;
          }
          break;
        case 'n':
          if (sawCommitFlag) {
            parseValid = false;
          } else {
            sawCommitFlag = true;
            openFlags &= ~0x4000u;
          }
          break;
        default:
          parseValid = false;
          break;
      }
    }

    while (*modeText == ' ') {
      ++modeText;
    }
    if (!parseValid || *modeText != '\0') {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    std::FILE* const stream = ::_fdopen(fileDescriptor, parsedModeText);
    if (stream == nullptr) {
      *_errno() = EMFILE;
    }
    return stream;
  }

  /**
   * Address: 0x00AAA97A (FUN_00AAA97A, _setenvp)
   *
   * What it does:
   * Builds one pointer-array environment from `_aenvptr` NUL-delimited text
   * block and marks CRT environment lanes initialized.
   */
  int RuntimeSetenvp()
  {
    if (__mbctype_initialized == 0) {
      __initmbctable();
    }

    if (_aenvptr == nullptr) {
      return -1;
    }

    int environmentCount = 0;
    char* scanCursor = _aenvptr;
    while (*scanCursor != '\0') {
      if (*scanCursor != '=') {
        ++environmentCount;
      }
      scanCursor += std::strlen(scanCursor) + 1u;
    }

    _environ = static_cast<char**>(_calloc_crt(static_cast<std::size_t>(environmentCount + 1), sizeof(char*)));
    if (_environ == nullptr) {
      return -1;
    }

    char** outputCursor = _environ;
    scanCursor = _aenvptr;
    while (*scanCursor != '\0') {
      const std::size_t entryLength = std::strlen(scanCursor) + 1u;
      if (*scanCursor != '=') {
        char* const copiedEntry = static_cast<char*>(_calloc_crt(entryLength, 1u));
        *outputCursor = copiedEntry;
        if (copiedEntry == nullptr) {
          _free_crt(_environ);
          _environ = nullptr;
          return -1;
        }

        if (RuntimeStrcpyS(copiedEntry, entryLength, scanCursor) != 0) {
          _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
        }

        ++outputCursor;
      }

      scanCursor += entryLength;
    }

    _free_crt(_aenvptr);
    _aenvptr = nullptr;
    *outputCursor = nullptr;
    __env_initialized = 1;
    return 0;
  }

  /**
   * Address: 0x00A850D6 (FUN_00A850D6, __dupenv_s)
   *
   * What it does:
   * Duplicates one environment-variable string under the CRT environment lock
   * and returns CRT `errno_t` status semantics.
   */
  errno_t RuntimeDupEnvS(char** const outBuffer, size_t* const outBufferCount, const char* const variableName)
  {
    RuntimeEnvironmentLockGuard lockGuard{};
    if (outBuffer != nullptr) {
      *outBuffer = nullptr;
      if (outBufferCount != nullptr) {
        *outBufferCount = 0u;
      }

      if (variableName != nullptr) {
        const char* const source = std::getenv(variableName);
        if (source != nullptr) {
          const size_t requiredBytes = std::strlen(source) + 1u;
          char* const destination = static_cast<char*>(std::calloc(requiredBytes, 1u));
          *outBuffer = destination;
          if (destination == nullptr) {
            *_errno() = ENOMEM;
            return *_errno();
          }

          if (RuntimeStrcpyS(destination, requiredBytes, source) != 0) {
            _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
          }

          if (outBufferCount != nullptr) {
            *outBufferCount = requiredBytes;
          }
        }

        return 0;
      }
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return EINVAL;
  }

  /**
   * Address: 0x00A855B2 (FUN_00A855B2, _time64)
   *
   * What it does:
   * Converts current FILETIME ticks into Unix epoch seconds and mirrors that
   * value through optional output pointer.
   */
  __time64_t RuntimeTime64(__time64_t* const outEpochSeconds)
  {
    FILETIME systemTimeAsFileTime{};
    ::GetSystemTimeAsFileTime(&systemTimeAsFileTime);

    const std::uint64_t filetimeTicks =
      BuildUnsigned64(systemTimeAsFileTime.dwLowDateTime, systemTimeAsFileTime.dwHighDateTime);
    const __time64_t epochSeconds = static_cast<__time64_t>(
      (filetimeTicks - kFiletimeToUnixEpochOffset) / kFiletimeHundredNsPerSecond
    );

    if (outEpochSeconds != nullptr) {
      *outEpochSeconds = epochSeconds;
    }

    return epochSeconds;
  }

  /**
   * Address: 0x00A8692D (FUN_00A8692D, _ftime64_s)
   *
   * What it does:
   * Populates `_timeb64` from FILETIME ticks, refreshes cached DST state once
   * per elapsed minute, and returns CRT `errno_t` status semantics.
   */
  errno_t RuntimeFtime64S(__timeb64* const outTime)
  {
    if (outTime == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    RuntimeTzset();

    long timezoneSeconds = 0;
    if (_get_timezone(&timezoneSeconds) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    outTime->timezone = static_cast<short>(timezoneSeconds / 60L);

    FILETIME systemTimeAsFileTime{};
    ::GetSystemTimeAsFileTime(&systemTimeAsFileTime);

    const std::uint64_t filetimeTicks =
      BuildUnsigned64(systemTimeAsFileTime.dwLowDateTime, systemTimeAsFileTime.dwHighDateTime);
    const std::int64_t elapsedMinutes = static_cast<std::int64_t>(filetimeTicks / kFiletimeHundredNsPerMinute);

    if (elapsedMinutes != gRuntimeElapsedMinutesCache) {
      TIME_ZONE_INFORMATION timeZoneInfo{};
      const DWORD timezoneState = ::GetTimeZoneInformation(&timeZoneInfo);
      if (timezoneState == TIME_ZONE_ID_INVALID) {
        gRuntimeDstFlagCache = -1;
      } else {
        const bool daylightActive = timezoneState == TIME_ZONE_ID_DAYLIGHT && timeZoneInfo.DaylightDate.wMonth != 0u
          && timeZoneInfo.DaylightBias != 0L;
        gRuntimeDstFlagCache = daylightActive ? 1 : 0;
      }

      gRuntimeElapsedMinutesCache = elapsedMinutes;
    }

    outTime->dstflag = static_cast<short>(gRuntimeDstFlagCache);

    const std::uint64_t millisecondsSinceFiletimeEpoch = filetimeTicks / kFiletimeHundredNsPerMillisecond;
    outTime->millitm = static_cast<unsigned short>(millisecondsSinceFiletimeEpoch % 1000u);

    const std::uint64_t secondsSinceUnixEpoch =
      (filetimeTicks - kFiletimeToUnixEpochOffset) / kFiletimeHundredNsPerSecond;
    outTime->time = static_cast<__time64_t>(secondsSinceUnixEpoch);
    return 0;
  }

  /**
   * Address: 0x00B57ED0 (FUN_00B57ED0)
   * Symbol: __ftol2_sse_0
   *
   * What it does:
   * Converts one floating value to a signed 64-bit integer via legacy ftol
   * lane semantics.
   */
  std::int64_t LegacyFtol2Sse(double value)
  {
    return static_cast<std::int64_t>(value);
  }

  /**
   * Address: 0x00B57F00 (FUN_00B57F00)
   * Symbol: shl
   *
   * What it does:
   * 64-bit shift-left helper with explicit `>=64` zero result semantics.
   */
  std::uint64_t LegacyShiftLeft64(std::uint64_t value, std::uint8_t shift)
  {
    if (shift >= 64u) {
      return 0u;
    }

    if (shift >= 32u) {
      const std::uint32_t low = static_cast<std::uint32_t>(value & 0xFFFFFFFFu);
      const std::uint32_t high = low << (shift & 0x1Fu);
      return static_cast<std::uint64_t>(high) << 32u;
    }

    return value << (shift & 0x1Fu);
  }

  /**
   * Address: 0x00B5F7F0 (FUN_00B5F7F0)
   *
   * What it does:
   * EH cleanup helper that deletes one pending allocation lane.
   */
  void EhDeletePendingAllocationA(void* allocation)
  {
    ::operator delete(allocation);
  }

  /**
   * Address: 0x00B5F850 (FUN_00B5F850)
   *
   * What it does:
   * EH cleanup helper that deletes one pending allocation lane.
   */
  void EhDeletePendingAllocationB(void* allocation)
  {
    ::operator delete(allocation);
  }

  /**
   * Address: 0x00B5F880 (FUN_00B5F880)
   *
   * What it does:
   * EH cleanup helper that deletes one pending allocation lane.
   */
  void EhDeletePendingAllocationC(void* allocation)
  {
    ::operator delete(allocation);
  }

  struct RuntimeScopedMutexLockView
  {
    struct RuntimeMutexView* mutex = nullptr; // +0x00
    std::uint8_t ownsLock = 0;            // +0x04
    std::uint8_t reserved05[0x3]{};       // +0x05
  };
  static_assert(
    offsetof(RuntimeScopedMutexLockView, ownsLock) == 0x4,
    "RuntimeScopedMutexLockView::ownsLock offset must be 0x4"
  );
  static_assert(sizeof(RuntimeScopedMutexLockView) == 0x8, "RuntimeScopedMutexLockView size must be 0x8");

  struct RuntimeMutexView
  {
    void* nativeHandleOrCriticalSection = nullptr; // +0x00
    std::uint8_t lockMode = 0;                     // +0x04
    std::uint8_t reserved05[0x3]{};                // +0x05
  };
  static_assert(sizeof(RuntimeMutexView) == 0x8, "RuntimeMutexView size must be 0x8");

  void RuntimeUnlockMutex(RuntimeMutexView* const mutex)
  {
    if (mutex == nullptr || mutex->nativeHandleOrCriticalSection == nullptr) {
      return;
    }

    if ((mutex->lockMode & 0x1u) != 0u) {
      ::LeaveCriticalSection(static_cast<CRITICAL_SECTION*>(mutex->nativeHandleOrCriticalSection));
    } else {
      ::ReleaseMutex(static_cast<HANDLE>(mutex->nativeHandleOrCriticalSection));
    }
  }

  struct RuntimeOwnedHandleCell
  {
    HANDLE handle = nullptr;              // +0x00
    std::uint32_t reserved04 = 0;         // +0x04
    std::uint8_t shouldCloseHandle = 0;   // +0x08
    std::uint8_t reserved09[0x3]{};       // +0x09
  };
  static_assert(
    offsetof(RuntimeOwnedHandleCell, shouldCloseHandle) == 0x8,
    "RuntimeOwnedHandleCell::shouldCloseHandle offset must be 0x8"
  );
  static_assert(sizeof(RuntimeOwnedHandleCell) == 0xC, "RuntimeOwnedHandleCell size must be 0xC");

  struct RuntimeWxStringView
  {
    wchar_t* m_pchData = nullptr; // +0x00
  };
  static_assert(sizeof(RuntimeWxStringView) == 0x4, "RuntimeWxStringView size must be 0x4");

  struct RuntimeWxObjectView
  {
    void* vtable = nullptr;  // +0x00
    void* refData = nullptr; // +0x04
  };
  static_assert(offsetof(RuntimeWxObjectView, refData) == 0x4, "RuntimeWxObjectView::refData offset must be 0x4");
  static_assert(sizeof(RuntimeWxObjectView) == 0x8, "RuntimeWxObjectView size must be 0x8");

  struct RuntimeWxCommandEventView
  {
    std::uint8_t reserved00[0x20]{};
    RuntimeWxStringView commandString; // +0x20
  };
  static_assert(
    offsetof(RuntimeWxCommandEventView, commandString) == 0x20,
    "RuntimeWxCommandEventView::commandString offset must be 0x20"
  );

  struct RuntimeCriticalSectionLeaveGuard
  {
    std::uint8_t shouldLeave = 0;         // +0x00
    std::uint8_t reserved01[0x3]{};       // +0x01
    CRITICAL_SECTION* criticalSection = nullptr; // +0x04
  };
  static_assert(
    offsetof(RuntimeCriticalSectionLeaveGuard, criticalSection) == 0x4,
    "RuntimeCriticalSectionLeaveGuard::criticalSection offset must be 0x4"
  );
  static_assert(sizeof(RuntimeCriticalSectionLeaveGuard) == 0x8, "RuntimeCriticalSectionLeaveGuard size must be 0x8");

  void DestroySharedWxStringRuntimePayload(RuntimeWxStringView* const value)
  {
    auto* const header = reinterpret_cast<std::int32_t*>(value->m_pchData) - 3;
    const std::int32_t refCount = header[0];
    if (refCount != -1) {
      header[0] = refCount - 1;
      if (refCount == 1) {
        ::operator delete(static_cast<void*>(header));
      }
    }
  }

  /**
   * Address: 0x00B5F8B0 (FUN_00B5F8B0)
   *
   * What it does:
   * EH cleanup helper that destroys one pending `wxCommandEvent` lane loaded
   * from a stack pointer slot.
   */
  void EhCleanupDestroyPendingWxCommandEvent(RuntimeWxCommandEventView** const commandEventSlot)
  {
    RuntimeWxCommandEventView* const commandEvent = *commandEventSlot;
    DestroySharedWxStringRuntimePayload(&commandEvent->commandString);
    reinterpret_cast<RuntimeWxObjectView*>(commandEvent)->refData = nullptr;
  }

  /**
   * Address: 0x00B5F8E0 (FUN_00B5F8E0)
   *
   * What it does:
   * EH cleanup helper that runs the shared wx-object unref tail for one pending
   * object pointer lane.
   */
  void EhCleanupDestroyPendingWxObject(RuntimeWxObjectView** const objectSlot)
  {
    (*objectSlot)->refData = nullptr;
  }

  /**
   * Address: 0x00B5F970 (FUN_00B5F970)
   *
   * What it does:
   * EH cleanup helper that runs the wx-region base unref tail on one stack
   * object lane.
   */
  void EhCleanupDestroyStackWxRegion(RuntimeWxObjectView* const regionStorage)
  {
    regionStorage->refData = nullptr;
  }

  /**
   * Address: 0x00B5F9A0 (FUN_00B5F9A0)
   *
   * What it does:
   * EH cleanup helper that releases one stack `wxString` shared payload lane.
   */
  void EhCleanupDestroyStackWxStringA(RuntimeWxStringView* const stringStorage)
  {
    DestroySharedWxStringRuntimePayload(stringStorage);
  }

  /**
   * Address: 0x00B6FD40 (FUN_00B6FD40)
   *
   * What it does:
   * EH cleanup helper that releases one stack `wxString` shared payload lane.
   */
  void EhCleanupDestroyStackWxStringB(RuntimeWxStringView* const stringStorage)
  {
    DestroySharedWxStringRuntimePayload(stringStorage);
  }

  /**
   * Address: 0x00B6FD48 (FUN_00B6FD48)
   *
   * What it does:
   * EH cleanup helper that releases one stack `wxString` shared payload lane.
   */
  void EhCleanupDestroyStackWxStringC(RuntimeWxStringView* const stringStorage)
  {
    DestroySharedWxStringRuntimePayload(stringStorage);
  }

  /**
   * Address: 0x00B6FD50 (FUN_00B6FD50)
   *
   * What it does:
   * EH cleanup helper that releases the adjacent `wxString` stack lane reached
   * from the incoming frame-base pointer.
   */
  void EhCleanupDestroyStackWxStringD(RuntimeWxStringView* const frameBaseAsString)
  {
    DestroySharedWxStringRuntimePayload(frameBaseAsString + 1);
  }

  /**
   * Address: 0x00B77300 (FUN_00B77300)
   *
   * What it does:
   * EH cleanup helper that unlocks one scoped mutex lock lane if ownership is
   * still active.
   */
  void EhCleanupUnlockScopedMutexA(RuntimeScopedMutexLockView* const scopedLock)
  {
    if (scopedLock->ownsLock != 0) {
      RuntimeUnlockMutex(scopedLock->mutex);
      scopedLock->ownsLock = 0;
    }
  }

  /**
   * Address: 0x00B77450 (FUN_00B77450)
   *
   * What it does:
   * EH cleanup helper that unlocks one scoped mutex lock lane if ownership is
   * still active.
   */
  void EhCleanupUnlockScopedMutexB(RuntimeScopedMutexLockView* const scopedLock)
  {
    if (scopedLock->ownsLock != 0) {
      RuntimeUnlockMutex(scopedLock->mutex);
      scopedLock->ownsLock = 0;
    }
  }

  /**
   * Address: 0x00B7748B (FUN_00B7748B)
   *
   * What it does:
   * EH cleanup helper that conditionally closes one owned handle and deletes
   * the owning cell.
   */
  void EhCleanupDestroyOwnedHandleCell(RuntimeOwnedHandleCell** const handleCellSlot)
  {
    RuntimeOwnedHandleCell* const handleCell = *handleCellSlot;
    if (handleCell != nullptr) {
      if (handleCell->shouldCloseHandle != 0) {
        ::CloseHandle(handleCell->handle);
      }
      ::operator delete(handleCell);
    }
  }

  /**
   * Address: 0x00B777E0 (FUN_00B777E0)
   *
   * What it does:
   * EH cleanup helper that leaves one critical section lane when the guard
   * still owns the lock.
   */
  void EhCleanupLeaveCriticalSection(RuntimeCriticalSectionLeaveGuard* const guard)
  {
    if (guard->shouldLeave != 0) {
      ::LeaveCriticalSection(guard->criticalSection);
    }
  }

  /**
   * Address: 0x00B915E0 (FUN_00B915E0)
   *
   * What it does:
   * EH cleanup helper that destroys one stack-local `std::string` lane.
   */
  void EhCleanupDestroyStdStringA(std::string* const stringStorage)
  {
    stringStorage->~basic_string();
  }

  /**
   * Address: 0x00B915E8 (FUN_00B915E8)
   *
   * What it does:
   * EH cleanup helper that destroys one stack-local `std::string` lane.
   */
  void EhCleanupDestroyStdStringB(std::string* const stringStorage)
  {
    stringStorage->~basic_string();
  }
} // namespace moho::runtime
