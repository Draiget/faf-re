// This translation unit re-implements CRT entry points (fprintf, _vsnprintf_l,
// etc.) that the UCRT headers otherwise provide as inline definitions. Suppress
// those inline bodies so the recovered definitions below are the sole ones.
#define _NO_CRT_STDIO_INLINE

#include <Windows.h>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/misc/DName.h"
#include "moho/misc/WeakPtr.h"

#include <bit>
#include <algorithm>
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
#include <cwctype>
#include <exception>
#include <fstream>
#include <float.h>
#include <io.h>
#include <ios>
#include <intrin.h>
#include <limits>
#include <locale>
#include <list>
#include <mutex>
#include <new>
#include <streambuf>
#include <sstream>
#include <cstdarg>
#include <stdexcept>
#include <string>
#include <sys/timeb.h>
#include <typeinfo>

#include <boost/thread/exceptions.hpp>
#include <boost/mutex.h>

// CRT headers expose a subset of ctype entry points as macros (for example
// `_isalpha_l` -> `_ischartype_l`). This translation unit provides recovered
// function bodies with the canonical symbol names, so we must disable those
// macro spellings before declaring the functions.
#ifdef _isalpha_l
#undef _isalpha_l
#endif
#ifdef isalpha
#undef isalpha
#endif
#ifdef _isupper_l
#undef _isupper_l
#endif
#ifdef isupper
#undef isupper
#endif
#ifdef _islower_l
#undef _islower_l
#endif
#ifdef islower
#undef islower
#endif
#ifdef _isdigit_l
#undef _isdigit_l
#endif
#ifdef isdigit
#undef isdigit
#endif
#ifdef _isxdigit_l
#undef _isxdigit_l
#endif
#ifdef isxdigit
#undef isxdigit
#endif
#ifdef _isspace_l
#undef _isspace_l
#endif
#ifdef isspace
#undef isspace
#endif
#ifdef _ispunct_l
#undef _ispunct_l
#endif
#ifdef ispunct
#undef ispunct
#endif
#ifdef _isalnum_l
#undef _isalnum_l
#endif
#ifdef isalnum
#undef isalnum
#endif
#ifdef _isprint_l
#undef _isprint_l
#endif
#ifdef isprint
#undef isprint
#endif
#ifdef _isgraph_l
#undef _isgraph_l
#endif
#ifdef isgraph
#undef isgraph
#endif
#ifdef _iscntrl_l
#undef _iscntrl_l
#endif
#ifdef iscntrl
#undef iscntrl
#endif
#ifdef _pctype
#undef _pctype
#endif
#ifdef _pwctype
#undef _pwctype
#endif
#ifdef __mb_cur_max
#undef __mb_cur_max
#endif

extern "C" void __cdecl _lock(int locknum);
extern "C" void __cdecl _unlock(int locknum);
extern "C" int __cdecl _filbuf(std::FILE* stream);
extern "C" int __cdecl get_errno_from_oserr(unsigned long osErrorCode);
extern "C" void __cdecl _lock_file(std::FILE* stream);
extern "C" void __cdecl __lock_file2(int streamIndex, std::FILE* stream);
extern "C" void __cdecl __unlock_file2(int streamIndex, std::FILE* stream);
extern "C" int __cdecl _fflush_nolock(std::FILE* stream);
extern "C" int __cdecl _fclose_nolock(std::FILE* stream);
extern "C" wint_t __cdecl _ungetwc_nolock(wint_t wideCharacter, std::FILE* stream);
extern "C" wchar_t __cdecl putwch_nolock(wchar_t wideCharacter);
extern "C" int __cdecl _getdrive();
extern "C" void __cdecl _dosmaperr(unsigned long osErrorCode);
extern "C" int __cdecl _get_winmajor(unsigned int* majorVersion);
extern "C" lconv* __cdecl RuntimeGetlconv();
extern "C" int __cdecl _tsopen_helper(
  const char* fileName,
  int openFlags,
  int shareFlags,
  int permissionFlags,
  int* outFileHandle,
  int secureMode
);
extern "C" int __cdecl _tsopen_nolock(
  int* outFileHandle,
  int* unlockFlag,
  const char* fileName,
  int openFlags,
  int shareFlags,
  int permissionFlags
);
extern "C" void __cdecl _unlock_fhandle(int fileDescriptor);
extern "C" int __cdecl _alloc_osfhnd();
extern "C" int __cdecl _free_osfhnd(int fileDescriptor);
extern "C" BOOL __cdecl _lock_fhandle(int fileDescriptor);
// Not named `_get_osfhandle`: that symbol is a real public UCRT export
// (corecrt_io.h, returns intptr_t) whose own internal fd table is unrelated
// to this project's __pioinfo; a same-name redeclaration with a different
// return type is a hard compile error, and even a compatible-signature
// redeclaration would silently resolve to the wrong (host-toolchain) table.
extern "C" HANDLE __cdecl RuntimeGetOsfHandle(int fileDescriptor);
extern "C" long __cdecl _lseek_nolock(int fileDescriptor, long offset, int moveMethod);
extern "C" __int64 __cdecl _lseeki64_nolock(int fileDescriptor, __int64 offset, int moveMethod);
extern "C" int __cdecl _close_nolock(int fileDescriptor);
extern "C" int __cdecl _setmode_nolock(int fileDescriptor, int mode);
extern "C" int __cdecl _write_nolock(int fileDescriptor, const char* buffer, unsigned int count);
extern "C" int __cdecl _write(int fileDescriptor, const void* buffer, unsigned int count);
extern "C" unsigned int __cdecl _read_nolock(int fileDescriptor, char* buffer, unsigned int count);
extern "C" int __cdecl _wsopen_nolock(
  int* outFileHandle,
  int* unlockFlag,
  const wchar_t* fileName,
  int openFlags,
  int shareFlags,
  int permissionFlags
);
constexpr int kOsfhndLock = 11;  // _OSFHND_LOCK, confirmed via `push 0Bh` at 0x00AAF529
constexpr int kLocktabLock = 10; // _LOCKTAB_LOCK, confirmed via `push 0Ah` at 0x00A96C26
extern "C" int __cdecl RuntimeInitCrtLockNumber(int lockId);
extern "C" void __cdecl RuntimeLockCrtLock(int lockId);
extern "C" int __cdecl _isatty(int fileDescriptor);
extern "C" int __cdecl isleadbyte(int character);
extern "C" errno_t __cdecl _chsize_nolock(int fileDescriptor, __int64 size);
extern "C" int _nhandle;
extern "C" int _commode;
extern "C" int _cflush;
extern "C" int _fmode;
extern "C" unsigned int _nstream;
extern "C" std::FILE** __piob;
extern "C" unsigned char _exitflag;
extern "C" std::uintptr_t __security_cookie;
extern "C" std::uintptr_t __enable_percent_n;
extern "C" int global_compat_flag;
/**
 * Address: 0x00A89E54 (FUN_00A89E54, __iob_func)
 *
 * What it does:
 * Returns the base address of the legacy CRT `_iob` stream array.
 */
extern "C" std::FILE* __cdecl __iob_func(void);
extern "C" std::FILE* __cdecl _getstream();
extern "C" void __cdecl __alloca_probe();
extern "C" int __cdecl _vsnwprintf_l(
  wchar_t* buffer,
  std::size_t bufferCount,
  const wchar_t* format,
  _locale_t locale,
  va_list argList
);
extern "C" std::size_t __cdecl _wcsftime_l(
  wchar_t* buffer,
  std::size_t bufferCount,
  const wchar_t* format,
  const std::tm* timeData,
  _locale_t locale
);
extern "C" int __cdecl _stricmp(const char* lhs, const char* rhs);
/**
 * Address: 0x00A89D6B (FUN_00A89D6B, __get_sys_err_msg)
 *
 * What it does:
 * Bounds-checks the requested errno lane and returns the corresponding legacy
 * system-error message pointer, falling back to the final "Unknown error" slot.
 */
extern "C" const char* __cdecl _get_sys_err_msg(int errorCode);
extern "C" void* __cdecl _calloc_crt(std::size_t num, std::size_t size);
extern "C" void __cdecl __amsg_exit(int runtimeMessageId);
extern "C" void* __cdecl _decode_pointer(void* encodedPointer);
extern "C" unsigned long __flsindex;
extern "C" void* gpFlsSetValue;
using RuntimeFlsGetValueFn = void* (__stdcall*)(unsigned long flsIndex);
extern "C" RuntimeFlsGetValueFn __cdecl __set_flsgetvalue();
extern "C" void __cdecl __initptd(void* ptd, void* initData);
extern "C" void __cdecl _free_crt(void* ptr);
extern "C" void __cdecl _tzset_nolock();
extern "C" void __cdecl _tzset();
extern "C" BOOL __cdecl _isindst(std::tm* brokenDownTime);
extern "C" int __mbctype_initialized;
extern "C" int __cdecl __initmbctable();
extern "C" int __cdecl _ismbblead(unsigned int value);
extern "C" BOOL __cdecl __local_unwind4(void* registrationFrame, int currentTryLevel, unsigned int targetTryLevel);
extern "C" int __cdecl __local_unwind2(void* registrationFrame, unsigned int targetTryLevel);
extern "C" void __cdecl __FrameUnwindToState(
  void* registrationNode,
  void* dispatcherContext,
  const void* functionInfo,
  int targetState
);
extern "C" char* _acmdln;
extern "C" char* _aenvptr;
extern "C" char** _environ;
extern "C" int __env_initialized;
extern "C" __declspec(dllimport) LPCH WINAPI GetEnvironmentStringsA(void);

/**
 * Address: 0x00AA653A (FUN_00AA653A, __init_collate)
 *
 * What it does:
 * Preserves one CRT locale-collation startup lane as a success no-op.
 */
extern "C" int __cdecl __init_collate()
{
  return 0;
}

/**
 * Address: 0x00ACE110 (FUN_00ACE110, _SFUO_Init -- non-canonical helper lane)
 *
 * What it does:
 * Preserves one CRT SFUO startup lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Init()
{
  return 0;
}

/**
 * Address: 0x00ACE120 (FUN_00ACE120, _SFUO_Finish -- non-canonical helper lane)
 *
 * What it does:
 * Preserves one CRT SFUO finish lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Finish()
{
  return 0;
}

/**
 * Address: 0x00ACE2E0 (FUN_00ACE2E0, _SFUO_Destroy -- non-canonical helper lane)
 *
 * What it does:
 * Preserves one CRT SFUO teardown lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Destroy()
{
  return 0;
}

/**
 * Address: 0x0076C730 (FUN_0076C730, the 12-byte-element
 * `LegacyVectorStorage<moho::OccupySourceBinding>` throw lane; reached from
 * `InsertOccupySourceBindingRange`, FUN_0076C490, PathTables.cpp)
 *
 * What it does:
 * Generic `std::length_error("... too long")` thrower shared by the
 * hand-rolled `LegacyVectorStorage<T>`-based grow lanes that live outside
 * the `msvc8::vector<T>` class template (see `throw_too_long()` in
 * `legacy/containers/Vector.h` for the class-template's own equivalent).
 * Each real binary throw lane is a byte-identical
 * `std::logic_error`-then-vftable-patch-to-`length_error` emission
 * differing only in the message literal; this consolidates them into one
 * parametrized helper, with each real address cited at its call site.
 */
// Container/runtime helpers invoked from both the CRT prelude and the
// moho::runtime block; defined at file scope so unqualified calls in either
// region resolve to this single definition. The parameter must be spelled
// `const char*`, not `const char* const` - MSVC's 32-bit decorated name
// encodes top-level const on a by-value pointer parameter (PBD vs QBD),
// so the two forms are different link symbols even though they're the same
// C++ overload. Unit.cpp/CWldSession.cpp/PathTables.cpp's forward
// declarations all use the plain form; this must match or every one of
// them is a permanently-unresolved external.
[[noreturn]] void RuntimeThrowContainerTooLong(const char* message)
{
  throw std::length_error(message);
}

namespace
{
  int gRuntimeErrorMode = 0;
  int gRuntimeAbortBehavior = 0;

  constexpr std::intptr_t kRuntimeUninitializedConsoleHandleValue = -2;

  [[nodiscard]] inline HANDLE RuntimeUninitializedConsoleHandle() noexcept
  {
    return reinterpret_cast<HANDLE>(kRuntimeUninitializedConsoleHandleValue);
  }

  [[nodiscard]] inline bool RuntimeConsoleHandleIsClosable(const HANDLE handle) noexcept
  {
    return handle != INVALID_HANDLE_VALUE && handle != RuntimeUninitializedConsoleHandle();
  }

  HANDLE gConsoleOutputHandle = RuntimeUninitializedConsoleHandle();
  HANDLE gConsoleInputHandle = RuntimeUninitializedConsoleHandle();
}

/**
 * Address: 0x00A90EB7 (FUN_00A90EB7)
 *
 * What it does:
 * Applies one masked update to the CRT abort-behavior lane and returns the
 * previous behavior value.
 */
extern "C" int __cdecl RuntimeSetAbortBehaviorMasked(
  const int value,
  const int mask
)
{
  const int previous = gRuntimeAbortBehavior;
  gRuntimeAbortBehavior = (mask & value) | (gRuntimeAbortBehavior & ~mask);
  return previous;
}

// Modern UCRT exposes `_iobuf` as an opaque single-pointer struct, but the
// FAF CRT helpers (and the binaries they wrap) treat `std::FILE` as the
// classic 32-byte VC8 layout below. This view lets us reach the legacy
// fields through reinterpret_cast without depending on the corecrt header
// shape.
struct LegacyFileView
{
  char* _ptr;
  int   _cnt;
  char* _base;
  int   _flag;
  int   _file;
  int   _charbuf;
  int   _bufsiz;
  char* _tmpfname;
};
static_assert(sizeof(LegacyFileView) == 0x20, "LegacyFileView size must be 0x20");

[[nodiscard]] inline LegacyFileView& legacy_file(std::FILE* const stream) noexcept
{
  return *reinterpret_cast<LegacyFileView*>(stream);
}

[[nodiscard]] inline LegacyFileView& legacy_file(std::FILE& stream) noexcept
{
  return *reinterpret_cast<LegacyFileView*>(&stream);
}

namespace
{
  using AcrtIobFunc = std::FILE* (__cdecl*)(unsigned int);

  [[nodiscard]] AcrtIobFunc ResolveAcrtIobFunc() noexcept
  {
    static AcrtIobFunc sResolved = []() noexcept -> AcrtIobFunc {
      HMODULE const ucrtModule = ::GetModuleHandleA("ucrtbase.dll");
      if (ucrtModule == nullptr) {
        return nullptr;
      }
      return reinterpret_cast<AcrtIobFunc>(::GetProcAddress(ucrtModule, "__acrt_iob_func"));
    }();
    return sResolved;
  }

  [[nodiscard]] LegacyFileView* LegacyIobFallbackBase() noexcept
  {
    static LegacyFileView sLegacyIob[20]{};
    return sLegacyIob;
  }
}

/**
 * Address: 0x00A89E54 (FUN_00A89E54, __iob_func)
 *
 * What it does:
 * Returns the base stream lane used by legacy CRT `_iob` callers.
 */
extern "C" std::FILE* __cdecl __iob_func(void)
{
  if (const AcrtIobFunc acrtIob = ResolveAcrtIobFunc(); acrtIob != nullptr) {
    return acrtIob(0u);
  }

  return reinterpret_cast<std::FILE*>(LegacyIobFallbackBase());
}

struct RuntimePmd
{
  int mdisp;
  int pdisp;
  int vdisp;
};
static_assert(sizeof(RuntimePmd) == 0x0C, "RuntimePmd size must be 0x0C");

struct RuntimeRttiClassHierarchyDescriptor;

struct RuntimeRttiBaseClassDescriptor
{
  const std::type_info* typeDescriptor;
  std::uint32_t numContainedBases;
  RuntimePmd pmd;
  std::uint32_t attributes;
  RuntimeRttiClassHierarchyDescriptor* classHierarchyDescriptor;
};
static_assert(sizeof(RuntimeRttiBaseClassDescriptor) == 0x1C, "RuntimeRttiBaseClassDescriptor size must be 0x1C");
static_assert(
  offsetof(RuntimeRttiBaseClassDescriptor, typeDescriptor) == 0x00,
  "RuntimeRttiBaseClassDescriptor::typeDescriptor offset must be 0x00"
);
static_assert(
  offsetof(RuntimeRttiBaseClassDescriptor, numContainedBases) == 0x04,
  "RuntimeRttiBaseClassDescriptor::numContainedBases offset must be 0x04"
);
static_assert(offsetof(RuntimeRttiBaseClassDescriptor, pmd) == 0x08, "RuntimeRttiBaseClassDescriptor::pmd offset must be 0x08");
static_assert(
  offsetof(RuntimeRttiBaseClassDescriptor, attributes) == 0x14,
  "RuntimeRttiBaseClassDescriptor::attributes offset must be 0x14"
);
static_assert(
  offsetof(RuntimeRttiBaseClassDescriptor, classHierarchyDescriptor) == 0x18,
  "RuntimeRttiBaseClassDescriptor::classHierarchyDescriptor offset must be 0x18"
);

struct RuntimeRttiClassHierarchyDescriptor
{
  std::uint32_t signature;
  std::uint32_t attributes;
  std::uint32_t numBaseClasses;
  RuntimeRttiBaseClassDescriptor** baseClassArray;
};
static_assert(sizeof(RuntimeRttiClassHierarchyDescriptor) == 0x10, "RuntimeRttiClassHierarchyDescriptor size must be 0x10");
static_assert(
  offsetof(RuntimeRttiClassHierarchyDescriptor, numBaseClasses) == 0x08,
  "RuntimeRttiClassHierarchyDescriptor::numBaseClasses offset must be 0x08"
);
static_assert(
  offsetof(RuntimeRttiClassHierarchyDescriptor, baseClassArray) == 0x0C,
  "RuntimeRttiClassHierarchyDescriptor::baseClassArray offset must be 0x0C"
);

/**
 * Address: 0x008D8590 (FUN_008D8590, func_StringGreater)
 *
 * What it does:
 * Provides strict lexical ordering for runtime string-map lanes used by CRT
 * type-info map insertion.
 */
extern "C" bool __stdcall RuntimeTypeInfoStringLess(const char* const lhsText, const char* const rhsText)
{
  return std::strcmp(lhsText, rhsText) < 0;
}

struct RuntimeIoInfo
{
  std::intptr_t osfhnd;        // +0x00
  std::uint8_t osfile;         // +0x04
  std::uint8_t pipech;         // +0x05, one-char pushback for text-mode reads
  std::uint8_t pipech2[2];     // +0x06, second/third pushback byte for wide-char reads
  std::int32_t lockinitflag;   // +0x08
  CRITICAL_SECTION lock;       // +0x0C, per-fd lock lazily initialized via lockinitflag
  std::int8_t textmodeUnicode; // +0x24
  std::uint8_t reserved25[0x13];
};
static_assert(offsetof(RuntimeIoInfo, osfhnd) == 0x00, "RuntimeIoInfo::osfhnd offset must be 0x00");
static_assert(offsetof(RuntimeIoInfo, osfile) == 0x04, "RuntimeIoInfo::osfile offset must be 0x04");
static_assert(offsetof(RuntimeIoInfo, pipech) == 0x05, "RuntimeIoInfo::pipech offset must be 0x05");
static_assert(offsetof(RuntimeIoInfo, pipech2) == 0x06, "RuntimeIoInfo::pipech2 offset must be 0x06");
static_assert(offsetof(RuntimeIoInfo, lockinitflag) == 0x08, "RuntimeIoInfo::lockinitflag offset must be 0x08");
static_assert(offsetof(RuntimeIoInfo, lock) == 0x0C, "RuntimeIoInfo::lock offset must be 0x0C");
static_assert(offsetof(RuntimeIoInfo, textmodeUnicode) == 0x24, "RuntimeIoInfo::textmodeUnicode offset must be 0x24");
static_assert(sizeof(RuntimeIoInfo) == 0x38, "RuntimeIoInfo size must be 0x38");
extern "C" RuntimeIoInfo __badioinfo;
extern "C" RuntimeIoInfo* __pioinfo[];
extern "C" unsigned int umaskval;
struct RuntimeThreadLocInfo
{
  volatile long refcount;
};

struct RuntimeLcTimeData
{
  const char* wday_abbr[7]; // +0x00
  const char* wday[7];      // +0x1C
  const char* month_abbr[12]; // +0x38
  const char* month[12];      // +0x68
  const char* ampm[2];        // +0x98
  const char* ww_sdatefmt;    // +0xA0
  const char* ww_ldatefmt;    // +0xA4
  const char* ww_timefmt;     // +0xA8
  std::int32_t ww_caltype;    // +0xAC
  LCID ww_lcid;               // +0xB0
  std::int32_t refcount;      // +0xB4
};
static_assert(offsetof(RuntimeLcTimeData, wday_abbr) == 0x00, "RuntimeLcTimeData::wday_abbr offset must be 0x00");
static_assert(offsetof(RuntimeLcTimeData, wday) == 0x1C, "RuntimeLcTimeData::wday offset must be 0x1C");
static_assert(offsetof(RuntimeLcTimeData, month_abbr) == 0x38, "RuntimeLcTimeData::month_abbr offset must be 0x38");
static_assert(offsetof(RuntimeLcTimeData, month) == 0x68, "RuntimeLcTimeData::month offset must be 0x68");
static_assert(offsetof(RuntimeLcTimeData, ampm) == 0x98, "RuntimeLcTimeData::ampm offset must be 0x98");
static_assert(offsetof(RuntimeLcTimeData, ww_sdatefmt) == 0xA0, "RuntimeLcTimeData::ww_sdatefmt offset must be 0xA0");
static_assert(offsetof(RuntimeLcTimeData, ww_ldatefmt) == 0xA4, "RuntimeLcTimeData::ww_ldatefmt offset must be 0xA4");
static_assert(offsetof(RuntimeLcTimeData, ww_timefmt) == 0xA8, "RuntimeLcTimeData::ww_timefmt offset must be 0xA8");
static_assert(offsetof(RuntimeLcTimeData, ww_caltype) == 0xAC, "RuntimeLcTimeData::ww_caltype offset must be 0xAC");
static_assert(offsetof(RuntimeLcTimeData, ww_lcid) == 0xB0, "RuntimeLcTimeData::ww_lcid offset must be 0xB0");
static_assert(offsetof(RuntimeLcTimeData, refcount) == 0xB4, "RuntimeLcTimeData::refcount offset must be 0xB4");
static_assert(sizeof(RuntimeLcTimeData) == 0xB8, "RuntimeLcTimeData size must be 0xB8");

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
 * Address: 0x00A8C397 (FUN_00A8C397, ___addlocaleref)
 *
 * What it does:
 * Increments one thread-locale payload refcount lane.
 */
extern "C" void __cdecl __addlocaleref(RuntimeThreadLocInfo* locinfo);
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
/**
 * Address: 0x00AA551D (FUN_00AA551D, _get_lc_time)
 *
 * What it does:
 * Populates one CRT locale-time table (`__lc_time_data`) from locale-info
 * providers for weekday/month names, AM/PM strings, date/time formats, and
 * calendar type.
 */
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
/**
 * Address: 0x00AA54F4 (FUN_00AA54F4, __pctype_func)
 *
 * What it does:
 * Returns one pointer to the active thread-locale ctype table.
 */
extern "C" const std::uint16_t* __cdecl __pctype_func();
/**
 * Address: 0x00AA54EE (FUN_00AA54EE, __pwctype_func)
 *
 * What it does:
 * Returns one pointer to the process-global wide-ctype lookup table lane.
 */
extern "C" const wctype_t* __cdecl __pwctype_func();
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
extern "C" int __cdecl __crtCompareStringA(
  _locale_t localeInfo,
  LCID locale,
  unsigned int compareFlags,
  LPCCH lhsText,
  int lhsCount,
  LPCCH rhsText,
  int rhsCount,
  int codePage
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
extern "C" int __cdecl _iswctype_l(wint_t character, wctype_t characterClass, _locale_t localeInfo);
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
  std::int32_t lcCollateCp;    // +0x08
  LCID lcHandle[6];            // +0x0C, per-category locale handles (matches
                                // RuntimeLocaleUpdateScope::CollateView)
};
static_assert(offsetof(RuntimeLocaleCodePageView, codepage) == 0x4, "RuntimeLocaleCodePageView::codepage offset must be 0x4");
static_assert(offsetof(RuntimeLocaleCodePageView, lcCollateCp) == 0x8, "RuntimeLocaleCodePageView::lcCollateCp offset must be 0x8");
static_assert(offsetof(RuntimeLocaleCodePageView, lcHandle) == 0xC, "RuntimeLocaleCodePageView::lcHandle offset must be 0xC");

struct RuntimeLocaleCTypeTableView
{
  std::uint8_t reserved00_C7[0xC8];
  const std::uint16_t* pctype;
};
static_assert(
  offsetof(RuntimeLocaleCTypeTableView, pctype) == 0xC8,
  "RuntimeLocaleCTypeTableView::pctype offset must be 0xC8"
);

struct RuntimeLocaleClassificationView
{
  std::uint8_t reserved00_AB[0xAC];
  std::int32_t mbCurMax;
  std::uint8_t reservedB0_C7[0x18];
  const std::uint16_t* pctype;
};
static_assert(
  offsetof(RuntimeLocaleClassificationView, mbCurMax) == 0xAC,
  "RuntimeLocaleClassificationView::mbCurMax offset must be 0xAC"
);
static_assert(
  offsetof(RuntimeLocaleClassificationView, pctype) == 0xC8,
  "RuntimeLocaleClassificationView::pctype offset must be 0xC8"
);

struct RuntimeLocaleLegacySyncView
{
  std::int32_t reserved00;
  std::int32_t lcCodepage;
  std::int32_t lcCollateCodepage;
  std::uint8_t reserved0C_A7[0x9C];
  std::int32_t lcClike;
  std::int32_t mbCurMax;
  std::uint8_t reservedB0_BB[0x0C];
  lconv* localeConventions;
  std::uint8_t reservedC0_C7[0x8];
  const std::uint16_t* pctype;
  std::uint8_t reservedCC_D3[0x8];
  RuntimeLcTimeData* lcTimeCurrent;
};
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, lcCodepage) == 0x04,
  "RuntimeLocaleLegacySyncView::lcCodepage offset must be 0x04"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, lcCollateCodepage) == 0x08,
  "RuntimeLocaleLegacySyncView::lcCollateCodepage offset must be 0x08"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, lcClike) == 0xA8,
  "RuntimeLocaleLegacySyncView::lcClike offset must be 0xA8"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, mbCurMax) == 0xAC,
  "RuntimeLocaleLegacySyncView::mbCurMax offset must be 0xAC"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, localeConventions) == 0xBC,
  "RuntimeLocaleLegacySyncView::localeConventions offset must be 0xBC"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, pctype) == 0xC8,
  "RuntimeLocaleLegacySyncView::pctype offset must be 0xC8"
);
static_assert(
  offsetof(RuntimeLocaleLegacySyncView, lcTimeCurrent) == 0xD4,
  "RuntimeLocaleLegacySyncView::lcTimeCurrent offset must be 0xD4"
);

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

struct RuntimeFrameInfoNode
{
  std::int32_t objectState;            // +0x00
  RuntimeFrameInfoNode* next = nullptr; // +0x04
};
static_assert(sizeof(RuntimeFrameInfoNode) == 0x8, "RuntimeFrameInfoNode size must be 0x8");
static_assert(offsetof(RuntimeFrameInfoNode, objectState) == 0x0, "RuntimeFrameInfoNode::objectState offset must be 0x0");
static_assert(offsetof(RuntimeFrameInfoNode, next) == 0x4, "RuntimeFrameInfoNode::next offset must be 0x4");

struct RuntimeTidDataLocaleView
{
  std::uint8_t reserved00[0x68];
  // +0x68/+0x6C read back-to-back by _LocaleUpdate::_LocaleUpdate (0x00A83031)
  // as `mov ecx,[eax+6Ch]` / `mov ecx,[eax+68h]`.
  RuntimeThreadMbcInfo* ptmbcinfo;
  RuntimeLocaleCodePageView* ptlocinfo;
  std::int32_t ownlocale;
  std::uint8_t reserved74[0x24];
  RuntimeFrameInfoNode* frameInfoChain;
  RuntimeSetLocLocaleView setlocData;
};
static_assert(offsetof(RuntimeTidDataLocaleView, ptmbcinfo) == 0x68, "RuntimeTidDataLocaleView::ptmbcinfo offset must be 0x68");
static_assert(offsetof(RuntimeTidDataLocaleView, ptlocinfo) == 0x6C, "RuntimeTidDataLocaleView::ptlocinfo offset must be 0x6C");
static_assert(offsetof(RuntimeTidDataLocaleView, ownlocale) == 0x70, "RuntimeTidDataLocaleView::ownlocale offset must be 0x70");
static_assert(offsetof(RuntimeTidDataLocaleView, frameInfoChain) == 0x98, "RuntimeTidDataLocaleView::frameInfoChain offset must be 0x98");
static_assert(offsetof(RuntimeTidDataLocaleView, setlocData) == 0x9C, "RuntimeTidDataLocaleView::setlocData offset must be 0x9C");

struct RuntimeThreadMbcInfoCaseView
{
  std::uint8_t reserved00_03[0x4];
  std::uint32_t mbcodepage;
  std::uint32_t ismbcodepage;
  LCID mblcid;
  std::uint16_t mbulinfo[6];
  std::uint8_t mbctype[0x101];
  std::uint8_t mbcasemap[0x100];
};
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbcodepage) == 0x4, "RuntimeThreadMbcInfoCaseView::mbcodepage offset must be 0x4");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, ismbcodepage) == 0x8, "RuntimeThreadMbcInfoCaseView::ismbcodepage offset must be 0x8");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mblcid) == 0xC, "RuntimeThreadMbcInfoCaseView::mblcid offset must be 0xC");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbulinfo) == 0x10, "RuntimeThreadMbcInfoCaseView::mbulinfo offset must be 0x10");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbctype) == 0x1C, "RuntimeThreadMbcInfoCaseView::mbctype offset must be 0x1C");
static_assert(offsetof(RuntimeThreadMbcInfoCaseView, mbcasemap) == 0x11D, "RuntimeThreadMbcInfoCaseView::mbcasemap offset must be 0x11D");

extern "C" RuntimeLocaleCodePageView* __ptlocinfo;
extern "C" std::int32_t __lc_codepage;
extern "C" std::int32_t __lc_collate_cp;
extern "C" std::int32_t __lc_clike;
extern "C" RuntimeLcTimeData* __lc_time_curr;
extern "C" lconv* __lconv;
extern "C" const std::uint16_t* _pctype;
extern "C" std::int32_t __mb_cur_max;
extern "C" std::int32_t __globallocalestatus;
extern "C" RuntimeTidDataLocaleView* __cdecl __getptd();
extern "C" RuntimeLocaleCodePageView* __cdecl __updatetlocinfo();
extern "C" RuntimeThreadMbcInfo* __ptmbcinfo;
extern "C" RuntimeThreadMbcInfo* __cdecl __updatetmbcinfo();
extern "C" int _getvalueindex;
extern "C" void __cdecl _freefls(void* ptd);
extern "C" int __cdecl _flsbuf(int character, std::FILE* stream);
extern "C" void __cdecl _getbuf(std::FILE* stream);
extern "C" int __cdecl _isctype_l(int character, int mask, _locale_t localeInfo);
extern "C" int __cdecl _isleadbyte_l(int character, _locale_t localeInfo);

/**
 * Modern RAII spelling of the CRT's internal `_LocaleUpdate` guard.
 *
 * Construction lane: 0x00A83031 (FUN_00A83031,
 * ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z). The destructor is emitted
 * inline at every use site rather than as its own body, which is why the
 * `updated` release lane appears open-coded in each `*_l` decompile.
 *
 * Layout matches the binary object exactly: `locinfo` +0x00, `mbcinfo` +0x04,
 * `thread` +0x08, `updated` +0x0C.
 *
 * Behaviour, straight from the construction lane:
 *  - an explicit `_locale_t` copies both payload pointers and takes no
 *    thread reference at all (nothing to release on scope exit),
 *  - a null `_locale_t` reads the per-thread payloads, refreshes either one
 *    that has drifted from the process-wide lane while this thread does not
 *    already own a per-thread locale, and then claims the per-thread locale
 *    bit -- recording that claim so the destructor releases it.
 */
class RuntimeLocaleUpdateScope
{
public:
  explicit RuntimeLocaleUpdateScope(_locale_t const explicitLocale) noexcept
  {
    if (explicitLocale != nullptr) {
      const auto* const handle = reinterpret_cast<const RuntimeLocaleHandle*>(explicitLocale);
      locinfo_ = reinterpret_cast<RuntimeLocaleCodePageView*>(handle->locinfo);
      mbcinfo_ = handle->mbcinfo;
      return;
    }

    thread_ = __getptd();
    locinfo_ = thread_->ptlocinfo;
    mbcinfo_ = thread_->ptmbcinfo;

    if (locinfo_ != __ptlocinfo && (thread_->ownlocale & __globallocalestatus) == 0) {
      locinfo_ = __updatetlocinfo();
    }
    if (mbcinfo_ != __ptmbcinfo && (thread_->ownlocale & __globallocalestatus) == 0) {
      mbcinfo_ = __updatetmbcinfo();
    }

    if ((thread_->ownlocale & kPerThreadLocaleBit) == 0) {
      thread_->ownlocale |= kPerThreadLocaleBit;
      updated_ = true;
    }
  }

  ~RuntimeLocaleUpdateScope()
  {
    if (updated_ && thread_ != nullptr) {
      thread_->ownlocale &= ~kPerThreadLocaleBit;
    }
  }

  RuntimeLocaleUpdateScope(const RuntimeLocaleUpdateScope&) = delete;
  RuntimeLocaleUpdateScope& operator=(const RuntimeLocaleUpdateScope&) = delete;

  /**
   * Narrow-locale payload lane as read by the collation helpers:
   * `lc_codepage` +0x04, `lc_collate_cp` +0x08, `lc_handle[]` +0x0C.
   */
  struct CollateView
  {
    std::int32_t refcount;        // +0x00
    std::int32_t lcCodepage;      // +0x04
    std::int32_t lcCollateCp;     // +0x08
    LCID lcHandle[6];             // +0x0C
  };
  static_assert(offsetof(CollateView, lcCollateCp) == 0x08, "CollateView::lcCollateCp offset must be 0x08");
  static_assert(offsetof(CollateView, lcHandle) == 0x0C, "CollateView::lcHandle offset must be 0x0C");

  /** Narrow-locale payload for the effective locale. */
  [[nodiscard]] const CollateView* loc() const noexcept
  {
    return reinterpret_cast<const CollateView*>(locinfo_);
  }

  /**
   * Legacy-sync view of the effective locale, for lanes that need the
   * `lc_time_curr` (+0xD4) weekday/month/format table pointer (e.g.
   * `__Getdays_l`/`__Getmonths_l`).
   */
  [[nodiscard]] const RuntimeLocaleLegacySyncView* timeView() const noexcept
  {
    return reinterpret_cast<const RuntimeLocaleLegacySyncView*>(locinfo_);
  }

  /** Raw `_locale_t` view of this scope, for forwarding to nested `*_l` lanes. */
  [[nodiscard]] _locale_t asLocale() const noexcept
  {
    return reinterpret_cast<_locale_t>(const_cast<RuntimeLocaleUpdateScope*>(this));
  }

  /** Multibyte code-page payload for the effective locale. */
  [[nodiscard]] const RuntimeThreadMbcInfoCaseView* mbc() const noexcept
  {
    return reinterpret_cast<const RuntimeThreadMbcInfoCaseView*>(mbcinfo_);
  }

  /** True when the effective locale uses a multibyte code page. */
  [[nodiscard]] bool isMultibyteCodePage() const noexcept
  {
    const RuntimeThreadMbcInfoCaseView* const info = mbc();
    return info != nullptr && info->ismbcodepage != 0u;
  }

  /** True when `byteValue` is a DBCS lead byte under the effective locale. */
  [[nodiscard]] bool isLeadByte(const unsigned int byteValue) const noexcept
  {
    return (mbc()->mbctype[(byteValue & 0xFFu) + 1u] & 0x4u) != 0u;
  }

private:
  static constexpr std::int32_t kPerThreadLocaleBit = 2;

  RuntimeLocaleCodePageView* locinfo_ = nullptr;  // +0x00
  RuntimeThreadMbcInfo* mbcinfo_ = nullptr;       // +0x04
  RuntimeTidDataLocaleView* thread_ = nullptr;    // +0x08
  bool updated_ = false;                          // +0x0C
};
extern "C" RuntimeLocaleCodePageView* __cdecl _updatetlocinfoEx_nolock(
  RuntimeLocaleCodePageView** threadLocale,
  RuntimeLocaleCodePageView* processLocale);
extern "C" int __cdecl _stbuf(std::FILE* stream);
extern "C" void __cdecl _ftbuf(int scratchAllocated, std::FILE* stream);
extern "C" int __cdecl _setmbcp(int codePageMode);
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
using RuntimeInvalidArgHandler = void(__cdecl*)(
  const wchar_t* expression,
  const wchar_t* functionName,
  const wchar_t* fileName,
  unsigned int lineNumber,
  std::uintptr_t reserved
);
using RuntimePurecallHandler = void(__cdecl*)();
using RuntimeHeapFailureHandler = int(__cdecl*)(std::size_t);
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
extern "C" int __cdecl _wcsicmp_l(const wchar_t* lhsText, const wchar_t* rhsText, _locale_t localeInfo);
extern "C" int __cdecl _wcsnicoll_l(
  const wchar_t* lhsText,
  const wchar_t* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _mbsnbcmp_l(
  const unsigned char* lhsText,
  const unsigned char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _mbsnbicmp_l(
  const unsigned char* lhsText,
  const unsigned char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" unsigned char* __cdecl _mbschr_l(const unsigned char* text, unsigned int ch, _locale_t localeInfo);
extern "C" unsigned char* __cdecl _mbspbrk_l(
  const unsigned char* text,
  const unsigned char* accept,
  _locale_t localeInfo
);
extern "C" wint_t __cdecl _fputwc_nolock(wchar_t wideChar, std::FILE* stream);
extern "C" unsigned char* __cdecl _mbsrchr_l(const unsigned char* text, unsigned int ch, _locale_t localeInfo);
extern "C" int __cdecl _wcstombs_s_l(
  std::size_t* retValue,
  char* destination,
  std::size_t sizeInBytes,
  const wchar_t* wideSource,
  std::size_t maxWideChars,
  _locale_t localeInfo
);
extern "C" std::size_t __cdecl _mbstowcs_l(
  wchar_t* destination,
  const char* source,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _mbtowc_l(
  wchar_t* destination,
  const char* source,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl _wctomb_s_l(int* retValue, char* destination, std::size_t sizeInBytes, wchar_t wideChar, _locale_t localeInfo);
extern "C" int __cdecl _vsprintf_s_l(char* buffer, std::size_t sizeInBytes, const char* format, _locale_t localeInfo, va_list argList);
extern "C" int __cdecl _vsnprintf_l(
  char* buffer,
  std::size_t count,
  const char* format,
  _locale_t localeInfo,
  va_list argList
);
extern "C" int __cdecl _output_l(
  std::FILE* stream,
  const char* format,
  _locale_t localeInfo,
  va_list arguments
);
extern "C" int __cdecl _output_s_l(
  std::FILE* stream,
  const char* format,
  _locale_t localeInfo,
  va_list arguments
);
extern "C" int __cdecl outfn(
  std::FILE* stream,
  const char* format,
  _locale_t localeInfo,
  va_list arguments
);
extern "C" int __cdecl _ismbblead_l(unsigned int value, _locale_t localeInfo);
extern "C" std::size_t __cdecl wstrlen(const wchar_t* str);
extern "C" errno_t wstrcpy(wchar_t* destination, int length, const wchar_t* source);
extern "C" int __cdecl _mbsnbicoll_l(
  const unsigned char* lhsText,
  const unsigned char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" int __cdecl woutput_l(
  std::FILE* stream,
  const wchar_t* format,
  _locale_t localeInfo,
  va_list arguments
);
extern "C" int __cdecl __InternalCxxFrameHandler(
  EXCEPTION_RECORD* exceptionRecord,
  void* registrationNode,
  CONTEXT* contextRecord,
  void* dispatcherContext,
  const void* functionInfo,
  int catchDepth,
  void* targetFrame,
  int recursionDepth
);
extern "C" unsigned long _maxwait;
extern "C" unsigned int _osplatform;
extern "C" unsigned int _osver;
extern "C" unsigned int _winmajor;
extern "C" unsigned int _winver;
extern "C" unsigned int _winminor;
extern "C" int __locale_changed;
extern "C" long _timezone;
extern "C" long _dstbias;
#ifdef _tzname
#undef _tzname
#endif
extern "C" char* _tzname[2];
extern "C" int daylight;
extern "C" HANDLE _crtheap;
extern "C" char* _pgmptr;
extern "C" int _active_heap;
extern "C" void __cdecl _CrtSetCheckCount();

/**
 * Address: 0x00AAAA55 (FUN_00AAAA55, _set_pgmptr)
 *
 * What it does:
 * Stores one raw program-path pointer in `_pgmptr` and returns that pointer.
 */
extern "C" char* __cdecl _set_pgmptr(char* const programPath)
{
  _pgmptr = programPath;
  return programPath;
}

/**
 * Address: 0x00AAAF0E (FUN_00AAAF0E, __get_heap_handle)
 *
 * What it does:
 * Returns the CRT process-heap handle as one integer-sized lane.
 */
extern "C" std::intptr_t __cdecl __get_heap_handle()
{
  return reinterpret_cast<std::intptr_t>(_crtheap);
}

using BITVEC = std::uint32_t;

struct tagEntry
{
  std::int32_t sizeFront;
  tagEntry* pEntryPrev;
  tagEntry* pEntryNext;
};

struct tagListHead
{
  tagEntry* pEntryPrev;
  tagEntry* pEntryNext;
};

struct tagGroup
{
  std::int32_t cntEntries;
  tagListHead listHead[64];
};

struct tagRegion
{
  std::int32_t indGroupUse;
  std::uint8_t cntRegionSize[64];
  BITVEC bitvGroupHi[32];
  BITVEC bitvGroupLo[32];
  tagGroup grpHeadList[32];
};

struct tagHeader
{
  BITVEC bitvEntryHi;
  BITVEC bitvEntryLo;
  BITVEC bitvCommit;
  tagEntry* pHeapData;
  tagRegion* pRegion;
};

static_assert(offsetof(tagEntry, sizeFront) == 0x0, "tagEntry::sizeFront offset must be 0x0");
static_assert(offsetof(tagEntry, pEntryPrev) == 0x4, "tagEntry::pEntryPrev offset must be 0x4");
static_assert(offsetof(tagEntry, pEntryNext) == 0x8, "tagEntry::pEntryNext offset must be 0x8");
static_assert(sizeof(tagEntry) == 0xC, "tagEntry size must be 0xC");
static_assert(offsetof(tagListHead, pEntryPrev) == 0x0, "tagListHead::pEntryPrev offset must be 0x0");
static_assert(offsetof(tagListHead, pEntryNext) == 0x4, "tagListHead::pEntryNext offset must be 0x4");
static_assert(sizeof(tagListHead) == 0x8, "tagListHead size must be 0x8");
static_assert(offsetof(tagGroup, cntEntries) == 0x0, "tagGroup::cntEntries offset must be 0x0");
static_assert(offsetof(tagGroup, listHead) == 0x4, "tagGroup::listHead offset must be 0x4");
static_assert(sizeof(tagGroup) == 0x204, "tagGroup size must be 0x204");
static_assert(offsetof(tagRegion, indGroupUse) == 0x0, "tagRegion::indGroupUse offset must be 0x0");
static_assert(offsetof(tagRegion, cntRegionSize) == 0x4, "tagRegion::cntRegionSize offset must be 0x4");
static_assert(offsetof(tagRegion, bitvGroupHi) == 0x44, "tagRegion::bitvGroupHi offset must be 0x44");
static_assert(offsetof(tagRegion, bitvGroupLo) == 0xC4, "tagRegion::bitvGroupLo offset must be 0xC4");
static_assert(offsetof(tagRegion, grpHeadList) == 0x144, "tagRegion::grpHeadList offset must be 0x144");
static_assert(sizeof(tagRegion) == 0x41C4, "tagRegion size must be 0x41C4");
static_assert(offsetof(tagHeader, bitvEntryHi) == 0x0, "tagHeader::bitvEntryHi offset must be 0x0");
static_assert(offsetof(tagHeader, bitvEntryLo) == 0x4, "tagHeader::bitvEntryLo offset must be 0x4");
static_assert(offsetof(tagHeader, bitvCommit) == 0x8, "tagHeader::bitvCommit offset must be 0x8");
static_assert(offsetof(tagHeader, pHeapData) == 0xC, "tagHeader::pHeapData offset must be 0xC");
static_assert(offsetof(tagHeader, pRegion) == 0x10, "tagHeader::pRegion offset must be 0x10");
static_assert(sizeof(tagHeader) == 0x14, "tagHeader size must be 0x14");

extern "C" tagHeader* _sbh_pHeaderList;
extern "C" tagHeader* _sbh_pHeaderDefer;
extern "C" int _sbh_cntHeaderList;
extern "C" tagHeader* _sbh_pHeaderScan;
extern "C" unsigned int _sbh_indGroupDefer;
extern "C" std::size_t _sbh_threshold;
extern "C" int _sbh_sizeHeaderList;
extern "C" int __cdecl __crtInitCritSecAndSpinCount(LPCRITICAL_SECTION criticalSection, DWORD spinCount);
extern "C" CRITICAL_SECTION lclcritsects[];
extern "C" LPCRITICAL_SECTION _locktable[];
extern "C" wchar_t _wnullstring[];
extern "C" int __app_type;
extern "C" std::uint16_t* _pwctype;
extern "C" void __cdecl __NMSG_WRITE(int msgId);
extern "C" wchar_t** _wenviron;
extern "C" int __cdecl __crtsetenv(const unsigned char** option, int primary);
/**
 * Address: 0x00AAADE5 (FUN_00AAADE5, __heap_select)
 *
 * What it does:
 * Selects one CRT heap backend from cached platform/version lanes.
 */
extern "C" int __cdecl _heap_select();
extern "C" int __cdecl _sbh_heap_init(std::size_t regionSize);
extern "C" tagHeader* __cdecl _sbh_heapmin();
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

struct RuntimeLocaleInfoStruct;
extern "C" RuntimeLocaleInfoStruct __initiallocalestructinfo;
extern "C" std::size_t __cdecl __Strftime_l(
  char* destination,
  std::size_t maxCount,
  const char* format,
  const std::tm* timeData,
  void* timeZoneInfo,
  _locale_t localeInfo
);
unsigned long __cdecl strtoxl(
  RuntimeLocaleInfoStruct* localeInfo,
  const char* text,
  char** endPointer,
  int radix,
  int isUnsigned
);
extern "C" void __cdecl doexit(unsigned int exitCode, int quick, int returnToCaller);
extern "C" unsigned __int64 __cdecl wcstoxq(
  RuntimeLocaleInfoStruct* localeInfo,
  const wchar_t* text,
  wchar_t** endPointer,
  int radix,
  int flags
);

using RuntimeInitFunctionWithStatus = int(__cdecl*)();

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
 * Address: 0x00A8E474 (FUN_00A8E474, strtod)
 *
 * What it does:
 * Forwards decimal parsing to the CRT `strtod` lane, preserving the
 * null-input invalid-parameter path used by the binary wrapper.
 *
 * Named off the reserved CRT symbol despite that - not `strtod` - for the
 * same reason as `EngineSetNewMode` above: `std::strtod` is simply
 * `using ::strtod;` in this toolchain's <cstring>-family headers, so a
 * global `strtod` defined here does not forward to the real CRT
 * implementation, it calls itself, unconditionally, on every invocation.
 * That is a guaranteed stack overflow the instant anything - this file's
 * own `RuntimeStrtodScaledByPowerOfTen` below, or any of Lua's numeric
 * parsing, or PNG chunk parsing - calls `strtod`/`std::strtod` anywhere in
 * the program. Keeping the disassembled wrapper under a non-colliding name
 * preserves the recovery; not colliding lets `std::strtod` resolve to the
 * real implementation everywhere else, as every one of those call sites
 * already assumes.
 */
extern "C" double __cdecl EngineStrtod(const char* text, char** endPtr)
{
  if (endPtr != nullptr) {
    *endPtr = const_cast<char*>(text);
  }

  if (text == nullptr) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0.0;
  }

  return std::strtod(text, endPtr);
}

namespace
{
  /**
   * Address: 0x00AC0EE9 (FUN_00AC0EE9)
   *
   * IDA signature:
   * int __cdecl sub_AC0EE9(const char **inOutCursor, const char **outConsumedEnd);
   *
   * What it does:
   * The CRT `_Stopfx`-family special-value token recognizer used by the real
   * `strtod` lane: skips leading whitespace, consumes an optional `+`/`-`
   * sign, then case-insensitively matches `"inf"` / `"infinity"` or `"nan"`
   * (with an optional `(alnum|'_')*` payload in parens after `"nan"`).
   * Returns a bitfield (bit 0x8 = negative sign, bits 0x1/0x3 = no-match /
   * infinity, 0x4 = nan-with-payload) inferred from control flow rather than
   * a documented header constant. Advances `*inOutCursor` past the matched
   * token (or leaves it unmoved on no match) and optionally reports the
   * match end through `outConsumedEnd`.
   *
   * Known divergence: `strtod` above is currently a simplified forward to
   * `std::strtod` and does not yet invoke this lane; flagged as technical
   * debt for a dedicated `strtod` fidelity pass rather than reworked here.
   */
  [[maybe_unused]] int RuntimeParseSpecialFloatToken(const char** const inOutCursor, const char** const outConsumedEnd)
  {
    const char* cursor = *inOutCursor;
    while (std::isspace(static_cast<unsigned char>(*cursor))) {
      ++cursor;
    }

    int flags = 0;
    if (*cursor == '-') {
      flags = 0x8;
      ++cursor;
    } else if (*cursor == '+') {
      ++cursor;
    }

    const char* const signedStart = cursor;
    const char first = *cursor;
    if (first == 'n' || first == 'N') {
      ++cursor;
      if ((*cursor == 'a' || *cursor == 'A') && (cursor[1] == 'n' || cursor[1] == 'N')) {
        cursor += 2;
        if (*cursor == '(') {
          const char* payload = cursor + 1;
          while (std::isalnum(static_cast<unsigned char>(*payload)) || *payload == '_') {
            ++payload;
          }
          flags = 0x4;
          if (*payload == ')') {
            cursor = payload + 1;
          }
        } else {
          flags = 0x4;
        }
      } else {
        cursor = *inOutCursor;
        flags = 0;
      }
    } else if (first == 'i' || first == 'I') {
      ++cursor;
      if ((*cursor == 'n' || *cursor == 'N') && (cursor[1] == 'f' || cursor[1] == 'F')) {
        cursor += 2;
        flags |= 0x3;
        if ((cursor[0] == 'i' || cursor[0] == 'I') && (cursor[1] == 'n' || cursor[1] == 'N')
          && (cursor[2] == 'i' || cursor[2] == 'I') && (cursor[3] == 't' || cursor[3] == 'T')
          && (cursor[4] == 'y' || cursor[4] == 'Y')) {
          cursor += 5;
        }
      } else {
        cursor = *inOutCursor;
        flags = 0;
      }
    } else {
      flags |= 0x1;
    }
    (void)signedStart;

    if (outConsumedEnd != nullptr) {
      *outConsumedEnd = cursor;
    }
    *inOutCursor = cursor;
    return flags;
  }
} // namespace

/**
 * Address: 0x00AC04F1 (FUN_00AC04F1)
 *
 * What it does:
 * Parses one decimal string through `strtod`, captures parse errno into
 * `outParseErrno`, restores caller errno state, then scales the parsed value
 * by `10^decimalScale`.
 */
double RuntimeStrtodScaledByPowerOfTen(
  const char* const text,
  char** const endPtr,
  const int decimalScale,
  int* const outParseErrno
)
{
  const int callerErrno = *_errno();
  *_errno() = 0;

  double parsedValue = EngineStrtod(text, endPtr);
  const int parseErrno = *_errno();
  if (outParseErrno != nullptr) {
    *outParseErrno = parseErrno;
  }

  *_errno() = callerErrno;

  if (decimalScale > 0) {
    int remaining = decimalScale;
    while (remaining-- > 0) {
      parsedValue *= 10.0;
    }
  } else if (decimalScale < 0) {
    int remaining = -decimalScale;
    while (remaining-- > 0) {
      parsedValue /= 10.0;
    }
  }

  return parsedValue;
}

/**
 * Address: 0x00AC0398 (FUN_00AC0398)
 *
 * What it does:
 * Wraps `RuntimeStrtodScaledByPowerOfTen`, then narrows the parsed result to
 * `float` while preserving the double-return ABI lane.
 */
extern "C" double __cdecl RuntimeStrtodScaledAsFloat(
  char* const text,
  char** const endPtr,
  const int decimalScale,
  int* const outParseErrno
)
{
  return static_cast<float>(RuntimeStrtodScaledByPowerOfTen(text, endPtr, decimalScale, outParseErrno));
}

/**
 * Address: 0x00AC068F (FUN_00AC068F)
 *
 * What it does:
 * Thunk lane that forwards directly to `RuntimeStrtodScaledByPowerOfTen`.
 */
extern "C" double __cdecl RuntimeStrtodScaledAlias(
  char* const text,
  char** const endPtr,
  const int decimalScale,
  int* const outParseErrno
)
{
  return RuntimeStrtodScaledByPowerOfTen(text, endPtr, decimalScale, outParseErrno);
}

/**
 * Address: 0x00AAB1A1 (FUN_00AAB1A1, _wchartodigit)
 *
 * What it does:
 * Converts one Unicode decimal-digit codepoint to its numeric value (`0..9`)
 * across the CRT's supported digit blocks; returns `-1` when unsupported.
 */
extern "C" int __cdecl _wchartodigit(const std::uint16_t codepoint)
{
  if (codepoint >= 0x30u && codepoint < 0x3Au) {
    return static_cast<int>(codepoint - 0x30u);
  }

  const auto decodeRange = [codepoint](const std::uint16_t first, const std::uint16_t last) -> int {
    if (codepoint >= first && codepoint < last) {
      return static_cast<int>(codepoint - first);
    }
    return -1;
  };

  if (const int value = decodeRange(0x0660u, 0x066Au); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x06F0u, 0x06FAu); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0966u, 0x0970u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x09E6u, 0x09F0u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0A66u, 0x0A70u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0AE6u, 0x0AF0u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0B66u, 0x0B70u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0C66u, 0x0C70u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0CE6u, 0x0CF0u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0D66u, 0x0D70u); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0E50u, 0x0E5Au); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0ED0u, 0x0EDAu); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x0F20u, 0x0F2Au); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x1040u, 0x104Au); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x17E0u, 0x17EAu); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0x1810u, 0x181Au); value >= 0) {
    return value;
  }
  if (const int value = decodeRange(0xFF10u, 0xFF1Au); value >= 0) {
    return value;
  }

  return -1;
}

namespace
{
  /**
   * Address: 0x00AA4615 (FUN_00AA4615)
   *
   * What it does:
   * Formats one unsigned integer into a caller-provided narrow buffer using
   * the requested radix, with optional sign handling for the signed caller
   * lane and CRT invalid-parameter / overflow semantics.
   */
  errno_t RuntimeIntegerToText(
    unsigned int value,
    char* const buffer,
    const std::size_t bufferSize,
    const unsigned int radix,
    const bool isNegative
  )
  {
    char* const outputStart = buffer;

    if (buffer == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    if (bufferSize == 0u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *buffer = '\0';
    if (bufferSize <= static_cast<std::size_t>(static_cast<unsigned int>(isNegative) + 1u)) {
      *_errno() = ERANGE;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return ERANGE;
    }

    if (radix < 2u || radix > 36u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::size_t digitsWritten = 0;
    char* writeCursor = buffer;
    if (isNegative) {
      *writeCursor++ = '-';
      digitsWritten = 1;
      value = 0u - value;
    }

    char* digitStart = writeCursor;
    do {
      const unsigned int digit = value % radix;
      value /= radix;
      *writeCursor++ = static_cast<char>(digit + (digit <= 9u ? '0' : 'a' - 10));
      ++digitsWritten;
    } while (value != 0u && digitsWritten < bufferSize);

    if (digitsWritten >= bufferSize) {
      *outputStart = '\0';
      *_errno() = ERANGE;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return ERANGE;
    }

    *writeCursor = '\0';
    char* reverseCursor = writeCursor - 1;
    while (digitStart < reverseCursor) {
      const char front = *digitStart;
      *digitStart++ = *reverseCursor;
      *reverseCursor-- = front;
    }

    return 0;
  }

  /**
   * Address: 0x00AA4755 (FUN_00AA4755, 64-bit integer-to-text core lane)
   *
   * What it does:
   * Formats one 64-bit integer into a caller-provided narrow buffer using the
   * requested radix and optional signed-minus handling.
   */
  errno_t RuntimeInteger64ToText(
    const std::uint64_t rawValue,
    char* const buffer,
    const std::size_t bufferSize,
    const unsigned int radix,
    const bool signedLane
  )
  {
    if (buffer == nullptr || bufferSize == 0u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *buffer = '\0';
    const std::size_t minimumChars = signedLane ? 2u : 1u;
    if (bufferSize <= minimumChars) {
      *_errno() = ERANGE;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return ERANGE;
    }

    if (radix < 2u || radix > 36u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::uint64_t value = rawValue;
    std::size_t charsWritten = 0u;
    char* writeCursor = buffer;
    if (signedLane && static_cast<std::int64_t>(rawValue) < 0) {
      *writeCursor++ = '-';
      ++charsWritten;
      value = 0u - value;
    }

    char* digitStart = writeCursor;
    do {
      const unsigned int digit = static_cast<unsigned int>(value % radix);
      value /= radix;
      *writeCursor++ = static_cast<char>(digit <= 9u ? digit + static_cast<unsigned int>('0') : digit + 87u);
      ++charsWritten;
    } while (value != 0u && charsWritten < bufferSize);

    if (charsWritten >= bufferSize) {
      *buffer = '\0';
      *_errno() = ERANGE;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return ERANGE;
    }

    *writeCursor = '\0';
    char* reverseCursor = writeCursor - 1;
    while (digitStart < reverseCursor) {
      const char temp = *reverseCursor;
      *reverseCursor-- = *digitStart;
      *digitStart++ = temp;
    }

    return 0;
  }
} // namespace

/**
 * Address: 0x00AA473D (FUN_00AA473D, _ultow_s)
 *
 * What it does:
 * Forwards the unsigned integer formatting lane into the shared radix helper
 * with sign handling disabled.
 */
extern "C" errno_t __cdecl RuntimeUnsignedLongToString(
  const unsigned long value,
  char* const buffer,
  const std::size_t bufferSize,
  const int radix
)
{
  return RuntimeIntegerToText(static_cast<unsigned int>(value), buffer, bufferSize, static_cast<unsigned int>(radix), false);
}

/**
 * Address: 0x00AA46F0 (FUN_00AA46F0, _itoa_s)
 *
 * What it does:
 * Formats one signed 32-bit integer into a caller buffer, preserving the CRT
 * decimal-negative lane (`radix == 10 && value < 0`) used by the binary.
 */
extern "C" errno_t __cdecl _itoa_s(
  const int value,
  char* const buffer,
  const std::size_t bufferSize,
  const int radix
)
{
  const bool decimalNegative = (radix == 10) && (value < 0);
  return RuntimeIntegerToText(
    static_cast<unsigned int>(value),
    buffer,
    bufferSize,
    static_cast<unsigned int>(radix),
    decimalNegative
  );
}

/**
 * Address: 0x00AA487E (FUN_00AA487E, _i64toa_s)
 *
 * What it does:
 * Formats one signed 64-bit integer into a caller-provided narrow buffer.
 */
extern "C" errno_t __cdecl _i64toa_s(
  const __int64 value,
  char* const buffer,
  const std::size_t bufferSize,
  const int radix
)
{
  return RuntimeInteger64ToText(
    static_cast<std::uint64_t>(value),
    buffer,
    bufferSize,
    static_cast<unsigned int>(radix),
    true
  );
}

/**
 * Address: 0x00AA4876 (FUN_00AA4876, _ui64toa_s)
 *
 * What it does:
 * Formats one unsigned 64-bit integer into a caller-provided narrow buffer.
 */
extern "C" errno_t __cdecl _ui64toa_s(
  const unsigned __int64 value,
  char* const buffer,
  const std::size_t bufferSize,
  const int radix
)
{
  return RuntimeInteger64ToText(value, buffer, bufferSize, static_cast<unsigned int>(radix), false);
}

extern "C" tagHeader* _sbh_pHeaderList = nullptr;
extern "C" tagHeader* _sbh_pHeaderDefer = nullptr;
extern "C" int _sbh_cntHeaderList = 0;
extern "C" tagHeader* _sbh_pHeaderScan = nullptr;
extern "C" unsigned int _sbh_indGroupDefer = 0u;
extern "C" std::size_t _sbh_threshold = 0;
extern "C" int _sbh_sizeHeaderList = 0;

namespace
{
  using CorExitProcessFn = void(__stdcall*)(unsigned int exitCode);

  void RuntimeTryCorExitProcess(const unsigned int exitCode)
  {
    const HMODULE mscoreeModule = ::GetModuleHandleA("mscoree.dll");
    if (mscoreeModule == nullptr) {
      return;
    }

    const FARPROC corExitProcess = ::GetProcAddress(mscoreeModule, "CorExitProcess");
    if (corExitProcess != nullptr) {
      reinterpret_cast<CorExitProcessFn>(corExitProcess)(exitCode);
    }
  }
}

namespace
{
  struct RuntimeThreadLocInfoView;

  [[nodiscard]] RuntimeThreadLocInfoView* RuntimeResolveLocaleLocInfo(
    _locale_t localeInfo,
    RuntimeTidDataLocaleView** outThreadData,
    bool* outUpdated
  );

  void RuntimeReleaseLocaleUpdate(RuntimeTidDataLocaleView* threadData, bool updated);
}

/**
 * Address: 0x00A83648 (FUN_00A83648, crtExitProcess)
 *
 * What it does:
 * Dispatches optional CLR process-exit notification through `CorExitProcess`
 * and then terminates the process via `ExitProcess`.
 */
extern "C" [[noreturn]] void __cdecl crtExitProcess(const unsigned int exitCode)
{
  RuntimeTryCorExitProcess(exitCode);
  ::ExitProcess(exitCode);
}

/**
 * Address: 0x00A836DE (FUN_00A836DE, _get_osver)
 *
 * What it does:
 * Returns one cached CRT OS-version lane through `outOsVersion` when platform
 * state is initialized; otherwise reports invalid-parameter semantics and
 * returns `EINVAL`.
 */
extern "C" int __cdecl _get_osver(unsigned int* const outOsVersion)
{
  if (outOsVersion != nullptr && _osplatform != 0u) {
    *outOsVersion = _osver;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00A83756 (FUN_00A83756, _get_winmajor)
 *
 * What it does:
 * Returns one cached CRT major Windows version through `outMajorVersion` when
 * platform state is initialized; otherwise reports invalid-parameter semantics
 * and returns `EINVAL`.
 */
extern "C" int __cdecl _get_winmajor(unsigned int* const outMajorVersion)
{
  if (outMajorVersion != nullptr && _osplatform != 0u) {
    *outMajorVersion = _winmajor;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
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
 * Address: 0x00A8ECE7 (FUN_00A8ECE7, _set_osplatform)
 *
 * What it does:
 * Stores one CRT platform-id lane and returns the stored value.
 */
extern "C" int __cdecl _set_osplatform(const unsigned int platformId)
{
  _osplatform = platformId;
  return static_cast<int>(platformId);
}

/**
 * Address: 0x00A8ECF1 (FUN_00A8ECF1, _set_osver)
 *
 * What it does:
 * Stores one CRT OS-version lane and returns the stored value.
 */
extern "C" unsigned int __cdecl _set_osver(const unsigned int osVersion)
{
  _osver = osVersion;
  return osVersion;
}

/**
 * Address: 0x00A8ECFB (FUN_00A8ECFB, _set_winver)
 *
 * What it does:
 * Stores one CRT Windows-version lane and returns the stored value.
 */
extern "C" unsigned int __cdecl _set_winver(const unsigned int winVersion)
{
  _winver = winVersion;
  return winVersion;
}

/**
 * Address: 0x00A8ED05 (FUN_00A8ED05, _set_winmajor)
 *
 * What it does:
 * Stores one CRT major Windows-version lane and returns the stored value.
 */
extern "C" unsigned int __cdecl _set_winmajor(const unsigned int majorVersion)
{
  _winmajor = majorVersion;
  return majorVersion;
}

/**
 * Address: 0x00A8ED0F (FUN_00A8ED0F, _set_winminor)
 *
 * What it does:
 * Stores one CRT minor Windows-version lane and returns the stored value.
 */
extern "C" unsigned int __cdecl _set_winminor(const unsigned int minorVersion)
{
  _winminor = minorVersion;
  return minorVersion;
}

namespace
{
  using RuntimeEhVectorStepFn = void(__thiscall*)(void* element);

}

/**
 * Address: 0x00A83A4E (FUN_00A83A4E)
 *
 * What it does:
 * Shared teardown loop reached from `eh vector destructor iterator` at
 * 0x00A83AAC and from the unwind funclets of `eh vector constructor
 * iterator` (0x00A83FC5) and `eh vector copy constructor iterator`
 * (0x00A8402A). Walks one element range in reverse order, invoking the
 * destructor callback once per element. A destructor callback that itself
 * throws is fatal (matches `catch (...) { std::terminate(); }`, the C++
 * rule that an exception escaping a destructor during teardown terminates
 * the program); the compiled body implements this via an SEH filter that
 * checks for the C++ exception code (0xE06D7363) before calling
 * `terminate`.
 */
extern "C" void __stdcall RuntimeEhVectorDestructorIterator(
  char* currentElement,
  const unsigned int elementSize,
  int elementCount,
  const RuntimeEhVectorStepFn destructorFn
)
{
  while (--elementCount >= 0) {
    currentElement -= elementSize;
    try {
      destructorFn(currentElement);
    } catch (...) {
      std::terminate();
    }
  }
}

/**
 * Address: 0x00A83FC5 (FUN_00A83FC5, `eh vector constructor iterator`)
 *
 * What it does:
 * Walks one element range in forward order, invoking the constructor callback
 * once per element and returning the number of constructed elements. If a
 * constructor throws partway through, the unwind funclet at 0x00A84012
 * destroys the already-constructed prefix in reverse order via the shared
 * teardown loop (RuntimeEhVectorDestructorIterator, 0x00A83A4E) before the
 * original exception continues propagating.
 */
extern "C" int __stdcall RuntimeEhVectorConstructorIterator(
  char* currentElement,
  const unsigned int elementSize,
  const int elementCount,
  const RuntimeEhVectorStepFn constructorFn,
  const RuntimeEhVectorStepFn destructorFn
)
{
  int constructedCount = 0;
  try {
    while (constructedCount < elementCount) {
      constructorFn(currentElement);
      currentElement += elementSize;
      ++constructedCount;
    }
  } catch (...) {
    RuntimeEhVectorDestructorIterator(currentElement, elementSize, constructedCount, destructorFn);
    throw;
  }

  return constructedCount;
}

/**
 * Address: 0x00AA2CB4 (FUN_00AA2CB4)
 *
 * What it does:
 * Invokes one `__thiscall int(int)` callback under CRT EH bridge semantics
 * and terminates on C++ exception propagation.
 */
extern "C" int __cdecl RuntimeInvokeThiscallIntCallbackNoexcept(
  int(__thiscall* const callback)(int),
  const int argument
)
{
  try {
    return callback(argument);
  } catch (...) {
    std::terminate();
  }
}

/**
 * Address: 0x00AA2CE6 (FUN_00AA2CE6)
 *
 * What it does:
 * Invokes one `__cdecl int(int)` callback under CRT EH bridge semantics and
 * terminates on C++ exception propagation.
 */
extern "C" int __cdecl RuntimeInvokeCdeclIntCallbackNoexcept(
  int(__cdecl* const callback)(int),
  const int argument
)
{
  try {
    return callback(argument);
  } catch (...) {
    std::terminate();
  }
}

/**
 * Address: 0x00AA2D19 (FUN_00AA2D19)
 *
 * What it does:
 * Invokes one `__stdcall int(int)` callback under CRT EH bridge semantics and
 * terminates on C++ exception propagation.
 */
extern "C" int __cdecl RuntimeInvokeStdcallIntCallbackNoexcept(
  int(__stdcall* const callback)(int),
  const int argument
)
{
  try {
    return callback(argument);
  } catch (...) {
    std::terminate();
  }
}

/**
 * Address: 0x00AA2D4B (FUN_00AA2D4B)
 *
 * What it does:
 * Invokes one `__stdcall int(int,int,int,int)` callback under CRT EH bridge
 * semantics and terminates on C++ exception propagation.
 */
extern "C" int __cdecl RuntimeInvokeStdcallInt4CallbackNoexcept(
  int(__stdcall* const callback)(int, int, int, int),
  const int argument0,
  const int argument1,
  const int argument2,
  const int argument3
)
{
  try {
    return callback(argument0, argument1, argument2, argument3);
  } catch (...) {
    std::terminate();
  }
}

// Shared helpers for the CRT ctype family (`_is*[_l]`) recovered below.
namespace
{
  struct RuntimeCtypeVec;

  using RuntimeLocaleClassifierFn = int(__cdecl*)(int character, _locale_t localeInfo);

  [[nodiscard]] int RuntimeClassifyLocaleCharacter(
    const int character,
    _locale_t const localeInfo,
    const unsigned int fastMask,
    const int ctypeMask
  )
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    const auto* const localeView = reinterpret_cast<const RuntimeLocaleClassificationView*>(
      RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated)
    );

    int result = 0;
    if (localeView != nullptr) {
      if (localeView->mbCurMax <= 1) {
        result = static_cast<int>(localeView->pctype[character] & fastMask);
      } else {
        result = _isctype_l(character, ctypeMask, localeInfo);
      }
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Shared implementation for `_isctype_l`. See the extern-C entry point at
   * address 0x00A984BB for the address annotation and caller context.
   *
   * What it does:
   * Locale-aware CRT `_isctype` classifier. Updates the effective locale via
   * `RuntimeResolveLocaleLocInfo` (the `_LocaleUpdate` construction lane),
   * then classifies `character` against `mask`:
   *   * single-byte fast path `(character + 1) <= 0x100`: returns
   *     `locale.pctype[character] & mask`
   *   * DBCS path: tests leadbyte state of `character >> 8` via
   *     `_isleadbyte_l` and combines with `pctype[character & 0xFF]`
   * Always pairs with `RuntimeReleaseLocaleUpdate` to release any
   * thread-local locale ref acquired by the resolve lane.
   */
  [[nodiscard]] int RuntimeIsCtypeLocale(
    const int character,
    const int mask,
    _locale_t const localeInfo
  )
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    const auto* const localeView = reinterpret_cast<const RuntimeLocaleClassificationView*>(
      RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated)
    );

    int result = 0;
    if (localeView != nullptr && localeView->pctype != nullptr) {
      if (static_cast<unsigned int>(character) + 1u <= 0x100u) {
        result = static_cast<int>(localeView->pctype[character]) & mask;
      } else {
        const int highByte = (character >> 8) & 0xFF;
        const int lowByte = character & 0xFF;
        const int leadByteFlag = _isleadbyte_l(highByte, localeInfo);
        if (leadByteFlag != 0) {
          result = static_cast<int>(localeView->pctype[lowByte]) & mask;
        } else {
          result = static_cast<int>(localeView->pctype[highByte]) & mask;
        }
      }
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  [[nodiscard]] int RuntimeClassifyInitialOrLocaleChanged(
    const int character,
    const unsigned int initialMask,
    const RuntimeLocaleClassifierFn changedLocaleClassifier
  )
  {
    if (__locale_changed != 0) {
      return changedLocaleClassifier(character, nullptr);
    }

    const auto* const initialLocale = reinterpret_cast<const RuntimeLocaleCTypeTableView*>(&__initiallocinfo);
    return static_cast<int>(initialLocale->pctype[character] & initialMask);
  }

  struct RuntimeToupperLocaleView
  {
    std::uint8_t reserved00_03[0x4]{};
    std::int32_t lcCodepage = 0;               // +0x04
    std::uint8_t reserved08_0B[0x4]{};
    LCID lcHandle[6]{};                        // +0x0C
    std::uint8_t reserved24_AB[0x88]{};
    std::int32_t mbCurMax = 0;                 // +0xAC
    std::uint8_t reservedB0_C7[0x18]{};
    const std::uint16_t* pctype = nullptr;     // +0xC8
    std::uint8_t reservedCC_CF[0x4]{};
    const unsigned char* pcumap = nullptr;     // +0xD0
  };
  static_assert(offsetof(RuntimeToupperLocaleView, lcCodepage) == 0x4, "RuntimeToupperLocaleView::lcCodepage offset must be 0x4");
  static_assert(offsetof(RuntimeToupperLocaleView, lcHandle) == 0xC, "RuntimeToupperLocaleView::lcHandle offset must be 0xC");
  static_assert((offsetof(RuntimeToupperLocaleView, lcHandle) + sizeof(LCID) * 2u) == 0x14, "RuntimeToupperLocaleView::lcHandle[2] offset must be 0x14");
  static_assert(offsetof(RuntimeToupperLocaleView, mbCurMax) == 0xAC, "RuntimeToupperLocaleView::mbCurMax offset must be 0xAC");
  static_assert(offsetof(RuntimeToupperLocaleView, pctype) == 0xC8, "RuntimeToupperLocaleView::pctype offset must be 0xC8");
  static_assert(offsetof(RuntimeToupperLocaleView, pcumap) == 0xD0, "RuntimeToupperLocaleView::pcumap offset must be 0xD0");

  /**
   * Address: 0x00A8E5CD (FUN_00A8E5CD)
   *
   * What it does:
   * Locale-aware uppercase helper for `toupper`; uses `_LocaleUpdate`-equivalent
   * locale resolution, supports DBCS lead-byte mapping through
   * `__crtLCMapStringA(LCMAP_UPPERCASE)`, and preserves `EILSEQ` fallback lanes.
   */
  int RuntimeToupperLocaleHelper(const int character, _locale_t const localeInfo)
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    const auto* const localeView = reinterpret_cast<const RuntimeToupperLocaleView*>(
      RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated)
    );

    int result = character;
    if (localeView != nullptr) {
      if (static_cast<unsigned int>(character) < 0x100u) {
        int lowerMask = 0;
        if (localeView->mbCurMax <= 1) {
          lowerMask = static_cast<int>(localeView->pctype[character] & 0x2u);
        } else {
          lowerMask = _isctype_l(character, 0x2, localeInfo);
        }

        if (lowerMask != 0) {
          result = static_cast<int>(localeView->pcumap[character]);
        }
      } else {
        int inputLength = 1;
        char inputBuffer[3]{};
        inputBuffer[0] = static_cast<char>(character & 0xFF);

        const unsigned int highByte = static_cast<unsigned int>(character >> 8) & 0xFFu;
        if (localeView->mbCurMax > 1 && _ismbblead_l(highByte, localeInfo) != 0) {
          inputBuffer[0] = static_cast<char>(highByte);
          inputBuffer[1] = static_cast<char>(character & 0xFF);
          inputLength = 2;
        } else {
          *_errno() = EILSEQ;
        }

        char mappedBytes[3]{};
        const int mappedLength = __crtLCMapStringA(
          0,
          localeView->lcHandle[2],
          LCMAP_UPPERCASE,
          inputBuffer,
          inputLength,
          reinterpret_cast<LPWSTR>(mappedBytes),
          3,
          localeView->lcCodepage,
          1
        );
        if (mappedLength == 1) {
          result = static_cast<unsigned char>(mappedBytes[0]);
        } else if (mappedLength > 1) {
          result = (static_cast<int>(static_cast<unsigned char>(mappedBytes[0])) << 8)
            | static_cast<int>(static_cast<unsigned char>(mappedBytes[1]));
        }
      }
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00A8F9E7 (FUN_00A8F9E7)
   *
   * What it does:
   * Converts one wide character to uppercase using the active locale-update
   * lane (`_LocaleUpdate` equivalent), falling back to ASCII-only uppercase
   * conversion when no locale handle is active.
   */
  int RuntimeTowupperLocaleHelperWide(
    const std::uint16_t sourceCharacter,
    _locale_t const localeInfo
  )
  {
    int result = static_cast<int>(sourceCharacter);
    if (sourceCharacter == 0xFFFFu) {
      return result;
    }

    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    const auto* const localeView = reinterpret_cast<const RuntimeToupperLocaleView*>(
      RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated)
    );

    if (localeView != nullptr) {
      const LCID localeHandle = localeView->lcHandle[2];
      if (localeHandle != 0) {
        if (sourceCharacter >= 0x100u) {
          wchar_t sourceWide = static_cast<wchar_t>(sourceCharacter);
          wchar_t destinationWide = sourceWide;
          const int mapResult = __crtLCMapStringW(
            0,
            localeHandle,
            LCMAP_UPPERCASE,
            &sourceWide,
            1,
            &destinationWide,
            1,
            localeView->lcCodepage
          );
          if (mapResult != 0) {
            result = static_cast<int>(static_cast<std::uint16_t>(destinationWide));
          }
        } else if (_iswctype_l(
                     static_cast<wint_t>(sourceCharacter),
                     static_cast<wctype_t>(C1_LOWER),
                     localeInfo
                   ) != 0) {
          result = static_cast<int>(localeView->pcumap[sourceCharacter]);
        }
      } else if (sourceCharacter >= static_cast<std::uint16_t>('a')
                 && sourceCharacter <= static_cast<std::uint16_t>('z')) {
        result = static_cast<int>(sourceCharacter - static_cast<std::uint16_t>('a' - 'A'));
      }
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }
}

/**
 * Address: 0x00A984BB (FUN_00A984BB, _isctype_l)
 *
 * See the anonymous namespace implementation `RuntimeIsCtypeLocale` for the
 * full behavior description. This `extern "C"` entry point is the stable
 * CRT-facing symbol that other recovered ctype helpers (`_isalpha_l`,
 * `_isdigit_l`, etc.) dispatch into for the DBCS slow path.
 */
extern "C" int __cdecl _isctype_l(const int character, const int mask, _locale_t const localeInfo)
{
  return RuntimeIsCtypeLocale(character, mask, localeInfo);
}

/**
 * Address: 0x00A855EE (FUN_00A855EE, _isalpha_l)
 *
 * What it does:
 * Returns one locale-aware alphabetic classification bitmask by using the
 * locale ctype table fast path for SBCS locales and `_isctype_l` otherwise.
 */
extern "C" int __cdecl _isalpha_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x103u, 0x103);
}

/**
 * Address: 0x00A85642 (FUN_00A85642, isalpha)
 *
 * What it does:
 * Returns one CRT alphabetic-classification mask by using the locale-changed
 * dispatch lane (`_isalpha_l`) or the initial-locale ctype table fast path.
 */
extern "C" int __cdecl isalpha(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x103u, &_isalpha_l);
}

/**
 * Address: 0x00A8566D (FUN_00A8566D, _isupper_l)
 *
 * What it does:
 * Returns one locale-aware uppercase classification mask.
 */
extern "C" int __cdecl _isupper_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x001u, 0x001);
}

/**
 * Address: 0x00A856BC (FUN_00A856BC, isupper)
 *
 * What it does:
 * Returns one uppercase classification mask through locale-changed dispatch
 * or initial-locale fast path.
 */
extern "C" int __cdecl isupper(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x001u, &_isupper_l);
}

/**
 * Address: 0x00A856E5 (FUN_00A856E5, _islower_l)
 *
 * What it does:
 * Returns one locale-aware lowercase classification mask.
 */
extern "C" int __cdecl _islower_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x002u, 0x002);
}

/**
 * Address: 0x00A85734 (FUN_00A85734, islower)
 *
 * What it does:
 * Returns one lowercase classification mask through locale-changed dispatch
 * or initial-locale fast path.
 */
extern "C" int __cdecl islower(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x002u, &_islower_l);
}

/**
 * Address: 0x00A8575D (FUN_00A8575D, _isdigit_l)
 *
 * What it does:
 * Returns one locale-aware decimal-digit classification mask.
 */
extern "C" int __cdecl _isdigit_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x004u, 0x004);
}

/**
 * Address: 0x00A857AC (FUN_00A857AC, isdigit)
 *
 * What it does:
 * Returns one decimal-digit classification mask through locale-changed
 * dispatch or initial-locale fast path.
 */
extern "C" int __cdecl isdigit(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x004u, &_isdigit_l);
}

/**
 * Address: 0x00A857D5 (FUN_00A857D5, _isxdigit_l)
 *
 * What it does:
 * Returns one locale-aware hexadecimal-digit classification mask.
 */
extern "C" int __cdecl _isxdigit_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x080u, 0x080);
}

/**
 * Address: 0x00A85829 (FUN_00A85829, isxdigit)
 *
 * What it does:
 * Returns one hexadecimal-digit classification mask through locale-changed
 * dispatch or initial-locale fast path.
 */
extern "C" int __cdecl isxdigit(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x080u, &_isxdigit_l);
}

/**
 * Address: 0x00A85854 (FUN_00A85854, _isspace_l)
 *
 * What it does:
 * Returns one locale-aware whitespace classification mask.
 */
extern "C" int __cdecl _isspace_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x008u, 0x008);
}

/**
 * Address: 0x00A858A3 (FUN_00A858A3, isspace)
 *
 * What it does:
 * Returns one whitespace classification mask through locale-changed dispatch
 * or initial-locale fast path.
 */
extern "C" int __cdecl isspace(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x008u, &_isspace_l);
}

/**
 * Address: 0x00A858CC (FUN_00A858CC, _ispunct_l)
 *
 * What it does:
 * Returns one locale-aware punctuation classification mask.
 */
extern "C" int __cdecl _ispunct_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x010u, 0x010);
}

/**
 * Address: 0x00A8591B (FUN_00A8591B, ispunct)
 *
 * What it does:
 * Returns one punctuation classification mask through locale-changed dispatch
 * or initial-locale fast path.
 */
extern "C" int __cdecl ispunct(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x010u, &_ispunct_l);
}

/**
 * Address: 0x00A85944 (FUN_00A85944, _isalnum_l)
 *
 * What it does:
 * Returns one locale-aware alpha/digit classification bitmask by using the
 * locale ctype table fast path for SBCS locales and `_isctype_l` otherwise.
 */
extern "C" int __cdecl _isalnum_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x107u, 0x107);
}

/**
 * Address: 0x00A85998 (FUN_00A85998, isalnum)
 *
 * What it does:
 * Returns one alphanumeric classification mask through locale-changed
 * dispatch or initial-locale fast path.
 */
extern "C" int __cdecl isalnum(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x107u, &_isalnum_l);
}

/**
 * Address: 0x00A859C3 (FUN_00A859C3, _isprint_l)
 *
 * What it does:
 * Returns one locale-aware printable-character classification mask.
 */
extern "C" int __cdecl _isprint_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x157u, 0x157);
}

/**
 * Address: 0x00A85A17 (FUN_00A85A17, isprint)
 *
 * What it does:
 * Returns one printable-character classification mask through locale-changed
 * dispatch or initial-locale fast path.
 */
extern "C" int __cdecl isprint(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x157u, &_isprint_l);
}

/**
 * Address: 0x00A85A42 (FUN_00A85A42, _isgraph_l)
 *
 * What it does:
 * Returns one locale-aware graphical-character classification mask.
 */
extern "C" int __cdecl _isgraph_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x117u, 0x117);
}

/**
 * Address: 0x00A85AC1 (FUN_00A85AC1, _iscntrl_l)
 *
 * What it does:
 * Returns one locale-aware control-character classification mask.
 */
extern "C" int __cdecl _iscntrl_l(const int character, _locale_t const localeInfo)
{
  return RuntimeClassifyLocaleCharacter(character, localeInfo, 0x020u, 0x020);
}

/**
 * Address: 0x00A85B10 (FUN_00A85B10, iscntrl)
 *
 * What it does:
 * Returns one control-character classification mask through locale-changed
 * dispatch or initial-locale fast path.
 */
extern "C" int __cdecl iscntrl(const int character)
{
  return RuntimeClassifyInitialOrLocaleChanged(character, 0x020u, &_iscntrl_l);
}

/**
 * Address: 0x00A8E6E5 (FUN_00A8E6E5, toupper)
 *
 * What it does:
 * Converts one character to uppercase using the locale-aware CRT conversion
 * lane when locale state changed, otherwise runs the fast ASCII fold path.
 */
extern "C" int __cdecl toupper(const int character)
{
  if (__locale_changed != 0) {
    return RuntimeToupperLocaleHelper(character, nullptr);
  }

  if (static_cast<unsigned int>(character - static_cast<int>('a'))
      <= static_cast<unsigned int>('z' - 'a')) {
    return character - static_cast<int>('a' - 'A');
  }

  return character;
}

/**
 * Address: 0x00A8FA95 (FUN_00A8FA95, towupper)
 *
 * What it does:
 * Converts one wide character to uppercase through the shared locale-update
 * helper lane with default-locale dispatch.
 */
extern "C" wint_t __cdecl towupper(const wint_t character)
{
  return static_cast<wint_t>(RuntimeTowupperLocaleHelperWide(
    static_cast<std::uint16_t>(character),
    nullptr
  ));
}

/**
 * Address: 0x00A8A3A6 (FUN_00A8A3A6, strtoul)
 *
 * What it does:
 * Parses one unsigned long integer by forwarding to `strtoxl`, selecting
 * either the thread-locale lane or the initial locale descriptor.
 */
extern "C" unsigned long __cdecl strtoul(
  const char* const text,
  char** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return strtoxl(localeInfo, text, endPointer, radix, 1);
}

/**
 * Address: 0x00A8A362 (FUN_00A8A362, strtol)
 *
 * What it does:
 * Parses one signed long integer by forwarding to `strtoxl` with signed-mode
 * semantics and locale-change dispatch parity.
 */
extern "C" long __cdecl strtol(
  const char* const text,
  char** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return static_cast<long>(strtoxl(localeInfo, text, endPointer, radix, 0));
}

/**
 * Address: 0x00A8EA9B (FUN_00A8EA9B, strtol_0)
 *
 * What it does:
 * Byte-string variant of the signed `strtol` lane used by parser callsites
 * that carry `unsigned char*` text/end pointers.
 */
long RuntimeStrtolByteString(
  const unsigned char* const text,
  unsigned char** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return static_cast<long>(strtoxl(
    localeInfo,
    reinterpret_cast<const char*>(text),
    reinterpret_cast<char**>(endPointer),
    radix,
    0
  ));
}

/**
 * Address: 0x00A835D8 (FUN_00A835D8, atoi)
 *
 * What it does:
 * Byte-string `atoi` lane that forwards to the signed decimal parser helper
 * with radix 10 and null end-pointer.
 */
extern "C" int __cdecl atoi(const char* const text)
{
  return static_cast<int>(RuntimeStrtolByteString(
    reinterpret_cast<const unsigned char*>(text),
    nullptr,
    10
  ));
}

/**
 * Address: 0x00A8A38B (FUN_00A8A38B, _strtol_l wrapper lane)
 *
 * What it does:
 * Forwards locale-explicit signed narrow integer parsing into `strtoxl` with
 * signed-mode semantics.
 */
extern "C" long __cdecl RuntimeStrtolLocaleForward(
  const char* const text,
  char** const endPointer,
  const int radix,
  _locale_t const localeInfo
)
{
  return static_cast<long>(strtoxl(
    reinterpret_cast<RuntimeLocaleInfoStruct*>(localeInfo),
    text,
    endPointer,
    radix,
    0
  ));
}

/**
 * Address: 0x00AAC2F6 (FUN_00AAC2F6, _wcstoi64)
 *
 * What it does:
 * Forwards wide-string 64-bit integer parsing to `wcstoxq`, selecting either
 * the active thread locale or `__initiallocalestructinfo`.
 */
static unsigned __int64 RuntimeWcstoi64(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* const localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return wcstoxq(localeInfo, text, endPointer, radix, 0);
}

/**
 * Address: 0x00AAC31F (FUN_00AAC31F, _wcstoi64_l)
 *
 * What it does:
 * Locale-explicit wide-string signed 64-bit parse wrapper forwarding into
 * `wcstoxq(..., flags=0)`.
 */
__int64 __cdecl Runtime_wcstoi64_l(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix,
  RuntimeLocaleInfoStruct* const localeInfo
)
{
  return static_cast<__int64>(wcstoxq(localeInfo, text, endPointer, radix, 0));
}

/**
 * Address: 0x00A8F450 (FUN_00A8F450, _wcstol_l wrapper lane)
 *
 * What it does:
 * Forwards locale-explicit signed wide integer parsing into `_wcstol_l`.
 */
extern "C" long __cdecl RuntimeWcstolLocaleForward(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix,
  _locale_t const localeInfo
)
{
  return ::_wcstol_l(text, endPointer, radix, localeInfo);
}

/**
 * Address: 0x00A8F427 (FUN_00A8F427, wcstol)
 *
 * What it does:
 * MSVC CRT `wcstol(nptr, endptr, base)` implementation. Picks either the
 * locale-changed global table (null pointer triggers the CRT fast path that
 * queries the thread-local locale) or the C-locale initial table depending on
 * the `_locale_changed` flag, then forwards to the low-level `wcstoxl`
 * long-parsing helper with the unsigned-result lane cleared.
 *
 * IDA signature:
 * unsigned int __cdecl wcstol(unsigned __int16 *nptr, unsigned __int16 **endptr, unsigned int ibase);
 */
extern "C" long __cdecl RuntimeWcstolFromLocale(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix
)
{
  // `::wcstol` performs the identical locale dispatch (`_locale_changed` check,
  // thread-local lookup for modified locales, `_initiallocalestructinfo` fast
  // path for the C locale) and invokes the same `wcstoxl` underneath.
  return ::wcstol(text, endPointer, radix);
}

/**
 * Address: 0x00A8F5B3 (FUN_00A8F5B3, wcstod)
 *
 * What it does:
 * MSVC CRT `wcstod(nptr, endptr)` implementation. Forwards to the
 * locale-explicit wide-to-double worker with a null `_locale_t` (use the
 * active thread locale), i.e. `_wcstod_l(nptr, endptr, nullptr)` semantics.
 *
 * IDA signature:
 * int __cdecl sub_A8F5B3(int a1, int a2);
 */
extern "C" double __cdecl RuntimeWcstodFromLocale(
  const wchar_t* const text,
  wchar_t** const endPointer
)
{
  // `::wcstod` performs the identical locale dispatch and invokes the same
  // underlying wide-to-double conversion worker (`sub_A8F4B0` in the
  // binary, i.e. `_wcstod_l(text, endPointer, nullptr)`) that the real
  // `wcstod(a1, a2)` forwards to here.
  return ::wcstod(text, endPointer);
}

/**
 * Address: 0x00A8F63A (FUN_00A8F63A, wcsspn)
 *
 * What it does:
 * MSVC CRT `wcsspn(string, control)` implementation: returns the length of
 * the leading run of `string` that consists entirely of code units also
 * present in `control` (the classic char-by-char nested scan, not the
 * bitmap-optimized variant later CRTs use). Behaviorally identical to
 * `::wcsspn`; the offset this returns is also what CRT `wcscspn`-shaped
 * "first char not in set" callers expect (the boundary right after the
 * matching prefix run).
 *
 * IDA signature:
 * int __cdecl sub_A8F63A(_WORD *a1, _WORD *a2);
 */
extern "C" std::size_t __cdecl RuntimeWcsSpanOfIncludedChars(
  const wchar_t* const text,
  const wchar_t* const characterSet
)
{
  return ::wcsspn(text, characterSet);
}

/**
 * Address: 0x00A8FC4B (FUN_00A8FC4B, _wtoi wrapper lane)
 *
 * What it does:
 * Parses one base-10 signed wide integer by forwarding to `wcstol`.
 */
extern "C" int __cdecl RuntimeWtoiFromWide(const wchar_t* const text)
{
  return static_cast<int>(::wcstol(text, nullptr, 10));
}

/**
 * Address: 0x00A8FC71 (FUN_00A8FC71, _wtoi thunk lane)
 *
 * What it does:
 * Tail-forwards one `_wtoi` thunk lane into `RuntimeWtoiFromWide`.
 */
extern "C" int __cdecl RuntimeWtoiFromWideThunk(const wchar_t* const text)
{
  return RuntimeWtoiFromWide(text);
}

/**
 * Address: 0x00A8FC5C (FUN_00A8FC5C, _wtoi_l wrapper lane)
 *
 * What it does:
 * Parses one base-10 signed wide integer with explicit locale forwarding.
 */
extern "C" int __cdecl RuntimeWtoiFromWideLocale(const wchar_t* const text, _locale_t const localeInfo)
{
  return static_cast<int>(RuntimeWcstolLocaleForward(text, nullptr, 10, localeInfo));
}

/**
 * Address: 0x00A8FC76 (FUN_00A8FC76)
 *
 * What it does:
 * Tail-forwards one `_wtoi_l` thunk lane into the canonical locale-aware
 * wide integer parser helper.
 */
extern "C" int __cdecl RuntimeWtoiFromWideLocaleThunk(const wchar_t* const text, _locale_t const localeInfo)
{
  return RuntimeWtoiFromWideLocale(text, localeInfo);
}

/**
 * Address: 0x00A8FC7B (FUN_00A8FC7B, _wtoi64)
 *
 * What it does:
 * Parses one base-10 wide integer lane by forwarding to `_wcstoi64` with a
 * null end-pointer lane.
 */
extern "C" __int64 __cdecl _wtoi64(const wchar_t* const text)
{
  return static_cast<__int64>(RuntimeWcstoi64(text, nullptr, 10));
}

/**
 * Address: 0x00A8FC8C (FUN_00A8FC8C, _wtoi64_l)
 *
 * What it does:
 * Parses one base-10 wide integer lane by forwarding to `_wcstoi64_l` with a
 * null end-pointer lane and caller-provided locale.
 */
extern "C" __int64 __cdecl _wtoi64_l(const wchar_t* const text, _locale_t localeInfo)
{
  return Runtime_wcstoi64_l(text, nullptr, 10, reinterpret_cast<RuntimeLocaleInfoStruct*>(localeInfo));
}

/**
 * Address: 0x00AAC33A (FUN_00AAC33A, _wcstoui64)
 *
 * What it does:
 * Forwards wide-string unsigned 64-bit parsing to `wcstoxq`, selecting either
 * the active thread locale or `__initiallocalestructinfo`.
 */
extern "C" unsigned __int64 __cdecl _wcstoui64(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* const localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  constexpr int kUnsignedParseFlags = 1;
  return wcstoxq(localeInfo, text, endPointer, radix, kUnsignedParseFlags);
}

/**
 * Address: 0x00AAC364 (FUN_00AAC364, _wcstoui64_l)
 *
 * What it does:
 * Locale-explicit wide-string unsigned 64-bit parse wrapper forwarding into
 * `wcstoxq(..., flags=1)`.
 */
extern "C" unsigned __int64 __cdecl _wcstoui64_l(
  const wchar_t* const text,
  wchar_t** const endPointer,
  const int radix,
  _locale_t localeInfo
)
{
  constexpr int kUnsignedParseFlags = 1;
  return wcstoxq(reinterpret_cast<RuntimeLocaleInfoStruct*>(localeInfo), text, endPointer, radix, kUnsignedParseFlags);
}

/**
 * Address: 0x00A8869E (FUN_00A8869E, mbstowcs)
 *
 * What it does:
 * Forwards multibyte-to-wide conversion into `_mbstowcs_l`, selecting either
 * the current thread locale or `__initiallocalestructinfo`.
 */
extern "C" std::size_t __cdecl
mbstowcs(wchar_t* const destination, const char* const source, const std::size_t maxCount)
{
  RuntimeLocaleInfoStruct* localeInfo = (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return ::_mbstowcs_l(destination, source, maxCount, reinterpret_cast<_locale_t>(localeInfo));
}

/**
 * Address: 0x00A886C6 (FUN_00A886C6, _mbstowcs_s_l)
 *
 * What it does:
 * Performs secure multibyte-to-wide conversion with locale resolution and
 * CRT-compatible invalid-parameter, errno, truncation, and output-nulling
 * semantics.
 */
extern "C" errno_t __cdecl _mbstowcs_s_l(
  std::size_t* const outConvertedCount,
  wchar_t* const destination,
  const std::size_t destinationCount,
  const char* const source,
  const std::size_t maxCount,
  _locale_t const localeInfo
)
{
  if (destination != nullptr) {
    if (destinationCount == 0u) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }
    destination[0] = L'\0';
  } else if (destinationCount != 0u) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return EINVAL;
  }

  if (outConvertedCount != nullptr) {
    *outConvertedCount = 0u;
  }

  RuntimeTidDataLocaleView* threadData = nullptr;
  bool updated = false;
  RuntimeThreadLocInfoView* const resolvedLocaleInfo =
    RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

  const std::size_t conversionCount = (maxCount > destinationCount) ? destinationCount : maxCount;
  const std::size_t convertedWideChars = ::_mbstowcs_l(
    destination,
    source,
    conversionCount,
    reinterpret_cast<_locale_t>(resolvedLocaleInfo)
  );
  if (convertedWideChars == static_cast<std::size_t>(-1)) {
    if (destination != nullptr) {
      destination[0] = L'\0';
    }

    const errno_t result = *_errno();
    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  std::size_t requiredWideChars = convertedWideChars + 1u;
  errno_t result = 0;
  if (destination != nullptr) {
    if (requiredWideChars > destinationCount) {
      if (maxCount != static_cast<std::size_t>(-1)) {
        destination[0] = L'\0';
        *_errno() = ERANGE;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        RuntimeReleaseLocaleUpdate(threadData, updated);
        return ERANGE;
      }

      requiredWideChars = destinationCount;
      result = 80;
    }

    destination[requiredWideChars - 1u] = L'\0';
  }

  if (outConvertedCount != nullptr) {
    *outConvertedCount = requiredWideChars;
  }

  RuntimeReleaseLocaleUpdate(threadData, updated);
  return result;
}

/**
 * Address: 0x00A887BC (FUN_00A887BC, _mbstowcs_s wrapper lane)
 *
 * What it does:
 * Forwards secure multibyte-to-wide conversion into `_mbstowcs_s_l` with
 * null locale so the active thread locale lane is used.
 */
extern "C" errno_t __cdecl RuntimeMbstowcsSecureNoLocale(
  std::size_t* const outConvertedCount,
  wchar_t* const destination,
  const std::size_t destinationCount,
  const char* const source,
  const std::size_t maxCount
)
{
  return _mbstowcs_s_l(outConvertedCount, destination, destinationCount, source, maxCount, nullptr);
}

/**
 * Address: 0x00AB85DF (FUN_00AB85DF, mbtowc)
 *
 * What it does:
 * Converts one multibyte sequence to one wide character through `_mbtowc_l`
 * using the active thread locale lane.
 */
extern "C" int __cdecl mbtowc(
  wchar_t* const destination,
  const char* const source,
  const std::size_t maxCount
)
{
  return ::_mbtowc_l(destination, source, maxCount, nullptr);
}

/**
 * Address: 0x00A85DC0 (FUN_00A85DC0, strcspn)
 *
 * What it does:
 * Returns one prefix length in `text` up to the first byte that belongs to
 * the reject-set string.
 */
extern "C" std::size_t __cdecl strcspn(const char* const text, const char* const reject)
{
  std::uint32_t rejectBitSet[8] = {};
  const auto* rejectCursor = reinterpret_cast<const unsigned char*>(reject);
  while (*rejectCursor != 0u) {
    const unsigned int value = static_cast<unsigned int>(*rejectCursor++);
    rejectBitSet[value >> 5u] |= (1u << (value & 31u));
  }

  std::size_t spanLength = 0u;
  const auto* textCursor = reinterpret_cast<const unsigned char*>(text);
  while (*textCursor != 0u) {
    const unsigned int value = static_cast<unsigned int>(*textCursor);
    if ((rejectBitSet[value >> 5u] & (1u << (value & 31u))) != 0u) {
      break;
    }

    ++textCursor;
    ++spanLength;
  }

  return spanLength;
}

/**
 * Address: 0x00A944E0 (FUN_00A944E0, strcpy)
 *
 * What it does:
 * Copies one null-terminated byte string from `source` to `destination`
 * using the legacy aligned 4-byte zero-detection fast path.
 */
extern "C" char* __cdecl strcpy(char* const destination, const char* const source)
{
  auto* output = reinterpret_cast<unsigned char*>(destination);
  const auto* input = reinterpret_cast<const unsigned char*>(source);

  while ((reinterpret_cast<std::uintptr_t>(input) & 0x3u) != 0u) {
    const unsigned char value = *input++;
    *output++ = value;
    if (value == 0u) {
      return destination;
    }
  }

  for (;;) {
    std::uint32_t chunk = 0u;
    std::memcpy(&chunk, input, sizeof(chunk));

    const std::uint32_t probe = (chunk + 0x7EFEFEFFu) ^ ~chunk;
    if ((probe & 0x81010100u) == 0u) {
      std::memcpy(output, &chunk, sizeof(chunk));
      input += 4u;
      output += 4u;
      continue;
    }

    const unsigned char byte0 = static_cast<unsigned char>(chunk & 0xFFu);
    if (byte0 == 0u) {
      output[0] = 0u;
      return destination;
    }

    const unsigned char byte1 = static_cast<unsigned char>((chunk >> 8u) & 0xFFu);
    if (byte1 == 0u) {
      output[0] = byte0;
      output[1] = 0u;
      return destination;
    }

    const unsigned char byte2 = static_cast<unsigned char>((chunk >> 16u) & 0xFFu);
    if (byte2 == 0u) {
      output[0] = byte0;
      output[1] = byte1;
      output[2] = 0u;
      return destination;
    }

    const unsigned char byte3 = static_cast<unsigned char>((chunk >> 24u) & 0xFFu);
    output[0] = byte0;
    output[1] = byte1;
    output[2] = byte2;
    output[3] = byte3;
    if (byte3 == 0u) {
      return destination;
    }

    input += 4u;
    output += 4u;
  }
}

/**
 * Address: 0x00A8AB75 (FUN_00A8AB75, remove)
 *
 * What it does:
 * Removes one filesystem path using Win32 `DeleteFileA`, mapping any Win32
 * error through `_dosmaperr` and returning CRT `0/-1` semantics.
 */
extern "C" int __cdecl remove(const char* const filePath)
{
  DWORD lastError = 0;
  if (::DeleteFileA(filePath) == FALSE) {
    lastError = ::GetLastError();
  }

  if (lastError == 0u) {
    return 0;
  }

  _dosmaperr(lastError);
  return -1;
}

/**
 * Address: 0x00A8ABA4 (FUN_00A8ABA4, rename)
 *
 * What it does:
 * Renames one filesystem path via Win32 `MoveFileA`, maps any Win32 failure
 * through `_dosmaperr`, and returns CRT `0/-1` status semantics.
 */
extern "C" int __cdecl rename(const char* const existingPath, const char* const newPath)
{
  DWORD lastError = 0;
  if (::MoveFileA(existingPath, newPath) == FALSE) {
    lastError = ::GetLastError();
  }

  if (lastError == 0u) {
    return 0;
  }

  _dosmaperr(lastError);
  return -1;
}

/**
 * Address: 0x00A91745 (FUN_00A91745)
 *
 * What it does:
 * Renames one wide filesystem path pair via Win32 `MoveFileW`, maps any
 * Win32 failure through `_dosmaperr`, and returns CRT `0/-1` status semantics.
 */
extern "C" int __cdecl _wrename(const wchar_t* const existingPath, const wchar_t* const newPath)
{
  DWORD lastError = 0;
  if (::MoveFileW(existingPath, newPath) == FALSE) {
    lastError = ::GetLastError();
  }

  if (lastError == 0u) {
    return 0;
  }

  _dosmaperr(lastError);
  return -1;
}

/**
 * Address: 0x00A83687 (FUN_00A83687, __initterm_e)
 *
 * What it does:
 * Invokes one `[first, last)` constructor table with early stop on the first
 * non-zero return status and returns that status.
 */
extern "C" int __cdecl _initterm_e(
  RuntimeInitFunctionWithStatus* const first,
  RuntimeInitFunctionWithStatus* const last
)
{
  int result = 0;
  for (RuntimeInitFunctionWithStatus* current = first; current < last && result == 0; ++current) {
    if (*current != nullptr) {
      result = (*current)();
    }
  }
  return result;
}

/**
 * Address: 0x00AAADE5 (FUN_00AAADE5, __heap_select)
 *
 * What it does:
 * Queries CRT OS platform/version getters and chooses the active CRT heap
 * backend. Getter failures route to Watson, matching original CRT contracts.
 */
extern "C" int __cdecl _heap_select()
{
  constexpr int kSystemHeap = 1;
  constexpr int kV6Heap = 3;

  unsigned int platformId = 0u;
  unsigned int platformMajorVersion = 0u;

  if (_get_osplatform(&platformId) != 0) {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
  }

  if (_get_winmajor(&platformMajorVersion) != 0) {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
  }

  if (platformId == static_cast<unsigned int>(VER_PLATFORM_WIN32_NT) && platformMajorVersion >= 5u) {
    return kSystemHeap;
  }

  return kV6Heap;
}

/**
 * Address: 0x00ABAB0D (FUN_00ABAB0D, _set_sbh_threshold)
 *
 * What it does:
 * Validates and applies one small-block heap threshold lane, initializing SBH
 * state when switching from system heap mode to V6 heap mode.
 */
extern "C" int __cdecl _set_sbh_threshold(const std::size_t threshold)
{
  constexpr int kSystemHeap = 1;
  constexpr int kV6Heap = 3;
  constexpr std::size_t kMaxSbhThreshold = 0x3F8u;

  if (_crtheap == nullptr) {
    return 0;
  }

  if (_active_heap != kV6Heap) {
    if (threshold != 0u) {
      if (_active_heap != kSystemHeap) {
        *_errno() = EINVAL;
        return 0;
      }

      if (threshold > kMaxSbhThreshold || _sbh_heap_init(threshold) == 0) {
        *_errno() = EINVAL;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        return 0;
      }

      _sbh_threshold = threshold;
      _active_heap = kV6Heap;
    }

    return 1;
  }

  if (threshold > kMaxSbhThreshold) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0;
  }

  _sbh_threshold = threshold;
  return 1;
}

/**
 * Address: 0x00ABA82B (FUN_00ABA82B, __sbh_verify)
 *
 * What it does:
 * Validates SBH headers, page tags, free-list bucket membership, and entry
 * bitvectors for every committed group and returns the first negative error
 * code on invariant failure.
 */
extern "C" int __cdecl _sbh_verify()
{
  if (_sbh_pHeaderList == nullptr) {
    return -1;
  }

  if (_sbh_cntHeaderList <= 0) {
    return 0;
  }

  for (int headerIndex = 0; headerIndex < _sbh_cntHeaderList; ++headerIndex) {
    tagHeader* const header = &_sbh_pHeaderList[headerIndex];
    tagRegion* const region = header->pRegion;
    if (region == nullptr) {
      return -2;
    }

    std::uint8_t* groupHeapBase = reinterpret_cast<std::uint8_t*>(header->pHeapData);
    std::int32_t commitBits = static_cast<std::int32_t>(header->bitvCommit);
    BITVEC expectedEntryHi = 0u;
    BITVEC expectedEntryLo = 0u;

    for (int groupIndex = 0; groupIndex < 32; ++groupIndex) {
      std::int32_t usedEntryCount = 0;
      BITVEC expectedGroupHi = 0u;
      BITVEC expectedGroupLo = 0u;
      std::uint32_t freeBucketHistogram[64]{};

      if (commitBits >= 0) {
        if (groupHeapBase == nullptr) {
          return -4;
        }

        auto* pageTail = reinterpret_cast<std::int32_t*>(groupHeapBase + 4092u);
        for (int pageIndex = 0; pageIndex < 8; ++pageIndex, pageTail += 1024) {
          auto* entry = pageTail - 1020;
          if (*(pageTail - 1021) != -1 || *pageTail != -1) {
            return -5;
          }

          std::int32_t* nextEntry = entry;
          do {
            const std::int32_t sizeWithFlags = *entry;
            std::int32_t spanBytes = sizeWithFlags;
            if ((sizeWithFlags & 1) != 0) {
              --spanBytes;
              if (static_cast<unsigned int>(spanBytes) > 1024u) {
                return -6;
              }
              ++usedEntryCount;
            } else {
              int bucket = (spanBytes >> 4) - 1;
              if (bucket > 63) {
                bucket = 63;
              }
              ++freeBucketHistogram[bucket];
            }

            if (spanBytes < 16 || (spanBytes & 0xF) != 0 || spanBytes > 4080) {
              return -7;
            }

            nextEntry = reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(entry) + spanBytes);
            const auto* const trailingSize = reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(entry) + spanBytes - 4);
            if (*trailingSize != sizeWithFlags) {
              return -8;
            }
            entry = nextEntry;
          } while (nextEntry < pageTail);

          if (nextEntry != pageTail) {
            return -8;
          }
        }

        int* bucketCursor = &region->grpHeadList[groupIndex].cntEntries;
        if (*bucketCursor != usedEntryCount) {
          return -9;
        }

        for (int bucketIndex = 0; bucketIndex < 64; ++bucketIndex) {
          int seenBucketCount = 0;
          int* const nextBucketCursor = bucketCursor + 2;

          const std::uintptr_t sentinel = reinterpret_cast<std::uintptr_t>(bucketCursor);
          std::uintptr_t previousNode = sentinel;
          std::uintptr_t currentNode = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(bucketCursor[1]));

          if (reinterpret_cast<int*>(currentNode) != bucketCursor) {
            do {
              if (seenBucketCount == static_cast<int>(freeBucketHistogram[bucketIndex])) {
                break;
              }

              if (
                currentNode < reinterpret_cast<std::uintptr_t>(groupHeapBase)
                || currentNode >= reinterpret_cast<std::uintptr_t>(groupHeapBase + 0x8000u)
              ) {
                return -10;
              }

              auto* pageCursor = reinterpret_cast<std::uint32_t*>((currentNode & 0xFFFFF000u) + 12u);
              const std::uintptr_t pageEnd = (currentNode & 0xFFFFF000u) + 4092u;
              if (reinterpret_cast<std::uintptr_t>(pageCursor) == pageEnd) {
                return -11;
              }

              do {
                if (reinterpret_cast<std::uintptr_t>(pageCursor) == currentNode) {
                  break;
                }
                pageCursor = reinterpret_cast<std::uint32_t*>(
                  reinterpret_cast<std::uint8_t*>(pageCursor) + ((*pageCursor) & 0xFFFFFFFEu)
                );
              } while (reinterpret_cast<std::uintptr_t>(pageCursor) != pageEnd);

              if (reinterpret_cast<std::uintptr_t>(pageCursor) == pageEnd) {
                return -11;
              }

              int bucketFromSize = (static_cast<int>(*reinterpret_cast<std::uint32_t*>(currentNode)) >> 4) - 1;
              if (bucketFromSize > 63) {
                bucketFromSize = 63;
              }
              if (bucketFromSize != bucketIndex) {
                return -12;
              }

              if (*reinterpret_cast<std::uint32_t*>(currentNode + 8u) != static_cast<std::uint32_t>(previousNode)) {
                return -13;
              }

              ++seenBucketCount;
              previousNode = currentNode;
              currentNode = *reinterpret_cast<std::uint32_t*>(currentNode + 4u);
            } while (reinterpret_cast<int*>(currentNode) != bucketCursor);

            if (seenBucketCount != 0) {
              if (bucketIndex >= 32) {
                const BITVEC bit = 0x80000000u >> (bucketIndex - 32);
                expectedGroupLo |= bit;
                expectedEntryLo |= bit;
              } else {
                const BITVEC bit = 0x80000000u >> bucketIndex;
                expectedGroupHi |= bit;
                expectedEntryHi |= bit;
              }
            }
          }

          if (
            *reinterpret_cast<std::uint32_t*>(previousNode + 4u) != static_cast<std::uint32_t>(sentinel)
            || seenBucketCount != static_cast<int>(freeBucketHistogram[bucketIndex])
          ) {
            return -14;
          }

          if (*nextBucketCursor != static_cast<int>(previousNode)) {
            return -15;
          }

          bucketCursor = nextBucketCursor;
        }
      }

      if (expectedGroupHi != region->bitvGroupHi[groupIndex] || expectedGroupLo != region->bitvGroupLo[groupIndex]) {
        return -16;
      }

      groupHeapBase += 0x8000u;
      commitBits <<= 1;
    }

    if (expectedEntryHi != header->bitvEntryHi || expectedEntryLo != header->bitvEntryLo) {
      return -17;
    }
  }

  return 0;
}

namespace
{
  int gRuntimeNewMode = 0;
}

/**
 * Address: 0x00AB9EC0 (FUN_00AB9EC0, _set_new_mode)
 *
 * What it does:
 * Stores one CRT new-allocation mode lane when the process heap is active;
 * invalid inputs (including newMode == 0) trigger `errno=EINVAL` and
 * invalid-parameter semantics, matching the disassembly exactly.
 *
 * Named off the reserved CRT symbol despite that - not `_set_new_mode` -
 * deliberately: this function has zero xrefs in the shipped binary (its
 * VS2005 static CRT never called it; nothing in this engine's own recovered
 * source does either), so there is no observed 2007 behavior this identity
 * preserves. Under the modern VS2022 toolchain this project builds with,
 * giving it that exact external name instead hijacks a real bootstrap step:
 * `pre_cpp_initialization` (genuine, unmodified vcstartup source) calls the
 * real `_set_new_mode(_newmode)` as part of CRT init with `_newmode`
 * defaulting to 0, and our all-zero-rejecting body took over that call
 * before `main` ever runs, hard-crashing the process at startup. Keeping
 * the disassembled logic under a non-colliding name preserves the
 * recovery; not colliding lets the linker's own, correct implementation
 * handle the real bootstrap call as intended.
 */
extern "C" int __cdecl EngineSetNewMode(const int newMode)
{
  if (newMode != 0 && _crtheap != nullptr) {
    gRuntimeNewMode = newMode;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00AB9F06 (FUN_00AB9F06, _query_new_mode)
 *
 * What it does:
 * Returns the active CRT new-allocation mode lane through `outNewMode`;
 * null outputs or missing process heap route through invalid-parameter flow.
 *
 * Renamed for the same reason as `EngineSetNewMode` above (zero xrefs in
 * the shipped binary, zero callers in recovered source, and the real
 * `_query_new_mode` name is load-bearing for the modern toolchain's own
 * CRT internals).
 */
extern "C" int __cdecl EngineQueryNewMode(int* const outNewMode)
{
  if (outNewMode != nullptr && _crtheap != nullptr) {
    *outNewMode = gRuntimeNewMode;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00AB9F42 (FUN_00AB9F42, __sbh_heap_init)
 *
 * What it does:
 * Allocates the small-block-heap header table and resets all SBH header-lane
 * globals to their startup defaults.
 */
extern "C" int __cdecl _sbh_heap_init(const std::size_t threshold)
{
  _sbh_pHeaderList = static_cast<tagHeader*>(::HeapAlloc(_crtheap, 0u, 0x140u));
  if (_sbh_pHeaderList == nullptr) {
    return 0;
  }

  _sbh_pHeaderDefer = nullptr;
  _sbh_cntHeaderList = 0;
  _sbh_pHeaderScan = _sbh_pHeaderList;
  _sbh_threshold = threshold;
  _sbh_sizeHeaderList = 16;
  return 1;
}

namespace
{
  constexpr int kSbhBinsPerGroup = 64;
  constexpr std::size_t kSbhCommittedGroupBytes = 0x8000;
  constexpr std::size_t kSbhCommitPageBytes = 0x1000;
  constexpr std::size_t kSbhCommitPageCount = 8;
  constexpr std::size_t kSbhLastPageOffset = 0x7000;
  constexpr std::int32_t kSbhFreePayloadBytes = 0x0FF0;

  [[nodiscard]] tagEntry* RuntimeSbhGroupSentinel(tagGroup* const group, const int bucketIndex) noexcept
  {
    auto* const groupBytes = reinterpret_cast<std::uint8_t*>(group);
    return reinterpret_cast<tagEntry*>(groupBytes + (static_cast<std::size_t>(bucketIndex) * sizeof(tagListHead)));
  }

  [[nodiscard]] std::uint32_t RuntimeSbhBucketFromSize(const std::uint32_t sizeBytes) noexcept
  {
    std::uint32_t bucket = (sizeBytes >> 4u) - 1u;
    if (bucket > 0x3Fu) {
      bucket = 0x3Fu;
    }
    return bucket;
  }

  void RuntimeSbhUnlinkEntry(tagEntry* const entry) noexcept
  {
    entry->pEntryNext->pEntryPrev = entry->pEntryPrev;
    entry->pEntryPrev->pEntryNext = entry->pEntryNext;
  }

  void RuntimeSbhClearBucketState(
    tagHeader* const header,
    tagRegion* const region,
    const unsigned int groupIndex,
    const unsigned int bucket
  ) noexcept
  {
    if (bucket >= 0x20u) {
      const std::uint32_t mask = ~(0x80000000u >> (bucket - 0x20u));
      region->bitvGroupLo[groupIndex] &= mask;
      if (region->cntRegionSize[bucket]-- == 1u) {
        header->bitvEntryLo &= mask;
      }
      return;
    }

    const std::uint32_t mask = ~(0x80000000u >> bucket);
    region->bitvGroupHi[groupIndex] &= mask;
    if (region->cntRegionSize[bucket]-- == 1u) {
      header->bitvEntryHi &= mask;
    }
  }

  void RuntimeSbhSetBucketState(
    tagHeader* const header,
    tagRegion* const region,
    const unsigned int groupIndex,
    const unsigned int bucket
  ) noexcept
  {
    const std::uint8_t countBeforeInsert = region->cntRegionSize[bucket];
    region->cntRegionSize[bucket] = static_cast<std::uint8_t>(countBeforeInsert + 1u);

    if (bucket >= 0x20u) {
      const std::uint32_t mask = 0x80000000u >> (bucket - 0x20u);
      if (countBeforeInsert == 0u) {
        header->bitvEntryLo |= mask;
      }
      region->bitvGroupLo[groupIndex] |= mask;
      return;
    }

    const std::uint32_t mask = 0x80000000u >> bucket;
    if (countBeforeInsert == 0u) {
      header->bitvEntryHi |= mask;
    }
    region->bitvGroupHi[groupIndex] |= mask;
  }
} // namespace

/**
 * Address: 0x00ABA379 (FUN_00ABA379, __sbh_alloc_new_group)
 *
 * What it does:
 * Commits one deferred 0x8000-byte SBH group, initializes per-page boundary
 * tags/free-list links, and publishes that group into the size-63 free-bin.
 */
extern "C" int __cdecl _sbh_alloc_new_group(tagHeader* const header)
{
  std::int32_t commitBits = static_cast<std::int32_t>(header->bitvCommit);
  tagRegion* const region = header->pRegion;
  int groupIndex = 0;
  while (commitBits >= 0) {
    commitBits <<= 1;
    ++groupIndex;
  }

  tagGroup* const group = &region->grpHeadList[groupIndex];
  for (int bucket = 0; bucket < (kSbhBinsPerGroup - 1); ++bucket) {
    tagEntry* const sentinel = RuntimeSbhGroupSentinel(group, bucket);
    sentinel->pEntryPrev = sentinel;
    sentinel->pEntryNext = sentinel;
  }

  auto* const groupMemory = reinterpret_cast<std::uint8_t*>(header->pHeapData)
    + (static_cast<std::size_t>(groupIndex) * kSbhCommittedGroupBytes);
  auto* const firstEntry = reinterpret_cast<tagEntry*>(groupMemory);
  if (::VirtualAlloc(firstEntry, kSbhCommittedGroupBytes, MEM_COMMIT, PAGE_READWRITE) == nullptr) {
    return -1;
  }

  // CRT SBH group format stores 32-bit boundary tags at fixed page offsets.
  const auto* const loopEnd = reinterpret_cast<const tagEntry*>(&firstEntry[2389].pEntryNext);
  if (firstEntry <= loopEnd) {
    for (std::size_t pageIndex = 0; pageIndex < kSbhCommitPageCount; ++pageIndex) {
      auto* const pageBase = groupMemory + (pageIndex * kSbhCommitPageBytes);
      *reinterpret_cast<std::int32_t*>(pageBase + 0x008) = -1;
      *reinterpret_cast<std::int32_t*>(pageBase + 0xFFC) = -1;
      *reinterpret_cast<tagEntry**>(pageBase + 0x010) = reinterpret_cast<tagEntry*>(pageBase + 0x100C);
      *reinterpret_cast<std::int32_t*>(pageBase + 0x00C) = kSbhFreePayloadBytes;
      *reinterpret_cast<tagEntry**>(pageBase + 0x014) = reinterpret_cast<tagEntry*>(pageBase + 0x00C);
      *reinterpret_cast<std::int32_t*>(pageBase + 0xFF8) = kSbhFreePayloadBytes;
    }
  }

  auto* const lastPageEntry = reinterpret_cast<tagEntry*>(groupMemory + kSbhLastPageOffset);
  tagEntry* const size63Sentinel = RuntimeSbhGroupSentinel(group, 63);
  size63Sentinel->pEntryPrev = firstEntry + 1;
  (firstEntry + 1)->pEntryNext = size63Sentinel;
  size63Sentinel->pEntryNext = lastPageEntry + 1;
  (lastPageEntry + 1)->pEntryPrev = size63Sentinel;

  region->bitvGroupHi[groupIndex] = 0;
  region->bitvGroupLo[groupIndex] = 1;
  if (region->cntRegionSize[63]++ == 0) {
    header->bitvEntryLo |= 1u;
  }

  header->bitvCommit &= ~(0x80000000u >> groupIndex);
  return groupIndex;
}

/**
 * Address: 0x00ABA75E (FUN_00ABA75E, __sbh_heapmin)
 *
 * What it does:
 * Decommits one deferred small-block heap group, updates owner header state,
 * and compacts the header table when the deferred header becomes fully free.
 */
extern "C" tagHeader* __cdecl _sbh_heapmin()
{
  tagHeader* result = _sbh_pHeaderDefer;
  if (_sbh_pHeaderDefer == nullptr) {
    return result;
  }

  (void)::VirtualFree(
    reinterpret_cast<std::uint8_t*>(_sbh_pHeaderDefer->pHeapData)
      + (static_cast<std::size_t>(_sbh_indGroupDefer) * kSbhCommittedGroupBytes),
    kSbhCommittedGroupBytes,
    MEM_DECOMMIT
  );
  _sbh_pHeaderDefer->bitvCommit |= 0x80000000u >> _sbh_indGroupDefer;
  _sbh_pHeaderDefer->pRegion->bitvGroupLo[_sbh_indGroupDefer] = 0u;
  --_sbh_pHeaderDefer->pRegion->cntRegionSize[63];

  result = _sbh_pHeaderDefer;
  if (_sbh_pHeaderDefer->pRegion->cntRegionSize[63] == 0u) {
    _sbh_pHeaderDefer->bitvEntryLo &= ~1u;
    result = _sbh_pHeaderDefer;
  }

  if (result->bitvCommit == 0xFFFFFFFFu && _sbh_cntHeaderList > 1) {
    (void)::HeapFree(_crtheap, 0u, result->pRegion);

    const std::size_t deferredIndex = static_cast<std::size_t>(_sbh_pHeaderDefer - _sbh_pHeaderList);
    const std::size_t headersToMove = static_cast<std::size_t>(_sbh_cntHeaderList) - deferredIndex - 1u;
    if (headersToMove != 0u) {
      std::memmove(_sbh_pHeaderDefer, _sbh_pHeaderDefer + 1, headersToMove * sizeof(tagHeader));
    }

    --_sbh_cntHeaderList;
  }

  _sbh_pHeaderDefer = nullptr;
  return result;
}

/**
 * Address: 0x00AB9FB5 (FUN_00AB9FB5, __sbh_free_block)
 *
 * What it does:
 * Releases one SBH allocation, coalesces with adjacent free neighbors, updates
 * free-bin bitvectors/lists, and maintains deferred group decommit state.
 */
extern "C" void __cdecl _sbh_free_block(tagHeader* const header, void* const allocation)
{
  tagHeader* ownerHeader = header;
  tagRegion* const region = ownerHeader->pRegion;
  auto* entry = reinterpret_cast<tagEntry*>(static_cast<std::uint8_t*>(allocation) - sizeof(std::int32_t));
  const unsigned int groupIndex = static_cast<unsigned int>(
    (reinterpret_cast<std::uintptr_t>(allocation) - reinterpret_cast<std::uintptr_t>(ownerHeader->pHeapData)) >> 15u
  );
  tagGroup* const group = &region->grpHeadList[groupIndex];

  std::int32_t mergedSize = entry->sizeFront - 1;
  if ((mergedSize & 1) != 0) {
    return;
  }

  auto* const rightEntry = reinterpret_cast<tagEntry*>(reinterpret_cast<std::uint8_t*>(entry) + mergedSize);
  const std::int32_t rightSize = rightEntry->sizeFront;
  const std::int32_t leftSizeOrFlags = *reinterpret_cast<std::int32_t*>(static_cast<std::uint8_t*>(allocation) - 8u);

  if ((rightSize & 1) == 0) {
    const unsigned int rightBucket = RuntimeSbhBucketFromSize(static_cast<std::uint32_t>(rightSize));
    if (rightEntry->pEntryPrev == rightEntry->pEntryNext) {
      RuntimeSbhClearBucketState(ownerHeader, region, groupIndex, rightBucket);
    }

    RuntimeSbhUnlinkEntry(rightEntry);
    mergedSize += rightSize;
  }

  unsigned int mergedBucket = RuntimeSbhBucketFromSize(static_cast<std::uint32_t>(mergedSize));
  unsigned int leftBucket = 0u;
  const bool previousAllocated = (leftSizeOrFlags & 1) != 0;

  if (!previousAllocated) {
    auto* const leftEntry = reinterpret_cast<tagEntry*>(reinterpret_cast<std::uint8_t*>(entry) - leftSizeOrFlags);
    leftBucket = RuntimeSbhBucketFromSize(static_cast<std::uint32_t>(leftSizeOrFlags));
    mergedSize += leftSizeOrFlags;
    mergedBucket = RuntimeSbhBucketFromSize(static_cast<std::uint32_t>(mergedSize));

    if (leftBucket != mergedBucket) {
      if (leftEntry->pEntryPrev == leftEntry->pEntryNext) {
        RuntimeSbhClearBucketState(ownerHeader, region, groupIndex, leftBucket);
      }

      RuntimeSbhUnlinkEntry(leftEntry);
    }

    entry = leftEntry;
  }

  if (previousAllocated || leftBucket != mergedBucket) {
    tagEntry* const bucketSentinel = RuntimeSbhGroupSentinel(group, static_cast<int>(mergedBucket));
    tagEntry* const previousTail = bucketSentinel->pEntryPrev;
    entry->pEntryNext = bucketSentinel;
    entry->pEntryPrev = previousTail;
    bucketSentinel->pEntryPrev = entry;
    entry->pEntryPrev->pEntryNext = entry;

    if (entry->pEntryPrev == entry->pEntryNext) {
      RuntimeSbhSetBucketState(ownerHeader, region, groupIndex, mergedBucket);
    }
  }

  entry->sizeFront = mergedSize;
  *reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(entry) + mergedSize - sizeof(std::int32_t)) = mergedSize;

  if (group->cntEntries-- == 1) {
    if (_sbh_pHeaderDefer != nullptr) {
      (void)::VirtualFree(
        reinterpret_cast<std::uint8_t*>(_sbh_pHeaderDefer->pHeapData)
          + (static_cast<std::size_t>(_sbh_indGroupDefer) * kSbhCommittedGroupBytes),
        kSbhCommittedGroupBytes,
        MEM_DECOMMIT
      );
      _sbh_pHeaderDefer->bitvCommit |= 0x80000000u >> _sbh_indGroupDefer;
      _sbh_pHeaderDefer->pRegion->bitvGroupLo[_sbh_indGroupDefer] = 0u;
      --_sbh_pHeaderDefer->pRegion->cntRegionSize[63];

      tagHeader* deferredHeader = _sbh_pHeaderDefer;
      if (_sbh_pHeaderDefer->pRegion->cntRegionSize[63] == 0u) {
        _sbh_pHeaderDefer->bitvEntryLo &= ~1u;
        deferredHeader = _sbh_pHeaderDefer;
      }

      if (deferredHeader->bitvCommit == 0xFFFFFFFFu) {
        (void)::VirtualFree(deferredHeader->pHeapData, 0u, MEM_RELEASE);
        (void)::HeapFree(_crtheap, 0u, _sbh_pHeaderDefer->pRegion);

        const std::size_t deferredIndex = static_cast<std::size_t>(_sbh_pHeaderDefer - _sbh_pHeaderList);
        const std::size_t headersToMove = static_cast<std::size_t>(_sbh_cntHeaderList) - deferredIndex - 1u;
        if (headersToMove != 0u) {
          std::memmove(_sbh_pHeaderDefer, _sbh_pHeaderDefer + 1, headersToMove * sizeof(tagHeader));
        }

        --_sbh_cntHeaderList;
        if (ownerHeader > _sbh_pHeaderDefer) {
          --ownerHeader;
        }
        _sbh_pHeaderScan = _sbh_pHeaderList;
      }
    }

    _sbh_pHeaderDefer = ownerHeader;
    _sbh_indGroupDefer = groupIndex;
  }
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
 * Address: 0x00AAAE9A (FUN_00AAAE9A, __heap_term)
 *
 * What it does:
 * Releases small-block heap region/header storage when the V6 heap backend is
 * active, destroys the CRT process heap, and clears `_crtheap`.
 */
extern "C" BOOL __cdecl _heap_term()
{
  if (_active_heap == 3 && _sbh_pHeaderList != nullptr) {
    const int headerCount = _sbh_cntHeaderList;
    for (int index = 0; index < headerCount; ++index) {
      tagHeader& header = _sbh_pHeaderList[index];
      (void)::VirtualFree(header.pHeapData, 0u, MEM_RELEASE);
      (void)::HeapFree(_crtheap, 0u, header.pRegion);
    }
    (void)::HeapFree(_crtheap, 0u, _sbh_pHeaderList);
  }

  const BOOL result = ::HeapDestroy(_crtheap);
  _crtheap = nullptr;
  return result;
}

namespace
{
  const char* const kLegacySystemErrorMessages[] = {
    "No error",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted function call",
    "Input/output error",
    "No such device or address",
    "Arg list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Not enough space",
    "Permission denied",
    "Bad address",
    "Unknown error",
    "Resource device",
    "File exists",
    "Improper link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate I/O control operation",
    "Unknown error",
    "File too large",
    "No space left on device",
    "Invalid seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Domain error",
    "Result too large",
    "Unknown error",
    "Resource deadlock avoided",
    "Unknown error",
    "Filename too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Illegal byte sequence",
    "Unknown error",
  };

  int kLegacySystemErrorMessageCount =
    static_cast<int>(sizeof(kLegacySystemErrorMessages) / sizeof(kLegacySystemErrorMessages[0]) - 1u);
}

/**
 * Address: 0x00AA3FC2 (FUN_00AA3FC2)
 *
 * What it does:
 * Returns the upper-bound count lane used by the legacy system-error message
 * lookup helper.
 */
extern "C" int* __cdecl RuntimeSystemErrorMessageLimit()
{
  return &kLegacySystemErrorMessageCount;
}

/**
 * Address: 0x00AA3FC8 (FUN_00AA3FC8)
 *
 * What it does:
 * Returns the base pointer for the legacy system-error message table whose
 * first entry is "No error".
 */
extern "C" const char* const* __cdecl RuntimeSystemErrorMessageTableBase()
{
  return kLegacySystemErrorMessages;
}

/**
 * Address: 0x00A89D6B (FUN_00A89D6B, __get_sys_err_msg)
 *
 * What it does:
 * Bounds-checks the requested errno lane and returns the corresponding legacy
 * system-error message pointer, falling back to the final "Unknown error" slot.
 */
extern "C" const char* __cdecl _get_sys_err_msg(const int errorCode)
{
  int index = errorCode;
  int* const count = RuntimeSystemErrorMessageLimit();
  if (index < 0 || index >= *count) {
    index = *count;
  }

  return RuntimeSystemErrorMessageTableBase()[index];
}

/**
 * Address: 0x00A89DF5 (FUN_00A89DF5, strerror_s)
 *
 * What it does:
 * Copies one CRT system-error text for `errorCode` into caller buffer and
 * triggers Watson on secure-copy failure.
 */
extern "C" errno_t __cdecl strerror_s(char* const outText, const std::size_t outTextChars, const int errorCode)
{
  if (outText != nullptr && outTextChars != 0) {
    const char* const errorText = _get_sys_err_msg(errorCode);
    if (strncpy_s(
          outText,
          static_cast<std::size_t>(outTextChars),
          errorText,
          static_cast<std::size_t>(outTextChars - 1)
        ) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
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
 * Address: 0x00A9CDB6 (FUN_00A9CDB6, _set_daylight)
 *
 * What it does:
 * Returns the CRT daylight global lane pointer.
 */
extern "C" int* __cdecl _set_daylight()
{
  return &daylight;
}

/**
 * Address: 0x00A9CDBC (FUN_00A9CDBC, _set_dstbias)
 *
 * What it does:
 * Returns the CRT daylight-saving bias global lane pointer.
 */
extern "C" long* __cdecl _set_dstbias()
{
  return &_dstbias;
}

/**
 * Address: 0x00A9CDC2 (FUN_00A9CDC2, _set_timezone)
 *
 * What it does:
 * Returns the CRT timezone global lane pointer.
 */
extern "C" long* __cdecl _set_timezone()
{
  return &_timezone;
}

/**
 * Address: 0x00A9CDC8 (FUN_00A9CDC8, __tzname)
 *
 * What it does:
 * Returns the CRT timezone-name pointer array lane.
 */
extern "C" char** __cdecl __tzname()
{
  return _tzname;
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
 * Address: 0x00A8C50B (FUN_00A8C50B, __updatetlocinfo)
 *
 * IDA signature:
 * threadlocinfo *__usercall __updatetlocinfo@<eax>();
 *
 * What it does:
 * Refreshes the per-thread locale pointer `_tiddata::ptlocinfo` so that it
 * reflects the current process locale:
 *   * If the thread owns its own locale (`globallocalestatus & ownlocale`
 *     non-zero) AND `ptlocinfo` is already set, return the current
 *     `ptlocinfo` without re-acquiring it.
 *   * Otherwise acquire `_SETLOCALE_LOCK`, call
 *     `_updatetlocinfoEx_nolock(&ptd->ptlocinfo, _ptlocinfo)` to copy the
 *     process locale into the thread slot with refcount bookkeeping,
 *     release the lock, and return the resulting pointer.
 *   * If the result is null, call `_amsg_exit(32)` (CRT runtime failure
 *     abort code for "locale init failure") and never return.
 */
extern "C" RuntimeLocaleCodePageView* __cdecl __updatetlocinfo()
{
  constexpr int kSetLocaleLock = 19;             // _SETLOCALE_LOCK in MSVC8 CRT
  constexpr int kCrtLocaleInitFailureCode = 32;  // _amsg_exit code R6032 equivalent

  RuntimeTidDataLocaleView* const threadData = __getptd();

  RuntimeLocaleCodePageView* locale = nullptr;
  if ((__globallocalestatus & threadData->ownlocale) != 0 && threadData->ptlocinfo != nullptr) {
    locale = __getptd()->ptlocinfo;
  } else {
    _lock(kSetLocaleLock);
    locale = _updatetlocinfoEx_nolock(&threadData->ptlocinfo, __ptlocinfo);
    _unlock(kSetLocaleLock);
  }

  if (locale == nullptr) {
    __amsg_exit(kCrtLocaleInitFailureCode);
  }
  return locale;
}

/**
 * Address: 0x00AA6489 (FUN_00AA6489, ___mb_cur_max_func)
 *
 * What it does:
 * Returns the active CRT `mb_cur_max` lane for the current thread locale,
 * refreshing thread-locale state when global-locale ownership is not active.
 */
extern "C" int __cdecl ___mb_cur_max_func()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  RuntimeLocaleCodePageView* locale = threadData->ptlocinfo;
  if (locale != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    locale = __updatetlocinfo();
  }

  return reinterpret_cast<const RuntimeLocaleLegacySyncView*>(locale)->mbCurMax;
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
 * Address: 0x00AA64EE (FUN_00AA64EE, ___lc_collate_cp_func)
 *
 * What it does:
 * Returns the active CRT collation codepage lane for the current thread,
 * refreshing thread-locale state when this thread is not in global-locale mode.
 */
extern "C" unsigned int __cdecl __lc_collate_cp_func()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  RuntimeLocaleCodePageView* locale = threadData->ptlocinfo;
  if (locale != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    locale = __updatetlocinfo();
  }

  const auto* const legacyLocale = reinterpret_cast<const RuntimeLocaleLegacySyncView*>(locale);
  return static_cast<unsigned int>(legacyLocale->lcCollateCodepage);
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

/**
 * Address: 0x00AA54EE (FUN_00AA54EE, __pwctype_func)
 *
 * What it does:
 * Returns the process-global wide-ctype lookup table pointer lane.
 */
extern "C" const wctype_t* __cdecl __pwctype_func()
{
  return reinterpret_cast<const wctype_t*>(_pwctype);
}

/**
 * Address: 0x00AA54F4 (FUN_00AA54F4, __pctype_func)
 *
 * What it does:
 * Returns the active CRT ctype table lane for the current thread, refreshing
 * thread-locale state when this thread does not own the global locale.
 */
extern "C" const std::uint16_t* __cdecl __pctype_func()
{
  RuntimeTidDataLocaleView* const threadData = __getptd();
  RuntimeLocaleCodePageView* locale = threadData->ptlocinfo;
  if (locale != __ptlocinfo && (__globallocalestatus & threadData->ownlocale) == 0) {
    locale = __updatetlocinfo();
  }

  return reinterpret_cast<const RuntimeLocaleCTypeTableView*>(locale)->pctype;
}

namespace
{
  // Address: 0x00A97C75 (FUN_00A97C75, getSystemCP)
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

namespace
{
  using RuntimeValidatedOutputFn = int(__cdecl*)(void* stream, int format, int localeInfo, int arguments);
}

/**
 * Address: 0x00A9790A (FUN_00A9790A, sub_A9790A)
 *
 * What it does:
 * Builds one stack-file scratch lane for CRT output callbacks; null stream
 * pointer follows `_invalid_parameter` failure semantics and returns `-1`.
 */
[[maybe_unused]] static int __cdecl RuntimeDispatchValidatedOutputCall(
  RuntimeValidatedOutputFn outputFn,
  const int stream,
  const int localeInfo,
  const int arguments
)
{
  if (stream != 0) {
    std::uint32_t scratchFile[8]{};
    scratchFile[1] = 0x7FFFFFFFu;
    scratchFile[2] = 0u;
    scratchFile[3] = 0x42u;
    return outputFn(scratchFile, stream, localeInfo, arguments);
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return -1;
}

/**
 * Address: 0x00A9795F (FUN_00A9795F)
 *
 * What it does:
 * Dispatches one validated narrow output callback with default locale (`0`).
 */
extern "C" int __cdecl RuntimeDispatchValidatedOutputLegacyNoLocale(
  const int stream,
  const int arguments
)
{
  return RuntimeDispatchValidatedOutputCall(
    reinterpret_cast<RuntimeValidatedOutputFn>(_output_l),
    stream,
    0,
    arguments
  );
}

/**
 * Address: 0x00A97977 (FUN_00A97977)
 *
 * What it does:
 * Dispatches one validated narrow output callback with caller-provided locale.
 */
extern "C" int __cdecl RuntimeDispatchValidatedOutputLegacyWithLocale(
  const int stream,
  const int localeInfo,
  const int arguments
)
{
  return RuntimeDispatchValidatedOutputCall(
    reinterpret_cast<RuntimeValidatedOutputFn>(_output_l),
    stream,
    localeInfo,
    arguments
  );
}

/**
 * Address: 0x00A97991 (FUN_00A97991)
 *
 * What it does:
 * Dispatches one validated narrow output callback lane using the default
 * locale (`0`) through `RuntimeDispatchValidatedOutputCall`.
 */
extern "C" int __cdecl RuntimeDispatchValidatedOutputNoLocale(
  const int stream,
  const int arguments
)
{
  return RuntimeDispatchValidatedOutputCall(
    reinterpret_cast<RuntimeValidatedOutputFn>(_output_l),
    stream,
    0,
    arguments
  );
}

/**
 * Address: 0x00A979A9 (FUN_00A979A9)
 *
 * What it does:
 * Dispatches one validated narrow output callback lane with an explicit
 * locale pointer lane through `RuntimeDispatchValidatedOutputCall`.
 */
extern "C" int __cdecl RuntimeDispatchValidatedOutputWithLocale(
  const int stream,
  const int localeInfo,
  const int arguments
)
{
  return RuntimeDispatchValidatedOutputCall(
    reinterpret_cast<RuntimeValidatedOutputFn>(_output_l),
    stream,
    localeInfo,
    arguments
  );
}

/**
 * Address: 0x00A8C762 (FUN_00A8C762, __init_dummy)
 *
 * What it does:
 * Retained CRT set-locale helper hook; returns success (`0`) in this build.
 */
extern "C" int __cdecl RuntimeSetLocaleCategoryInitHook()
{
  return 0;
}

/**
 * Address: 0x00A979C3 (FUN_00A979C3, CPtoLCID)
 *
 * What it does:
 * Maps select East-Asian codepages to their LCID defaults for MBCS setup.
 */
extern "C" int __cdecl RuntimeCodePageToLcid(const int codePage)
{
  switch (codePage) {
    case 932:
      return 1041;
    case 936:
      return 2052;
    case 949:
      return 1042;
    case 950:
      return 1028;
    default:
      return 0;
  }
}

/**
 * Address: 0x00A9809E (FUN_00A9809E, ___initmbctable)
 *
 * What it does:
 * Lazily initializes CRT multibyte classification tables by forcing the
 * default ANSI codepage lane once and marking the init guard.
 */
extern "C" int __cdecl __initmbctable()
{
  if (__mbctype_initialized == 0) {
    _setmbcp(-3);
    __mbctype_initialized = 1;
  }
  return 0;
}

/**
 * Address: 0x00A84313 (FUN_00A84313, __time64_t_from_ft)
 * Address: 0x00A8462D (FUN_00A8462D, __time64_t_from_ft)
 *
 * What it does:
 * Converts one non-zero `FILETIME` to local broken-down time and then to
 * `__time64_t`; returns `-1` when conversion fails. The compiler emitted this
 * body twice (not folded by ICF because each copy calls a different
 * not-yet-merged `__loctotime64_t` instantiation -- 0x00A84313 calls
 * FUN_00A9AD55, 0x00A8462D calls FUN_00A9AFBE, both already recovered as
 * `__loctotime64_t` above).
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
 * Address: 0x00A855B2 (FUN_00A855B2, _time64)
 *
 * IDA signature:
 * __time64_t __usercall time64@<edx:eax>(__time64_t *Time);
 *
 * What it does:
 * Current UTC time in seconds since the Unix epoch. Reads the system clock as
 * a FILETIME (100ns ticks since 1601-01-01), shifts it onto the 1970 epoch and
 * converts to seconds. Writes the result through `outTime` when supplied and
 * also returns it.
 *
 * Unlike `__time64_t_from_ft` above this stays in UTC - no local-time
 * conversion is involved.
 */
extern "C" __time64_t __cdecl RuntimeCurrentTime64(__time64_t* const outTime)
{
  // 116444736000000000 = 100ns ticks between 1601-01-01 and 1970-01-01.
  constexpr std::int64_t kFileTimeToUnixEpochTicks = 0x19DB1DED53E8000LL;
  constexpr std::int64_t kTicksPerSecond = 10000000LL;

  FILETIME systemTimeAsFileTime{};
  ::GetSystemTimeAsFileTime(&systemTimeAsFileTime);

  const std::int64_t ticks =
    (static_cast<std::int64_t>(systemTimeAsFileTime.dwHighDateTime) << 32)
    | static_cast<std::int64_t>(systemTimeAsFileTime.dwLowDateTime);

  const __time64_t seconds =
    static_cast<__time64_t>((ticks - kFileTimeToUnixEpochTicks) / kTicksPerSecond);

  if (outTime != nullptr) {
    *outTime = seconds;
  }
  return seconds;
}

namespace
{
  /**
   * CRT `_days[]` cumulative-days-before-month table (0xF3EFB4).
   * Indexed by month in 1..12: `kMonthCumulativeDays[m - 1]` is the count of
   * days before month `m` in a non-leap year, and the span
   * `kMonthCumulativeDays[m] - kMonthCumulativeDays[m - 1]` gives that month's
   * length (used to validate the day-of-month argument).
   */
  constexpr int kMonthCumulativeDays[13] = {
    -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364
  };

  /**
   * Seconds from 1970-01-01 back to the CRT day-count origin used below
   * (0x7C558180). The running total accumulates local wall-clock seconds
   * relative to that origin; subtracting this constant rebases the result to
   * the Unix epoch.
   */
  constexpr int kCrtEpochBiasSeconds = 2085978496;
}

/**
 * Address: 0x00A9AFBE (FUN_00A9AFBE, __loctotime64_t)
 * Mangled: __loctotime64_t
 *
 * IDA signature:
 * int __cdecl sub_A9AFBE(int year, int month, int day, unsigned int hour,
 *                        unsigned int minute, unsigned int second, int dstflag);
 *
 * What it does:
 * CRT worker behind `mktime`/`_mkgmtime`: validates a broken-down local time
 * (year 1970..2038, month 1..12, day/hour/min/sec ranges, leap-day rules),
 * converts it to seconds since the CRT epoch, then applies the timezone and
 * (per `dstflag`) daylight-saving bias. Returns `-1` with `errno = EINVAL`
 * on an out-of-range field.
 */
extern "C" __time64_t __cdecl __loctotime64_t(
  int year,
  int month,
  int day,
  int hour,
  int minute,
  int second,
  int dstflag)
{
  const int yearsSince1900 = year - 1900;

  int daylight = 0;
  long dstBias = 0;
  long timezoneSeconds = 0;

  // Range validation. The final clause rejects an out-of-range day-of-month,
  // with a leap-year exception that admits Feb 29 only in an actual leap year.
  const bool outOfRange =
    yearsSince1900 < 70
    || yearsSince1900 > 138
    || static_cast<unsigned int>(month - 1) > 0xBu
    || static_cast<unsigned int>(hour) > 0x17u
    || static_cast<unsigned int>(minute) > 0x3Bu
    || static_cast<unsigned int>(second) > 0x3Bu
    || day < 1
    || ((kMonthCumulativeDays[month] - kMonthCumulativeDays[month - 1] < day)
        && ((yearsSince1900 % 4 || !(yearsSince1900 % 100)) && year % 400
            || month != 2
            || day > 29));

  if (outOfRange)
  {
    *_errno() = EINVAL;
    return static_cast<__time64_t>(-1);
  }

  // Day-of-year (1-based), plus the extra leap day once the date passes February.
  int dayOfYear = day + kMonthCumulativeDays[month - 1];
  const bool isLeapYear =
    (!(yearsSince1900 % 4) && (yearsSince1900 % 100))
    || !((yearsSince1900 + 1900) % 400);
  if (isLeapYear && month > 2)
  {
    ++dayOfYear;
  }

  _tzset();
  if (_get_daylight(&daylight))
  {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
  }
  if (_get_dstbias(&dstBias))
  {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
  }
  if (_get_timezone(&timezoneSeconds))
  {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
  }

  // Total days since the epoch origin, folded through the leap-day corrections
  // for the 4/100/400-year cycles, then scaled to seconds.
  const int totalDays =
    (yearsSince1900 + 299) / 400
    - (yearsSince1900 - 1) / 100
    + dayOfYear
    + (yearsSince1900 - 1) / 4
    + 365 * yearsSince1900;

  int result =
    timezoneSeconds
    + 60 * (minute + 60 * (hour + 24 * totalDays))
    + second
    + kCrtEpochBiasSeconds;

  if (dstflag == 1)
  {
    result += dstBias;
  }
  else if (dstflag == -1 && daylight)
  {
    std::tm brokenDown{};
    brokenDown.tm_sec = second;
    brokenDown.tm_min = minute;
    brokenDown.tm_hour = hour;
    brokenDown.tm_mon = month - 1;
    brokenDown.tm_year = yearsSince1900;
    brokenDown.tm_yday = dayOfYear;
    if (_isindst(&brokenDown))
    {
      result += dstBias;
    }
  }

  return result;
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
    return static_cast<int>(::atol(localeCodePage));
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
 * Address: 0x00A48EC0 (FUN_00A48EC0)
 *
 * What it does:
 * Opens `filePath` with `mode` via `RuntimeFopenS` (fopen_0) and returns
 * the resulting `FILE*` only when it reports success (return value `0`),
 * masking the result to `nullptr` on any failure -- the classic
 * `neg/sbb/not/and` all-ones-or-all-zeros boolean mask idiom compiled down
 * to a plain conditional here.
 *
 * No recovered caller identified yet in this pass; kept as a free function
 * since the owning call site is not yet located.
 */
[[maybe_unused]] std::FILE* OpenFileOrNull(char* const filePath, char* const mode)
{
  std::FILE* file = nullptr;
  const int status = RuntimeFopenS(&file, filePath, mode);
  return (status == 0) ? file : nullptr;
}

/**
 * Address: 0x00AB8486 (FUN_00AB8486, _putwch)
 *
 * What it does:
 * Acquires `_CONIO_LOCK`, emits one wide character through the no-lock
 * console write lane, then unlocks and returns that character result.
 */
extern "C" wint_t __cdecl _putwch(wchar_t wideCharacter)
{
  constexpr int kConioLock = 3; // _CONIO_LOCK
  _lock(kConioLock);
  const wchar_t result = putwch_nolock(wideCharacter);
  _unlock(kConioLock);
  return result;
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

[[nodiscard]] int RuntimeReadBufferedByteNoLockLegacy(std::FILE* const stream)
{
  int& counter = legacy_file(stream)._cnt;
  if (--counter < 0) {
    return _filbuf(stream);
  }

  unsigned char* const cursor = reinterpret_cast<unsigned char*>(legacy_file(stream)._ptr);
  const int value = static_cast<int>(*cursor);
  legacy_file(stream)._ptr = reinterpret_cast<char*>(cursor + 1);
  return value;
}

/**
 * Address: 0x00A9DB15 (FUN_00A9DB15)
 *
 * What it does:
 * Reads one buffered byte from a legacy CRT stream using `_cnt/_ptr` fast-path
 * semantics and falls back to `_filbuf` when the local buffer is exhausted.
 */
extern "C" int __fastcall RuntimeReadBufferedByteNoLockLaneA(
  const int /*unused*/,
  std::FILE* const stream
)
{
  return RuntimeReadBufferedByteNoLockLegacy(stream);
}

/**
 * Address: 0x00A9E816 (FUN_00A9E816)
 *
 * What it does:
 * Duplicate no-lock buffered-byte read lane used by a sibling CRT parser path;
 * preserves `_cnt/_ptr` fast-path with `_filbuf` fallback semantics.
 */
extern "C" int __fastcall RuntimeReadBufferedByteNoLockLaneB(
  const int /*unused*/,
  std::FILE* const stream
)
{
  return RuntimeReadBufferedByteNoLockLegacy(stream);
}

using RuntimeOutputFn = int(__cdecl*)(std::FILE* stream, const char* format, _locale_t localeInfo, va_list arguments);
using RuntimeWideOutputFn = int(__cdecl*)(std::FILE* stream, const wchar_t* format, _locale_t localeInfo, va_list arguments);

/**
 * Address: 0x00A96E17 (FUN_00A96E17, write_char_0)
 *
 * IDA signature:
 * void __usercall sub_A96E17(std::FILE *f@<ecx>, char ch@<al>, int *pnumwritten@<esi>);
 *
 * What it does:
 * The register-convention entry point for the same buffered-char-write logic
 * implemented below (`RuntimeWriteBufferedCharImpl`) -- field-for-field
 * identical: tests `_flag & 0x40` / `_base != nullptr`, decrements `_cnt`,
 * either writes through `_ptr` or falls back to `_flsbuf`, then updates
 * `*pnumwritten`. Called from `_output_l`'s (external) hot loop with the
 * stream/count-pointer already resident in ecx/esi.
 */
static void RuntimeWriteBufferedCharImpl(std::FILE* const f, int ch, int* const pnumwritten)
{
  if ((legacy_file(f)._flag & 0x40) == 0 || legacy_file(f)._base != nullptr) {
    int& counter = legacy_file(f)._cnt;
    if (--counter < 0) {
      ch = _flsbuf(ch, f);
    } else {
      *legacy_file(f)._ptr = static_cast<char>(ch);
      ++legacy_file(f)._ptr;
      ch = static_cast<unsigned char>(ch);
    }

    if (ch == -1) {
      *pnumwritten = -1;
    } else {
      ++*pnumwritten;
    }
  } else {
    ++*pnumwritten;
  }
}

/**
 * Address: 0x00A9F589 (FUN_00A9F589, write_char)
 *
 * What it does:
 * Writes one buffered character into a legacy CRT stream and updates the
 * written-count lane with buffered-output fallback semantics.
 */
static void RuntimeWriteBufferedCharLegacy(std::FILE* const f, int ch, int* const pnumwritten)
{
  RuntimeWriteBufferedCharImpl(f, ch, pnumwritten);
}

/**
 * Address: 0x00A9F5BC (FUN_00A9F5BC, write_multi_char)
 *
 * What it does:
 * Writes one character `num` times into the target stream using the legacy
 * buffered write-char lane until either the count is exhausted or write
 * failure marks `*pnumwritten == -1`.
 */
static void write_multi_char(
  int* const pnumwritten,
  const char ch,
  int num,
  std::FILE* const f
)
{
  while (num > 0) {
    --num;
    RuntimeWriteBufferedCharLegacy(f, static_cast<unsigned char>(ch), pnumwritten);
    if (*pnumwritten == -1) {
      break;
    }
  }
}

/**
 * Address: 0x00A9F5E0 (FUN_00A9F5E0, write_string)
 * Address: 0x00A96E6E (FUN_00A96E6E, unfolded twin)
 *
 * What it does:
 * Writes one bounded narrow string lane into a legacy CRT stream, preserving
 * buffered-output semantics and `_errno()`-driven fallback behavior. The
 * 0x00A96E6E instantiation is byte-for-byte the same shape (fast-path direct
 * counter bump when `_flag&0x40` is set and `_base==nullptr`, else a
 * per-character `write_char_0` loop substituting `'?'` once
 * `errno=='*'`(0x2A) is observed) reached from `_output_l`'s formatter core
 * (FUN_00A96EE3 -- its `external_dependency` DB tag is a stale mis-tag from
 * the same contamination sweep this cluster is being drained from; it is
 * ~2.4KB of real `_output_l` code, not an import).
 */
static void write_string(int* const pnumwritten, char* string, std::FILE* const f, int len)
{
  int* const written = pnumwritten;

  if ((legacy_file(f)._flag & 0x40) == 0 || legacy_file(f)._base != nullptr) {
    while (len > 0) {
      const int ch = static_cast<unsigned char>(*string);
      --len;
      RuntimeWriteBufferedCharImpl(f, ch, written);
      ++string;

      if (*written == -1) {
        int* const errnoValue = _errno();
        if (*errnoValue != '*') {
          return;
        }

        RuntimeWriteBufferedCharImpl(f, '?', written);
      }
    }
  } else {
    *written += len;
  }
}

/**
 * Address: 0x00A97877 (FUN_00A97877)
 *
 * What it does:
 * Runs the `_vsprintf` stack-`FILE` formatter core: validates format/buffer,
 * dispatches to `_output_l`, then commits the trailing null through direct
 * store or `_flsbuf` when the sink counter underflows.
 */
int RuntimeVsprintfOutputCore(
  char* const buffer,
  const char* const format,
  _locale_t const localeInfo,
  va_list arguments
)
{
  if (format == nullptr || buffer == nullptr) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  std::FILE outputFile{};
  legacy_file(outputFile)._base = buffer;
  legacy_file(outputFile)._ptr = buffer;
  legacy_file(outputFile)._cnt = 0x7FFFFFFF;
  legacy_file(outputFile)._flag = 0x42;

  const int formatResult = _output_l(&outputFile, format, localeInfo, arguments);
  if (--legacy_file(outputFile)._cnt < 0) {
    (void)_flsbuf(0, &outputFile);
  } else {
    *legacy_file(outputFile)._ptr = '\0';
  }

  return formatResult;
}

/**
 * Address: 0x00A978F3 (FUN_00A978F3, _vsprintf)
 *
 * What it does:
 * Forwards variadic narrow formatting to the recovered stack-`FILE` helper
 * lane with the default thread locale.
 */
extern "C" int __cdecl _vsprintf(char* const buffer, const char* const format, va_list arguments)
{
  return RuntimeVsprintfOutputCore(buffer, format, nullptr, arguments);
}

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
  legacy_file(outputFile)._cnt = 0x7FFFFFFF;
  if (count <= 0x7FFFFFFFu) {
    legacy_file(outputFile)._cnt = static_cast<int>(count);
  }
  legacy_file(outputFile)._flag = 0x42;
  legacy_file(outputFile)._base = string;
  legacy_file(outputFile)._ptr = string;

  const int formatResult = outfn(&outputFile, format, localeInfo, arguments);
  if (string == nullptr) {
    return formatResult;
  }

  if (formatResult >= 0) {
    --legacy_file(outputFile)._cnt;
    if (legacy_file(outputFile)._cnt >= 0) {
      *legacy_file(outputFile)._ptr = '\0';
      return formatResult;
    }
    if (_flsbuf(0, &outputFile) != -1) {
      return formatResult;
    }
  }

  const bool remainingIsNonNegative = legacy_file(outputFile)._cnt >= 0;
  string[count - 1u] = '\0';
  return remainingIsNonNegative ? -1 : -2;
}

/**
 * Address: 0x00A95646 (FUN_00A95646, _vsnprintf_l)
 *
 * What it does:
 * Dispatches narrow locale-aware vararg formatting through
 * `_vsnprintf_helper` with the legacy `_output_l` callback and normalizes all
 * negative helper results to `-1`.
 */
extern "C" int __cdecl _vsnprintf_l(
  char* const string,
  const std::size_t count,
  const char* const format,
  _locale_t const localeInfo,
  va_list arguments
)
{
  const int result = _vsnprintf_helper(_output_l, string, count, format, localeInfo, arguments);
  return (result < 0) ? -1 : result;
}

namespace
{
}

/**
 * Address: 0x00A954E1 (FUN_00A954E1)
 *
 * What it does:
 * Forwards narrow secure vararg formatting to `_vsprintf_s_l` with a null
 * locale lane.
 */
extern "C" int __cdecl RuntimeVsprintfSecureNoLocale(
  char* const buffer,
  const std::size_t sizeInBytes,
  const char* const format,
  va_list arguments
)
{
  return ::_vsprintf_s_l(buffer, sizeInBytes, format, nullptr, arguments);
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

    // C-style cast: convertedEntry is char*, but __crtsetenv takes a
    // pointer-to-const-pointer. Two-step cast: first reinterpret the
    // address as const-aware, then cast to the unsigned variant.
    if (__crtsetenv((const unsigned char**)&convertedEntry, 0) < 0) {
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
 * Address: 0x00AB8033 (FUN_00AB8033, _findenv)
 *
 * What it does:
 * Searches the narrow CRT environment table for a matching `NAME=` prefix
 * using bounded case-insensitive multibyte comparison, returning either the
 * matching index or the negative insertion slot.
 */
extern "C" int __cdecl _findenv(const std::size_t nameLength, const unsigned char* const name)
{
  char** const environment = _environ;
  char** cursor = environment;

  for (;; ++cursor) {
    if (*cursor == nullptr) {
      return -static_cast<int>(cursor - environment);
    }

    if (::_mbsnbicoll_l(name, reinterpret_cast<const unsigned char*>(*cursor), nameLength, nullptr) == 0) {
      const unsigned char suffix = static_cast<unsigned char>((*cursor)[nameLength]);
      if (suffix == static_cast<unsigned char>('=') || suffix == 0u) {
        break;
      }
    }
  }

  return static_cast<int>(cursor - environment);
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
  legacy_file(outputFile)._cnt = 0x7FFFFFFF;
  legacy_file(outputFile)._flag = 0x42;
  legacy_file(outputFile)._base = nullptr;
  legacy_file(outputFile)._ptr = nullptr;
  return woutfn(&outputFile, format, plocinfo, ap);
}

/**
 * Address: 0x00AAE47B (FUN_00AAE47B, vwprintf)
 *
 * What it does:
 * Dispatches wide varargs print through `vwprintf_helper` using the default
 * locale lane.
 */
int __cdecl Runtime_vwprintf(const wchar_t* const format, va_list arguments)
{
  return vwprintf_helper(woutput_l, format, nullptr, arguments);
}

/**
 * Address: 0x00A90485 (FUN_00A90485, _wprintf_l)
 *
 * What it does:
 * Variadic wide-print wrapper that forwards one format+arg-pack lane to
 * `vwprintf`.
 */
extern "C" int __cdecl _wprintf_l(const wchar_t* const format, _locale_t const localeInfo, ...)
{
  (void)localeInfo;
  va_list arguments;
  va_start(arguments, localeInfo);
  const int result = Runtime_vwprintf(format, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00AAB19C (FUN_00AAB19C, is_wctype)
 *
 * What it does:
 * Thunk wrapper over `iswctype` for one wide character and classification
 * mask lane.
 */
extern "C" int __cdecl is_wctype(const wint_t character, const wctype_t characterClass)
{
  return ::iswctype(character, characterClass);
}

/**
 * Address: 0x00A8FB50 (FUN_00A8FB50)
 *
 * What it does:
 * Lowercases one wide character under the current CRT locale lane.
 *
 * Forward declaration here keeps the helper visible to other
 * anonymous-namespace bodies in this file; the real file-scope
 * definition lives after the anonymous namespace closes (see
 * `RuntimeToLowerWideWithCurrentLocale` near `_mbschr` further
 * down) so the global mangled name is exported and the file-scope
 * caller `WxRuntimeTypes.cpp:49627` links against the real body
 * (previously fell back to the no-op stub in
 * `EngineUnrecoveredStubs.cpp`).
 */
int RuntimeToLowerWideWithCurrentLocale(wchar_t character);

/**
 * Address: 0x00AAE493 (FUN_00AAE493, _vwprintf_p_l)
 *
 * What it does:
 * Dispatches wide varargs print through `vwprintf_helper` with the caller's
 * explicit locale lane.
 */
int __cdecl Runtime_vwprintf_p_l(const wchar_t* const format, _locale_t const localeInfo, va_list arguments)
{
  return vwprintf_helper(woutput_l, format, localeInfo, arguments);
}

/**
 * Address: 0x00A904A7 (FUN_00A904A7, _wprintf_p_l)
 *
 * What it does:
 * Variadic wide `%`-format wrapper that forwards one format+locale+arg-pack
 * lane to the recovered `_vwprintf_p_l` helper.
 */
extern "C" int __cdecl _wprintf_p_l(const wchar_t* const format, _locale_t const localeInfo, ...)
{
  va_list arguments;
  va_start(arguments, localeInfo);
  const int result = Runtime_vwprintf_p_l(format, localeInfo, arguments);
  va_end(arguments);
  return result;
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
 * Address: 0x00A95A8A (FUN_00A95A8A, __fls_setvalue)
 *
 * What it does:
 * Decodes the CRT cached `FlsSetValue` lane and forwards one FLS slot/value
 * update through that function pointer.
 */
extern "C" int __stdcall _fls_setvalue(const unsigned long flsIndex, void* const value)
{
  using RuntimeFlsSetValueFn = int(__stdcall*)(unsigned long flsIndexValue, void* slotValue);
  auto* const flsSetValue = reinterpret_cast<RuntimeFlsSetValueFn>(_decode_pointer(gpFlsSetValue));
  return flsSetValue(flsIndex, value);
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
 * Address: 0x00A979F2 (FUN_00A979F2, setSBCS)
 *
 * What it does:
 * Resets one thread multibyte-info lane to SBCS defaults and copies canonical
 * `mbctype`/`mbcasemap` tables from CRT `__initialmbcinfo`.
 */
extern "C" void __cdecl setSBCS(RuntimeThreadMbcInfoCaseView* const threadMbcInfo)
{
  std::memset(threadMbcInfo->mbctype, 0, sizeof(threadMbcInfo->mbctype));
  threadMbcInfo->mbcodepage = 0;
  threadMbcInfo->ismbcodepage = 0;
  threadMbcInfo->mblcid = 0;
  std::memset(threadMbcInfo->mbulinfo, 0, sizeof(threadMbcInfo->mbulinfo));

  const auto* const initialInfo = reinterpret_cast<const RuntimeThreadMbcInfoCaseView*>(&__initialmbcinfo);
  std::memcpy(threadMbcInfo->mbctype, initialInfo->mbctype, sizeof(threadMbcInfo->mbctype));
  std::memcpy(threadMbcInfo->mbcasemap, initialInfo->mbcasemap, sizeof(threadMbcInfo->mbcasemap));
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
 * Address: 0x00957BF0 (FUN_00957BF0, _recalloc)
 *
 * What it does:
 * Multiplies `count * size` and forwards the resize request to `realloc`.
 */
extern "C" void* __cdecl _recalloc(void* const memblock, const std::size_t count, const std::size_t size)
{
  return std::realloc(memblock, count * size);
}

namespace
{
  constexpr int kRuntimeAllocatorSmallBlockSizes[44] = {
    4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64,
    80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
    2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168,
    8192, 10240, 12288, 14336, 16384
  };
}

namespace
{
  CRITICAL_SECTION gAllocatorSentinel{};
  volatile LONG gAllocatorSentinelInitState = 0;

}

/**
 * Address: 0x00A95F48 (FUN_00A95F48)
 *
 * What it does:
 * Sleeps for `waitMillis`, then returns the next retry delay (`+1000`) or `-1`
 * when the value would exceed `_maxwait`.
 */
[[maybe_unused]] int RuntimeSleepAndAdvanceAllocationRetryDelay(const DWORD waitMillis) noexcept
{
  ::Sleep(waitMillis);
  const DWORD nextWait = waitMillis + 1000u;
  if (nextWait > _maxwait) {
    return -1;
  }
  return static_cast<int>(nextWait);
}

/**
 * Address: 0x00A95F69 (FUN_00A95F69, func_SetAllocationSleepMax)
 *
 * What it does:
 * Replaces the CRT retry-sleep upper bound (`_maxwait`) and returns the
 * previous value.
 */
extern "C" unsigned long __cdecl func_SetAllocationSleepMax(const unsigned long millis)
{
  const unsigned long previousMaxWait = _maxwait;
  _maxwait = millis;
  return previousMaxWait;
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

    nextSeconds = static_cast<DWORD>(RuntimeSleepAndAdvanceAllocationRetryDelay(seconds));
    seconds = nextSeconds;
  } while (nextSeconds != static_cast<DWORD>(-1));

  return result;
}

namespace
{
  [[nodiscard]] void* RuntimeRetryMallocWithMaxwait(const std::size_t size)
  {
    DWORD seconds = 0;
    void* result = nullptr;
    DWORD nextSeconds = 0;

    do {
      result = std::malloc(size);
      if (result != nullptr || _maxwait == 0u) {
        break;
      }

      nextSeconds = static_cast<DWORD>(RuntimeSleepAndAdvanceAllocationRetryDelay(seconds));
      seconds = nextSeconds;
    } while (nextSeconds != static_cast<DWORD>(-1));

    return result;
  }

  [[nodiscard]] void* RuntimeRetryReallocWithMaxwait(void* const ptr, const std::size_t size)
  {
    DWORD seconds = 0;
    void* result = nullptr;
    DWORD nextSeconds = 0;

    do {
      result = std::realloc(ptr, size);
      if (result != nullptr || size == 0u || _maxwait == 0u) {
        break;
      }

      nextSeconds = static_cast<DWORD>(RuntimeSleepAndAdvanceAllocationRetryDelay(seconds));
      seconds = nextSeconds;
    } while (nextSeconds != static_cast<DWORD>(-1));

    return result;
  }
}

/**
 * Address: 0x00A9609C (FUN_00A9609C)
 *
 * What it does:
 * Forwards one allocation request through the CRT max-wait retry lane.
 */
extern "C" void* __cdecl RuntimeMallocRetryLane(const std::size_t size)
{
  return RuntimeRetryMallocWithMaxwait(size);
}

/**
 * Address: 0x00A960A4 (FUN_00A960A4)
 *
 * What it does:
 * Forwards one zeroed-allocation request through `_calloc_crt`.
 */
extern "C" void* __cdecl RuntimeCallocRetryLane(const std::size_t count, const std::size_t size)
{
  return _calloc_crt(count, size);
}

/**
 * Address: 0x00A960AE (FUN_00A960AE)
 *
 * What it does:
 * Forwards one reallocation request through the CRT max-wait retry lane.
 */
extern "C" void* __cdecl RuntimeReallocRetryLane(void* const ptr, const std::size_t size)
{
  return RuntimeRetryReallocWithMaxwait(ptr, size);
}

/**
 * Address: 0x00A839D2 (FUN_00A839D2, __cexit)
 *
 * What it does:
 * Runs CRT process-exit handlers in return-to-caller mode without terminating
 * the process.
 */
extern "C" void __cdecl _cexit()
{
  doexit(0u, 0, 1);
}

/**
 * Address: 0x00A95A52 (FUN_00A95A52, __get_flsindex)
 *
 * What it does:
 * Returns the process-global FLS slot index used by CRT thread-local storage
 * dispatch lanes.
 */
extern "C" unsigned long __cdecl __get_flsindex()
{
  return __flsindex;
}

namespace
{
  using RuntimeSignalHandler = void(__cdecl*)(int);
  using RuntimeMathErrorHandler = int(__cdecl*)(int*);

  constexpr int kRuntimeEnvironmentLock = 7;
  constexpr int kRuntimeSetLocaleLock = 12;
  constexpr int kRuntimeIobScanLock = 1;
  constexpr int kRuntimeSignalLock = 0;
  constexpr int kRuntimeTimeLock = 6;
  constexpr int kRuntimeHeapLock = 4;
  constexpr int kRuntimeTypeInfoLock = 14;
  constexpr int kRuntimeFileFlagFlushMask = 0x83;
  constexpr int kRuntimeFileFlagWritable = 0x02;
  constexpr std::uint64_t kFiletimeHundredNsPerMillisecond = 10000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerSecond = 10000000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerMinute = 600000000ull;
  constexpr std::uint64_t kFiletimeToUnixEpochOffset = 116444736000000000ull;
  constexpr std::size_t kRuntimeCodePageLocaleHashBucketCount = 0x3Eu;
  constexpr int kRuntimeOnExitFailureCode = 0x18;
  using RuntimeInitCritSecAndSpinCountFn = int(__cdecl*)(LPCRITICAL_SECTION, DWORD);

  std::uint64_t gRuntimeClockStartFiletime = 0;
  std::int64_t gRuntimeElapsedMinutesCache = 0;
  std::int32_t gRuntimeDstFlagCache = 0;
  std::int32_t gRuntimeTzsetFirstTime = 0;
  std::int32_t gRuntimeGetEnvironmentStringsEncodingMode = 0;
  void* gRuntimeCtrlCActionEncoded = nullptr;
  void* gRuntimeCtrlBreakActionEncoded = nullptr;
  void* gRuntimeAbortActionEncoded = nullptr;
  void* gRuntimeTermActionEncoded = nullptr;
  void* gRuntimeMathErrorActionEncoded = nullptr;
  std::int32_t gRuntimeMathErrorActionEnabled = 0;
  void* gRuntimeTerminateActionEncoded = nullptr;
  RuntimeInvalidArgHandler gRuntimeInvalidArgHandler = nullptr;
  void* gRuntimePurecallHandlerEncoded = nullptr;
  RuntimePurecallHandler gRuntimePurecallHandler = nullptr;
  static_assert(sizeof(RuntimeHeapFailureHandler) == sizeof(void*), "RuntimeHeapFailureHandler pointer size must match void*");
  void* gRuntimeHeapFailureHandlerEncoded = nullptr;
  std::int32_t gRuntimeRandomSImportAddress = 0;
  RuntimeInitCritSecAndSpinCountFn gRuntimeInitCritSecAndSpinCount = nullptr;
  void* gRuntimeCfltCvtTable[10]{};
  struct RuntimeTypeInfoFrameListNode
  {
    void* frameState = nullptr;                  // +0x00
    RuntimeTypeInfoFrameListNode* next = nullptr; // +0x04
  };
  static_assert(sizeof(RuntimeTypeInfoFrameListNode) == 0x8, "RuntimeTypeInfoFrameListNode size must be 0x8");
  static_assert(
    offsetof(RuntimeTypeInfoFrameListNode, frameState) == 0x0,
    "RuntimeTypeInfoFrameListNode::frameState offset must be 0x0"
  );
  static_assert(
    offsetof(RuntimeTypeInfoFrameListNode, next) == 0x4,
    "RuntimeTypeInfoFrameListNode::next offset must be 0x4"
  );
  RuntimeTypeInfoFrameListNode gRuntimeTypeInfoFrameRoot{};
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

  /**
   * Address: 0x00AC0725 (FUN_00AC0725, _Mtxinit)
   *
   * What it does:
   * Initializes one CRT mutex critical-section lane.
   */
  void RuntimeMtxInit(CRITICAL_SECTION* const lock) noexcept
  {
    ::InitializeCriticalSection(lock);
  }

  /**
   * Address: 0x00AC0730 (_Mtxdst)
   *
   * What it does:
   * Tears down one CRT mutex critical-section lane.
   */
  void RuntimeMtxDestroy(CRITICAL_SECTION* const lock) noexcept
  {
    ::DeleteCriticalSection(lock);
  }

  /**
   * Address: 0x00FB8A50 (xlock::mtx) / 0x00F3F848 (xlock::init)
   *
   * The iostreams lock table and its one-time guard. The guard starts at -1
   * (read from the image at 0x00F3F848) so the first InterlockedIncrement
   * returns 0 and exactly one caller performs the initialization. The table
   * spans 0x00FB8A50..0x00FB8AB0 = 0x60 bytes at 0x18 per CRITICAL_SECTION,
   * i.e. four locks, and lives in zero-initialised BSS.
   */
  constexpr std::size_t kIostreamsLockCount = 4;
  CRITICAL_SECTION gIostreamsLocks[kIostreamsLockCount]{};
  volatile LONG gIostreamsLockInit = -1;

  /**
   * Address: 0x00ABF81C (FUN_00ABF81C, _Init_locks::_Init_locks)
   *
   * IDA signature:
   * void __thiscall _Init_locks::_Init_locks(void *this);
   *
   * What it does:
   * Initializes the iostreams lock table exactly once. The interlocked
   * increment is the arbiter: only the caller that observes 0 (the guard was
   * -1) runs the loop, so concurrent constructions are safe and later ones are
   * no-ops.
   */
  void RuntimeInitIostreamsLocks() noexcept
  {
    if (::InterlockedIncrement(&gIostreamsLockInit) != 0) {
      return;
    }

    for (CRITICAL_SECTION& lock : gIostreamsLocks) {
      RuntimeMtxInit(&lock);
    }
  }

  /**
   * Address: 0x00F3F894 (atcount_cdecl) / 0x00FB8BD0 (atfuns_cdecl)
   *
   * The iostreams-side atexit table. `atcount_cdecl` holds 10 in the image, so
   * there are ten slots and the table fills downward from index 9 - handlers
   * therefore run in registration order when walked from the bottom up.
   * `atfuns_cdecl` is zero-initialised BSS.
   */
  constexpr std::size_t kAtexitSlotCount = 10;
  using RuntimeAtexitFn = void(__cdecl*)();
  RuntimeAtexitFn gAtexitFuncs[kAtexitSlotCount]{};
  int gAtexitRemaining = static_cast<int>(kAtexitSlotCount);

  /**
   * Address: 0x00AC06A9 (FUN_00AC06A9, _Atexit)
   *
   * IDA signature:
   * void __cdecl _Atexit(void (__cdecl *a1)());
   *
   * What it does:
   * Records one shutdown handler in the fixed ten-slot table, filling from the
   * top down. There is no growth path: exhausting the table calls `abort`
   * rather than failing softly, which is why the count is checked before the
   * decrement.
   */
  void RuntimeAtexit(const RuntimeAtexitFn handler)
  {
    if (gAtexitRemaining == 0) {
      std::abort();
    }

    --gAtexitRemaining;
    gAtexitFuncs[static_cast<std::size_t>(gAtexitRemaining)] = handler;
  }


  /**
   * Address: 0x00AC073B (FUN_00AC073B, _Mtxlock)
   *
   * What it does:
   * Enters one CRT mutex critical-section lane and returns zero on completion.
   */
  int RuntimeMtxLock(CRITICAL_SECTION* const lock) noexcept
  {
    ::EnterCriticalSection(lock);
    return 0;
  }

  /**
   * Address: 0x00AC0746 (FUN_00AC0746, _Mtxunlock)
   *
   * What it does:
   * Leaves one CRT mutex critical-section lane and returns zero.
   */
  int RuntimeMtxUnlock(CRITICAL_SECTION* const lock) noexcept
  {
    ::LeaveCriticalSection(lock);
    return 0;
  }

  /**
   * Address: 0x00ABF8DB (std::_Lockit::_Lockit(int))
   *          0x00ABF8FC (std::_Lockit::~_Lockit())
   *
   * What it does:
   * RAII guard over one of the four iostreams locks. The selector is masked
   * with 3 rather than bounds-checked, which independently confirms the table
   * size derived from the xlock::mtx address range, and means an out-of-range
   * request silently aliases onto an existing lock instead of faulting.
   */
  class RuntimeLockitGuard
  {
  public:
    explicit RuntimeLockitGuard(const int selector) noexcept
      : mSlot(selector & 3)
    {
      (void)RuntimeMtxLock(&gIostreamsLocks[static_cast<std::size_t>(mSlot)]);
    }

    ~RuntimeLockitGuard()
    {
      (void)RuntimeMtxUnlock(&gIostreamsLocks[static_cast<std::size_t>(mSlot)]);
    }

    RuntimeLockitGuard(const RuntimeLockitGuard&) = delete;
    RuntimeLockitGuard& operator=(const RuntimeLockitGuard&) = delete;

  private:
    int mSlot;
  };

  /**
   * `std::locale::facet` header. The vftable sits at +0x00 and the reference
   * count at +0x04 (0x00479C50 reads [edi+4]); slot 0 of the vftable is the
   * scalar deleting destructor.
   */
  struct RuntimeLocaleFacetView
  {
    void** vftable;
    std::size_t refs;
  };
  static_assert(offsetof(RuntimeLocaleFacetView, refs) == 0x04, "facet::_Refs offset must be 0x04");

  /**
   * Address: 0x00479C40 (std::locale::facet::_Decref)
   *
   * What it does:
   * Drops one reference under the locale lock and returns the facet only when
   * the count reached zero, i.e. only when the caller now owns it.
   *
   * A count of 0xFFFFFFFF is the never-delete sentinel used by statically
   * allocated facets: 0x00479C57 skips the decrement for it, so such a facet
   * never reports itself as collectable.
   */
  RuntimeLocaleFacetView* RuntimeFacetDecref(RuntimeLocaleFacetView* const facet) noexcept
  {
    const RuntimeLockitGuard guard(0);

    const std::size_t refs = facet->refs;
    if (refs != 0u && refs != static_cast<std::size_t>(-1)) {
      facet->refs = refs - 1u;
    }
    return (facet->refs == 0u) ? facet : nullptr;
  }

  /**
   * Address: 0x00ABF314 (FUN_00ABF314)
   *
   * What it does:
   * Releases the facet a list node points at, invoking its scalar deleting
   * destructor (vftable slot 0, flag 1) only if the reference drop made this
   * the last owner.
   */
  void RuntimeReleaseFacetNode(RuntimeFacetNode* const node) noexcept
  {
    RuntimeLocaleFacetView* const owned =
      RuntimeFacetDecref(reinterpret_cast<RuntimeLocaleFacetView*>(node->facet));
    if (owned == nullptr) {
      return;
    }

    using RuntimeFacetDeletingDtorFn = void*(__thiscall*)(RuntimeLocaleFacetView*, int);
    auto* const deletingDtor = reinterpret_cast<RuntimeFacetDeletingDtorFn>(owned->vftable[0]);
    (void)deletingDtor(owned, 1);
  }

  /**
   * Address: 0x00ABF440 (FUN_00ABF440, _Fac_tidy)
   *
   * What it does:
   * Shutdown hook: drains the registered-facet list under the locale lock,
   * releasing each facet and freeing its node.
   */
  void RuntimeFacetTidy()
  {
    const RuntimeLockitGuard guard(0);

    while (gRuntimeFacetHead != nullptr) {
      RuntimeFacetNode* const node = gRuntimeFacetHead;
      gRuntimeFacetHead = node->next;
      RuntimeReleaseFacetNode(node);
      ::operator delete(static_cast<void*>(node));
    }
  }

  /**
   * Address: 0x00ABF483 (FUN_00ABF483, std::locale::facet::_Register)
   *
   * What it does:
   * Adds one facet to the list that `RuntimeFacetTidy` drains at shutdown,
   * arming that hook on first registration.
   *
   * Note the allocation-failure path: the binary stores the null straight into
   * the head (0x00ABF4B4/0x00ABF4B6), discarding every previously registered
   * node rather than leaving the list intact. Reproduced as-is.
   */
  void RuntimeRegisterFacet(std::locale::facet* const facet)
  {
    if (gRuntimeFacetHead == nullptr) {
      RuntimeAtexit(&RuntimeFacetTidy);
    }

    auto* const node = static_cast<RuntimeFacetNode*>(::operator new(sizeof(RuntimeFacetNode), std::nothrow));
    if (node != nullptr) {
      node->next = gRuntimeFacetHead;
      node->facet = facet;
    }
    gRuntimeFacetHead = node;
  }

  /**
   * Address: 0x00A99EAA (FUN_00A99EAA)
   *
   * What it does:
   * Classifies one IEEE-754 double represented as low/high 32-bit words into
   * positive infinity (`1`), negative infinity (`2`), canonical NaN (`3`),
   * or payload NaN (`4`), and returns `0` for finite values.
   */
  [[maybe_unused]] int RuntimeClassifyDoubleWords(const std::uint32_t lowDword, const std::uint32_t highDword)
  {
    if (highDword == 0x7FF00000u) {
      if (lowDword == 0u) {
        return 1;
      }
    } else if (highDword == 0xFFF00000u && lowDword == 0u) {
      return 2;
    }

    const std::uint16_t hiWord = static_cast<std::uint16_t>(highDword >> 16);
    if ((hiWord & 0x7FF8u) == 0x7FF8u) {
      return 3;
    }

    if ((hiWord & 0x7FF8u) == 0x7FF0u && (((highDword & 0x7FFFFu) != 0u) || lowDword != 0u)) {
      return 4;
    }

    return 0;
  }

  [[nodiscard]] CRITICAL_SECTION* RuntimeStdLockSlot(const int slot) noexcept
  {
    return &gRuntimeStdLockSlots[slot & 3];
  }

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

  struct RuntimeLocaleIdEntryView
  {
    std::uint16_t codePage = 0; // +0x00
    std::uint16_t wLanguage = 0; // +0x02
    std::uint16_t wCountry = 0; // +0x04
  };
  static_assert(sizeof(RuntimeLocaleIdEntryView) == 0x06, "RuntimeLocaleIdEntryView size must be 0x06");

  struct RuntimeThreadLocInfoTimeInitView
  {
    std::uint8_t reserved00[0x40]{};
    RuntimeLocaleIdEntryView timeCategory; // +0x40
  };
  static_assert(
    offsetof(RuntimeThreadLocInfoTimeInitView, timeCategory) == 0x40,
    "RuntimeThreadLocInfoTimeInitView::timeCategory offset must be 0x40"
  );

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
    std::int32_t lcCodepage = 0;             // +0x04
    std::uint8_t reserved08[0x04]{};         // +0x08
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
  static_assert(offsetof(RuntimeThreadLocInfoView, lcCodepage) == 0x04, "RuntimeThreadLocInfoView::lcCodepage offset must be 0x04");
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
  static_assert(sizeof(RuntimeThreadLocInfoView) == 0xD8, "RuntimeThreadLocInfoView size must be 0xD8");

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

  /**
   * Address: 0x00A88511 (FUN_00A88511, _mbstowcs_l)
   *
   * IDA signature:
   * int __cdecl sub_A88511(LPWSTR lpWideCharStr, unsigned __int8 *lpMultiByteStr,
   *                        unsigned int cchWideChar, _locale_tstruct *a4);
   *
   * What it does:
   * Locale-aware CRT `_mbstowcs_l` core. Converts the multibyte `source`
   * string into wide characters in `destination`, honouring the effective
   * thread/explicit locale resolved through the `_LocaleUpdate` lane:
   *   * When the locale has no active codepage handle (SBCS-only): performs a
   *     byte-widening copy (or, for a null destination, returns `strlen`).
   *   * Otherwise routes through
   *     `MultiByteToWideChar(MB_PRECOMPOSED | MB_ERR_INVALID_CHARS)`,
   *     and on `ERROR_NO_UNICODE_TRANSLATION` retries the largest whole-
   *     multibyte prefix that fits `maxCount`, walking DBCS lead bytes via
   *     `_isleadbyte_l`.
   * Preserves CRT `EINVAL`/`EILSEQ` errno lanes, invalid-parameter dispatch,
   * and always releases any thread-local locale reference acquired.
   */
  std::size_t RuntimeMbstowcsLocaleCore(
    wchar_t* const destination,
    const char* const source,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    if (destination != nullptr) {
      if (maxCount == 0u) {
        return 0u;
      }
      destination[0] = L'\0';
    }

    if (source == nullptr || maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<std::size_t>(-1);
    }

    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    RuntimeThreadLocInfoView* const localeView =
      RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    const bool hasCodepageHandle = localeView->lcHandle[2] != 0;

    // Null destination: caller only wants the converted length.
    if (destination == nullptr) {
      if (!hasCodepageHandle) {
        const std::size_t asciiLength = std::strlen(source);
        RuntimeReleaseLocaleUpdate(threadData, updated);
        return asciiLength;
      }

      const int wideCount = ::MultiByteToWideChar(
        static_cast<UINT>(localeView->lcCodepage),
        MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
        source,
        -1,
        nullptr,
        0
      );
      if (wideCount == 0) {
        *_errno() = EILSEQ;
        RuntimeReleaseLocaleUpdate(threadData, updated);
        return static_cast<std::size_t>(-1);
      }

      const std::size_t result = static_cast<std::size_t>(wideCount) - 1u;
      RuntimeReleaseLocaleUpdate(threadData, updated);
      return result;
    }

    // Real destination with an active codepage handle: route through the OS.
    if (hasCodepageHandle) {
      const int wideCount = ::MultiByteToWideChar(
        static_cast<UINT>(localeView->lcCodepage),
        MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
        source,
        -1,
        destination,
        static_cast<int>(maxCount)
      );
      if (wideCount != 0) {
        const std::size_t result = static_cast<std::size_t>(wideCount) - 1u;
        RuntimeReleaseLocaleUpdate(threadData, updated);
        return result;
      }

      if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        // Buffer too small: find the largest whole-multibyte prefix that fits.
        const auto* scanCursor = reinterpret_cast<const unsigned char*>(source);
        std::size_t remaining = maxCount;
        bool sawInvalidLead = false;
        while (remaining != 0u) {
          --remaining;
          if (*scanCursor == 0u) {
            break;
          }
          if (_isleadbyte_l(*scanCursor, localeInfo) != 0) {
            if (*++scanCursor == 0u) {
              sawInvalidLead = true;
              break;
            }
          }
          ++scanCursor;
        }

        if (!sawInvalidLead) {
          const int prefixBytes = static_cast<int>(
            reinterpret_cast<const char*>(scanCursor) - source
          );
          const int partialWideCount = ::MultiByteToWideChar(
            static_cast<UINT>(localeView->lcCodepage),
            MB_PRECOMPOSED,
            source,
            prefixBytes,
            destination,
            static_cast<int>(maxCount)
          );
          if (partialWideCount != 0) {
            const std::size_t result = static_cast<std::size_t>(partialWideCount);
            RuntimeReleaseLocaleUpdate(threadData, updated);
            return result;
          }
        }
      }

      *_errno() = EILSEQ;
      destination[0] = L'\0';
      RuntimeReleaseLocaleUpdate(threadData, updated);
      return static_cast<std::size_t>(-1);
    }

    // Real destination, SBCS-only locale: byte-widening copy up to maxCount.
    if (maxCount != 0u) {
      wchar_t* out = destination;
      std::size_t index = 0u;
      while (true) {
        const std::size_t current = index;
        *out = static_cast<wchar_t>(static_cast<unsigned char>(source[index]));
        if (source[current] == '\0') {
          RuntimeReleaseLocaleUpdate(threadData, updated);
          return current;
        }
        ++out;
        index = current + 1u;
        if (index >= maxCount) {
          break;
        }
      }
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return maxCount;
  }

  /**
   * Address: 0x00A88511 (FUN_00A88511, _mbstowcs_l)
   *
   * See the anonymous namespace implementation `RuntimeMbstowcsLocaleCore` for
   * the full behavior description. This `extern "C"` entry point is the stable
   * CRT-facing symbol that `mbstowcs` (0x00A8869E) and `_mbstowcs_s_l`
   * (0x00A886C6) dispatch into by name.
   */
  extern "C" std::size_t __cdecl _mbstowcs_l(
    wchar_t* const destination,
    const char* const source,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    return RuntimeMbstowcsLocaleCore(destination, source, maxCount, localeInfo);
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

  [[nodiscard]] constexpr unsigned char RuntimeAsciiToLower(const unsigned char value) noexcept
  {
    if (value >= 'A' && value <= 'Z') {
      return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
  }

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

namespace
{
  using RuntimeLockedOutputFn = int(__cdecl*)(
    std::FILE* stream,
    const char* format,
    _locale_t localeInfo,
    va_list arguments
  );
}

/**
 * Address: 0x00A882CC (FUN_00A882CC, RuntimeDispatchLockedFormattedOutput)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A882CC@<eax>(FILE *(__cdecl *a1)(FILE *, const char *, int, va_list), FILE *f, const char *a3, int a4, va_list args);
 *
 * What it does:
 * Shared narrow-output dispatcher behind the `vfprintf`-family entry
 * points (0x00A88474, 0x00A8841A, 0x00A88438, 0x00A88456, 0x00A88490):
 * validates `stream`/`format`, locks the stream, rejects a unicode-textmode
 * stream the same way `fprintf` (0x00A85BC2) does, acquires the write
 * scratch buffer via `_stbuf`, invokes the caller-supplied formatter
 * callback (`_output_l`/`_output_s_l`/`outfn`/`woutput_l`), flushes scratch
 * via `_ftbuf`, then unlocks. Returns the callback's byte count, or `-1`
 * with `errno = EINVAL` on a validation failure.
 */
extern "C" int __cdecl RuntimeDispatchLockedFormattedOutput(
  const RuntimeLockedOutputFn outputCallback,
  std::FILE* const stream,
  const char* const format,
  const _locale_t localeInfo,
  va_list arguments)
{
  if (stream == nullptr || format == nullptr) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  _lock_file(stream);

  int result = 0;
  if ((RuntimeGetFileFlags(stream) & 0x40) == 0) {
    const RuntimeIoInfo* const ioInfo = ResolveIoInfoFromStream(stream);
    if ((ioInfo->textmodeUnicode & 0x7F) != 0 || ioInfo->textmodeUnicode < 0) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      result = -1;
    }
  }

  if (result == 0) {
    const int scratchAllocated = _stbuf(stream);
    result = outputCallback(stream, format, localeInfo, arguments);
    _ftbuf(scratchAllocated, stream);
  }

  _unlock_file(stream);
  return result;
}

/**
 * Address: 0x00A88474 (FUN_00A88474, vfprintf)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A88474@<eax>(FILE *a1, const char *a2, va_list a3);
 *
 * What it does:
 * CRT narrow-character formatted output to a stream from an existing
 * `va_list`. Thin forward into `RuntimeDispatchLockedFormattedOutput` with
 * the `_output_l` callback and the default (null) locale.
 */
extern "C" int __cdecl vfprintf(std::FILE* const stream, const char* const format, va_list arguments)
{
  return RuntimeDispatchLockedFormattedOutput(_output_l, stream, format, nullptr, arguments);
}

/**
 * Address: 0x00A8841A (FUN_00A8841A, _vfprintf_l)
 *
 * IDA signature:
 * FILE *callcnv_F4 sub_A8841A@<eax>(FILE *a1, const char *a2, _locale_t a3, va_list a4);
 *
 * What it does:
 * Locale-explicit CRT narrow-character formatted output to a stream from an
 * existing `va_list`. Thin forward into `RuntimeDispatchLockedFormattedOutput`
 * with the `_output_l` callback and the caller-supplied locale (matches
 * `vfprintf`'s shape exactly, differing only in passing `locale` through
 * instead of a hardcoded `nullptr`).
 */
extern "C" int __cdecl _vfprintf_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, va_list arguments
)
{
  return RuntimeDispatchLockedFormattedOutput(_output_l, stream, format, locale, arguments);
}

/**
 * Address: 0x00A85D11 (FUN_00A85D11, _fprintf_l)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A85D11@<eax>(FILE *a1, const char *a2, _locale_t a3, ...);
 *
 * What it does:
 * Locale-explicit CRT narrow-character formatted output to a stream.
 * Builds a `va_list` over its trailing arguments and forwards to
 * `_vfprintf_l`, exactly mirroring how `fprintf`/`vfprintf` pair up.
 */
extern "C" int __cdecl _fprintf_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, ...
)
{
  va_list arguments;
  va_start(arguments, locale);
  const int result = _vfprintf_l(stream, format, locale, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A88438 (FUN_00A88438, _vfprintf_s_l)
 *
 * IDA signature:
 * FILE *callcnv_F4 sub_A88438@<eax>(FILE *a1, const char *a2, _locale_t a3, va_list a4);
 *
 * What it does:
 * Locale-explicit, secure (`_s`) CRT narrow-character formatted output to a
 * stream from an existing `va_list`. Same shape as `_vfprintf_l`, but routed
 * through the `_output_s_l` callback (the format-string-validating secure
 * variant) instead of `_output_l`.
 */
extern "C" int __cdecl _vfprintf_s_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, va_list arguments
)
{
  return RuntimeDispatchLockedFormattedOutput(_output_s_l, stream, format, locale, arguments);
}

/**
 * Address: 0x00A85D2B (FUN_00A85D2B, _fprintf_s_l)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A85D2B@<eax>(FILE *a1, const char *a2, _locale_t a3, ...);
 *
 * What it does:
 * Locale-explicit, secure CRT narrow-character formatted output to a
 * stream. Builds a `va_list` over its trailing arguments and forwards to
 * `_vfprintf_s_l`, mirroring `_fprintf_l`/`_vfprintf_l`.
 */
extern "C" int __cdecl _fprintf_s_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, ...
)
{
  va_list arguments;
  va_start(arguments, locale);
  const int result = _vfprintf_s_l(stream, format, locale, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A85D45 (FUN_00A85D45, _fprintf_s)
 *
 * IDA signature:
 * FILE *callcnv_F2 sub_A85D45@<eax>(FILE *a1, const char *a2, ...);
 *
 * What it does:
 * Secure CRT narrow-character formatted output to a stream, current-locale
 * only (no locale parameter exposed to the caller). Builds a `va_list` over
 * its trailing arguments and forwards to `_vfprintf_s_l` with a null locale,
 * mirroring `fprintf`/`vfprintf`'s null-locale forwarding.
 */
extern "C" int __cdecl _fprintf_s(std::FILE* const stream, const char* const format, ...)
{
  va_list arguments;
  va_start(arguments, format);
  const int result = _vfprintf_s_l(stream, format, nullptr, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A88456 (FUN_00A88456, _vfprintf_p_l)
 *
 * IDA signature:
 * FILE *callcnv_F4 sub_A88456@<eax>(FILE *a1, const char *a2, _locale_t a3, va_list a4);
 *
 * What it does:
 * Locale-explicit, positional-argument (`%N$`) CRT narrow-character
 * formatted output to a stream from an existing `va_list`. Same shape as
 * `_vfprintf_l`/`_vfprintf_s_l`, routed through the distinct `outfn`
 * callback the shared dispatcher's own citation already names for the
 * positional-argument formatter.
 */
extern "C" int __cdecl _vfprintf_p_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, va_list arguments
)
{
  return RuntimeDispatchLockedFormattedOutput(outfn, stream, format, locale, arguments);
}

/**
 * Address: 0x00A85D5D (FUN_00A85D5D, _fprintf_p_l)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A85D5D@<eax>(FILE *a1, const char *a2, _locale_t a3, ...);
 *
 * What it does:
 * Locale-explicit, positional-argument CRT narrow-character formatted
 * output to a stream. Builds a `va_list` over its trailing arguments and
 * forwards to `_vfprintf_p_l`, mirroring `_fprintf_l`/`_fprintf_s_l`.
 */
extern "C" int __cdecl _fprintf_p_l(
  std::FILE* const stream, const char* const format, const _locale_t locale, ...
)
{
  va_list arguments;
  va_start(arguments, locale);
  const int result = _vfprintf_p_l(stream, format, locale, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A85D77 (FUN_00A85D77, _fprintf_p)
 *
 * IDA signature:
 * FILE *callcnv_F2 sub_A85D77@<eax>(FILE *a1, const char *a2, ...);
 *
 * What it does:
 * Positional-argument CRT narrow-character formatted output to a stream,
 * current-locale only. Builds a `va_list` over its trailing arguments and
 * forwards to `_vfprintf_p_l` with a null locale, mirroring `_fprintf_s`.
 */
extern "C" int __cdecl _fprintf_p(std::FILE* const stream, const char* const format, ...)
{
  va_list arguments;
  va_start(arguments, format);
  const int result = _vfprintf_p_l(stream, format, nullptr, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A88490 (FUN_00A88490, _vfprintf_s)
 *
 * IDA signature:
 * FILE *callcnv_F3 sub_A88490@<eax>(FILE *a1, const char *a2, va_list a3);
 *
 * What it does:
 * Secure CRT narrow-character formatted output to a stream from an
 * existing `va_list`, current-locale only (no locale parameter at all).
 * Thin forward into `RuntimeDispatchLockedFormattedOutput` with the
 * `_output_s_l` callback and a null locale, mirroring `vfprintf`'s
 * null-locale shape but through the secure callback.
 */
extern "C" int __cdecl _vfprintf_s(std::FILE* const stream, const char* const format, va_list arguments)
{
  return RuntimeDispatchLockedFormattedOutput(_output_s_l, stream, format, nullptr, arguments);
}

/**
 * Address: 0x00A48EF0 (FUN_00A48EF0, fprintf_s)
 *
 * IDA signature:
 * int callcnv_F2 sub_A48EF0@<eax>(FILE *a1, const char *a2, ...);
 *
 * What it does:
 * C11-standard-named secure CRT narrow-character formatted output to a
 * stream (the non-underscore-prefixed `fprintf_s`, a separate real entry
 * point from the legacy `_fprintf_s` recovered above). Rejects a null
 * stream or format by returning -1 directly, without routing through
 * `_invalid_parameter` the way the rest of this family does; otherwise
 * builds a `va_list` over its trailing arguments and forwards to
 * `_vfprintf_s`.
 */
extern "C" int __cdecl fprintf_s(std::FILE* const stream, const char* const format, ...)
{
  if (stream == nullptr || format == nullptr) {
    return -1;
  }

  va_list arguments;
  va_start(arguments, format);
  const int result = _vfprintf_s(stream, format, arguments);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00A85BC2 (FUN_00A85BC2, fprintf)
 *
 * IDA signature:
 * int callcnv_D3 fprintf@<eax>(FILE *a2, char *a3);
 *
 * What it does:
 * CRT narrow-character formatted output to a stream. Locks the stream,
 * validates the ioinfo is not in unicode-textmode (narrow output requires
 * a non-unicode text lane), acquires its write scratch buffer via
 * `_stbuf`, runs `_output_l(stream, format, nullptr-locale, va_args)`,
 * flushes scratch via `_ftbuf`, and unlocks.
 *
 * Returns the `_output_l` byte count on success, `-1` on argument/stream
 * lane validation failure. Error path sets `errno = EINVAL` and calls
 * `_invalid_parameter` before returning.
 */
extern "C" int __cdecl fprintf(std::FILE* const stream, const char* const format, ...)
{
  if (stream == nullptr || format == nullptr) {
    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
  }

  va_list arguments;
  va_start(arguments, format);

  _lock_file(stream);

  int result = 0;
  if ((RuntimeGetFileFlags(stream) & 0x40) == 0) {
    const RuntimeIoInfo* const ioInfo = ResolveIoInfoFromStream(stream);
    if ((ioInfo->textmodeUnicode & 0x7F) != 0 || ioInfo->textmodeUnicode < 0) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      result = -1;
    }
  }

  if (result == 0) {
    const int scratchAllocated = _stbuf(stream);
    result = _output_l(stream, format, nullptr, arguments);
    _ftbuf(scratchAllocated, stream);
  }

  _unlock_file(stream);
  va_end(arguments);
  return result;
}

/**
 * Address: 0x00AB8F20 (FUN_00AB8F20, _mbschr)
 *
 * What it does:
 * Forwards the default-locale multibyte character search lane into the
 * locale-aware helper.
 */
extern "C" unsigned char* __cdecl _mbschr(const unsigned char* const text, const unsigned int searchChar)
{
  return ::_mbschr_l(text, searchChar, nullptr);
}

/**
 * Address: 0x00A8FB50 (FUN_00A8FB50, RuntimeToLowerWideWithCurrentLocale)
 *
 * What it does:
 * Lowercases one wide character under the current CRT locale lane.
 * File-scope definition (anonymous-namespace lookalike inside this
 * TU is a forward declaration only); exported so the call site at
 * `WxRuntimeTypes.cpp:49627` resolves to this body and not to the
 * no-op stub in `EngineUnrecoveredStubs.cpp`.
 *
 * Caller chain:
 *   - `WxRuntimeTypes.cpp:49627` (typed wxString lowercase loop) calls
 *     this helper for each character in a wide-string argument.
 */
int RuntimeToLowerWideWithCurrentLocale(const wchar_t character)
{
  return static_cast<int>(_towlower_l(static_cast<wint_t>(character), nullptr));
}

namespace
{
  std::once_flag gThreadMonInitOnce;
  CRITICAL_SECTION gThreadMonMutex{};
  DWORD gThreadMonTlsKey = TLS_OUT_OF_INDEXES;
  std::int32_t gAttachedThreadCount = 0;

  struct RuntimeNonLocalGotoContext
  {
    std::uint32_t reserved00;
    std::uint32_t eaxValue;
    std::uint32_t notifyCode;
    std::uint32_t ebpValue;
  };
  static_assert(sizeof(RuntimeNonLocalGotoContext) == 0x10, "RuntimeNonLocalGotoContext size must be 0x10");
  static_assert(
    offsetof(RuntimeNonLocalGotoContext, eaxValue) == 0x04,
    "RuntimeNonLocalGotoContext::eaxValue offset must be 0x04"
  );
  static_assert(
    offsetof(RuntimeNonLocalGotoContext, notifyCode) == 0x08,
    "RuntimeNonLocalGotoContext::notifyCode offset must be 0x08"
  );
  static_assert(
    offsetof(RuntimeNonLocalGotoContext, ebpValue) == 0x0C,
    "RuntimeNonLocalGotoContext::ebpValue offset must be 0x0C"
  );

  RuntimeNonLocalGotoContext gRuntimeNonLocalGotoContext{};

  /**
   * Address: 0x00AA3B2C (FUN_00AA3B2C)
   *
   * IDA signature:
   * void __usercall sub_AA3B2C(int eaxValue@<eax>, int notifyCode@<ecx>, int ebpValue@<ebp>);
   *
   * What it does:
   * Register-argument entry into the non-local-goto context publication lane:
   * assumes the notify code is already loaded in the caller's ecx (unlike the
   * sibling stack-argument entry at 0x00AA3B35), then falls into the shared
   * tail that stores eax/ecx/ebp into the fixed `dword_F3F110` scratch block
   * and returns eax unchanged. Both real call sites in `_CallSettingFrame`
   * (0x00AA39A0) dispatch through this entry.
   */
  [[nodiscard]] std::uint32_t RuntimePublishNonLocalGotoState(
    const std::uint32_t eaxValue,
    const std::uint32_t ebpValue,
    const std::uint32_t notifyCode
  ) noexcept
  {
    gRuntimeNonLocalGotoContext.notifyCode = notifyCode;
    gRuntimeNonLocalGotoContext.eaxValue = eaxValue;
    gRuntimeNonLocalGotoContext.ebpValue = ebpValue;
    return eaxValue;
  }

  using ThreadExitHandler = void(__cdecl*)();

  /**
   * The thread-monitor's handler list.
   *
   * Address: 0x00AC5A70 (FUN_00AC5A70, std::list<thread_exit_handler>::list)
   * Address: 0x00AC5AD0 (FUN_00AC5AD0, std::list<thread_exit_handler>::_Buynode)
   * Address: 0x00AC5B70 (FUN_00AC5B70, std::list<thread_exit_handler>::~list)
   *
   * What it does:
   * Instantiating this one alias is what makes MSVC emit the three
   * out-of-line `std::list<thread_exit_handler>` bodies that IDA surfaces as
   * standalone functions. They are compiler emissions of this alias, not
   * three hand-written functions, so the instantiating call sites below are
   * the recovery of all three:
   *
   *   - 0x00AC5A70 is the default ctor: `operator new(0xC)` for the sentinel
   *     node, then self-links `_Next`/`_Prev`. Emitted by the
   *     `new (std::nothrow) ThreadExitHandlerList()` in `at_thread_exit`.
   *   - 0x00AC5AD0 is the node splice behind `push_front`: `operator new(0xC)`
   *     then stores `_Next`, `_Prev` and `_Myval`. Emitted by the
   *     `handlers->push_front(exitHandler)` in `at_thread_exit`.
   *   - 0x00AC5B70 is the dtor: unlinks the sentinel, walks `_Next` freeing
   *     each node, zeroes `_Mysize`, then frees the sentinel. Emitted by the
   *     `delete handlers` lanes in `on_thread_exit` and `at_thread_exit`.
   *
   * The 0xC node width (`_Next`, `_Prev`, `_Myval`) identifies the
   * specialisation: one pointer-sized payload, which is the
   * `void(__cdecl*)()` handler.
   */
  using ThreadExitHandlerList = std::list<ThreadExitHandler>;

}

/**
 * Address: 0x00AC5700 (FUN_00AC5700, init_threadmon_mutex)
 *
 * What it does:
 * Initializes the process-wide thread monitor critical section.
 */
extern "C" void init_threadmon_mutex()
{
  ::InitializeCriticalSection(&gThreadMonMutex);
}

/**
 * Address: 0x00AC5710 (FUN_00AC5710, on_process_enter)
 *
 * What it does:
 * One-time initializes the thread monitor mutex, then enters and immediately
 * leaves it to validate synchronization lane readiness.
 */
extern "C" void on_process_enter()
{
  std::call_once(gThreadMonInitOnce, []() { init_threadmon_mutex(); });
  ::EnterCriticalSection(&gThreadMonMutex);
  ::LeaveCriticalSection(&gThreadMonMutex);
}

/**
 * Address: 0x00AC5740 (FUN_00AC5740, on_process_exit)
 *
 * What it does:
 * One-time initializes thread-monitor synchronization lanes, enters the
 * monitor mutex, releases the thread-exit TLS key when present, and leaves
 * the mutex.
 */
extern "C" void on_process_exit()
{
  std::call_once(gThreadMonInitOnce, []() { init_threadmon_mutex(); });
  ::EnterCriticalSection(&gThreadMonMutex);
  if (gThreadMonTlsKey != TLS_OUT_OF_INDEXES) {
    ::TlsFree(gThreadMonTlsKey);
    gThreadMonTlsKey = TLS_OUT_OF_INDEXES;
  }
  ::LeaveCriticalSection(&gThreadMonMutex);
}

/**
 * Address: 0x00AC5C50 (FUN_00AC5C50, on_thread_exit)
 *
 * What it does:
 * Detaches one thread-local exit-handler list from TLS under the monitor lock,
 * decrements attached thread count on successful detach, executes handlers in
 * registration stack order, and destroys the list storage.
 */
extern "C" void on_thread_exit()
{
  std::call_once(gThreadMonInitOnce, []() { init_threadmon_mutex(); });

  bool lockHeld = true;
  ::EnterCriticalSection(&gThreadMonMutex);

  if (gThreadMonTlsKey != TLS_OUT_OF_INDEXES) {
    ThreadExitHandlerList* const handlers = static_cast<ThreadExitHandlerList*>(::TlsGetValue(gThreadMonTlsKey));
    if (handlers != nullptr && ::TlsSetValue(gThreadMonTlsKey, nullptr) != FALSE) {
      --gAttachedThreadCount;
      lockHeld = false;
      ::LeaveCriticalSection(&gThreadMonMutex);

      while (!handlers->empty()) {
        const ThreadExitHandler handler = handlers->front();
        if (handler != nullptr) {
          handler();
        }
        handlers->pop_front();
      }
      delete handlers;
    }
  }

  if (lockHeld) {
    ::LeaveCriticalSection(&gThreadMonMutex);
  }
}

/**
 * Address: 0x00AC5EB0 (FUN_00AC5EB0, at_thread_exit)
 *
 * ThreadExitHandler exitHandler
 *
 * What it does:
 * Lazily allocates the TLS slot for per-thread exit handlers, creates one
 * handler list for the current thread when needed, and prepends one callback
 * to preserve LIFO execution on thread detach.
 */
extern "C" int __cdecl at_thread_exit(const ThreadExitHandler exitHandler)
{
  std::call_once(gThreadMonInitOnce, []() { init_threadmon_mutex(); });
  ::EnterCriticalSection(&gThreadMonMutex);

  DWORD tlsKey = gThreadMonTlsKey;
  if (tlsKey == TLS_OUT_OF_INDEXES) {
    tlsKey = ::TlsAlloc();
    gThreadMonTlsKey = tlsKey;
  }

  if (tlsKey != TLS_OUT_OF_INDEXES) {
    ThreadExitHandlerList* handlers = static_cast<ThreadExitHandlerList*>(::TlsGetValue(tlsKey));
    if (handlers == nullptr) {
      handlers = new (std::nothrow) ThreadExitHandlerList();
      if (handlers != nullptr) {
        if (::TlsSetValue(gThreadMonTlsKey, handlers) != FALSE) {
          ++gAttachedThreadCount;
        } else {
          delete handlers;
          handlers = nullptr;
        }
      }
    }

    if (handlers != nullptr) {
      handlers->push_front(exitHandler);
      ::LeaveCriticalSection(&gThreadMonMutex);
      return 0;
    }
  }

  ::LeaveCriticalSection(&gThreadMonMutex);
  return -1;
}

/**
 * Address: 0x00AC6030 (FUN_00AC6030, on_process_init)
 *
 * What it does:
 * Registers thread-exit cleanup and performs one process-enter synchronization
 * probe.
 */
extern "C" int on_process_init()
{
  std::atexit(&on_thread_exit);
  on_process_enter();
  return 0;
}

/**
 * Address: 0x00AC6050 (FUN_00AC6050, func_at_exit_01)
 *
 * What it does:
 * Calls process-exit thread monitor teardown helper and returns zero.
 */
extern "C" int func_at_exit_01()
{
  on_process_exit();
  return 0;
}

/**
 * Address: 0x00AC6060 (FUN_00AC6060, TlsCallback_0)
 *
 * What it does:
 * Executes thread-exit cleanup when TLS callback reason equals thread detach
 * (`DLL_THREAD_DETACH`).
 */
extern "C" void __stdcall TlsCallback_0(void* /*module*/, const DWORD reason, void* /*reserved*/)
{
  if (reason == DLL_THREAD_DETACH) {
    on_thread_exit();
  }
}

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
 * Address: 0x00AA26FA (FUN_00AA26FA, func_SetZeroX8)
 *
 * What it does:
 * Clears one aligned memory range in 128-byte chunks (8 contiguous 16-byte
 * lanes per iteration).
 */
void RuntimeClearAligned128ByteChunks(void* const alignedStart, const unsigned int byteCount)
{
  auto* writeCursor = static_cast<unsigned char*>(alignedStart);
  unsigned int chunkCount = byteCount >> 7;
  while (chunkCount != 0u) {
    std::memset(writeCursor, 0, 0x80u);
    writeCursor += 0x80u;
    --chunkCount;
  }
}

/**
 * Address: 0x00AA2751 (FUN_00AA2751, func_ClearRange)
 *
 * What it does:
 * Clears one byte range with legacy CRT alignment strategy: it aligns the
 * start to 16 bytes, clears aligned 128-byte blocks, and zeroes trailing
 * bytes.
 */
void* RuntimeClearRange(void* const start, const int /*fillValue*/, const int byteCount)
{
  auto* const startBytes = static_cast<unsigned char*>(start);
  const std::uintptr_t unalignedBytes = reinterpret_cast<std::uintptr_t>(startBytes) & 0x0Fu;
  if (unalignedBytes != 0u) {
    const int headBytes = static_cast<int>(0x10u - unalignedBytes);
    std::memset(startBytes, 0, static_cast<std::size_t>(headBytes));
    (void)RuntimeClearRange(startBytes + headBytes, 0, byteCount - headBytes);
    return start;
  }

  const int trailingBytes = (byteCount & 0x7F);
  if (byteCount != trailingBytes) {
    RuntimeClearAligned128ByteChunks(start, static_cast<unsigned int>(byteCount - trailingBytes));
  }

  if (trailingBytes != 0) {
    std::memset(startBytes + (byteCount - trailingBytes), 0, static_cast<std::size_t>(trailingBytes));
  }

  return start;
}

/**
 * Address: 0x00AA5B6C (FUN_00AA5B6C, __free_lconv_num)
 *
 * What it does:
 * Releases numeric `lconv` heap lanes (`decimal_point`, `thousands_sep`,
 * `grouping`) when they are not aliased to the C-locale defaults.
 */
extern "C" void __cdecl __free_lconv_num(lconv* const localeConv)
{
  if (localeConv == nullptr) {
    return;
  }

  if (localeConv->decimal_point != __lconv_c.decimal_point) {
    _free_crt(localeConv->decimal_point);
  }

  if (localeConv->thousands_sep != __lconv_c.thousands_sep) {
    _free_crt(localeConv->thousands_sep);
  }

  if (localeConv->grouping != __lconv_c.grouping) {
    _free_crt(localeConv->grouping);
  }
}

/**
 * Address: 0x00AB98D2 (FUN_00AB98D2, _get_fmode)
 *
 * What it does:
 * Returns the active CRT file-mode lane into caller storage and preserves
 * invalid-parameter semantics for null destinations.
 */
extern "C" int __cdecl _get_fmode(int* const outMode)
{
  if (outMode != nullptr) {
    *outMode = _fmode;
    return 0;
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return EINVAL;
}

/**
 * Address: 0x00AB5F56 (FUN_00AB5F56, __set_error_mode)
 *
 * What it does:
 * Gets/sets CRT error-mode state for values `0..2`, supports read-only query
 * mode `3`, and applies invalid-parameter semantics on unsupported values.
 */
extern "C" int __cdecl __set_error_mode(const int mode)
{
  if (mode >= 0) {
    if (mode <= 2) {
      const int previousMode = gRuntimeErrorMode;
      gRuntimeErrorMode = mode;
      return previousMode;
    }

    if (mode == 3) {
      return gRuntimeErrorMode;
    }
  }

  *_errno() = EINVAL;
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
  return -1;
}

/**
 * Address: 0x00AB5F9C (FUN_00AB5F9C, __set_app_type)
 *
 * What it does:
 * Stores one CRT app-type lane (`__app_type`) and returns the stored value.
 */
extern "C" int __cdecl __set_app_type(const int appType)
{
  __app_type = appType;
  return appType;
}

namespace
{
}

/**
 * Address: 0x00A96878 (FUN_00A96878, __FF_MSGBANNER)
 *
 * What it does:
 * Emits CRT startup message banner records when current error-mode policy
 * enables console diagnostics.
 */
extern "C" void __cdecl __FF_MSGBANNER()
{
  constexpr int kErrorModeQueryOnly = 3;
  constexpr int kErrorModeOutputToStdErr = 1;
  constexpr int kConsoleAppType = 1;
  constexpr int kRtLocaleTlossThreadMessage = 0xFC;
  constexpr int kRtBannerMessage = 0xFF;

  const int currentErrorMode = __set_error_mode(kErrorModeQueryOnly);
  if (currentErrorMode == kErrorModeOutputToStdErr || (currentErrorMode == 0 && __app_type == kConsoleAppType)) {
    __NMSG_WRITE(kRtLocaleTlossThreadMessage);
    __NMSG_WRITE(kRtBannerMessage);
  }
}

/**
 * Address: 0x00A89F67 (FUN_00A89F67, __lock_file2)
 *
 * What it does:
 * Acquires one FILE lock lane: for dynamic streams (`index >= 20`) enters the
 * per-stream critical section at `FILE+0x20`; otherwise acquires the global
 * CRT lock slot (`index + 16`) and marks `_IOLOCKED`.
 */
extern "C" void __cdecl __lock_file2(const int streamIndex, std::FILE* const stream)
{
  if (streamIndex >= 20) {
    struct RuntimeFileLockOwnerView
    {
      std::uint8_t reserved00[0x20];
      CRITICAL_SECTION lock;
    };
    static_assert(
      offsetof(RuntimeFileLockOwnerView, lock) == 0x20,
      "RuntimeFileLockOwnerView::lock offset must be 0x20"
    );

    auto* const lockOwner = reinterpret_cast<RuntimeFileLockOwnerView*>(stream);
    ::EnterCriticalSection(&lockOwner->lock);
    return;
  }

  _lock(streamIndex + 16);
  legacy_file(stream)._flag |= 0x8000;
}

/**
 * Address: 0x00A89F2B (FUN_00A89F2B, _lock_file)
 *
 * IDA signature:
 * void __cdecl _lock_file(FILE *Stream);
 *
 * What it does:
 * Same two-way lock acquisition as `__lock_file2`, but decides by pointer
 * range rather than by index: a stream outside the static `_iob` table owns
 * its critical section inline at `FILE+0x20`, while a table entry uses the
 * global CRT lock slot at `(entry index) + 16` and is marked `_IOLOCKED`.
 */
extern "C" void __cdecl _lock_file(std::FILE* const stream)
{
  std::FILE* const table = __iob_func();
  // 0x00A89F39 compares against `_iob_IOB_ENTRIES`, which is the address of
  // the LAST table entry (_iob + 19), not one past the end - the test is
  // `ja`, so index 19 is still in range.
  constexpr std::ptrdiff_t kIobLastEntry = 19;

  if (stream < table || stream > (table + kIobLastEntry)) {
    struct RuntimeFileLockOwnerView
    {
      std::uint8_t reserved00[0x20];
      CRITICAL_SECTION lock;
    };
    static_assert(
      offsetof(RuntimeFileLockOwnerView, lock) == 0x20,
      "RuntimeFileLockOwnerView::lock offset must be 0x20"
    );

    auto* const lockOwner = reinterpret_cast<RuntimeFileLockOwnerView*>(stream);
    ::EnterCriticalSection(&lockOwner->lock);
    return;
  }

  _lock(static_cast<int>(stream - table) + 16);
  legacy_file(stream)._flag |= 0x8000;
}

// Defined below alongside the other CRT lock-table lanes.
extern "C" void __cdecl RuntimeUnlockCrtLock(int lockId);

// Defined below with the other stream lanes.
extern "C" int __cdecl RuntimeFlushAllStreams(int mode);

/**
 * Address: 0x00A86537 (FUN_00A86537, fflush)
 *
 * IDA signature:
 * int __cdecl fflush(FILE *a1);
 *
 * What it does:
 * Flushes one stream under its own lock, or every stream when given null.
 *
 * The null case deliberately does NOT take a per-stream lock - the flush-all
 * lane walks the stream table under the table lock instead, which is why the
 * two paths cannot be collapsed.
 */
extern "C" int __cdecl fflush(std::FILE* const stream)
{
  if (stream == nullptr) {
    return RuntimeFlushAllStreams(0);
  }

  _lock_file(stream);
  const int result = _fflush_nolock(stream);
  _unlock_file(stream);
  return result;
}

/**
 * Address: 0x00ABF7C1 (FUN_00ABF7C1, _Getctype)
 *
 * IDA signature:
 * struct _Ctypevec *__cdecl Getctype(struct _Ctypevec *a1);
 *
 * What it does:
 * Snapshots the current locale ctype classification table. It tries to take a
 * private 512-byte copy so the caller is immune to a later setlocale, and only
 * if that allocation fails does it alias the shared table instead - which is
 * what `ownsTable` records, so teardown knows whether the buffer is his to
 * free.
 */
extern "C" RuntimeCtypeVec* __cdecl RuntimeGetCtypeVec(RuntimeCtypeVec* const out)
{
  out->handle = __lc_handle_func()[1];
  out->codePage = __lc_codepage_func();

  auto* const copy = static_cast<std::uint16_t*>(_calloc_crt(0x100u, sizeof(std::uint16_t)));
  out->table = copy;

  if (copy != nullptr) {
    std::memcpy(copy, __pctype_func(), 0x200u);
    out->ownsCopiedTable = 1;
  } else {
    out->ownsCopiedTable = 0;
    out->table = __pctype_func();
  }
  return out;
}

extern "C" int global_mode_sse2;
extern "C" double __cdecl __CIpow_pentium4(double exponent, double base);

/**
 * Address: 0x00A8E0E0 (FUN_00A8E0E0, _CIpow)
 *
 * IDA signature:
 * double callcnv_F3 _CIpow@<st0>(double x@<st0>, double y@<st1>);
 *
 * What it does:
 * Dispatches pow between the SSE2 and x87 implementations. The SSE2 path is
 * taken only when the build has it enabled AND both control words are in their
 * default state: every MXCSR exception masked (0x1F80) and the x87 control
 * word low seven bits at 0x7F. If either has been reprogrammed - which the
 * engine does around some render and sim paths - it falls back to x87 so the
 * caller keeps the rounding and exception behaviour it set up.
 */
extern "C" double __cdecl RuntimePowDispatch(const double base, const double exponent)
{
  if (global_mode_sse2 != 0) {
    const bool mxcsrIsDefault = (_mm_getcsr() & 0x1F80u) == 0x1F80u;
    if (mxcsrIsDefault) {
      std::uint16_t x87ControlWord = 0;
      __asm { fnstcw x87ControlWord }
      if ((x87ControlWord & 0x7Fu) == 0x7Fu) {
        return __CIpow_pentium4(exponent, base);
      }
    }
  }

  return std::pow(base, exponent);
}

/**
 * Address: 0x00AAA815 (FUN_00AAA815, func_GetCompatModeSub)
 *
 * What it does:
 * Probes SSE2 availability by executing an actual `movapd` under structured
 * exception handling. Returns 1 when the instruction runs cleanly; the
 * handler catches an access-violation or illegal-instruction fault (the two
 * codes a `movapd` raises on hardware/OS combinations without real SSE2
 * support) and returns 0 instead of letting the exception propagate.
 */
extern "C" int __cdecl func_GetCompatModeSub()
{
  __try {
    volatile __m128d probe = _mm_setzero_pd();
    (void)probe;
    return 1;
  } __except (
    (GetExceptionCode() == static_cast<DWORD>(EXCEPTION_ACCESS_VIOLATION) ||
     GetExceptionCode() == static_cast<DWORD>(EXCEPTION_ILLEGAL_INSTRUCTION))
      ? EXCEPTION_EXECUTE_HANDLER
      : EXCEPTION_CONTINUE_SEARCH
  ) {
    return 0;
  }
}

/**
 * Address: 0x00AAA865 (FUN_00AAA865, func_GetCompatMode)
 *
 * What it does:
 * Detects SSE2 support two independent ways and requires both to agree:
 * toggles EFLAGS.ID to confirm CPUID itself is available, reads CPUID leaf
 * 1's feature bitmask (EDX bit 26 = SSE2) when it is, and separately runs
 * `func_GetCompatModeSub`'s SEH-guarded instruction probe.
 */
extern "C" int __cdecl func_GetCompatMode()
{
  const unsigned int originalFlags = __readeflags();
  __writeeflags(originalFlags ^ 0x200000u);
  const bool cpuidAvailable = (__readeflags() != originalFlags);
  __writeeflags(originalFlags);

  unsigned int featureFlagsEdx = 0u;
  if (cpuidAvailable) {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 0);
    __cpuid(cpuInfo, 1);
    featureFlagsEdx = static_cast<unsigned int>(cpuInfo[3]);
  }

  return ((featureFlagsEdx & 0x4000000u) != 0u) && (func_GetCompatModeSub() != 0);
}

/**
 * Address: 0x00A8ECBF (FUN_00A8ECBF, register_sseCompatMode)
 *
 * What it does:
 * C-init table entry: writes `global_mode_sse2` from the SSE2 detection
 * probe. Runs during the CRT's C-style static-init pass, before any C++
 * static object constructor.
 */
extern "C" int __cdecl register_sseCompatMode()
{
  global_mode_sse2 = 0;
  global_mode_sse2 = func_GetCompatMode();
  return 0;
}

__pragma(section(".CRT$XIU", read))
extern "C" __declspec(allocate(".CRT$XIU"))
int(__cdecl* const gRegisterSseCompatModeInit)() = &register_sseCompatMode;

/**
 * Address: 0x00AAA8C5 (FUN_00AAA8C5, register_compatFlag)
 *
 * What it does:
 * C-init table entry: writes `global_compat_flag` from the SSE2 detection
 * probe. Runs during the CRT's C-style static-init pass, before any C++
 * static object constructor.
 */
extern "C" int __cdecl register_compatFlag()
{
  global_compat_flag = func_GetCompatMode();
  return 0;
}

__pragma(section(".CRT$XIU", read))
extern "C" __declspec(allocate(".CRT$XIU"))
int(__cdecl* const gRegisterCompatFlagInit)() = &register_compatFlag;

/**
 * Address: 0x00A824E7 (FUN_00A824E7, memmove_s)
 *
 * IDA signature:
 * errno_t __usercall memmove_s@<eax>(void *const Destination, const rsize_t DestinationSize,
 *                                    const void *const Source, const rsize_t SourceSize);
 *
 * What it does:
 * Bounds-checked memmove. A zero-byte request succeeds without touching or
 * even validating the pointers; otherwise a null pointer reports EINVAL and an
 * undersized destination reports ERANGE, both after setting errno and running
 * the invalid-parameter handler.
 *
 * Note it does NOT scrub the destination on failure, unlike the later UCRT
 * behaviour - the buffer is left exactly as the caller had it.
 */
extern "C" errno_t __cdecl RuntimeMemMoveChecked(
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
    errno = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0, 0);
    return EINVAL;
  }

  if (destinationSize < sourceSize) {
    errno = ERANGE;
    _invalid_parameter(nullptr, nullptr, nullptr, 0, 0);
    return ERANGE;
  }

  (void)std::memmove(destination, source, sourceSize);
  return 0;
}

/**
 * Address: 0x00A9003B (FUN_00A9003B, _wcsdup)
 *
 * IDA signature:
 * wchar_t *__cdecl wcsdup(const wchar_t *String);
 *
 * What it does:
 * Allocates a copy of one wide string, terminator included. A null input and a
 * failed allocation both return null rather than raising; only a copy that
 * reports failure into a buffer sized from the same string is treated as
 * impossible and routed to the Watson handler.
 *
 * The allocation is calloc, not malloc, so the buffer is already zeroed if the
 * copy writes short.
 */
extern "C" wchar_t* __cdecl RuntimeWideStringDuplicate(const wchar_t* const text)
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
 * Address: 0x00A89F95 (FUN_00A89F95, _unlock_file)
 *
 * IDA signature:
 * void callcnv_33 _unlock_file(FILE *Stream);
 *
 * What it does:
 * Releases what `_lock_file` took, choosing the same way: a stream outside the
 * static `_iob` table leaves its own inline critical section, a table entry
 * clears `_IOLOCKED` and releases the global slot at (index + 16).
 *
 * The order is the mirror of the acquire: the flag is cleared *before* the
 * lock is dropped (0x00A89FA9 precedes the _unlock call), so no other thread
 * can observe the stream unlocked but still flagged.
 */
extern "C" void __cdecl _unlock_file(std::FILE* const stream)
{
  std::FILE* const table = __iob_func();
  constexpr std::ptrdiff_t kIobLastEntry = 19;

  if (stream < table || stream > (table + kIobLastEntry)) {
    struct RuntimeFileLockOwnerView
    {
      std::uint8_t reserved00[0x20];
      CRITICAL_SECTION lock;
    };
    static_assert(
      offsetof(RuntimeFileLockOwnerView, lock) == 0x20,
      "RuntimeFileLockOwnerView::lock offset must be 0x20"
    );

    auto* const lockOwner = reinterpret_cast<RuntimeFileLockOwnerView*>(stream);
    ::LeaveCriticalSection(&lockOwner->lock);
    return;
  }

  legacy_file(stream)._flag &= ~0x8000;
  RuntimeUnlockCrtLock(static_cast<int>(stream - table) + 16);
}

/**
 * Address: 0x00ABFA82 (FUN_00ABFA82, _Getcvt)
 *
 * IDA signature:
 * LCID Getcvt();
 *
 * What it does:
 * Returns the LC_NUMERIC locale handle. The codepage query is issued for its
 * side effect of refreshing thread locale state; its result is discarded, and
 * the handle is read before it so the pre-refresh value is what comes back.
 */
extern "C" LCID __cdecl RuntimeGetConversionLocale()
{
  const LCID numericHandle = __lc_handle_func()[2];
  (void)__lc_codepage_func();
  return numericHandle;
}

/**
 * Address: 0x00A89FCB (FUN_00A89FCB, __unlock_file2)
 *
 * What it does:
 * Releases one FILE lock lane: for dynamic streams (`index >= 20`) leaves the
 * per-stream critical section at `FILE+0x20`; otherwise clears `_IOLOCKED`
 * and releases the global CRT lock slot (`index + 16`).
 */
extern "C" void __cdecl __unlock_file2(const int streamIndex, std::FILE* const stream)
{
  if (streamIndex >= 20) {
    struct RuntimeFileLockOwnerView
    {
      std::uint8_t reserved00[0x20];
      CRITICAL_SECTION lock;
    };
    static_assert(
      offsetof(RuntimeFileLockOwnerView, lock) == 0x20,
      "RuntimeFileLockOwnerView::lock offset must be 0x20"
    );

    auto* const lockOwner = reinterpret_cast<RuntimeFileLockOwnerView*>(stream);
    ::LeaveCriticalSection(&lockOwner->lock);
    return;
  }

  legacy_file(stream)._flag &= ~0x8000;
  _unlock(streamIndex + 16);
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
 * Address: 0x00A8C4A9 (FUN_00A8C4A9, __copytlocinfo_nolock)
 *
 * What it does:
 * Copies one thread-locale payload lane and rebinds it with a fresh refcount
 * through `__addlocaleref`.
 */
extern "C" void __cdecl __copytlocinfo_nolock(
  RuntimeThreadLocInfo* const destination,
  const RuntimeThreadLocInfo* const source
)
{
  if (source == nullptr || destination == nullptr || destination == source) {
    return;
  }

  std::memcpy(destination, source, sizeof(RuntimeThreadLocInfoView));
  destination->refcount = 0;
  __addlocaleref(destination);
}

/**
 * Address: 0x00A968B1 (FUN_00A968B1, __getlocaleinfo)
 *
 * What it does:
 * Resolves one locale field either as an allocated multibyte string lane
 * (`LC_STR_TYPE`) or as a parsed numeric byte lane (`LC_INT_TYPE`).
 */
extern "C" int __cdecl __getlocaleinfo(
  RuntimeLocaleHandle* const localeHandle,
  const int localeType,
  const LCID localeId,
  const int localeField,
  void* const output
)
{
  (void)localeHandle;

  constexpr int kLocaleIntegerType = 0;
  constexpr int kLocaleStringType = 1;
  constexpr int kStackLocaleBufferChars = 128;
  constexpr int kWideIntegerBufferChars = 4;

  if (localeType == kLocaleStringType) {
    char stackLocaleText[kStackLocaleBufferChars]{};
    char* localeText = stackLocaleText;
    bool allocatedLocaleText = false;

    int localeTextChars =
      ::GetLocaleInfoA(localeId, static_cast<LCTYPE>(localeField), stackLocaleText, kStackLocaleBufferChars);
    if (localeTextChars == 0) {
      if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return -1;
      }

      localeTextChars = ::GetLocaleInfoA(localeId, static_cast<LCTYPE>(localeField), nullptr, 0);
      if (localeTextChars == 0) {
        return -1;
      }

      localeText = static_cast<char*>(_calloc_crt(static_cast<std::size_t>(localeTextChars), 1u));
      if (localeText == nullptr) {
        return -1;
      }

      allocatedLocaleText = true;
      localeTextChars = ::GetLocaleInfoA(localeId, static_cast<LCTYPE>(localeField), localeText, localeTextChars);
      if (localeTextChars == 0) {
        _free_crt(localeText);
        return -1;
      }
    }

    char* const copiedText = static_cast<char*>(_calloc_crt(static_cast<std::size_t>(localeTextChars), 1u));
    *static_cast<char**>(output) = copiedText;
    if (copiedText == nullptr) {
      if (allocatedLocaleText) {
        _free_crt(localeText);
      }
      return -1;
    }

    if (strncpy_s(copiedText, static_cast<std::size_t>(localeTextChars), localeText, static_cast<std::size_t>(localeTextChars - 1))
        != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    if (allocatedLocaleText) {
      _free_crt(localeText);
    }
    return 0;
  }

  if (localeType != kLocaleIntegerType) {
    return -1;
  }

  static wchar_t sLocaleIntegerDigits[kWideIntegerBufferChars]{};
  if (::GetLocaleInfoW(localeId, static_cast<LCTYPE>(localeField), sLocaleIntegerDigits, kWideIntegerBufferChars) == 0) {
    return -1;
  }

  auto* const numericValue = static_cast<unsigned char*>(output);
  *numericValue = 0;
  for (const wchar_t* cursor = sLocaleIntegerDigits; cursor < (sLocaleIntegerDigits + kWideIntegerBufferChars); ++cursor) {
    const unsigned char digit = static_cast<unsigned char>(*cursor);
    if (::isdigit(digit) == 0) {
      break;
    }

    *numericValue = static_cast<unsigned char>(digit + (10u * (*numericValue)) - static_cast<unsigned char>('0'));
  }

  return 0;
}

/**
 * Address: 0x00AA551D (FUN_00AA551D, _get_lc_time)
 *
 * What it does:
 * Loads one locale-time data table from locale-info providers, including day
 * and month names, AM/PM strings, date/time formats, and calendar metadata.
 */
extern "C" int __cdecl _get_lc_time(RuntimeThreadLocInfo* const locinfo, RuntimeLcTimeData* const lcTimeData)
{
  constexpr int kLocaleIntegerField = 0;
  constexpr int kLocaleStringField = 1;

  if (lcTimeData == nullptr) {
    return -1;
  }

  const auto* const timeLocInfo = reinterpret_cast<const RuntimeThreadLocInfoTimeInitView*>(locinfo);
  const LCID localeLanguage = static_cast<LCID>(timeLocInfo->timeCategory.wLanguage);
  const LCID localeCountry = static_cast<LCID>(timeLocInfo->timeCategory.wCountry);

  RuntimeLocaleHandle localeHandle{};
  localeHandle.locinfo = locinfo;
  localeHandle.mbcinfo = nullptr;

  int status = 0;
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME1, &lcTimeData->wday_abbr[1]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME2, &lcTimeData->wday_abbr[2]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME3, &lcTimeData->wday_abbr[3]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME4, &lcTimeData->wday_abbr[4]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME5, &lcTimeData->wday_abbr[5]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME6, &lcTimeData->wday_abbr[6]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVDAYNAME7, &lcTimeData->wday_abbr[0]);

  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME1, &lcTimeData->wday[1]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME2, &lcTimeData->wday[2]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME3, &lcTimeData->wday[3]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME4, &lcTimeData->wday[4]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME5, &lcTimeData->wday[5]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME6, &lcTimeData->wday[6]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SDAYNAME7, &lcTimeData->wday[0]);

  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME1, &lcTimeData->month_abbr[0]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME2, &lcTimeData->month_abbr[1]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME3, &lcTimeData->month_abbr[2]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME4, &lcTimeData->month_abbr[3]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME5, &lcTimeData->month_abbr[4]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME6, &lcTimeData->month_abbr[5]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME7, &lcTimeData->month_abbr[6]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME8, &lcTimeData->month_abbr[7]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME9, &lcTimeData->month_abbr[8]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME10, &lcTimeData->month_abbr[9]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME11, &lcTimeData->month_abbr[10]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SABBREVMONTHNAME12, &lcTimeData->month_abbr[11]);

  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME1, &lcTimeData->month[0]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME2, &lcTimeData->month[1]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME3, &lcTimeData->month[2]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME4, &lcTimeData->month[3]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME5, &lcTimeData->month[4]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME6, &lcTimeData->month[5]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME7, &lcTimeData->month[6]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME8, &lcTimeData->month[7]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME9, &lcTimeData->month[8]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME10, &lcTimeData->month[9]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME11, &lcTimeData->month[10]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SMONTHNAME12, &lcTimeData->month[11]);

  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SAM, &lcTimeData->ampm[0]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeLanguage, LOCALE_SPM, &lcTimeData->ampm[1]);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SSHORTDATE, &lcTimeData->ww_sdatefmt);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SLONGDATE, &lcTimeData->ww_ldatefmt);
  status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_STIMEFORMAT, &lcTimeData->ww_timefmt);
  status |= __getlocaleinfo(&localeHandle, kLocaleIntegerField, localeCountry, LOCALE_ICALENDARTYPE, &lcTimeData->ww_caltype);

  lcTimeData->ww_lcid = localeCountry;
  return status;
}

/**
 * Address: 0x00AA5936 (FUN_00AA5936, __free_lc_time)
 *
 * What it does:
 * Releases all heap-owned locale-time string lanes for one `__lc_time_data`
 * payload (weekday/month names, AM/PM, and date/time format strings).
 */
extern "C" void __cdecl __free_lc_time(void* const lcTimeData)
{
  auto* const lcTime = static_cast<RuntimeLcTimeData*>(lcTimeData);
  if (lcTime == nullptr) {
    return;
  }

  for (int dayIndex = 1; dayIndex < 7; ++dayIndex) {
    _free_crt(const_cast<char*>(lcTime->wday_abbr[dayIndex]));
  }
  _free_crt(const_cast<char*>(lcTime->wday_abbr[0]));

  for (int dayIndex = 1; dayIndex < 7; ++dayIndex) {
    _free_crt(const_cast<char*>(lcTime->wday[dayIndex]));
  }
  _free_crt(const_cast<char*>(lcTime->wday[0]));

  for (int monthIndex = 0; monthIndex < 12; ++monthIndex) {
    _free_crt(const_cast<char*>(lcTime->month_abbr[monthIndex]));
  }

  for (int monthIndex = 0; monthIndex < 12; ++monthIndex) {
    _free_crt(const_cast<char*>(lcTime->month[monthIndex]));
  }

  _free_crt(const_cast<char*>(lcTime->ampm[0]));
  _free_crt(const_cast<char*>(lcTime->ampm[1]));
  _free_crt(const_cast<char*>(lcTime->ww_sdatefmt));
  _free_crt(const_cast<char*>(lcTime->ww_ldatefmt));
  _free_crt(const_cast<char*>(lcTime->ww_timefmt));
}

/**
 * Address: 0x00A8B1C5 (FUN_00A8B1C5, __Getdays_l)
 *
 * IDA signature:
 * char *__cdecl __Getdays_l(_locale_t plocinfo);
 *
 * What it does:
 * Builds one heap-allocated `:abbrev:full:abbrev:full:...` weekday-name
 * catalog (seven `wday_abbr[]`/`wday[]` pairs) for the effective locale's
 * `lc_time_curr` table, resolved through the `_LocaleUpdate` lane. Matches
 * the CRT's internal `__Getdays` contract: a `strcpy_s` failure while
 * assembling the catalog routes to Watson, exactly like the rest of this
 * file's `_l` helpers.
 */
extern "C" char* __cdecl __Getdays_l(_locale_t const localeInfo)
{
  const RuntimeLocaleUpdateScope locale(localeInfo);
  const RuntimeLcTimeData* const lcTime = locale.timeView()->lcTimeCurrent;

  std::size_t totalLength = 0u;
  for (int dayIndex = 0; dayIndex < 7; ++dayIndex) {
    totalLength += std::strlen(lcTime->wday_abbr[dayIndex]) + std::strlen(lcTime->wday[dayIndex]) + 2u;
  }

  char* const daysCatalog = static_cast<char*>(std::malloc(totalLength + 1u));
  if (daysCatalog != nullptr) {
    char* cursor = daysCatalog;
    for (int dayIndex = 0; dayIndex < 7; ++dayIndex) {
      *cursor++ = ':';
      if (::strcpy_s(cursor, totalLength + 1u - static_cast<std::size_t>(cursor - daysCatalog), lcTime->wday_abbr[dayIndex]) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      cursor += std::strlen(cursor);

      *cursor++ = ':';
      if (::strcpy_s(cursor, totalLength + 1u - static_cast<std::size_t>(cursor - daysCatalog), lcTime->wday[dayIndex]) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      cursor += std::strlen(cursor);
    }
    *cursor = '\0';
  }

  return daysCatalog;
}

/**
 * Address: 0x00A8B2C3 (IDA-unclassified 9-byte chunk between __Getdays_l's
 * end at 0x00A8B2C3 and __Getmonths_l's start at 0x00A8B2CC; real caller of
 * __Getdays_l per raw-byte disassembly: `push 0; call __Getdays_l; pop ecx;
 * retn`. No `FUN_*` token exists for this address because IDA folded it
 * into the surrounding gap rather than exporting it as its own function.)
 *
 * What it does:
 * Public `_Getdays()` entry point; forwards to `__Getdays_l` with the
 * current thread/global locale (no explicit `_locale_t` override).
 */
extern "C" char* __cdecl _Getdays()
{
  return __Getdays_l(nullptr);
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
 * Address: 0x00AA5BAC (FUN_00AA5BAC, _init_numeric)
 *
 * What it does:
 * Rebuilds numeric `lconv` lanes (`decimal_point`, `thousands_sep`,
 * `grouping`) for one thread locale, normalizes grouping bytes, and swaps
 * refcount-owned locale-conversion storage.
 */
extern "C" int __cdecl _init_numeric(RuntimeThreadLocInfo* const locinfo)
{
  constexpr int kLocaleMonetaryCategory = 3;
  constexpr int kLocaleNumericCategory = 4;
  constexpr int kLocaleIntegerField = 0;
  constexpr int kLocaleStringField = 1;

  auto* const localeInfo = reinterpret_cast<RuntimeThreadLocInfoView*>(locinfo);
  RuntimeLocaleHandle localeHandle{};
  localeHandle.locinfo = locinfo;
  localeHandle.mbcinfo = nullptr;

  int* newNumericRefcount = nullptr;
  int* newIntlRefcount = nullptr;
  lconv* newLocaleConv = nullptr;

  if (localeInfo->lcHandle[kLocaleNumericCategory] == 0 && localeInfo->lcHandle[kLocaleMonetaryCategory] == 0) {
    newLocaleConv = &__lconv_c;
  } else {
    newLocaleConv = static_cast<lconv*>(_calloc_crt(1u, 0x30u));
    if (newLocaleConv == nullptr) {
      return 1;
    }

    std::memcpy(newLocaleConv, localeInfo->localeConv, sizeof(lconv));

    newIntlRefcount = static_cast<int*>(std::malloc(sizeof(int)));
    if (newIntlRefcount == nullptr) {
      _free_crt(newLocaleConv);
      return 1;
    }
    *newIntlRefcount = 0;

    if (localeInfo->lcHandle[kLocaleNumericCategory] == 0) {
      newLocaleConv->decimal_point = __lconv_c.decimal_point;
      newLocaleConv->thousands_sep = __lconv_c.thousands_sep;
      newLocaleConv->grouping = __lconv_c.grouping;
      *newIntlRefcount = 1;
    } else {
      newNumericRefcount = static_cast<int*>(std::malloc(sizeof(int)));
      if (newNumericRefcount == nullptr) {
        _free_crt(newLocaleConv);
        _free_crt(newIntlRefcount);
        return 1;
      }
      *newNumericRefcount = 0;

      const LCID localeCountry = static_cast<LCID>((localeInfo->lcId[kLocaleNumericCategory] >> 16u) & 0xFFFFu);
      int status = 0;
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SDECIMAL, &newLocaleConv->decimal_point);
      status |=
        __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_STHOUSAND, &newLocaleConv->thousands_sep);
      status |= __getlocaleinfo(&localeHandle, kLocaleStringField, localeCountry, LOCALE_SGROUPING, &newLocaleConv->grouping);
      if (status != 0) {
        __free_lconv_num(newLocaleConv);
        _free_crt(newLocaleConv);
        _free_crt(newIntlRefcount);
        // Matches original CRT lane: numeric-refcount allocation is not freed
        // on this error path.
        return -1;
      }

      char* numericGrouping = newLocaleConv->grouping;
      while (numericGrouping != nullptr && *numericGrouping != '\0') {
        const char groupingChar = *numericGrouping;
        if (groupingChar >= '0' && groupingChar <= '9') {
          *numericGrouping = static_cast<char>(groupingChar - '0');
          ++numericGrouping;
          continue;
        }

        if (groupingChar == ';') {
          char* shiftCursor = numericGrouping;
          do {
            *shiftCursor = *(shiftCursor + 1);
            ++shiftCursor;
          } while (*shiftCursor != '\0');
          continue;
        }

        ++numericGrouping;
      }

      *newIntlRefcount = 1;
      *newNumericRefcount = 1;
    }
  }

  if (localeInfo->lconvNumRefcount != nullptr) {
    (void)InterlockedDecrement(reinterpret_cast<volatile long*>(localeInfo->lconvNumRefcount));
  }

  if (localeInfo->lconvIntlRefcount != nullptr) {
    if (InterlockedDecrement(reinterpret_cast<volatile long*>(localeInfo->lconvIntlRefcount)) == 0) {
      _free_crt(localeInfo->lconvIntlRefcount);
      _free_crt(localeInfo->localeConv);
    }
  }

  localeInfo->lconvNumRefcount = newNumericRefcount;
  localeInfo->lconvIntlRefcount = newIntlRefcount;
  localeInfo->localeConv = newLocaleConv;
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
  constexpr int kLocaleIntegerField = 0;
  constexpr int kLocaleStringField = 1;

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

/**
 * Address: 0x00A89CF6 (FUN_00A89CF6, __ftol2)
 *
 * What it does:
 * Converts one floating input to signed 64-bit integer with legacy
 * truncation-toward-zero semantics.
 */
extern "C" std::int64_t __cdecl __ftol2(const double value)
{
  std::uint64_t resultBits = static_cast<std::uint64_t>(static_cast<std::int64_t>(value));
  const std::uint32_t lowDword = static_cast<std::uint32_t>(resultBits & 0xFFFFFFFFu);
  const std::int32_t highDword = static_cast<std::int32_t>(resultBits >> 32u);

  if (lowDword != 0u || (static_cast<std::uint32_t>(highDword) & 0x7FFFFFFFu) != 0u) {
    const double integral = static_cast<double>(static_cast<std::int64_t>(resultBits));
    if (highDword >= 0) {
      const std::uint32_t fractionBits = std::bit_cast<std::uint32_t>(static_cast<float>(value - integral));
      const std::uint32_t sum = fractionBits + 0x7FFFFFFFu;
      if (sum < fractionBits) {
        --resultBits;
      }
    } else {
      const std::uint32_t fractionBits = std::bit_cast<std::uint32_t>(static_cast<float>(-(value - integral)));
      const std::uint32_t signToggled = fractionBits ^ 0x80000000u;
      const std::uint32_t sum = signToggled + 0x7FFFFFFFu;
      if (sum < signToggled) {
        ++resultBits;
      }
    }
  }

  return static_cast<std::int64_t>(resultBits);
}

/**
 * Address: 0x00A8EF99 (FUN_00A8EF99, func_wstrFindLast)
 *
 * IDA signature:
 * _WORD *__cdecl func_wstrFindLast(_WORD *a1, __int16 a2);
 *
 * What it does:
 * `wcsrchr`: walks to the terminator, then scans back for `needle` and returns
 * that position, or null when absent. Searching the terminator itself finds it,
 * because the backward scan starts there.
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

/**
 * Address: 0x00B57ED0 (FUN_00B57ED0, func_SofdecToInt)
 *
 * IDA signature:
 * __int64 __usercall func_SofdecToInt@<edx:eax>(double a1@<st0>);
 *
 * What it does:
 * Truncating double to signed 64-bit conversion, the plain form used by the
 * Sofdec lanes. Distinct from `__ftol2` above, which carries the extra
 * rounding-correction shuffle.
 */
extern "C" std::int64_t __cdecl RuntimeDoubleToInt64(const double value)
{
  return static_cast<std::int64_t>(value);
}

/**
 * Address: 0x00B57F00 (FUN_00B57F00, shl)
 *
 * IDA signature:
 * int __usercall shl@<eax>(__int64 a1@<edx:eax>, unsigned __int8 a2@<cl>);
 *
 * What it does:
 * The CRT `__allshl` helper: 64-bit left shift by a byte count. A count of 64
 * or more yields zero rather than being taken modulo the width, which is what
 * a bare x86 shift would do.
 */
extern "C" std::int64_t __cdecl RuntimeShiftLeft64(const std::int64_t value, const unsigned char count)
{
  if (count >= 64u) {
    return 0;
  }
  return static_cast<std::int64_t>(static_cast<std::uint64_t>(value) << (count & 0x3Fu));
}

/**
 * Address: 0x00A9A813 (FUN_00A9A813)
 *
 * What it does:
 * Reads the current x87 control word, applies one masked update
 * (`(current & ~mask) | (control & mask)`), writes the new control word,
 * and returns the previous control word sign-extended to `int`.
 */
extern "C" int __cdecl RuntimeSetFpuControlMasked(
  const unsigned int controlWord,
  const unsigned int mask
)
{
  unsigned short previousControlWord = 0;
  unsigned short updatedControlWord = 0;

  __asm {
    fstcw previousControlWord
  }

  updatedControlWord = static_cast<unsigned short>(
    (static_cast<unsigned int>(previousControlWord) & ~mask) | (controlWord & mask)
  );

  __asm {
    fldcw updatedControlWord
  }

  return static_cast<int>(static_cast<short>(previousControlWord));
}

/**
 * Address: 0x00A9DA09 (FUN_00A9DA09, _controlfp_s)
 *
 * What it does:
 * Validates control/mask bits, optionally writes previous control-word state,
 * and applies the requested floating-point control changes.
 */
extern "C" errno_t __cdecl _controlfp_s(
  unsigned int* const outCurrentControl,
  const unsigned int newControl,
  const unsigned int mask
)
{
  const unsigned int sanitizedMask = mask & 0xFFF7FFFFu;
  if ((newControl & sanitizedMask & 0xFCF0FCE0u) != 0u) {
    if (outCurrentControl != nullptr) {
      *outCurrentControl = _controlfp(0u, 0u);
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return EINVAL;
  }

  const unsigned int currentControl = _controlfp(newControl, sanitizedMask);
  if (outCurrentControl != nullptr) {
    *outCurrentControl = currentControl;
  }

  return 0;
}

/**
 * Address: 0x00A89CDC (FUN_00A89CDC, __ftol2_sse_excpt)
 *
 * What it does:
 * Preserves the legacy SSE ftol exception path: when compatibility mode is on
 * and the x87 control word matches the Pentium4 exception mask lane, uses the
 * SSE scalar conversion path; otherwise falls back to `__ftol2`.
 */
extern "C" std::int64_t __cdecl __ftol2_sse_excpt(const double value)
{
  if (global_compat_flag != 0) {
    const unsigned int controlWord = _controlfp(0u, 0u);
    if ((controlWord & 0x7Fu) == 0x7Fu) {
      return static_cast<std::int64_t>(static_cast<std::int32_t>(value));
    }
  }

  return __ftol2(value);
}

/**
 * Address: 0x00AEA160 (FUN_00AEA160, _UTY_MulDivRound)
 *
 * What it does:
 * Multiplies two signed 32-bit values, rounds by half of the divisor, divides
 * by the signed divisor, and preserves the legacy divide-by-zero saturation
 * lane.
 */
extern "C" int __cdecl _UTY_MulDivRound(const int value, const int multiplier, const int divisor)
{
  if (divisor == 0) {
    return ((multiplier ^ value) < 0) ? std::numeric_limits<int>::min() : std::numeric_limits<int>::max();
  }

  std::int64_t absoluteValue = value;
  std::int64_t absoluteMultiplier = multiplier;
  std::int64_t absoluteDivisor = divisor;
  int sign = 1;

  if (absoluteValue < 0) {
    absoluteValue = -absoluteValue;
    sign = -sign;
  }
  if (absoluteMultiplier < 0) {
    absoluteMultiplier = -absoluteMultiplier;
    sign = -sign;
  }
  if (absoluteDivisor < 0) {
    absoluteDivisor = -absoluteDivisor;
    sign = -sign;
  }

  const std::int64_t rounded =
    ((absoluteMultiplier * absoluteValue) + (absoluteDivisor / 2)) / absoluteDivisor;
  const std::int64_t signedResult = (sign < 0) ? -rounded : rounded;
  return static_cast<int>(signedResult);
}

/**
 * Address: 0x00A89E5A (FUN_00A89E5A, ___initstdio)
 *
 * What it does:
 * Initializes CRT stream table storage, seeds the legacy 20-entry `_iob`
 * lane into `__piob`, and marks invalid OS handles as detached (`_file=-2`).
 */
extern "C" int __cdecl __initstdio()
{
  constexpr unsigned int kDefaultStreamCount = 0x200u;
  constexpr unsigned int kMinimumStreamCount = 0x14u;
  constexpr int kLegacyIobCount = 20;
  constexpr int kInitFailureStatus = 26;

  unsigned int streamCount = _nstream;
  if (streamCount == 0u) {
    streamCount = kDefaultStreamCount;
  } else if (streamCount < kMinimumStreamCount) {
    streamCount = kMinimumStreamCount;
  }
  _nstream = streamCount;

  std::FILE** streamTable =
    static_cast<std::FILE**>(_calloc_crt(static_cast<std::size_t>(streamCount), sizeof(std::FILE*)));
  __piob = streamTable;
  if (streamTable == nullptr) {
    _nstream = kMinimumStreamCount;
    streamTable = static_cast<std::FILE**>(_calloc_crt(kMinimumStreamCount, sizeof(std::FILE*)));
    __piob = streamTable;
    if (streamTable == nullptr) {
      return kInitFailureStatus;
    }
  }

  std::FILE* const ioBase = __iob_func();
  for (int streamIndex = 0; streamIndex < kLegacyIobCount; ++streamIndex) {
    streamTable[streamIndex] = ioBase + streamIndex;
  }

  for (int streamIndex = 0; streamIndex < kLegacyIobCount; ++streamIndex) {
    RuntimeIoInfo* const ioInfo = __pioinfo[streamIndex >> 5] + (streamIndex & 0x1F);
    const int osHandle = static_cast<int>(ioInfo->osfhnd);
    if (osHandle == -1 || osHandle == -2 || osHandle == 0) {
      legacy_file(ioBase[streamIndex])._file = -2;
    }
  }

  return 0;
}

namespace moho::runtime
{
  int RuntimeMemicmp(const void* lhsBuffer, const void* rhsBuffer, std::size_t byteCount);
  [[nodiscard]] unsigned long* RuntimeDosErrno();
  extern "C" unsigned int __cdecl div64_0(unsigned __int64 dividend, __int64 divisor);

  /**
   * Address: 0x00A96AF8 (FUN_00A96AF8, _mtinitlocks)
   *
   * What it does:
   * Initializes preallocated CRT lock-table entries by assigning them to
   * `lclcritsects` slots and calling `__crtInitCritSecAndSpinCount(0xFA0)`.
   */
  extern "C" int __cdecl _mtinitlocks()
  {
    struct RuntimeLockTableEntryView
    {
      LPCRITICAL_SECTION lock;
      LPCRITICAL_SECTION kind;
    };
    static_assert(sizeof(RuntimeLockTableEntryView) == 0x8, "RuntimeLockTableEntryView size must be 0x8");

    const LPCRITICAL_SECTION preallocKind = reinterpret_cast<LPCRITICAL_SECTION>(1);
    constexpr DWORD kSpinCount = 0xFA0;
    constexpr std::size_t kLockEntryCount = 36u;

    auto* const lockTable = reinterpret_cast<RuntimeLockTableEntryView*>(_locktable);
    CRITICAL_SECTION* nextPreallocLock = lclcritsects;
    for (std::size_t index = 0; index < kLockEntryCount; ++index) {
      RuntimeLockTableEntryView& entry = lockTable[index];
      if (entry.kind != preallocKind) {
        continue;
      }

      entry.lock = nextPreallocLock++;
      RuntimeInitCritSecAndSpinCountFn initFn = gRuntimeInitCritSecAndSpinCount;
      if (initFn == nullptr) {
        initFn = &__crtInitCritSecAndSpinCount;
      }
      if (initFn(entry.lock, kSpinCount) == 0) {
        entry.lock = nullptr;
        return 0;
      }
    }

    return 1;
  }

  /**
   * Address: 0x00A96B41 (FUN_00A96B41, _mtdeletelocks)
   *
   * What it does:
   * Walks CRT lock-table entries and destroys lock objects in two passes:
   * heap-owned locks are deleted/freed first, then static locks are deleted.
   */
  extern "C" void __cdecl _mtdeletelocks()
  {
    const LPCRITICAL_SECTION staticLockTag = reinterpret_cast<LPCRITICAL_SECTION>(1);

    LPCRITICAL_SECTION* lockCursor = _locktable;
    LPCRITICAL_SECTION* const lockEnd = reinterpret_cast<LPCRITICAL_SECTION*>(_wnullstring);

    while (lockCursor < lockEnd) {
      LPCRITICAL_SECTION const lock = lockCursor[0];
      if (lock != nullptr && lockCursor[1] != staticLockTag) {
        ::DeleteCriticalSection(lock);
        _free_crt(lock);
        lockCursor[0] = nullptr;
      }
      lockCursor += 2;
    }

    lockCursor = _locktable;
    while (lockCursor < lockEnd) {
      LPCRITICAL_SECTION const lock = lockCursor[0];
      if (lock != nullptr && lockCursor[1] == staticLockTag) {
        ::DeleteCriticalSection(lock);
      }
      lockCursor += 2;
    }
  }

  /**
   * Address: 0x00A9BD16 (FUN_00A9BD16, _freebuf)
   *
   * What it does:
   * Releases one CRT stream-owned heap buffer when `_IOMYBUF` is set on a
   * buffered stream and clears stream pointers/count state.
   */
  extern "C" int __cdecl _freebuf(std::FILE* const stream)
  {
    int streamFlags = legacy_file(stream)._flag;
    if ((streamFlags & 0x83) != 0 && (streamFlags & 0x08) != 0) {
      _free_crt(legacy_file(stream)._base);
      legacy_file(stream)._flag &= ~0x408;
      legacy_file(stream)._ptr = nullptr;
      legacy_file(stream)._base = nullptr;
      legacy_file(stream)._cnt = 0;
      streamFlags = 0;
    }

    return streamFlags;
  }

  constexpr int kOFlagWronly = 1;
  constexpr int kOFlagRdwr = 2;
  constexpr int kOFlagAppend = 8;
  constexpr int kOFlagRandom = 0x10;
  constexpr int kOFlagSequential = 0x20;
  constexpr int kOFlagTemporary = 0x40;
  constexpr int kOFlagNoinherit = 0x80;
  constexpr int kOFlagCreat = 0x100;
  constexpr int kOFlagTrunc = 0x200;
  constexpr int kOFlagExcl = 0x400;
  constexpr int kOFlagShortLived = 0x1000;
  constexpr int kOFlagWText = 0x10000;
  constexpr int kOFlagU16Text = 0x20000;
  constexpr int kOFlagU8Text = 0x40000;
  constexpr int kUtf8Bom = 0x00BFBBEF; // "EF BB BF" read little-endian into a 3-byte int
  constexpr std::uint16_t kUtf16LeBom = 0xFEFF;
  constexpr std::uint16_t kUtf16ReversedBom = 0xFFFE;

  /**
   * Address: 0x00AA4A6D (FUN_00AA4A6D, tsopen_nolock / _tsopen_nolock)
   *
   * What it does:
   * Narrow-path counterpart of `_wsopen_nolock` (0x00AAF7B4) -- identical
   * flag-decode/CreateFile/GetFileType/Ctrl-Z-truncation/BOM-sniff-and-write
   * pipeline, using `CreateFileA` and a `char`-typed BOM scratch buffer.
   * See `_wsopen_nolock`'s doc comment for the full behavior description.
   */
  extern "C" int __cdecl _tsopen_nolock(
    int* const outFileHandle,
    int* const unlockFlag,
    const char* const lpFileName,
    const int openFlags,
    const int shareFlags,
    const int permissionFlags
  )
  {
    int defaultFileMode = 0;
    unsigned int osPlatform = 0;
    if (_get_fmode(&defaultFileMode) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }
    if (_get_osplatform(&osPlatform) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    SECURITY_ATTRIBUTES securityAttributes;
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.lpSecurityDescriptor = nullptr;
    securityAttributes.bInheritHandle = (openFlags & kOFlagNoinherit) == 0 ? TRUE : FALSE;

    std::uint8_t pendingOsfileFlags = ((openFlags & kOFlagNoinherit) != 0) ? 0x10 : 0;
    if ((openFlags & 0x8000 /* _O_BINARY */) == 0 &&
        ((openFlags & 0x74000 /* _O_WTEXT|_O_U16TEXT|_O_U8TEXT|_O_TEXT */) != 0 || defaultFileMode != 0x8000))
    {
      pendingOsfileFlags |= 0x80;
    }

    auto invalidArgument = [&]() -> int {
      *RuntimeDosErrno() = 0;
      *outFileHandle = -1;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    };

    DWORD dwDesiredAccess;
    if ((openFlags & 3) != 0) {
      if ((openFlags & 3) == kOFlagWronly) {
        if ((openFlags & kOFlagAppend) != 0 && (openFlags & 0x70000) != 0) {
          dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
        } else {
          dwDesiredAccess = GENERIC_WRITE;
        }
      } else if ((openFlags & 3) == kOFlagRdwr) {
        dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
      } else {
        return invalidArgument();
      }
    } else {
      dwDesiredAccess = GENERIC_READ;
    }

    DWORD dwShareMode;
    switch (shareFlags) {
      case 16: dwShareMode = 0; break;
      case 32: dwShareMode = FILE_SHARE_READ; break;
      case 48: dwShareMode = FILE_SHARE_WRITE; break;
      case 64: dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE; break;
      case 128: dwShareMode = (dwDesiredAccess == GENERIC_READ) ? FILE_SHARE_READ : 0; break;
      default: return invalidArgument();
    }

    DWORD dwCreationDisposition;
    const int creationBits = openFlags & 0x700;
    if (creationBits > 0x400) {
      if (creationBits == 0x500) {
        dwCreationDisposition = CREATE_NEW;
      } else if (creationBits == 0x600) {
        dwCreationDisposition = TRUNCATE_EXISTING;
      } else if (creationBits == 0x700) {
        dwCreationDisposition = CREATE_NEW;
      } else {
        return invalidArgument();
      }
    } else if (creationBits == 0x400 || creationBits == 0) {
      dwCreationDisposition = OPEN_EXISTING;
    } else if (creationBits == 0x100 /* kOFlagCreat alone */) {
      dwCreationDisposition = OPEN_ALWAYS;
    } else if (creationBits == 0x200 /* kOFlagTrunc alone */) {
      dwCreationDisposition = TRUNCATE_EXISTING;
    } else if (creationBits == 0x300 /* CREAT|TRUNC */) {
      dwCreationDisposition = CREATE_ALWAYS;
    } else {
      return invalidArgument();
    }

    DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    if ((openFlags & kOFlagCreat) != 0 && (permissionFlags & ~umaskval & 0x80) == 0) {
      dwFlagsAndAttributes = FILE_ATTRIBUTE_READONLY;
    }
    if ((openFlags & kOFlagTemporary) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_DELETE_ON_CLOSE;
      dwDesiredAccess |= DELETE;
      if (osPlatform == 2 /* VER_PLATFORM_WIN32_NT */) {
        dwShareMode |= FILE_SHARE_DELETE;
      }
    }
    if ((openFlags & kOFlagShortLived) != 0) {
      dwFlagsAndAttributes |= FILE_ATTRIBUTE_TEMPORARY;
    }
    if ((openFlags & kOFlagSequential) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_SEQUENTIAL_SCAN;
    } else if ((openFlags & kOFlagRandom) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_RANDOM_ACCESS;
    }

    const int newDescriptor = _alloc_osfhnd();
    *outFileHandle = newDescriptor;
    if (newDescriptor == -1) {
      *RuntimeDosErrno() = 0;
      *outFileHandle = -1;
      *_errno() = EMFILE;
      return *_errno();
    }

    *unlockFlag = 1;
    RuntimeIoInfo* const slot = __pioinfo[newDescriptor >> 5] + (newDescriptor & 0x1F);

    HANDLE hFile = ::CreateFileA(
      lpFileName, dwDesiredAccess, dwShareMode, &securityAttributes, dwCreationDisposition, dwFlagsAndAttributes, nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) {
      bool retryOk = false;
      if ((dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE) &&
          (openFlags & 1) != 0)
      {
        dwDesiredAccess &= ~GENERIC_READ;
        hFile = ::CreateFileA(
          lpFileName, dwDesiredAccess, dwShareMode, &securityAttributes, dwCreationDisposition, dwFlagsAndAttributes, nullptr
        );
        retryOk = (hFile != INVALID_HANDLE_VALUE);
      }
      if (!retryOk) {
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        _dosmaperr(::GetLastError());
        return *_errno();
      }
    }

    switch (::GetFileType(hFile)) {
      case FILE_TYPE_UNKNOWN: {
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        const DWORD lastError = ::GetLastError();
        _dosmaperr(lastError);
        ::CloseHandle(hFile);
        if (lastError == 0) {
          *_errno() = EACCES;
        }
        return *_errno();
      }
      case FILE_TYPE_CHAR: pendingOsfileFlags |= 0x40; break;
      case FILE_TYPE_PIPE: pendingOsfileFlags |= 0x08; break;
      default: break;
    }

    _set_osfhnd(newDescriptor, reinterpret_cast<std::intptr_t>(hFile));
    pendingOsfileFlags |= 0x01;
    slot->osfile = pendingOsfileFlags;
    slot->textmodeUnicode &= static_cast<std::int8_t>(0x80);
    const std::uint8_t wasPipeOrChar = pendingOsfileFlags & 0x48;

    if (wasPipeOrChar == 0 && static_cast<std::int8_t>(pendingOsfileFlags) < 0 && (openFlags & kOFlagRdwr) != 0) {
      // Regular disk file, text mode, opened for read+write: peek the
      // trailing byte and truncate a lone Ctrl-Z.
      const long tailPos = _lseek_nolock(newDescriptor, -1, FILE_END);
      if (tailPos == -1) {
        if (*RuntimeDosErrno() != 131 /* ERROR_NEGATIVE_SEEK: empty file, nothing to truncate */) {
          _close_nolock(newDescriptor);
          return *_errno();
        }
      } else {
        char tailByte = 0;
        const unsigned int readResult = _read_nolock(newDescriptor, &tailByte, 1u);
        const bool isTrailingCtrlZ = (readResult == 0 && tailByte == 0x1A);
        if ((isTrailingCtrlZ && _chsize_nolock(newDescriptor, tailPos) == -1) ||
            _lseek_nolock(newDescriptor, 0, FILE_BEGIN) == -1)
        {
          _close_nolock(newDescriptor);
          return *_errno();
        }
      }
    }

    int bomSubmode = 0; // 0 = none, 1 = UTF-8, 2 = UTF-16LE
    if (static_cast<std::int8_t>(pendingOsfileFlags) < 0) {
      int effectiveFlags = openFlags;
      if ((effectiveFlags & 0x74000) == 0) {
        if ((defaultFileMode & 0x74000) != 0) {
          effectiveFlags |= (defaultFileMode & 0x74000);
        } else {
          effectiveFlags |= 0x4000 /* _O_TEXT */;
        }
      }
      const int textKind = effectiveFlags & 0x74000;

      bool wantsBomLogic = false;
      if (textKind == 0x4000 /* plain _O_TEXT */) {
        bomSubmode = 0;
      } else if (textKind == kOFlagWText || textKind == (kOFlagWText | 0x4000)) {
        wantsBomLogic = (effectiveFlags & 0x301) == 0x301;
      } else if (textKind == kOFlagU16Text || textKind == (kOFlagU16Text | 0x4000)) {
        bomSubmode = 2;
        wantsBomLogic = true;
      } else if (textKind == kOFlagU8Text || textKind == (kOFlagU8Text | 0x4000)) {
        bomSubmode = 1;
        wantsBomLogic = true;
      }

      if (wantsBomLogic && (effectiveFlags & 0x70000) != 0 && (pendingOsfileFlags & 0x40) == 0) {
        bool shouldWriteBom = false;
        bool aborted = false;
        bool bailedOut = false;

        const auto sniffBom = [&]() -> bool {
          unsigned char bomBytes[3] = {};
          const unsigned int peeked = _read_nolock(newDescriptor, reinterpret_cast<char*>(bomBytes), 3u);
          if (peeked == static_cast<unsigned int>(-1)) {
            _close_nolock(newDescriptor);
            return false;
          }
          bool rewind = true;
          if (peeked == 3 &&
              (static_cast<unsigned int>(bomBytes[0]) | (static_cast<unsigned int>(bomBytes[1]) << 8) |
               (static_cast<unsigned int>(bomBytes[2]) << 16)) == static_cast<unsigned int>(kUtf8Bom))
          {
            bomSubmode = 1;
            rewind = false;
          } else if (peeked >= 2) {
            const std::uint16_t leading16 =
              static_cast<std::uint16_t>(bomBytes[0]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(bomBytes[1]) << 8);
            if (leading16 == kUtf16ReversedBom) {
              _close_nolock(newDescriptor);
              *_errno() = EINVAL;
              return false;
            }
            if (leading16 == kUtf16LeBom) {
              if (_lseek_nolock(newDescriptor, 2, FILE_BEGIN) == -1) {
                _close_nolock(newDescriptor);
                return false;
              }
              bomSubmode = 2;
              rewind = false;
            }
          }
          if (rewind && _lseek_nolock(newDescriptor, 0, FILE_BEGIN) == -1) {
            _close_nolock(newDescriptor);
            return false;
          }
          return true;
        };

        const DWORD accessKind = dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE);
        if (accessKind == GENERIC_WRITE) {
          if (dwCreationDisposition == CREATE_NEW || dwCreationDisposition == CREATE_ALWAYS) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == OPEN_ALWAYS) {
            if (_lseeki64_nolock(newDescriptor, 0, FILE_END) != 0) {
              _lseeki64_nolock(newDescriptor, 0, FILE_BEGIN);
            } else {
              shouldWriteBom = true;
            }
          } else if (dwCreationDisposition == TRUNCATE_EXISTING) {
            shouldWriteBom = true;
          }
        } else if (accessKind == GENERIC_READ) {
          bailedOut = !sniffBom();
        } else if (accessKind == (GENERIC_READ | GENERIC_WRITE)) {
          if (dwCreationDisposition == 0) {
            // nothing to do
          } else if (dwCreationDisposition == CREATE_NEW || dwCreationDisposition == CREATE_ALWAYS) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == TRUNCATE_EXISTING) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == OPEN_ALWAYS) {
            if (_lseeki64_nolock(newDescriptor, 0, FILE_END) == 0) {
              shouldWriteBom = true;
            } else {
              const __int64 rewound = _lseeki64_nolock(newDescriptor, 0, FILE_BEGIN);
              if (rewound == -1) {
                _close_nolock(newDescriptor);
                return *_errno();
              }
              bailedOut = !sniffBom();
            }
          }
        } else {
          aborted = true;
        }

        if (bailedOut) {
          return *_errno();
        }

        if (!aborted && shouldWriteBom) {
          unsigned char bomToWrite[3] = {};
          int bomLength = 0;
          if (bomSubmode == 1) {
            bomToWrite[0] = 0xEF; bomToWrite[1] = 0xBB; bomToWrite[2] = 0xBF;
            bomLength = 3;
          } else if (bomSubmode == 2) {
            bomToWrite[0] = 0xFF; bomToWrite[1] = 0xFE;
            bomLength = 2;
          }
          if (bomLength != 0) {
            int written = 0;
            while (written < bomLength) {
              const int chunk = _write(newDescriptor, bomToWrite + written, static_cast<unsigned int>(bomLength - written));
              if (chunk == -1) {
                _close_nolock(newDescriptor);
                return *_errno();
              }
              written += chunk;
            }
          }
        }
      }
    }

    slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & ~0x7F) | (bomSubmode & 0x7F));
    slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & 0x7F) | (((openFlags >> 16) & 1) << 7));
    if (wasPipeOrChar == 0 && (openFlags & kOFlagAppend) != 0) {
      slot->osfile |= 0x20;
    }

    if ((dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE) && (openFlags & 1) != 0) {
      ::CloseHandle(hFile);
      hFile = ::CreateFileA(
        lpFileName, dwDesiredAccess & 0x7FFFFFFFu, dwShareMode, &securityAttributes, OPEN_EXISTING, dwFlagsAndAttributes, nullptr
      );
      if (hFile == INVALID_HANDLE_VALUE) {
        _dosmaperr(::GetLastError());
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        _free_osfhnd(newDescriptor);
        return *_errno();
      }
      slot->osfhnd = reinterpret_cast<std::intptr_t>(hFile);
    }

    return 0;
  }

  /**
   * Address: 0x00AA527C (FUN_00AA527C, tsopen_helper / _tsopen_helper)
   *
   * What it does:
   * Validates the out-fd pointer and path are non-null and that
   * `secureMode` is only combined with the secure subset of open flags,
   * then dispatches to `_tsopen_nolock`; on failure it clears the "in use"
   * bit in `_pioinfo` for the freshly-allocated slot and releases the
   * per-handle lock, then resets `*outFileHandle` to `-1`. Narrow-path
   * counterpart of `RuntimeWideSopenHelper` (0x00AAFFC4).
   */
  extern "C" int __cdecl _tsopen_helper(
    const char* const lpFileName,
    const int openFlags,
    const int shareFlags,
    const int permissionFlags,
    int* const outFileHandle,
    const int secureMode
  )
  {
    constexpr int kReservedFlagsWhenSecure = static_cast<int>(0xFFFFFE7FL);

    if (outFileHandle == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *outFileHandle = -1;

    if (lpFileName == nullptr ||
        (secureMode != 0 && (permissionFlags & kReservedFlagsWhenSecure) != 0))
    {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    int unlockNeeded = 0;
    const int openStatus = _tsopen_nolock(outFileHandle, &unlockNeeded, lpFileName, openFlags, shareFlags, permissionFlags);

    if (unlockNeeded != 0) {
      if (openStatus != 0) {
        RuntimeIoInfo* const slot = __pioinfo[*outFileHandle >> 5] + (*outFileHandle & 0x1F);
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
      }
      _unlock_fhandle(*outFileHandle);
    }

    if (openStatus != 0) {
      *outFileHandle = -1;
    }

    return openStatus;
  }

  /**
   * Address: 0x00AA5378 (FUN_00AA5378, _tsopen_s)
   * Address: 0x00AB00C0 (FUN_00AB00C0)
   *
   * What it does:
   * Forwards secure descriptor-open requests into `_tsopen_helper` with the
   * secure-mode flag set.
   */
  extern "C" int __cdecl _tsopen_s(
    int* const outFileHandle,
    const char* const fileName,
    const int openFlags,
    const int shareFlags,
    const int permissionFlags
  )
  {
    return _tsopen_helper(fileName, openFlags, shareFlags, permissionFlags, outFileHandle, 1);
  }

  /**
   * Address: 0x00AAF500 (FUN_00AAF500, _alloc_osfhnd)
   *
   * What it does:
   * Finds or allocates a free file-descriptor slot in the `__pioinfo` paged
   * table (32 slots/page, growing lazily). Scans existing pages for a free
   * (`osfile&1==0`) slot under its own lazily-initialized per-slot lock; if
   * none exists, allocates and zero-initializes a fresh 32-slot page.
   * Returns the new descriptor index, or -1 on failure.
   */
  extern "C" int __cdecl _alloc_osfhnd()
  {
    if (!RuntimeInitCrtLockNumber(kOsfhndLock)) {
      return -1;
    }

    RuntimeLockCrtLock(kOsfhndLock);

    int newDescriptor = -1;
    bool lockFailed = false;
    for (int page = 0; page < 64; ++page) {
      RuntimeIoInfo* const slot = __pioinfo[page];

      if (slot == nullptr) {
        auto* const newPage = static_cast<RuntimeIoInfo*>(_calloc_crt(32u, sizeof(RuntimeIoInfo)));
        if (newPage != nullptr) {
          __pioinfo[page] = newPage;
          _nhandle += 32;
          for (RuntimeIoInfo* init = newPage; init < newPage + 32; ++init) {
            init->osfile = 0;
            init->osfhnd = -1;
            init->pipech = 10;
            init->lockinitflag = 0;
          }

          newDescriptor = 32 * page;
          newPage->osfile = 1;
          if (!_lock_fhandle(newDescriptor)) {
            newDescriptor = -1;
          }
        }
        break;
      }

      for (RuntimeIoInfo* candidate = slot; candidate < slot + 32; ++candidate) {
        if ((candidate->osfile & 1) != 0) {
          continue;
        }

        if (candidate->lockinitflag == 0) {
          RuntimeLockCrtLock(kLocktabLock);
          if (candidate->lockinitflag == 0) {
            if (__crtInitCritSecAndSpinCount(&candidate->lock, 4000u)) {
              ++candidate->lockinitflag;
            } else {
              lockFailed = true;
            }
          }
          RuntimeUnlockCrtLock(kLocktabLock);
        }

        if (!lockFailed) {
          ::EnterCriticalSection(&candidate->lock);
          if ((candidate->osfile & 1) == 0) {
            candidate->osfile = 1;
            candidate->osfhnd = -1;
            newDescriptor = 32 * page + static_cast<int>(candidate - slot);
            break;
          }
          ::LeaveCriticalSection(&candidate->lock);
        }
      }

      if (newDescriptor != -1) {
        break;
      }
    }

    RuntimeUnlockCrtLock(kOsfhndLock);
    return newDescriptor;
  }

  /**
   * Address: 0x00AAF34C (FUN_00AAF34C, _free_osfhnd)
   *
   * What it does:
   * Releases the OS handle slot for `fileDescriptor` back to closed
   * (`osfhnd = -1`), clearing the matching std handle when releasing one of
   * the three console standard streams under a console-subsystem app.
   */
  extern "C" int __cdecl _free_osfhnd(const int fileDescriptor)
  {
    if (fileDescriptor < 0 || fileDescriptor >= _nhandle) {
      *_errno() = EBADF;
      *RuntimeDosErrno() = 0;
      return -1;
    }

    RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
    if ((slot->osfile & 1) == 0 || slot->osfhnd == -1) {
      *_errno() = EBADF;
      *RuntimeDosErrno() = 0;
      return -1;
    }

    constexpr int kConsoleAppType = 1;
    if (__app_type == kConsoleAppType) {
      if (fileDescriptor == 0) {
        ::SetStdHandle(STD_INPUT_HANDLE, nullptr);
      } else if (fileDescriptor == 1) {
        ::SetStdHandle(STD_OUTPUT_HANDLE, nullptr);
      } else if (fileDescriptor == 2) {
        ::SetStdHandle(STD_ERROR_HANDLE, nullptr);
      }
    }

    slot->osfhnd = -1;
    return 0;
  }

  /**
   * Address: 0x00AAF43E (FUN_00AAF43E, _lock_fhandle)
   *
   * What it does:
   * Enters the per-fd critical section for `fileDescriptor`, lazily
   * initializing it (under the lock-table lock) on first use.
   */
  extern "C" BOOL __cdecl _lock_fhandle(const int fileDescriptor)
  {
    RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);

    BOOL status = TRUE;
    if (slot->lockinitflag == 0) {
      RuntimeLockCrtLock(kLocktabLock);
      if (slot->lockinitflag == 0) {
        status = __crtInitCritSecAndSpinCount(&slot->lock, 4000u);
        ++slot->lockinitflag;
      }
      RuntimeUnlockCrtLock(kLocktabLock);
    }

    if (status) {
      ::EnterCriticalSection(&slot->lock);
    }
    return status;
  }

  /**
   * Address: 0x00AAF4DE (FUN_00AAF4DE, _unlock_fhandle)
   *
   * What it does:
   * Leaves the per-fd critical section for `fileDescriptor`.
   */
  extern "C" void __cdecl _unlock_fhandle(const int fileDescriptor)
  {
    ::LeaveCriticalSection(&(__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->lock);
  }

  /**
   * Address: 0x00AAF3CD (FUN_00AAF3CD, _get_osfhandle)
   *
   * What it does:
   * Returns the raw OS `HANDLE` backing `fileDescriptor`, or `(HANDLE)-1`
   * with `errno=EBADF` if the descriptor is the sentinel `-2` value, out of
   * range, or not currently open.
   */
  extern "C" HANDLE __cdecl RuntimeGetOsfHandle(const int fileDescriptor)
  {
    if (fileDescriptor == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1));
    }

    if (fileDescriptor >= 0 && fileDescriptor < _nhandle) {
      RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
      if ((slot->osfile & 1) != 0) {
        return reinterpret_cast<HANDLE>(slot->osfhnd);
      }
    }

    *RuntimeDosErrno() = 0;
    *_errno() = EBADF;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1));
  }

  /**
   * Address: 0x00A9CAE6 (FUN_00A9CAE6, _lseek_nolock)
   *
   * What it does:
   * Repositions the file pointer for `fileDescriptor` via `SetFilePointer`,
   * clearing the "ungetc pending" flag (`osfile & 0x02`) on success.
   */
  extern "C" long __cdecl _lseek_nolock(const int fileDescriptor, const long offset, const int moveMethod)
  {
    const HANDLE osHandle = RuntimeGetOsfHandle(fileDescriptor);
    if (osHandle == reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1))) {
      *_errno() = EBADF;
      return -1;
    }

    const DWORD newPos = ::SetFilePointer(osHandle, offset, nullptr, static_cast<DWORD>(moveMethod));
    const DWORD lastError = (newPos == 0xFFFFFFFFu) ? ::GetLastError() : 0u;
    if (lastError != 0) {
      _dosmaperr(lastError);
      return -1;
    }

    (__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->osfile &= static_cast<std::uint8_t>(~0x02u);
    return static_cast<long>(newPos);
  }

  /**
   * Address: 0x00AB629A (FUN_00AB629A, _lseeki64_nolock)
   *
   * What it does:
   * 64-bit-offset counterpart of `_lseek_nolock`, using the high/low
   * `SetFilePointer` overload.
   */
  extern "C" __int64 __cdecl _lseeki64_nolock(const int fileDescriptor, const __int64 offset, const int moveMethod)
  {
    const HANDLE osHandle = RuntimeGetOsfHandle(fileDescriptor);
    if (osHandle == reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1))) {
      *_errno() = EBADF;
      return -1;
    }

    LONG highPart = static_cast<LONG>(offset >> 32);
    const DWORD lowResult = ::SetFilePointer(
      osHandle, static_cast<LONG>(offset), &highPart, static_cast<DWORD>(moveMethod)
    );
    if (lowResult == 0xFFFFFFFFu) {
      const DWORD lastError = ::GetLastError();
      if (lastError != 0) {
        _dosmaperr(lastError);
        return -1;
      }
    }

    (__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->osfile &= static_cast<std::uint8_t>(~0x02u);
    return (static_cast<__int64>(highPart) << 32) | lowResult;
  }

  /**
   * Address: 0x00A9BBB5 (FUN_00A9BBB5, close_nolock / _close_nolock)
   *
   * What it does:
   * Closes the OS handle for `fileDescriptor`, skipping the actual
   * `CloseHandle` when fd 1/2 alias the same handle (real CRT stdout/stderr
   * handle-sharing special case), then frees the descriptor slot.
   */
  extern "C" int __cdecl _close_nolock(const int fileDescriptor)
  {
    // The fd-1/fd-2 aliasing check reads a flag bit off the *adjacent*
    // ioinfo slot's textmodeUnicode (fd 2 when closing fd 1) or off fd 1's
    // own CRITICAL_SECTION RecursionCount word (when closing fd 2) --
    // preserved verbatim from the decompiled shape; the exact intended flag
    // semantics for the second case are not independently confirmed.
    const bool skipClose =
      (RuntimeGetOsfHandle(fileDescriptor) == reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1))) ||
      (((fileDescriptor == 1 && (__pioinfo[0][2].textmodeUnicode & 1) != 0) ||
        (fileDescriptor == 2 && (reinterpret_cast<int*>(&__pioinfo[0][1].lock)[2] & 1) != 0)) &&
       RuntimeGetOsfHandle(2) == RuntimeGetOsfHandle(1));

    const bool closedOk = skipClose || ::CloseHandle(RuntimeGetOsfHandle(fileDescriptor)) != 0;
    const DWORD lastError = closedOk ? 0u : ::GetLastError();

    _free_osfhnd(fileDescriptor);
    (__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->osfile = 0;

    if (lastError == 0) {
      return 0;
    }
    _dosmaperr(lastError);
    return -1;
  }

  constexpr int kOModeText = 0x4000;
  constexpr int kOModeBinary = 0x8000;
  constexpr int kOModeWText = 0x10000;
  constexpr int kOModeU16Text = 0x20000;
  constexpr int kOModeU8Text = 0x40000;

  /**
   * Address: 0x00AB97D0 (FUN_00AB97D0, _setmode_nolock)
   *
   * What it does:
   * Switches the text/binary/Unicode translation mode for `fileDescriptor`,
   * returning the previous mode (`_O_TEXT`/`_O_WTEXT`/`_O_BINARY`).
   */
  extern "C" int __cdecl _setmode_nolock(const int fileDescriptor, const int mode)
  {
    RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
    const bool wasTextMode = (slot->osfile & 0x80) != 0;
    const int previousUnicodeSubmode = static_cast<int>(static_cast<std::int8_t>(slot->textmodeUnicode << 1) >> 1);

    if (mode == kOModeText) {
      slot->osfile |= 0x80;
      slot->textmodeUnicode &= static_cast<std::int8_t>(0x80);
    } else if (mode == kOModeBinary) {
      slot->osfile &= static_cast<std::uint8_t>(~0x80);
    } else if (mode == kOModeWText || mode == kOModeU16Text) {
      slot->osfile |= 0x80;
      slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & 0x80) | 2);
    } else if (mode == kOModeU8Text) {
      slot->osfile |= 0x80;
      slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & 0x80) | 1);
    }

    if (wasTextMode) {
      return previousUnicodeSubmode != 0 ? kOModeWText : kOModeText;
    }
    return kOModeBinary;
  }

  namespace detail {
    /**
     * Shared tail for `_write_nolock`: when nothing was written, maps the
     * captured async Win32 error (if any) through `_dosmaperr`, special-cases
     * "wrote 0 of a leading Ctrl-Z byte into a piped/char device" as success,
     * and otherwise reports `ENOSPC`; when something was written, returns the
     * byte count minus the bytes inserted purely for `\n`->`\r\n` expansion.
     * Mirrors the real function's shared `LABEL_83` exit.
     */
    int FinalizeNolockWrite(
      const int fileDescriptor, const unsigned int totalWritten, const unsigned int crInsertedCount,
      const DWORD asyncError, const char firstByte)
    {
      if (totalWritten != 0) {
        return static_cast<int>(totalWritten - crInsertedCount);
      }

      DWORD mappedDosError = 0;
      if (asyncError != 0) {
        mappedDosError = 5;
        if (asyncError != 5) {
          _dosmaperr(asyncError);
          return -1;
        }
        *_errno() = EBADF;
      } else {
        RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
        if ((slot->osfile & 0x40) != 0 && firstByte == 0x1A) {
          return 0;
        }
        *_errno() = ENOSPC;
      }
      *RuntimeDosErrno() = mappedDosError;
      return -1;
    }
  } // namespace detail

  /**
   * Address: 0x00A9B4E6 (FUN_00A9B4E6, _write_nolock)
   *
   * What it does:
   * Low-level buffered write for `fileDescriptor`. For a TTY in text mode,
   * writes character-by-character through the console, converting between
   * the file's translation submode (ANSI/UTF-16/UTF-8) and the console's
   * active code page, expanding `\n` to `\r\n`. For a regular file: binary
   * mode writes the buffer directly; ANSI/UTF-16/UTF-8 text modes buffer
   * through a fixed scratch page doing the same `\n`->`\r\n` expansion
   * (re-encoding via `WideCharToMultiByte` for the UTF-8 submode) before
   * calling `WriteFile`.
   */
  extern "C" int __cdecl _write_nolock(const int fileDescriptor, const char* const buffer, const unsigned int count)
  {
    if (count == 0) {
      return 0;
    }
    if (buffer == nullptr) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
    const int submode = static_cast<int>(static_cast<std::int8_t>(slot->textmodeUnicode << 1) >> 1);

    if ((submode == 1 || submode == 2) && (count & 1u) != 0) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    if ((slot->osfile & 0x20) != 0) {
      _lseeki64_nolock(fileDescriptor, 0, FILE_END);
    }

    // Console path: only taken for a TTY currently in text mode (osfile
    // sign bit, matching _setmode_nolock's O_TEXT bit).
    if (_isatty(fileDescriptor) != 0 && static_cast<std::int8_t>(slot->osfile) < 0) {
      const HANDLE consoleHandle = reinterpret_cast<HANDLE>(slot->osfhnd);
      DWORD consoleMode = 0;
      if (::GetConsoleMode(consoleHandle, &consoleMode) != 0) {
        RuntimeTidDataLocaleView* const threadData = __getptd();
        const bool usesDefaultLocale = (threadData->ptlocinfo->lcHandle[2] == 0);

        if (!usesDefaultLocale || submode != 0) {
          const UINT consoleCp = ::GetConsoleCP();
          const char* readCursor = buffer;
          unsigned int consumed = 0;
          unsigned int totalWritten = 0;
          unsigned int crInsertedCount = 0;
          DWORD asyncError = 0;
          bool failed = false;

          while (consumed < count && !failed) {
            bool isNewline = false;

            if (submode != 0) {
              const std::uint16_t wch = *reinterpret_cast<const std::uint16_t*>(readCursor);
              readCursor += 2;
              ++consumed;
              isNewline = (wch == static_cast<std::uint16_t>(L'\n'));

              if (static_cast<std::uint16_t>(::putwch_nolock(static_cast<wchar_t>(wch))) != wch) {
                failed = true;
                asyncError = ::GetLastError();
              } else {
                ++totalWritten;
                if (isNewline) {
                  if (static_cast<std::uint16_t>(::putwch_nolock(L'\r')) != static_cast<std::uint16_t>(L'\r')) {
                    failed = true;
                    asyncError = ::GetLastError();
                  } else {
                    ++totalWritten;
                    ++crInsertedCount;
                  }
                }
              }
            } else {
              const int leadByte = static_cast<unsigned char>(*readCursor);
              isNewline = (leadByte == '\n');
              wchar_t decoded = 0;
              bool decodeOk = true;

              if (isleadbyte(leadByte) != 0) {
                if (count - consumed <= 1 || mbtowc(&decoded, readCursor, 2) == -1) {
                  decodeOk = false;
                } else {
                  ++readCursor;
                }
              } else if (mbtowc(&decoded, readCursor, 1) == -1) {
                decodeOk = false;
              }

              if (!decodeOk) {
                failed = true;
              } else {
                ++readCursor;
                ++consumed;

                char multiByte[5] = {};
                const int mbLen = ::WideCharToMultiByte(consoleCp, 0, &decoded, 1, multiByte, 5, nullptr, nullptr);
                DWORD bytesWritten = 0;
                if (mbLen == 0) {
                  failed = true;
                } else if (!::WriteFile(consoleHandle, multiByte, static_cast<DWORD>(mbLen), &bytesWritten, nullptr)) {
                  failed = true;
                  asyncError = ::GetLastError();
                } else {
                  totalWritten += bytesWritten;
                  if (static_cast<int>(bytesWritten) < mbLen) {
                    failed = true;
                  } else if (isNewline) {
                    multiByte[0] = '\r';
                    if (!::WriteFile(consoleHandle, multiByte, 1u, &bytesWritten, nullptr)) {
                      failed = true;
                      asyncError = ::GetLastError();
                    } else if (bytesWritten < 1) {
                      failed = true;
                    } else {
                      ++crInsertedCount;
                      ++totalWritten;
                    }
                  }
                }
              }
            }
          }

          return detail::FinalizeNolockWrite(fileDescriptor, totalWritten, crInsertedCount, asyncError, buffer[0]);
        }
      }
    }

    // Regular-file path.
    if (static_cast<std::int8_t>(slot->osfile) >= 0) {
      DWORD bytesWritten = 0;
      DWORD asyncError = 0;
      unsigned int totalWritten = 0;
      if (::WriteFile(reinterpret_cast<HANDLE>(slot->osfhnd), buffer, count, &bytesWritten, nullptr)) {
        totalWritten = bytesWritten;
      } else {
        asyncError = ::GetLastError();
      }
      return detail::FinalizeNolockWrite(fileDescriptor, totalWritten, 0u, asyncError, buffer[0]);
    }

    if (submode == 0) {
      // ANSI text mode: buffer through a scratch page, expanding
      // '\n' -> "\r\n", flushing in <=0x400-byte chunks.
      const char* readCursor = buffer;
      unsigned int consumed = 0;
      unsigned int totalWritten = 0;
      unsigned int crInsertedCount = 0;
      DWORD asyncError = 0;
      while (consumed < count) {
        char scratch[0x400];
        char* dst = scratch;
        while (consumed < count && (dst - scratch) < 0x400) {
          const char ch = *readCursor++;
          ++consumed;
          if (ch == '\n') {
            ++crInsertedCount;
            *dst++ = '\r';
          }
          *dst++ = ch;
        }
        const unsigned int producedThisChunk = static_cast<unsigned int>(dst - scratch);
        DWORD bytesWritten = 0;
        if (!::WriteFile(reinterpret_cast<HANDLE>(slot->osfhnd), scratch, producedThisChunk, &bytesWritten, nullptr)) {
          asyncError = ::GetLastError();
          break;
        }
        totalWritten += bytesWritten;
        if (bytesWritten < producedThisChunk) {
          break;
        }
      }
      return detail::FinalizeNolockWrite(fileDescriptor, totalWritten, crInsertedCount, asyncError, buffer[0]);
    }

    if (submode == 2) {
      // Wide (_O_WTEXT/_O_U16TEXT) mode into a non-console file: source is
      // wchar_t data; expand L'\n'->L"\r\n", write the wide bytes as-is.
      const char* readCursor = buffer;
      unsigned int consumed = 0;
      unsigned int totalWritten = 0;
      unsigned int crInsertedCount = 0;
      DWORD asyncError = 0;
      while (consumed < count) {
        char scratch[0x400];
        char* dst = scratch;
        while (consumed < count && (dst - scratch) < 0x3FE) {
          const std::uint16_t wch = *reinterpret_cast<const std::uint16_t*>(readCursor);
          readCursor += 2;
          consumed += 2;
          if (wch == static_cast<std::uint16_t>(L'\n')) {
            crInsertedCount += 2;
            *reinterpret_cast<std::uint16_t*>(dst) = static_cast<std::uint16_t>(L'\r');
            dst += 2;
          }
          *reinterpret_cast<std::uint16_t*>(dst) = wch;
          dst += 2;
        }
        const unsigned int producedThisChunk = static_cast<unsigned int>(dst - scratch);
        DWORD bytesWritten = 0;
        if (!::WriteFile(reinterpret_cast<HANDLE>(slot->osfhnd), scratch, producedThisChunk, &bytesWritten, nullptr)) {
          asyncError = ::GetLastError();
          break;
        }
        totalWritten += bytesWritten;
        if (bytesWritten < producedThisChunk) {
          break;
        }
      }
      return detail::FinalizeNolockWrite(fileDescriptor, totalWritten, crInsertedCount, asyncError, buffer[0]);
    }

    // UTF-8 (_O_U8TEXT) mode into a non-console file: source is wchar_t
    // data; expand L'\n'->L"\r\n" in a wide scratch buffer, re-encode to
    // UTF-8 via WideCharToMultiByte, then WriteFile the encoded bytes.
    {
      const auto* wideCursor = reinterpret_cast<const std::uint16_t*>(buffer);
      const auto* const wideBase = wideCursor;
      unsigned int totalWritten = 0;
      DWORD asyncError = 0;
      bool stop = false;
      while (!stop && static_cast<unsigned int>(reinterpret_cast<const char*>(wideCursor) - buffer) < count) {
        wchar_t wideScratch[0xA9 + 1];
        wchar_t* wDst = wideScratch;
        while (static_cast<unsigned int>(reinterpret_cast<const char*>(wideCursor) - buffer) < count &&
               (wDst - wideScratch) < 0xA9) {
          const std::uint16_t wch = *wideCursor++;
          if (wch == static_cast<std::uint16_t>(L'\n')) {
            *wDst++ = L'\r';
          }
          *wDst++ = static_cast<wchar_t>(wch);
        }

        char utf8Scratch[688];
        const int encodedLen = ::WideCharToMultiByte(
          CP_UTF8, 0, wideScratch, static_cast<int>(wDst - wideScratch), utf8Scratch, 683, nullptr, nullptr
        );
        if (encodedLen == 0) {
          break;
        }

        int flushed = 0;
        DWORD bytesWritten = 0;
        bool chunkOk = false;
        while (::WriteFile(reinterpret_cast<HANDLE>(slot->osfhnd), &utf8Scratch[flushed], encodedLen - flushed, &bytesWritten, nullptr)) {
          flushed += static_cast<int>(bytesWritten);
          if (encodedLen <= flushed) {
            chunkOk = true;
            break;
          }
        }
        if (!chunkOk && encodedLen > flushed) {
          asyncError = ::GetLastError();
          stop = true;
        } else {
          totalWritten = static_cast<unsigned int>(reinterpret_cast<const char*>(wideCursor) - buffer);
          if (totalWritten >= count) {
            stop = true;
          }
        }
      }
      (void)wideBase;
      return detail::FinalizeNolockWrite(fileDescriptor, totalWritten, 0u, asyncError, buffer[0]);
    }
  }

  /**
   * Address: 0x00A9BAAC (FUN_00A9BAAC, write / _write)
   *
   * What it does:
   * Public fd-based write entry point: validates `fileDescriptor` is open,
   * acquires its per-fd lock, forwards to `_write_nolock`, releases the
   * lock, and returns its result.
   */
  extern "C" int __cdecl _write(const int fileDescriptor, const void* const buffer, const unsigned int count)
  {
    if (fileDescriptor == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1;
    }

    if (fileDescriptor < 0 || fileDescriptor >= _nhandle ||
        ((__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->osfile & 1) == 0)
    {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    _lock_fhandle(fileDescriptor);

    int result;
    if (((__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F))->osfile & 1) != 0) {
      result = _write_nolock(fileDescriptor, static_cast<const char*>(buffer), count);
    } else {
      *_errno() = EBADF;
      *RuntimeDosErrno() = 0;
      result = -1;
    }

    _unlock_fhandle(fileDescriptor);
    return result;
  }

  // Real address unresolved: MSVC CRT's per-lead-byte trailing-multibyte-
  // sequence-length table (0-255), consulted only by _read_nolock's UTF-8
  // partial-sequence recovery path. Declared as an opaque data reference
  // pending a dedicated CRT locale-table recovery pass; not exercised by
  // any currently-recovered caller (ANSI/binary reads never reach it).
  extern "C" const unsigned char g_mbcsTrailingByteCount[256];

  /**
   * Address: 0x00AA1246 (FUN_00AA1246, _read_nolock)
   *
   * What it does:
   * Low-level buffered read for `fileDescriptor`. Serves any pending
   * pushback byte(s) first (`pipech`/`pipech2`, set by ungetc-style
   * callers), then `ReadFile`s the rest. In text mode: ANSI/UTF-8 submodes
   * scan the raw bytes for `\r\n`->`\n` collapse and Ctrl-Z truncation
   * (UTF-8 additionally re-decodes the collapsed bytes into the caller's
   * wide buffer via `MultiByteToWideChar`, buffering the tail of a split
   * multibyte sequence into the fd's pushback slots for the next call);
   * UTF-16 submode does the same `\r\n`->`\n` collapse on 16-bit units.
   * Binary mode returns the raw byte count unchanged.
   */
  extern "C" unsigned int __cdecl _read_nolock(const int fileDescriptor, char* const lpBuffer, const unsigned int requestedSize)
  {
    if (fileDescriptor == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return static_cast<unsigned int>(-1);
    }
    if (fileDescriptor < 0 || fileDescriptor >= _nhandle) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<unsigned int>(-1);
    }

    RuntimeIoInfo* const slot = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
    if ((slot->osfile & 1) == 0) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<unsigned int>(-1);
    }

    if (requestedSize > 0x7FFFFFFFu) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<unsigned int>(-1);
    }
    if (requestedSize == 0 || (slot->osfile & 2) != 0) {
      return 0;
    }
    if (lpBuffer == nullptr) {
      *RuntimeDosErrno() = 0;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return static_cast<unsigned int>(-1);
    }

    const int submode = static_cast<int>(static_cast<std::int8_t>(slot->textmodeUnicode << 1) >> 1);

    char* scratch = lpBuffer;
    unsigned int readCapacity = requestedSize;
    bool scratchOwned = false;

    if (submode == 2 /* _O_U16TEXT */) {
      if ((requestedSize & 1u) != 0) {
        *RuntimeDosErrno() = 0;
        *_errno() = EINVAL;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        return static_cast<unsigned int>(-1);
      }
      readCapacity &= ~1u;
    } else if (submode == 1 /* _O_U8TEXT */) {
      if ((requestedSize & 1u) != 0) {
        *RuntimeDosErrno() = 0;
        *_errno() = EINVAL;
        _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
        return static_cast<unsigned int>(-1);
      }
      readCapacity = std::max<unsigned int>(4u, requestedSize >> 1);
      scratch = static_cast<char*>(std::malloc(readCapacity));
      if (scratch == nullptr) {
        *_errno() = ENOMEM;
        *RuntimeDosErrno() = 8;
        return static_cast<unsigned int>(-1);
      }
      scratchOwned = true;

      // Real body: `v9 = lseeki64_nolock(...); *(&_pioinfo[fd>>5][1].osfhnd + v5) = v9;`
      // -- stores the pre-read position into the *next* slot's osfhnd field
      // (page base + one RuntimeIoInfo further + this slot's own byte
      // offset). Preserved verbatim; the intended field/purpose is not
      // independently confirmed (not exercised by any recovered caller --
      // UTF-8-mode reads never occur on a freshly _wsopen_nolock'd file).
      const __int64 preReadPosition = _lseeki64_nolock(fileDescriptor, 0, FILE_CURRENT);
      *reinterpret_cast<__int64*>(&(__pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F) + 1)->osfhnd) = preReadPosition;
    }

    char* writeCursor = scratch;
    unsigned int producedSoFar = 0;

    // Serve any pending pushback byte(s) (ungetc-style) before the real read.
    if ((slot->osfile & 0x48) != 0 && slot->pipech != 10 && readCapacity != 0) {
      *writeCursor++ = static_cast<char>(slot->pipech);
      --readCapacity;
      producedSoFar = 1;
      slot->pipech = 10;

      if (submode != 0 && slot->pipech2[0] != 10 && readCapacity != 0) {
        *writeCursor++ = static_cast<char>(slot->pipech2[0]);
        --readCapacity;
        producedSoFar = 2;
        slot->pipech2[0] = 10;

        if (submode == 1 && slot->pipech2[1] != 10 && readCapacity != 0) {
          *writeCursor++ = static_cast<char>(slot->pipech2[1]);
          --readCapacity;
          producedSoFar = 3;
          slot->pipech2[1] = 10;
        }
      }
    }

    DWORD bytesRead = 0;
    const BOOL readOk = ::ReadFile(reinterpret_cast<HANDLE>(slot->osfhnd), writeCursor, readCapacity, &bytesRead, nullptr);
    if (!readOk || (bytesRead & 0x80000000u) != 0 || bytesRead > readCapacity) {
      const DWORD lastError = ::GetLastError();
      const auto cleanup = [&]() {
        if (scratchOwned) {
          _free_crt(scratch);
        }
      };
      if (lastError == ERROR_ACCESS_DENIED) {
        *_errno() = EBADF;
        *RuntimeDosErrno() = ERROR_ACCESS_DENIED;
        cleanup();
        return static_cast<unsigned int>(-1);
      }
      if (lastError == ERROR_BROKEN_PIPE) {
        cleanup();
        return 0;
      }
      _dosmaperr(lastError);
      cleanup();
      return static_cast<unsigned int>(-1);
    }

    producedSoFar += bytesRead;
    unsigned int result = producedSoFar;
    bool forced = false;
    unsigned int forcedValue = 0;

    if (static_cast<std::int8_t>(slot->osfile) < 0) {
      if (submode != 2) {
        // ANSI (submode 0) or UTF-8 (submode 1): scan raw bytes, collapsing
        // "\r\n"->"\n" and stopping at a Ctrl-Z byte (unless the fd allows
        // literal Ctrl-Z passthrough, osfile&0x40).
        char* dst = scratch;
        const char* src = scratch;
        const char* const srcEnd = scratch + producedSoFar;
        bool sawEof = false;

        while (src < srcEnd) {
          const char ch = *src;
          if (ch == 0x1A) {
            if ((slot->osfile & 0x40) != 0) {
              *dst++ = *src;
            } else {
              slot->osfile |= 2;
            }
            sawEof = true;
            break;
          }
          if (ch == '\r') {
            if (src + 1 < srcEnd) {
              if (src[1] == '\n') {
                src += 2;
                *dst++ = '\n';
                continue;
              }
              ++src;
              *dst++ = '\r';
              continue;
            }
            // Trailing lone '\r' at the end of this chunk: peek one more
            // byte from the file to resolve whether it's really "\r\n".
            ++src;
            char peek = 0;
            DWORD peekRead = 0;
            if ((!::ReadFile(reinterpret_cast<HANDLE>(slot->osfhnd), &peek, 1u, &peekRead, nullptr) && ::GetLastError()) ||
                peekRead == 0)
            {
              *dst++ = '\r';
              continue;
            }
            if ((slot->osfile & 0x48) != 0) {
              if (peek != '\n') {
                *dst++ = '\r';
                slot->pipech = peek;
                continue;
              }
              *dst++ = '\n';
              continue;
            }
            if (dst == scratch && peek == '\n') {
              *dst++ = '\n';
              continue;
            }
            _lseeki64_nolock(fileDescriptor, -1, FILE_CURRENT);
            if (peek != '\n') {
              *dst++ = '\r';
            } else {
              *dst++ = '\n';
            }
            continue;
          }
          *dst++ = ch;
          ++src;
        }
        (void)sawEof;

        producedSoFar = static_cast<unsigned int>(dst - scratch);

        if (submode != 1 || dst == scratch) {
          result = producedSoFar;
        } else {
          // UTF-8 submode: re-decode the collapsed ANSI-shaped bytes as
          // UTF-8 into the caller's wide buffer, holding back a trailing
          // partial multibyte sequence for the next call's pushback slots.
          const unsigned char* tail = reinterpret_cast<unsigned char*>(dst) - 1;
          unsigned int decodeLen;
          if ((*tail & 0x80) != 0) {
            unsigned int trailingScanned = 1;
            while (g_mbcsTrailingByteCount[*tail] == 0 && trailingScanned <= 4 &&
                   reinterpret_cast<char*>(const_cast<unsigned char*>(tail)) >= scratch) {
              --tail;
              ++trailingScanned;
            }
            if (g_mbcsTrailingByteCount[*tail] == 0) {
              *_errno() = EILSEQ;
              forced = true;
              forcedValue = static_cast<unsigned int>(-1);
              decodeLen = 0;
            } else if (g_mbcsTrailingByteCount[*tail] + 1u == trailingScanned) {
              decodeLen = static_cast<unsigned int>(reinterpret_cast<char*>(const_cast<unsigned char*>(tail)) + trailingScanned - scratch);
            } else if ((slot->osfile & 0x48) != 0) {
              const unsigned char lead = *tail;
              const unsigned char* src2 = tail + 1;
              slot->pipech = static_cast<std::uint8_t>(lead);
              if (trailingScanned >= 2) {
                slot->pipech2[0] = *src2++;
              }
              if (trailingScanned == 3) {
                slot->pipech2[1] = *src2++;
              }
              decodeLen = static_cast<unsigned int>(reinterpret_cast<const char*>(src2) - trailingScanned - scratch);
            } else {
              _lseeki64_nolock(fileDescriptor, -static_cast<int>(trailingScanned), FILE_CURRENT);
              decodeLen = static_cast<unsigned int>(reinterpret_cast<char*>(const_cast<unsigned char*>(tail)) - scratch);
            }
          } else {
            decodeLen = static_cast<unsigned int>(reinterpret_cast<char*>(const_cast<unsigned char*>(tail)) + 1 - scratch);
          }

          if (!forced) {
            const int decodedChars = ::MultiByteToWideChar(
              CP_UTF8, 0, scratch, static_cast<int>(decodeLen), reinterpret_cast<LPWSTR>(lpBuffer),
              static_cast<int>(requestedSize >> 1)
            );
            if (decodedChars != 0) {
              // Real body stores a "wasn't an exact wchar-for-byte-run
              // decode" flag into the *next* slot's lockinitflag field
              // (same page-relative-plus-slot-offset shape as the
              // pre-read-position store above); not independently confirmed
              // and not reproduced here since it feeds no read caller yet.
              result = static_cast<unsigned int>(decodedChars) * 2u;
            } else {
              _dosmaperr(::GetLastError());
              forced = true;
              forcedValue = static_cast<unsigned int>(-1);
            }
          }
        }
      } else {
        // UTF-16 submode: identical "\r\n"->"\n" collapse on 16-bit units,
        // written directly into the caller's buffer (scratch == lpBuffer).
        auto* dst = reinterpret_cast<std::uint16_t*>(scratch);
        const auto* src = reinterpret_cast<std::uint16_t*>(scratch);
        const auto* const srcEnd = reinterpret_cast<std::uint16_t*>(scratch + producedSoFar);

        while (src < srcEnd) {
          const std::uint16_t ch = *src;
          if (ch == 0x1A) {
            if ((slot->osfile & 0x40) != 0) {
              *dst++ = *src;
            } else {
              slot->osfile |= 2;
            }
            break;
          }
          if (ch == static_cast<std::uint16_t>(L'\r')) {
            if (src + 1 < srcEnd) {
              if (src[1] == static_cast<std::uint16_t>(L'\n')) {
                src += 2;
                *dst++ = static_cast<std::uint16_t>(L'\n');
                continue;
              }
              ++src;
              *dst++ = static_cast<std::uint16_t>(L'\r');
              continue;
            }
            ++src;
            std::uint16_t peek = 0;
            DWORD peekRead = 0;
            if ((!::ReadFile(reinterpret_cast<HANDLE>(slot->osfhnd), &peek, 2u, &peekRead, nullptr) && ::GetLastError()) ||
                peekRead == 0)
            {
              *dst++ = static_cast<std::uint16_t>(L'\r');
              continue;
            }
            if ((slot->osfile & 0x48) != 0) {
              if (peek != static_cast<std::uint16_t>(L'\n')) {
                *dst++ = static_cast<std::uint16_t>(L'\r');
                slot->pipech = static_cast<std::uint8_t>(peek);
                slot->pipech2[0] = static_cast<std::uint8_t>(peek >> 8);
                slot->pipech2[1] = 10;
                continue;
              }
              *dst++ = static_cast<std::uint16_t>(L'\n');
              continue;
            }
            if (dst == reinterpret_cast<std::uint16_t*>(scratch) && peek == static_cast<std::uint16_t>(L'\n')) {
              *dst++ = static_cast<std::uint16_t>(L'\n');
              continue;
            }
            _lseeki64_nolock(fileDescriptor, -2, FILE_CURRENT);
            if (peek != static_cast<std::uint16_t>(L'\n')) {
              *dst++ = static_cast<std::uint16_t>(L'\r');
            } else {
              *dst++ = static_cast<std::uint16_t>(L'\n');
            }
            continue;
          }
          *dst++ = ch;
          ++src;
        }

        result = static_cast<unsigned int>(reinterpret_cast<char*>(dst) - scratch);
      }
    }

    if (scratchOwned) {
      _free_crt(scratch);
    }
    return forced ? forcedValue : result;
  }

  /**
   * Address: 0x00AB9517 (FUN_00AB9517, chsize_nolock / _chsize_nolock)
   *
   * What it does:
   * Resizes the file behind `fileDescriptor` to `size` bytes. Growing
   * zero-fills the new tail in 0x1000-byte chunks via `_write_nolock`
   * (temporarily forcing binary mode so no text-mode translation touches
   * the padding); shrinking seeks to `size` and calls `SetEndOfFile`.
   * Restores the original file position before returning.
   */
  extern "C" errno_t __cdecl _chsize_nolock(const int fileDescriptor, const __int64 size)
  {
    const __int64 originalPosition = _lseeki64_nolock(fileDescriptor, 0, FILE_CURRENT);
    if (originalPosition == -1) {
      return *_errno();
    }
    const __int64 currentSize = _lseeki64_nolock(fileDescriptor, 0, FILE_END);
    if (currentSize == -1) {
      return *_errno();
    }

    errno_t result = 0;

    if (size > currentSize) {
      const HANDLE processHeap = ::GetProcessHeap();
      auto* const zeroBuffer = static_cast<char*>(::HeapAlloc(processHeap, HEAP_ZERO_MEMORY, 0x1000u));
      if (zeroBuffer == nullptr) {
        *_errno() = ENOMEM;
        return *_errno();
      }

      const int previousMode = _setmode_nolock(fileDescriptor, kOModeBinary);
      __int64 remaining = size - currentSize;
      bool failed = false;
      while (remaining > 0) {
        const unsigned int chunkSize = remaining < 0x1000 ? static_cast<unsigned int>(remaining) : 0x1000u;
        const int written = _write_nolock(fileDescriptor, zeroBuffer, chunkSize);
        if (written == -1) {
          failed = true;
          break;
        }
        remaining -= written;
      }
      _setmode_nolock(fileDescriptor, previousMode);
      ::HeapFree(processHeap, 0, zeroBuffer);

      if (failed) {
        if (*RuntimeDosErrno() == ERROR_ACCESS_DENIED) {
          *_errno() = EACCES;
        }
        result = *_errno();
      }
    } else if (size < currentSize) {
      if (_lseeki64_nolock(fileDescriptor, size, FILE_BEGIN) == -1) {
        return *_errno();
      }
      if (!::SetEndOfFile(RuntimeGetOsfHandle(fileDescriptor))) {
        *_errno() = EACCES;
        *RuntimeDosErrno() = ::GetLastError();
        result = *_errno();
      }
    }

    if (result == 0) {
      if (_lseeki64_nolock(fileDescriptor, originalPosition, FILE_BEGIN) == -1) {
        return *_errno();
      }
    }
    return result;
  }

  /**
   * Address: 0x00AAF7B4 (FUN_00AAF7B4, _wsopen_nolock)
   *
   * What it does:
   * MSVC CRT wide-path file-open worker (the body `_wsopen_helper` forwards
   * to). Decodes the `_O_*` open-flag bitmask into Win32
   * access/share/creation-disposition/flags-and-attributes, allocates a
   * descriptor slot, calls `CreateFileW` (retrying write-only if a
   * read+write open against read-only media fails), classifies the handle
   * via `GetFileType`. For a regular disk file opened with `_O_RDWR` in
   * text mode, peeks the trailing byte and truncates a lone Ctrl-Z. For a
   * text-mode open with `_O_WTEXT`/`_O_U16TEXT`/`_O_U8TEXT`, sniffs (and,
   * for a fresh/truncated/write-only file, writes) the UTF-16LE or UTF-8
   * byte-order mark. Finally re-opens as a plain `OPEN_EXISTING` handle
   * when the original access combined `GENERIC_READ|GENERIC_WRITE` with
   * `_O_WRONLY`.
   */
  extern "C" int __cdecl _wsopen_nolock(
    int* const outFileHandle,
    int* const unlockFlag,
    const wchar_t* const lpFileName,
    const int openFlags,
    const int shareFlags,
    const int permissionFlags
  )
  {
    int defaultFileMode = 0;
    unsigned int osPlatform = 0;
    if (_get_fmode(&defaultFileMode) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }
    if (_get_osplatform(&osPlatform) != 0) {
      _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    }

    SECURITY_ATTRIBUTES securityAttributes;
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.lpSecurityDescriptor = nullptr;
    securityAttributes.bInheritHandle = (openFlags & kOFlagNoinherit) == 0 ? TRUE : FALSE;

    std::uint8_t pendingOsfileFlags = ((openFlags & kOFlagNoinherit) != 0) ? 0x10 : 0;
    if ((openFlags & 0x8000 /* _O_BINARY */) == 0 &&
        ((openFlags & 0x74000 /* _O_WTEXT|_O_U16TEXT|_O_U8TEXT|_O_TEXT */) != 0 || defaultFileMode != 0x8000))
    {
      pendingOsfileFlags |= 0x80;
    }

    auto invalidArgument = [&]() -> int {
      *RuntimeDosErrno() = 0;
      *outFileHandle = -1;
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    };

    DWORD dwDesiredAccess;
    if ((openFlags & 3) != 0) {
      if ((openFlags & 3) == kOFlagWronly) {
        if ((openFlags & kOFlagAppend) != 0 && (openFlags & 0x70000) != 0) {
          dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
        } else {
          dwDesiredAccess = GENERIC_WRITE;
        }
      } else if ((openFlags & 3) == kOFlagRdwr) {
        dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
      } else {
        return invalidArgument();
      }
    } else {
      dwDesiredAccess = GENERIC_READ;
    }

    DWORD dwShareMode;
    switch (shareFlags) {
      case 16: dwShareMode = 0; break;
      case 32: dwShareMode = FILE_SHARE_READ; break;
      case 48: dwShareMode = FILE_SHARE_WRITE; break;
      case 64: dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE; break;
      case 128: dwShareMode = (dwDesiredAccess == GENERIC_READ) ? FILE_SHARE_READ : 0; break;
      default: return invalidArgument();
    }

    DWORD dwCreationDisposition;
    const int creationBits = openFlags & 0x700;
    if (creationBits > 0x400) {
      if (creationBits == 0x500) {
        dwCreationDisposition = CREATE_NEW;
      } else if (creationBits == 0x600) {
        dwCreationDisposition = TRUNCATE_EXISTING;
      } else if (creationBits == 0x700) {
        dwCreationDisposition = CREATE_NEW;
      } else {
        return invalidArgument();
      }
    } else if (creationBits == 0x400 || creationBits == 0) {
      dwCreationDisposition = OPEN_EXISTING;
    } else if (creationBits == 0x100 /* kOFlagCreat alone */) {
      dwCreationDisposition = OPEN_ALWAYS;
    } else if (creationBits == 0x200 /* kOFlagTrunc alone */) {
      dwCreationDisposition = TRUNCATE_EXISTING;
    } else if (creationBits == 0x300 /* CREAT|TRUNC */) {
      dwCreationDisposition = CREATE_ALWAYS;
    } else {
      return invalidArgument();
    }

    DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    if ((openFlags & kOFlagCreat) != 0 && (permissionFlags & ~umaskval & 0x80) == 0) {
      dwFlagsAndAttributes = FILE_ATTRIBUTE_READONLY;
    }
    if ((openFlags & kOFlagTemporary) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_DELETE_ON_CLOSE;
      dwDesiredAccess |= DELETE;
      if (osPlatform == 2 /* VER_PLATFORM_WIN32_NT */) {
        dwShareMode |= FILE_SHARE_DELETE;
      }
    }
    if ((openFlags & kOFlagShortLived) != 0) {
      dwFlagsAndAttributes |= FILE_ATTRIBUTE_TEMPORARY;
    }
    if ((openFlags & kOFlagSequential) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_SEQUENTIAL_SCAN;
    } else if ((openFlags & kOFlagRandom) != 0) {
      dwFlagsAndAttributes |= FILE_FLAG_RANDOM_ACCESS;
    }

    const int newDescriptor = _alloc_osfhnd();
    *outFileHandle = newDescriptor;
    if (newDescriptor == -1) {
      *RuntimeDosErrno() = 0;
      *outFileHandle = -1;
      *_errno() = EMFILE;
      return *_errno();
    }

    *unlockFlag = 1;
    RuntimeIoInfo* const slot = __pioinfo[newDescriptor >> 5] + (newDescriptor & 0x1F);

    HANDLE hFile = ::CreateFileW(
      lpFileName, dwDesiredAccess, dwShareMode, &securityAttributes, dwCreationDisposition, dwFlagsAndAttributes, nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) {
      bool retryOk = false;
      if ((dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE) &&
          (openFlags & 1) != 0)
      {
        dwDesiredAccess &= ~GENERIC_READ;
        hFile = ::CreateFileW(
          lpFileName, dwDesiredAccess, dwShareMode, &securityAttributes, dwCreationDisposition, dwFlagsAndAttributes, nullptr
        );
        retryOk = (hFile != INVALID_HANDLE_VALUE);
      }
      if (!retryOk) {
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        _dosmaperr(::GetLastError());
        return *_errno();
      }
    }

    switch (::GetFileType(hFile)) {
      case FILE_TYPE_UNKNOWN: {
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        const DWORD lastError = ::GetLastError();
        _dosmaperr(lastError);
        ::CloseHandle(hFile);
        if (lastError == 0) {
          *_errno() = EACCES;
        }
        return *_errno();
      }
      case FILE_TYPE_CHAR: pendingOsfileFlags |= 0x40; break;
      case FILE_TYPE_PIPE: pendingOsfileFlags |= 0x08; break;
      default: break;
    }

    _set_osfhnd(newDescriptor, reinterpret_cast<std::intptr_t>(hFile));
    pendingOsfileFlags |= 0x01;
    slot->osfile = pendingOsfileFlags;
    slot->textmodeUnicode &= static_cast<std::int8_t>(0x80);
    const std::uint8_t wasPipeOrChar = pendingOsfileFlags & 0x48;

    if (wasPipeOrChar == 0 && static_cast<std::int8_t>(pendingOsfileFlags) < 0 && (openFlags & kOFlagRdwr) != 0) {
      // Regular disk file, text mode, opened for read+write: peek the
      // trailing byte and truncate a lone Ctrl-Z (real _wsopen_nolock
      // behavior for text-mode read+write opens).
      const long tailPos = _lseek_nolock(newDescriptor, -1, FILE_END);
      if (tailPos == -1) {
        if (*RuntimeDosErrno() != 131 /* ERROR_NEGATIVE_SEEK: empty file, nothing to truncate */) {
          _close_nolock(newDescriptor);
          return *_errno();
        }
      } else {
        char tailByte = 0;
        const unsigned int readResult = _read_nolock(newDescriptor, &tailByte, 1u);
        const bool isTrailingCtrlZ = (readResult == 0 && tailByte == 0x1A);
        if ((isTrailingCtrlZ && _chsize_nolock(newDescriptor, tailPos) == -1) ||
            _lseek_nolock(newDescriptor, 0, FILE_BEGIN) == -1)
        {
          _close_nolock(newDescriptor);
          return *_errno();
        }
      }
    }

    int bomSubmode = 0; // 0 = none, 1 = UTF-8, 2 = UTF-16LE
    if (static_cast<std::int8_t>(pendingOsfileFlags) < 0) {
      int effectiveFlags = openFlags;
      if ((effectiveFlags & 0x74000) == 0) {
        if ((defaultFileMode & 0x74000) != 0) {
          effectiveFlags |= (defaultFileMode & 0x74000);
        } else {
          effectiveFlags |= 0x4000 /* _O_TEXT */;
        }
      }
      const int textKind = effectiveFlags & 0x74000;

      bool wantsBomLogic = false;
      if (textKind == 0x4000 /* plain _O_TEXT */) {
        bomSubmode = 0;
      } else if (textKind == kOFlagWText || textKind == (kOFlagWText | 0x4000)) {
        wantsBomLogic = (effectiveFlags & 0x301) == 0x301;
      } else if (textKind == kOFlagU16Text || textKind == (kOFlagU16Text | 0x4000)) {
        bomSubmode = 2;
        wantsBomLogic = true;
      } else if (textKind == kOFlagU8Text || textKind == (kOFlagU8Text | 0x4000)) {
        bomSubmode = 1;
        wantsBomLogic = true;
      }

      if (wantsBomLogic && (effectiveFlags & 0x70000) != 0 && (pendingOsfileFlags & 0x40) == 0) {
        bool shouldWriteBom = false;
        bool aborted = false;
        bool bailedOut = false;

        // Peeks up to 3 bytes for a UTF-8/UTF-16LE BOM, consuming it (and
        // setting bomSubmode) on a match, or rewinding to the start
        // otherwise. Shared by the read-only path and the read+write
        // OPEN_ALWAYS-existing-content path.
        const auto sniffBom = [&]() -> bool {
          unsigned char bomBytes[3] = {};
          const unsigned int peeked = _read_nolock(newDescriptor, reinterpret_cast<char*>(bomBytes), 3u);
          if (peeked == static_cast<unsigned int>(-1)) {
            _close_nolock(newDescriptor);
            return false;
          }
          bool rewind = true;
          if (peeked == 3 &&
              (static_cast<unsigned int>(bomBytes[0]) | (static_cast<unsigned int>(bomBytes[1]) << 8) |
               (static_cast<unsigned int>(bomBytes[2]) << 16)) == static_cast<unsigned int>(kUtf8Bom))
          {
            bomSubmode = 1;
            rewind = false;
          } else if (peeked >= 2) {
            const std::uint16_t leading16 =
              static_cast<std::uint16_t>(bomBytes[0]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(bomBytes[1]) << 8);
            if (leading16 == kUtf16ReversedBom) {
              _close_nolock(newDescriptor);
              *_errno() = EINVAL;
              return false;
            }
            if (leading16 == kUtf16LeBom) {
              if (_lseek_nolock(newDescriptor, 2, FILE_BEGIN) == -1) {
                _close_nolock(newDescriptor);
                return false;
              }
              bomSubmode = 2;
              rewind = false;
            }
          }
          if (rewind && _lseek_nolock(newDescriptor, 0, FILE_BEGIN) == -1) {
            _close_nolock(newDescriptor);
            return false;
          }
          return true;
        };

        const DWORD accessKind = dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE);
        if (accessKind == GENERIC_WRITE) {
          if (dwCreationDisposition == CREATE_NEW || dwCreationDisposition == CREATE_ALWAYS) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == OPEN_ALWAYS) {
            if (_lseeki64_nolock(newDescriptor, 0, FILE_END) != 0) {
              _lseeki64_nolock(newDescriptor, 0, FILE_BEGIN);
              // File already had content: nothing to sniff or write for a
              // write-only handle -- leave bomSubmode as detected above.
            } else {
              shouldWriteBom = true;
            }
          } else if (dwCreationDisposition == TRUNCATE_EXISTING) {
            shouldWriteBom = true;
          }
        } else if (accessKind == GENERIC_READ) {
          bailedOut = !sniffBom();
        } else if (accessKind == (GENERIC_READ | GENERIC_WRITE)) {
          if (dwCreationDisposition == 0) {
            // nothing to do
          } else if (dwCreationDisposition == CREATE_NEW || dwCreationDisposition == CREATE_ALWAYS) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == TRUNCATE_EXISTING) {
            shouldWriteBom = true;
          } else if (dwCreationDisposition == OPEN_ALWAYS) {
            if (_lseeki64_nolock(newDescriptor, 0, FILE_END) == 0) {
              shouldWriteBom = true;
            } else {
              const __int64 rewound = _lseeki64_nolock(newDescriptor, 0, FILE_BEGIN);
              if (rewound == -1) {
                _close_nolock(newDescriptor);
                return *_errno();
              }
              bailedOut = !sniffBom();
            }
          }
        } else {
          aborted = true;
        }

        if (bailedOut) {
          return *_errno();
        }

        if (!aborted && shouldWriteBom) {
          unsigned char bomToWrite[3] = {};
          int bomLength = 0;
          if (bomSubmode == 1) {
            bomToWrite[0] = 0xEF; bomToWrite[1] = 0xBB; bomToWrite[2] = 0xBF;
            bomLength = 3;
          } else if (bomSubmode == 2) {
            bomToWrite[0] = 0xFF; bomToWrite[1] = 0xFE;
            bomLength = 2;
          }
          if (bomLength != 0) {
            int written = 0;
            while (written < bomLength) {
              const int chunk = _write(newDescriptor, bomToWrite + written, static_cast<unsigned int>(bomLength - written));
              if (chunk == -1) {
                _close_nolock(newDescriptor);
                return *_errno();
              }
              written += chunk;
            }
          }
        }
      }
    }

    slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & ~0x7F) | (bomSubmode & 0x7F));
    slot->textmodeUnicode = static_cast<std::int8_t>((slot->textmodeUnicode & 0x7F) | (((openFlags >> 16) & 1) << 7));
    if (wasPipeOrChar == 0 && (openFlags & kOFlagAppend) != 0) {
      slot->osfile |= 0x20;
    }

    if ((dwDesiredAccess & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE) && (openFlags & 1) != 0) {
      ::CloseHandle(hFile);
      hFile = ::CreateFileW(
        lpFileName, dwDesiredAccess & 0x7FFFFFFFu, dwShareMode, &securityAttributes, OPEN_EXISTING, dwFlagsAndAttributes, nullptr
      );
      if (hFile == INVALID_HANDLE_VALUE) {
        _dosmaperr(::GetLastError());
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
        _free_osfhnd(newDescriptor);
        return *_errno();
      }
      slot->osfhnd = reinterpret_cast<std::intptr_t>(hFile);
    }

    return 0;
  }

  /**
   * Address: 0x00AAFFC4 (FUN_00AAFFC4, _wsopen_s / _wsopen_helper)
   *
   * What it does:
   * MSVC CRT wide-path open helper. Validates that the out-fd pointer and the
   * path are non-null, that the `secureMode` flag is only combined with the
   * secure subset of open flags, and that the `open-flag` bitmask excludes
   * reserved bits when secure. On argument violation, sets `EINVAL`, calls
   * `_invalid_parameter`, and returns `EINVAL` (`22`). Otherwise dispatches to
   * `_wsopen_nolock`; on failure it clears the "in use" bit in `_pioinfo` for
   * the freshly-allocated slot and releases the per-handle lock so the
   * descriptor is not leaked, then resets `*outFileHandle` to `-1`.
   *
   * IDA signature:
   * int __cdecl sub_AAFFC4(LPCWSTR lpFileName, int a2, int a3, int a4, int *a5, int a6);
   */
  extern "C" int __cdecl RuntimeWideSopenHelper(
    const wchar_t* const lpFileName,
    const int openFlags,
    const int shareFlags,
    const int permissionFlags,
    int* const outFileHandle,
    const int secureMode
  )
  {
    constexpr int kReservedFlagsWhenSecure = static_cast<int>(0xFFFFFE7FL);

    if (outFileHandle == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *outFileHandle = -1;

    if (lpFileName == nullptr ||
        (secureMode != 0 && (permissionFlags & kReservedFlagsWhenSecure) != 0))
    {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    // Forwards to the CRT `_wsopen_nolock` worker (IDA `sub_AAF7B4`), which
    // returns the errno-valued status and sets `*unlockNeeded` when the
    // caller must release the per-fd lock on exit (mirrors `_open`'s
    // `_tsopen_nolock`/`shouldUnlockHandle` pattern above).
    int unlockNeeded = 0;
    const int openStatus = _wsopen_nolock(outFileHandle, &unlockNeeded, lpFileName, openFlags, shareFlags, permissionFlags);

    if (unlockNeeded != 0) {
      if (openStatus != 0) {
        RuntimeIoInfo* const slot = __pioinfo[*outFileHandle >> 5] + (*outFileHandle & 0x1F);
        slot->osfile &= static_cast<std::uint8_t>(~0x01u);
      }
      _unlock_fhandle(*outFileHandle);
    }

    if (openStatus != 0) {
      *outFileHandle = -1;
    }

    return openStatus;
  }

  /**
   * Address: 0x00AA51C6 (FUN_00AA51C6, _open)
   *
   * What it does:
   * Opens one narrow path by forwarding to `_tsopen_nolock` with default
   * sharing (`_SH_DENYNO`), then preserves CRT handle-lock cleanup and errno
   * propagation semantics.
   */
  extern "C" int __cdecl _open(
    const char* const fileName,
    const int openFlags,
    const int permissionFlags
  )
  {
    int fileDescriptor = -1;
    int shouldUnlockHandle = 0;

    if (fileName == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    const int openResult = _tsopen_nolock(
      &fileDescriptor,
      &shouldUnlockHandle,
      fileName,
      openFlags,
      64,
      permissionFlags
    );

    if (shouldUnlockHandle != 0) {
      if (openResult != 0) {
        RuntimeIoInfo* const ioInfo = __pioinfo[fileDescriptor >> 5] + (fileDescriptor & 0x1F);
        ioInfo->osfile &= static_cast<std::uint8_t>(~0x01u);
      }
      _unlock_fhandle(fileDescriptor);
    }

    if (openResult != 0) {
      *_errno() = openResult;
      return -1;
    }

    return fileDescriptor;
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

  /**
   * Address: 0x00A88F68 (FUN_00A88F68)
   *
   * What it does:
   * Secure wide-open wrapper: validates output pointer, opens with secure
   * share mode (`0x80`) through `_wfsopen`, stores the stream pointer, and
   * returns either `0` or the current `errno` lane.
   */
  extern "C" int __cdecl _wfopen_s(
    std::FILE** const outStream,
    const wchar_t* const filePath,
    const wchar_t* const mode
  )
  {
    if (outStream == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::FILE* const stream = RuntimeWfsopen(filePath, mode, 0x80);
    *outStream = stream;
    if (stream != nullptr) {
      return 0;
    }

    return *_errno();
  }

  /**
   * Address: 0x00A88F55 (FUN_00A88F55, wfopen)
   *
   * What it does:
   * Opens one wide-character file path with default CRT share mode `0x40`
   * by forwarding to the recovered `_wfsopen` lane.
   */
  extern "C" std::FILE* __cdecl wfopen(const wchar_t* const filePath, const wchar_t* const mode)
  {
    return RuntimeWfsopen(filePath, mode, 0x40);
  }

  [[noreturn]] void RuntimeTerminate();

  /**
   * Address: 0x00A99357 (FUN_00A99357, _imp___CrtSetCheckCount)
   *
   * What it does:
   * Returns the `_CrtSetCheckCount` routine lane address used by CRT startup
   * import indirection.
   */
  extern "C" void* __cdecl _imp___CrtSetCheckCount()
  {
    return reinterpret_cast<void*>(static_cast<void (__cdecl*)()>(&_CrtSetCheckCount));
  }

  /**
   * Address: 0x00A9937B (FUN_00A9937B, _RTC_Terminate)
   *
   * What it does:
   * Preserves the CRT runtime-check terminate hook lane as a no-op.
   */
  extern "C" void __cdecl _RTC_Terminate()
  {}

  /**
   * Address: 0x00A9939F (FUN_00A9939F, __initp_misc_cfltcvt_tab)
   *
   * What it does:
   * Encodes the 10-entry CRT floating-conversion callback lane table in place
   * and returns the final encoded entry lane.
   */
  extern "C" void* __cdecl __initp_misc_cfltcvt_tab()
  {
    void* encodedEntry = nullptr;
    for (void*& entry : gRuntimeCfltCvtTable) {
      encodedEntry = ::EncodePointer(entry);
      entry = encodedEntry;
    }
    return encodedEntry;
  }

  /**
   * Address: 0x00A9957E (FUN_00A9957E, _initp_eh_hooks)
   *
   * What it does:
   * Encodes the runtime terminate lane and publishes it into the CRT
   * terminate-action slot used by EH hook dispatch.
   */
  extern "C" void* __cdecl _initp_eh_hooks()
  {
    gRuntimeTerminateActionEncoded = ::EncodePointer(reinterpret_cast<void*>(static_cast<void (*)()>(&RuntimeTerminate)));
    return gRuntimeTerminateActionEncoded;
  }

  /**
   * Address: 0x00A99823 (FUN_00A99823, __get_sigabrt)
   *
   * What it does:
   * Decodes and returns the active SIGABRT action handler lane.
   */
  extern "C" RuntimeSignalHandler __cdecl __get_sigabrt()
  {
    return reinterpret_cast<RuntimeSignalHandler>(_decode_pointer(gRuntimeAbortActionEncoded));
  }

  /**
   * Address: 0x00A8ED3D (FUN_00A8ED3D, _check_managed_app)
   *
   * What it does:
   * Validates DOS/NT/PE32 headers at image base `0x400000` and reports true
   * only when the COM descriptor data-directory entry is present/non-zero.
   */
  extern "C" BOOL __cdecl _check_managed_app()
  {
    constexpr std::uintptr_t kRuntimeModuleImageBase = 0x00400000u;
    const auto* const imageBase = reinterpret_cast<const std::uint8_t*>(kRuntimeModuleImageBase);
    const auto* const dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      return FALSE;
    }

    const auto* const ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
      return FALSE;
    }

    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      return FALSE;
    }

    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
      return FALSE;
    }

    const IMAGE_DATA_DIRECTORY& comDescriptorDirectory =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    return comDescriptorDirectory.VirtualAddress != 0u ? TRUE : FALSE;
  }

  /**
   * Address: 0x00A9973B (FUN_00A9973B, _initp_misc_winsig)
   *
   * What it does:
   * Seeds Ctrl-C/Ctrl-Break/SIGABRT/SIGTERM action slots with one shared
   * caller-provided handler lane value.
   */
  extern "C" void __cdecl _initp_misc_winsig(void* const encodedHandler)
  {
    gRuntimeCtrlCActionEncoded = encodedHandler;
    gRuntimeCtrlBreakActionEncoded = encodedHandler;
    gRuntimeAbortActionEncoded = encodedHandler;
    gRuntimeTermActionEncoded = encodedHandler;
  }

  /**
   * Address: 0x00A99C2F (FUN_00A99C2F, _initp_misc_rrand_s)
   *
   * What it does:
   * Publishes the startup `rand_s` import lane pointer and returns the same
   * raw lane value.
   */
  extern "C" std::int32_t __cdecl _initp_misc_rrand_s(const std::int32_t importLaneAddress)
  {
    gRuntimeRandomSImportAddress = importLaneAddress;
    return importLaneAddress;
  }

  /**
   * Address: 0x00A99C39 (FUN_00A99C39, rand_s)
   *
   * What it does:
   * Resolves and caches the `SystemFunction036` (`RtlGenRandom`) lane, fills
   * one caller `uint32` output, and mirrors CRT invalid-parameter/errno
   * semantics on failure.
   */
  extern "C" int __cdecl rand_s(unsigned int* const randomValueOut)
  {
    using RuntimeRtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);

    if (randomValueOut == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *randomValueOut = 0u;

    RuntimeRtlGenRandomFn randomFn = reinterpret_cast<RuntimeRtlGenRandomFn>(
      _decode_pointer(reinterpret_cast<void*>(static_cast<std::uintptr_t>(gRuntimeRandomSImportAddress)))
    );

    if (randomFn == nullptr) {
      HMODULE const advapi32Module = ::LoadLibraryA("ADVAPI32.DLL");
      if (advapi32Module == nullptr) {
        const int mappedErrno = get_errno_from_oserr(::GetLastError());
        *_errno() = mappedErrno;
        return mappedErrno;
      }

      FARPROC const proc = ::GetProcAddress(advapi32Module, "SystemFunction036");
      if (proc == nullptr) {
        const int mappedErrno = get_errno_from_oserr(::GetLastError());
        *_errno() = mappedErrno;
        return mappedErrno;
      }

      randomFn = reinterpret_cast<RuntimeRtlGenRandomFn>(proc);
      gRuntimeRandomSImportAddress =
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(::EncodePointer(reinterpret_cast<void*>(randomFn))));
    }

    if (randomFn(randomValueOut, static_cast<ULONG>(sizeof(*randomValueOut))) == FALSE) {
      const int mappedErrno = get_errno_from_oserr(::GetLastError());
      *_errno() = mappedErrno;
      return mappedErrno;
    }

    return 0;
  }

  /**
   * Address: 0x00A99D3D (FUN_00A99D3D, _initp_misc_initcrit)
   *
   * What it does:
   * Publishes the startup critical-section init callback lane used by
   * `_mtinitlocks`.
   */
  extern "C" void __cdecl _initp_misc_initcrit(void* const initCritSecAndSpinCountLane)
  {
    gRuntimeInitCritSecAndSpinCount =
      reinterpret_cast<RuntimeInitCritSecAndSpinCountFn>(initCritSecAndSpinCountLane);
  }

  /**
   * Address: 0x00A99D47 (FUN_00A99D47, crtInitCritSecNoSpinCount@8)
   *
   * What it does:
   * Initializes one critical section and reports success, ignoring the
   * optional spin-count lane.
   */
  extern "C" int __stdcall crtInitCritSecNoSpinCount(
    LPCRITICAL_SECTION const criticalSection,
    const int spinCount
  )
  {
    (void)spinCount;
    ::InitializeCriticalSection(criticalSection);
    return 1;
  }

  /**
   * Address: 0x00A848DE (FUN_00A848DE, _initp_misc_invarg)
   *
   * What it does:
   * Publishes the CRT invalid-parameter handler pointer lane and returns the
   * installed handler.
   */
  extern "C" RuntimeInvalidArgHandler __cdecl _initp_misc_invarg(
    RuntimeInvalidArgHandler const handler
  )
  {
    gRuntimeInvalidArgHandler = handler;
    return handler;
  }

  /**
   * Address: 0x00A96A0B (FUN_00A96A0B, _initp_misc_purevirt)
   *
   * What it does:
   * Publishes the CRT pure-virtual-call handler lane and returns the handler.
   */
  extern "C" RuntimePurecallHandler __cdecl _initp_misc_purevirt(
    RuntimePurecallHandler const handler
  )
  {
    gRuntimePurecallHandler = handler;
    return handler;
  }

  /**
   * Address: 0x00A82571 (FUN_00A82571, _set_purecall_handler)
   *
   * What it does:
   * Atomically swaps the encoded CRT purecall-handler lane and returns the
   * previously installed decoded handler pointer.
   */
  extern "C" RuntimePurecallHandler __cdecl _set_purecall_handler(
    RuntimePurecallHandler const handler
  )
  {
    const auto previousHandler = reinterpret_cast<RuntimePurecallHandler>(
      _decode_pointer(gRuntimePurecallHandlerEncoded)
    );
    gRuntimePurecallHandlerEncoded = ::EncodePointer(reinterpret_cast<void*>(handler));
    gRuntimePurecallHandler = handler;
    return previousHandler;
  }

  /**
   * Address: 0x00A82593 (FUN_00A82593, _get_purecall_handler)
   *
   * What it does:
   * Returns the decoded CRT purecall-handler lane currently stored in the
   * encoded purecall handler slot.
   */
  extern "C" RuntimePurecallHandler __cdecl _get_purecall_handler()
  {
    return reinterpret_cast<RuntimePurecallHandler>(
      _decode_pointer(gRuntimePurecallHandlerEncoded)
    );
  }

  /**
   * Address: 0x00A96A15 (FUN_00A96A15, _initp_heap_handler)
   *
   * What it does:
   * Publishes the CRT heap-allocation failure handler pointer lane.
   */
  extern "C" void __cdecl _initp_heap_handler(RuntimeHeapFailureHandler const handler)
  {
    gRuntimeHeapFailureHandlerEncoded = std::bit_cast<void*>(handler);
  }

  /**
   * Address: 0x00A96A59 (FUN_00A96A59, _query_new_handler)
   *
   * What it does:
   * Returns the decoded CRT heap-allocation failure handler lane.
   */
  extern "C" RuntimeHeapFailureHandler __cdecl _query_new_handler()
  {
    return std::bit_cast<RuntimeHeapFailureHandler>(_decode_pointer(gRuntimeHeapFailureHandlerEncoded));
  }

  /**
   * Address: 0x00A96A50 (FUN_00A96A50)
   *
   * What it does:
   * Clears the active CRT heap-failure handler lane and returns the previously
   * installed handler.
   */
  extern "C" RuntimeHeapFailureHandler __cdecl RuntimeClearNewHandler()
  {
    RuntimeLockGuard heapLock(kRuntimeHeapLock);
    const RuntimeHeapFailureHandler previousHandler = _query_new_handler();
    _initp_heap_handler(nullptr);
    return previousHandler;
  }

  /**
   * Address: 0x00AC06EE (FUN_00AC06EE, _Once)
   *
   * What it does:
   * Publishes one three-state once-control lane (`0 -> 1 -> 2`) and runs the
   * initializer callback exactly once while waiters spin/sleep until done.
   */
  extern "C" void __cdecl Once(volatile LONG* const control, void (__cdecl* const initializer)())
  {
    constexpr LONG kOncePending = 0;
    constexpr LONG kOnceRunning = 1;
    constexpr LONG kOnceDone = 2;

    if (*control == kOnceDone) {
      return;
    }

    const LONG previousState = ::InterlockedExchange(control, kOnceRunning);
    if (previousState == kOncePending) {
      initializer();
      *control = kOnceDone;
      return;
    }

    if (previousState == kOnceDone) {
      *control = kOnceDone;
      return;
    }

    while (*control != kOnceDone) {
      ::Sleep(1u);
    }
  }

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

  // Mirrors `` `std::basic_filebuf<char>::_Init'::`2'::_Stinit`` (.data, 0x010C6BB4).
  // Confirmed via data_refs: FUN_004C5430 (`_Init`) reads this exact address into a
  // freshly bound filebuf's stateWord (+0x44), and FUN_004C55A0 (`close`, see
  // RuntimeFilebufClose below) writes this exact address back into stateWord when
  // releasing the file - same global, read on init, restored on close.
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

  /**
   * Address: 0x004C5430 (FUN_004C5430, std::basic_filebuf<char>::_Init)
   *
   * IDA signature:
   * void __thiscall std::basic_filebuf::_Init(std::filebuf *this, int a2);
   *
   * What it does:
   * Binds one filebuf to a `FILE`. The streambuf lanes are not given their own
   * buffer - they are pointed straight at the FILE's internal cursor fields, so
   * the two stay in sync with no copying: `_ptr` at +0x00 feeds both I/O
   * pointers, `_cnt` at +0x04 both counts, and `_base` at +0x08 both bases.
   *
   * A null FILE leaves the lanes as `_Init` on the streambuf base left them
   * (all null) and only the scalar state is written.
   */
  void RuntimeFilebufInit(RuntimeFilebufCharView* const filebuf, std::FILE* const file)
  {
    filebuf->closeOnClose = 0;
    filebuf->wroteSome = 0;
    RuntimeFilebufResetIoLanes(filebuf);

    if (file != nullptr) {
      LegacyFileView& legacy = legacy_file(file);
      filebuf->inputBase = &legacy._base;
      filebuf->outputBase = &legacy._base;
      filebuf->inputPtr = &legacy._ptr;
      filebuf->outputPtr = &legacy._ptr;
      filebuf->inputCount = &legacy._cnt;
      filebuf->outputCount = &legacy._cnt;
    }

    filebuf->myFile = file;
    filebuf->stateWord = gRuntimeFilebufInitialStateWord;
    filebuf->codecvtFacet = nullptr;
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
   * Address: 0x004C5640 (FUN_004C5640, std::basic_filebuf<char>::_Endwrite)
   *
   * IDA signature:
   * char __thiscall std::filebuf::_Endwrite(void *this);
   *
   * What it does:
   * Flushes a pending codecvt shift-state reset before the filebuf goes
   * idle. In the original binary this is called from `close()` (see
   * RuntimeFilebufClose below), `seekoff()`, and `seekpos()` - anywhere a
   * write sequence through a stateful encoding needs to leave the output
   * in the "initial shift state" before repositioning or closing.
   *
   * Early-out true when there is no attached codecvt facet (+0x3C) or when
   * `wroteSome` (+0x41) is already clear: nothing was written through a
   * stateful encoding, so there is nothing to unshift. Otherwise it flushes
   * the pending put area via `overflow(EOF)` (dispatch slot +0x04) and, on
   * success, loops calling the facet's `unshift()` - the public wrapper the
   * binary calls indirectly through the codecvt vtable at +24 bytes, i.e.
   * `do_unshift` - into a growable scratch buffer, `fwrite`-ing whatever
   * `unshift` produced on each pass:
   *   - `error`   -> stop, report failure.
   *   - `noconv`  -> stop, report success; nothing was ever pending.
   *   - `ok`      -> clears `wroteSome`, then falls into the shared tail
   *                  below; since `wroteSome` is now false the tail always
   *                  returns success after at most one more `fwrite`.
   *   - `partial` -> falls into the same shared tail with `wroteSome`
   *                  still set. If this call produced zero bytes the
   *                  scratch buffer was too small to make progress, so it
   *                  is grown by 8 bytes and the facet is called again
   *                  with the same (persisted) shift state; if it produced
   *                  bytes but is still not done, the buffer is reused as
   *                  is for another round.
   * This shape matches the published Dinkumware `<fstream>` `_Endwrite`
   * algorithm for this era (see CLAUDE.md's CRT/STL reference-source
   * convention) - error/noconv exit immediately, ok/partial share a
   * flush-then-check-`wroteSome` tail, and only a partial-with-zero-progress
   * result grows the buffer.
   *
   * The scratch buffer is a real `std::string` used purely as byte storage
   * (mirrors the binary's SSO-buffer growth via `append`, without modelling
   * its raw `_Bxty`/`_Mysize`/`_Myres` internals). The unshift state is a
   * function-local `std::mbstate_t` rather than an alias of `stateWord`
   * (+0x44) directly: the original VC8 ABI's `mbstate_t` was a 4-byte `int`
   * and fit that field exactly (matches `close()` restoring it from a
   * single-DWORD `_Stinit` global), but `codecvtFacet` here is typed as the
   * real, modern `std::codecvt<char,char,mbstate_t>` and its `unshift()`
   * needs the toolchain's real (8-byte `_Mbstatet`) `mbstate_t` - which no
   * longer fits the original 4-byte slot, so this recovery cannot alias it
   * without corrupting the adjacent `closeOnClose`/`myFile` fields.
   */
  bool RuntimeFilebufEndwrite(RuntimeFilebufCharView* const filebuf)
  {
    if (filebuf->codecvtFacet == nullptr || !filebuf->wroteSome) {
      return true;
    }

    if (filebuf->dispatch->overflow(filebuf, EOF) == EOF) {
      return false;
    }

    std::string scratch(8, '\0');
    std::mbstate_t shiftState{};

    for (;;) {
      char* const to = scratch.data();
      char* const toEnd = to + scratch.size();
      char* toNext = to;

      const std::codecvt_base::result unshiftResult =
        filebuf->codecvtFacet->unshift(shiftState, to, toEnd, toNext);

      if (unshiftResult == std::codecvt_base::error) {
        return false;
      }
      if (unshiftResult == std::codecvt_base::noconv) {
        return true;
      }
      if (unshiftResult == std::codecvt_base::ok) {
        filebuf->wroteSome = 0;
      }

      const std::size_t producedByteCount = static_cast<std::size_t>(toNext - to);
      if (producedByteCount != 0 &&
          std::fwrite(to, 1, producedByteCount, filebuf->myFile) != producedByteCount) {
        return false;
      }

      if (!filebuf->wroteSome) {
        return true;
      }

      if (producedByteCount == 0) {
        scratch.append(8, '\0');
      }
      // else: partial made progress with room to spare - retry with the same buffer.
    }
  }

  /**
   * Address: 0x004C55A0 (FUN_004C55A0, std::basic_filebuf<char>::close)
   *
   * IDA signature:
   * int __thiscall std::filebuf::close(int this);
   *
   * IDA's `int` return is really `basic_filebuf<char>*`: the real mangled
   * signature is `?close@?$basic_filebuf@DU?$char_traits@D@std@@@std@@QAEPAV12@XZ`,
   * i.e. `std::basic_filebuf<char>::close()` returning `this` on success or
   * a null pointer on failure - matching the standard `close()` contract.
   *
   * What it does:
   * No-ops to failure when `myFile` (+0x4C) is already null - a filebuf
   * that isn't open has nothing to close. Otherwise it calls
   * RuntimeFilebufEndwrite() to flush any pending codecvt shift-state reset
   * (result false demotes the return value to null) and unconditionally
   * `fclose`s `myFile` afterward regardless of whether the unshift flush
   * succeeded (a failed `fclose` also demotes the return value to null).
   * Either way, the filebuf is then reset to a fresh, unopened state:
   * `closeOnClose` (+0x48) and `wroteSome` (+0x41) cleared, the streambuf
   * I/O lanes reset (RuntimeFilebufResetIoLanes - matches the binary's
   * `std::wstreambuf::_Init` call, ICF-merged from the shared streambuf
   * base `_Init`), `myFile` nulled, `codecvtFacet` (+0x3C) cleared, and
   * `stateWord` (+0x44) restored to `gRuntimeFilebufInitialStateWord`
   * (confirmed to be the same `_Stinit` global RuntimeFilebufInit reads -
   * see the comment on that global above).
   *
   * Source-level trigger: `moho::USER_SavePreferences()`
   * (src/sdk/moho/misc/StartupHelpers.cpp) calls the real, standard
   * `std::filebuf::close()` through a genuine `std::filebuf*` obtained from
   * `std::ofstream::rdbuf()`:
   *   if (std::filebuf* const fileBuffer = outputStream.rdbuf(); fileBuffer != nullptr) {
   *     if (fileBuffer->close() == nullptr) { outputStream.setstate(std::ios::failbit); }
   *   }
   * That real call is serviced by the toolchain's own `std::filebuf::close()`,
   * not by this recovered mirror - the same relationship RuntimeFopen has
   * with the real `::_fsopen` it documents. RuntimeFilebufClose exists as
   * the address-traceable, 1:1 recovery of what FUN_004C55A0 does in the
   * shipped binary, and it invokes RuntimeFilebufEndwrite by name below,
   * which is what satisfies that function's own invocation requirement.
   */
  RuntimeFilebufCharView* RuntimeFilebufClose(RuntimeFilebufCharView* const filebuf)
  {
    RuntimeFilebufCharView* result = filebuf;

    if (filebuf->myFile != nullptr) {
      if (!RuntimeFilebufEndwrite(filebuf)) {
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
    filebuf->codecvtFacet = nullptr;
    filebuf->stateWord = gRuntimeFilebufInitialStateWord;

    return result;
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
   * Destroys the critical section this mutex owns and releases its storage -
   * the counterpart to RuntimeMutexConstruct above.
   */
  void RuntimeMutexDestruct(RuntimeMutexHandle* const object)
  {
    CRITICAL_SECTION* const lock = object->criticalSection;
    RuntimeMtxDestroy(lock);
    ::operator delete(static_cast<void*>(lock));
  }

  /**
   * Address: 0x00ABF9A8 (FUN_00ABF9A8, std::_Mutex::_Lock)
   *
   * IDA signature:
   * int __thiscall sub_ABF9A8(LPCRITICAL_SECTION *this);
   *
   * What it does:
   * Enters the critical section this mutex owns. The handle holds a pointer,
   * so the section is reached through one indirection rather than being
   * embedded.
   */
  int RuntimeMutexLock(RuntimeMutexHandle* const object) noexcept
  {
    return RuntimeMtxLock(object->criticalSection);
  }

  /**
   * Address: 0x00ABF9B1 (FUN_00ABF9B1, std::_Mutex::_Unlock)
   *
   * IDA signature:
   * int __thiscall func_LeaveCritical05(LPCRITICAL_SECTION *this);
   *
   * What it does:
   * Leaves the critical section this mutex owns; the counterpart to
   * RuntimeMutexLock.
   */
  int RuntimeMutexUnlock(RuntimeMutexHandle* const object) noexcept
  {
    return RuntimeMtxUnlock(object->criticalSection);
  }

  /**
   * Address: 0x00A899D4 (FUN_00A899D4, feof)
   *
   * What it does:
   * Reports the stream end-of-file flag. A null stream is a parameter error,
   * not a crash: errno is set to EINVAL, the invalid-parameter handler runs,
   * and zero is returned.
   */
  extern "C" int __cdecl RuntimeStreamAtEof(std::FILE* const stream)
  {
    if (stream == nullptr) {
      errno = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0, 0);
      return 0;
    }
    return legacy_file(stream)._flag & 0x10;
  }

  /**
   * Address: 0x00A89A03 (FUN_00A89A03, ferror)
   *
   * What it does:
   * Reports the stream error flag, with the same null-stream handling as
   * RuntimeStreamAtEof. Differs from it only in the flag bit tested.
   */
  extern "C" int __cdecl RuntimeStreamHasError(std::FILE* const stream)
  {
    if (stream == nullptr) {
      errno = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0, 0);
      return 0;
    }
    return legacy_file(stream)._flag & 0x20;
  }

  /**
   * Address: 0x00A96B96 (FUN_00A96B96, _unlock)
   *
   * What it does:
   * Leaves the CRT lock-table entry for `lockId`. The paired acquire lives in
   * the same table; entries are initialized lazily by the lock-table setup lane.
   */
  extern "C" void __cdecl RuntimeUnlockCrtLock(const int lockId)
  {
    // The table is pairs of {lock, kind}; _locktable is typed as a flat
    // LPCRITICAL_SECTION array, so the lock lives at index 2*lockId.
    ::LeaveCriticalSection(_locktable[2 * static_cast<std::size_t>(lockId)]);
  }

  constexpr int kRtCrtNotInit = 0x1E;

  /**
   * Address: 0x00A96BC3 (FUN_00A96BC3, _mtinitlocknum)
   *
   * What it does:
   * Lazily allocates and initializes the CRT lock-table entry for `lockId`
   * (a `CRITICAL_SECTION` behind `_locktable[2*lockId]`), guarded by the
   * lock-table's own lock (`_LOCKTAB_LOCK`). Fatal-exits via the CRT
   * not-initialized banner if the process heap isn't up yet.
   */
  extern "C" int __cdecl RuntimeInitCrtLockNumber(const int lockId)
  {
    if (_crtheap == nullptr) {
      __FF_MSGBANNER();
      __NMSG_WRITE(kRtCrtNotInit);
      crtExitProcess(0xFFu);
    }

    if (_locktable[2 * static_cast<std::size_t>(lockId)] != nullptr) {
      return 1;
    }

    auto* const newLock = static_cast<LPCRITICAL_SECTION>(std::malloc(sizeof(CRITICAL_SECTION)));
    if (newLock == nullptr) {
      *_errno() = ENOMEM;
      return 0;
    }

    int status = 1;
    RuntimeLockCrtLock(kLocktabLock);
    if (_locktable[2 * static_cast<std::size_t>(lockId)] != nullptr) {
      _free_crt(newLock);
    } else if (__crtInitCritSecAndSpinCount(newLock, 4000u)) {
      _locktable[2 * static_cast<std::size_t>(lockId)] = newLock;
    } else {
      _free_crt(newLock);
      *_errno() = ENOMEM;
      status = 0;
    }
    RuntimeUnlockCrtLock(kLocktabLock);
    return status;
  }

  /**
   * Address: 0x00A96C86 (FUN_00A96C86, _lock)
   *
   * What it does:
   * Enters the CRT lock-table entry for `lockId`, initializing it on first
   * use via `RuntimeInitCrtLockNumber`. Fatal-exits (`__amsg_exit`) if
   * initialization fails.
   */
  extern "C" void __cdecl RuntimeLockCrtLock(const int lockId)
  {
    if (_locktable[2 * static_cast<std::size_t>(lockId)] == nullptr && !RuntimeInitCrtLockNumber(lockId)) {
      __amsg_exit(17);
    }
    ::EnterCriticalSection(_locktable[2 * static_cast<std::size_t>(lockId)]);
  }

  /**
   * Address: 0x00A82D30 (FUN_00A82D30, strchr)
   *
   * What it does:
   * Returns the first occurrence of `value` in `text`, or `nullptr` when no
   * matching byte is present before the NUL terminator.
   *
   * Named off the reserved CRT symbol despite that - not `strchr` - for the
   * same reason as `EngineSetNewMode`/`EngineStrtod` above: this toolchain's
   * <cstring> spells `std::strchr` as `using ::strchr;`, so a global
   * `strchr` defined here does not forward to the real implementation, it
   * calls itself - an unconditional, guaranteed stack overflow the instant
   * anything calls `strchr` anywhere in the program (which is constantly:
   * Lua's parser, path handling, logging, and dozens of other recovered
   * call sites throughout src/sdk all call `std::strchr`/`strchr` expecting
   * the real one). Keeping the disassembled body under a non-colliding name
   * preserves the recovery; not colliding lets every one of those callers
   * resolve to the real CRT implementation as they already assume.
   */
  extern "C" char* __cdecl EngineStrchr(const char* const text, const int value)
  {
    return const_cast<char*>(std::strchr(text, value));
  }

  /**
   * Address: 0x00A8E710 (FUN_00A8E710, strpbrk)
   *
   * What it does:
   * Returns the first byte in `text` that matches any byte in `accept`,
   * using the legacy 256-bit lookup-table scan shape.
   */
  extern "C" char* __cdecl strpbrk(const char* const text, const char* const accept)
  {
    std::uint32_t acceptedByteMaskWords[8]{};
    for (const auto* acceptCursor = reinterpret_cast<const unsigned char*>(accept); *acceptCursor != 0; ++acceptCursor) {
      const std::uint32_t byteValue = static_cast<std::uint32_t>(*acceptCursor);
      acceptedByteMaskWords[byteValue >> 5u] |= (1u << (byteValue & 31u));
    }

    for (const auto* textCursor = reinterpret_cast<const unsigned char*>(text); *textCursor != 0; ++textCursor) {
      const std::uint32_t byteValue = static_cast<std::uint32_t>(*textCursor);
      if ((acceptedByteMaskWords[byteValue >> 5u] & (1u << (byteValue & 31u))) != 0u) {
        return const_cast<char*>(reinterpret_cast<const char*>(textCursor));
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00AB09E0 (FUN_00AB09E0)
   *
   * What it does:
   * Locale-explicit `strpbrk` entry point: forwards `(text, accept, nullptr)`
   * into `_strpbrk_l` (FUN_00AB0916). With a null locale argument,
   * `_strpbrk_l`'s `_LocaleUpdate` always resolves to the global/classic
   * locale and its `[localeState+8]==0` fast path calls straight into the
   * plain `strpbrk` above -- so a null-locale call is behaviourally just
   * `strpbrk(text, accept)`.
   *
   * Real callers: FUN_00AB055B (a `_findfirst`-family wildcard check doing
   * `strpbrk(lpFileName, "?*")`) and FUN_00A95010 -- neither is recovered
   * source yet (FUN_00AB055B is a ~0x309-byte path/wildcard validator; its
   * DB status of `external_dependency` is a stale mis-tag from the same
   * contamination sweep this cluster is being drained from -- it is real
   * code, not an import). Kept as a free function rather than wired to a
   * caller here since neither owner is identified/recovered yet;
   * address-taken-by-name is the intended source invocation once
   * FUN_00AB055B is recovered.
   */
  [[maybe_unused]] char* StrpbrkWithGlobalLocale(const char* const text, const char* const accept)
  {
    return strpbrk(text, accept);
  }

  /**
   * Address: 0x00A83B0F (FUN_00A83B0F, func_CpySign)
   *
   * What it does:
   * Copies the sign of `signSource` onto the magnitude of `magnitude`.
   */
  extern "C" double __cdecl func_CpySign(const double magnitude, const double signSource)
  {
    return std::copysign(magnitude, signSource);
  }

  /**
   * Address: 0x00A8E0A0 (FUN_00A8E0A0, _pow)
   *
   * What it does:
   * Computes one `pow(base, exponent)` lane for CRT callsites.
   */
  extern "C" double __cdecl _pow(const double base, const double exponent)
  {
    return std::pow(base, exponent);
  }

  /**
   * Address: 0x00A8EBE0 (FUN_00A8EBE0, __allrem)
   *
   * What it does:
   * Computes signed 64-bit remainder (`dividend % divisor`) for compiler
   * helper callsites that import the legacy `__allrem` runtime lane.
   */
  extern "C" __int64 __stdcall __allrem(const __int64 dividend, const __int64 divisor)
  {
    return dividend % divisor;
  }

  /**
   * Address: 0x00AA93C0 (FUN_00AA93C0, __CIpow_pentium4)
   *
   * What it does:
   * x87 inline-`pow` helper lane that forwards to `_pow(base, exponent)` after
   * argument-order normalization from the FPU stack convention.
   */
  extern "C" double __cdecl __CIpow_pentium4(const double exponent, const double base)
  {
    return _pow(base, exponent);
  }

  alignas(1) const unsigned char gRuntimeFpuClassDispatchOffsetByFxamClass[16] = {
    0x08, 0x04, 0x08, 0x08,
    0x08, 0x04, 0x08, 0x08,
    0x00, 0x04, 0x0C, 0x08,
    0x00, 0x04, 0x0C, 0x08
  };
  static_assert(
    sizeof(gRuntimeFpuClassDispatchOffsetByFxamClass) == 0x10,
    "gRuntimeFpuClassDispatchOffsetByFxamClass size must be 0x10"
  );
  alignas(2) const unsigned char gRuntimeFpuExceptionTriggerConstantA80[10] = {
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x10, 0x44
  };
  static_assert(
    sizeof(gRuntimeFpuExceptionTriggerConstantA80) == 0x0A,
    "gRuntimeFpuExceptionTriggerConstantA80 size must be 0x0A"
  );
  alignas(2) const unsigned char gRuntimeFpuExceptionTriggerConstantB80[10] = {
    0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x00, 0x30
  };
  static_assert(
    sizeof(gRuntimeFpuExceptionTriggerConstantB80) == 0x0A,
    "gRuntimeFpuExceptionTriggerConstantB80 size must be 0x0A"
  );
  const double gRuntimeHalfScaleDouble = 0.5;
  alignas(2) const unsigned char gRuntimeFpuIndefiniteValue80[10] = {
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xC0, 0xFF, 0xFF
  };
  static_assert(sizeof(gRuntimeFpuIndefiniteValue80) == 0x0A, "gRuntimeFpuIndefiniteValue80 size must be 0x0A");

  /**
   * Address: 0x00A8E302 (FUN_00A8E302)
   * Address: 0x00AAA0C1 (FUN_00AAA0C1)
   *
   * What it does:
   * Classifies the legacy `_pow_0` exponent lane into non-integer, odd integer,
   * or even integer categories using the same round-to-nearest integral checks
   * the x87 path applied. The compiler emitted this body a second time
   * (0x00AAA0C1) as the private copy used by the Pentium4/SSE2 `pow()` lane
   * (`__pow_pentium4`, already `external_dependency`); confirmed instruction
   * for instruction against the x87 body, including the `fmul dbl_F3F3D2`
   * multiply by the same 0.5 constant as `gRuntimeHalfScaleDouble` below.
   */
  extern "C" std::uint8_t __cdecl RuntimeClassifyPowExponentParity(const double exponent)
  {
    const double roundedExponent = std::nearbyint(exponent);
    if (roundedExponent != exponent) {
      return 0u;
    }

    const double halfExponent = exponent * 0.5;
    const double roundedHalfExponent = std::nearbyint(halfExponent);
    return (roundedHalfExponent == halfExponent) ? 2u : 1u;
  }

  /**
   * Address: 0x00AA7BD5 (FUN_00AA7BD5, func_Fldcw)
   *
   * What it does:
   * Rebuilds one x87 control-word lane from caller-supplied precision-control
   * bits and applies it through the CRT control-word setter.
   */
  extern "C" void __cdecl func_Fldcw(const int controlWord)
  {
    const unsigned int x87ControlWord =
      (static_cast<unsigned int>(controlWord) & 0x0300u) | 0x007Fu;
    (void)_controlfp(x87ControlWord, 0x037Fu);
  }

  /**
   * Address: 0x00A83EEE (FUN_00A83EEE, _finite)
   *
   * What it does:
   * Returns nonzero when the incoming IEEE-754 double lane is finite by
   * checking the exponent mask against the all-ones NaN/Inf pattern.
   */
  extern "C" int __cdecl _finite(const double value)
  {
    std::uint64_t bitPattern = 0u;
    std::memcpy(&bitPattern, &value, sizeof(bitPattern));
    const std::uint16_t highWord = static_cast<std::uint16_t>(bitPattern >> 48u);
    return ((highWord & 0x7FF0u) != 0x7FF0u) ? 1 : 0;
  }

  /**
   * Address: 0x00A89076 (FUN_00A89076, func_FPmt)
   *
   * What it does:
   * No-op floating-point multithread init/term hook used by `_FPmtinit` and
   * `_FPmtterm` callsites.
   */
  extern "C" void __cdecl func_FPmt()
  {
    // Intentionally empty: VC8 CRT lane is a stub.
  }

  /**
   * Address: 0x00ABED10 (FUN_00ABED10, __ascii_memicmp)
   *
   * What it does:
   * Compares up to `byteCount` ASCII bytes case-insensitively using legacy
   * null-terminated early-stop semantics and returns -1/0/+1 ordering.
   */
  int RuntimeAsciiMemicmp(
    const unsigned char* lhsBytes,
    const unsigned char* rhsBytes,
    int byteCount
  )
  {
    int remaining = byteCount;
    if (remaining == 0) {
      return remaining;
    }

    unsigned char lhsValue = 0u;
    unsigned char rhsValue = 0u;
    do {
      lhsValue = *lhsBytes;
      rhsValue = *rhsBytes;
      if (lhsValue == 0u || rhsValue == 0u) {
        break;
      }

      ++lhsBytes;
      ++rhsBytes;
      lhsValue = RuntimeAsciiToLower(lhsValue);
      rhsValue = RuntimeAsciiToLower(rhsValue);
      if (lhsValue != rhsValue) {
        return (lhsValue < rhsValue) ? -1 : 1;
      }

      --remaining;
    } while (remaining != 0);

    if (lhsValue == rhsValue) {
      return 0;
    }
    return (lhsValue < rhsValue) ? -1 : 1;
  }

  /**
   * Address: 0x00AAE83A (FUN_00AAE83A, _wcsnicoll_l)
   *
   * What it does:
   * Performs one bounded locale-aware wide case-insensitive collation
   * compare, with ASCII fold fallback when the locale collate-handle lane is
   * disabled.
   */
  int RuntimeWcsnicollLocale(
    const wchar_t* const lhsText,
    const wchar_t* const rhsText,
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

    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    RuntimeThreadLocInfoView* const localeView = RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    int result = 0x7FFFFFFF;
    const LCID collateHandle = (localeView != nullptr) ? localeView->lcHandle[1] : 0;
    if (collateHandle != 0) {
      const int compareResult = ::CompareStringW(
        collateHandle,
        NORM_IGNORECASE,
        lhsText,
        static_cast<int>(maxCount),
        rhsText,
        static_cast<int>(maxCount)
      );
      if (compareResult == 0) {
        *_errno() = EINVAL;
      } else {
        result = compareResult - 2;
      }
    } else {
      const wchar_t* lhsCursor = lhsText;
      const wchar_t* rhsCursor = rhsText;
      std::size_t remaining = maxCount;
      wchar_t lhsValue = 0;
      wchar_t rhsValue = 0;

      do {
        lhsValue = *lhsCursor++;
        if (lhsValue >= L'A' && lhsValue <= L'Z') {
          lhsValue = static_cast<wchar_t>(lhsValue + (L'a' - L'A'));
        }

        rhsValue = *rhsCursor++;
        if (rhsValue >= L'A' && rhsValue <= L'Z') {
          rhsValue = static_cast<wchar_t>(rhsValue + (L'a' - L'A'));
        }

        --remaining;
      } while (remaining != 0u && lhsValue != 0 && lhsValue == rhsValue);

      result = static_cast<int>(lhsValue) - static_cast<int>(rhsValue);
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00AAE97B (FUN_00AAE97B, _wcsnicoll)
   *
   * What it does:
   * Compares up to `maxCount` UTF-16 code units case-insensitively, using the
   * locale-aware `_wcsnicoll_l` lane when locale state changed and the legacy
   * ASCII-fold fallback lane otherwise.
   */
  extern "C" int __cdecl _wcsnicoll(
    const wchar_t* const lhsText,
    const wchar_t* const rhsText,
    const unsigned int maxCount
  )
  {
    if (__locale_changed != 0) {
      return RuntimeWcsnicollLocale(lhsText, rhsText, maxCount, nullptr);
    }

    if (lhsText == nullptr || rhsText == nullptr || maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    const wchar_t* lhsCursor = lhsText;
    const wchar_t* rhsCursor = rhsText;
    unsigned int remaining = maxCount;
    wchar_t lhsValue = L'\0';
    wchar_t rhsValue = L'\0';

    do {
      lhsValue = *lhsCursor++;
      if (lhsValue >= L'A' && lhsValue <= L'Z') {
        lhsValue = static_cast<wchar_t>(lhsValue + (L'a' - L'A'));
      }

      rhsValue = *rhsCursor++;
      if (rhsValue >= L'A' && rhsValue <= L'Z') {
        rhsValue = static_cast<wchar_t>(rhsValue + (L'a' - L'A'));
      }

      --remaining;
    } while (remaining != 0u && lhsValue != L'\0' && lhsValue == rhsValue);

    return static_cast<int>(lhsValue) - static_cast<int>(rhsValue);
  }

  /**
   * Address: 0x00ABEB2C (FUN_00ABEB2C, _mbsnbicmp_l)
   *
   * What it does:
   * Compares up to `byteCount` bytes from two multibyte buffers
   * case-insensitively under one locale, returning CRT ordering and
   * invalid-parameter sentinel behavior.
   */
  int RuntimeMbsnbicmpLocale(
    const void* const lhsBuffer,
    const unsigned char* const rhsBuffer,
    const std::size_t byteCount,
    _locale_t const localeInfo
  )
  {
    if (byteCount == 0u) {
      return 0;
    }

    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    (void)RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    int result = 0x7FFFFFFF;
    if (lhsBuffer == nullptr || rhsBuffer == nullptr || byteCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    } else {
      result = ::_mbsnbicmp_l(
        reinterpret_cast<const unsigned char*>(lhsBuffer),
        rhsBuffer,
        byteCount,
        localeInfo
      );
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00ABECF5 (FUN_00ABECF5)
   *
   * What it does:
   * Forwards one default-locale `_mbsnbicmp_l` lane into
   * `RuntimeMbsnbicmpLocale`.
   */
  extern "C" int __cdecl RuntimeMbsnbicmpDefaultLocale(
    const void* const lhsBuffer,
    const void* const rhsBuffer,
    const std::size_t byteCount
  )
  {
    return RuntimeMbsnbicmpLocale(lhsBuffer, reinterpret_cast<const unsigned char*>(rhsBuffer), byteCount, nullptr);
  }

  /**
   * Address: 0x00A8B198 (FUN_00A8B198, _MarkAllocaS)
   *
   * What it does:
   * Stores one alloca marker word and returns the caller scratch cursor two
   * dwords ahead when marker storage exists.
   */
  extern "C" void* __cdecl _MarkAllocaS(void* const markerWord, const unsigned int markerValue)
  {
    if (markerWord != nullptr) {
      auto* const markerCursor = static_cast<std::uint32_t*>(markerWord);
      *markerCursor = markerValue;
      return markerCursor + 2;
    }
    return markerWord;
  }

  /**
   * Address: 0x00A8B751 (FUN_00A8B751, __store_number)
   *
   * What it does:
   * Emits decimal digits for `value` into the target cursor (bounded by
   * `remainingSlots`), then reverses that span in-place and returns its first
   * byte.
   */
  extern "C" char* __cdecl __store_number(
    std::int32_t value,
    char** const inOutWriteCursor,
    std::uint32_t* const remainingSlots
  )
  {
    char* cursor = *inOutWriteCursor;
    if (*remainingSlots > 1u) {
      do {
        const std::int32_t digit = value % 10;
        value /= 10;
        *cursor++ = static_cast<char>(digit + '0');
        --(*remainingSlots);
      } while (value > 0 && *remainingSlots > 1u);
    }

    char* first = *inOutWriteCursor;
    *inOutWriteCursor = cursor;
    char* last = cursor - 1;
    while (first < last) {
      const char tmp = *last;
      *last-- = *first;
      *first++ = tmp;
    }
    return first;
  }

  /**
   * Address: 0x00A9B420 (FUN_00A9B420, __mbsnbicoll)
   *
   * What it does:
   * Forwards bounded multibyte case-insensitive collation to the
   * locale-aware lane with default thread locale (`nullptr` locale).
   */
  extern "C" int __cdecl _mbsnbicoll(
    const unsigned char* const lhsText,
    const unsigned char* const rhsText,
    const std::size_t maxCount
  )
  {
    return ::_mbsnbicoll_l(lhsText, rhsText, maxCount, nullptr);
  }

  /**
   * Address: 0x00A8E750 (FUN_00A8E750, sub_A8E750)
   *
   * What it does:
   * Locale-aware narrow collation backend used by `strcoll`; resolves the
   * active collate LCID/codepage lane, falls back to `strcmp` when collation
   * is disabled, and preserves CRT invalid-parameter/`EINVAL` semantics.
   */
  int RuntimeStrcollLocale(const char* const lhsText, const char* const rhsText, _locale_t const localeInfo)
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    RuntimeThreadLocInfoView* const localeView = RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);

    int result = 0x7FFFFFFF;
    if (lhsText != nullptr && rhsText != nullptr) {
      const LCID collateLcid = localeView != nullptr ? localeView->lcHandle[3] : 0;
      if (collateLcid == 0) {
        result = std::strcmp(lhsText, rhsText);
      } else {
        const int compareResult = ::CompareStringA(
          collateLcid,
          0x1000u,
          lhsText,
          -1,
          rhsText,
          -1
        );
        if (compareResult != 0) {
          result = compareResult - 2;
        } else {
          *_errno() = EINVAL;
        }
      }
    } else {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    }

    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00A8E7F4 (FUN_00A8E7F4, strcoll)
   *
   * What it does:
   * Default-locale narrow collation wrapper forwarding to
   * `RuntimeStrcollLocale(..., nullptr)`.
   */
  extern "C" int __cdecl strcoll(const char* const lhsText, const char* const rhsText)
  {
    return RuntimeStrcollLocale(lhsText, rhsText, nullptr);
  }

  /**
   * Address: 0x00AB9E03 (FUN_00AB9E03, __ismbblead)
   *
   * What it does:
   * Tests one byte against the active locale lead-byte table by forwarding to
   * `_ismbblead_l(..., nullptr)`.
   */
  extern "C" int __cdecl _ismbblead(const unsigned int value)
  {
    return ::_ismbblead_l(static_cast<unsigned char>(value), nullptr);
  }

  /**
   * Address: 0x00AB8810 (FUN_00AB8810, _tcsicmp_l)
   *
   * What it does:
   * Default-locale TCHAR compare lane for this binary profile: forwards to
   * `_mbsicmp_l` with a null locale argument.
   */
  extern "C" int __cdecl _tcsicmp_l(const char* const lhsText, const char* const rhsText)
  {
    return ::_mbsicmp_l(
      reinterpret_cast<const unsigned char*>(lhsText),
      reinterpret_cast<const unsigned char*>(rhsText),
      nullptr
    );
  }

  /**
   * Address: 0x00AA4961 (FUN_00AA4961, __mbsrchr)
   *
   * What it does:
   * Reverse-searches one multibyte string for `searchChar` using the CRT
   * default-locale lane (`_mbsrchr_l(..., nullptr)`).
   */
  extern "C" unsigned char* __cdecl _mbsrchr(const unsigned char* const text, const unsigned int searchChar)
  {
    return ::_mbsrchr_l(text, searchChar, nullptr);
  }

  /**
   * Address: 0x00A845E0 (FUN_00A845E0, _strrchr)
   *
   * What it does:
   * Reverse-searches one C string for the final byte equal to `searchChar`,
   * including the terminating NUL lane when `searchChar == 0`.
   */
  extern "C" char* __cdecl _strrchr(const char* const text, const int searchChar)
  {
    if (text == nullptr) {
      return nullptr;
    }

    const unsigned char target = static_cast<unsigned char>(searchChar);
    const char* cursor = text + std::strlen(text);

    while (cursor >= text) {
      if (static_cast<unsigned char>(*cursor) == target) {
        return const_cast<char*>(cursor);
      }

      if (cursor == text) {
        break;
      }
      --cursor;
    }

    return nullptr;
  }

  /**
   * Address: 0x00AB898C (FUN_00AB898C, _tcsncmp)
   *
   * What it does:
   * Narrow TCHAR bounded-compare wrapper that forwards directly into
   * `_mbsnbcmp_l` with the default locale lane.
   */
  extern "C" int __cdecl _tcsncmp(const char* const lhsText, const char* const rhsText, const std::size_t maxCount)
  {
    return ::_mbsnbcmp_l(
      reinterpret_cast<const unsigned char*>(lhsText),
      reinterpret_cast<const unsigned char*>(rhsText),
      maxCount,
      nullptr
    );
  }

  /**
   * Address: 0x00AA6ED2 (FUN_00AA6ED2, __getpath)
   *
   * What it does:
   * Parses one semicolon-delimited PATH lane token into `destination`,
   * honoring quoted segments and setting `errno=ERANGE` on output truncation.
   * Returns the next parse cursor or null when no token was consumed.
   */
  extern "C" unsigned char* __cdecl __getpath(
    unsigned char* source,
    unsigned char* const destination,
    const int destinationCapacity
  )
  {
    while (*source == ';') {
      ++source;
    }

    unsigned char* sourceAtError = source;
    int remainingChars = destinationCapacity - 1;
    unsigned char* writeCursor = destination;

    if (remainingChars == 0) {
      *_errno() = ERANGE;
    } else {
      while (*source != '\0') {
        const unsigned char current = *source;
        if (current == ';') {
          while (*source == ';') {
            ++source;
          }
          break;
        }

        if (current == '"') {
          ++source;
          while (*source != '\0') {
            if (*source == '"') {
              break;
            }

            *writeCursor++ = *source++;
            --remainingChars;
            if (remainingChars == 0) {
              sourceAtError = source;
              *_errno() = ERANGE;
              break;
            }
          }

          if (remainingChars == 0 || *source == '\0') {
            break;
          }

          ++source;
          continue;
        }

        *writeCursor++ = current;
        ++source;
        --remainingChars;
        if (remainingChars == 0) {
          sourceAtError = source;
          *_errno() = ERANGE;
          break;
        }
      }
    }

    *writeCursor = '\0';
    return (source != sourceAtError) ? source : nullptr;
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
    // The binary tests __locale_changed first and only takes the ASCII fast
    // path when the process is still on the initial locale; the locale-aware
    // lane is _memicmp_l with a null locale. An earlier recovery of this body
    // dropped the branch entirely and always went ASCII, which silently
    // mis-compared non-ASCII bytes once any setlocale() call had run.
    if (__locale_changed != 0) {
      return _memicmp_l(lhsBuffer, rhsBuffer, byteCount, nullptr);
    }

    if (lhsBuffer != nullptr && rhsBuffer != nullptr && byteCount <= 0x7FFFFFFFu) {
      const auto* const lhsBytes = static_cast<const unsigned char*>(lhsBuffer);
      const auto* const rhsBytes = static_cast<const unsigned char*>(rhsBuffer);
      return RuntimeAsciiMemicmp(lhsBytes, rhsBytes, static_cast<int>(byteCount));
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return 0x7FFFFFFF;
  }

  /**
   * Address: 0x00ABD060 (FUN_00ABD060, write_char_uni)
   *
   * What it does:
   * Emits one wide character into a legacy CRT stream and updates the written
   * count, preserving the failed-write lane used by the wide formatter.
   */
  static void write_char_uni(std::FILE* const f, int* const pnumwritten, const wchar_t wideChar)
  {
    if (((legacy_file(f)._flag & 0x40) == 0 || legacy_file(f)._base != nullptr)
        && ::_fputwc_nolock(wideChar, f) == static_cast<wint_t>(-1)) {
      *pnumwritten = -1;
    } else {
      ++*pnumwritten;
    }
  }

  /**
   * Address: 0x00A88100 (FUN_00A88100, strstr)
   *
   * What it does:
   * MSVC CRT `strstr(haystack, needle)` implementation. Returns `haystack`
   * when `needle` is the empty string, otherwise scans `haystack` with the
   * two-byte fast-path loop (compare first/second `needle` byte against the
   * current window, then fall through to the general suffix walk). Returns
   * `nullptr` when no match is found. The recovered body uses `std::strstr`
   * which has identical semantics on the MSVC CRT.
   *
   * IDA signature:
   * int __cdecl strstr(const char *str, const char *substr);
   */
  extern "C" const char* __cdecl RuntimeStrstr(
    const char* const haystack,
    const char* const needle
  ) noexcept
  {
    if (needle == nullptr || *needle == '\0') {
      return haystack;
    }
    if (haystack == nullptr) {
      return nullptr;
    }
    return std::strstr(haystack, needle);
  }

  /**
   * Address: 0x00A900FC (FUN_00A900FC, swscanf)
   *
   * What it does:
   * MSVC CRT `swscanf(source, format, ...)` variadic entry point. Packs the
   * variadic argument list and forwards to the secure wide-string scan worker
   * (IDA `sub_A9008E` -> `sub_AAC874`, the wide-input-scan conversion lane),
   * which wraps `source` as an in-memory scan stream and dispatches the
   * conversion worker. Used throughout the wx control-attribute and DC text
   * paths to parse RichEdit version/class strings from HWND class names.
   *
   * IDA signature:
   * int sub_A900FC(int a1, int a2, ...);  // (source, format, ...)
   */
  extern "C" int __cdecl RuntimeSscanfWide(
    const wchar_t* const source,
    const wchar_t* const format,
    ...
  )
  {
    std::va_list argList;
    va_start(argList, format);
    // Forwards to `::vswscanf`, which the MSVC CRT implements via the exact
    // `_input_l` / scan-stream dispatch chain `FUN_00A9008E`/`FUN_00AAC874`
    // represent in the binary.
    const int result = ::vswscanf(source, format, argList);
    va_end(argList);
    return result;
  }

  struct RuntimeScanStringStreamView
  {
    const void* current = nullptr;      // +0x00
    std::int32_t remainingBytes = 0;    // +0x04
    const void* sourceStart = nullptr;  // +0x08
    std::int32_t flags = 0;             // +0x0C
  };
  static_assert(sizeof(RuntimeScanStringStreamView) == 0x10, "RuntimeScanStringStreamView size must be 0x10");

  using RuntimeStringScanWorker = int(__cdecl*)(RuntimeScanStringStreamView*, int, int, int);

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
   * Address: 0x00A90762 (FUN_00A90762)
   *
   * What it does:
   * Resolves one locale-update lane and forwards wide time formatting into the
   * locale-aware CRT formatter.
   */
  std::size_t RuntimeWcsftimeLocaleLane(
    wchar_t* const destination,
    const std::size_t maxSize,
    const wchar_t* const format,
    const std::tm* const timeData,
    _locale_t const localeInfo
  )
  {
    RuntimeTidDataLocaleView* threadData = nullptr;
    bool updated = false;
    (void)RuntimeResolveLocaleLocInfo(localeInfo, &threadData, &updated);
    const std::size_t result = ::_wcsftime_l(destination, maxSize, format, timeData, localeInfo);
    RuntimeReleaseLocaleUpdate(threadData, updated);
    return result;
  }

  /**
   * Address: 0x00A9079A (FUN_00A9079A, wcsftime)
   *
   * What it does:
   * Forwards wide time formatting to the locale-aware CRT lane with a null
   * locale so the active thread locale is used.
   */
  extern "C" std::size_t __cdecl wcsftime(
    wchar_t* const lpWideCharStr,
    const std::size_t maxSize,
    const wchar_t* const format,
    const std::tm* const timeData
  )
  {
    return RuntimeWcsftimeLocaleLane(lpWideCharStr, maxSize, format, timeData, nullptr);
  }

  /**
   * Address: 0x00A9A4F9 (FUN_00A9A4F9)
   *
   * What it does:
   * Maps one CRT floating-category bitmask lane into the legacy small integer
   * category code used by higher-level classification helpers.
   */
  extern "C" int __cdecl RuntimeMapFloatClassMaskToLegacyCode(const char classMask)
  {
    if ((classMask & 0x20) != 0) {
      return 5;
    }
    if ((classMask & 0x08) != 0) {
      return 1;
    }
    if ((classMask & 0x04) != 0) {
      return 2;
    }
    if ((classMask & 0x01) != 0) {
      return 3;
    }
    return 2 * (classMask & 0x02);
  }

  /**
   * Address: 0x00A9A807 (FUN_00A9A807, func_ClearFloatExceptionFlags)
   *
   * What it does:
   * Reads the current x87 status word, clears pending floating-point exception
   * flags, and returns the captured status lane.
   */
extern "C" int __cdecl RuntimeClearFloatExceptionFlags()
{
#if defined(_M_IX86)
  short statusWord = 0;
  __asm {
      fnstsw statusWord
      fnclex
    }
    return static_cast<int>(statusWord);
#else
    return static_cast<int>(_clearfp());
#endif
}

/**
 * Address: 0x00A9A91E (FUN_00A9A91E)
 *
 * What it does:
 * Clears the MXCSR exception flags lane when compatibility mode is enabled.
 */
extern "C" void __cdecl RuntimeClearMxcsrExceptionFlagsIfCompatEnabled()
{
  if (global_compat_flag != 0) {
    _mm_setcsr(_mm_getcsr() & 0xFFFFFFC0u);
  }
}

/**
 * Address: 0x00A9A936 (FUN_00A9A936)
 *
 * What it does:
 * Returns pending MXCSR exception flags (`bits 0..5`) when compatibility mode
 * is enabled; returns `0` when compatibility mode is disabled.
 */
extern "C" int __cdecl RuntimeQueryMxcsrExceptionFlagsIfCompatEnabled()
{
  const int mxcsr = (global_compat_flag != 0) ? static_cast<int>(_mm_getcsr()) : 0;
  return mxcsr & 0x3F;
}

/**
 * Address: 0x00A9A949 (FUN_00A9A949)
 *
 * What it does:
 * Returns currently pending MXCSR exception flags (`bits 0..5`) and clears the
 * pending flags when compatibility mode is enabled.
 */
extern "C" int __cdecl RuntimeConsumeMxcsrExceptionFlagsIfCompatEnabled()
{
  if (global_compat_flag == 0) {
    return 0;
  }

  const int flags = static_cast<int>(_mm_getcsr()) & 0x3F;
  _mm_setcsr(_mm_getcsr() & 0xFFFFFFC0u);
  return flags;
}

/**
 * Address: 0x00A9A961 (FUN_00A9A961)
 *
 * What it does:
 * Returns the previous MXCSR lane and applies one masked update to MXCSR
 * control bits while preserving reserved/exception lanes required by VC8 CRT
 * compatibility behavior.
 */
extern "C" int __cdecl RuntimeSetMxcsrMaskedIfCompatEnabled(
  const int value,
  const int mask
)
{
  int previous = 0;
  if (global_compat_flag != 0) {
    previous = static_cast<int>(_mm_getcsr());
    const int merged = (value & mask) | (previous & (~mask | 0xFFFF807F));
    _mm_setcsr(static_cast<unsigned int>(merged & 0xFFFFFFBF));
  }
  return previous;
}

/**
 * Address: 0x00A9A995 (FUN_00A9A995)
 *
 * What it does:
 * Raises MXCSR exception-flag bits (`0..5`) by OR-ing caller flags into the
 * current MXCSR lane when compatibility mode is enabled.
 */
extern "C" int __cdecl RuntimeRaiseMxcsrExceptionFlags(const char flags)
{
  const int currentMxcsr = (global_compat_flag != 0) ? static_cast<int>(_mm_getcsr()) : 0;
  const int merged = currentMxcsr | (static_cast<int>(flags) & 0x3F);
  (void)RuntimeSetMxcsrMaskedIfCompatEnabled(merged, 0x3F);
  return 0;
}

/**
 * Address: 0x00A874BF (FUN_00A874BF)
 *
 * What it does:
 * Maps MXCSR exception flags into CRT `_statusfp`-style status bits when
   * compatibility mode enables MXCSR probing.
   */
  extern "C" int __cdecl RuntimeStatusfpFromMxcsr()
  {
    const unsigned int mxcsr = (global_compat_flag != 0) ? static_cast<unsigned int>(_mm_getcsr()) : 0u;
    unsigned int status = 0u;
    if ((mxcsr & 0x3Fu) != 0u) {
      if ((mxcsr & 0x01u) != 0u) {
        status |= 0x10u;
      }
      if ((mxcsr & 0x04u) != 0u) {
        status |= 0x08u;
      }
      if ((mxcsr & 0x08u) != 0u) {
        status |= 0x04u;
      }
      if ((mxcsr & 0x10u) != 0u) {
        status |= 0x02u;
      }
      if ((mxcsr & 0x20u) != 0u) {
        status |= 0x01u;
      }
      if ((mxcsr & 0x02u) != 0u) {
        status |= 0x80000u;
      }
    }
    return static_cast<int>(status);
  }

  /**
   * Address: 0x00A9D5B0 (FUN_00A9D5B0, mod64)
   *
   * What it does:
   * Computes one unsigned 64-bit remainder lane used by CRT time helpers.
   */
  extern "C" std::uint64_t __stdcall mod64(const std::uint64_t dividendValue, const std::int64_t divisorValue)
  {
    const std::uint64_t divisorUnsigned = static_cast<std::uint64_t>(divisorValue);
    const std::uint32_t divisorHigh = static_cast<std::uint32_t>(divisorUnsigned >> 32u);
    if (divisorHigh != 0u) {
      std::uint32_t normalizedHigh = divisorHigh;
      std::uint32_t normalizedLow = static_cast<std::uint32_t>(divisorUnsigned);
      std::uint64_t normalizedDividend = dividendValue;
      do {
        const bool carry = (normalizedHigh & 1u) != 0u;
        normalizedHigh >>= 1u;
        normalizedLow = (normalizedLow >> 1u) | (static_cast<std::uint32_t>(carry) << 31u);
        normalizedDividend >>= 1u;
      } while (normalizedHigh != 0u);

      const std::uint32_t quotient =
        static_cast<std::uint32_t>(normalizedDividend / static_cast<std::uint64_t>(normalizedLow));
      const std::uint64_t lowProduct = static_cast<std::uint64_t>(static_cast<std::uint32_t>(divisorUnsigned))
        * static_cast<std::uint64_t>(quotient);
      const std::uint64_t highProduct = static_cast<std::uint64_t>(static_cast<std::uint32_t>(divisorUnsigned >> 32u))
        * static_cast<std::uint64_t>(quotient);

      const std::uint32_t lowProductHigh32 = static_cast<std::uint32_t>(lowProduct >> 32u);
      const std::uint32_t highProductLow32 = static_cast<std::uint32_t>(highProduct);
      const std::uint64_t summedHigh =
        static_cast<std::uint64_t>(lowProductHigh32) + static_cast<std::uint64_t>(highProductLow32);
      const bool carryOut = summedHigh > 0xFFFFFFFFull;

      std::uint64_t combinedProduct =
        (static_cast<std::uint64_t>(static_cast<std::uint32_t>(summedHigh)) << 32u)
        | static_cast<std::uint32_t>(lowProduct);
      if (carryOut || combinedProduct > dividendValue) {
        combinedProduct -= divisorUnsigned;
      }
      return dividendValue - combinedProduct;
    }

    const std::uint32_t divisorLow = static_cast<std::uint32_t>(divisorUnsigned);
    const std::uint32_t remainderHigh = static_cast<std::uint32_t>(dividendValue >> 32u) % divisorLow;
    const std::uint64_t foldedDividend =
      (static_cast<std::uint64_t>(remainderHigh) << 32u) | static_cast<std::uint32_t>(dividendValue);
    return foldedDividend % divisorLow;
  }

  /**
   * Address: 0x00A904E0 (FUN_00A904E0, mod64_0)
   *
   * What it does:
   * Computes signed 64-bit remainder using the CRT helper algorithm that
   * normalizes operand sign and performs quotient approximation with 32-bit
   * division lanes.
   */
  extern "C" std::uint64_t __stdcall mod64_0(std::uint64_t dividendValue, std::int64_t divisorValue)
  {
    bool negateResult = false;
    std::uint64_t dividend = dividendValue;
    if (static_cast<std::int64_t>(dividendValue) < 0) {
      negateResult = true;
      dividend = 0ull - dividend;
    }

    std::uint64_t divisor = static_cast<std::uint64_t>(divisorValue);
    if (divisorValue < 0) {
      divisor = 0ull - divisor;
    }

    const std::uint32_t divisorHigh = static_cast<std::uint32_t>(divisor >> 32u);
    std::uint64_t remainder = 0ull;
    if (divisorHigh == 0u) {
      const std::uint32_t divisorLow = static_cast<std::uint32_t>(divisor);
      const std::uint32_t dividendHigh = static_cast<std::uint32_t>(dividend >> 32u);
      const std::uint32_t foldedHighRemainder = dividendHigh % divisorLow;
      const std::uint64_t foldedDividend =
        (static_cast<std::uint64_t>(foldedHighRemainder) << 32u) | static_cast<std::uint32_t>(dividend);
      remainder = foldedDividend % divisorLow;
    } else {
      std::uint64_t scaledDivisor = divisor;
      std::uint64_t scaledDividend = dividend;
      while ((scaledDivisor >> 32u) != 0u) {
        scaledDivisor >>= 1u;
        scaledDividend >>= 1u;
      }

      const std::uint32_t quotient =
        static_cast<std::uint32_t>(scaledDividend / static_cast<std::uint32_t>(scaledDivisor));
      const std::uint64_t lowProduct = static_cast<std::uint64_t>(static_cast<std::uint32_t>(divisor))
        * static_cast<std::uint64_t>(quotient);
      const std::uint64_t highProduct = static_cast<std::uint64_t>(static_cast<std::uint32_t>(divisor >> 32u))
        * static_cast<std::uint64_t>(quotient);

      const std::uint32_t lowProductHigh32 = static_cast<std::uint32_t>(lowProduct >> 32u);
      const std::uint32_t highProductLow32 = static_cast<std::uint32_t>(highProduct);
      const std::uint64_t summedHigh =
        static_cast<std::uint64_t>(lowProductHigh32) + static_cast<std::uint64_t>(highProductLow32);
      const bool carryOut = summedHigh > 0xFFFFFFFFull;

      std::uint64_t product =
        (static_cast<std::uint64_t>(static_cast<std::uint32_t>(summedHigh)) << 32u) | static_cast<std::uint32_t>(lowProduct);
      if (carryOut || product > dividend) {
        product -= divisor;
      }

      remainder = dividend - product;
    }

    return negateResult ? (0ull - remainder) : remainder;
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
   * Address: 0x00A8958C (FUN_00A8958C, ___CxxFrameHandler3)
   *
   * What it does:
   * Thin front-end for `__InternalCxxFrameHandler` that forwards the handler
   * context with zeroed catch-depth/target recursion lanes.
   */
  extern "C" int __cdecl __CxxFrameHandler3(
    const void* const functionInfo,
    EXCEPTION_RECORD* const exceptionRecord,
    void* const registrationNode,
    CONTEXT* const contextRecord,
    void* const dispatcherContext
  )
  {
    return __InternalCxxFrameHandler(
      exceptionRecord,
      registrationNode,
      contextRecord,
      dispatcherContext,
      functionInfo,
      0,
      nullptr,
      0
    );
  }

  /**
   * Address: 0x00AA39A0 (FUN_00AA39A0, __CallSettingFrame)
   *
   * What it does:
   * Publishes pre/post non-local-goto frame state for one unwind action,
   * executes the target action callback, and remaps notify code `0x100` to `2`
   * on the post-call publication lane.
   */
  extern "C" int __stdcall _CallSettingFrame(const int targetAction, const int establisherFrame, const int notifyCode)
  {
    using RuntimeSettingFrameTarget = int(__cdecl*)();

    const std::uint32_t frameEbpValue = static_cast<std::uint32_t>(establisherFrame + 0x0C);
    const auto actionTarget = reinterpret_cast<RuntimeSettingFrameTarget>(RuntimePublishNonLocalGotoState(
      static_cast<std::uint32_t>(targetAction), frameEbpValue, static_cast<std::uint32_t>(notifyCode)
    ));

    const int actionResult = actionTarget();
    const int postNotifyCode = (notifyCode == 0x100) ? 2 : notifyCode;
    return static_cast<int>(RuntimePublishNonLocalGotoState(
      static_cast<std::uint32_t>(actionResult), frameEbpValue, static_cast<std::uint32_t>(postNotifyCode)
    ));
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
   * Address: 0x00A9BB88 (FUN_00A9BB88, __fileno)
   *
   * What it does:
   * Returns one CRT stream file-descriptor lane (`FILE::_file`) and reports
   * invalid-parameter semantics for null stream input.
   */
  extern "C" int __cdecl __fileno(std::FILE* const stream)
  {
    if (stream != nullptr) {
      return legacy_file(stream)._file;
    }

    *_errno() = EINVAL;
    _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    return -1;
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

  /**
   * Address: 0x00A83F31 (FUN_00A83F31, _fpclass helper lane)
   *
   * What it does:
   * Classifies one double into CRT `_FPCLASS_*` categories using recovered
   * special-value and sign/magnitude tests.
   */
  extern "C" int __cdecl RuntimeFpclass(const double value)
  {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const std::uint32_t lowDword = static_cast<std::uint32_t>(bits);
    const std::uint32_t highDword = static_cast<std::uint32_t>(bits >> 32u);

    switch (RuntimeClassifyDoubleWords(lowDword, highDword)) {
      case 1:
        return _FPCLASS_PINF;
      case 2:
        return _FPCLASS_NINF;
      case 3:
        return _FPCLASS_QNAN;
      case 4:
        return _FPCLASS_SNAN;
      default:
        break;
    }

    const bool negative = (highDword & 0x80000000u) != 0u;
    const bool zeroExponent = (highDword & 0x7FF00000u) == 0u;
    const bool nonZeroMantissa = ((highDword & 0x000FFFFFu) != 0u) || (lowDword != 0u);
    if (zeroExponent && nonZeroMantissa) {
      return negative ? _FPCLASS_ND : _FPCLASS_PD;
    }
    if (value == 0.0) {
      return negative ? _FPCLASS_NZ : _FPCLASS_PZ;
    }
    return negative ? _FPCLASS_NN : _FPCLASS_PN;
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

  struct RuntimeTidDataRandomView
  {
    std::uint8_t mReserved00_13[0x14];
    std::uint32_t mHoldRand;
  };
  static_assert(
    offsetof(RuntimeTidDataRandomView, mHoldRand) == 0x14,
    "RuntimeTidDataRandomView::mHoldRand offset must be 0x14"
  );

  struct RuntimeXcptActionEntry
  {
    std::uint32_t mExceptionCode; // +0x00
    std::int32_t mSignalNumber;   // +0x04
    void* mSignalHandler;         // +0x08
  };
  static_assert(sizeof(RuntimeXcptActionEntry) == 0x0C, "RuntimeXcptActionEntry size must be 0x0C");

  struct RuntimeTidDataXcptView
  {
    std::uint8_t mReserved00_5B[0x5C];
    RuntimeXcptActionEntry* mXcptActionTable; // +0x5C
    void* mThreadExceptionPointers;           // +0x60
    std::int32_t mThreadFpeCode;              // +0x64
  };
  static_assert(
    offsetof(RuntimeTidDataXcptView, mXcptActionTable) == 0x5C,
    "RuntimeTidDataXcptView::mXcptActionTable offset must be 0x5C"
  );
  static_assert(
    offsetof(RuntimeTidDataXcptView, mThreadExceptionPointers) == 0x60,
    "RuntimeTidDataXcptView::mThreadExceptionPointers offset must be 0x60"
  );
  static_assert(
    offsetof(RuntimeTidDataXcptView, mThreadFpeCode) == 0x64,
    "RuntimeTidDataXcptView::mThreadFpeCode offset must be 0x64"
  );

  struct RuntimeTidDataProcessingThrowView
  {
    std::uint8_t mReserved00_8F[0x90];
    std::int32_t mProcessingThrow; // +0x90
  };
  static_assert(
    offsetof(RuntimeTidDataProcessingThrowView, mProcessingThrow) == 0x90,
    "RuntimeTidDataProcessingThrowView::mProcessingThrow offset must be 0x90"
  );

  struct RuntimeTidDataCxxRethrowView
  {
    std::uint8_t mReserved00_20B[0x20C];
    std::int32_t mCxxRethrow; // +0x20C
  };
  static_assert(
    offsetof(RuntimeTidDataCxxRethrowView, mCxxRethrow) == 0x20C,
    "RuntimeTidDataCxxRethrowView::mCxxRethrow offset must be 0x20C"
  );

  /**
   * Address: 0x00AA2882 (FUN_00AA2882, std::terminate@@YAXXZ)
   *
   * IDA signature:
   * void __cdecl __noreturn std::terminate(int **a1);
   *
   * What it does:
   * MSVC `std::terminate`-adjacent EH state helper: reads the first dword of
   * the provided exception-record pointer and acts on two classic MSVC C++
   * EH signatures:
   *   * `0xE0434F4D` ("MOC", managed/native boundary EH) — if the thread's
   *     `_ProcessingThrow` counter is positive, decrement it.
   *   * `0xE06D7363` ("csm", classic VC C++ EH) — clear `_ProcessingThrow`
   *     and dispatch the real `terminate` action (which does not return).
   *   * Any other code — no-op return.
   *
   * Despite the symbol name, the binary's emitted body is the MSVC CRT
   * thread-unwind filter that runs before `_CxxThrowException` handoff;
   * it coordinates the "in-flight throw" flag with the configured
   * terminate action.
   */
  extern "C" void __cdecl RuntimeUpdateProcessingThrowForExceptionRecord(
    EXCEPTION_RECORD** const exceptionRecordSlot
  )
  {
    if (exceptionRecordSlot == nullptr || *exceptionRecordSlot == nullptr) {
      return;
    }

    constexpr DWORD kMsvcManagedNativeEh = 0xE0434F4Du;  // "MOC"
    constexpr DWORD kMsvcClassicCppEh = 0xE06D7363u;     // "csm"

    const DWORD exceptionCode = (*exceptionRecordSlot)->ExceptionCode;
    auto* const threadData = reinterpret_cast<RuntimeTidDataProcessingThrowView*>(__getptd());
    if (threadData == nullptr) {
      return;
    }

    if (exceptionCode == kMsvcManagedNativeEh) {
      if (threadData->mProcessingThrow > 0) {
        --threadData->mProcessingThrow;
      }
    } else if (exceptionCode == kMsvcClassicCppEh) {
      threadData->mProcessingThrow = 0;
      ::terminate();
    }
  }

  /**
   * Address: 0x00A99839 (FUN_00A99839)
   *
   * What it does:
   * Returns the current thread-data slot that stores the active
   * exception-pointer lane (`_tpxcptinfoptrs`).
   */
  extern "C" void** __cdecl RuntimeGetThreadExceptionPointersSlot()
  {
    auto* const threadData = reinterpret_cast<RuntimeTidDataXcptView*>(__getptd());
    return (threadData != nullptr) ? &threadData->mThreadExceptionPointers : nullptr;
  }

  /**
   * Address: 0x00AA29A7 (FUN_00AA29A7)
   *
   * What it does:
   * Validates one classic VC C++ EH record (`0xE06D7363` + `0x1993052x`
   * signature, rethrow lane) and marks current `_tiddata` as rethrowing.
   */
  extern "C" int __cdecl RuntimeMarkCxxRethrowIfClassicException(EXCEPTION_RECORD** const exceptionRecordSlot)
  {
    if (exceptionRecordSlot == nullptr || *exceptionRecordSlot == nullptr) {
      return 0;
    }

    constexpr DWORD kCppEhExceptionCode = 0xE06D7363u;
    constexpr ULONG_PTR kCppEhSignature0 = 0x19930520u;
    constexpr ULONG_PTR kCppEhSignature1 = 0x19930521u;
    constexpr ULONG_PTR kCppEhSignature2 = 0x19930522u;

    const EXCEPTION_RECORD* const exceptionRecord = *exceptionRecordSlot;
    if (exceptionRecord->ExceptionCode != kCppEhExceptionCode) {
      return 0;
    }

    if (exceptionRecord->NumberParameters != 3u) {
      return 0;
    }

    const ULONG_PTR signature = exceptionRecord->ExceptionInformation[0];
    if (signature != kCppEhSignature0
        && signature != kCppEhSignature1
        && signature != kCppEhSignature2) {
      return 0;
    }

    if (exceptionRecord->ExceptionInformation[2] != 0u) {
      return 0;
    }

    auto* const threadData = reinterpret_cast<RuntimeTidDataCxxRethrowView*>(__getptd());
    if (threadData != nullptr) {
      threadData->mCxxRethrow = 1;
    }
    return 1;
  }

  using RuntimeSignalHandler = void(__cdecl*)(int);
  using RuntimeFpeSignalHandler = void(__cdecl*)(int, int);

  extern "C" int _XcptActTabCount;
  extern "C" int _First_FPE_Indx;
  extern "C" int _Num_FPE;

  constexpr std::int32_t kXcptActionReturnContinueExecution = 5;
  constexpr std::int32_t kXcptActionDefault = 1;
  constexpr std::int32_t kSignalFpe = 8;

  enum class RuntimeFpeCode : std::int32_t
  {
    Invalid = _FPE_INVALID,
    Denormal = _FPE_DENORMAL,
    ZeroDivide = _FPE_ZERODIVIDE,
    Overflow = _FPE_OVERFLOW,
    Underflow = _FPE_UNDERFLOW,
    Inexact = _FPE_INEXACT,
    StackOverflow = _FPE_STACKOVERFLOW,
  };

  /**
   * What it does:
   * Maps a structured float exception code to its `_FPE_*` sub-code for the
   * SIGFPE handler dispatch, falling back to `fallbackCode` for unknown codes.
   */
  [[nodiscard]] std::int32_t RuntimeMapXcptCodeToFpe(
    const std::uint32_t exceptionCode,
    const std::int32_t fallbackCode
  ) noexcept
  {
    switch (exceptionCode) {
      case STATUS_FLOAT_DIVIDE_BY_ZERO:
        return static_cast<std::int32_t>(RuntimeFpeCode::ZeroDivide);
      case STATUS_FLOAT_INVALID_OPERATION:
        return static_cast<std::int32_t>(RuntimeFpeCode::Invalid);
      case STATUS_FLOAT_OVERFLOW:
        return static_cast<std::int32_t>(RuntimeFpeCode::Overflow);
      case STATUS_FLOAT_UNDERFLOW:
        return static_cast<std::int32_t>(RuntimeFpeCode::Underflow);
      case STATUS_FLOAT_DENORMAL_OPERAND:
        return static_cast<std::int32_t>(RuntimeFpeCode::Denormal);
      case STATUS_FLOAT_INEXACT_RESULT:
        return static_cast<std::int32_t>(RuntimeFpeCode::Inexact);
      case STATUS_FLOAT_STACK_CHECK:
        return static_cast<std::int32_t>(RuntimeFpeCode::StackOverflow);
      default:
        return fallbackCode;
    }
  }

  /**
   * Address: 0x00A95A3D (FUN_00A95A3D, __fls_getvalue)
   *
   * What it does:
   * Reads the per-thread FLS getter thunk from `_getvalueindex` TLS storage
   * and dispatches one `flsIndex` lookup through that thunk.
   */
  extern "C" int __stdcall __fls_getvalue(const int flsIndex)
  {
    using RuntimeTlsGetValueThunk = int(__stdcall*)(int);
    auto* const flsGetValueThunk = reinterpret_cast<RuntimeTlsGetValueThunk>(::TlsGetValue(_getvalueindex));
    return flsGetValueThunk(flsIndex);
  }

  /**
   * Address: 0x00A993F0 (FUN_00A993F0, _FindPESection)
   *
   * What it does:
   * Resolves one PE section header containing `rva` by scanning section ranges
   * from the image's NT header table.
   */
  extern "C" IMAGE_SECTION_HEADER* __cdecl _FindPESection(IMAGE_DOS_HEADER* const imageBase, const DWORD_PTR rva)
  {
    auto* const ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(
      reinterpret_cast<std::uint8_t*>(imageBase) + static_cast<std::uint32_t>(imageBase->e_lfanew)
    );
    const unsigned int sectionCount = static_cast<unsigned int>(ntHeader->FileHeader.NumberOfSections);
    auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
      reinterpret_cast<std::uint8_t*>(&ntHeader->OptionalHeader)
      + static_cast<std::size_t>(ntHeader->FileHeader.SizeOfOptionalHeader)
    );

    for (unsigned int sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex, ++section) {
      const DWORD_PTR sectionRva = static_cast<DWORD_PTR>(section->VirtualAddress);
      const DWORD_PTR sectionEnd = sectionRva + static_cast<DWORD_PTR>(section->Misc.PhysicalAddress);
      if (rva >= sectionRva && rva < sectionEnd) {
        return section;
      }
    }

    return nullptr;
  }

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

  constexpr int kRuntimeSecondsPerDay = 86'400;
  constexpr int kRuntimeSecondsPerYear = 31'536'000;
  constexpr int kRuntimeSecondsPerLeapYear = 31'622'400;
  constexpr int kRuntimeSecondsPerFourYearCycle = 126'230'400;

  constexpr int kRuntimeMonthOffsets[13] = {
    -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364
  };

  constexpr int kRuntimeLeapMonthOffsets[13] = {
    -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
  };

  /**
   * Address: 0x00A9D625 (FUN_00A9D625)
   *
   * What it does:
   * Converts one non-negative 32-bit epoch-seconds lane into CRT `tm` fields
   * (`sec/min/hour/mday/mon/year/wday/yday/isdst`) and reports `EINVAL` for
   * null or negative inputs.
   */
  int RuntimeConvertEpochSecondsToTm32(
    int* const outTimeFields,
    const int* const epochSeconds
  )
  {
    if (outTimeFields == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    std::memset(outTimeFields, 0xFF, 0x24u);
    if (epochSeconds == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    const int totalSeconds = *epochSeconds;
    if (totalSeconds < 0) {
      *_errno() = EINVAL;
      return EINVAL;
    }

    int isLeapYearLane = 0;
    const int fourYearCycles = totalSeconds / kRuntimeSecondsPerFourYearCycle;
    int secondsWithinCycle = totalSeconds % kRuntimeSecondsPerFourYearCycle;
    int yearSince1900 = fourYearCycles * 4 + 70;

    if (secondsWithinCycle >= kRuntimeSecondsPerYear) {
      secondsWithinCycle -= kRuntimeSecondsPerYear;
      ++yearSince1900;
      if (secondsWithinCycle >= kRuntimeSecondsPerYear) {
        secondsWithinCycle -= kRuntimeSecondsPerYear;
        ++yearSince1900;
        if (secondsWithinCycle < kRuntimeSecondsPerLeapYear) {
          isLeapYearLane = 1;
        } else {
          ++yearSince1900;
          secondsWithinCycle -= kRuntimeSecondsPerLeapYear;
        }
      }
    }

    outTimeFields[5] = yearSince1900;
    outTimeFields[7] = secondsWithinCycle / kRuntimeSecondsPerDay;
    const int secondsWithinDay = secondsWithinCycle % kRuntimeSecondsPerDay;

    const int* monthOffsets = isLeapYearLane != 0 ? kRuntimeLeapMonthOffsets : kRuntimeMonthOffsets;
    const int dayOfYear = outTimeFields[7];

    int monthScanIndex = 1;
    while (monthOffsets[monthScanIndex] < dayOfYear) {
      ++monthScanIndex;
    }

    const int monthIndex = monthScanIndex - 1;
    outTimeFields[4] = monthIndex;
    outTimeFields[3] = dayOfYear - monthOffsets[monthIndex];
    outTimeFields[8] = 0;
    outTimeFields[6] = (totalSeconds / kRuntimeSecondsPerDay + 4) % 7;
    outTimeFields[2] = secondsWithinDay / 3600;

    const int secondsWithinHour = secondsWithinDay % 3600;
    outTimeFields[1] = secondsWithinHour / 60;
    outTimeFields[0] = secondsWithinHour % 60;
    return 0;
  }

  /**
   * Address: 0x00A8E337 (FUN_00A8E337, rand)
   *
   * What it does:
   * Advances the per-thread CRT linear-congruential generator state and
   * returns one 15-bit random value from bits `[30:16]`.
   */
  extern "C" int __cdecl rand()
  {
    auto* const threadData = reinterpret_cast<RuntimeTidDataRandomView*>(__getptd());
    const std::uint32_t nextState = threadData->mHoldRand * 0x343FDu + 0x269EC3u;
    threadData->mHoldRand = nextState;
    return static_cast<int>((nextState >> 16u) & 0x7FFFu);
  }

  /**
   * Address: 0x00A8E32A (FUN_00A8E32A, srand)
   *
   * What it does:
   * Seeds the per-thread CRT linear-congruential random state lane.
   */
  void __cdecl Runtime_srand(const int seed)
  {
    auto* const threadData = reinterpret_cast<RuntimeTidDataRandomView*>(__getptd());
    threadData->mHoldRand = static_cast<std::uint32_t>(seed);
  }

  /**
   * Address: 0x00A995C2 (FUN_00A995C2, _XcptFilter)
   *
   * What it does:
   * Resolves one CRT `_tiddata` exception-action entry for the incoming SEH
   * code, dispatches configured signal handlers (including SIGFPE remap lanes),
   * and returns the CRT filter decision code.
   */
  extern "C" int __cdecl _XcptFilter(const int exceptionCode, _EXCEPTION_POINTERS* const exceptionPointers)
  {
    auto* const threadData = reinterpret_cast<RuntimeTidDataXcptView*>(RuntimeGetPtdNoExit());
    if (threadData == nullptr) {
      return 0;
    }

    RuntimeXcptActionEntry* const actionTable = threadData->mXcptActionTable;
    const int actionCount = _XcptActTabCount;

    RuntimeXcptActionEntry* matchedAction = nullptr;
    for (int index = 0; index < actionCount; ++index) {
      RuntimeXcptActionEntry* const action = &actionTable[index];
      if (action->mExceptionCode == static_cast<std::uint32_t>(exceptionCode)) {
        matchedAction = action;
        break;
      }
    }

    if (matchedAction == nullptr || matchedAction->mSignalHandler == nullptr) {
      return 0;
    }

    void* const rawHandler = matchedAction->mSignalHandler;
    if (rawHandler == reinterpret_cast<void*>(kXcptActionReturnContinueExecution)) {
      matchedAction->mSignalHandler = nullptr;
      return 1;
    }

    if (rawHandler == reinterpret_cast<void*>(kXcptActionDefault)) {
      return -1;
    }

    void* const previousExceptionPointers = threadData->mThreadExceptionPointers;
    threadData->mThreadExceptionPointers = exceptionPointers;

    const int signalNumber = matchedAction->mSignalNumber;
    if (signalNumber == kSignalFpe) {
      const int firstFpeIndex = _First_FPE_Indx;
      const int fpeCount = _Num_FPE;
      for (int index = firstFpeIndex; index < firstFpeIndex + fpeCount; ++index) {
        actionTable[index].mSignalHandler = nullptr;
      }

      const int previousFpeCode = threadData->mThreadFpeCode;
      threadData->mThreadFpeCode =
        RuntimeMapXcptCodeToFpe(matchedAction->mExceptionCode, threadData->mThreadFpeCode);
      reinterpret_cast<RuntimeFpeSignalHandler>(rawHandler)(kSignalFpe, threadData->mThreadFpeCode);
      threadData->mThreadFpeCode = previousFpeCode;
    } else {
      matchedAction->mSignalHandler = nullptr;
      reinterpret_cast<RuntimeSignalHandler>(rawHandler)(signalNumber);
    }

    threadData->mThreadExceptionPointers = previousExceptionPointers;
    return -1;
  }

  struct RuntimeOsErrorErrnoMapEntry
  {
    unsigned long osErrorCode = 0; // +0x00
    int crtErrnoValue = 0;         // +0x04
  };
  static_assert(
    offsetof(RuntimeOsErrorErrnoMapEntry, osErrorCode) == 0x00,
    "RuntimeOsErrorErrnoMapEntry::osErrorCode offset must be 0x00"
  );
  static_assert(
    offsetof(RuntimeOsErrorErrnoMapEntry, crtErrnoValue) == 0x04,
    "RuntimeOsErrorErrnoMapEntry::crtErrnoValue offset must be 0x04"
  );
  static_assert(sizeof(RuntimeOsErrorErrnoMapEntry) == 0x08, "RuntimeOsErrorErrnoMapEntry size must be 0x08");

  static constexpr RuntimeOsErrorErrnoMapEntry kRuntimeOsErrorErrnoMap[0x2D] = {
    {1u, 22},    {2u, 2},     {3u, 2},    {4u, 24},    {5u, 13},    {6u, 9},    {7u, 12},    {8u, 12},
    {9u, 12},    {10u, 7},    {11u, 8},   {12u, 22},   {13u, 22},   {15u, 2},   {16u, 13},   {17u, 18},
    {18u, 2},    {33u, 13},   {53u, 2},   {65u, 13},   {67u, 2},    {80u, 17},  {82u, 13},   {83u, 13},
    {87u, 22},   {89u, 11},   {108u, 13}, {109u, 32},  {112u, 28},  {114u, 9},  {6u, 22},    {128u, 10},
    {129u, 10},  {130u, 9},   {131u, 22}, {132u, 13},  {145u, 41},  {158u, 13}, {161u, 2},   {164u, 11},
    {167u, 13},  {183u, 17},  {206u, 2},  {215u, 11},  {1816u, 12},
  };

  /**
   * Address: 0x00A83371 (FUN_00A83371, get_errno_from_oserr)
   *
   * What it does:
   * Maps one Win32 OS error code to CRT errno using the 45-entry static map,
   * with range fallbacks matching VC8 `_dosmaperr` behavior.
   */
  extern "C" int __cdecl get_errno_from_oserr(const unsigned long osErrorCode)
  {
    for (const RuntimeOsErrorErrnoMapEntry& entry : kRuntimeOsErrorErrnoMap) {
      if (entry.osErrorCode == osErrorCode) {
        return entry.crtErrnoValue;
      }
    }

    if ((osErrorCode - 19u) <= 0x11u) {
      return EACCES;
    }
    if ((osErrorCode - 188u) <= 0x0Eu) {
      return ENOEXEC;
    }
    return EINVAL;
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

  [[nodiscard]] bool RuntimeIsPathSeparator(const char value) noexcept
  {
    return value == '\\' || value == '/';
  }

  [[nodiscard]] bool RuntimeIsPathSeparator(const wchar_t value) noexcept
  {
    return value == L'\\' || value == L'/';
  }

  /**
   * Address: 0x00A94AA4 (FUN_00A94AA4)
   *
   * What it does:
   * Thunk lane that forwards one stream clear-error request to `clearerr_s`.
   */
  extern "C" int __cdecl RuntimeClearerrSafeThunk(std::FILE* const stream)
  {
    return ::clearerr_s(stream);
  }

  /**
   * Address: 0x00A94B30 (FUN_00A94B30, _waccess wrapper lane)
   *
   * What it does:
   * Returns `0` on access success and `-1` on failure by forwarding to
   * `_waccess_s`.
   */
  extern "C" int __cdecl RuntimeWaccess(const wchar_t* const path, const int mode)
  {
    return (::_waccess_s(path, mode) == 0) ? 0 : -1;
  }

  /**
   * Address: 0x00A94C25 (FUN_00A94C25, _tell wrapper lane)
   *
   * What it does:
   * Returns the current file position by forwarding to `_lseek(fd, 0, SEEK_CUR)`.
   */
  extern "C" long __cdecl RuntimeLseek32(
    const int fileHandle,
    const long distance,
    const int moveMethod
  );

  extern "C" long __cdecl RuntimeTell(const int fileHandle)
  {
    return RuntimeLseek32(fileHandle, 0L, SEEK_CUR);
  }

  /**
   * Address: 0x00A90F12 (FUN_00A90F12, _snwprintf)
   * Mangled: sub_A90F12
   *
   * IDA signature:
   * int sub_A90F12(char *arg0, unsigned int a2, wchar_t *a3, ...);
   *
   * What it does:
   * MSVC CRT wide `_snwprintf(buffer, count, format, ...)`. Rejects null
   * format pointer or (non-zero count with null buffer) with `errno=EINVAL`
   * and `_invalid_parameter`. Otherwise seeds a string-mode `FILE`
   * (`_flag = _IOWRT | _IOSTRG = 66`), binds the buffer as both `_base`
   * and `_ptr`, clamps `_cnt` to `2 * count` (bytes, wide char span) or
   * `INT_MAX` when the count exceeds 0x3FFFFFFF, dispatches to
   * `_woutput_l(fh, fmt, nullptr, va)`, then writes a trailing L'\0' byte
   * pair (via `_cnt` decrement + `_flsbuf` on overflow) and returns the
   * number of wide characters emitted (the terminator itself is excluded
   * from the returned count).
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
   * Mangled: sub_A94C36
   *
   * IDA signature:
   * int __cdecl sub_A94C36(int a1);
   *
   * What it does:
   * MSVC CRT `_filelength(fd)` implementation. Returns the total length of
   * the open file descriptor's underlying file (signed long) or `-1` on
   * error (setting `errno = EBADF`). Rejects the sentinel pseudo-handle
   * `-2`, validates `fd` against `_nhandle`, confirms the handle is open
   * (`FOPEN` bit in `_pioinfo[fd]->osfile`), then under the per-handle
   * spinlock:
   *   curPos = _lseek_nolock(fd, 0, SEEK_CUR)
   *   endPos = _lseek_nolock(fd, 0, SEEK_END)
   *   if (curPos != endPos) _lseek_nolock(fd, curPos, SEEK_SET)
   *   return endPos
   */
  extern "C" long __cdecl RuntimeFileLength(const int fileHandle)
  {
    if (fileHandle == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1L;
    }

    if (fileHandle < 0 || fileHandle >= _nhandle) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      ::_invalid_parameter_noinfo();
      return -1L;
    }

    RuntimeIoInfo* const ioInfo = __pioinfo[fileHandle >> 5] + (fileHandle & 0x1F);
    if ((ioInfo->osfile & 0x01u) == 0u) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      ::_invalid_parameter_noinfo();
      return -1L;
    }

    // Forward to the MSVC CRT implementation which performs the per-fd
    // spinlock + _lseek_nolock(SEEK_CUR)/_lseek_nolock(SEEK_END) dance and
    // restores the original position when different. This preserves the
    // binary's 1:1 behavior (including errno/doserrno propagation) without
    // reimplementing the spinlock primitives.
    return ::_filelength(fileHandle);
  }

  /**
   * Address: 0x00A9CB58 (FUN_00A9CB58, _lseek)
   *
   * What it does:
   * MSVC CRT `_lseek(fd, distance, origin)` implementation. Validates the file
   * descriptor (the special pseudo-handle `-2` and out-of-range/closed handles
   * all fail with `EBADF`), enters the per-fd spinlock, forwards to the
   * `_lseek_nolock` path while holding the lock when the file is still open,
   * and returns `-1` otherwise. Restores the spinlock on all exit paths.
   *
   * IDA signature:
   * DWORD __cdecl sub_A9CB58(int a1, LONG lDistanceToMove, DWORD dwMoveMethod);
   */
  extern "C" long __cdecl RuntimeLseek32(
    const int fileHandle,
    const long distance,
    const int moveMethod
  )
  {
    if (fileHandle == -2) {
      *RuntimeDosErrno() = 0;
      *_errno() = EBADF;
      return -1L;
    }

    // Forward to CRT `_lseek`, which performs the `_pioinfo` bounds check,
    // `FOPEN` flag verification, per-handle locking, and the `_lseek_nolock`
    // dispatch preserved by the original binary.
    return ::_lseek(fileHandle, distance, moveMethod);
  }

  /**
   * Address: 0x00A94DF0 (FUN_00A94DF0)
   *
   * What it does:
   * Returns the low dword of one arithmetic right shift over a signed 64-bit
   * lane, including saturated sign-fill behavior for shifts >= 64.
   */
  extern "C" int __cdecl RuntimeArithmeticShiftRightI64ToLowDword(
    const std::int64_t value,
    const std::uint8_t shift
  ) noexcept
  {
    if (shift >= 64u) {
      return static_cast<int>(value < 0 ? -1 : 0);
    }

    if (shift >= 32u) {
      const std::int32_t high = static_cast<std::int32_t>(value >> 32);
      return high >> (shift & 0x1Fu);
    }

    return static_cast<int>(value >> (shift & 0x1Fu));
  }

  /**
   * Address: 0x00AAEEC4 (FUN_00AAEEC4)
   *
   * What it does:
   * Validates whether one wide path names a UNC root/share lane:
   * `\\server\\share` (optionally with one trailing slash).
   */
  extern "C" BOOL __cdecl RuntimeIsUncPathRootedWide(const wchar_t* const path)
  {
    if (path == nullptr || std::wcslen(path) < 5u) {
      return FALSE;
    }

    const auto isSlash = [](const wchar_t value) noexcept { return value == L'\\' || value == L'/'; };
    if (!isSlash(path[0]) || !isSlash(path[1])) {
      return FALSE;
    }
    if (path[2] == L'\0' || isSlash(path[2])) {
      return FALSE;
    }

    const wchar_t* serverEnd = path + 3;
    while (*serverEnd != L'\0' && !isSlash(*serverEnd)) {
      ++serverEnd;
    }
    if (*serverEnd == L'\0') {
      return FALSE;
    }

    const wchar_t* shareStart = serverEnd + 1;
    if (*shareStart == L'\0') {
      return FALSE;
    }

    const wchar_t* shareEnd = shareStart;
    while (*shareEnd != L'\0' && !isSlash(*shareEnd)) {
      ++shareEnd;
    }

    if (*shareEnd == L'\0') {
      return TRUE;
    }
    return (shareEnd[1] == L'\0') ? TRUE : FALSE;
  }

  /**
   * Address: 0x00AB0485 (FUN_00AB0485)
   *
   * What it does:
   * Validates whether one narrow path names a UNC root/share lane:
   * `\\server\\share` (optionally with one trailing slash).
   */
  extern "C" BOOL __cdecl RuntimeIsUncPathRootedNarrow(const char* const path)
  {
    if (path == nullptr || std::strlen(path) < 5u) {
      return FALSE;
    }

    const auto isSlash = [](const char value) noexcept { return value == '\\' || value == '/'; };
    if (!isSlash(path[0]) || !isSlash(path[1])) {
      return FALSE;
    }
    if (path[2] == '\0' || isSlash(path[2])) {
      return FALSE;
    }

    const char* serverEnd = path + 3;
    while (*serverEnd != '\0' && !isSlash(*serverEnd)) {
      ++serverEnd;
    }
    if (*serverEnd == '\0') {
      return FALSE;
    }

    const char* shareStart = serverEnd + 1;
    if (*shareStart == '\0') {
      return FALSE;
    }

    const char* shareEnd = shareStart;
    while (*shareEnd != '\0' && !isSlash(*shareEnd)) {
      ++shareEnd;
    }

    if (*shareEnd == '\0') {
      return TRUE;
    }
    return (shareEnd[1] == '\0') ? TRUE : FALSE;
  }

  /**
   * Address: 0x009A18D0 (FUN_009A18D0, _setdrive)
   *
   * What it does:
   * Validates one 1-based DOS drive index, builds the `<letter>:` root path,
   * and asks Win32 to switch the current directory to that drive root.
   */
  extern "C" int __cdecl _setdrive(const int drive)
  {
    if (static_cast<std::uint32_t>(drive - 1) > 0x1Eu) {
      return -1;
    }

    const wchar_t driveRoot[3]{
      static_cast<wchar_t>(drive + L'@'),
      L':',
      L'\0',
    };
    return (::SetCurrentDirectoryW(driveRoot) != FALSE) ? 0 : -1;
  }

  /**
   * Address: 0x00AAECDD (FUN_00AAECDD)
   *
   * What it does:
   * Counts non-NUL UTF-16 code units in one wide-string lane, capped by
   * `maxCount`.
   */
  [[maybe_unused]] unsigned int RuntimeBoundedWideLength(
    const wchar_t* text,
    const unsigned int maxCount
  ) noexcept
  {
    unsigned int count = 0;
    if (count >= maxCount) {
      return count;
    }

    const std::uint16_t* cursor = reinterpret_cast<const std::uint16_t*>(text);
    while (*cursor != 0u) {
      ++count;
      ++cursor;
      if (count >= maxCount) {
        break;
      }
    }

    return count;
  }

  /**
   * Address: 0x00A9B1CA (FUN_00A9B1CA)
   *
   * What it does:
   * Copies one aligned `0x80`-byte lane block per iteration from `source` to
   * `destination`, with iteration count derived from `byteCount >> 7`.
   */
  [[maybe_unused]] void RuntimeCopyAligned128ByteBlocksSse(
    __m128i* destination,
    const __m128i* source,
    const unsigned int byteCount
  ) noexcept
  {
    unsigned int blockCount = byteCount >> 7;
    do {
      const __m128i lane0 = _mm_load_si128(source + 0);
      const __m128i lane1 = _mm_load_si128(source + 1);
      const __m128i lane2 = _mm_load_si128(source + 2);
      const __m128i lane3 = _mm_load_si128(source + 3);
      _mm_store_si128(destination + 0, lane0);
      _mm_store_si128(destination + 1, lane1);
      _mm_store_si128(destination + 2, lane2);
      _mm_store_si128(destination + 3, lane3);

      const __m128i lane4 = _mm_load_si128(source + 4);
      const __m128i lane5 = _mm_load_si128(source + 5);
      const __m128i lane6 = _mm_load_si128(source + 6);
      const __m128i lane7 = _mm_load_si128(source + 7);
      _mm_store_si128(destination + 4, lane4);
      _mm_store_si128(destination + 5, lane5);
      _mm_store_si128(destination + 6, lane6);
      _mm_store_si128(destination + 7, lane7);

      source += 8;
      destination += 8;
      --blockCount;
    } while (blockCount != 0u);
  }

  /**
   * Address: 0x00A9B251 (FUN_00A9B251, sub_A9B251)
   *
   * IDA signature:
   * int __cdecl sub_A9B251(int a1, int a2, unsigned int a3);
   *
   * Callsite evidence:
   * Three xrefs, including jmp tails from `memmov` (0x00A84A60 → 0x00A84AA2)
   * and `memcpy` (0x00A89190 → 0x00A891D2) plus self-recursion
   * (0x00A9B300 → 0x00A9B251). Both CRT entry points dispatch through this
   * helper (Rule 1 evidence).
   *
   * What it does:
   * SSE-aware aligned `memmove` core. When either `destination` or `source`
   * is not 16-byte aligned the helper takes the slow path:
   *   * if both lanes share the same modulo-16 misalignment, the leading
   *     `(16 - srcAlign)` bytes are copied byte-wise via `std::memmove` and
   *     the routine recurses on the now 16-byte-aligned tail,
   *   * otherwise the entire range is copied byte-wise via `std::memmove`.
   * When both lanes are 16-byte aligned, the bulk
   * `[byteCount - tailBytes)` portion is copied through
   * `RuntimeCopyAligned128ByteBlocksSse` (FUN_00A9B1CA) in `0x80`-byte SSE
   * blocks; the residual `tailBytes = byteCount & 0x7F` bytes are finished
   * with `std::memmove`. Returns `destination` in all paths.
   */
  [[maybe_unused]] void* RuntimeAlignedMemmoveDispatch(
    void* const destination,
    const void* const source,
    const std::size_t byteCount
  ) noexcept
  {
    const auto destAddress = reinterpret_cast<std::uintptr_t>(destination);
    const auto srcAddress = reinterpret_cast<std::uintptr_t>(source);
    const unsigned int destAlign = static_cast<unsigned int>(destAddress & 0xFu);
    const unsigned int srcAlign = static_cast<unsigned int>(srcAddress & 0xFu);

    if ((destAlign | srcAlign) != 0u) {
      if (destAlign == srcAlign) {
        const std::size_t leadingBytes = 16u - srcAlign;
        std::memmove(destination, source, leadingBytes);
        (void)RuntimeAlignedMemmoveDispatch(
          static_cast<char*>(destination) + leadingBytes,
          static_cast<const char*>(source) + leadingBytes,
          byteCount - leadingBytes
        );
      } else {
        std::memmove(destination, source, byteCount);
      }
      return destination;
    }

    const std::size_t tailBytes = byteCount & 0x7Fu;
    if (byteCount != tailBytes) {
      RuntimeCopyAligned128ByteBlocksSse(
        static_cast<__m128i*>(destination),
        static_cast<const __m128i*>(source),
        static_cast<unsigned int>(byteCount - tailBytes)
      );
    }
    if (tailBytes != 0u) {
      const std::size_t consumedBytes = byteCount - tailBytes;
      std::memmove(
        static_cast<char*>(destination) + consumedBytes,
        static_cast<const char*>(source) + consumedBytes,
        tailBytes
      );
    }
    return destination;
  }

  /**
   * Address: 0x00A84FFE (FUN_00A84FFE, getenv_s)
   *
   * What it does:
   * Reads one environment variable value under `_ENV_LOCK`, returns the
   * required buffer length, and performs bounded copy semantics for callers
   * that supply destination storage.
   */
  extern "C" errno_t __cdecl getenv_s(
    size_t* const requiredCountOut,
    char* const destination,
    const rsize_t destinationSize,
    const char* const variableName
  )
  {
    RuntimeLockGuard lockGuard(kRuntimeEnvironmentLock);

    if (requiredCountOut == nullptr || variableName == nullptr ||
        (destination == nullptr && destinationSize != 0u) ||
        (destination != nullptr && destinationSize == 0u))
    {
      if (requiredCountOut != nullptr) {
        *requiredCountOut = 0u;
      }
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *requiredCountOut = 0u;

    if (destination != nullptr) {
      destination[0] = '\0';
    }

    const char* const value = std::getenv(variableName);
    if (value == nullptr) {
      return 0;
    }

    const size_t requiredCount = std::strlen(value) + 1u;
    *requiredCountOut = requiredCount;

    if (destination == nullptr) {
      return 0;
    }

    if (requiredCount > destinationSize) {
      *_errno() = ERANGE;
      return ERANGE;
    }

    const errno_t copyError = strcpy_s(destination, destinationSize, value);
    if (copyError != 0) {
      destination[0] = '\0';
      return copyError;
    }

    return 0;
  }

  namespace
  {
    // Cached result of probing GetEnvironmentStringsW() support: 0 = not yet
    // probed, 1 = natively supported, 2 = unsupported (this CRT's classic
    // ERROR_CALL_NOT_IMPLEMENTED fallback trigger, pre-NT/Win9x heritage).
    int gCrtEnvironmentStringsWSupport = 0;
  }

  // Staging pointer for the raw wide (UTF-16) environment block returned by
  // RuntimeBuildWideEnvironmentBlock, consumed and freed by
  // RuntimePublishWideEnvironFromBlock. Real symbol at 0x00FB8970 (`ptr` in
  // IDA's decompile); also written by the not-yet-recovered `_wputenv`
  // internal (FUN_00ABDD6F).
  extern "C" wchar_t* gCrtRawWideEnvironmentBlock = nullptr;

  // The parsed `wchar_t*` array view of the environment (one pointer per
  // "NAME=value" entry, nullptr-terminated) that `_wgetenv`-family lookups
  // scan. Real symbol at 0x00FB7D78 (`dword_FB7D78` in IDA's decompile) --
  // a VC8-internal staging array, distinct from the published `_wenviron`
  // (0x00FB7D70) the two are compared against each other at 0x00A90805,
  // proving they are separate storage. Also read/written by the
  // not-yet-recovered `_wputenv` internal (FUN_00ABDD6F).
  extern "C" wchar_t** gCrtWideEnvironPointerArray = nullptr;

  /**
   * Address: 0x00AAEB7C (FUN_00AAEB7C, sub_AAEB7C)
   *
   * IDA signature:
   * char *sub_AAEB7C(void);
   *
   * What it does:
   * Builds one heap-owned copy of the process's wide (UTF-16) environment
   * block -- a run of null-terminated `NAME=value` strings ending in an
   * extra null wide character. Prefers the native `GetEnvironmentStringsW`
   * API, caching whether it is supported in `gCrtEnvironmentStringsWSupport`
   * so later calls skip the probe. When the native API fails with
   * `ERROR_CALL_NOT_IMPLEMENTED`, falls back to the ANSI
   * `GetEnvironmentStrings` plus a per-entry `MultiByteToWideChar`
   * conversion into a freshly allocated wide buffer sized exactly to the
   * summed per-entry conversion lengths. Returns `nullptr` on any
   * allocation or conversion failure.
   *
   * Binary quirk preserved: if the very first `MultiByteToWideChar` length
   * probe in the ANSI fallback fails, the function returns `nullptr`
   * without releasing the `GetEnvironmentStrings()` block (every other
   * failure path in this function does release it). This matches the
   * shipped binary exactly, not a mistake introduced here.
   */
  extern "C" wchar_t* __cdecl RuntimeBuildWideEnvironmentBlock()
  {
    LPWCH nativeBlock = nullptr;
    int support = gCrtEnvironmentStringsWSupport;

    if (support == 0) {
      nativeBlock = ::GetEnvironmentStringsW();
      if (nativeBlock != nullptr) {
        support = 1;
      } else if (::GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
        support = 2;
      }
      gCrtEnvironmentStringsWSupport = support;
    }

    if (support == 1) {
      if (nativeBlock == nullptr) {
        nativeBlock = ::GetEnvironmentStringsW();
        if (nativeBlock == nullptr) {
          return nullptr;
        }
      }

      const wchar_t* scan = nativeBlock;
      if (*scan != L'\0') {
        do {
          while (*scan != L'\0') {
            ++scan;
          }
          ++scan;
        } while (*scan != L'\0');
      }

      const std::size_t byteCount = static_cast<std::size_t>(
        reinterpret_cast<const std::uint8_t*>(scan) - reinterpret_cast<const std::uint8_t*>(nativeBlock)
      ) + sizeof(wchar_t);
      wchar_t* const copy = static_cast<wchar_t*>(std::malloc(byteCount));
      if (copy != nullptr) {
        std::memcpy(copy, nativeBlock, byteCount);
      }
      ::FreeEnvironmentStringsW(nativeBlock);
      return copy;
    }

    if (support != 2) {
      return nullptr;
    }

    LPCH const ansiBlock = ::GetEnvironmentStringsA();
    if (ansiBlock == nullptr) {
      return nullptr;
    }

    int requiredWideChars = 0;
    for (const char* entry = ansiBlock; *entry != '\0'; entry += std::strlen(entry) + 1) {
      const int wideLength = ::MultiByteToWideChar(0, MB_PRECOMPOSED, entry, -1, nullptr, 0);
      if (wideLength == 0) {
        // Binary quirk, preserved -- see the Doxygen note above.
        return nullptr;
      }
      requiredWideChars += wideLength;
    }

    wchar_t* const wideBlock = static_cast<wchar_t*>(
      _calloc_crt(static_cast<std::size_t>(requiredWideChars) + 1u, sizeof(wchar_t))
    );
    if (wideBlock == nullptr) {
      ::FreeEnvironmentStringsA(ansiBlock);
      return nullptr;
    }

    const char* ansiCursor = ansiBlock;
    wchar_t* wideCursor = wideBlock;
    if (*ansiCursor != '\0') {
      for (;;) {
        const int remainingWideChars = (requiredWideChars + 1) - static_cast<int>(wideCursor - wideBlock);
        if (::MultiByteToWideChar(0, MB_PRECOMPOSED, ansiCursor, -1, wideCursor, remainingWideChars) == 0) {
          _free_crt(wideBlock);
          ::FreeEnvironmentStringsA(ansiBlock);
          return nullptr;
        }

        ansiCursor += std::strlen(ansiCursor) + 1;
        wideCursor += wstrlen(wideCursor) + 1;
        if (*ansiCursor == '\0') {
          break;
        }
      }
    }

    *wideCursor = L'\0';
    ::FreeEnvironmentStringsA(ansiBlock);
    return wideBlock;
  }

  /**
   * Address: 0x00AAEAA2 (FUN_00AAEAA2, sub_AAEAA2)
   *
   * IDA signature:
   * int sub_AAEAA2(void);
   *
   * What it does:
   * Parses `gCrtRawWideEnvironmentBlock` (built by
   * `RuntimeBuildWideEnvironmentBlock`) into `gCrtWideEnvironPointerArray`,
   * one heap-owned copy per entry, skipping entries that start with `=`
   * (Windows' hidden per-drive current-directory pseudo-variables). Frees
   * the raw block and marks `__env_initialized` on success. Returns `-1`
   * if the raw block is null or any allocation fails, `0` on success.
   */
  extern "C" int __cdecl RuntimePublishWideEnvironFromBlock()
  {
    if (gCrtRawWideEnvironmentBlock == nullptr) {
      return -1;
    }

    int visibleEntryCount = 0;
    for (const wchar_t* entry = gCrtRawWideEnvironmentBlock; *entry != L'\0'; entry += wstrlen(entry) + 1) {
      if (*entry != L'=') {
        ++visibleEntryCount;
      }
    }

    wchar_t** const pointerArray = static_cast<wchar_t**>(
      _calloc_crt(static_cast<std::size_t>(visibleEntryCount) + 1u, sizeof(wchar_t*))
    );
    gCrtWideEnvironPointerArray = pointerArray;
    if (pointerArray == nullptr) {
      return -1;
    }

    wchar_t** writeSlot = pointerArray;
    for (const wchar_t* entry = gCrtRawWideEnvironmentBlock;;) {
      if (*entry == L'\0') {
        _free_crt(gCrtRawWideEnvironmentBlock);
        gCrtRawWideEnvironmentBlock = nullptr;
        *writeSlot = nullptr;
        __env_initialized = 1;
        return 0;
      }

      const std::size_t entryLength = wstrlen(entry);
      const std::size_t entryStride = entryLength + 1u;
      if (*entry != L'=') {
        wchar_t* const entryCopy = static_cast<wchar_t*>(_calloc_crt(entryLength + 1u, sizeof(wchar_t)));
        *writeSlot = entryCopy;
        if (entryCopy == nullptr) {
          _free_crt(gCrtWideEnvironPointerArray);
          gCrtWideEnvironPointerArray = nullptr;
          return -1;
        }

        if (wstrcpy(entryCopy, static_cast<int>(entryStride), entry) != 0) {
          _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
        }
        ++writeSlot;
      }

      entry += entryStride;
    }
  }

  // The CRT's pristine, process-startup-captured wide environment array
  // pointer (real symbol at 0x00FB7D7C) -- compared against
  // gCrtWideEnvironPointerArray (0x00FB7D78) by
  // RuntimePublishWideEnvironmentVariable to detect whether the working
  // array still just aliases the untouched startup snapshot (in which case
  // it must be privately duplicated before any in-place mutation, matching
  // the real MSVCRT `__winitenv` convention). No writer to this symbol
  // appears anywhere in this binary's traced call graph -- consistent with
  // it being set only by CRT process-startup code outside the currently-
  // recovered address range; the role is inferred from observed comparison
  // behavior, not proven via vendored source or an additional xref.
  wchar_t** gCrtWideEnvironStartupSnapshot = nullptr;

  // Cached result of probing SetEnvironmentVariableW() support (real symbol
  // at 0x00F3F7A4) -- a one-way latch like gCrtEnvironmentStringsWSupport
  // above: starts at 1 (assume supported), permanently cleared to 0 the
  // first time SetEnvironmentVariableW fails with ERROR_CALL_NOT_IMPLEMENTED.
  int gCrtSetEnvironmentVariableWSupport = 1;

  /**
   * Address: 0x00ABDCC1 (FUN_00ABDCC1, sub_ABDCC1)
   *
   * IDA signature:
   * int __usercall sub_ABDCC1@<eax>(int a1@<edi>, int a2);
   *
   * What it does:
   * Linear-scans `gCrtWideEnvironPointerArray` for an entry whose first
   * `nameLength` characters case-insensitively match `needleName`
   * (`_wcsnicoll`) and whose character right after that prefix is `=` or
   * the string terminator (a whole-name match, not a prefix hit). Returns
   * the matching entry's index on success, or the negated entry count
   * scanned before reaching the null terminator when nothing matches.
   *
   * DB-integrity fix: was tagged `external_dependency` ("all-external-
   * callees thunk") -- wrong: its only real callee, `_wcsnicoll`, is
   * engine-recovered in this same file, not third-party runtime.
   */
  [[nodiscard]] int RuntimeFindWideEnvironmentEntryIndex(
    const std::uint32_t nameLength,
    const wchar_t* const needleName
  )
  {
    int index = 0;
    for (;; ++index) {
      const wchar_t* const entry = gCrtWideEnvironPointerArray[index];
      if (entry == nullptr) {
        return -index;
      }
      if (_wcsnicoll(needleName, entry, nameLength) == 0) {
        const wchar_t afterPrefix = entry[nameLength];
        if (afterPrefix == L'=' || afterPrefix == L'\0') {
          return index;
        }
      }
    }
  }

  /**
   * Address: 0x00ABDD12 (FUN_00ABDD12, sub_ABDD12)
   *
   * What it does:
   * Duplicates one null-terminated `wchar_t**` environment pointer vector
   * into CRT heap storage and deep-copies each entry -- the wide sibling of
   * `_copy_environ` above, `wcsdup` (`RuntimeWideStringDuplicate`) in place
   * of `_strdup`.
   *
   * DB-integrity fix: was tagged `external_dependency` ("MSVC CRT internal
   * ... duplicator") -- wrong: its per-entry callee, `wcsdup`
   * (`RuntimeWideStringDuplicate`), is engine-recovered in this same file.
   */
  [[nodiscard]] wchar_t** RuntimeDuplicateWideEnvironmentArray(
    wchar_t** const sourceArray
  )
  {
    if (sourceArray == nullptr) {
      return nullptr;
    }

    std::size_t entryCount = 0u;
    while (sourceArray[entryCount] != nullptr) {
      ++entryCount;
    }

    auto** const duplicateArray = static_cast<wchar_t**>(_calloc_crt(entryCount + 1u, sizeof(wchar_t*)));
    if (duplicateArray == nullptr) {
      __amsg_exit(9);
      return nullptr;
    }

    for (std::size_t entryIndex = 0u; entryIndex < entryCount; ++entryIndex) {
      duplicateArray[entryIndex] = RuntimeWideStringDuplicate(sourceArray[entryIndex]);
    }
    duplicateArray[entryCount] = nullptr;
    return duplicateArray;
  }

  // Forward declaration: RuntimePublishWideEnvironmentVariable's own
  // bootstrap path can call RuntimeSyncWideEnvironFromAnsiFallback (real
  // definition below, at 0x00AAEA1D), which is itself defined in terms of
  // RuntimePublishWideEnvironmentVariable -- a genuine mutual recursion in
  // the shipped binary, not a layering mistake here.
  extern "C" int __cdecl RuntimeSyncWideEnvironFromAnsiFallback();

  /**
   * Address: 0x00ABDD6F (FUN_00ABDD6F, sub_ABDD6F)
   *
   * IDA signature:
   * int __cdecl sub_ABDD6F(struct_Frame **a1, int a2);
   *
   * What it does:
   * The shared VC8 `_putenv`/`_wputenv` internal. Called with a fully-formed
   * heap-owned "NAME=value" (or "NAME=", a delete request) wide string in
   * `*assignmentSlot`; takes ownership of that string, and on every return
   * path either stores it into `gCrtWideEnvironPointerArray`/`_wenviron` or
   * frees it, always clearing `*assignmentSlot` to null before returning.
   *
   * If the working array (`gCrtWideEnvironPointerArray`) still just
   * aliases the pristine startup snapshot (`gCrtWideEnvironStartupSnapshot`
   * -- this also covers "not yet built at all", since both start null), it
   * is first privately duplicated via `RuntimeDuplicateWideEnvironmentArray`.
   * If no array is available even after that: when `synchronizeNativeEnvironment`
   * is set and `_wenviron` exists, attempts the native rebuild chain
   * (`RuntimeBuildWideEnvironmentBlock` + `RuntimePublishWideEnvironFromBlock`,
   * falling back to `RuntimeSyncWideEnvironFromAnsiFallback` -- the mutual-
   * recursion partner that reaches this function itself, always with
   * `synchronizeNativeEnvironment=false`); otherwise bootstraps both
   * `_wenviron` and the working array as fresh single-null-entry arrays.
   *
   * Looks up an existing entry by name (`RuntimeFindWideEnvironmentEntryIndex`).
   * If found: on a delete request, shifts every later entry down by one slot
   * and shrinks the array (`__recalloc_crt`); otherwise replaces the
   * existing entry's string in place. If not found: on a delete request
   * this is a no-op success (early return); otherwise grows the array by
   * one slot (`__recalloc_crt`) and appends the new entry.
   *
   * When `synchronizeNativeEnvironment` is set, additionally pushes the
   * change to the OS via `SetEnvironmentVariableW` (probing support once
   * via `gCrtSetEnvironmentVariableWSupport`, degrading permanently to an
   * ANSI `SetEnvironmentVariableA` fallback -- through a
   * `WideCharToMultiByte` conversion of both name and value -- the first
   * time the native call fails with `ERROR_CALL_NOT_IMPLEMENTED`). Binary
   * quirk preserved: if the temporary "NAME\0value" buffer allocation
   * itself fails, the function returns success (0) without attempting any
   * OS publish -- matches the shipped binary exactly, not a mistake
   * introduced here.
   *
   * Real caller: `RuntimeSyncWideEnvironFromAnsiFallback` (0x00AAEA1D,
   * cited below), always with `synchronizeNativeEnvironment=false` -- the
   * only reachable call path for this function in this binary, matching
   * `RuntimeSyncWideEnvironFromAnsiFallback`'s own status as a dead-in-
   * practice pre-NT fallback. The `synchronizeNativeEnvironment=true`
   * branches are preserved faithfully (this is the shared general-purpose
   * CRT internal) even though nothing in this binary's reachable call
   * graph currently exercises them.
   */
  int RuntimePublishWideEnvironmentVariable(
    wchar_t** const assignmentSlot,
    const bool synchronizeNativeEnvironment
  )
  {
    if (assignmentSlot == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return -1;
    }

    wchar_t* const newAssignment = *assignmentSlot;
    if (newAssignment == nullptr) {
      *_errno() = EINVAL;
      return -1;
    }

    const wchar_t* const equalsSign = std::wcschr(newAssignment, L'=');
    if (equalsSign == nullptr || equalsSign == newAssignment) {
      *_errno() = EINVAL;
      return -1;
    }

    const bool isDeleteRequest = (equalsSign[1] == L'\0');
    const std::uint32_t nameLength = static_cast<std::uint32_t>(equalsSign - newAssignment);

    wchar_t** workingArray = gCrtWideEnvironPointerArray;
    if (gCrtWideEnvironPointerArray == gCrtWideEnvironStartupSnapshot) {
      workingArray = RuntimeDuplicateWideEnvironmentArray(gCrtWideEnvironPointerArray);
      gCrtWideEnvironPointerArray = workingArray;
    }

    if (workingArray == nullptr) {
      if (synchronizeNativeEnvironment && _wenviron != nullptr) {
        gCrtRawWideEnvironmentBlock = RuntimeBuildWideEnvironmentBlock();
        if (RuntimePublishWideEnvironFromBlock() < 0 && RuntimeSyncWideEnvironFromAnsiFallback() != 0) {
          *_errno() = EINVAL;
          return -1;
        }
      } else {
        if (isDeleteRequest) {
          return 0;
        }
        if (_wenviron == nullptr) {
          wchar_t** const freshWenviron = static_cast<wchar_t**>(std::malloc(sizeof(wchar_t*)));
          _wenviron = freshWenviron;
          if (freshWenviron == nullptr) {
            return -1;
          }
          *freshWenviron = nullptr;
        }
        if (gCrtWideEnvironPointerArray == nullptr) {
          wchar_t** const freshArray = static_cast<wchar_t**>(std::malloc(sizeof(wchar_t*)));
          gCrtWideEnvironPointerArray = freshArray;
          if (freshArray == nullptr) {
            return -1;
          }
          *freshArray = nullptr;
        }
      }
    }

    if (gCrtWideEnvironPointerArray == nullptr) {
      return -1;
    }

    int publishResult = 0;
    const int matchIndex = RuntimeFindWideEnvironmentEntryIndex(nameLength, newAssignment);
    if (matchIndex < 0 || gCrtWideEnvironPointerArray[0] == nullptr) {
      if (!isDeleteRequest) {
        const std::size_t existingCount = (matchIndex < 0) ? static_cast<std::size_t>(-matchIndex) : 0u;
        if (existingCount + 2u <= existingCount || existingCount + 2u >= 0x3FFFFFFFu) {
          return -1;
        }
        auto** const grownArray = static_cast<wchar_t**>(
          __recalloc_crt(gCrtWideEnvironPointerArray, sizeof(wchar_t*), existingCount + 2u)
        );
        if (grownArray == nullptr) {
          return -1;
        }
        grownArray[existingCount] = newAssignment;
        grownArray[existingCount + 1u] = nullptr;
        *assignmentSlot = nullptr;
        gCrtWideEnvironPointerArray = grownArray;
      } else {
        _free_crt(newAssignment);
        *assignmentSlot = nullptr;
        return 0;
      }
    } else {
      _free_crt(gCrtWideEnvironPointerArray[matchIndex]);
      if (!isDeleteRequest) {
        gCrtWideEnvironPointerArray[matchIndex] = newAssignment;
        *assignmentSlot = nullptr;
      } else {
        std::size_t shiftPosition = static_cast<std::size_t>(matchIndex);
        while (gCrtWideEnvironPointerArray[shiftPosition] != nullptr) {
          gCrtWideEnvironPointerArray[shiftPosition] = gCrtWideEnvironPointerArray[shiftPosition + 1u];
          ++shiftPosition;
        }

        if (shiftPosition < 0x3FFFFFFFu) {
          auto** const shrunkArray = static_cast<wchar_t**>(
            __recalloc_crt(gCrtWideEnvironPointerArray, shiftPosition, sizeof(wchar_t*))
          );
          if (shrunkArray != nullptr) {
            gCrtWideEnvironPointerArray = shrunkArray;
          }
        }
      }
    }

    if (!synchronizeNativeEnvironment) {
      if (isDeleteRequest) {
        _free_crt(newAssignment);
        *assignmentSlot = nullptr;
      }
      return publishResult;
    }

    const std::size_t fullLength = wstrlen(newAssignment);
    wchar_t* const nameOnlyCopy = static_cast<wchar_t*>(_calloc_crt(fullLength + 2u, sizeof(wchar_t)));
    if (nameOnlyCopy != nullptr) {
      if (wstrcpy(nameOnlyCopy, static_cast<int>(fullLength + 2u), newAssignment) != 0) {
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
      }
      nameOnlyCopy[nameLength] = L'\0';
      const wchar_t* const valuePart = &nameOnlyCopy[nameLength + 1u];

      bool skipAnsiFallback = false;
      if (gCrtSetEnvironmentVariableWSupport == 1) {
        if (!SetEnvironmentVariableW(nameOnlyCopy, isDeleteRequest ? nullptr : valuePart)) {
          if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
            gCrtSetEnvironmentVariableWSupport = 0;
          } else {
            publishResult = -1;
            skipAnsiFallback = true;
          }
        } else {
          skipAnsiFallback = true;
        }
      }

      if (!skipAnsiFallback && gCrtSetEnvironmentVariableWSupport == 0) {
        bool ansiPublishSucceeded = false;
        char* ansiName = nullptr;
        char* ansiValue = nullptr;

        const int ansiNameLength = WideCharToMultiByte(CP_ACP, 0, nameOnlyCopy, -1, nullptr, 0, nullptr, nullptr);
        if (ansiNameLength != 0) {
          ansiName = static_cast<char*>(_calloc_crt(static_cast<std::size_t>(ansiNameLength), 1u));
          if (ansiName != nullptr &&
              WideCharToMultiByte(CP_ACP, 0, nameOnlyCopy, -1, ansiName, ansiNameLength, nullptr, nullptr) != 0)
          {
            bool valueReady = isDeleteRequest;
            if (!isDeleteRequest) {
              const int ansiValueLength = WideCharToMultiByte(CP_ACP, 0, valuePart, -1, nullptr, 0, nullptr, nullptr);
              if (ansiValueLength != 0) {
                ansiValue = static_cast<char*>(_calloc_crt(static_cast<std::size_t>(ansiValueLength), 1u));
                if (ansiValue != nullptr) {
                  valueReady = (WideCharToMultiByte(CP_ACP, 0, valuePart, -1, ansiValue, ansiValueLength, nullptr, nullptr) != 0);
                }
              }
            }

            if (valueReady && SetEnvironmentVariableA(ansiName, isDeleteRequest ? nullptr : ansiValue)) {
              ansiPublishSucceeded = true;
            }
          }
        }

        publishResult = ansiPublishSucceeded ? 0 : -1;
        _free_crt(ansiValue);
        _free_crt(ansiName);
      }

      if (publishResult == -1) {
        *_errno() = 42;  // Literal preserved from the binary; no standard
                           // errno name in <cerrno> matches this exact code.
      }
      _free_crt(nameOnlyCopy);
    }

    if (isDeleteRequest) {
      _free_crt(newAssignment);
      *assignmentSlot = nullptr;
    }
    return publishResult;
  }

  /**
   * Address: 0x00AAEA1D (FUN_00AAEA1D, sub_AAEA1D)
   *
   * IDA signature:
   * int sub_AAEA1D(void);
   *
   * What it does:
   * ANSI-to-wide environment sync fallback, reached from
   * `RuntimeGetWideEnvironmentValue` only when `_wenviron` is already
   * non-null but `RuntimePublishWideEnvironFromBlock` fails on the pre-NT
   * `GetEnvironmentStringsW`-unsupported path (dead in practice on every
   * Windows version this game targets).
   *
   * Preserves a real type-confusion confirmed in the shipped binary (raw
   * asm: `mov esi, _wenviron` at 0x00AAEA24): each `_wenviron` entry --
   * already a `wchar_t*` -- is reinterpreted as a narrow `const char*` and
   * fed to `MultiByteToWideChar`, which reads through it as ANSI bytes
   * rather than UTF-16 code units. This is almost certainly a genuine VC8
   * source-level bug (`_wenviron` used where `_environ` was meant), but it
   * is what the shipped binary does, and this path is unreachable on any
   * target OS this game actually ships for -- preserved as-is rather than
   * "corrected" to what was presumably intended, per this project's
   * binary-fidelity contract.
   *
   * For each `_wenviron` entry: probes the required wide buffer length via
   * `MultiByteToWideChar`, allocates it, converts, and publishes the result
   * through `RuntimePublishWideEnvironmentVariable` (with
   * `synchronizeNativeEnvironment=false` -- this function is the mutual-
   * recursion fallback partner that function's own bootstrap path can
   * reach). Returns 0 once every entry has been processed, or -1 on the
   * first conversion, allocation, or publish failure.
   */
  extern "C" int __cdecl RuntimeSyncWideEnvironFromAnsiFallback()
  {
    wchar_t** environEntry = _wenviron;
    if (*environEntry == nullptr) {
      return 0;
    }

    const char* sourceText = reinterpret_cast<const char*>(*environEntry);
    for (;;) {
      const int requiredWideChars = MultiByteToWideChar(0, 0, sourceText, -1, nullptr, 0);
      if (requiredWideChars == 0) {
        return -1;
      }

      wchar_t* convertedEntry = static_cast<wchar_t*>(
        _calloc_crt(static_cast<std::size_t>(requiredWideChars), sizeof(wchar_t))
      );
      if (convertedEntry == nullptr) {
        return -1;
      }

      if (MultiByteToWideChar(0, 0, sourceText, -1, convertedEntry, requiredWideChars) == 0) {
        _free_crt(convertedEntry);
        return -1;
      }

      if (RuntimePublishWideEnvironmentVariable(&convertedEntry, false) < 0) {
        if (convertedEntry != nullptr) {
          _free_crt(convertedEntry);
        }
        return -1;
      }

      ++environEntry;
      if (*environEntry == nullptr) {
        return 0;
      }
      sourceText = reinterpret_cast<const char*>(*environEntry);
    }
  }

  /**
   * Address: 0x00A907EB (FUN_00A907EB, sub_A907EB)
   *
   * IDA signature:
   * int __cdecl sub_A907EB(const wchar_t *a1);
   *
   * What it does:
   * The real VC8 `_wgetenv` implementation. Bails if `__env_initialized`
   * is false. If `gCrtWideEnvironPointerArray` is not yet built, and
   * `_wenviron` is set, lazily builds it -- `RuntimeBuildWideEnvironmentBlock`
   * then `RuntimePublishWideEnvironFromBlock`, falling back to
   * `RuntimeSyncWideEnvironFromAnsiFallback` only if that fails. Once the
   * array is available, linear-scans it for a `NAME=value` entry whose
   * name matches `variableName` case-insensitively (`_wcsnicoll`), and
   * returns a pointer just past the `=`.
   *
   * Real caller: `_wdupenv_s` (0x00A90B12, `sub_A90B12` calls
   * `sub_A907EB(a3)` directly -- confirmed reading its raw decompile, not
   * just its already-recovered source) -- rewired below to call this
   * function by name instead of the modern CRT's own `_wgetenv`, which
   * does not touch this VC8-shaped `gCrtWideEnvironPointerArray` state at
   * all and was a placeholder pending this recovery.
   */
  extern "C" const wchar_t* __cdecl RuntimeGetWideEnvironmentValue(const wchar_t* const variableName)
  {
    const wchar_t* const* environArray = gCrtWideEnvironPointerArray;

    if (__env_initialized == 0) {
      return nullptr;
    }

    const bool ready = (gCrtWideEnvironPointerArray != nullptr) || (
      _wenviron != nullptr &&
      ((gCrtRawWideEnvironmentBlock = RuntimeBuildWideEnvironmentBlock(), RuntimePublishWideEnvironFromBlock() >= 0) ||
       !RuntimeSyncWideEnvironFromAnsiFallback()) &&
      (environArray = gCrtWideEnvironPointerArray) != nullptr
    );

    if (ready && variableName != nullptr) {
      const std::size_t nameLength = wstrlen(variableName);
      for (; *environArray != nullptr; ++environArray) {
        if (wstrlen(*environArray) > nameLength &&
            (*environArray)[nameLength] == L'=' &&
            _wcsnicoll(*environArray, variableName, static_cast<unsigned int>(nameLength)) == 0)
        {
          return &(*environArray)[nameLength + 1];
        }
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00A90B12 (FUN_00A90B12, _wdupenv_s)
   *
   * What it does:
   * Duplicates one wide environment variable value into caller-owned heap
   * storage and reports the required UTF-16 element count.
   *
   * Real callsite evidence for `RuntimeGetWideEnvironmentValue`: this
   * function's raw decompile (`FUN_00A90B12.c`) shows
   * `v3 = sub_A907EB(a3);` -- a direct call to the VC8 `_wgetenv` internal,
   * not to some generic CRT entry point. Previously called the modern
   * toolchain's own `_wgetenv`, which does not participate in this file's
   * recovered `gCrtWideEnvironPointerArray` state at all; rewired here to
   * match the binary.
   */
  extern "C" errno_t __cdecl _wdupenv_s(
    wchar_t** const duplicatedValueOut,
    size_t* const requiredCountOut,
    const wchar_t* const variableName
  )
  {
    RuntimeLockGuard lockGuard(kRuntimeEnvironmentLock);

    if (duplicatedValueOut == nullptr || variableName == nullptr) {
      if (requiredCountOut != nullptr) {
        *requiredCountOut = 0u;
      }
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return EINVAL;
    }

    *duplicatedValueOut = nullptr;
    if (requiredCountOut != nullptr) {
      *requiredCountOut = 0u;
    }

    const wchar_t* const source = RuntimeGetWideEnvironmentValue(variableName);
    if (source == nullptr) {
      return 0;
    }

    const size_t requiredCount = std::wcslen(source) + 1u;
    wchar_t* const duplicatedValue = static_cast<wchar_t*>(std::calloc(requiredCount, sizeof(wchar_t)));
    if (duplicatedValue == nullptr) {
      *_errno() = ENOMEM;
      return ENOMEM;
    }

    const errno_t copyError = wcscpy_s(duplicatedValue, requiredCount, source);
    if (copyError != 0) {
      std::free(duplicatedValue);
      return copyError;
    }

    *duplicatedValueOut = duplicatedValue;
    if (requiredCountOut != nullptr) {
      *requiredCountOut = requiredCount;
    }

    return 0;
  }

  /**
   * Address: 0x00A9127E (FUN_00A9127E, _wgetcwd)
   *
   * What it does:
   * MSVC CRT `_wgetcwd(buffer, maxlen)` implementation. Drive-relative
   * working directories are tracked through the CRT's per-drive
   * pseudo-environment block, so this takes `_ENV_LOCK` for the duration of
   * the lookup, resolves the *current* drive's (`drive=0`) working
   * directory through the no-lock worker, then releases the lock. Returns
   * `buffer` on success or `nullptr` on failure (matching `GetLastError()`
   * left set by the underlying `GetCurrentDirectoryW`/`GetDriveType` calls).
   *
   * IDA signature:
   * int __cdecl sub_A9127E(LPWSTR lpBuffer, DWORD a2);
   */
  extern "C" wchar_t* __cdecl _wgetcwd(
    wchar_t* const buffer,
    const int maxLength
  )
  {
    RuntimeLockGuard lockGuard(kRuntimeEnvironmentLock);
    // `::_wgetdcwd_nolock` is the same no-lock drive-relative worker the
    // binary's `sub_A9113F` (called here as `sub_A9113F(0, lpBuffer, a2)`)
    // implements: drive 0 means "the current drive".
    return ::_wgetdcwd_nolock(0, buffer, maxLength);
  }

  struct RuntimeTryBlockMapEntry
  {
    std::int32_t tryLow;            // +0x00
    std::int32_t tryHigh;           // +0x04
    std::int32_t catchHigh;         // +0x08
    std::int32_t catchHandlerCount; // +0x0C
    void* catchHandlerArray;        // +0x10
  };
  static_assert(sizeof(RuntimeTryBlockMapEntry) == 0x14, "RuntimeTryBlockMapEntry size must be 0x14");
  static_assert(offsetof(RuntimeTryBlockMapEntry, tryHigh) == 0x04, "RuntimeTryBlockMapEntry::tryHigh offset must be 0x04");
  static_assert(offsetof(RuntimeTryBlockMapEntry, catchHigh) == 0x08, "RuntimeTryBlockMapEntry::catchHigh offset must be 0x08");

  struct RuntimeCxxFuncInfoView
  {
    std::uint8_t reserved00_0B[0x0C];
    const RuntimeTryBlockMapEntry* tryBlockMap; // +0x0C
    std::uint32_t tryBlockCount;                // +0x10
  };
  static_assert(offsetof(RuntimeCxxFuncInfoView, tryBlockMap) == 0x0C, "RuntimeCxxFuncInfoView::tryBlockMap offset must be 0x0C");
  static_assert(
    offsetof(RuntimeCxxFuncInfoView, tryBlockCount) == 0x10,
    "RuntimeCxxFuncInfoView::tryBlockCount offset must be 0x10"
  );

  struct RuntimeLongjmpUnwindContextView
  {
    void* savedFramePointer;           // +0x00
    std::uint8_t reserved04_17[0x14];  // +0x04
    void* registrationNode;            // +0x18
    std::int32_t targetState;          // +0x1C
    std::uint8_t reserved20_27[0x08];  // +0x20
    const void* functionInfo;          // +0x28
  };
  static_assert(
    offsetof(RuntimeLongjmpUnwindContextView, registrationNode) == 0x18,
    "RuntimeLongjmpUnwindContextView::registrationNode offset must be 0x18"
  );
  static_assert(
    offsetof(RuntimeLongjmpUnwindContextView, targetState) == 0x1C,
    "RuntimeLongjmpUnwindContextView::targetState offset must be 0x1C"
  );
  static_assert(
    offsetof(RuntimeLongjmpUnwindContextView, functionInfo) == 0x28,
    "RuntimeLongjmpUnwindContextView::functionInfo offset must be 0x28"
  );
  static_assert(sizeof(RuntimeLongjmpUnwindContextView) == 0x2C, "RuntimeLongjmpUnwindContextView size must be 0x2C");

  /**
   * Address: 0x00A8962E (FUN_00A8962E, __CxxLongjmpUnwind)
   *
   * What it does:
   * Unwinds C++ EH state for one longjmp context by forwarding registration,
   * function-info, and target-state lanes to `__FrameUnwindToState`.
   */
  extern "C" void __stdcall __CxxLongjmpUnwind(const RuntimeLongjmpUnwindContextView* const unwindContext)
  {
    __FrameUnwindToState(
      unwindContext->registrationNode,
      nullptr,
      unwindContext->functionInfo,
      unwindContext->targetState
    );
  }

  [[noreturn]] void RuntimeRaiseEhFrameConsistencyFailure()
  {
    _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
    std::abort();
  }

  /**
   * Address: 0x00A897EA (FUN_00A897EA, _GetRangeOfTrysToCheck)
   *
   * What it does:
   * Walks C++ EH try-block descriptors backward from the current state to
   * derive one contiguous range of candidates for handler probing.
   */
  extern "C" const RuntimeTryBlockMapEntry* __cdecl _GetRangeOfTrysToCheck(
    const RuntimeCxxFuncInfoView* const funcInfo,
    int nestedTryDepth,
    const int currentState,
    unsigned int* const outRangeStart,
    unsigned int* const outRangeEnd
  )
  {
    unsigned int scanIndex = funcInfo->tryBlockCount;
    const RuntimeTryBlockMapEntry* const tryBlocks = funcInfo->tryBlockMap;
    unsigned int rangeEnd = scanIndex;

    while (nestedTryDepth >= 0) {
      const unsigned int previousRangeEnd = scanIndex;
      while (true) {
        if (scanIndex == static_cast<unsigned int>(-1)) {
          RuntimeRaiseEhFrameConsistencyFailure();
        }

        const RuntimeTryBlockMapEntry* const entry = &tryBlocks[--scanIndex];
        if (((entry->tryHigh < currentState) && (currentState <= entry->catchHigh))
            || scanIndex == static_cast<unsigned int>(-1)) {
          --nestedTryDepth;
          rangeEnd = previousRangeEnd;
          break;
        }
      }
    }

    const unsigned int rangeStart = scanIndex + 1u;
    *outRangeStart = rangeStart;
    *outRangeEnd = rangeEnd;
    if (rangeEnd > funcInfo->tryBlockCount || rangeStart > rangeEnd) {
      RuntimeRaiseEhFrameConsistencyFailure();
    }

    return &tryBlocks[rangeStart];
  }

  /**
   * Address: 0x00A8985D (FUN_00A8985D, __CreateFrameInfo)
   *
   * What it does:
   * Pushes one exception-object frame marker onto the per-thread frame-info
   * chain tracked in `_tiddata`.
   */
  extern "C" RuntimeFrameInfoNode* __cdecl __CreateFrameInfo(
    RuntimeFrameInfoNode* const frameInfo,
    const int objectState
  )
  {
    frameInfo->objectState = objectState;
    RuntimeTidDataLocaleView* const threadData = __getptd();
    frameInfo->next = threadData->frameInfoChain;
    threadData->frameInfoChain = frameInfo;
    return frameInfo;
  }

  /**
   * Address: 0x00A89885 (FUN_00A89885, __IsExceptionObjectToBeDestroyed)
   *
   * What it does:
   * Returns true when the incoming exception-object state is absent from the
   * active per-thread frame-info chain.
   */
  extern "C" int __cdecl __IsExceptionObjectToBeDestroyed(const int objectState)
  {
    for (RuntimeFrameInfoNode* frame = __getptd()->frameInfoChain; frame != nullptr; frame = frame->next) {
      if (frame->objectState == objectState) {
        return 0;
      }
    }

    return 1;
  }

  /**
   * Address: 0x00A898F2 (FUN_00A898F2, _CallCatchBlock2)
   *
   * What it does:
   * Forwards one catch-block action thunk through `_CallSettingFrame` using
   * the active EH registration frame and notify code.
   */
  extern "C" void* __cdecl _CallCatchBlock2(
    void* const establisherFrame,
    const void* const /*funcInfo*/,
    void* const targetAction,
    const int /*catchDepth*/,
    const unsigned int notifyCode
  )
  {
    const int targetActionLane = static_cast<int>(reinterpret_cast<std::uintptr_t>(targetAction));
    const int establisherFrameLane = static_cast<int>(reinterpret_cast<std::uintptr_t>(establisherFrame));
    return reinterpret_cast<void*>(_CallSettingFrame(targetActionLane, establisherFrameLane, static_cast<int>(notifyCode)));
  }

  /**
   * Address: 0x00A8953A (FUN_00A8953A, _UnwindNestedFrames)
   *
   * What it does:
   * Saves the current SEH chain head, performs a structured unwind to the
   * requested target frame, clears the unwind bit on the exception record,
   * and restores the `fs:[0]` registration chain pointer.
   */
extern "C" void __cdecl _UnwindNestedFrames(PVOID targetFrame, PEXCEPTION_RECORD exceptionRecord)
  {
    auto* const savedTib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    _EXCEPTION_REGISTRATION_RECORD* const savedExceptionList = savedTib->ExceptionList;
    void* targetInstructionPointer = nullptr;

    __asm
    {
      mov eax, offset unwind_resume
      mov targetInstructionPointer, eax
    }

    ::RtlUnwind(targetFrame, targetInstructionPointer, exceptionRecord, nullptr);

  unwind_resume:
    exceptionRecord->ExceptionFlags &= ~2u;
    auto* const currentTib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    _EXCEPTION_REGISTRATION_RECORD* const currentExceptionList = currentTib->ExceptionList;
    savedExceptionList->Next = currentExceptionList;
    currentTib->ExceptionList = savedExceptionList;
  }

  /**
   * Address: 0x00A9C21D (FUN_00A9C21D)
   *
   * What it does:
   * Publishes non-local-goto notification state (`notifyCode = 1`) for an EH4
   * filter callback, then invokes that filter with zeroed argument lanes.
   */
  extern "C" int __fastcall RuntimeCallEh4FilterWithNlgNotify(
    int (__fastcall* const filterCallback)(std::uint32_t, std::uint32_t),
    const std::uint32_t frameBase
  )
  {
    const std::uint32_t callbackLane = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(filterCallback));
    (void)RuntimePublishNonLocalGotoState(callbackLane, frameBase, 1u);
    return filterCallback(0u, 0u);
  }

  /**
   * Address: 0x00A9C236 (FUN_00A9C236)
   *
   * What it does:
   * Performs the EH4 global unwind lane by issuing `RtlUnwind` toward one
   * local resume label.
   */
  extern "C" void __cdecl RuntimeEh4GlobalUnwind2(PVOID targetFrame)
  {
    void* targetInstructionPointer = nullptr;
    __asm
    {
      mov eax, offset eh4_global_unwind_resume
      mov targetInstructionPointer, eax
    }
    ::RtlUnwind(targetFrame, targetInstructionPointer, nullptr, nullptr);
  eh4_global_unwind_resume:
    return;
  }

  /**
   * Address: 0x00AA3A20 (FUN_00AA3A20)
   *
   * What it does:
   * Performs the EH3 global unwind lane by issuing `RtlUnwind` toward one
   * local resume label.
   */
  extern "C" void __cdecl RuntimeEh3GlobalUnwind2(PVOID targetFrame)
  {
    void* targetInstructionPointer = nullptr;
    __asm
    {
      mov eax, offset eh3_global_unwind_resume
      mov targetInstructionPointer, eax
    }
    ::RtlUnwind(targetFrame, targetInstructionPointer, nullptr, nullptr);
  eh3_global_unwind_resume:
    return;
  }

  /**
   * Address: 0x00A9C250 (FUN_00A9C250, _EH4_LocalUnwind)
   *
   * What it does:
   * Bridges EH4 local-unwind dispatch by forwarding registration and target
   * try levels into `__local_unwind4`.
   */
  extern "C" BOOL __fastcall EH4_LocalUnwind(
    const int currentTryLevel,
    const unsigned int targetTryLevel,
    int /*unusedHandlerLevel*/,
    void* const registrationFrame
  )
  {
    return __local_unwind4(registrationFrame, currentTryLevel, targetTryLevel);
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
   * Address: 0x00A8E490 (FUN_00A8E490, strncat)
   *
   * What it does:
   * Appends up to `maxAppendCount` source bytes to the destination tail and
   * always leaves one trailing NUL terminator.
   */
  extern "C" char* __cdecl strncat(char* const destination, const char* source, std::size_t maxAppendCount)
  {
    if (maxAppendCount == 0u) {
      return destination;
    }

    char* destinationTail = destination;
    while (*destinationTail != '\0') {
      ++destinationTail;
    }

    while (maxAppendCount != 0u) {
      const char ch = *source++;
      *destinationTail++ = ch;
      if (ch == '\0') {
        return destination;
      }
      --maxAppendCount;
    }

    *destinationTail = '\0';
    return destination;
  }

  /**
   * Address: 0x00A8C765 (FUN_00A8C765, __strcats)
   *
   * What it does:
   * Appends `sourceCount` C-string arguments to one destination buffer through
   * repeated `strcat_s` semantics and invokes Watson on the first failure.
   */
  extern "C" void __cdecl __strcats(char* const destination, const std::size_t destinationSize, int sourceCount, ...)
  {
    if (sourceCount <= 0) {
      return;
    }

    va_list sourceList;
    va_start(sourceList, sourceCount);
    while (sourceCount > 0) {
      const char* const source = va_arg(sourceList, const char*);
      if (RuntimeStrcatS(destination, destinationSize, source) != 0) {
        va_end(sourceList);
        _invoke_watson(nullptr, nullptr, nullptr, 0u, 0u);
        return;
      }
      --sourceCount;
    }
    va_end(sourceList);
  }

  /**
   * Address: 0x00A8C5E7 (FUN_00A8C5E7, _sync_legacy_variables_lk)
   *
   * What it does:
   * Copies one lane of locale-dependent legacy CRT globals from `__ptlocinfo`
   * so non-thread-local callers observe the updated locale state.
   */
  extern "C" void __cdecl _sync_legacy_variables_lk()
  {
    const auto* const localeView = reinterpret_cast<const RuntimeLocaleLegacySyncView*>(__ptlocinfo);
    __lc_codepage = localeView->lcCodepage;
    __lc_collate_cp = localeView->lcCollateCodepage;
    __lc_clike = localeView->lcClike;
    __lc_time_curr = localeView->lcTimeCurrent;
    __lconv = localeView->localeConventions;
    _pctype = localeView->pctype;
    __mb_cur_max = localeView->mbCurMax;
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

  [[nodiscard]] void* RuntimeAllocateArrayWithBadAllocCommon(const unsigned int count, const unsigned int elementSize)
  {
    if (count != 0u && (std::numeric_limits<unsigned int>::max() / count) < elementSize) {
      throw std::bad_alloc();
    }

    return ::operator new(static_cast<std::size_t>(elementSize) * count);
  }

  [[nodiscard]] void* RuntimeAllocateArrayWithBadAllocLane021(const unsigned int count);

  /**
   * Address: 0x00533620 (FUN_00533620)
   *
   * What it does:
   * Allocates one `20`-byte element array lane and throws `std::bad_alloc`
   * when the 32-bit count multiplication overflows.
   */
  [[nodiscard]] void* RuntimeAllocateArrayWithBadAllocLane009(const unsigned int count)
  {
    return RuntimeAllocateArrayWithBadAllocCommon(count, 20u);
  }

  std::uint8_t gRuntimeByte54741F = 0;

  struct RuntimeSharedControlBlockView;
  using RuntimeSharedControlReleaseFn = void(__thiscall*)(RuntimeSharedControlBlockView*);

  struct RuntimeSharedControlBlockView
  {
    RuntimeSharedControlReleaseFn* vtable = nullptr; // +0x00
    volatile long sharedRefs = 0;                    // +0x04
    volatile long weakRefs = 0;                      // +0x08
  };
  static_assert(sizeof(RuntimeSharedControlBlockView) == 0x0C, "RuntimeSharedControlBlockView size must be 0x0C");

  using RuntimeOffsetDispatchThreeLaneFn = int(__thiscall*)(std::uint32_t, std::uint32_t, std::uint32_t);
  using RuntimeOffsetDispatchPointerLaneFn = int(__thiscall*)(std::uint32_t, const void*);
  using RuntimeOffsetDispatchTwoLaneFn = int(__thiscall*)(std::uint32_t, std::uint32_t);

  struct RuntimeReleasableObject;
  using RuntimeReleaseWithCountFn = std::intptr_t(__thiscall*)(RuntimeReleasableObject*, int);

  struct RuntimeReleasableObjectVTable
  {
    RuntimeReleaseWithCountFn release = nullptr; // +0x00
  };

  struct RuntimeReleasableObject
  {
    RuntimeReleasableObjectVTable* vtable = nullptr; // +0x00
  };

  struct RuntimeStdcallReleaseObject;
  using RuntimeStdcallReleaseSlot2Fn = int(__stdcall*)(RuntimeStdcallReleaseObject*);

  struct RuntimeStdcallReleaseVTable
  {
    void* reserved00 = nullptr;                     // +0x00
    void* reserved04 = nullptr;                     // +0x04
    RuntimeStdcallReleaseSlot2Fn releaseSlot2 = nullptr; // +0x08
  };

  struct RuntimeStdcallReleaseObject
  {
    RuntimeStdcallReleaseVTable* vtable = nullptr; // +0x00
  };

  struct RuntimeDispatchSlot24Object;
  using RuntimeDispatchSlot24Fn = void(__thiscall*)(
    RuntimeDispatchSlot24Object*,
    int,
    int,
    int,
    int,
    int,
    int,
    int
  );

  struct RuntimeDispatchSlot24VTable
  {
    void* slot00 = nullptr;            // +0x00
    void* slot04 = nullptr;            // +0x04
    void* slot08 = nullptr;            // +0x08
    void* slot0C = nullptr;            // +0x0C
    void* slot10 = nullptr;            // +0x10
    void* slot14 = nullptr;            // +0x14
    RuntimeDispatchSlot24Fn slot24 = nullptr; // +0x18
  };

  struct RuntimeDispatchSlot24Object
  {
    RuntimeDispatchSlot24VTable* vtable = nullptr; // +0x00
  };

  void RuntimeReleaseSharedControlBlock(RuntimeSharedControlBlockView* const sharedControl)
  {
    if (sharedControl == nullptr) {
      return;
    }

    if (::InterlockedDecrement(&sharedControl->sharedRefs) == 0) {
      sharedControl->vtable[1](sharedControl);
      if (::InterlockedDecrement(&sharedControl->weakRefs) == 0) {
        sharedControl->vtable[2](sharedControl);
      }
    }
  }

  /**
   * Address: 0x0056F520 (FUN_0056F520)
   *
   * What it does:
   * Throws the legacy VC8 map/set growth overflow length-error diagnostic.
   */
  [[noreturn]] void RuntimeThrowMapSetTooLongQ()
  {
    RuntimeThrowContainerTooLong("map/set<T> too long");
  }

  /**
   * Address: 0x007029C0 (FUN_007029C0)
   *
   * What it does:
   * Throws the legacy VC8 vector growth overflow length-error diagnostic.
   */
  [[noreturn]] void RuntimeThrowVectorTooLongBW()
  {
    RuntimeThrowContainerTooLong("vector<T> too long");
  }

  [[noreturn]] void RuntimeThrowListTooLongS();

  /**
   * Address: 0x0082F5D0 (FUN_0082F5D0)
   *
   * What it does:
   * Throws the legacy VC8 list growth overflow length-error diagnostic.
   */
  [[noreturn]] void RuntimeThrowListTooLongS()
  {
    RuntimeThrowContainerTooLong("list<T> too long");
  }

  struct RuntimeSharedControlPairEntry
  {
    void* reserved00 = nullptr;                     // +0x00
    volatile long* firstControl = nullptr;          // +0x04
    void* reserved08 = nullptr;                     // +0x08
    volatile long* secondControl = nullptr;         // +0x0C
  };
  static_assert(sizeof(RuntimeSharedControlPairEntry) == 0x10, "RuntimeSharedControlPairEntry size must be 0x10");

  RuntimeSharedControlPairEntry* gRuntimeSharedControlPairBegin = nullptr;
  RuntimeSharedControlPairEntry* gRuntimeSharedControlPairEnd = nullptr;
  RuntimeSharedControlPairEntry* gRuntimeSharedControlPairCapacity = nullptr;

  using RuntimeDestroyCallbackFn = int(__thiscall*)(void*, int);

  using RuntimeLegacyProxyVectorThrowFn = void (*)();
  using RuntimeLegacyProxyVectorAllocateFn = void* (*)(unsigned int);

  using DequeMapThrowTooLongFn = void (*)();

  struct RuntimePointerGridView
  {
    std::int32_t rowCount = 0;       // +0x00
    std::int32_t columnCount = 0;    // +0x04
    std::int32_t elementCount = 0;   // +0x08
    void* elementStorage = nullptr;  // +0x0C
    void** rowPointers = nullptr;    // +0x10
  };
  static_assert(sizeof(RuntimePointerGridView) == 0x14, "RuntimePointerGridView size must be 0x14");
  static_assert(offsetof(RuntimePointerGridView, rowCount) == 0x00, "RuntimePointerGridView::rowCount offset must be 0x00");
  static_assert(
    offsetof(RuntimePointerGridView, elementStorage) == 0x0C,
    "RuntimePointerGridView::elementStorage offset must be 0x0C"
  );
  static_assert(
    offsetof(RuntimePointerGridView, rowPointers) == 0x10,
    "RuntimePointerGridView::rowPointers offset must be 0x10"
  );

  using RuntimePointerGridAllocator = int (*)(RuntimePointerGridView&, std::uint8_t);

  struct RuntimeLocaleNameTableEntry
  {
    const char* fullName = nullptr; // +0x00
    char* abbreviation = nullptr;   // +0x04
  };
  static_assert(sizeof(RuntimeLocaleNameTableEntry) == 0x8, "RuntimeLocaleNameTableEntry size must be 0x8");

  /**
   * Address: 0x00AA653D (FUN_00AA653D, TranslateName)
   *
   * What it does:
   * Performs one case-insensitive binary search over locale-name table lanes;
   * on match, replaces `*inOutName` with the matched abbreviation lane.
   */
  extern "C" BOOL __cdecl TranslateName(
    const RuntimeLocaleNameTableEntry* const table,
    int maxIndex,
    char** const inOutName
  )
  {
    int lowIndex = 0;
    int compareResult = 1;

    while (lowIndex <= maxIndex) {
      if (compareResult == 0) {
        break;
      }

      const int middleIndex = (lowIndex + maxIndex) / 2;
      const RuntimeLocaleNameTableEntry& entry = table[middleIndex];
      compareResult = _stricmp(*inOutName, entry.fullName);
      if (compareResult == 0) {
        *inOutName = entry.abbreviation;
      } else if (compareResult < 0) {
        maxIndex = middleIndex - 1;
      } else {
        lowIndex = middleIndex + 1;
      }
    }

    return (compareResult == 0) ? TRUE : FALSE;
  }

  struct RuntimeUndecoratorHeapFrameNode
  {
    RuntimeUndecoratorHeapFrameNode* next = nullptr; // +0x00
  };
  static_assert(sizeof(RuntimeUndecoratorHeapFrameNode) == 0x04, "RuntimeUndecoratorHeapFrameNode size must be 0x04");

  using RuntimeUndecoratorFrameFreeFn = void(__cdecl*)(RuntimeUndecoratorHeapFrameNode* frame);

  const char* gRuntimeUndecoratorCurrentDecoratedName = nullptr;

  extern "C" const std::uint16_t __rglangidNotDefault[10];

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

  [[nodiscard]] std::size_t RuntimeCodePageHashBucket(const std::uint32_t codePage) noexcept
  {
    return static_cast<std::size_t>(codePage % static_cast<std::uint32_t>(kRuntimeCodePageLocaleHashBucketCount));
  }

  [[nodiscard]] int RuntimeGetCodePageMaxCharBytes(const RuntimeLocaleHandle* const locale, const UINT fallbackCodePage)
  {
    // `RuntimeLocaleHandle` is layout-identical to the real `_locale_tstruct`
    // (`{locinfo, mbcinfo}`, both single pointers) -- FUN_00AA64B2's real body
    // (`___mb_cur_max_l_func`) is a documented, exported UCRT symbol
    // (declared in <ctype.h>), so it is called directly here instead of being
    // reimplemented as engine source (matching this project's `_findfirst64`/
    // `_ftime64_s` precedent for CRT functions the modern UCRT still exports).
    static_assert(sizeof(RuntimeLocaleHandle) == sizeof(__crt_locale_pointers), "RuntimeLocaleHandle must match _locale_tstruct layout");
    if (locale != nullptr && locale->locinfo != nullptr) {
      const int mbCurMax = ___mb_cur_max_l_func(reinterpret_cast<_locale_t>(const_cast<RuntimeLocaleHandle*>(locale)));
      if (mbCurMax > 0) {
        return mbCurMax;
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

  int RuntimeMultiByteToWideStep(
    wchar_t* destinationWideChar,
    const char* sourceBytes,
    const unsigned int sourceByteCount,
    char* pendingStateBytes,
    const RuntimeCvtVec* localeVector
  );

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
   * Address: 0x00AA2A65 (FUN_00AA2A65, __uncaught_exception)
   *
   * What it does:
   * Reports whether the current thread is processing an active throw lane.
   */
  extern "C" bool __cdecl __uncaught_exception()
  {
    const auto* const threadData = reinterpret_cast<const RuntimeTidDataProcessingThrowView*>(__getptd());
    return threadData->mProcessingThrow != 0;
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
      char* const base = legacy_file(stream)._base;
      const int pendingBytes = static_cast<int>(legacy_file(stream)._ptr - base);
      if (pendingBytes > 0) {
        const int fileDescriptor = ::_fileno(stream);
        if (::_write(fileDescriptor, base, static_cast<unsigned int>(pendingBytes)) == pendingBytes) {
          if ((legacy_file(stream)._flag & 0x80) != 0) {
            legacy_file(stream)._flag &= ~0x2;
          }
        } else {
          legacy_file(stream)._flag |= 0x20;
          flushStatus = -1;
        }
      }
    }

    legacy_file(stream)._cnt = 0;
    legacy_file(stream)._ptr = legacy_file(stream)._base;
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
   * Address: 0x00A8658A (FUN_00A8658A, _flushall)
   *
   * What it does:
   * Flushes all active CRT streams and returns the flushed stream count.
   */
  extern "C" int __cdecl _flushall()
  {
    return RuntimeFlushAllStreams(1);
  }

  /**
   * Address: 0x00A89F0B (FUN_00A89F0B, ___endstdio)
   *
   * What it does:
   * Flushes all CRT streams, conditionally closes active streams during exit,
   * then releases the dynamic `__piob` table storage.
   */
  extern "C" void __cdecl __endstdio()
  {
    (void)RuntimeFlushAllStreams(1);
    if (_exitflag != 0u) {
      (void)RuntimeFcloseall();
    }
    _free_crt(__piob);
  }

  /**
   * Address: 0x00AB65D2 (FUN_00AB65D2, _get_printf_count_output)
   *
   * What it does:
   * Returns whether `%n` output is enabled by validating the guarded runtime
   * cookie lane (`__enable_percent_n == (__security_cookie | 1)`).
   */
  extern "C" int __cdecl _get_printf_count_output()
  {
    return (__enable_percent_n == (__security_cookie | static_cast<std::uintptr_t>(1u))) ? 1 : 0;
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

    if ((legacy_file(stream)._flag & 0x4000) == 0) {
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
   * Address: 0x00A8C1F2 (FUN_00A8C1F2, _strftime_l)
   *
   * What it does:
   * Formats one `tm` lane into caller buffer by forwarding to `__Strftime_l`
   * with explicit locale and null timezone lanes.
   */
  extern "C" std::size_t __cdecl _strftime_l(
    char* const destination,
    const std::size_t maxCount,
    const char* const format,
    const std::tm* const timeData,
    _locale_t localeInfo
  )
  {
    return __Strftime_l(destination, maxCount, format, timeData, nullptr, localeInfo);
  }

  /**
   * Address: 0x00A8C210 (FUN_00A8C210, strftime)
   *
   * What it does:
   * Formats one `tm` lane into caller buffer by forwarding to `__Strftime_l`
   * with default timezone/locale lanes.
   */
extern "C" std::size_t __cdecl strftime(
  char* const destination,
  const std::size_t maxCount,
  const char* const format,
  const std::tm* const timeData
)
{
  return __Strftime_l(destination, maxCount, format, timeData, nullptr, nullptr);
}

/**
 * Address: 0x00A8C22D (FUN_00A8C22D, __Strftime)
 *
 * What it does:
 * Forwards time formatting to `__Strftime_l` with caller-provided locale-time
 * lane and a null explicit locale lane.
 */
extern "C" std::size_t __cdecl __Strftime(
  char* const destination,
  const std::size_t maxCount,
  const char* const format,
  const std::tm* const timeData,
  void* const localeTimeArg
)
{
  return __Strftime_l(destination, maxCount, format, timeData, localeTimeArg, nullptr);
}

/**
 * Address: 0x00A8C24B (FUN_00A8C24B)
 *
 * What it does:
 * Returns one process-global runtime storage scalar lane.
 */
extern "C" int __cdecl RuntimeGetStaticStorageIntLane()
{
  return gRuntimeStaticStorageSlotB;
}

/**
 * Address: 0x00A8C251 (FUN_00A8C251)
 *
 * What it does:
 * Returns the address of one process-global runtime storage lane.
 */
extern "C" void* __cdecl RuntimeGetStaticStoragePointerLane()
{
  return &gRuntimeStaticStorageSlotC;
}

  /**
   * Address: 0x00AAAA5F (FUN_00AAAA5F, parse_cmdline)
   *
   * What it does:
   * Splits one CRT startup command-line lane into `argv`/`args` storage while
   * preserving quote, backslash, and lead-byte parsing semantics.
   */
  extern "C" void __cdecl parse_cmdline(
    char* cmdstart,
    int* const numchars,
    char** argv,
    char* args,
    int* const numargs
  )
  {
    *numchars = 0;
    *numargs = 1;
    if (argv != nullptr) {
      *argv++ = args;
    }

    int inquote = 0;
    char c = '\0';
    do {
      if (*cmdstart == '"') {
        c = '"';
        ++cmdstart;
        inquote = (inquote == 0) ? 1 : 0;
      } else {
        ++(*numchars);
        if (args != nullptr) {
          *args++ = *cmdstart;
        }

        c = *cmdstart++;
        if (_ismbblead(static_cast<unsigned char>(c)) != 0) {
          ++(*numchars);
          if (args != nullptr) {
            *args++ = *cmdstart;
          }
          ++cmdstart;
        }

        if (c == '\0') {
          --cmdstart;
          break;
        }
      }
    } while (inquote != 0 || (c != ' ' && c != '\t'));

    if (c != '\0' && args != nullptr) {
      *(args - 1) = '\0';
    }

    inquote = 0;
    while (*cmdstart != '\0') {
      while (*cmdstart == ' ' || *cmdstart == '\t') {
        ++cmdstart;
      }
      if (*cmdstart == '\0') {
        break;
      }

      if (argv != nullptr) {
        *argv++ = args;
      }
      ++(*numargs);

      while (true) {
        int copychar = 1;
        unsigned int numslash = 0;
        while (*cmdstart == '\\') {
          ++cmdstart;
          ++numslash;
        }

        if (*cmdstart == '"') {
          if ((numslash & 1u) == 0u) {
            if (inquote != 0 && cmdstart[1] == '"') {
              ++cmdstart;
            } else {
              copychar = 0;
              inquote = (inquote == 0) ? 1 : 0;
            }
          }
          numslash >>= 1u;
        }

        while (numslash != 0u) {
          --numslash;
          if (args != nullptr) {
            *args++ = '\\';
          }
          ++(*numchars);
        }

        const char current = *cmdstart;
        if (current == '\0' || (inquote == 0 && (current == ' ' || current == '\t'))) {
          break;
        }

        if (copychar != 0) {
          if (args != nullptr) {
            if (_ismbblead(static_cast<unsigned char>(current)) != 0) {
              *args++ = *cmdstart++;
              ++(*numchars);
            }
            *args++ = *cmdstart;
          } else if (_ismbblead(static_cast<unsigned char>(current)) != 0) {
            ++cmdstart;
            ++(*numchars);
          }
          ++(*numchars);
        }

        ++cmdstart;
      }

      if (args != nullptr) {
        *args++ = '\0';
      }
      ++(*numchars);
    }

    if (argv != nullptr) {
      *argv = nullptr;
    }
    ++(*numargs);
  }

  /**
   * Address: 0x00AAA91D (FUN_00AAA91D, __wincmdln)
   *
   * What it does:
   * Returns the first non-program-token character in `_acmdln`, honoring
   * quote state and multibyte lead-byte stepping used by CRT startup parsing.
   */
  extern "C" char* __cdecl __wincmdln()
  {
    if (__mbctype_initialized == 0) {
      __initmbctable();
    }

    char* cursor = (_acmdln != nullptr) ? _acmdln : const_cast<char*>("");
    bool inQuotes = false;

    while (true) {
      const unsigned char current = static_cast<unsigned char>(*cursor);
      if (current <= 0x20u) {
        if (current == 0u) {
          return cursor;
        }
        if (!inQuotes) {
          break;
        }
      }

      if (current == static_cast<unsigned char>('\"')) {
        inQuotes = !inQuotes;
      }

      if (_ismbblead(current) != 0) {
        ++cursor;
      }
      ++cursor;
    }

    while (*cursor != '\0' && static_cast<unsigned char>(*cursor) <= 0x20u) {
      ++cursor;
    }
    return cursor;
  }

  namespace
  {
    struct RuntimeTssSlotVector;
    using RuntimeTryEnterCriticalSectionFn = BOOL(WINAPI*)(LPCRITICAL_SECTION);

    RuntimeTryEnterCriticalSectionFn gRuntimeTryEnterCriticalSectionLegacyA = nullptr;
    RuntimeTryEnterCriticalSectionFn gRuntimeTryEnterCriticalSectionLegacyB = nullptr;

    extern "C" RuntimeTssSlotVector* __cdecl get_slots(bool alloc);
    extern "C" void __cdecl cleanup_slots(RuntimeTssSlotVector* slots);

  } // namespace

  /**
   * Address: 0x00ABE1FB (FUN_00ABE1FB, _initconin)
   *
   * What it does:
   * Opens the CRT console input handle (`"CONIN$"`) for read/write access and
   * stores it in the shared runtime console-input lane.
   */
  extern "C" HANDLE __cdecl _initconin()
  {
    gConsoleInputHandle = ::CreateFileA(
      "CONIN$",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      0u,
      nullptr
    );
    return gConsoleInputHandle;
  }

  /**
   * Address: 0x00ABE21A (FUN_00ABE21A, _initconout)
   *
   * What it does:
   * Opens the CRT console output handle (`"CONOUT$"`) for write access and
   * stores it in the shared runtime console-output lane.
   */
  extern "C" void __cdecl _initconout()
  {
    gConsoleOutputHandle = ::CreateFileA(
      "CONOUT$",
      GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      0u,
      nullptr
    );
  }

  /**
   * Address: 0x00ABE239 (FUN_00ABE239, _termcon)
   *
   * What it does:
   * Closes CRT console output/input handles when they are real kernel handles
   * (not sentinel `-1`/`-2` values).
   */
  extern "C" void __cdecl _termcon()
  {
    if (RuntimeConsoleHandleIsClosable(gConsoleOutputHandle)) {
      ::CloseHandle(gConsoleOutputHandle);
    }

    if (RuntimeConsoleHandleIsClosable(gConsoleInputHandle)) {
      ::CloseHandle(gConsoleInputHandle);
    }
  }

  /**
   * Address: 0x00AB7EF7 (FUN_00AB7EF7, _fptrap)
   *
   * What it does:
   * Raises CRT floating-point trap startup failure message lane via
   * `__amsg_exit(2)`.
   */
  extern "C" void __cdecl _fptrap()
  {
    __amsg_exit(2);
  }

  /**
   * Address: 0x00AB8080 (FUN_00AB8080, _copy_environ)
   *
   * What it does:
   * Duplicates one null-terminated `char**` environment pointer vector into
   * CRT heap storage and deep-copies each entry with `_strdup` semantics.
   */
  extern "C" char** __cdecl _copy_environ(const char* const* const sourceEnvironment)
  {
    if (sourceEnvironment == nullptr) {
      return nullptr;
    }

    std::size_t entryCount = 0u;
    while (sourceEnvironment[entryCount] != nullptr) {
      ++entryCount;
    }

    auto** const copiedEnvironment = static_cast<char**>(_calloc_crt(entryCount + 1u, sizeof(char*)));
    if (copiedEnvironment == nullptr) {
      __amsg_exit(9);
      return nullptr;
    }

    for (std::size_t entryIndex = 0u; entryIndex < entryCount; ++entryIndex) {
      copiedEnvironment[entryIndex] = RuntimeStrdup(sourceEnvironment[entryIndex]);
    }
    copiedEnvironment[entryCount] = nullptr;
    return copiedEnvironment;
  }

  /**
   * Address: 0x00ABDA15 (FUN_00ABDA15)
   *
   * What it does:
   * Returns the number of UTF-16 code units before NUL, bounded by
   * `maxCharacters`.
   */
  [[maybe_unused]] int RuntimeBoundedWideLength(
    const std::uint16_t* text,
    const int maxCharacters
  ) noexcept
  {
    int remaining = maxCharacters;
    while (remaining != 0) {
      --remaining;
      if (*text == 0u) {
        return maxCharacters - remaining - 1;
      }
      ++text;
    }

    remaining = -1;
    return maxCharacters - remaining - 1;
  }

  /**
   * Address: 0x00A8B161 (FUN_00A8B161, ___inittime)
   *
   * What it does:
   * Captures one FILETIME startup baseline used by legacy CRT clock tick
   * calculations.
   */
  extern "C" int __cdecl __inittime()
  {
    FILETIME systemTimeAsFileTime{};
    ::GetSystemTimeAsFileTime(&systemTimeAsFileTime);
    gRuntimeClockStartFiletime =
      BuildUnsigned64(systemTimeAsFileTime.dwLowDateTime, systemTimeAsFileTime.dwHighDateTime);
    return 0;
  }

  /**
   * Address: 0x00A96A90 (FUN_00A96A90, div64_0)
   *
   * What it does:
   * Performs the CRT's 64-bit unsigned division helper used by time/clock
   * conversions, including the normalization path for wide divisors.
   */
  extern "C" unsigned int __cdecl div64_0(unsigned __int64 dividend, __int64 divisor)
  {
    const std::uint64_t divisorUnsigned = static_cast<std::uint64_t>(divisor);
    if ((divisorUnsigned >> 32) != 0u) {
      std::uint32_t normalizedHigh = static_cast<std::uint32_t>(divisorUnsigned >> 32);
      std::uint32_t normalizedLow = static_cast<std::uint32_t>(divisorUnsigned);
      std::uint64_t normalizedDividend = dividend;
      do {
        const bool carry = (normalizedHigh & 1u) != 0u;
        normalizedHigh >>= 1;
        normalizedLow = (normalizedLow >> 1) | (static_cast<std::uint32_t>(carry) << 31);
        normalizedDividend >>= 1;
      } while (normalizedHigh != 0u);

      std::uint32_t quotient = static_cast<std::uint32_t>(normalizedDividend / normalizedLow);
      const std::uint32_t divisorHigh = static_cast<std::uint32_t>(divisorUnsigned >> 32);
      const std::uint32_t divisorLow = static_cast<std::uint32_t>(divisorUnsigned);
      const std::uint64_t lowProduct = static_cast<std::uint64_t>(divisorLow) * quotient;
      const std::uint64_t highProduct = static_cast<std::uint64_t>(divisorHigh) * quotient;
      const std::uint64_t productUpper = highProduct + (lowProduct >> 32);
      const std::uint64_t productLower = static_cast<std::uint32_t>(lowProduct);
      if ((productUpper >> 32) != 0u || (((productUpper & 0xFFFFFFFFULL) << 32) | productLower) > dividend) {
        --quotient;
      }
      return quotient;
    }

    const std::uint32_t divisorLow = static_cast<std::uint32_t>(divisorUnsigned);
    std::uint64_t combinedDividend = dividend;
    combinedDividend = (combinedDividend & 0x00000000FFFFFFFFULL)
      | (static_cast<std::uint64_t>(static_cast<std::uint32_t>(combinedDividend >> 32) % divisorLow) << 32);
    return static_cast<unsigned int>(combinedDividend / divisorLow);
  }

  /**
   * Address: 0x00A8A572 (FUN_00A8A572, _difftime64)
   *
   * What it does:
   * Returns `timeA - timeB` as `double` when both inputs are non-negative;
   * otherwise sets `errno=EINVAL` and returns `0.0`.
   */
extern "C" double __cdecl _difftime64(const __time64_t timeA, const __time64_t timeB)
{
  if (timeA >= 0 && timeB >= 0) {
    return static_cast<double>(timeA - timeB);
    }

  *_errno() = EINVAL;
  return 0.0;
}

  /**
   * Address: 0x009F2330 (FUN_009F2330, difftime)
   *
   * What it does:
   * Public `difftime(__time64_t, __time64_t)` entry point; forwards both
   * arguments to `_difftime64` unchanged.
   */
  extern "C" double __cdecl difftime(const __time64_t timeA, const __time64_t timeB)
  {
    return _difftime64(timeA, timeB);
  }

  /**
   * Address: 0x00AB7F03 (FUN_00AB7F03)
   *
   * IDA signature:
   * double __cdecl sub_AB7F03(double value);
   *
   * What it does:
   * Rounds `value` to the nearest integer using the x87 FPU's current
   * rounding-control-word mode (`frndint`) -- the round-to-nearest-per-mode
   * CRT internal used by the printf/scanf float formatting family, distinct
   * from `floor`/`ceil`'s fixed-direction rounding.
   */
  extern "C" double __cdecl RuntimeRoundDoubleToNearestFpuMode(const double value)
  {
    return std::nearbyint(value);
  }

  /**
   * Address: 0x009EFF10 (FUN_009EFF10, wcstombs)
   *
   * What it does:
   * CRT `wcstombs()` entry point wrapper. Applies the standard fast-path
   * pre-checks before dispatching to the locale-aware helper with a null
   * locale (active thread locale):
   * - when destination is null, zeroes the count lane and dispatches the
   *   size-query form (`wcstombs(nullptr, src, 0, nullptr)`),
   * - when destination is non-null and count is zero, returns zero without
   *   dispatching,
   * - when source is empty, writes a single terminator and returns zero,
   * - otherwise forwards to the locale-aware converter with no locale.
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

  /**
   * Address: 0x00A9491A (FUN_00A9491A, wcstombs_s)
   *
   * What it does:
   * Forwards to the locale-aware secure converter lane with a null locale so
   * conversion uses the active thread locale.
   */
  extern "C" int __cdecl wcstombs_s(
    std::size_t* const outConvertedCount,
    char* const destination,
    const std::size_t destinationSize,
    const wchar_t* const wideSource,
    const std::size_t maxWideChars
  )
  {
    return _wcstombs_s_l(outConvertedCount, destination, destinationSize, wideSource, maxWideChars, nullptr);
  }

  /**
   * Address: 0x00A835A8 (FUN_00A835A8, atol)
   *
   * IDA signature:
   * int __cdecl atol(const char *a1);
   *
   * What it does:
   * CRT `atol()` entry point. Parses one base-10 signed long from `text`
   * through the shared `strtol` lane, discarding the parse end pointer.
   */
  extern "C" long __cdecl atol(const char* const text)
  {
    return ::strtol(text, nullptr, 10);
  }

  /**
   * Address: 0x00AAA764 (FUN_00AAA764, _vsnprintf)
   *
   * IDA signature:
   * int __usercall vsnprintf@<eax>(char *const Buffer, const size_t BufferCount,
   *                                const char *const Format, va_list ArgList);
   *
   * What it does:
   * CRT `_vsnprintf()` entry point: forwards bounded narrow vararg formatting
   * to the locale-aware `_vsnprintf_l` lane with a null locale, so the active
   * thread locale is used.
   */
  extern "C" int __cdecl _vsnprintf(
    char* const buffer,
    const std::size_t count,
    const char* const format,
    va_list arguments
  )
  {
    return ::_vsnprintf_l(buffer, count, format, nullptr, arguments);
  }

  /**
   * Address: 0x00A8826E (FUN_00A8826E, wcsstr)
   *
   * IDA signature:
   * _WORD *__cdecl sub_A8826E(_WORD *a1, char *a2);
   *
   * What it does:
   * CRT `wcsstr()`: locates the first occurrence of the wide substring
   * `needle` inside `haystack`. An empty needle matches at the start of
   * `haystack`; returns null when no occurrence exists.
   */
  extern "C" wchar_t* __cdecl wcsstr(const wchar_t* haystack, const wchar_t* const needle)
  {
    if (*needle == L'\0') {
      return const_cast<wchar_t*>(haystack);
    }

    for (; *haystack != L'\0'; ++haystack) {
      const wchar_t* candidate = haystack;
      const wchar_t* pattern = needle;
      while (*pattern != L'\0' && *candidate == *pattern) {
        ++candidate;
        ++pattern;
      }
      if (*pattern == L'\0') {
        return const_cast<wchar_t*>(haystack);
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00A8F5FB (FUN_00A8F5FB, wcspbrk)
   *
   * IDA signature:
   * _WORD *__cdecl sub_A8F5FB(_WORD *a1, _WORD *a2);
   *
   * What it does:
   * CRT `wcspbrk()`: returns a pointer to the first character of `text` that
   * also occurs in the `charSet` control string, or null when `text` contains
   * no character from the set.
   */
  extern "C" wchar_t* __cdecl wcspbrk(const wchar_t* text, const wchar_t* const charSet)
  {
    for (; *text != L'\0'; ++text) {
      for (const wchar_t* candidate = charSet; *candidate != L'\0'; ++candidate) {
        if (*candidate == *text) {
          return const_cast<wchar_t*>(text);
        }
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00A90ED5 (FUN_00A90ED5, wcsncat)
   *
   * IDA signature:
   * _WORD *__cdecl sub_A90ED5(_WORD *a1, __int16 *a2, int a3);
   *
   * What it does:
   * CRT `wcsncat()`: appends at most `maxAppend` wide characters of `source`
   * onto the end of `destination` and terminates the result. Matches the CRT
   * body exactly, including the "stop early on source NUL" lane and the
   * unconditional terminator write when the count limit is what stops the
   * copy. Returns `destination`.
   */
  extern "C" wchar_t* __cdecl wcsncat(
    wchar_t* const destination,
    const wchar_t* source,
    std::size_t maxAppend
  )
  {
    wchar_t* cursor = destination;
    while (*cursor != L'\0') {
      ++cursor;
    }

    for (; maxAppend != 0u; --maxAppend) {
      const wchar_t copied = *source++;
      *cursor++ = copied;
      if (copied == L'\0') {
        return destination;
      }
    }

    *cursor = L'\0';
    return destination;
  }

  /**
   * Address: 0x00AB8823 (FUN_00AB8823, _mbsnbcmp_l)
   *
   * IDA signature:
   * int __cdecl _mbsnbcmp_l(unsigned char *lhsText, unsigned char *rhsText,
   *   size_t maxCount, _locale_t localeInfo);
   *
   * What it does:
   * Locale-aware, byte-count-bounded multibyte string compare. Under a
   * single-byte code page it defers straight to `strncmp`. Under a DBCS
   * code page it walks both strings, pairing a lead byte with its trailing
   * byte into one 16-bit character unit via `isLeadByte()` before
   * comparing, and returns a value with the same sign as `lhsValue -
   * rhsValue` for the first differing unit (matching `strncmp` semantics).
   *
   * `maxCount` bounds bytes read from `lhsText`'s lead byte and from
   * `rhsText`'s *trailing* byte specifically -- this asymmetry (a lead byte
   * read never itself decrements the budget a second time when consuming
   * its own trailing byte on the `lhsText` side, but does on the
   * `rhsText` side) is preserved exactly from the CRT body, quirks
   * included: if the budget runs out immediately after reading a lead byte
   * from `lhsText`, the CRT peeks (without consuming) `rhsText`'s current
   * byte and declares the strings equal outright when that peeked byte is
   * itself a lead byte.
   */
  extern "C" int __cdecl _mbsnbcmp_l(
    const unsigned char* lhsText,
    const unsigned char* rhsText,
    std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    if (maxCount == 0u) {
      return 0;
    }

    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (!locale.isMultibyteCodePage()) {
      return std::strncmp(
        reinterpret_cast<const char*>(lhsText),
        reinterpret_cast<const char*>(rhsText),
        maxCount);
    }

    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    const unsigned char* p1 = lhsText;
    const unsigned char* p2 = rhsText;

    for (;;) {
      // lhsText side: the lead/single byte read always consumes one unit of
      // budget; consuming its trailing byte (if any) does not.
      const unsigned int c1 = *p1++;
      --maxCount;

      unsigned int value1;
      bool p1TruncatedAtBudget = false;
      unsigned int peekedValue2 = 0u;

      if (!locale.isLeadByte(c1)) {
        value1 = c1;
      } else if (maxCount == 0u) {
        // Budget exhausted right after the lead byte: peek (do not consume)
        // rhsText's current byte. If it is itself a lead byte, the CRT body
        // declares the strings equal immediately.
        peekedValue2 = *p2;
        if (locale.isLeadByte(peekedValue2)) {
          return 0;
        }
        value1 = 0u;
        p1TruncatedAtBudget = true;
      } else {
        const unsigned int c1Trail = p1[0];
        if (c1Trail == 0u) {
          value1 = 0u;
        } else {
          ++p1;
          value1 = (c1 << 8) | c1Trail;
        }
      }

      // rhsText side.
      unsigned int value2;
      if (p1TruncatedAtBudget) {
        value2 = peekedValue2;
      } else {
        const unsigned int c2 = *p2++;
        if (!locale.isLeadByte(c2)) {
          value2 = c2;
        } else if (maxCount == 0u) {
          value2 = 0u;
        } else {
          const unsigned int c2Trail = p2[0];
          --maxCount;
          if (c2Trail == 0u) {
            value2 = 0u;
          } else {
            ++p2;
            value2 = (c2 << 8) | c2Trail;
          }
        }
      }

      if (value2 != value1) {
        return (value2 < value1) ? 1 : -1;
      }

      if (value1 == 0u || maxCount == 0u) {
        return 0;
      }
    }
  }

  /**
   * Address: 0x00AB8E66 (FUN_00AB8E66, _mbschr_l)
   *
   * IDA signature:
   * char *__cdecl mbschr_l(char *Str1, int Val, _LocaleUpdate *a3);
   *
   * What it does:
   * Locale-aware multibyte `strchr`. Under a single-byte code page it defers
   * to plain `strchr`; under a DBCS code page it walks the string two bytes at
   * a time whenever the current byte is a lead byte, so a double-byte
   * character is only matched against the full 16-bit `searchChar` and never
   * against one of its halves. A null `text` reports `EINVAL` through the
   * invalid-parameter lane and returns null.
   */
  extern "C" unsigned char* __cdecl _mbschr_l(
    const unsigned char* const text,
    const unsigned int searchChar,
    _locale_t const localeInfo
  )
  {
    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (text == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    if (!locale.isMultibyteCodePage()) {
      return reinterpret_cast<unsigned char*>(
        const_cast<char*>(std::strchr(reinterpret_cast<const char*>(text), static_cast<int>(searchChar)))
      );
    }

    const unsigned char* cursor = text;
    while (*cursor != '\0') {
      if (locale.isLeadByte(*cursor)) {
        const unsigned int leadByte = *cursor;
        if (cursor[1] == '\0') {
          return nullptr;
        }
        if (searchChar == ((leadByte << 8) | cursor[1])) {
          return const_cast<unsigned char*>(cursor);
        }
        cursor += 2;
        continue;
      }

      if (searchChar == *cursor) {
        return const_cast<unsigned char*>(cursor);
      }
      ++cursor;
    }

    // Trailing NUL still matches a zero search character, as in the CRT body.
    return (searchChar == *cursor) ? const_cast<unsigned char*>(cursor) : nullptr;
  }

  /**
   * Address: 0x00AA48A1 (FUN_00AA48A1, _mbsrchr_l)
   *
   * IDA signature:
   * char *__cdecl mbsrchr_l(char *Str, int a2, _LocaleUpdate *a3);
   *
   * What it does:
   * Locale-aware multibyte `strrchr`: returns the *last* occurrence of
   * `searchChar`. Under a single-byte code page it defers to `strrchr`;
   * otherwise it scans forward remembering the most recent match, treating
   * lead-byte pairs as one double-byte character. A truncated trailing lead
   * byte ends the scan, and matches the terminator only when nothing has
   * matched yet -- both quirks are preserved from the CRT body.
   */
  extern "C" unsigned char* __cdecl _mbsrchr_l(
    const unsigned char* const text,
    const unsigned int searchChar,
    _locale_t const localeInfo
  )
  {
    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (!locale.isMultibyteCodePage()) {
      return reinterpret_cast<unsigned char*>(
        const_cast<char*>(std::strrchr(reinterpret_cast<const char*>(text), static_cast<int>(searchChar)))
      );
    }

    if (text == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    const unsigned char* lastMatch = nullptr;
    const unsigned char* cursor = text;
    for (;;) {
      const unsigned int current = *cursor;
      unsigned char scanned = *cursor;

      if (locale.isLeadByte(current)) {
        scanned = cursor[1];
        if (scanned != '\0') {
          if (searchChar == ((current << 8) | scanned)) {
            lastMatch = cursor;
          }
          cursor += 2;
          continue;
        }
        // Truncated lead byte at end of string: only the "nothing matched
        // yet" case records this position.
        if (lastMatch == nullptr) {
          lastMatch = cursor + 1;
        }
      } else if (searchChar == current) {
        lastMatch = cursor;
      }

      ++cursor;
      if (scanned == '\0') {
        break;
      }
    }

    return const_cast<unsigned char*>(lastMatch);
  }

  /**
   * Address: 0x00AB99FD (FUN_00AB99FD, _memicmp_l)
   *
   * IDA signature:
   * int __cdecl memicmp_l(unsigned __int8 *dst, unsigned __int8 *src,
   *                       unsigned int count, _locale_tstruct *plocinfo);
   *
   * What it does:
   * Case-insensitive memory compare under an explicit locale. A zero count
   * compares equal before the locale is even resolved. When the locale has no
   * active ctype handle the ASCII fast path (`__ascii_memicmp`) is used;
   * otherwise each byte pair is folded through `_tolower_l` and compared until
   * the count runs out, a NUL is folded, or the bytes differ. Null buffers or
   * a count above `INT_MAX` report `EINVAL` and return `INT_MAX`.
   */
  extern "C" int __cdecl _memicmp_l(
    const void* const lhsBuffer,
    const void* const rhsBuffer,
    const std::size_t byteCount,
    _locale_t const localeInfo
  )
  {
    if (byteCount == 0u) {
      return 0;
    }

    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (lhsBuffer == nullptr || rhsBuffer == nullptr || byteCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    const auto* lhsBytes = static_cast<const unsigned char*>(lhsBuffer);
    const auto* rhsBytes = static_cast<const unsigned char*>(rhsBuffer);

    if (locale.loc()->lcHandle[2] == 0) {
      return RuntimeAsciiMemicmp(lhsBytes, rhsBytes, static_cast<int>(byteCount));
    }

    std::size_t remaining = byteCount;
    int lhsFolded = 0;
    int rhsFolded = 0;
    do {
      lhsFolded = _tolower_l(*lhsBytes++, locale.asLocale());
      rhsFolded = _tolower_l(*rhsBytes++, locale.asLocale());
      --remaining;
    } while (remaining != 0u && lhsFolded != 0 && lhsFolded == rhsFolded);

    return lhsFolded - rhsFolded;
  }

  /**
   * Address: 0x00AB7F14 (FUN_00AB7F14, _strnicoll_l)
   *
   * IDA signature:
   * int __usercall _strnicoll_l@<eax>(const char *String1, const char *String2,
   *                                   size_t MaxCount, _locale_t Locale);
   *
   * What it does:
   * Bounded case-insensitive narrow collation. A zero count collates equal.
   * When the locale carries a collate handle the comparison is delegated to
   * `__crtCompareStringA(NORM_IGNORECASE | LOCALE_USE_CP_ACP)` and the Win32
   * 1/2/3 result is rebased to the C -1/0/1 convention; a zero return from
   * Win32 is an error and reports `EINVAL`. Without a collate handle it falls
   * back to the case-folding byte compare in `_memicmp_l`.
   */
  extern "C" int __cdecl _strnicoll_l(
    const char* const lhsText,
    const char* const rhsText,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (maxCount == 0u) {
      return 0;
    }

    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    if (maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    const LCID collateHandle = locale.loc()->lcHandle[1];
    if (collateHandle == 0) {
      return _memicmp_l(lhsText, rhsText, maxCount, locale.asLocale());
    }

    const int comparison = __crtCompareStringA(
      locale.asLocale(),
      collateHandle,
      NORM_IGNORECASE | LOCALE_USE_CP_ACP,
      lhsText,
      static_cast<int>(maxCount),
      rhsText,
      static_cast<int>(maxCount),
      locale.loc()->lcCollateCp
    );
    if (comparison == 0) {
      *_errno() = EINVAL;
      return 0x7FFFFFFF;
    }

    return comparison - 2;
  }

  /**
   * Address: 0x00A9B334 (FUN_00A9B334, _mbsnbicoll_l)
   *
   * IDA signature:
   * int __usercall _mbsnbicoll_l@<eax>(const unsigned __int8 *Str1,
   *   const unsigned __int8 *Str2, size_t MaxCount, _locale_t Locale);
   *
   * What it does:
   * Byte-bounded case-insensitive multibyte collation. A zero count collates
   * equal. Under a DBCS code page the comparison runs through
   * `__crtCompareStringA` on the multibyte LCID/code page and the Win32
   * 1/2/3 result is rebased to -1/0/1; a zero return propagates as `INT_MAX`
   * without touching `errno` (unlike the narrow lane). Under a single-byte
   * code page it defers to `_strnicoll_l`, forwarding the *caller's* original
   * locale argument rather than the resolved scope.
   */
  extern "C" int __cdecl _mbsnbicoll_l(
    const unsigned char* const lhsText,
    const unsigned char* const rhsText,
    const std::size_t maxCount,
    _locale_t const localeInfo
  )
  {
    const RuntimeLocaleUpdateScope locale(localeInfo);

    if (maxCount == 0u) {
      return 0;
    }

    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    if (maxCount > 0x7FFFFFFFu) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    if (!locale.isMultibyteCodePage()) {
      return _strnicoll_l(
        reinterpret_cast<const char*>(lhsText),
        reinterpret_cast<const char*>(rhsText),
        maxCount,
        localeInfo
      );
    }

    const int comparison = __crtCompareStringA(
      locale.asLocale(),
      locale.mbc()->mblcid,
      NORM_IGNORECASE | LOCALE_USE_CP_ACP,
      reinterpret_cast<LPCCH>(lhsText),
      static_cast<int>(maxCount),
      reinterpret_cast<LPCCH>(rhsText),
      static_cast<int>(maxCount),
      static_cast<int>(locale.mbc()->mbcodepage)
    );
    if (comparison == 0) {
      return 0x7FFFFFFF;
    }

    return comparison - 2;
  }

  /**
   * Address: 0x00A8F089 (FUN_00A8F089, iswdigit)
   *
   * IDA signature:
   * int __cdecl sub_A8F089(WCHAR a1);
   *
   * What it does:
   * CRT `iswdigit()`: classifies one wide character through `iswctype` with
   * the `_DIGIT` mask (0x4, confirmed as the literal `push 4` at 0x00A8F089).
   */
  extern "C" int __cdecl iswdigit(const wint_t character)
  {
    return ::iswctype(character, _DIGIT);
  }

  /**
   * Address: 0x00A8F0D1 (FUN_00A8F0D1, iswspace)
   *
   * IDA signature:
   * int __cdecl sub_A8F0D1(WCHAR a1);
   *
   * What it does:
   * CRT `iswspace()`: classifies one wide character through `iswctype` with
   * the `_SPACE` mask (0x8, confirmed as the literal `push 8` at 0x00A8F0D1).
   */
  extern "C" int __cdecl iswspace(const wint_t character)
  {
    return ::iswctype(character, _SPACE);
  }

  /**
   * Address: 0x00A86A7F (FUN_00A86A7F, _ftime64)
   *
   * IDA signature:
   * void callcnv_33 ftime64(struct __timeb64 *Time);
   *
   * What it does:
   * CRT `_ftime64()`: a one-instruction tail-jump thunk onto the secure
   * `_ftime64_s` lane, discarding its `errno_t` result. IDA marks the body
   * `thunk` for exactly that reason.
   */
  extern "C" void __cdecl _ftime64(struct __timeb64* const timeBuffer)
  {
    (void)::_ftime64_s(timeBuffer);
  }

  using RuntimeVirtualDestroyWithFlagFn = int(__thiscall*)(void* owner, int destroyFlag);

  using RuntimeComSlotDispatchFn = int(__stdcall*)(void*);

  using RuntimeVirtualForwardSlot16Fn = void(
    __thiscall*
  )(void*, int, int, int, int, int, int, int, int, int, int);

  using RuntimeSortCompareUnsignedAddressFn = int(__cdecl*)(unsigned int, unsigned int);

  /**
   * Address: 0x00A48A40 (FUN_00A48A40)
   *
   * What it does:
   * Reverses the byte order of `count` fixed-size records (each `recordSize`
   * bytes) in place starting at `buffer` -- an in-place endian-swap utility
   * applied to arrays of small binary records read directly off disk.
   */
  void ReverseRecordByteOrder(const std::int32_t recordSize, const std::int32_t count, void* const buffer)
  {
    if (buffer == nullptr || recordSize <= 0 || count <= 0) {
      return;
    }

    auto* cursor = static_cast<std::uint8_t*>(buffer);
    const std::int32_t halfSize = recordSize / 2;
    for (std::int32_t i = 0; i < count; ++i, cursor += recordSize) {
      for (std::int32_t j = 0; j < halfSize; ++j) {
        std::swap(cursor[j], cursor[recordSize - 1 - j]);
      }
    }
  }

  /**
   * Address: 0x00A48C90 (FUN_00A48C90)
   *
   * What it does:
   * Reads `count` 16-bit values from `file` into `buffer` via `fread`, then
   * byte-swaps each one in place (`ReverseRecordByteOrder`) -- a foreign-
   * endian array read helper. Returns the byte count requested (`count*2`).
   */
  std::size_t ReadAndByteSwapU16Array(void* const buffer, const std::size_t count, std::FILE* const file)
  {
    (void)std::fread(buffer, 2u, count, file);
    ReverseRecordByteOrder(2, static_cast<std::int32_t>(count), buffer);
    return count * 2u;
  }

} // namespace moho::runtime

