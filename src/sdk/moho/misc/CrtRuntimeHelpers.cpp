#include <Windows.h>

#include <bit>
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
#include <float.h>
#include <io.h>
#include <intrin.h>
#include <locale>
#include <list>
#include <mutex>
#include <new>
#include <streambuf>
#include <stdexcept>
#include <string>
#include <sys/timeb.h>
#include <typeinfo>

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
#ifdef __mb_cur_max
#undef __mb_cur_max
#endif

extern "C" void __cdecl _lock(int locknum);
extern "C" void __cdecl _unlock(int locknum);
extern "C" void __cdecl _lock_file(std::FILE* stream);
extern "C" void __cdecl __lock_file2(int streamIndex, std::FILE* stream);
extern "C" void __cdecl __unlock_file2(int streamIndex, std::FILE* stream);
extern "C" int __cdecl _fflush_nolock(std::FILE* stream);
extern "C" int __cdecl _fclose_nolock(std::FILE* stream);
extern "C" int __cdecl _getdrive();
extern "C" void __cdecl _dosmaperr(unsigned long osErrorCode);
extern "C" int __cdecl _get_winmajor(unsigned int* majorVersion);
extern "C" int __cdecl _tsopen_helper(
  const char* fileName,
  int openFlags,
  int shareFlags,
  int permissionFlags,
  int* outFileHandle,
  int secureMode
);
extern "C" int _nhandle;
extern "C" int _commode;
extern "C" int _cflush;
extern "C" int _fmode;
extern "C" unsigned int _nstream;
extern "C" std::FILE** __piob;
extern "C" unsigned char _exitflag;
extern "C" std::uintptr_t __security_cookie;
extern "C" std::uintptr_t __enable_percent_n;
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
extern "C" int __mbctype_initialized;
extern "C" int __cdecl __initmbctable();
extern "C" int __cdecl _ismbblead(unsigned int value);
extern "C" BOOL __cdecl __local_unwind4(void* registrationFrame, int currentTryLevel, unsigned int targetTryLevel);
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
 * Address: 0x00ACE110 (FUN_00ACE110, _SFUO_Init)
 *
 * What it does:
 * Preserves one CRT SFUO startup lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Init()
{
  return 0;
}

/**
 * Address: 0x00ACE120 (FUN_00ACE120, _SFUO_Finish)
 *
 * What it does:
 * Preserves one CRT SFUO finish lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Finish()
{
  return 0;
}

/**
 * Address: 0x00ACE2E0 (FUN_00ACE2E0, _SFUO_Destroy)
 *
 * What it does:
 * Preserves one CRT SFUO teardown lane as a success no-op.
 */
extern "C" int __cdecl _SFUO_Destroy()
{
  return 0;
}

namespace
{
  int gRuntimeErrorMode = 0;

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

struct RuntimeStdExceptionLayout
{
  void* vtable;
  const char* what;
  int doFree;
};
static_assert(sizeof(RuntimeStdExceptionLayout) == 0x0C, "RuntimeStdExceptionLayout size must be 0x0C");

struct RuntimeTypeInfoView
{
  void* vtable;
  void* spare;
  const char* decoratedName;
};
static_assert(sizeof(RuntimeTypeInfoView) == 0x0C, "RuntimeTypeInfoView size must be 0x0C");

struct RuntimeTypeInfoMapPair
{
  const std::type_info* keyTypeInfo;
  void* valueTypeInfo;
};
static_assert(sizeof(RuntimeTypeInfoMapPair) == 0x08, "RuntimeTypeInfoMapPair size must be 0x08");

struct RuntimeTypeInfoMapNode
{
  RuntimeTypeInfoMapNode* left;
  RuntimeTypeInfoMapNode* parent;
  RuntimeTypeInfoMapNode* right;
  RuntimeTypeInfoMapPair pair;
  std::uint8_t color;
  std::uint8_t isNil;
  std::uint8_t reserved16;
  std::uint8_t reserved17;
};
static_assert(sizeof(RuntimeTypeInfoMapNode) == 0x18, "RuntimeTypeInfoMapNode size must be 0x18");
static_assert(offsetof(RuntimeTypeInfoMapNode, left) == 0x00, "RuntimeTypeInfoMapNode::left offset must be 0x00");
static_assert(offsetof(RuntimeTypeInfoMapNode, parent) == 0x04, "RuntimeTypeInfoMapNode::parent offset must be 0x04");
static_assert(offsetof(RuntimeTypeInfoMapNode, right) == 0x08, "RuntimeTypeInfoMapNode::right offset must be 0x08");
static_assert(offsetof(RuntimeTypeInfoMapNode, pair) == 0x0C, "RuntimeTypeInfoMapNode::pair offset must be 0x0C");
static_assert(offsetof(RuntimeTypeInfoMapNode, color) == 0x14, "RuntimeTypeInfoMapNode::color offset must be 0x14");
static_assert(offsetof(RuntimeTypeInfoMapNode, isNil) == 0x15, "RuntimeTypeInfoMapNode::isNil offset must be 0x15");

/**
 * Address: 0x008DA230 (FUN_008DA230, _Tree::_Buynode)
 *
 * What it does:
 * Allocates one red-black tree node for the `type_info* -> value` map and
 * initializes linkage, payload, and color/nil marker lanes.
 */
RuntimeTypeInfoMapNode* RuntimeTypeInfoMapAllocateNode(
  RuntimeTypeInfoMapNode* const left,
  RuntimeTypeInfoMapNode* const parent,
  RuntimeTypeInfoMapNode* const right,
  const RuntimeTypeInfoMapPair* const value,
  const std::uint8_t color
)
{
  auto* const node = static_cast<RuntimeTypeInfoMapNode*>(::operator new(sizeof(RuntimeTypeInfoMapNode)));
  if (node != nullptr) {
    node->left = left;
    node->right = right;
    node->parent = parent;
    node->pair = *value;
    node->color = color;
    node->isNil = 0;
  }
  return node;
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

struct RuntimeRttiCompleteObjectLocator
{
  std::uint32_t signature;
  std::uint32_t offset;
  std::uint32_t cdOffset;
  const std::type_info* typeDescriptor;
  RuntimeRttiClassHierarchyDescriptor* classDescriptor;
};
static_assert(sizeof(RuntimeRttiCompleteObjectLocator) == 0x14, "RuntimeRttiCompleteObjectLocator size must be 0x14");
static_assert(
  offsetof(RuntimeRttiCompleteObjectLocator, offset) == 0x04,
  "RuntimeRttiCompleteObjectLocator::offset offset must be 0x04"
);
static_assert(
  offsetof(RuntimeRttiCompleteObjectLocator, cdOffset) == 0x08,
  "RuntimeRttiCompleteObjectLocator::cdOffset offset must be 0x08"
);
static_assert(
  offsetof(RuntimeRttiCompleteObjectLocator, classDescriptor) == 0x10,
  "RuntimeRttiCompleteObjectLocator::classDescriptor offset must be 0x10"
);

[[nodiscard]] inline const char* RuntimeTypeInfoDecoratedName(const std::type_info* const type) noexcept
{
  if (type == nullptr) {
    return nullptr;
  }

  const auto* const view = reinterpret_cast<const RuntimeTypeInfoView*>(type);
  if (view->decoratedName != nullptr) {
    return view->decoratedName;
  }
  return type->name();
}

[[nodiscard]] inline bool RuntimeTypeInfoMatches(
  const std::type_info* const lhs,
  const std::type_info* const rhs
) noexcept
{
  if (lhs == rhs) {
    return true;
  }
  if (lhs == nullptr || rhs == nullptr) {
    return false;
  }

  const char* const lhsName = RuntimeTypeInfoDecoratedName(lhs);
  const char* const rhsName = RuntimeTypeInfoDecoratedName(rhs);
  return lhsName != nullptr && rhsName != nullptr && std::strcmp(lhsName, rhsName) == 0;
}

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

[[nodiscard]] inline const RuntimeRttiBaseClassDescriptor*
RuntimeGetContainedBaseDescriptor(const RuntimeRttiBaseClassDescriptor* const root, const unsigned int relativeIndex) noexcept
{
  if (root == nullptr || root->classHierarchyDescriptor == nullptr || root->classHierarchyDescriptor->baseClassArray == nullptr) {
    return nullptr;
  }
  if (relativeIndex >= root->classHierarchyDescriptor->numBaseClasses) {
    return nullptr;
  }
  return root->classHierarchyDescriptor->baseClassArray[relativeIndex];
}

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
  std::uint8_t reserved00[0x6C];
  RuntimeLocaleCodePageView* ptlocinfo;
  std::int32_t ownlocale;
  std::uint8_t reserved74[0x24];
  RuntimeFrameInfoNode* frameInfoChain;
  RuntimeSetLocLocaleView setlocData;
};
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
extern "C" int _getvalueindex;
extern "C" void __cdecl _freefls(void* ptd);
extern "C" int __cdecl _flsbuf(int character, std::FILE* stream);
extern "C" int __cdecl _isctype_l(int character, int mask, _locale_t localeInfo);
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
using RuntimePurecallHandler = int(__cdecl*)();
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
extern "C" int __cdecl _mbsnbcmp_l(
  const unsigned char* lhsText,
  const unsigned char* rhsText,
  std::size_t maxCount,
  _locale_t localeInfo
);
extern "C" unsigned char* __cdecl _mbschr_l(const unsigned char* text, unsigned int ch, _locale_t localeInfo);
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
extern "C" int __cdecl _ismbblead_l(unsigned int value, _locale_t localeInfo);
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
extern "C" int __locale_changed;
extern "C" long _timezone;
extern "C" long _dstbias;
#ifdef _tzname
#undef _tzname
#endif
extern "C" char* _tzname[2];
extern "C" int daylight;
extern "C" HANDLE _crtheap;
extern "C" int _active_heap;
extern "C" void __cdecl _CrtSetCheckCount();

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
 */
extern "C" double __cdecl strtod(const char* text, char** endPtr)
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
    return ::_toupper_l(character, nullptr);
  }

  if (static_cast<unsigned int>(character - static_cast<int>('a'))
      <= static_cast<unsigned int>('z' - 'a')) {
    return character - static_cast<int>('a' - 'A');
  }

  return character;
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
 * Address: 0x00A8EAC4 (FUN_00A8EAC4, _strtol_l)
 *
 * What it does:
 * Locale-explicit byte-string signed parse lane that forwards directly to
 * `strtoxl` with signed conversion mode.
 */
long __cdecl Runtime_strtol_l(
  const unsigned char* const text,
  unsigned char** const endPointer,
  const int radix,
  RuntimeLocaleInfoStruct* const localeInfo
)
{
  return static_cast<long>(strtoxl(
    localeInfo,
    reinterpret_cast<const char*>(text),
    reinterpret_cast<char**>(endPointer),
    radix,
    0
  ));
}

/**
 * Address: 0x00A8EADF (FUN_00A8EADF, strtoul_0)
 *
 * What it does:
 * Byte-string variant of the unsigned `strtoul` lane used by parser callsites
 * that carry `unsigned char*` text/end pointers.
 */
unsigned long RuntimeStrtoulByteString(
  const unsigned char* const text,
  unsigned char** const endPointer,
  const int radix
)
{
  RuntimeLocaleInfoStruct* localeInfo =
    (__locale_changed != 0) ? nullptr : &__initiallocalestructinfo;
  return strtoxl(
    localeInfo,
    reinterpret_cast<const char*>(text),
    reinterpret_cast<char**>(endPointer),
    radix,
    1
  );
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
 * Address: 0x00A96E17 (FUN_00A96E17, write_char_0)
 *
 * What it does:
 * Writes one buffered character into a legacy CRT stream and updates the
 * written-count lane with buffered-output fallback semantics.
 */
static void RuntimeWriteBufferedChar(std::FILE* const f, int ch, int* const pnumwritten)
{
  RuntimeWriteBufferedCharImpl(f, ch, pnumwritten);
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
 *
 * What it does:
 * Writes one bounded narrow string lane into a legacy CRT stream, preserving
 * buffered-output semantics and `_errno()`-driven fallback behavior.
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
 * Address: 0x00AAA764 (FUN_00AAA764, _vsnprintf)
 *
 * What it does:
 * Forwards narrow vararg formatting to `_vsnprintf_l` with null locale so the
 * active thread locale lane is used.
 */
static int RuntimeVsnprintfCompat(
  char* const buffer,
  const std::size_t bufferCount,
  const char* const format,
  va_list argList
)
{
  return ::_vsnprintf_l(buffer, bufferCount, format, nullptr, argList);
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

  constexpr int kRuntimeEnvironmentLock = 7;
  constexpr int kRuntimeSetLocaleLock = 12;
  constexpr int kRuntimeIobScanLock = 1;
  constexpr int kRuntimeSignalLock = 0;
  constexpr int kRuntimeTimeLock = 6;
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
  void* gRuntimeTerminateActionEncoded = nullptr;
  RuntimeInvalidArgHandler gRuntimeInvalidArgHandler = nullptr;
  RuntimePurecallHandler gRuntimePurecallHandler = nullptr;
  RuntimeHeapFailureHandler gRuntimeHeapFailureHandler = nullptr;
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
   * Address: 0x00AC0730 (FUN_00AC0730, _Mtxdst)
   *
   * What it does:
   * Destroys one CRT mutex critical-section lane.
   */
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
  static_assert(sizeof(RuntimeThreadLocInfoView) == 0xD8, "RuntimeThreadLocInfoView size must be 0xD8");

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
  using ThreadExitHandlerList = std::list<ThreadExitHandler>;

  /**
   * Address: 0x00AC5B70 (FUN_00AC5B70, std::list_thread_exit_handler::~list_thread_exit_handler)
   * Mangled: ??1list_thread_exit_handler@std@@QAE@@Z
   *
   * What it does:
   * Runs one thread-exit handler list destructor lane (node chain + sentinel
   * node teardown) and leaves the list object in a null-head state.
   */
  void RuntimeThreadExitHandlerListDestructor(ThreadExitHandlerList* const handlers)
  {
    if (handlers == nullptr) {
      return;
    }

    handlers->~ThreadExitHandlerList();
  }

  /**
   * Address: 0x00AC5C30 (FUN_00AC5C30)
   *
   * What it does:
   * Implements the deleting-dtor wrapper for the thread-exit list lane and
   * conditionally frees storage when bit0 of `deleteFlags` is set.
   */
  ThreadExitHandlerList* RuntimeThreadExitHandlerListDeleteWithFlags(
    ThreadExitHandlerList* const handlers,
    const std::uint8_t deleteFlags
  )
  {
    RuntimeThreadExitHandlerListDestructor(handlers);
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(handlers);
    }
    return handlers;
  }
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

  /**
   * Address: 0x00AA5378 (FUN_00AA5378, _tsopen_s)
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

  /**
   * Address: 0x00A959BD (FUN_00A959BD, encoded_null)
   *
   * What it does:
   * Returns one encoded null pointer through the CRT encode-pointer lane, used
   * as the sentinel value for unset signal/exit action slots.
   */
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
   * Address: 0x00A96A15 (FUN_00A96A15, _initp_heap_handler)
   *
   * What it does:
   * Publishes the CRT heap-allocation failure handler pointer lane.
   */
  extern "C" void __cdecl _initp_heap_handler(RuntimeHeapFailureHandler const handler)
  {
    gRuntimeHeapFailureHandler = handler;
  }

  [[nodiscard]] inline void*& RuntimeTypeInfoFrameStateSlot(std::type_info* const typeInfo) noexcept
  {
    return reinterpret_cast<RuntimeTypeInfoView*>(typeInfo)->spare;
  }

  [[nodiscard]] inline void* RuntimeTypeInfoBaseVtableLane() noexcept
  {
    static const std::type_info& kTypeInfoAnchor = typeid(void);
    return reinterpret_cast<const RuntimeTypeInfoView*>(&kTypeInfoAnchor)->vtable;
  }

  /**
   * Address: 0x00A962E6 (FUN_00A962E6, func_FreeTypeInfoFrame)
   *
   * What it does:
   * Removes one `type_info::_m_data` frame payload from the global intrusive
   * type-info frame list under `_TYPEINFO_LOCK`, then frees that payload.
   */
  void RuntimeFreeTypeInfoFrame(std::type_info* const typeInfo)
  {
    RuntimeLockGuard lockGuard(kRuntimeTypeInfoLock);

    void*& frameStateSlot = RuntimeTypeInfoFrameStateSlot(typeInfo);
    void* const frameState = frameStateSlot;
    if (frameState == nullptr) {
      return;
    }

    RuntimeTypeInfoFrameListNode* previous = &gRuntimeTypeInfoFrameRoot;
    for (RuntimeTypeInfoFrameListNode* node = gRuntimeTypeInfoFrameRoot.next; node != nullptr; node = node->next) {
      if (node->frameState == frameState) {
        previous->next = node->next;
        _free_crt(node);
        break;
      }
      previous = node;
    }

    _free_crt(frameState);
    frameStateSlot = nullptr;
  }

  /**
   * Address: 0x00A8243C (FUN_00A8243C, ??1type_info@@QAE@@Z [type_info::~type_info])
   *
   * What it does:
   * Restores one `std::type_info` base vtable lane and releases its
   * associated type-info frame state through the frame cleanup helper.
   */
  void RuntimeTypeInfoDestructorWrapper(std::type_info* const typeInfo)
  {
    auto* const typeInfoView = reinterpret_cast<RuntimeTypeInfoView*>(typeInfo);
    typeInfoView->vtable = RuntimeTypeInfoBaseVtableLane();
    RuntimeFreeTypeInfoFrame(typeInfo);
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
   * Address: 0x00A82D30 (FUN_00A82D30, strchr)
   *
   * What it does:
   * Returns the first occurrence of `value` in `text`, or `nullptr` when no
   * matching byte is present before the NUL terminator.
   */
  extern "C" char* __cdecl strchr(const char* const text, const int value)
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
   * Address: 0x00A887DA (FUN_00A887DA, _wcsicmp_l)
   *
   * What it does:
   * Locale-aware wide case-insensitive string compare; reports CRT
   * invalid-parameter semantics on null inputs and returns `0x7FFFFFFF` on
   * failure, otherwise forwards to the UCRT lane.
   */
  int RuntimeWcsicmpLocale(const wchar_t* const lhsText, const wchar_t* const rhsText, _locale_t const localeInfo)
  {
    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_wcsicmp_l(lhsText, rhsText, localeInfo);
  }

  /**
   * Address: 0x00AA48A1 (FUN_00AA48A1, _mbsrchr_l)
   *
   * What it does:
   * Locale-aware reverse multibyte character search; falls back to ASCII
   * `strrchr` in single-byte codepages and reports invalid-parameter semantics
   * on null input.
   */
  unsigned char* RuntimeMbsrchrLocale(
    const unsigned char* const text,
    const unsigned int searchChar,
    _locale_t const localeInfo
  )
  {
    if (text == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    return ::_mbsrchr_l(text, searchChar, localeInfo);
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
   * Address: 0x00AB8823 (FUN_00AB8823, _mbsnbcmp_l)
   *
   * What it does:
   * Locale-aware bounded multibyte byte-count compare; returns `0` on a
   * zero-length request and reports invalid-parameter semantics on null input
   * before forwarding to the UCRT lane.
   */
  int RuntimeMbsnbcmpLocale(
    const unsigned char* const lhsText,
    const unsigned char* const rhsText,
    const std::size_t byteCount,
    _locale_t const localeInfo
  )
  {
    if (byteCount == 0u) {
      return 0;
    }

    if (lhsText == nullptr || rhsText == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return 0x7FFFFFFF;
    }

    return ::_mbsnbcmp_l(lhsText, rhsText, byteCount, localeInfo);
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
   * Address: 0x00AB8E66 (FUN_00AB8E66, _mbschr_l)
   *
   * What it does:
   * Locale-aware multibyte character search; walks lead/trail pairs in DBCS
   * codepages and reports invalid-parameter semantics on null input.
   */
  unsigned char* RuntimeMbschrLocale(
    const unsigned char* const text,
    const unsigned int searchChar,
    _locale_t const localeInfo
  )
  {
    if (text == nullptr) {
      *_errno() = EINVAL;
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
      return nullptr;
    }

    return ::_mbschr_l(text, searchChar, localeInfo);
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
    return _wcsftime_l(lpWideCharStr, maxSize, format, timeData, nullptr);
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

  [[nodiscard]] int RuntimeSseProbeExceptionFilter(const unsigned int exceptionCode) noexcept
  {
    if (exceptionCode == EXCEPTION_ACCESS_VIOLATION || exceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
      return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
  }

  /**
   * Address: 0x00AAA815 (FUN_00AAA815, func_GetCompatModeSub)
   *
   * What it does:
   * Probes whether one SSE2 lane can execute safely by issuing `movapd` in an
   * SEH guard and treating AV/illegal-instruction exceptions as incompatibility.
   */
  int RuntimeProbeSse2ExecutionSupport()
  {
    int probeResult = 1;
    __try {
#if defined(_M_IX86)
      __asm
      {
        movapd xmm0, xmm1
      }
#endif
    } __except (RuntimeSseProbeExceptionFilter(GetExceptionCode())) {
      probeResult = 0;
    }
    return probeResult;
  }

  /**
   * Address: 0x00AAA865 (FUN_00AAA865, func_GetCompatMode)
   *
   * What it does:
   * Detects CPUID availability, reads leaf-1 feature bits, requires SSE2
   * capability (`EDX bit 26`), and then verifies runtime SSE2 execution support.
   */
  int RuntimeGetCompatMode()
  {
    unsigned int leaf1EdxFeatures = 0;

#if defined(_M_IX86)
    const unsigned int originalFlags = __readeflags();
    __writeeflags(originalFlags ^ 0x00200000u);
    const unsigned int modifiedFlags = __readeflags();

    if (modifiedFlags != originalFlags) {
      __writeeflags(originalFlags);

      int cpuInfo[4]{};
      __cpuid(cpuInfo, 0);
      __cpuid(cpuInfo, 1);
      leaf1EdxFeatures = static_cast<unsigned int>(cpuInfo[3]);
    }
#endif

    if ((leaf1EdxFeatures & 0x04000000u) == 0u) {
      return 0;
    }

    return RuntimeProbeSse2ExecutionSupport() != 0 ? 1 : 0;
  }

  /**
   * Address: 0x00AAA8D2 (FUN_00AAA8D2, func_ExceptionHandler)
   *
   * What it does:
   * Handles top-level C++ exception records and escalates known MSVC C++
   * runtime EH signatures to the CRT terminate lane.
   */
  LONG WINAPI RuntimeExceptionHandler(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    const EXCEPTION_RECORD* const exceptionRecord = (exceptionInfo != nullptr) ? exceptionInfo->ExceptionRecord : nullptr;
    if (exceptionRecord != nullptr && exceptionRecord->ExceptionCode == 0xE06D7363u
      && exceptionRecord->NumberParameters == 3u) {
      const ULONG_PTR signature = exceptionRecord->ExceptionInformation[0];
      if (signature == 0x19930520u || signature == 0x19930521u || signature == 0x19930522u
        || signature == 0x01994000u) {
        RuntimeTerminate();
      }
    }
    return 0;
  }

  /**
   * Address: 0x00AAA90F (FUN_00AAA90F, register_ExceptionHandler)
   *
   * What it does:
   * Registers `RuntimeExceptionHandler` as the process top-level unhandled
   * exception filter and reports success to startup caller lanes.
   */
  int register_ExceptionHandler()
  {
    (void)SetUnhandledExceptionFilter(&RuntimeExceptionHandler);
    return 0;
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
   * Address: 0x00A8826E (FUN_00A8826E, __imp_wcsstr)
   *
   * What it does:
   * Performs a naive wide-string substring scan and returns the first
   * occurrence of `needle` inside `haystack`.
   */
  wchar_t* RuntimeFindWideSubstring(wchar_t* const haystack, const wchar_t* const needle)
  {
    if (*needle == L'\0') {
      return haystack;
    }

    if (*haystack == L'\0') {
      return nullptr;
    }

    for (wchar_t* cursor = haystack; *cursor != L'\0'; ++cursor) {
      wchar_t* haystackProbe = cursor;
      const wchar_t* needleProbe = needle;
      while (*needleProbe != L'\0' && *haystackProbe == *needleProbe) {
        ++haystackProbe;
        ++needleProbe;
      }

      if (*needleProbe == L'\0') {
        return cursor;
      }
    }

    return nullptr;
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

  using RuntimeSignalHandler = void(__cdecl*)(int);
  using RuntimeFpeSignalHandler = void(__cdecl*)(int, int);

  extern "C" int _XcptActTabCount;
  extern "C" int _First_FPE_Indx;
  extern "C" int _Num_FPE;

  constexpr std::int32_t kXcptActionReturnContinueExecution = 5;
  constexpr std::int32_t kXcptActionDefault = 1;
  constexpr std::int32_t kSignalFpe = 8;

  /**
   * Address: 0x00A997EF (FUN_00A997EF, siglookup)
   *
   * What it does:
   * Scans one `_XCPT_ACTION` table for an entry matching `signalNumber` and
   * returns the matching action lane (or `nullptr` when missing).
   */
  [[nodiscard]] [[maybe_unused]] RuntimeXcptActionEntry* RuntimeLookupSignalAction(
    const int signalNumber, RuntimeXcptActionEntry* const actionTable
  ) noexcept
  {
    RuntimeXcptActionEntry* action = actionTable;
    RuntimeXcptActionEntry* const end = actionTable + _XcptActTabCount;

    while (action < end && action->mSignalNumber != signalNumber) {
      ++action;
    }

    if (action >= end || action->mSignalNumber != signalNumber) {
      return nullptr;
    }

    return action;
  }

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
   * Address: 0x00A894F5 (FUN_00A894F5, _JumpToContinuation)
   *
   * What it does:
   * Restores the SEH chain from the target registration node, rebinds `ebp`
   * and `esp` to continuation-frame lanes, and tail-jumps to the continuation
   * target.
   */
  extern "C" __declspec(naked) void __stdcall _JumpToContinuation(
    void (__stdcall* /*continuation*/)(void*, void*),
    void* /*registrationNode*/
  )
  {
    __asm
    {
      push ebp
      mov ebp, esp
      push ecx
      push ebx
      mov eax, [ebp + 0Ch]
      add eax, 0Ch
      mov [ebp - 4], eax
      mov ebx, dword ptr fs:[0]
      mov eax, [ebx]
      mov dword ptr fs:[0], eax
      mov eax, [ebp + 8]
      mov ebx, [ebp + 0Ch]
      mov ebp, [ebp - 4]
      mov esp, [ebx - 4]
      jmp eax
    }
  }

  /**
   * Address: 0x00A89525 (FUN_00A89525, _CallMemberFunction1)
   *
   * What it does:
   * Shuffles return/member-function lanes on the stack and tail-jumps into the
   * member-function pointer lane.
   */
  extern "C" __declspec(naked) void __cdecl _CallMemberFunction1(
    void* /*a1*/,
    void* /*a2*/,
    void* /*a3*/
  )
  {
    __asm
    {
      pop eax
      pop ecx
      xchg eax, [esp + 4]
      jmp eax
    }
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
   * Address: 0x00AA116F (FUN_00AA116F, __EH_prolog3_catch)
   *
   * What it does:
   * Installs EH3 catch-frame registration lanes (`fs:[0]`, cookie, and
   * scope-state init) using the classic VC8 helper prolog shape.
   */
  extern "C" __declspec(naked) void* __cdecl __EH_prolog3_catch()
  {
    __asm
    {
      push eax
      push dword ptr fs:[0]
      lea eax, [esp + 0Ch]
      sub esp, [esp + 0Ch]
      push ebx
      push esi
      push edi
      mov [eax], ebp
      mov ebp, eax
      mov eax, __security_cookie
      xor eax, ebp
      push eax
      mov [ebp - 10h], esp
      push dword ptr [ebp - 4]
      mov dword ptr [ebp - 4], 0FFFFFFFFh
      lea eax, [ebp - 0Ch]
      mov dword ptr fs:[0], eax
      ret
    }
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
   * Address: 0x00A82F32 (FUN_00A82F32, sprintf_s)
   *
   * What it does:
   * Variadic `sprintf_s` wrapper forwarding the vararg pack to the UCRT
   * `_vsprintf_s_l` lane with a null locale.
   */
  int RuntimeSprintfS(char* const buffer, const std::size_t bufferSize, const char* const format, ...)
  {
    va_list argList;
    va_start(argList, format);
    const int result = ::_vsprintf_s_l(buffer, bufferSize, format, nullptr, argList);
    va_end(argList);
    return result;
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
   * Address: 0x00A8220F (FUN_00A8220F, func_ExceptionCtr)
   *
   * What it does:
   * Initializes one `std::exception` payload from an indirection lane and
   * leaves message-ownership disabled.
   */
  std::exception* RuntimeConstructStdExceptionFromMessageRef(
    std::exception* const destination,
    const char* const* const messageRef,
    int /*unusedOwnershipFlag*/
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    new (destination) std::exception();
    auto* const destinationView = reinterpret_cast<RuntimeStdExceptionLayout*>(destination);
    destinationView->what = messageRef != nullptr ? *messageRef : nullptr;
    destinationView->doFree = 0;
    return destination;
  }

  /**
   * Address: 0x00A82334 (FUN_00A82334, func_BadTypeidExc)
   *
   * What it does:
   * Constructs one `std::bad_typeid` object and patches its message lane to
   * the incoming text pointer without taking ownership.
   */
  void* RuntimeConstructBadTypeidException(void* const storage, const char* const message)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    new (storage) std::bad_typeid();
    auto* const view = reinterpret_cast<RuntimeStdExceptionLayout*>(storage);
    view->what = message != nullptr ? message : "bad typeid";
    view->doFree = 0;
    return storage;
  }

  /**
   * Address: 0x00A825A0 (FUN_00A825A0, std::bad_alloc::bad_alloc)
   *
   * What it does:
   * Constructs one `std::bad_alloc` object at caller-provided storage and
   * returns the original storage pointer.
   */
  void* RuntimeConstructBadAllocException(void* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    static const char* kBadAllocMessage = "bad allocation";
    (void)RuntimeConstructStdExceptionFromMessageRef(
      static_cast<std::exception*>(storage),
      &kBadAllocMessage,
      1
    );

    const std::bad_alloc badAllocPrototype{};
    auto* const destinationView = reinterpret_cast<RuntimeStdExceptionLayout*>(storage);
    const auto* const prototypeView = reinterpret_cast<const RuntimeStdExceptionLayout*>(&badAllocPrototype);
    destinationView->vtable = prototypeView->vtable;
    return storage;
  }

  /**
   * Address: 0x00A82370 (FUN_00A82370, func_NonRttiObjectExc)
   *
   * What it does:
   * Constructs one non-RTTI-object exception by first initializing
   * `std::bad_typeid` state, then switching to the `std::__non_rtti_object`
   * vtable lane.
   */
  void* RuntimeConstructNonRttiObjectException(void* const storage, const char* const message)
  {
    auto* const destinationView = reinterpret_cast<RuntimeStdExceptionLayout*>(
      RuntimeConstructBadTypeidException(storage, message)
    );
    if (destinationView == nullptr) {
      return nullptr;
    }

    const auto nonRttiObject =
      std::__non_rtti_object::__construct_from_string_literal("bad typeid");
    const auto* const sourceView = reinterpret_cast<const RuntimeStdExceptionLayout*>(&nonRttiObject);
    destinationView->vtable = sourceView->vtable;
    return storage;
  }

  /**
   * Address: 0x00A826AC (FUN_00A826AC, func_GetMostDerivedObj)
   *
   * What it does:
   * Uses one subobject's vtable COL lane to recover the complete-object base
   * address for RTTI dynamic-cast resolution.
   */
  int RuntimeGetMostDerivedObjectAddress(const int objectAddress)
  {
    const auto objectPointer = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectAddress));
    const auto vtableAddress = static_cast<std::uintptr_t>(*reinterpret_cast<const std::uint32_t*>(objectPointer));
    const auto* const completeObjectLocator = *reinterpret_cast<const RuntimeRttiCompleteObjectLocator* const*>(
      vtableAddress - sizeof(std::uint32_t)
    );

    int mostDerivedObject = objectAddress - static_cast<int>(completeObjectLocator->offset);
    const int constructorDisplacementOffset = static_cast<int>(completeObjectLocator->cdOffset);
    if (constructorDisplacementOffset != 0) {
      const auto vbptrBaseAddress = static_cast<std::uintptr_t>(
        static_cast<std::uint32_t>(objectAddress - constructorDisplacementOffset)
      );
      mostDerivedObject -= *reinterpret_cast<const int*>(vbptrBaseAddress);
    }

    return mostDerivedObject;
  }

  /**
   * Address: 0x00A826C2 (FUN_00A826C2, dynamic_cast_0)
   *
   * What it does:
   * Finds one target base descriptor and returns it only when a following base
   * lane matches the source type before a non-public (`0x04`) boundary.
   */
  const RuntimeRttiBaseClassDescriptor* RuntimeResolveDynamicCastBasePrefix(
    const RuntimeRttiCompleteObjectLocator* const completeObjectLocator,
    const std::type_info* const sourceType,
    const std::type_info* const targetType
  )
  {
    const RuntimeRttiClassHierarchyDescriptor* const classDescriptor = completeObjectLocator->classDescriptor;
    const unsigned int numBaseClasses = classDescriptor->numBaseClasses;
    RuntimeRttiBaseClassDescriptor** const baseClassArray = classDescriptor->baseClassArray;

    unsigned int index = 0;
    const RuntimeRttiBaseClassDescriptor* targetDescriptor = nullptr;
    while (index < numBaseClasses) {
      RuntimeRttiBaseClassDescriptor* const candidate = baseClassArray[index];
      if (RuntimeTypeInfoMatches(candidate->typeDescriptor, targetType)) {
        targetDescriptor = candidate;
        break;
      }
      ++index;
    }

    if (targetDescriptor == nullptr) {
      return nullptr;
    }

    ++index;
    while (index < numBaseClasses) {
      RuntimeRttiBaseClassDescriptor* const candidate = baseClassArray[index];
      if ((candidate->attributes & 0x4u) != 0u) {
        break;
      }

      if (RuntimeTypeInfoMatches(candidate->typeDescriptor, sourceType)) {
        return targetDescriptor;
      }

      ++index;
    }

    return nullptr;
  }

  /**
   * Address: 0x00A82737 (FUN_00A82737, func_UsePMD)
   *
   * What it does:
   * Applies one RTTI PMD lane to an object base and returns the computed
   * subobject displacement used by CRT dynamic-cast helpers.
   */
  int RuntimeUsePmd(const RuntimePmd* const pmd, const int objectBase)
  {
    int pdispAdjustment = 0;
    const int pdisp = pmd->pdisp;
    if (pdisp >= 0) {
      const auto objectAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectBase));
      const auto vbtableAddress = static_cast<std::uintptr_t>(
        *reinterpret_cast<const std::uint32_t*>(objectAddress + static_cast<std::uintptr_t>(pdisp))
      );
      const int vdispAdjustment = static_cast<int>(
        *reinterpret_cast<const std::uint32_t*>(vbtableAddress + static_cast<std::uintptr_t>(pmd->vdisp))
      );
      pdispAdjustment = pdisp + vdispAdjustment;
    }

    return pmd->mdisp + pdispAdjustment;
  }

  /**
   * Address: 0x00A827B6 (FUN_00A827B6, dynamic_cast_1)
   *
   * What it does:
   * Resolves one single-inheritance dynamic-cast target lane by scanning RTTI
   * base descriptors and rejecting ambiguous/private conversions.
   */
  const RuntimeRttiBaseClassDescriptor* RuntimeResolveDynamicCastSingleInheritance(
    const RuntimeRttiCompleteObjectLocator* const completeObjectLocator,
    const int mostDerivedObject,
    const std::type_info* const sourceType,
    const void* const sourceSubobject,
    const std::type_info* const targetType
  )
  {
    const RuntimeRttiClassHierarchyDescriptor* const classDescriptor = completeObjectLocator->classDescriptor;
    const unsigned int numBaseClasses = classDescriptor->numBaseClasses;
    RuntimeRttiBaseClassDescriptor** const baseClassArray = classDescriptor->baseClassArray;

    const RuntimeRttiBaseClassDescriptor* targetCandidate = nullptr;
    const RuntimeRttiBaseClassDescriptor* sourceCandidateOutsideTarget = nullptr;
    unsigned int targetContainedBaseCount = 0u;
    int targetIndex = -1;

    for (unsigned int index = 0; index < numBaseClasses; ++index) {
      RuntimeRttiBaseClassDescriptor* const base = baseClassArray[index];

      const unsigned int relativeIndex = static_cast<unsigned int>(static_cast<int>(index) - targetIndex);
      if (relativeIndex > targetContainedBaseCount && RuntimeTypeInfoMatches(base->typeDescriptor, targetType)) {
        if (sourceCandidateOutsideTarget != nullptr) {
          if ((base->attributes & 0x3u) == 0u && (sourceCandidateOutsideTarget->attributes & 0x1u) == 0u) {
            return base;
          }
          return nullptr;
        }

        targetIndex = static_cast<int>(index);
        targetCandidate = base;
        targetContainedBaseCount = base->numContainedBases;
      }

      if (!RuntimeTypeInfoMatches(base->typeDescriptor, sourceType)) {
        continue;
      }
      if (reinterpret_cast<const void*>(
            static_cast<std::uintptr_t>(RuntimeUsePmd(&base->pmd, mostDerivedObject))
          ) != sourceSubobject) {
        continue;
      }

      if (targetCandidate == nullptr) {
        sourceCandidateOutsideTarget = base;
        continue;
      }

      const unsigned int sourceRelativeIndex = static_cast<unsigned int>(static_cast<int>(index) - targetIndex);
      if (sourceRelativeIndex > targetContainedBaseCount) {
        if ((targetCandidate->attributes & 0x3u) != 0u) {
          return nullptr;
        }
      } else {
        if ((targetCandidate->attributes & 0x40u) != 0u) {
          const RuntimeRttiBaseClassDescriptor* const contained =
            RuntimeGetContainedBaseDescriptor(targetCandidate, sourceRelativeIndex);
          return (contained != nullptr && (contained->attributes & 0x1u) == 0u) ? targetCandidate : nullptr;
        }
        if (targetIndex != 0) {
          return targetCandidate;
        }
      }

      return (base->attributes & 0x1u) == 0u ? targetCandidate : nullptr;
    }

    return nullptr;
  }

  /**
   * Address: 0x00A828B8 (FUN_00A828B8, dynamic_cast_3)
   *
   * What it does:
   * Resolves one multiple-inheritance dynamic-cast target lane by validating
   * public-path accessibility and collapsing ambiguous PMD outcomes.
   */
  const RuntimeRttiBaseClassDescriptor* RuntimeResolveDynamicCastMultipleInheritance(
    const RuntimeRttiCompleteObjectLocator* const completeObjectLocator,
    const int mostDerivedObject,
    const std::type_info* const sourceType,
    const void* const sourceSubobject,
    const std::type_info* const targetType
  )
  {
    const RuntimeRttiClassHierarchyDescriptor* const classDescriptor = completeObjectLocator->classDescriptor;
    const unsigned int numBaseClasses = classDescriptor->numBaseClasses;
    RuntimeRttiBaseClassDescriptor** const baseClassArray = classDescriptor->baseClassArray;

    int targetIndex = -1;
    int resolvedTargetAddress = -1;
    const RuntimeRttiBaseClassDescriptor* activeTargetRoot = nullptr;
    const RuntimeRttiBaseClassDescriptor* uniqueResolvedTarget = nullptr;
    const RuntimeRttiBaseClassDescriptor* sourceOutsideTarget = nullptr;
    const RuntimeRttiBaseClassDescriptor* strictTargetCandidate = nullptr;
    unsigned int targetContainedBaseCount = 0u;
    bool hasPublicPath = true;

    for (unsigned int index = 0; index < numBaseClasses; ++index) {
      RuntimeRttiBaseClassDescriptor* const base = baseClassArray[index];

      const unsigned int relativeIndex = static_cast<unsigned int>(static_cast<int>(index) - targetIndex);
      if (relativeIndex > targetContainedBaseCount && RuntimeTypeInfoMatches(base->typeDescriptor, targetType)) {
        if ((base->attributes & 0x3u) == 0u) {
          strictTargetCandidate = base;
        }
        targetIndex = static_cast<int>(index);
        activeTargetRoot = base;
        targetContainedBaseCount = base->numContainedBases;
      }

      if (!RuntimeTypeInfoMatches(base->typeDescriptor, sourceType)) {
        continue;
      }
      if (reinterpret_cast<const void*>(
            static_cast<std::uintptr_t>(RuntimeUsePmd(&base->pmd, mostDerivedObject))
          ) != sourceSubobject) {
        continue;
      }

      const unsigned int sourceRelativeIndex = static_cast<unsigned int>(static_cast<int>(index) - targetIndex);
      if (sourceRelativeIndex > targetContainedBaseCount) {
        if ((base->attributes & 0x5u) == 0u) {
          sourceOutsideTarget = base;
        }
        continue;
      }

      if (!hasPublicPath || activeTargetRoot == nullptr) {
        continue;
      }

      bool pathAccepted = true;
      if ((activeTargetRoot->attributes & 0x40u) != 0u) {
        const RuntimeRttiBaseClassDescriptor* const contained =
          RuntimeGetContainedBaseDescriptor(activeTargetRoot, sourceRelativeIndex);
        if (contained == nullptr) {
          hasPublicPath = false;
          continue;
        }
        if ((contained->attributes & 0x1u) != 0u) {
          hasPublicPath = false;
        }
        pathAccepted = (contained->attributes & 0x4u) == 0u;
      } else {
        if (targetIndex == 0 && (base->attributes & 0x1u) != 0u) {
          hasPublicPath = false;
        }
      }

      if (!hasPublicPath || !pathAccepted) {
        continue;
      }

      const int targetAddress = RuntimeUsePmd(&activeTargetRoot->pmd, mostDerivedObject);
      if (uniqueResolvedTarget != nullptr && resolvedTargetAddress != targetAddress) {
        return nullptr;
      }

      uniqueResolvedTarget = activeTargetRoot;
      resolvedTargetAddress = targetAddress;
    }

    if (hasPublicPath && uniqueResolvedTarget != nullptr) {
      return uniqueResolvedTarget;
    }
    if (sourceOutsideTarget == nullptr) {
      return nullptr;
    }
    return strictTargetCandidate;
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
  struct RuntimeUndecoratorHeapFrameNode
  {
    RuntimeUndecoratorHeapFrameNode* next = nullptr; // +0x00
  };
  static_assert(sizeof(RuntimeUndecoratorHeapFrameNode) == 0x04, "RuntimeUndecoratorHeapFrameNode size must be 0x04");

  using RuntimeUndecoratorFrameFreeFn = void(__cdecl*)(RuntimeUndecoratorHeapFrameNode* frame);

  struct RuntimeUndecoratorHeapManagerState
  {
    void* reserved00 = nullptr;                            // +0x00
    RuntimeUndecoratorFrameFreeFn deallocator = nullptr;  // +0x04
    RuntimeUndecoratorHeapFrameNode* firstFrame = nullptr; // +0x08
    RuntimeUndecoratorHeapFrameNode* frame = nullptr;     // +0x0C
  };
  static_assert(
    offsetof(RuntimeUndecoratorHeapManagerState, deallocator) == 0x04,
    "RuntimeUndecoratorHeapManagerState::deallocator offset must be 0x04"
  );
  static_assert(
    offsetof(RuntimeUndecoratorHeapManagerState, firstFrame) == 0x08,
    "RuntimeUndecoratorHeapManagerState::firstFrame offset must be 0x08"
  );
  static_assert(
    offsetof(RuntimeUndecoratorHeapManagerState, frame) == 0x0C,
    "RuntimeUndecoratorHeapManagerState::frame offset must be 0x0C"
  );
  static_assert(sizeof(RuntimeUndecoratorHeapManagerState) == 0x10, "RuntimeUndecoratorHeapManagerState size must be 0x10");

  /**
   * Address: 0x00AB0A14 (FUN_00AB0A14, HeapManager::Destructor)
   *
   * What it does:
   * Drains one undecorator heap-manager frame chain and releases each frame
   * through the manager's deallocator callback lane.
   */
  void RuntimeUndecoratorHeapManagerDrain(RuntimeUndecoratorHeapManagerState* const manager)
  {
    if (manager == nullptr || manager->deallocator == nullptr) {
      return;
    }

    while (true) {
      RuntimeUndecoratorHeapFrameNode* const current = manager->firstFrame;
      manager->frame = current;
      if (current == nullptr) {
        break;
      }

      manager->firstFrame = current->next;
      manager->deallocator(current);
    }
  }
  struct RuntimeUndecoratorDNameLane
  {
    std::uint8_t storage[0x8]{};
  };
  static_assert(sizeof(RuntimeUndecoratorDNameLane) == 0x8, "RuntimeUndecoratorDNameLane size must be 0x8");

  struct RuntimeUndecoratorReplicatorView
  {
    std::int32_t highestStoredArgument = -1;                   // +0x00
    RuntimeUndecoratorDNameLane* argumentNames[10]{};          // +0x04
    RuntimeUndecoratorDNameLane overflowArgumentName{};        // +0x2C
    RuntimeUndecoratorDNameLane missingArgumentNameSentinel{}; // +0x34
  };
  static_assert(
    offsetof(RuntimeUndecoratorReplicatorView, highestStoredArgument) == 0x00,
    "RuntimeUndecoratorReplicatorView::highestStoredArgument offset must be 0x00"
  );
  static_assert(
    offsetof(RuntimeUndecoratorReplicatorView, argumentNames) == 0x04,
    "RuntimeUndecoratorReplicatorView::argumentNames offset must be 0x04"
  );
  static_assert(
    offsetof(RuntimeUndecoratorReplicatorView, overflowArgumentName) == 0x2C,
    "RuntimeUndecoratorReplicatorView::overflowArgumentName offset must be 0x2C"
  );
  static_assert(
    offsetof(RuntimeUndecoratorReplicatorView, missingArgumentNameSentinel) == 0x34,
    "RuntimeUndecoratorReplicatorView::missingArgumentNameSentinel offset must be 0x34"
  );
  static_assert(sizeof(RuntimeUndecoratorReplicatorView) == 0x3C, "RuntimeUndecoratorReplicatorView size must be 0x3C");

  /**
   * Address: 0x00AB123B (FUN_00AB123B, Replicator::operator[])
   *
   * What it does:
   * Resolves one undecorator argument-name lane by index, returning overflow
   * and missing-value sentinels for out-of-range requests.
   */
  RuntimeUndecoratorDNameLane* RuntimeReplicatorSelectArgumentName(
    RuntimeUndecoratorReplicatorView* const replicator,
    const unsigned int argumentIndex
  )
  {
    if (argumentIndex > 9u) {
      return &replicator->overflowArgumentName;
    }

    if (replicator->highestStoredArgument == -1 || static_cast<int>(argumentIndex) > replicator->highestStoredArgument) {
      return &replicator->missingArgumentNameSentinel;
    }

    return replicator->argumentNames[argumentIndex];
  }

  /**
   * Address: 0x00AB134A (FUN_00AB134A, und_strncpy)
   *
   * What it does:
   * Copies at most `count` bytes from source to destination, stopping after
   * writing the first null terminator and returning the destination pointer.
   */
  char* RuntimeUndecoratorStrncpy(
    const char* source,
    char* const destination,
    unsigned int count
  )
  {
    char* writeCursor = destination;
    while (count != 0u) {
      const char character = *source;
      *writeCursor = character;
      if (character == '\0') {
        break;
      }

      ++writeCursor;
      ++source;
      --count;
    }
    return destination;
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
   * Address: 0x00AA679B (FUN_00AA679B, LangCountryEnumProc)
   *
   * What it does:
   * Enumerates locale IDs while matching both language and country lanes, and
   * updates `setlocData` state bits/LCIDs for exact, primary-prefix, and
   * default-country/default-language fallback cases.
   */
  BOOL __stdcall RuntimeLangCountryEnumProc(LPSTR localeText)
  {
    auto* const setlocData = &__getptd()->setlocData;
    const LCID localeId = static_cast<LCID>(RuntimeLcidFromHexString(localeText));
    char localeName[120]{};

    const LCTYPE countryField =
      (setlocData->bAbbrevCountry != 0) ? LOCALE_SABBREVCTRYNAME : LOCALE_SENGCOUNTRY;
    if (!::GetLocaleInfoA(localeId, countryField, localeName, 120)) {
      setlocData->iLcidState = 0;
      return TRUE;
    }

    if (_stricmp(setlocData->pchCountry, localeName) == 0) {
      const LCTYPE languageField =
        (setlocData->bAbbrevLanguage != 0) ? LOCALE_SABBREVLANGNAME : LOCALE_SENGLANGUAGE;
      if (!::GetLocaleInfoA(localeId, languageField, localeName, 120)) {
        setlocData->iLcidState = 0;
        return TRUE;
      }

      if (_stricmp(setlocData->pchLanguage, localeName) == 0) {
        setlocData->iLcidState |= 0x304;
        setlocData->lcidLanguage = localeId;
        setlocData->lcidCountry = localeId;
      } else if ((setlocData->iLcidState & 2) == 0) {
        const int primaryLength = setlocData->iPrimaryLen;
        if (primaryLength != 0 && RuntimeMemicmp(setlocData->pchLanguage, localeName, primaryLength) == 0) {
          setlocData->iLcidState |= 2;
          setlocData->lcidCountry = localeId;
          if (std::strlen(setlocData->pchLanguage) == static_cast<std::size_t>(primaryLength)) {
            setlocData->lcidLanguage = localeId;
          }
        } else if ((setlocData->iLcidState & 1) == 0
                   && RuntimeTestDefaultCountry(static_cast<std::uint16_t>(localeId)) != 0) {
          setlocData->iLcidState |= 1;
          setlocData->lcidCountry = localeId;
        }
      }
    }

    if ((setlocData->iLcidState & 0x300) != 0x300) {
      const LCTYPE languageField =
        (setlocData->bAbbrevLanguage != 0) ? LOCALE_SABBREVLANGNAME : LOCALE_SENGLANGUAGE;
      if (!::GetLocaleInfoA(localeId, languageField, localeName, 120)) {
        setlocData->iLcidState = 0;
        return TRUE;
      }

      if (_stricmp(setlocData->pchLanguage, localeName) == 0) {
        setlocData->iLcidState |= 0x200;

        bool acceptLanguageLcid = false;
        if (setlocData->bAbbrevLanguage != 0) {
          acceptLanguageLcid = true;
        } else if (setlocData->iPrimaryLen == 0
                   || std::strlen(setlocData->pchLanguage) != static_cast<std::size_t>(setlocData->iPrimaryLen)) {
          acceptLanguageLcid = true;
        } else {
          acceptLanguageLcid = RuntimeTestDefaultLanguage(setlocData, localeId, 1) != FALSE;
        }

        if (acceptLanguageLcid) {
          setlocData->iLcidState |= 0x100;
          if (setlocData->lcidLanguage == 0) {
            setlocData->lcidLanguage = localeId;
          }
        }
      } else if (setlocData->bAbbrevLanguage == 0
                 && setlocData->iPrimaryLen != 0
                 && _stricmp(setlocData->pchLanguage, localeName) == 0
                 && RuntimeTestDefaultLanguage(setlocData, localeId, 0) != FALSE) {
        setlocData->iLcidState |= 0x100;
        if (setlocData->lcidLanguage == 0) {
          setlocData->lcidLanguage = localeId;
        }
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

  /**
   * Address: 0x00AA6A56 (FUN_00AA6A56, GetLcidFromLangCountry)
   *
   * What it does:
   * Prepares setlocale language/country matching flags, runs the combined
   * language+country locale enumeration callback, and normalizes state bits.
   */
  int RuntimeGetLcidFromLangCountry(RuntimeSetLocLocaleView* const setlocData)
  {
    setlocData->bAbbrevLanguage = (std::strlen(setlocData->pchLanguage) == 3u) ? 1 : 0;
    setlocData->bAbbrevCountry = (std::strlen(setlocData->pchCountry) == 3u) ? 1 : 0;
    setlocData->lcidLanguage = 0;
    setlocData->iPrimaryLen = (setlocData->bAbbrevLanguage != 0) ? 2 : RuntimeGetPrimaryLen(setlocData->pchLanguage);

    (void)::EnumSystemLocalesA(RuntimeLangCountryEnumProc, 1u);

    const int previousState = setlocData->iLcidState;
    if ((previousState & 0x100) == 0 || (previousState & 0x200) == 0 || (previousState & 7) == 0) {
      setlocData->iLcidState = 0;
    }
    return previousState;
  }

  /**
   * Address: 0x00AA6ABB (FUN_00AA6ABB, GetLcidFromLanguage)
   *
   * What it does:
   * Prepares language matching state, runs language-only locale enumeration,
   * and clears state when no primary language match bit was latched.
   */
  BOOL RuntimeGetLcidFromLanguage(RuntimeSetLocLocaleView* const setlocData)
  {
    setlocData->bAbbrevLanguage = (std::strlen(setlocData->pchLanguage) == 3u) ? 1 : 0;
    setlocData->iPrimaryLen = (setlocData->bAbbrevLanguage != 0) ? 2 : RuntimeGetPrimaryLen(setlocData->pchLanguage);

    const BOOL enumResult = ::EnumSystemLocalesA(RuntimeLanguageEnumProc, 1u);
    if ((setlocData->iLcidState & 4) == 0) {
      setlocData->iLcidState = 0;
    }
    return enumResult;
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
    if ((legacy_file(stream)._flag & 0x10C) != 0) {
      return 0;
    }

    char*& bufferSlot = gRuntimeStdTerminalBuffers[stdbufSlot];
    if (bufferSlot == nullptr) {
      bufferSlot = static_cast<char*>(std::malloc(4096u));
    }

    // Modern MSVC <_iobuf> hides legacy fields (_cnt/_flag/_base/_ptr/
    // _bufsiz/_charbuf/_tmpfname) behind opaque storage. Reach the same
    // legacy slots through a struct view that mirrors the legacy 32-byte
    // FILE layout (matches the binary's assumption that std::FILE is the
    // legacy `_iobuf`).
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
    auto* const legacyView = reinterpret_cast<LegacyFileView*>(stream);
    if (bufferSlot != nullptr) {
      legacyView->_base = bufferSlot;
      legacyView->_ptr = bufferSlot;
      legacyView->_bufsiz = 4096;
      legacyView->_cnt = 4096;
    } else {
      legacyView->_base = reinterpret_cast<char*>(&legacyView->_charbuf);
      legacyView->_ptr = reinterpret_cast<char*>(&legacyView->_charbuf);
      legacyView->_bufsiz = 2;
      legacyView->_cnt = 2;
    }

    legacyView->_flag |= 0x1102;
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
   * Address: 0x00A86A7F (FUN_00A86A7F, _ftime64)
   *
   * What it does:
   * Thunks `_ftime64` into the secure `_ftime64_s` lane; the stub's error
   * return is ignored by the CRT contract.
   */
  void RuntimeFtime64(__timeb64* const outTime)
  {
    (void)RuntimeFtime64S(outTime);
  }

  /**
   * Address: 0x00A835A8 (FUN_00A835A8, atol)
   *
   * What it does:
   * Parses one decimal signed-long integer using the CRT `strtol` lane with a
   * fixed base of ten.
   */
  long RuntimeAtol(const char* const text)
  {
    return std::strtol(text, nullptr, 10);
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
   * Address: 0x00AB6747 (FUN_00AB6747, wctomb_s)
   *
   * What it does:
   * Forwards to the UCRT `_wctomb_s_l` lane with a null locale so the active
   * thread locale is used.
   */
  int RuntimeWctombS(int* const outBytesWritten, char* const destination, const std::size_t sizeInBytes, const wchar_t wideChar)
  {
    return ::_wctomb_s_l(outBytesWritten, destination, sizeInBytes, wideChar, nullptr);
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

