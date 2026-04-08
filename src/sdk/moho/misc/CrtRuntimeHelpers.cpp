#include <Windows.h>

#include <cerrno>
#include <clocale>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <exception>
#include <io.h>
#include <new>
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
extern "C" int _nhandle;
extern "C" int _commode;
extern "C" int _cflush;
extern "C" unsigned int _nstream;
extern "C" std::FILE** __piob;
extern "C" std::FILE* __cdecl _getstream();
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
  std::uint8_t reserved00[0x24];
  std::int8_t textmodeUnicode;
  std::uint8_t reserved25[0x13];
};
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
extern "C" void __cdecl __free_lc_time(void* lcTimeData);
extern "C" void __cdecl __free_lconv_num(lconv* localeConv);
extern "C" void __cdecl __free_lconv_mon(lconv* localeConv);
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

namespace
{
  constexpr int kRuntimeEnvironmentLock = 7;
  constexpr int kRuntimeSetLocaleLock = 12;
  constexpr int kRuntimeIobScanLock = 1;
  constexpr int kRuntimeTimeLock = 6;
  constexpr int kRuntimeFileFlagFlushMask = 0x83;
  constexpr int kRuntimeFileFlagWritable = 0x02;
  constexpr std::uint64_t kFiletimeHundredNsPerMillisecond = 10000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerSecond = 10000000ull;
  constexpr std::uint64_t kFiletimeHundredNsPerMinute = 600000000ull;
  constexpr std::uint64_t kFiletimeToUnixEpochOffset = 116444736000000000ull;

  std::int64_t gRuntimeElapsedMinutesCache = 0;
  std::int32_t gRuntimeDstFlagCache = 0;
  std::int32_t gRuntimeTzsetFirstTime = 0;
  std::int32_t gRuntimeGetEnvironmentStringsEncodingMode = 0;

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

  struct RuntimeSetLocLocaleView
  {
    std::uint8_t reserved00[0x1C];
    LCID lcidCountry;
  };
  static_assert(
    offsetof(RuntimeSetLocLocaleView, lcidCountry) == 0x1C,
    "RuntimeSetLocLocaleView::lcidCountry offset must be 0x1C"
  );
  static_assert(sizeof(RuntimeSetLocLocaleView) == 0x20, "RuntimeSetLocLocaleView size must be 0x20");

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

  struct RuntimeThreadLocInfoView
  {
    volatile long refcount = 0;                          // +0x00
    std::uint8_t reserved04[0x4C]{};                     // +0x04
    RuntimeLocaleCategoryView categories[6];             // +0x50
    int* lconvIntlRefcount = nullptr;                    // +0xB0
    int* lconvNumRefcount = nullptr;                     // +0xB4
    int* lconvMonRefcount = nullptr;                     // +0xB8
    lconv* localeConv = nullptr;                         // +0xBC
    int* ctype1Refcount = nullptr;                       // +0xC0
    std::uint16_t* ctype1 = nullptr;                     // +0xC4
    std::uint8_t reservedC8[0x04]{};                     // +0xC8
    unsigned char* pclmap = nullptr;                     // +0xCC
    unsigned char* pcumap = nullptr;                     // +0xD0
    RuntimeLcTimeData* lcTimeCurrent = nullptr;          // +0xD4
  };
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
} // namespace moho::runtime
