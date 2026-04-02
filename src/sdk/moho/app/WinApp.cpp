#include "WinApp.h"

#include "platform/Platform.h"

#include <DbgHelp.h>

#include <algorithm>
#include <cstdio>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <intrin.h>
#include <limits>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include <float.h>
#include <commctrl.h>
#include <objbase.h>
#include <TlHelp32.h>

#include "boost/mutex.h"
#include "CWaitHandleSet.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/time/Timer.h"
#include "IWinApp.h"
#include "WxAppRuntime.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/ResourceManager.h"
#include "moho/core/Thread.h"

#pragma warning(push)
#pragma warning(disable : 4996)

int wxEntry(HINSTANCE hInstance, HINSTANCE hPrevInstance, char* pCmdLine, int nCmdShow, bool shouldInit);

namespace
{
  constexpr float kMaxFiniteTimeoutMs = 4294967300.0f;
  constexpr float kInfiniteWakeupMs = std::numeric_limits<float>::infinity();

  moho::IWinApp* sSupComApp = nullptr;
  HHOOK sWindowHook = nullptr;
  gpg::time::Timer wakeupTimer;
  float wakeupTimerDur = kInfiniteWakeupMs;
  std::once_flag sSymHandlerMutexInitOnce;
  boost::mutex* sMutexSymHandler = nullptr;
  bool sSymHandlerMutexConstructed = false;
  std::aligned_storage_t<sizeof(boost::mutex), alignof(boost::mutex)> sSymHandlerMutexStorage{};
  bool sMohoEngineMuexInitialized = false;
  bool sSymbolHandlerInitialized = false;
  constexpr DWORD kPlatformSymbolHandlerOptions =
    SYMOPT_FAIL_CRITICAL_ERRORS | // suppress critical-error UI while probing symbols.
    SYMOPT_LOAD_LINES | // include source line records for resolved addresses.
    SYMOPT_DEFERRED_LOADS | // lazily load module symbols as needed.
    SYMOPT_UNDNAME; // undecorate C++ names in symbol output.
  static_assert(
    kPlatformSymbolHandlerOptions == 0x216u,
    "PLAT_Init symbol options must match recovered SymSetOptions(0x216)"
  );

  moho::CWinLogTarget sLogWindowTarget{};
  moho::SplashScreenRuntime* sSplashScreenPtr = nullptr;

  void DestroyActiveSplashScreen() noexcept
  {
    if (sSplashScreenPtr != nullptr) {
      sSplashScreenPtr->DeleteObject(1);
      sSplashScreenPtr = nullptr;
    }
  }

  constexpr wchar_t kPathSeparator = L'\\';
  constexpr wchar_t kDxdiagOutputFileName[] = L"dxdiag.txt";
  constexpr wchar_t kDxdiagCommandPrefix[] = L"dxdiag.exe ";
  constexpr std::uint32_t kBugSplatPrepareAttachmentsEvent = 0x100;
  constexpr std::uint32_t kBugSplatQueryAttachmentPathEvent = 0x1101;
  constexpr char kBugSplatModuleName[] = "BugSplat.dll";
  constexpr char kMiniDmpSenderCtorExport[] = "??0MiniDmpSender@@QAE@PBD000K@Z";
  constexpr char kMiniDmpSenderDtorExport[] = "??1MiniDmpSender@@UAE@XZ";
  constexpr char kMiniDmpSenderSetCallbackExport[] = "?setCallback@MiniDmpSender@@QAEXP6A_NIPAX0@Z@Z";
  constexpr char kMiniDmpSenderCreateReportExport[] = "?createReport@MiniDmpSender@@QAEXPAU_EXCEPTION_POINTERS@@@Z";
  std::wstring sLegacyErrorReportOutputDir{};

  /**
   * Address: 0x004A0EC0 (FUN_004A0EC0, sub_4A0EC0)
   *
   * What it does:
   * Returns the inline-buffer subobject pointer (`this + 4`) for one recovered
   * legacy wide-string layout view.
   */
  struct LegacyWideStringObjectView
  {
    std::uint32_t allocatorState = 0;
    union
    {
      wchar_t* heap = nullptr;
      wchar_t inlineBuffer[8];
    } storage;
    std::uint32_t length = 0;
    std::uint32_t capacity = 7;
  };

#if defined(_M_IX86)
  static_assert(sizeof(LegacyWideStringObjectView) == 0x1C, "LegacyWideStringObjectView size must be 0x1C");
#endif

  [[maybe_unused]] wchar_t* GetLegacyWideStringInlineBufferSubobject(LegacyWideStringObjectView* const value) noexcept
  {
    return reinterpret_cast<wchar_t*>(&(value->storage));
  }

  /**
   * Address: 0x004A1020 (FUN_004A1020, sub_4A1020)
   *
   * What it does:
   * Returns the process-global error-report output directory wide string.
   */
  [[maybe_unused]] std::wstring* GetLegacyErrorReportOutputDirStorage() noexcept
  {
    return &sLegacyErrorReportOutputDir;
  }

  /**
   * Address: 0x004A1920 (FUN_004A1920, sub_4A1920)
   *
   * What it does:
   * Assigns one zero-terminated wide string into the destination string.
   */
  [[maybe_unused]] std::wstring* AssignWideStringFromNullTerminatedInput(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    const wchar_t* const safeSource = (source != nullptr) ? source : L"";
    destination->assign(safeSource, std::wcslen(safeSource));
    return destination;
  }

  /**
   * Address: 0x004A17B0 (FUN_004A17B0, sub_4A17B0)
   *
   * What it does:
   * Initializes one local wide string into empty SSO state, then assigns from
   * one zero-terminated wide source.
   */
  [[maybe_unused]] std::wstring* InitializeAndAssignWideStringFromNullTerminatedInput(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    destination->clear();
    return AssignWideStringFromNullTerminatedInput(destination, source);
  }

  /**
   * Address: 0x004A17F0 (FUN_004A17F0, sub_4A17F0)
   *
   * What it does:
   * Assigns the global error-report output directory from one zero-terminated
   * wide source.
   */
  [[maybe_unused]] std::wstring* AssignErrorReportOutputDirFromNullTerminatedInput(const wchar_t* const source)
  {
    return AssignWideStringFromNullTerminatedInput(GetLegacyErrorReportOutputDirStorage(), source);
  }

  /**
   * Address: 0x004A1AE0 (FUN_004A1AE0)
   * Mangled: ?append@wstring@std@@QAEAAV12@ABV12@II@Z
   *
   * What it does:
   * Appends a clamped substring range from `source` into `destination`.
   */
  [[maybe_unused]] std::wstring* AppendWideSubstringRangeClamped(
    std::wstring* const destination,
    const std::wstring& source,
    std::size_t count,
    const std::size_t sourceOffset
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    if (sourceOffset > source.size()) {
      throw std::out_of_range("wstring::append sourceOffset");
    }

    const std::size_t available = source.size() - sourceOffset;
    if (count > available) {
      count = available;
    }

    destination->append(source, sourceOffset, count);
    return destination;
  }

  /**
   * Address: 0x004A19E0 (FUN_004A19E0)
   * Mangled: ??Ywstring@std@@VQAEAAV01@PB_W@Z
   *
   * What it does:
   * Appends one wide source range into destination while preserving overlapping
   * source semantics.
   */
  [[maybe_unused]] std::wstring* AppendWideRangePreservingOverlap(
    std::wstring* const destination,
    const wchar_t* const source,
    const std::size_t sourceLength
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    const wchar_t* const destinationData = destination->data();
    const wchar_t* const destinationEnd = destinationData + destination->size();
    if (source >= destinationData && source < destinationEnd) {
      const std::size_t sourceOffset = static_cast<std::size_t>(source - destinationData);
      return AppendWideSubstringRangeClamped(destination, *destination, sourceLength, sourceOffset);
    }

    destination->append(source, sourceLength);
    return destination;
  }

  /**
   * Address: 0x004A1820 (FUN_004A1820, sub_4A1820)
   *
   * What it does:
   * Appends one zero-terminated wide source to the destination string.
   */
  [[maybe_unused]] std::wstring* AppendWideStringFromNullTerminatedInputA(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    const wchar_t* const safeSource = (source != nullptr) ? source : L"";
    return AppendWideRangePreservingOverlap(destination, safeSource, std::wcslen(safeSource));
  }

  /**
   * Address: 0x004A18F0 (FUN_004A18F0, sub_4A18F0)
   *
   * What it does:
   * Duplicate zero-terminated wide append helper.
   */
  [[maybe_unused]] std::wstring* AppendWideStringFromNullTerminatedInputB(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    return AppendWideStringFromNullTerminatedInputA(destination, source);
  }

  /**
   * Address: 0x004A1870 (FUN_004A1870, sub_4A1870)
   *
   * What it does:
   * Returns whether the global error-report output directory is empty.
   */
  [[maybe_unused]] bool IsLegacyErrorReportOutputDirEmpty() noexcept
  {
    return GetLegacyErrorReportOutputDirStorage()->empty();
  }

  /**
   * Address: 0x004A1950 (FUN_004A1950)
   * Mangled: ?compare@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QBEHPB_W@Z
   *
   * What it does:
   * Lexicographically compares up to `lhsRequestedLength` characters from one
   * wide string against one raw wide range and returns `-1/0/1`.
   */
  [[maybe_unused]] int CompareWideStringPrefixRange(
    std::size_t lhsRequestedLength,
    const std::wstring* const lhs,
    const std::size_t rhsLength,
    const wchar_t* const rhs
  ) noexcept
  {
    if (lhs == nullptr || rhs == nullptr) {
      return (lhs == nullptr) ? ((rhs == nullptr) ? 0 : -1) : 1;
    }

    std::size_t lhsLength = lhsRequestedLength;
    if (lhs->size() < lhsLength) {
      lhsLength = lhs->size();
    }

    std::size_t compareCount = lhsLength;
    if (compareCount > rhsLength) {
      compareCount = rhsLength;
    }

    for (std::size_t i = 0; i < compareCount; ++i) {
      const wchar_t left = (*lhs)[i];
      const wchar_t right = rhs[i];
      if (left != right) {
        return (left < right) ? -1 : 1;
      }
    }

    if (lhsLength >= rhsLength) {
      return (lhsLength != rhsLength) ? 1 : 0;
    }
    return -1;
  }

  /**
   * Address: 0x004A1880 (FUN_004A1880, sub_4A1880)
   *
   * What it does:
   * Compares one wide string against one zero-terminated wide source.
   */
  [[maybe_unused]] int CompareWideStringWithNullTerminatedInput(
    const std::wstring* const lhs,
    const wchar_t* const rhs
  ) noexcept
  {
    const wchar_t* const safeRhs = (rhs != nullptr) ? rhs : L"";
    return CompareWideStringPrefixRange(
      (lhs != nullptr) ? lhs->size() : 0U,
      lhs,
      std::wcslen(safeRhs),
      safeRhs
    );
  }

  /**
   * Address: 0x004A1850 (FUN_004A1850, sub_4A1850)
   *
   * What it does:
   * Returns a pointer to one character index in a recovered legacy wide-string
   * object view (SSO-aware).
   */
  [[maybe_unused]] wchar_t* GetLegacyWideStringCharacterPointer(
    LegacyWideStringObjectView* const value,
    const std::uint32_t index
  ) noexcept
  {
    if (value == nullptr) {
      return nullptr;
    }
    if (value->capacity < 8U) {
      return GetLegacyWideStringInlineBufferSubobject(value) + index;
    }
    return value->storage.heap + index;
  }

  struct LegacyWideStringVectorAccessorView
  {
    std::uint32_t reserved = 0;
    LegacyWideStringObjectView* first = nullptr;
  };

  /**
   * Address: 0x004A18B0 (FUN_004A18B0, sub_4A18B0)
   *
   * What it does:
   * Returns one legacy wide-string element pointer by index from a recovered
   * vector-storage accessor view.
   */
  [[maybe_unused]] LegacyWideStringObjectView* GetLegacyWideStringElementPointerByIndex(
    const std::uint32_t index,
    const LegacyWideStringVectorAccessorView* const accessor
  ) noexcept
  {
    if (accessor == nullptr || accessor->first == nullptr) {
      return nullptr;
    }
    return accessor->first + index;
  }

  /**
   * Address: 0x004A18C0 (FUN_004A18C0, sub_4A18C0)
   *
   * What it does:
   * Resets one legacy wide-string pointer-slot to null.
   */
  [[maybe_unused]] LegacyWideStringObjectView** ResetLegacyWideStringPointerSlotA(
    LegacyWideStringObjectView** const pointerSlot
  ) noexcept
  {
    if (pointerSlot != nullptr) {
      *pointerSlot = nullptr;
    }
    return pointerSlot;
  }

  /**
   * Address: 0x004A18D0 (FUN_004A18D0, sub_4A18D0)
   *
   * What it does:
   * Loads one legacy wide-string pointer-slot value.
   */
  [[maybe_unused]] LegacyWideStringObjectView* LoadLegacyWideStringPointerSlotA(
    LegacyWideStringObjectView* const* const pointerSlot
  ) noexcept
  {
    return (pointerSlot != nullptr) ? *pointerSlot : nullptr;
  }

  /**
   * Address: 0x004A18E0 (FUN_004A18E0, sub_4A18E0)
   *
   * What it does:
   * Advances one legacy wide-string pointer-slot by one element stride.
   */
  [[maybe_unused]] LegacyWideStringObjectView** AdvanceLegacyWideStringPointerSlotByOneElement(
    LegacyWideStringObjectView** const pointerSlot
  ) noexcept
  {
    if (pointerSlot != nullptr && *pointerSlot != nullptr) {
      *pointerSlot = reinterpret_cast<LegacyWideStringObjectView*>(
        reinterpret_cast<std::byte*>(*pointerSlot) + sizeof(LegacyWideStringObjectView)
      );
    }
    return pointerSlot;
  }

  /**
   * Address: 0x004A19C0 (FUN_004A19C0, sub_4A19C0)
   *
   * What it does:
   * Duplicate legacy wide-string pointer-slot load helper.
   */
  [[maybe_unused]] LegacyWideStringObjectView* LoadLegacyWideStringPointerSlotB(
    LegacyWideStringObjectView* const* const pointerSlot
  ) noexcept
  {
    return LoadLegacyWideStringPointerSlotA(pointerSlot);
  }

  /**
   * Address: 0x004A19D0 (FUN_004A19D0, sub_4A19D0)
   *
   * What it does:
   * Duplicate legacy wide-string pointer-slot reset helper.
   */
  [[maybe_unused]] LegacyWideStringObjectView** ResetLegacyWideStringPointerSlotB(
    LegacyWideStringObjectView** const pointerSlot
  ) noexcept
  {
    return ResetLegacyWideStringPointerSlotA(pointerSlot);
  }

  /**
   * Address: 0x004A1BF0 (FUN_004A1BF0)
   * Mangled:
   * ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@ABV10@PB_W@Z
   *
   * What it does:
   * Builds `lhs + rhs` for one wide-string plus zero-terminated wide literal.
   */
  [[maybe_unused]] std::wstring BuildWideStringPlusWideLiteral(
    const std::wstring& lhs,
    const wchar_t* const rhs
  )
  {
    std::wstring tmp(lhs);
    const wchar_t* const safeRhs = (rhs != nullptr) ? rhs : L"";
    tmp += safeRhs;
    return tmp;
  }

  /**
   * Address: 0x004A1D50 (FUN_004A1D50)
   * Mangled:
   * ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@ABV10@0@Z
   *
   * What it does:
   * Builds `lhs + rhs` for one wide-string plus wide-string pair.
   */
  [[maybe_unused]] std::wstring BuildWideStringPlusWideString(const std::wstring& lhs, const std::wstring& rhs)
  {
    std::wstring tmp(lhs);
    tmp.append(rhs, 0, std::wstring::npos);
    return tmp;
  }

  /**
   * Address: 0x004A1E10 (FUN_004A1E10, j__strrchr)
   *
   * What it does:
   * Forwards one C-string reverse-character search to CRT `strrchr`.
   */
  [[maybe_unused]] char* FindLastCharacterInCString(char* const text, const int character) noexcept
  {
    return std::strrchr(text, character);
  }

  struct LegacyByteVectorStorageView
  {
    std::uint8_t* first = nullptr;
    std::uint8_t* last = nullptr;
    std::uint8_t* end = nullptr;
  };

#if defined(_M_IX86)
  static_assert(sizeof(LegacyByteVectorStorageView) == 0x0C, "LegacyByteVectorStorageView size must be 0x0C");
#endif

  [[nodiscard]] std::size_t LegacyByteVectorSizeBytes(const LegacyByteVectorStorageView* const storage) noexcept
  {
    if (storage == nullptr || storage->first == nullptr) {
      return 0;
    }
    return static_cast<std::size_t>(storage->last - storage->first);
  }

  [[nodiscard]] std::size_t LegacyByteVectorCapacityBytes(const LegacyByteVectorStorageView* const storage) noexcept
  {
    if (storage == nullptr || storage->first == nullptr) {
      return 0;
    }
    return static_cast<std::size_t>(storage->end - storage->first);
  }

  /**
   * Address: 0x004A2FD0 (FUN_004A2FD0, sub_4A2FD0)
   *
   * What it does:
   * Resets one byte-vector storage triplet to null pointers.
   */
  [[maybe_unused]] LegacyByteVectorStorageView* ResetLegacyByteVectorStorage(LegacyByteVectorStorageView* const storage)
    noexcept
  {
    if (storage != nullptr) {
      storage->first = nullptr;
      storage->last = nullptr;
      storage->end = nullptr;
    }
    return storage;
  }

  /**
   * Address: 0x004A3280 (FUN_004A3280, sub_4A3280)
   *
   * What it does:
   * Writes `base + offset` into one output pointer slot.
   */
  [[maybe_unused]] std::uint8_t** WritePointerWithByteOffset(
    std::uint8_t* const base,
    std::uint8_t** const outPointer,
    const std::uint32_t offset
  ) noexcept
  {
    if (outPointer != nullptr) {
      *outPointer = (base != nullptr) ? (base + offset) : nullptr;
    }
    return outPointer;
  }

  /**
   * Address: 0x004A3290 (FUN_004A3290, sub_4A3290)
   *
   * What it does:
   * Returns capacity bytes (`end - first`) for one byte-vector storage view.
   */
  [[maybe_unused]] std::uint32_t GetLegacyByteVectorCapacityBytes(const LegacyByteVectorStorageView* const storage)
    noexcept
  {
    if (storage == nullptr || storage->first == nullptr) {
      return 0;
    }
    return static_cast<std::uint32_t>(storage->end - storage->first);
  }

  /**
   * Address: 0x004A32A0 (FUN_004A32A0, sub_4A32A0)
   *
   * What it does:
   * Assigns one 32-bit slot value.
   */
  [[maybe_unused]] std::uint32_t* AssignUint32Slot(std::uint32_t* const slot, const std::uint32_t value) noexcept
  {
    if (slot != nullptr) {
      *slot = value;
    }
    return slot;
  }

  /**
   * Address: 0x004A32B0 (FUN_004A32B0, sub_4A32B0)
   *
   * What it does:
   * Adds one 32-bit delta into one slot.
   */
  [[maybe_unused]] std::uint32_t* AddUint32SlotDelta(std::uint32_t* const slot, const std::uint32_t delta) noexcept
  {
    if (slot != nullptr) {
      *slot += delta;
    }
    return slot;
  }

  /**
   * Address: 0x004A32C0 (FUN_004A32C0, sub_4A32C0)
   *
   * What it does:
   * Returns whether two 32-bit slot values differ.
   */
  [[maybe_unused]] bool AreUint32SlotsDifferent(
    const std::uint32_t* const lhs, const std::uint32_t* const rhs
  ) noexcept
  {
    if (lhs == nullptr || rhs == nullptr) {
      return lhs != rhs;
    }
    return *lhs != *rhs;
  }

  /**
   * Address: 0x004A32E0 (FUN_004A32E0, sub_4A32E0)
   *
   * What it does:
   * Duplicate 32-bit slot assignment helper.
   */
  [[maybe_unused]] std::uint32_t* AssignUint32SlotDuplicate(std::uint32_t* const slot, const std::uint32_t value)
    noexcept
  {
    return AssignUint32Slot(slot, value);
  }

  /**
   * Address: 0x004A32F0 (FUN_004A32F0, sub_4A32F0)
   *
   * What it does:
   * Duplicate 32-bit slot delta-add helper.
   */
  [[maybe_unused]] std::uint32_t* AddUint32SlotDeltaDuplicate(
    std::uint32_t* const slot,
    const std::uint32_t delta
  ) noexcept
  {
    return AddUint32SlotDelta(slot, delta);
  }

  /**
   * Address: 0x004A3300 (FUN_004A3300, sub_4A3300)
   *
   * What it does:
   * Returns whether two 32-bit slot values are equal.
   */
  [[maybe_unused]] bool AreUint32SlotsEqual(const std::uint32_t* const lhs, const std::uint32_t* const rhs) noexcept
  {
    if (lhs == nullptr || rhs == nullptr) {
      return lhs == rhs;
    }
    return *lhs == *rhs;
  }

  /**
   * Address: 0x004A3070 (FUN_004A3070, sub_4A3070)
   *
   * What it does:
   * Writes the current begin pointer into an output pointer slot.
   */
  [[maybe_unused]] std::uint8_t** WriteLegacyByteVectorBeginPointer(
    const LegacyByteVectorStorageView* const storage,
    std::uint8_t** const outPointer
  ) noexcept
  {
    return WritePointerWithByteOffset(storage != nullptr ? storage->first : nullptr, outPointer, 0);
  }

  /**
   * Address: 0x004A3080 (FUN_004A3080, sub_4A3080)
   *
   * What it does:
   * Writes the current end-of-used-range pointer into an output pointer slot.
   */
  [[maybe_unused]] std::uint8_t** WriteLegacyByteVectorLastPointer(
    const LegacyByteVectorStorageView* const storage,
    std::uint8_t** const outPointer
  ) noexcept
  {
    return WritePointerWithByteOffset(storage != nullptr ? storage->last : nullptr, outPointer, 0);
  }

  /**
   * Address: 0x004A3090 (FUN_004A3090, sub_4A3090)
   *
   * What it does:
   * Moves one tail byte range to `destination`, updates `last`, and writes the
   * destination pointer to the output slot.
   */
  [[maybe_unused]] std::uint8_t** MoveLegacyByteVectorTailAndWriteDestination(
    LegacyByteVectorStorageView* const storage,
    std::uint8_t** const outPointer,
    std::uint8_t* const destination,
    std::uint8_t* const source
  ) noexcept
  {
    if (storage == nullptr) {
      if (outPointer != nullptr) {
        *outPointer = destination;
      }
      return outPointer;
    }

    if (destination != source && source != nullptr && storage->last != nullptr) {
      const std::ptrdiff_t tailSize = storage->last - source;
      std::uint8_t* const newLast = destination + tailSize;
      if (tailSize > 0) {
        std::memmove(destination, source, static_cast<std::size_t>(tailSize));
      }
      storage->last = newLast;
    }

    if (outPointer != nullptr) {
      *outPointer = destination;
    }
    return outPointer;
  }

  /**
   * Address: 0x004A3320 (FUN_004A3320, sub_4A3320)
   *
   * What it does:
   * Moves one byte range `[sourceBegin, sourceEnd)` into `destination` when
   * range length is positive and returns destination end.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenPositiveLength(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    const std::ptrdiff_t length = sourceEnd - sourceBegin;
    std::uint8_t* const destinationEnd = destination + length;
    if (length > 0) {
      std::memmove(destination, sourceBegin, static_cast<std::size_t>(length));
    }
    return destinationEnd;
  }

  /**
   * Address: 0x004A3350 (FUN_004A3350, sub_4A3350)
   *
   * What it does:
   * Moves one byte range `[sourceBegin, sourceEnd)` into `destination` when
   * range length is non-zero and returns destination end.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenNonZeroLength(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    const std::ptrdiff_t length = sourceEnd - sourceBegin;
    std::uint8_t* const destinationEnd = destination + length;
    if (sourceBegin != sourceEnd) {
      std::memmove(destination, sourceBegin, static_cast<std::size_t>(length));
    }
    return destinationEnd;
  }

  /**
   * Address: 0x004A3380 (FUN_004A3380, sub_4A3380)
   *
   * What it does:
   * Fills one byte range `[begin, end)` with one source byte.
   */
  [[maybe_unused]] std::uint8_t* FillByteRangeWithSourceValue(
    std::uint8_t* begin,
    const std::uint8_t* const end,
    const std::uint8_t* const sourceValue
  ) noexcept
  {
    while (begin != end) {
      *begin = *sourceValue;
      ++begin;
    }
    return begin;
  }

  /**
   * Address: 0x004A33A0 (FUN_004A33A0, sub_4A33A0)
   *
   * What it does:
   * Moves one byte range `[sourceBegin, sourceEnd)` so it ends at
   * `destinationEnd` and returns the moved-range begin pointer.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeToEndWhenPositiveLength(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destinationEnd
  ) noexcept
  {
    const std::ptrdiff_t length = sourceEnd - sourceBegin;
    std::uint8_t* const destinationBegin = destinationEnd - length;
    if (length > 0) {
      std::memmove(destinationBegin, sourceBegin, static_cast<std::size_t>(length));
    }
    return destinationBegin;
  }

  /**
   * Address: 0x004A33D0 (FUN_004A33D0, sub_4A33D0)
   *
   * What it does:
   * Returns input value unchanged.
   */
  [[maybe_unused]] int ReturnIdentityInt(const int value) noexcept
  {
    return value;
  }

  /**
   * Address: 0x004A33E0 (FUN_004A33E0, sub_4A33E0)
   *
   * What it does:
   * Duplicate positive-length forward byte-range move helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenPositiveLengthDuplicate(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    return MoveByteRangeForwardWhenPositiveLength(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A3410 (FUN_004A3410, sub_4A3410)
   *
   * What it does:
   * Duplicate non-zero-length forward byte-range move helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenNonZeroLengthDuplicateA(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    return MoveByteRangeForwardWhenNonZeroLength(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A3440 (FUN_004A3440, sub_4A3440)
   *
   * What it does:
   * Duplicate byte-range fill helper.
   */
  [[maybe_unused]] std::uint8_t* FillByteRangeWithSourceValueDuplicate(
    std::uint8_t* begin,
    const std::uint8_t* const end,
    const std::uint8_t* const sourceValue
  ) noexcept
  {
    return FillByteRangeWithSourceValue(begin, end, sourceValue);
  }

  /**
   * Address: 0x004A3460 (FUN_004A3460, sub_4A3460)
   *
   * What it does:
   * Returns high byte from low 16-bit lane of the input integer.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByteFromLowWord(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  }

  /**
   * Address: 0x004A3470 (FUN_004A3470, sub_4A3470)
   *
   * What it does:
   * Duplicate move-range-to-end helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeToEndWhenPositiveLengthDuplicateA(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destinationEnd
  ) noexcept
  {
    return MoveByteRangeToEndWhenPositiveLength(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x004A34A0 (FUN_004A34A0, sub_4A34A0)
   *
   * What it does:
   * Duplicate non-zero-length forward byte-range move helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenNonZeroLengthDuplicateB(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    return MoveByteRangeForwardWhenNonZeroLength(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A34D0 (FUN_004A34D0, sub_4A34D0)
   *
   * What it does:
   * Duplicate move-range-to-end helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeToEndWhenPositiveLengthDuplicateB(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destinationEnd
  ) noexcept
  {
    return MoveByteRangeToEndWhenPositiveLength(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x004A3500 (FUN_004A3500, sub_4A3500)
   *
   * What it does:
   * Duplicate non-zero-length forward byte-range move helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenNonZeroLengthDuplicateC(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    return MoveByteRangeForwardWhenNonZeroLength(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A3530 (FUN_004A3530, sub_4A3530)
   *
   * What it does:
   * Duplicate non-zero-length forward byte-range move helper.
   */
  [[maybe_unused]] std::uint8_t* MoveByteRangeForwardWhenNonZeroLengthDuplicateD(
    const std::uint8_t* const sourceBegin,
    const std::uint8_t* const sourceEnd,
    std::uint8_t* const destination
  ) noexcept
  {
    return MoveByteRangeForwardWhenNonZeroLength(sourceBegin, sourceEnd, destination);
  }

  struct LegacyUint32PairEmitterView
  {
    std::uint32_t reserved0 = 0;
    std::uint32_t secondValue = 0;
    std::uint32_t firstBase = 0;
  };

  struct LegacyUint32PairView
  {
    std::uint32_t first = 0;
    std::uint32_t second = 0;
  };

#if defined(_M_IX86)
  static_assert(sizeof(LegacyUint32PairEmitterView) == 0x0C, "LegacyUint32PairEmitterView size must be 0x0C");
  static_assert(sizeof(LegacyUint32PairView) == 0x08, "LegacyUint32PairView size must be 0x08");
#endif

  /**
   * Address: 0x004A35B0 (FUN_004A35B0, sub_4A35B0)
   *
   * What it does:
   * Writes one 32-bit pair where `first = firstBase + delta` and
   * `second = secondValue`.
   */
  [[maybe_unused]] LegacyUint32PairView* WriteAdjustedUint32PairFromEmitter(
    const LegacyUint32PairEmitterView* const emitter,
    LegacyUint32PairView* const outPair,
    const std::uint32_t delta
  ) noexcept
  {
    if (outPair == nullptr) {
      return nullptr;
    }

    if (emitter == nullptr) {
      outPair->first = delta;
      outPair->second = 0;
      return outPair;
    }

    outPair->first = emitter->firstBase + delta;
    outPair->second = emitter->secondValue;
    return outPair;
  }

  /**
   * Address: 0x004A30D0 (FUN_004A30D0, sub_4A30D0)
   *
   * What it does:
   * Inserts `count` fill-bytes at `insertPosition` in one legacy byte-vector
   * storage view and returns the insertion-start pointer.
   */
  [[maybe_unused]] std::uint8_t* InsertFillBytesIntoLegacyByteVectorStorage(
    LegacyByteVectorStorageView* const storage,
    std::uint8_t* insertPosition,
    const std::uint32_t count,
    const std::uint8_t fillValue
  )
  {
    if (storage == nullptr) {
      return nullptr;
    }

    const std::size_t currentSize = LegacyByteVectorSizeBytes(storage);
    const std::size_t currentCapacity = LegacyByteVectorCapacityBytes(storage);
    if (count == 0U) {
      return storage->last;
    }
    if (currentSize > (std::numeric_limits<std::size_t>::max() - static_cast<std::size_t>(count))) {
      throw std::length_error("LegacyByteVectorStorageView too long");
    }

    std::size_t insertOffset = 0;
    if (storage->first != nullptr) {
      if (insertPosition == nullptr || insertPosition < storage->first) {
        insertOffset = 0;
      } else if (insertPosition > storage->last) {
        insertOffset = currentSize;
      } else {
        insertOffset = static_cast<std::size_t>(insertPosition - storage->first);
      }
    }

    const std::size_t newSize = currentSize + static_cast<std::size_t>(count);
    if (newSize > currentCapacity) {
      std::size_t grownCapacity = 0;
      if (currentCapacity <= ((std::numeric_limits<std::size_t>::max() - currentCapacity) / 2U)) {
        grownCapacity = currentCapacity + (currentCapacity / 2U);
      }
      if (grownCapacity < newSize) {
        grownCapacity = newSize;
      }

      auto* const newBuffer = static_cast<std::uint8_t*>(::operator new(grownCapacity));
      if (insertOffset != 0U && storage->first != nullptr) {
        std::memmove(newBuffer, storage->first, insertOffset);
      }

      std::memset(newBuffer + insertOffset, fillValue, count);

      if (currentSize > insertOffset && storage->first != nullptr) {
        const std::size_t trailingSize = currentSize - insertOffset;
        std::memmove(newBuffer + insertOffset + count, storage->first + insertOffset, trailingSize);
      }

      if (storage->first != nullptr) {
        ::operator delete(storage->first);
      }
      storage->first = newBuffer;
      storage->last = newBuffer + newSize;
      storage->end = newBuffer + grownCapacity;
      return newBuffer + insertOffset;
    }

    insertPosition = storage->first + insertOffset;
    const std::size_t trailingSize = currentSize - insertOffset;
    if (trailingSize != 0U) {
      std::memmove(insertPosition + count, insertPosition, trailingSize);
    }
    std::memset(insertPosition, fillValue, count);
    storage->last = storage->first + newSize;
    return insertPosition;
  }

  /**
   * Address: 0x004A2FF0 (FUN_004A2FF0, sub_4A2FF0)
   *
   * What it does:
   * Resizes one legacy byte-vector storage view to `requestedSize`, filling
   * newly-grown bytes with `fillValue`.
   */
  [[maybe_unused]] void ResizeLegacyByteVectorStorage(
    LegacyByteVectorStorageView* const storage,
    const std::size_t requestedSize,
    const std::uint8_t fillValue
  )
  {
    if (storage == nullptr) {
      return;
    }

    const std::size_t currentSize = LegacyByteVectorSizeBytes(storage);
    if (currentSize >= requestedSize) {
      if (storage->first != nullptr && requestedSize < currentSize && (storage->first + requestedSize) != storage->last) {
        storage->last = storage->first + requestedSize;
      }
      return;
    }

    InsertFillBytesIntoLegacyByteVectorStorage(
      storage,
      storage->last,
      static_cast<std::uint32_t>(requestedSize - currentSize),
      fillValue
    );
  }

  /**
   * Address: 0x004A2FE0 (FUN_004A2FE0, sub_4A2FE0)
   *
   * What it does:
   * Wrapper that forwards to byte-vector resize helper with zero fill.
   */
  [[maybe_unused]] void ResizeLegacyByteVectorStorageWithZeroFill(
    LegacyByteVectorStorageView* const storage,
    const std::size_t requestedSize
  )
  {
    ResizeLegacyByteVectorStorage(storage, requestedSize, 0);
  }

  [[maybe_unused]] void DestroyLegacyByteVectorStorage(LegacyByteVectorStorageView* const storage) noexcept
  {
    if (storage != nullptr && storage->first != nullptr) {
      ::operator delete(storage->first);
      storage->first = nullptr;
      storage->last = nullptr;
      storage->end = nullptr;
    }
  }

  struct ParsedRegistryPathView
  {
    HKEY rootKey = HKEY_CURRENT_USER;
    char* subKey = nullptr;
    const char* valueName = nullptr;
  };

  [[nodiscard]] HKEY ResolveRegistryRootKey(const char* const rootKeyName) noexcept
  {
    if (rootKeyName == nullptr) {
      return HKEY_CURRENT_USER;
    }
    if (_stricmp(rootKeyName, "HKEY_CLASSES_ROOT") == 0) {
      return HKEY_CLASSES_ROOT;
    }
    if (_stricmp(rootKeyName, "HKEY_CURRENT_USER") == 0) {
      return HKEY_CURRENT_USER;
    }
    if (_stricmp(rootKeyName, "HKEY_LOCAL_MACHINE") == 0) {
      return HKEY_LOCAL_MACHINE;
    }
    if (_stricmp(rootKeyName, "HKEY_USERS") == 0) {
      return HKEY_USERS;
    }
    if (_stricmp(rootKeyName, "HKEY_CURRENT_CONFIG") == 0) {
      return HKEY_CURRENT_CONFIG;
    }
    if (_stricmp(rootKeyName, "HKEY_DYN_DATA") == 0) {
      return reinterpret_cast<HKEY>(static_cast<std::uintptr_t>(0x80000006u));
    }
    if (_stricmp(rootKeyName, "HKEY_PERFORMANCE_DATA") == 0) {
      return HKEY_PERFORMANCE_DATA;
    }
    return HKEY_CURRENT_USER;
  }

  [[nodiscard]] ParsedRegistryPathView ParseRegistryPathInPlace(char* const mutablePath) noexcept
  {
    ParsedRegistryPathView parsed{};
    if (mutablePath == nullptr) {
      return parsed;
    }

    char* subKey = std::strchr(mutablePath, '\\');
    const char* valueName = subKey;
    if (subKey != nullptr) {
      ++subKey;
      subKey[-1] = '\0';

      char* const lastSeparator = FindLastCharacterInCString(subKey, '\\');
      if (lastSeparator != nullptr) {
        *lastSeparator = '\0';
        valueName = lastSeparator + 1;
      } else {
        valueName = subKey;
        subKey = nullptr;
      }
    } else {
      valueName = nullptr;
      subKey = nullptr;
    }

    parsed.rootKey = ResolveRegistryRootKey(mutablePath);
    parsed.subKey = subKey;
    parsed.valueName = valueName;
    return parsed;
  }

  using BugSplatAttachmentCallbackFn = bool(__cdecl*)(std::uint32_t, void*, void*);
  void DestroyBugSplatMiniDmpSenderAtExit();

  [[nodiscard]]
  moho::WWinLogWindow* CreateLogWindowRuntime()
  {
    moho::WWinLogWindow* const logWindow = new (std::nothrow) moho::WWinLogWindow();
    if (logWindow != nullptr) {
      logWindow->SetOwnerTarget(&sLogWindowTarget);
    }
    return logWindow;
  }

  /**
   * Address: 0x010A87B8 (`bugsplat_miniDmpSender`)
   *
   * What it does:
   * Process-global opaque `MiniDmpSender` object storage used by BugSplat
   * methods. IDA data-item sizing marks this global at 8 bytes.
   */
  struct BugSplatMiniDmpSenderRuntime
  {
    std::byte mOpaqueStorage[0x8]{};
  };

  static_assert(
    sizeof(BugSplatMiniDmpSenderRuntime) == 0x8,
    "BugSplatMiniDmpSenderRuntime size must be 0x8"
  );

  class BugSplatApi
  {
  public:
    using MiniDmpSenderCtorFn =
      void(__thiscall*)(void*, const char*, const char*, const char*, const char*, unsigned long);
    using MiniDmpSenderDtorFn = void(__thiscall*)(void*);
    using MiniDmpSenderSetCallbackFn = void(__thiscall*)(void*, BugSplatAttachmentCallbackFn);
    using MiniDmpSenderCreateReportFn = void(__thiscall*)(void*, _EXCEPTION_POINTERS*);

    [[nodiscard]]
    bool Resolve()
    {
      if (resolveAttempted_) {
        return ctor_ != nullptr && dtor_ != nullptr && setCallback_ != nullptr && createReport_ != nullptr;
      }

      resolveAttempted_ = true;
      module_ = ::GetModuleHandleA(kBugSplatModuleName);
      if (module_ == nullptr) {
        module_ = ::LoadLibraryA(kBugSplatModuleName);
      }
      if (module_ == nullptr) {
        return false;
      }

      ctor_ = reinterpret_cast<MiniDmpSenderCtorFn>(::GetProcAddress(module_, kMiniDmpSenderCtorExport));
      dtor_ = reinterpret_cast<MiniDmpSenderDtorFn>(::GetProcAddress(module_, kMiniDmpSenderDtorExport));
      setCallback_ =
        reinterpret_cast<MiniDmpSenderSetCallbackFn>(::GetProcAddress(module_, kMiniDmpSenderSetCallbackExport));
      createReport_ =
        reinterpret_cast<MiniDmpSenderCreateReportFn>(::GetProcAddress(module_, kMiniDmpSenderCreateReportExport));

      return ctor_ != nullptr && dtor_ != nullptr && setCallback_ != nullptr && createReport_ != nullptr;
    }

    void Construct(
      BugSplatMiniDmpSenderRuntime* const senderStorage,
      const char* const database,
      const char* const appName,
      const char* const versionText,
      const char* const userName,
      const unsigned long flags
    ) const
    {
      ctor_(static_cast<void*>(senderStorage), database, appName, versionText, userName, flags);
    }

    void Destroy(BugSplatMiniDmpSenderRuntime* const senderStorage) const
    {
      dtor_(static_cast<void*>(senderStorage));
    }

    void SetCallback(BugSplatMiniDmpSenderRuntime* const senderStorage, const BugSplatAttachmentCallbackFn callback)
      const
    {
      setCallback_(static_cast<void*>(senderStorage), callback);
    }

    void CreateReport(BugSplatMiniDmpSenderRuntime* const senderStorage, _EXCEPTION_POINTERS* const exceptionInfo)
      const
    {
      createReport_(static_cast<void*>(senderStorage), exceptionInfo);
    }

  private:
    HMODULE module_ = nullptr;
    bool resolveAttempted_ = false;
    MiniDmpSenderCtorFn ctor_ = nullptr;
    MiniDmpSenderDtorFn dtor_ = nullptr;
    MiniDmpSenderSetCallbackFn setCallback_ = nullptr;
    MiniDmpSenderCreateReportFn createReport_ = nullptr;
  };

  class BugSplatMiniDmpSenderRegistry
  {
  public:
    [[nodiscard]]
    bool Register()
    {
      std::lock_guard<std::mutex> lock(mutex_);
      return RegisterLocked();
    }

    [[nodiscard]]
    bool SetCallbackAndCreateReport(_EXCEPTION_POINTERS* const exceptionInfo, const BugSplatAttachmentCallbackFn callback)
    {
      if (exceptionInfo == nullptr || callback == nullptr) {
        return false;
      }

      std::lock_guard<std::mutex> lock(mutex_);
      if (!RegisterLocked()) {
        return false;
      }

      api_.SetCallback(&sender_, callback);
      api_.CreateReport(&sender_, exceptionInfo);
      return true;
    }

    void DestroyAtProcessExit()
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!isRegistered_) {
        return;
      }

      api_.Destroy(&sender_);
      isRegistered_ = false;
    }

  private:
    [[nodiscard]]
    bool RegisterLocked()
    {
      if (isRegistered_) {
        return true;
      }
      if (!api_.Resolve()) {
        return false;
      }

      const msvc8::string versionText = gpg::STR_Printf("%i", 3620);
      api_.Construct(&sender_, "gaspowered", "SupremeCommander", versionText.c_str(), nullptr, 0x20u);
      isRegistered_ = true;
      (void)std::atexit(&DestroyBugSplatMiniDmpSenderAtExit);
      return true;
    }

    std::mutex mutex_;
    BugSplatApi api_{};
    BugSplatMiniDmpSenderRuntime sender_{};
    bool isRegistered_ = false;
  };

  class CrashReportAttachmentRegistry
  {
  public:
    void SetOutputDir(const wchar_t* const outputDir)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      AssignErrorReportOutputDirFromNullTerminatedInput(outputDir);
      if (!IsLegacyErrorReportOutputDirEmpty() && sLegacyErrorReportOutputDir.back() != kPathSeparator) {
        (void)AppendWideStringFromNullTerminatedInputA(&sLegacyErrorReportOutputDir, L"\\");
      }
      outputDir_ = sLegacyErrorReportOutputDir;
    }

    [[nodiscard]]
    std::wstring GetOutputDirSnapshot() const
    {
      std::lock_guard<std::mutex> lock(mutex_);
      return outputDir_;
    }

    void RegisterFile(const wchar_t* const file)
    {
      if (file == nullptr || file[0] == L'\0') {
        return;
      }

      std::lock_guard<std::mutex> lock(mutex_);
      for (const std::wstring& existing : files_) {
        if (CompareWideStringWithNullTerminatedInput(&existing, file) == 0) {
          return;
        }
      }

      std::wstring candidate{};
      (void)InitializeAndAssignWideStringFromNullTerminatedInput(&candidate, file);
      files_.push_back(candidate);
    }

    [[nodiscard]]
    std::size_t GetFileCount() const
    {
      std::lock_guard<std::mutex> lock(mutex_);
      return files_.size();
    }

    [[nodiscard]]
    bool GetFileByOneBasedIndex(const std::uint32_t oneBasedIndex, std::wstring* const outFile) const
    {
      if (oneBasedIndex == 0 || outFile == nullptr) {
        return false;
      }

      std::lock_guard<std::mutex> lock(mutex_);
      const std::size_t zeroBasedIndex = static_cast<std::size_t>(oneBasedIndex - 1);
      if (zeroBasedIndex >= files_.size()) {
        return false;
      }

      *outFile = files_[zeroBasedIndex];
      return true;
    }

  private:
    mutable std::mutex mutex_;
    std::wstring outputDir_;
    std::vector<std::wstring> files_;
  };

  CrashReportAttachmentRegistry sCrashReportAttachments;
  BugSplatMiniDmpSenderRegistry sBugSplatMiniDmpSenderRegistry;

  /**
   * Address: 0x004A1CA0 (FUN_004A1CA0, sub_4A1CA0)
   *
   * What it does:
   * Builds `prefix + suffix` for wide-string command fragments used by the
   * crash-report dxdiag launcher.
   */
  [[nodiscard]]
  std::wstring BuildDxdiagCommandLine(const std::wstring& outputPath)
  {
    return BuildWideStringPlusWideLiteral(std::wstring(kDxdiagCommandPrefix), outputPath.c_str());
  }

  [[nodiscard]]
  std::wstring GetErrorReportOutputDirSnapshot()
  {
    return sCrashReportAttachments.GetOutputDirSnapshot();
  }

  /**
   * Address: 0x004A1030 (FUN_004A1030, sub_4A1030)
   *
   * What it does:
   * Launches `dxdiag.exe` with an output path under the report directory, waits
   * up to 60 seconds for completion, then registers the file when it exists.
   */
  void PLAT_CreateDxdiagForReport()
  {
    const std::wstring outputPath = GetErrorReportOutputDirSnapshot() + kDxdiagOutputFileName;
    const std::wstring commandLineText = BuildDxdiagCommandLine(outputPath);

    std::vector<wchar_t> commandLine(commandLineText.begin(), commandLineText.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInformation{};

    if (::CreateProcessW(
          nullptr,
          commandLine.data(),
          nullptr,
          nullptr,
          FALSE,
          0x4000020u,
          nullptr,
          nullptr,
          &startupInfo,
          &processInformation
        ) != FALSE) {
      (void)::WaitForSingleObject(processInformation.hProcess, 60000u);
      (void)::CloseHandle(processInformation.hProcess);
      (void)::CloseHandle(processInformation.hThread);
    }

    const msvc8::string outputPathUtf8 = gpg::STR_WideToUtf8(outputPath.c_str());
    if (moho::FILE_GetFileInfo(outputPathUtf8.c_str(), nullptr, false)) {
      moho::PLAT_RegisterFileForErrorReport(outputPath.c_str());
    }
  }

  /**
   * Address: 0x004A1610 (FUN_004A1610, sub_4A1610)
   *
   * What it does:
   * Handles BugSplat attachment callback events:
   * - `0x100`: regenerates attachment files and reports attachment count.
   * - `0x1101`: returns one attachment path as a `GlobalAlloc` wide string.
   */
  bool BugSplatAttachmentCallback(const std::uint32_t callbackCode, void* const outPayload, void* const callbackData)
  {
    if (callbackCode == kBugSplatPrepareAttachmentsEvent) {
      moho::PLAT_CreateGameLogForReport();
      PLAT_CreateDxdiagForReport();
      if (outPayload != nullptr) {
        *static_cast<std::size_t*>(outPayload) = sCrashReportAttachments.GetFileCount();
      }
      return true;
    }

    if (callbackCode != kBugSplatQueryAttachmentPathEvent || outPayload == nullptr) {
      return false;
    }

    const auto oneBasedIndex = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(callbackData));
    std::wstring selectedPath;
    if (!sCrashReportAttachments.GetFileByOneBasedIndex(oneBasedIndex, &selectedPath)) {
      return false;
    }

    const std::size_t payloadBytes = (selectedPath.size() + 1) * sizeof(wchar_t);
    const HGLOBAL globalText = ::GlobalAlloc(0, payloadBytes);
    *static_cast<HGLOBAL*>(outPayload) = globalText;
    if (globalText == nullptr) {
      return false;
    }

    wchar_t* const destination = static_cast<wchar_t*>(::GlobalLock(globalText));
    if (destination == nullptr) {
      return false;
    }

    std::memcpy(destination, selectedPath.c_str(), payloadBytes);
    (void)::GlobalUnlock(globalText);
    return true;
  }

  bool HasCorrectPlatform()
  {
    OSVERSIONINFOW versionInfo{};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    return !::GetVersionExW(&versionInfo) || versionInfo.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS;
  }

  float ProbeWakeTimerMs()
  {
    return static_cast<float>(wakeupTimer.ElapsedMilliseconds());
  }

  /**
   * Address: 0x0040D820 (FUN_0040D820, func_round)
   *
   * float
   *
   * What it does:
   * Applies x87 `frndint` rounding, then adjusts down by one when the original
   * value is below the rounded lane (floor-equivalent in default rounding mode).
   */
  [[nodiscard]] int FloorFrndintAdjustDown(const float value) noexcept
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value < rounded) ? -1 : 0);
  }

  DWORD ComputeWaitTimeoutMs()
  {
    const float remainingMs = wakeupTimerDur - ProbeWakeTimerMs();
    if (remainingMs < 0.0f) {
      return 0;
    }

    if (remainingMs > kMaxFiniteTimeoutMs) {
      return INFINITE;
    }

    return static_cast<DWORD>(FloorFrndintAdjustDown(remainingMs));
  }

  void WxPumpToIdleAndExit()
  {
    if (!moho::WxAppRuntime::IsAvailable()) {
      return;
    }

    bool keepIdle = true;
    for (;;) {
      if (moho::WxAppRuntime::Pending()) {
        moho::WxAppRuntime::Dispatch();
        continue;
      }

      if (!keepIdle) {
        break;
      }

      keepIdle = moho::WxAppRuntime::ProcessIdle();
    }

    moho::WxAppRuntime::OnExit();
    wxApp::CleanUp();
  }

  LRESULT CALLBACK WindowHook(const int code, const WPARAM wParam, const LPARAM lParam)
  {
    if (code == HC_ACTION && sSupComApp != nullptr && sSupComApp->AppDoSuppressWindowsKeys() && wParam >= WM_KEYDOWN &&
        wParam <= WM_KEYUP) {
      const auto* const keyData = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
      if (keyData != nullptr && (keyData->vkCode == VK_LWIN || keyData->vkCode == VK_RWIN)) {
        return 1;
      }
    }

    return ::CallNextHookEx(sWindowHook, code, wParam, lParam);
  }

  [[nodiscard]]
  boost::mutex* GetSymHandlerMutexStorage()
  {
    return reinterpret_cast<boost::mutex*>(&sSymHandlerMutexStorage);
  }

  /**
   * Address: 0x00BF02B0 (FUN_00BF02B0, ??1sMutexSymHandler@Moho@@QAE@@Z)
   *
   * What it does:
   * `atexit` callback for the lazily-constructed symbol-handler mutex storage.
   */
  void DestroySymHandlerMutexAtProcessExit()
  {
    if (!sSymHandlerMutexConstructed) {
      return;
    }

    GetSymHandlerMutexStorage()->~mutex();
    sSymHandlerMutexConstructed = false;
    sMutexSymHandler = nullptr;
  }

  /**
   * Address: 0x004A1E20 (FUN_004A1E20, Moho::InitSymHandlerMutex)
   *
   * What it does:
   * Lazily constructs process-global symbol-handler mutex storage and installs
   * its process-exit destructor callback.
   */
  void InitSymHandlerMutex()
  {
    if (!sSymHandlerMutexConstructed) {
      new (&sSymHandlerMutexStorage) boost::mutex();
      sSymHandlerMutexConstructed = true;
      (void)std::atexit(&DestroySymHandlerMutexAtProcessExit);
    }

    sMutexSymHandler = GetSymHandlerMutexStorage();
  }

  [[nodiscard]]
  boost::mutex& GetSymHandlerMutex()
  {
    std::call_once(sSymHandlerMutexInitOnce, &InitSymHandlerMutex);
    return *sMutexSymHandler;
  }

  struct StackWalkSeedRegisters
  {
    std::uint32_t programCounter = 0;
    std::uint32_t stackPointer = 0;
    std::uint32_t framePointer = 0;
  };

  /**
   * Address: 0x004A1EB0 (FUN_004A1EB0, sub_4A1EB0)
   *
   * What it does:
   * Captures caller `EIP/ESP/EBP` seed registers for `StackWalk` when no
   * external context record is supplied.
   */
  void CaptureStackWalkSeedRegisters(StackWalkSeedRegisters* const outRegisters)
  {
#if defined(_M_IX86)
    if (outRegisters == nullptr) {
      return;
    }

    const auto returnAddressValue = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    const auto returnAddressSlot = reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const auto callerFramePointerSlot = returnAddressSlot - sizeof(std::uint32_t);

    outRegisters->programCounter = static_cast<std::uint32_t>(returnAddressValue - 5u);
    outRegisters->stackPointer = static_cast<std::uint32_t>(returnAddressSlot + sizeof(std::uint32_t));
    outRegisters->framePointer = *reinterpret_cast<const std::uint32_t*>(callerFramePointerSlot);
#else
    (void)outRegisters;
#endif
  }

  constexpr WORD kCrashDialogTemplateId = 0x7A;
  constexpr int kCrashTextControlId = 1065;
  constexpr int kCrashCopyButtonId = 1066;
  constexpr int kCrashDisableButtonId = 1067;
  constexpr int kCrashCloseButtonId = 1068;

  struct CrashDialogInitData
  {
    gpg::StrArg caption;
    gpg::StrArg body;
  };

  [[nodiscard]]
  msvc8::string NormalizeDialogNewlines(const gpg::StrArg text)
  {
    const char* const source = text != nullptr ? text : "";
    std::string normalized;
    normalized.reserve(std::strlen(source) * 2);

    char previous = '\0';
    for (const char current : std::string(source)) {
      if (current == '\n' && previous != '\r') {
        normalized.push_back('\r');
      }
      normalized.push_back(current);
      previous = current;
    }

    msvc8::string result;
    result.assign_owned(normalized);
    return result;
  }

  bool WIN_CopyToClipboard(const wchar_t* const text)
  {
    if (text == nullptr) {
      return false;
    }

    const std::size_t characterCount = std::wcslen(text) + 1;
    const std::size_t payloadBytes = characterCount * sizeof(wchar_t);

    if (::OpenClipboard(nullptr) == FALSE) {
      return false;
    }

    (void)::EmptyClipboard();
    HGLOBAL globalBlock = ::GlobalAlloc(GMEM_MOVEABLE, payloadBytes);
    if (globalBlock == nullptr) {
      ::CloseClipboard();
      return false;
    }

    void* const targetBuffer = ::GlobalLock(globalBlock);
    if (targetBuffer == nullptr) {
      ::GlobalFree(globalBlock);
      ::CloseClipboard();
      return false;
    }

    std::memcpy(targetBuffer, text, payloadBytes);
    ::GlobalUnlock(globalBlock);

    if (::SetClipboardData(CF_UNICODETEXT, globalBlock) == nullptr) {
      ::GlobalFree(globalBlock);
      ::CloseClipboard();
      return false;
    }

    ::CloseClipboard();
    return true;
  }

  INT_PTR CALLBACK CrashDialogProc(HWND hWnd, const UINT message, const WPARAM wParam, const LPARAM lParam)
  {
    if (message == WM_INITDIALOG) {
      auto* const initData = reinterpret_cast<CrashDialogInitData*>(lParam);
      (void)::SetWindowLongPtrW(hWnd, DWLP_USER, reinterpret_cast<LONG_PTR>(initData));

      const std::wstring caption = gpg::STR_Utf8ToWide(initData != nullptr ? initData->caption : "");
      (void)::SetWindowTextW(hWnd, caption.c_str());

      const msvc8::string normalizedBody = NormalizeDialogNewlines(initData != nullptr ? initData->body : "");
      const std::wstring bodyText = gpg::STR_Utf8ToWide(normalizedBody.c_str());
      (void)::SetDlgItemTextW(hWnd, kCrashTextControlId, bodyText.c_str());

      (void)::EnableWindow(::GetDlgItem(hWnd, kCrashDisableButtonId), FALSE);
      return TRUE;
    }

    if (message != WM_COMMAND) {
      return FALSE;
    }

    switch (LOWORD(wParam)) {
      case kCrashDisableButtonId:
        (void)::EnableWindow(reinterpret_cast<HWND>(lParam), FALSE);
        return TRUE;
      case IDCANCEL:
        ::TerminateProcess(::GetCurrentProcess(), 1u);
        return TRUE;
      case kCrashCopyButtonId: {
        const auto* const initData = reinterpret_cast<const CrashDialogInitData*>(::GetWindowLongPtrW(hWnd, DWLP_USER));
        if (initData != nullptr) {
          const std::wstring bodyText = gpg::STR_Utf8ToWide(initData->body != nullptr ? initData->body : "");
          (void)WIN_CopyToClipboard(bodyText.c_str());
        }
        return TRUE;
      }
      case kCrashCloseButtonId:
        ::EndDialog(hWnd, 0);
        return TRUE;
      default:
        return FALSE;
    }
  }

  /**
   * Address: 0x004A1740 (FUN_004A1740, sub_4A1740)
   *
   * What it does:
   * Enables BugSplat reporting when `/bugreport` is present, otherwise keeps
   * BugSplat enabled unless `/nobugreport` is present.
   */
  [[nodiscard]]
  bool ShouldUseBugSplatPath()
  {
    if (moho::CFG_GetArgOption("/bugreport", 0, nullptr)) {
      return true;
    }
    return !moho::CFG_GetArgOption("/nobugreport", 0, nullptr);
  }

  void SuspendSiblingThreadsForCrashReport()
  {
    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
      return;
    }

    THREADENTRY32 threadEntry{};
    threadEntry.dwSize = sizeof(threadEntry);
    if (::Thread32First(snapshot, &threadEntry) == FALSE) {
      ::CloseHandle(snapshot);
      return;
    }

    const DWORD processId = ::GetCurrentProcessId();
    const DWORD currentThreadId = ::GetCurrentThreadId();
    do {
      if (threadEntry.th32OwnerProcessID != processId || threadEntry.th32ThreadID == currentThreadId) {
        continue;
      }

      HANDLE threadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
      if (threadHandle != nullptr) {
        (void)::SuspendThread(threadHandle);
        ::CloseHandle(threadHandle);
      }
    } while (::Thread32Next(snapshot, &threadEntry) != FALSE);

    ::CloseHandle(snapshot);
  }

  void TryReportFault(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    if (exceptionInfo == nullptr) {
      return;
    }

    using ReportFaultFn = DWORD(WINAPI*)(LPEXCEPTION_POINTERS, DWORD);
    HMODULE faultReportingModule = ::GetModuleHandleW(L"faultrep.dll");
    bool loadedNow = false;
    if (faultReportingModule == nullptr) {
      faultReportingModule = ::LoadLibraryW(L"faultrep.dll");
      loadedNow = (faultReportingModule != nullptr);
    }

    if (faultReportingModule != nullptr) {
      const auto reportFault =
        reinterpret_cast<ReportFaultFn>(::GetProcAddress(faultReportingModule, "ReportFault"));
      if (reportFault != nullptr) {
        (void)reportFault(exceptionInfo, 0);
      }
    }

    if (loadedNow && faultReportingModule != nullptr) {
      (void)::FreeLibrary(faultReportingModule);
    }
  }

  /**
   * Address: 0x00BF0280 (FUN_00BF0280, DestroyBugSplatMiniDmpSenderAtExit)
   *
   * What it does:
   * Process-exit callback that tears down the process-global BugSplat sender.
   */
  void DestroyBugSplatMiniDmpSenderAtExit()
  {
    sBugSplatMiniDmpSenderRegistry.DestroyAtProcessExit();
  }

  /**
   * Address: 0x00BC5850 (FUN_00BC5850, register_MiniDmpSender)
   *
   * What it does:
   * Constructs the process-global BugSplat sender using build-version text
   * and registers an `atexit` callback for destructor teardown.
   */
  void register_MiniDmpSender()
  {
    (void)sBugSplatMiniDmpSenderRegistry.Register();
  }

  /**
   * Address: 0x004A1780 (FUN_004A1780, sub_4A1780)
   *
   * What it does:
   * Calls `ReportFault`, then dispatches BugSplat callback+report creation on
   * the process-global `MiniDmpSender`.
   */
  void ReportFaultAndCreateBugSplatReport(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    if (exceptionInfo == nullptr) {
      return;
    }

    TryReportFault(exceptionInfo);
    register_MiniDmpSender();
    (void)sBugSplatMiniDmpSenderRegistry.SetCallbackAndCreateReport(exceptionInfo, &BugSplatAttachmentCallback);
  }

  /**
   * Address: 0x004A2930 (FUN_004A2930)
   *
   * What it does:
   * Maps Windows structured-exception codes to fixed symbolic names.
   */
  const char* StructuredExceptionToString(const DWORD exceptionCode)
  {
    switch (exceptionCode) {
      case EXCEPTION_ACCESS_VIOLATION:
        return "EXCEPTION_ACCESS_VIOLATION";
      case EXCEPTION_DATATYPE_MISALIGNMENT:
        return "EXCEPTION_DATATYPE_MISALIGNMENT";
      case EXCEPTION_BREAKPOINT:
        return "EXCEPTION_BREAKPOINT";
      case EXCEPTION_SINGLE_STEP:
        return "EXCEPTION_SINGLE_STEP";
      case EXCEPTION_IN_PAGE_ERROR:
        return "EXCEPTION_IN_PAGE_ERROR";
      case EXCEPTION_ILLEGAL_INSTRUCTION:
        return "EXCEPTION_ILLEGAL_INSTRUCTION";
      case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
      case EXCEPTION_INVALID_DISPOSITION:
        return "EXCEPTION_INVALID_DISPOSITION";
      case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
      case EXCEPTION_FLT_DENORMAL_OPERAND:
        return "EXCEPTION_FLT_DENORMAL_OPERAND";
      case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
      case EXCEPTION_FLT_INEXACT_RESULT:
        return "EXCEPTION_FLT_INEXACT_RESULT";
      case EXCEPTION_FLT_INVALID_OPERATION:
        return "EXCEPTION_FLT_INVALID_OPERATION";
      case EXCEPTION_FLT_OVERFLOW:
        return "EXCEPTION_FLT_OVERFLOW";
      case EXCEPTION_FLT_STACK_CHECK:
        return "EXCEPTION_FLT_STACK_CHECK";
      case EXCEPTION_FLT_UNDERFLOW:
        return "EXCEPTION_FLT_UNDERFLOW";
      case EXCEPTION_INT_DIVIDE_BY_ZERO:
        return "EXCEPTION_INT_DIVIDE_BY_ZERO";
      case EXCEPTION_INT_OVERFLOW:
        return "EXCEPTION_INT_OVERFLOW";
      case EXCEPTION_PRIV_INSTRUCTION:
        return "EXCEPTION_PRIV_INSTRUCTION";
      case EXCEPTION_STACK_OVERFLOW:
        return "EXCEPTION_STACK_OVERFLOW";
      default:
        return "Unknown structured exception";
    }
  }

  /**
   * Address: 0x004A2B30 (FUN_004A2B30, TopLevelExceptionFilter)
   *
   * What it does:
   * Handles unhandled structured exceptions and chooses BugSplat/report-fault
   * flow or local crash-dialog flow based on startup command-line switches.
   */
  LONG WINAPI TopLevelExceptionFilter(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    if (exceptionInfo == nullptr || exceptionInfo->ExceptionRecord == nullptr) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    if (ShouldUseBugSplatPath()) {
      if (moho::sMainWindow != nullptr) {
        (void)::DestroyWindow(
          reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()))
        );
      }

      SuspendSiblingThreadsForCrashReport();
      ReportFaultAndCreateBugSplatReport(exceptionInfo);
      return EXCEPTION_EXECUTE_HANDLER;
    }

    const DWORD exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
    if (exceptionCode == EXCEPTION_BREAKPOINT) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    const std::uintptr_t exceptionAddressRaw =
      reinterpret_cast<std::uintptr_t>(exceptionInfo->ExceptionRecord->ExceptionAddress);
    char message[256]{};
    std::snprintf(
      message,
      sizeof(message),
      "%s (0x%08X) at address 0x%08X",
      StructuredExceptionToString(exceptionCode),
      static_cast<unsigned int>(exceptionCode),
      static_cast<unsigned int>(exceptionAddressRaw)
    );

    std::string dialogText(message);
    if (exceptionCode == EXCEPTION_ACCESS_VIOLATION && exceptionInfo->ExceptionRecord->NumberParameters >= 2u) {
      const char* const operation = exceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0 ? "read" : "write";
      char accessViolationDetails[128]{};
      std::snprintf(
        accessViolationDetails,
        sizeof(accessViolationDetails),
        "\n    attempted to %s memory at 0x%08X",
        operation,
        static_cast<unsigned int>(exceptionInfo->ExceptionRecord->ExceptionInformation[1])
      );
      dialogText += accessViolationDetails;
    }

    moho::WIN_ShowCrashDialog(0, exceptionInfo, "Unhandled Exception", dialogText.c_str());
    return EXCEPTION_CONTINUE_SEARCH;
  }

} // namespace

moho::CTaskStage* moho::WIN_GetBeforeEventsStage()
{
  // 0x011043CC
  static CTaskStage sBeforeEventsStage{};
  return &sBeforeEventsStage;
}

moho::CTaskStage* moho::WIN_GetBeforeWaitStage()
{
  // 0x011043B4
  static CTaskStage sBeforeWaitStage{};
  return &sBeforeWaitStage;
}

moho::CWaitHandleSet* moho::WIN_GetWaitHandleSet()
{
  // 0x011043E0
  static CWaitHandleSet sWaitHandleSet{};
  return &sWaitHandleSet;
}

msvc8::string moho::SPlatSymbolInfo::FormatResolvedLine() const
{
  return gpg::STR_Printf(
    "%s + %u bytes (%s(%u) + %u bytes)",
    symbol.c_str(),
    symDis,
    filename.c_str(),
    lineNum,
    lineDis
  );
}

/**
 * Address: 0x004F1FC0
 *
 * What it does:
 * Requests that the main wait loop wake no later than `milliseconds` from now.
 */
void moho::WIN_SetWakeupTimer(const float milliseconds)
{
  if (milliseconds < wakeupTimerDur) {
    wakeupTimerDur = milliseconds;
  }
}

void moho::WIN_SetMainWindow(wxWindowBase* const mainWindow)
{
  sMainWindow = mainWindow;
}

/**
 * Address: 0x004F20B0 (FUN_004F20B0)
 *
 * IWinApp *
 *
 * What it does:
 * Drives app bootstrap, frame pumping, and shutdown around the IWinApp interface.
 */
void moho::WIN_AppExecute(IWinApp* const app)
{
  if (app == nullptr) {
    return;
  }

  sSupComApp = app;
  const HMODULE module = ::GetModuleHandleW(nullptr);
  sWindowHook = ::SetWindowsHookExW(WH_KEYBOARD_LL, &WindowHook, module, 0);

  HMODULE selfModule = nullptr;
  ::GetModuleHandleExW(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    reinterpret_cast<LPCWSTR>(&WindowHook),
    &selfModule
  );
  wxEntry(selfModule, nullptr, nullptr, 0, false);

  if (!HasCorrectPlatform()) {
    WIN_OkBox(
      "Old OS Version",
      "This application requires Windows NT, 2000, XP, or newer, to operate.\n"
      "Windows 95, 98, and ME are not supported."
    );
    sSupComApp = nullptr;
    return;
  }

  THREAD_SetAffinity(true);
  ::InitCommonControls();
  ::CoInitialize(nullptr);
  PLAT_Init();
  PLAT_CatchStructuredExceptions();
  wakeupTimer.Reset();
  wakeupTimerDur = kInfiniteWakeupMs;

  if (!app->Init()) {
    ::TerminateProcess(::GetCurrentProcess(), 1u);
  }

  moho::WxAppRuntime::EnableLoopFlags();

  _controlfp(0x20000, 0x30000);

  bool success = true;
  bool acceptNewEvent = true;
  for (;;) {
    while (acceptNewEvent) {
      ::SleepEx(0, TRUE);
      WIN_GetBeforeEventsStage()->UserFrame();
      acceptNewEvent = false;
    }

    if (moho::WxAppRuntime::Pending()) {
      moho::WxAppRuntime::Dispatch();
      success = true;
      continue;
    }

    if (moho::WxAppRuntime::IsAvailable() && success) {
      success = moho::WxAppRuntime::ProcessIdle();
      continue;
    }

    if (!moho::WxAppRuntime::KeepGoing()) {
      break;
    }

    app->Main();
    success = true;
    acceptNewEvent = true;

    WIN_GetBeforeWaitStage()->UserFrame();

    const DWORD timeoutMs = ComputeWaitTimeoutMs();
    wakeupTimerDur = kInfiniteWakeupMs;
    WIN_GetWaitHandleSet()->MsgWaitEx(timeoutMs);
  }

  app->Destroy();
  WINX_Exit();
  PLAT_Exit();
  WxPumpToIdleAndExit();

  if (sWindowHook != nullptr) {
    ::UnhookWindowsHookEx(sWindowHook);
    sWindowHook = nullptr;
  }

  RES_Exit();
  sSupComApp = nullptr;
}

/**
 * Address: 0x004A2150 (FUN_004A2150)
 *
 * What it does:
 * Initializes symbol-handler state and process-wide platform mutex.
 * Uses symbol options:
 * `SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_LOAD_LINES |
 *  SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME` (`0x216`).
 */
void moho::PLAT_Init()
{
  boost::mutex::scoped_lock lock(GetSymHandlerMutex());

  if (sMohoEngineMuexInitialized) {
    return;
  }

  sSymbolHandlerInitialized = false;
  (void)::SymSetOptions(kPlatformSymbolHandlerOptions);
  if (::SymInitialize(::GetCurrentProcess(), nullptr, TRUE) != FALSE) {
    sSymbolHandlerInitialized = true;
  }

  (void)::CreateMutexA(nullptr, FALSE, "GPG_MohoEngine_Mutex");
  sMohoEngineMuexInitialized = true;
}

/**
 * Address: 0x004A2D30 (FUN_004A2D30)
 *
 * What it does:
 * Installs the engine top-level SEH filter.
 */
void moho::PLAT_CatchStructuredExceptions()
{
  (void)::SetUnhandledExceptionFilter(&TopLevelExceptionFilter);
}

/**
 * Address: 0x004A2210 (FUN_004A2210)
 *
 * What it does:
 * Tears down symbol-handler state initialized by `PLAT_Init`.
 */
void moho::PLAT_Exit()
{
  boost::mutex::scoped_lock lock(GetSymHandlerMutex());

  if (!sMohoEngineMuexInitialized) {
    return;
  }

  if (sSymbolHandlerInitialized) {
    (void)::SymCleanup(::GetCurrentProcess());
    sSymbolHandlerInitialized = false;
  }

  sMohoEngineMuexInitialized = false;
}

/**
 * Address: 0x004A0FC0 (FUN_004A0FC0, ?PLAT_InitErrorReportOutputDir@Moho@@YAXPB_W@Z)
 *
 * What it does:
 * Sets the root path used by crash-report attachments and ensures the path
 * ends with one trailing `\\`.
 */
void moho::PLAT_InitErrorReportOutputDir(const wchar_t* const outputDir)
{
  sCrashReportAttachments.SetOutputDir(outputDir);
}

/**
 * Address: 0x004A0ED0 (FUN_004A0ED0)
 * Mangled: ?PLAT_RegisterFileForErrorReport@Moho@@YAXPB_W@Z
 *
 * What it does:
 * Adds a crash-report attachment path if it is non-empty and not already
 * present in the report file list.
 */
void moho::PLAT_RegisterFileForErrorReport(const wchar_t* const file)
{
  sCrashReportAttachments.RegisterFile(file);
}

/**
 * Address: 0x004A1230 (FUN_004A1230)
 * Mangled: ?PLAT_CreateGameLogForReport@Moho@@YAXXZ
 *
 * What it does:
 * Writes current in-memory log history to `<report_dir><app_short_name>.sclog`
 * and registers the generated file as a crash-report attachment.
 */
void moho::PLAT_CreateGameLogForReport()
{
  const msvc8::string recentLogLines = gpg::GetRecentLogLines();
  const char* const appShortName = (sSupComApp != nullptr && !sSupComApp->shortName.empty())
                                     ? sSupComApp->shortName.c_str()
                                     : "SupCom";
  const std::wstring logFilePrefix =
    BuildWideStringPlusWideString(GetErrorReportOutputDirSnapshot(), gpg::STR_Utf8ToWide(appShortName));
  const std::wstring logFilePath = BuildWideStringPlusWideLiteral(logFilePrefix, L".sclog");

  HANDLE logFileHandle =
    ::CreateFileW(logFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (logFileHandle == INVALID_HANDLE_VALUE) {
    const msvc8::string errorText = WIN_GetLastError();
    const msvc8::string utf8Path = gpg::STR_WideToUtf8(logFilePath.c_str());
    gpg::Warnf(
      "PLAT_CreateGameLogForReport(\"%s\") log file creation failed: %s",
      utf8Path.c_str(),
      errorText.c_str()
    );
    return;
  }

  DWORD bytesWritten = 0;
  if (::WriteFile(
        logFileHandle,
        recentLogLines.c_str(),
        static_cast<DWORD>(recentLogLines.size()),
        &bytesWritten,
        nullptr
      ) == FALSE) {
    const msvc8::string errorText = WIN_GetLastError();
    const msvc8::string utf8Path = gpg::STR_WideToUtf8(logFilePath.c_str());
    gpg::Warnf(
      "PLAT_CreateGameLogForReport(\"%s\") log file writing failed: %s",
      utf8Path.c_str(),
      errorText.c_str()
    );
    (void)::CloseHandle(logFileHandle);
    return;
  }

  PLAT_RegisterFileForErrorReport(logFilePath.c_str());
  (void)::CloseHandle(logFileHandle);
}

/**
 * Address: 0x004A22B0 (FUN_004A22B0)
 * Mangled: ?PLAT_GetCallStack@Moho@@YAIPAXIPAI@Z
 *
 * What it does:
 * Captures up to `maxFrames` return addresses from the supplied CPU context
 * (or current thread context when null).
 */
std::uint32_t moho::PLAT_GetCallStack(
  void* const contextRecord, const std::uint32_t maxFrames, std::uint32_t* const outFrames
)
{
  if (outFrames == nullptr || maxFrames == 0) {
    return 0;
  }

  boost::mutex::scoped_lock lock(GetSymHandlerMutex());
  if (!sSymbolHandlerInitialized) {
    return 0;
  }

#if defined(_M_IX86)
  STACKFRAME stackFrame{};
  stackFrame.AddrFrame.Mode = AddrModeFlat;
  stackFrame.AddrPC.Mode = AddrModeFlat;
  stackFrame.AddrStack.Mode = AddrModeFlat;

  DWORD instructionPointer = 0;
  DWORD stackPointer = 0;
  DWORD framePointer = 0;
  if (contextRecord != nullptr) {
    const auto* const activeContext = static_cast<const CONTEXT*>(contextRecord);
    instructionPointer = activeContext->Eip;
    stackPointer = activeContext->Esp;
    framePointer = activeContext->Ebp;
  } else {
    StackWalkSeedRegisters stackWalkSeed{};
    CaptureStackWalkSeedRegisters(&stackWalkSeed);
    instructionPointer = stackWalkSeed.programCounter;
    stackPointer = stackWalkSeed.stackPointer;
    framePointer = stackWalkSeed.framePointer;
  }

  stackFrame.AddrPC.Offset = instructionPointer;
  stackFrame.AddrStack.Offset = stackPointer;
  stackFrame.AddrFrame.Offset = framePointer;

  std::uint32_t frameCount = 0;
  while (frameCount < maxFrames) {
    if (::StackWalk(
          IMAGE_FILE_MACHINE_I386,
          ::GetCurrentProcess(),
          ::GetCurrentThread(),
          &stackFrame,
          nullptr,
          nullptr,
          ::SymFunctionTableAccess,
          ::SymGetModuleBase,
          nullptr
        ) == FALSE) {
      break;
    }

    DWORD frameAddress = stackFrame.AddrPC.Offset;
    if (frameAddress == 0) {
      continue;
    }

    if (frameCount != 0) {
      frameAddress -= 5;
      stackFrame.AddrPC.Offset -= 5;
    }

    outFrames[frameCount] = frameAddress;
    ++frameCount;
  }

  return frameCount;
#else
  (void)contextRecord;
  (void)maxFrames;
  (void)outFrames;
  return 0;
#endif
}

/**
 * Address: 0x004A2440 (FUN_004A2440)
 * Mangled: ?PLAT_GetSymbolInfo@Moho@@YA_NIAAUSPlatSymbolInfo@1@@Z
 *
 * What it does:
 * Resolves one callstack address into symbol/file/line metadata when available.
 */
bool moho::PLAT_GetSymbolInfo(const std::uint32_t address, SPlatSymbolInfo* const outInfo)
{
  if (outInfo == nullptr) {
    return false;
  }

  boost::mutex::scoped_lock lock(GetSymHandlerMutex());
  if (!sSymbolHandlerInitialized) {
    return false;
  }

  struct SymbolStorage
  {
    IMAGEHLP_SYMBOL symbol{};
    char nameBuffer[255]{};
  };

  SymbolStorage symbolStorage{};
  symbolStorage.symbol.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
  symbolStorage.symbol.MaxNameLength = 233;

  DWORD symbolDisplacement = 0;
  if (::SymGetSymFromAddr(::GetCurrentProcess(), address, &symbolDisplacement, &symbolStorage.symbol) == FALSE) {
    return false;
  }

  outInfo->addr = address;
  outInfo->symbol.assign_owned(symbolStorage.symbol.Name);
  outInfo->symDis = symbolDisplacement;

  IMAGEHLP_LINE lineInfo{};
  lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE);
  DWORD lineDisplacement = 0;
  if (::SymGetLineFromAddr(::GetCurrentProcess(), address, &lineDisplacement, &lineInfo) != FALSE) {
    outInfo->filename.assign_owned(lineInfo.FileName);
    outInfo->lineNum = lineInfo.LineNumber;
    outInfo->lineDis = lineDisplacement;
  } else {
    outInfo->filename.assign_owned("(Unknown)");
    outInfo->lineNum = 0;
    outInfo->lineDis = 0;
  }

  return true;
}

/**
 * Address: 0x004A26E0 (FUN_004A26E0)
 * Mangled:
 * ?PLAT_FormatCallstack@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@HHPBI@Z
 *
 * What it does:
 * Formats callstack entries from `[firstFrame, endFrame)` into text lines.
 */
msvc8::string moho::PLAT_FormatCallstack(
  std::int32_t firstFrame, const std::int32_t endFrame, const std::uint32_t* const frames
)
{
  msvc8::string formatted;
  formatted.assign_owned("");
  if (frames == nullptr || firstFrame >= endFrame) {
    return formatted;
  }
  if (firstFrame < 0) {
    firstFrame = 0;
  }

  std::string assembled;
  for (std::int32_t frameIndex = firstFrame; frameIndex < endFrame; ++frameIndex) {
    SPlatSymbolInfo symbolInfo{};
    if (PLAT_GetSymbolInfo(frames[frameIndex], &symbolInfo)) {
      assembled.append("\t");
      assembled.append(symbolInfo.FormatResolvedLine().c_str());
      assembled.append("\r\n");
    } else {
      const msvc8::string line = gpg::STR_Printf("\tUnknown symbol (address 0x%08x)\r\n", frames[frameIndex]);
      assembled.append(line.c_str());
    }
  }

  formatted.assign_owned(assembled);
  return formatted;
}

/**
 * Address: 0x004A25D0 (FUN_004A25D0)
 * Mangled:
 * ?PLAT_UnDecorateSymbolName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBD_N@Z
 *
 * What it does:
 * Converts one decorated symbol into undecorated text under the shared
 * symbol-handler mutex, with optional underscore stripping.
 */
msvc8::string moho::PLAT_UnDecorateSymbolName(const char* const name, const bool stripLeadingUnderscore)
{
  boost::mutex::scoped_lock lock(GetSymHandlerMutex());

  msvc8::string result;
  if (name == nullptr) {
    result.assign_owned("");
    return result;
  }

  CHAR outputString[1024]{};
  const DWORD flags = stripLeadingUnderscore ? 0x1000u : 0u;
  if (::UnDecorateSymbolName(name, outputString, 0x3FFu, flags) != 0) {
    result.assign_owned(outputString);
  } else {
    result.assign_owned(name);
  }
  return result;
}

/**
 * Address: 0x004A1F10 (FUN_004A1F10)
 *
 * What it does:
 * Writes one registry value at `keyPath` using raw byte payload and explicit
 * registry value type.
 */
bool moho::PLAT_SetRegistryValue(
  const char* const keyPath,
  const std::uint8_t* const data,
  const std::uint32_t dataSize,
  const std::uint32_t valueType
)
{
  if (keyPath == nullptr) {
    return false;
  }

  LegacyByteVectorStorageView keyBuffer{};
  (void)ResetLegacyByteVectorStorage(&keyBuffer);
  ResizeLegacyByteVectorStorageWithZeroFill(&keyBuffer, std::strlen(keyPath) + 1U);

  char* const mutableKeyPath = reinterpret_cast<char*>(keyBuffer.first);
  std::strcpy(mutableKeyPath, keyPath);
  const ParsedRegistryPathView parsedPath = ParseRegistryPathInPlace(mutableKeyPath);

  HKEY openedKey = nullptr;
  if (::RegCreateKeyExA(
        parsedPath.rootKey,
        parsedPath.subKey,
        0,
        nullptr,
        0,
        0xF003Fu,
        nullptr,
        &openedKey,
        nullptr
      ) != ERROR_SUCCESS) {
    gpg::Logf("PLAT_SetRegistryValue: Unable to create registry key \"%s\"", keyPath);
    DestroyLegacyByteVectorStorage(&keyBuffer);
    return false;
  }

  if (::RegSetValueExA(
        openedKey,
        parsedPath.valueName,
        0,
        valueType,
        reinterpret_cast<const BYTE*>(data),
        dataSize
      ) != ERROR_SUCCESS) {
    (void)::RegCloseKey(openedKey);
    gpg::Logf("PLAT_SetRegistryValue: Unable to write registry key \"%s\"", keyPath);
    DestroyLegacyByteVectorStorage(&keyBuffer);
    return false;
  }

  (void)::RegCloseKey(openedKey);
  DestroyLegacyByteVectorStorage(&keyBuffer);
  return true;
}

/**
 * Address: 0x004A2F60 (FUN_004A2F60)
 *
 * What it does:
 * Writes one 32-bit DWORD registry value.
 */
bool moho::PLAT_SetRegistryValueDword(const char* const keyPath, const std::uint32_t value)
{
  return PLAT_SetRegistryValue(
    keyPath,
    reinterpret_cast<const std::uint8_t*>(&value),
    sizeof(value),
    REG_DWORD
  );
}

/**
 * Address: 0x004A2F80 (FUN_004A2F80)
 *
 * What it does:
 * Writes one zero-terminated string registry value; null input writes an
 * empty string payload.
 */
bool moho::PLAT_SetRegistryValueString(const char* const value, const char* const keyPath)
{
  const char* const safeValue = (value != nullptr) ? value : "";
  return PLAT_SetRegistryValue(
    keyPath,
    reinterpret_cast<const std::uint8_t*>(safeValue),
    static_cast<std::uint32_t>(std::strlen(safeValue) + 1U),
    REG_SZ
  );
}

/**
 * Address: 0x004A2D40 (FUN_004A2D40)
 *
 * What it does:
 * Reads one registry value payload into `outData` and returns byte count read.
 * Binary behavior clamps read size to 0x100 bytes.
 */
std::uint32_t moho::PLAT_GetRegistryValue(
  const char* const keyPath, void* const outData, const std::uint32_t maxDataBytes
)
{
  (void)maxDataBytes;
  if (keyPath == nullptr || outData == nullptr) {
    return 0;
  }

  LegacyByteVectorStorageView keyBuffer{};
  (void)ResetLegacyByteVectorStorage(&keyBuffer);
  ResizeLegacyByteVectorStorageWithZeroFill(&keyBuffer, std::strlen(keyPath) + 1U);

  char* const mutableKeyPath = reinterpret_cast<char*>(keyBuffer.first);
  std::strcpy(mutableKeyPath, keyPath);
  const ParsedRegistryPathView parsedPath = ParseRegistryPathInPlace(mutableKeyPath);

  HKEY openedKey = nullptr;
  if (::RegOpenKeyExA(parsedPath.rootKey, parsedPath.subKey, 0, 0x20019u, &openedKey) != ERROR_SUCCESS) {
    gpg::Logf("PLAT_GetRegistryValue: Unable to open registry key \"%s\"", keyPath);
    DestroyLegacyByteVectorStorage(&keyBuffer);
    return 0;
  }

  DWORD bytesRead = 0x100u;
  if (::RegQueryValueExA(
        openedKey,
        parsedPath.valueName,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(outData),
        &bytesRead
      ) != ERROR_SUCCESS) {
    (void)::RegCloseKey(openedKey);
    gpg::Logf("PLAT_GetRegistryValue: Unable to read registry key \"%s\"", keyPath);
    DestroyLegacyByteVectorStorage(&keyBuffer);
    return 0;
  }

  (void)::RegCloseKey(openedKey);
  DestroyLegacyByteVectorStorage(&keyBuffer);
  return bytesRead;
}

/**
 * Address: 0x004F2A00 (FUN_004F2A00)
 * Mangled:
 * ?WIN_GetLastError@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
 *
 * What it does:
 * Converts current `GetLastError()` value into readable UTF-8 text.
 */
msvc8::string moho::WIN_GetLastError()
{
  const DWORD errorCode = ::GetLastError();

  LPWSTR messageBuffer = nullptr;
  const DWORD formatResult = ::FormatMessageW(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
    nullptr,
    errorCode,
    0x400u,
    reinterpret_cast<LPWSTR>(&messageBuffer),
    0,
    nullptr
  );

  if (formatResult == 0 || messageBuffer == nullptr) {
    return gpg::STR_Printf("Unknown error 0x%08x", errorCode);
  }

  const msvc8::string message = gpg::STR_WideToUtf8(messageBuffer);
  (void)::LocalFree(messageBuffer);
  return message;
}

/**
 * Address: 0x004F1190 (FUN_004F1190)
 * Mangled: ?WIN_ShowCrashDialog@Moho@@YAXPBD0PAU_EXCEPTION_POINTERS@@H@Z
 *
 * What it does:
 * Builds crash-details text (program, args, callstack, recent log lines) and
 * displays the crash dialog UI/fallback prompt.
 */
void moho::WIN_ShowCrashDialog(
  std::int32_t skipCallstackFrames,
  _EXCEPTION_POINTERS* const exceptionInfo,
  const gpg::StrArg caption,
  const gpg::StrArg summaryText
)
{
  std::ostringstream details;
  details << (summaryText != nullptr ? summaryText : "") << "\n\n";

  WCHAR programFileName[512]{};
  if (::GetModuleFileNameW(
        nullptr,
        programFileName,
        static_cast<DWORD>(sizeof(programFileName) / sizeof(programFileName[0]))
      ) != 0) {
    const msvc8::string programPath = gpg::STR_WideToUtf8(programFileName);
    details << "Program : " << programPath.c_str() << "\n";
  } else {
    details << "Program : <unknown>\n";
  }

  const msvc8::string args = CFG_GetArgs();
  details << "Cmd line arguments : " << args.c_str() << "\n\n";
  details << "Callstack:\n";

  void* contextRecord = nullptr;
  if (exceptionInfo != nullptr) {
    contextRecord = exceptionInfo->ContextRecord;
  } else {
    skipCallstackFrames += 2;
  }

  std::uint32_t stackFrames[64]{};
  const std::uint32_t frameCount = PLAT_GetCallStack(contextRecord, 64, stackFrames);
  const std::uint32_t firstFrame =
    skipCallstackFrames > 0 ? static_cast<std::uint32_t>(skipCallstackFrames) : static_cast<std::uint32_t>(0);
  if (frameCount <= firstFrame) {
    details << "    unavailable.\n";
  } else {
    const msvc8::string callstackText =
      PLAT_FormatCallstack(static_cast<std::int32_t>(firstFrame), static_cast<std::int32_t>(frameCount), stackFrames);
    details << callstackText.c_str();
  }

  details << "\n";
  details << "Last 100 lines of log...\n\n";
  const msvc8::string recentLogLines = gpg::GetRecentLogLines();
  details << recentLogLines.c_str();

  const std::string bodyText = details.str();
  CrashDialogInitData dialogInit{
    caption != nullptr ? caption : "Crash",
    bodyText.c_str(),
  };

  HMODULE module = nullptr;
  (void)::GetModuleHandleExW(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    reinterpret_cast<LPCWSTR>(&CrashDialogProc),
    &module
  );

  if (module == nullptr || ::DialogBoxParamW(
                            module,
                            MAKEINTRESOURCEW(kCrashDialogTemplateId),
                            nullptr,
                            &CrashDialogProc,
                            reinterpret_cast<LPARAM>(&dialogInit)
                          ) == -1) {
    const msvc8::string dialogError = WIN_GetLastError();
    gpg::Logf("DialogBoxParam failed: %s", dialogError.c_str());
    WIN_OkBox(dialogInit.caption, dialogInit.body);
  }
}

/**
 * Address: 0x004F2800 (FUN_004F2800, ?WIN_OkBox@Moho@@YAXVStrArg@gpg@@0@Z)
 *
 * What it does:
 * Displays a UTF-8 message box using the active engine main window as owner
 * when available.
 */
void moho::WIN_OkBox(const gpg::StrArg caption, const gpg::StrArg text)
{
  const HWND ownerWindow = sMainWindow != nullptr
                             ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(sMainWindow->GetHandle()))
                             : nullptr;
  const std::wstring wideCaption = gpg::STR_Utf8ToWide(caption);
  const std::wstring wideText = gpg::STR_Utf8ToWide(text);
  (void)::MessageBoxW(ownerWindow, wideText.c_str(), wideCaption.c_str(), 0x40000u);
}

/**
 * Address: 0x004F3A60 (FUN_004F3A60, ?WINX_Exit@Moho@@YAXXZ)
 *
 * What it does:
 * Destroys all managed dialog/frame windows and unlinks their registry slots.
 */
void moho::WINX_Exit()
{
  WWinManagedDialog::DestroyManagedOwners(managedWindows);
  WWinManagedFrame::DestroyManagedOwners(managedFrames);
}

/**
 * Address: 0x004F3CE0 (FUN_004F3CE0)
 * Mangled: ?WINX_InitSplash@Moho@@YAXVStrArg@gpg@@@Z
 *
 * gpg::StrArg
 *
 * What it does:
 * Initializes splash PNG handler state, clears any existing splash object,
 * then loads and creates a splash-screen runtime when the file is available.
 */
void moho::WINX_InitSplash(const gpg::StrArg filename)
{
  (void)WX_EnsureSplashPngHandler();
  DestroyActiveSplashScreen();

  if (filename == nullptr || filename[0] == '\0') {
    return;
  }

  wxSize splashSize{1024, 768};
  RECT desktopRect{};
  if (::GetWindowRect(nullptr, &desktopRect) != 0) {
    std::int32_t width = desktopRect.right - desktopRect.left;
    if (width >= 1600) {
      width = 1600;
    }
    splashSize.x = width;

    std::int32_t height = desktopRect.top - desktopRect.bottom;
    if (height < 1200) {
      height = 1200;
    }
    splashSize.y = height;
  }

  sSplashScreenPtr = WX_CreateSplashScreen(filename, splashSize);
}

/**
 * Address: 0x004F67E0 (FUN_004F67E0, ?WINX_PrecreateLogWindow@Moho@@YAXXZ)
 *
 * What it does:
 * Lazily allocates the global log window object and stores it under the
 * shared log-window target lock.
 */
void moho::WINX_PrecreateLogWindow()
{
  if (sLogWindowTarget.dialog != nullptr) {
    return;
  }

  moho::WWinLogWindow* const createdLogWindow = CreateLogWindowRuntime();
  boost::mutex::scoped_lock lock(sLogWindowTarget.lock);
  sLogWindowTarget.dialog = createdLogWindow;
}

/**
 * Address: 0x004F3F30 (FUN_004F3F30, ?WINX_ExitSplash@Moho@@YAXXZ)
 *
 * What it does:
 * Deletes the active splash-screen object through its deleting-dtor slot and
 * clears the global splash pointer.
 */
void moho::WINX_ExitSplash()
{
  DestroyActiveSplashScreen();
}

#pragma warning(pop)
