// Engine addition (dedicated-server plan WPL.4, WPL.5, WPR.11): the Windows
// platform services the simulation uses - symbol-handler init, crash-report
// attachment paths, call stacks and their formatting, the last Win32 error as
// text, and the OK message box - moved unchanged out of moho/app/WinApp.cpp,
// which keeps the wx application shell, the crash dialog and the structured
// exception filter. A POSIX build implements the same functions elsewhere.

#include "moho/app/WinApp.h"
#include "platform/Platform.h"
#include <DbgHelp.h>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>
#include "boost/mutex.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Vector.h"

// Engine addition: helpers shared with the file these functions came from.
namespace
{
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

  std::wstring sLegacyErrorReportOutputDir{};

  constexpr wchar_t kPathSeparator = L'\\';

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

  boost::mutex* sMutexSymHandler = nullptr;

  /**
   * Address: 0x004A1E20 (FUN_004A1E20, Moho::InitSymHandlerMutex)
   * Address: 0x00BF02B0 (FUN_00BF02B0, atexit destructor of InitSymHandlerMutex's static mutex)
   *
   * What it does:
   * Constructs the process-global symbol-handler mutex once and publishes it
   * through `sMutexSymHandler`.
   */
  void InitSymHandlerMutex()
  {
    static boost::mutex sMutex;
    sMutexSymHandler = &sMutex;
  }
  std::once_flag sSymHandlerMutexInitOnce;

  [[nodiscard]]
  boost::mutex& GetSymHandlerMutex()
  {
    std::call_once(sSymHandlerMutexInitOnce, &InitSymHandlerMutex);
    return *sMutexSymHandler;
  }
  constexpr DWORD kPlatformSymbolHandlerOptions =
    SYMOPT_FAIL_CRITICAL_ERRORS | // suppress critical-error UI while probing symbols.
    SYMOPT_LOAD_LINES | // include source line records for resolved addresses.
    SYMOPT_DEFERRED_LOADS | // lazily load module symbols as needed.
    SYMOPT_UNDNAME; // undecorate C++ names in symbol output.
  bool sMohoEngineMuexInitialized = false;
  bool sSymbolHandlerInitialized = false;
} // namespace


// Engine addition (dedicated-server plan WPL.4), declared in WinApp.h.
moho::OkBoxOwnerWindowHook moho::sOkBoxOwnerWindow = nullptr;
moho::AppExitMainLoopHook moho::sAppExitMainLoop = nullptr;
moho::AppPumpEventsHook moho::sAppPumpEvents = nullptr;

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
 * Address: 0x004A22B0 (FUN_004A22B0)
 * Mangled: ?PLAT_GetCallStack@Moho@@YAIPAXIPAI@Z
 *
 * What it does:
 * Captures up to `maxFrames` return addresses from the supplied CPU context
 * (or current thread context when null).
 */
std::uint32_t moho::PLAT_GetCallStack(
  void* const contextRecord, const std::uint32_t maxFrames, std::uintptr_t* const outFrames
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
#elif defined(_M_X64)
  CONTEXT context{};
  if (contextRecord != nullptr) {
    context = *static_cast<const CONTEXT*>(contextRecord);
  } else {
    ::RtlCaptureContext(&context);
  }

  STACKFRAME64 stackFrame{};
  stackFrame.AddrPC.Mode = AddrModeFlat;
  stackFrame.AddrPC.Offset = context.Rip;
  stackFrame.AddrStack.Mode = AddrModeFlat;
  stackFrame.AddrStack.Offset = context.Rsp;
  stackFrame.AddrFrame.Mode = AddrModeFlat;
  stackFrame.AddrFrame.Offset = context.Rbp;

  std::uint32_t frameCount = 0;
  while (frameCount < maxFrames) {
    if (::StackWalk64(
          IMAGE_FILE_MACHINE_AMD64,
          ::GetCurrentProcess(),
          ::GetCurrentThread(),
          &stackFrame,
          &context,
          nullptr,
          ::SymFunctionTableAccess64,
          ::SymGetModuleBase64,
          nullptr
        ) == FALSE) {
      break;
    }

    DWORD64 frameAddress = stackFrame.AddrPC.Offset;
    if (frameAddress == 0) {
      break;
    }

    // A return address points past its call; step back into the call itself.
    if (frameCount != 0) {
      frameAddress -= 1;
    }

    outFrames[frameCount] = static_cast<std::uintptr_t>(frameAddress);
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
bool moho::PLAT_GetSymbolInfo(const std::uintptr_t address, SPlatSymbolInfo* const outInfo)
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

  // DWORD on x86; dbghelp maps SymGetSymFromAddr to the 64-bit form on x64.
  DWORD_PTR symbolDisplacement = 0;
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

msvc8::string moho::SPlatSymbolInfo::FormatResolvedLine() const
{
  return gpg::STR_Printf(
    "%s + %zu bytes (%s(%u) + %u bytes)",
    symbol.c_str(),
    symDis,
    filename.c_str(),
    lineNum,
    lineDis
  );
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
  std::int32_t firstFrame, const std::int32_t endFrame, const std::uintptr_t* const frames
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
      const msvc8::string line = gpg::STR_Printf("\tUnknown symbol (address %p)\r\n", reinterpret_cast<const void*>(frames[frameIndex]));
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
 * Address: 0x004F2800 (FUN_004F2800, ?WIN_OkBox@Moho@@YAXVStrArg@gpg@@0@Z)
 *
 * What it does:
 * Displays a UTF-8 message box using the active engine main window as owner
 * when available.
 */
void moho::WIN_OkBox(const gpg::StrArg caption, const gpg::StrArg text)
{
  // Engine addition (dedicated-server plan WPL.4): the owner is the client's
  // main window (`sMainWindow`, wx), asked through sOkBoxOwnerWindow.
  const HWND ownerWindow = sOkBoxOwnerWindow != nullptr ? static_cast<HWND>(sOkBoxOwnerWindow()) : nullptr;
  const std::wstring wideCaption = gpg::STR_Utf8ToWide(caption);
  const std::wstring wideText = gpg::STR_Utf8ToWide(text);
  (void)::MessageBoxW(ownerWindow, wideText.c_str(), wideCaption.c_str(), 0x40000u);
}

/**
 * Engine addition (dedicated-server plan WPL.4), declared in WinApp.h.
 */
std::wstring moho::PLAT_GetErrorReportOutputDir()
{
  return sCrashReportAttachments.GetOutputDirSnapshot();
}
