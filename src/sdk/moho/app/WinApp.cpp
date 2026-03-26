#include "WinApp.h"

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
#include <type_traits>
#include <vector>

#include "platform/Platform.h"

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

  using BugSplatAttachmentCallbackFn = bool(__cdecl*)(std::uint32_t, void*, void*);
  void sub_BF0280();

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
      (void)std::atexit(&sub_BF0280);
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
      outputDir_.assign(outputDir != nullptr ? outputDir : L"");
      if (!outputDir_.empty() && outputDir_.back() != kPathSeparator) {
        outputDir_.push_back(kPathSeparator);
      }
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
      const std::wstring candidate(file);
      const auto existing = std::find(files_.begin(), files_.end(), candidate);
      if (existing == files_.end()) {
        files_.push_back(candidate);
      }
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
    std::wstring commandLine(kDxdiagCommandPrefix);
    commandLine.append(outputPath);
    return commandLine;
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

  DWORD ComputeWaitTimeoutMs()
  {
    const float remainingMs = wakeupTimerDur - ProbeWakeTimerMs();
    if (remainingMs < 0.0f) {
      return 0;
    }

    if (remainingMs > kMaxFiniteTimeoutMs) {
      return INFINITE;
    }

    return static_cast<DWORD>(std::lround(remainingMs));
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
   * Address: 0x00BF0280 (FUN_00BF0280, sub_BF0280)
   *
   * What it does:
   * Process-exit callback that tears down the process-global BugSplat sender.
   */
  void sub_BF0280()
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
  const std::wstring logFilePath =
    GetErrorReportOutputDirSnapshot() + gpg::STR_Utf8ToWide(appShortName) + L".sclog";

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
