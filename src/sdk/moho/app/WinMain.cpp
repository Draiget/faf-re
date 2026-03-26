#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <array>
#include <algorithm>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <shellapi.h>

#include "CScApp.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Error.hpp"
#include "WinApp.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  class AllocationLogSymbolAddressCache
  {
  private:
    struct SymbolAddressNode
    {
      SymbolAddressNode* next = nullptr;
      SymbolAddressNode* prev = nullptr;
      std::uint32_t address = 0;
    };
    static_assert(offsetof(SymbolAddressNode, next) == 0x00, "SymbolAddressNode::next offset must be 0x00");
    static_assert(offsetof(SymbolAddressNode, prev) == 0x04, "SymbolAddressNode::prev offset must be 0x04");
    static_assert(offsetof(SymbolAddressNode, address) == 0x08, "SymbolAddressNode::address offset must be 0x08");
    static_assert(sizeof(SymbolAddressNode) == 0x0C, "SymbolAddressNode size must be 0x0C");

    static constexpr std::uint32_t kInitialSymbolAddressMask = 0x3;
    static constexpr std::uint32_t kHashXorMask = 0xDEADBEEFu;
    static constexpr long kHashDivisor = 127773L;
    static constexpr long kHashMul = 16807L;
    static constexpr long kHashSub = 2836L;
    static constexpr long kHashModulus = 0x7FFFFFFFL;

    /**
     * Address: 0x008D5580 (FUN_008D5580, sub_8D5580)
     *
     * What it does:
     * Normalizes the bucket-head vector size used by the symbol-address cache.
     */
    static void NormalizeBucketVectorSize(
      std::vector<SymbolAddressNode*>& bucketHeads, const std::size_t size, SymbolAddressNode* const fillValue
    )
    {
      if (bucketHeads.size() < size) {
        bucketHeads.insert(bucketHeads.end(), size - bucketHeads.size(), fillValue);
      } else if (bucketHeads.size() > size) {
        bucketHeads.erase(bucketHeads.begin() + static_cast<std::ptrdiff_t>(size), bucketHeads.end());
      }
    }

    /**
     * Address: 0x008D6410 (FUN_008D6410, func_NewSymbolAddrNode)
     *
     * What it does:
     * Allocates and initializes one symbol-address cache node.
     */
    SymbolAddressNode* CreateSymbolAddressNode(
      SymbolAddressNode* const next, SymbolAddressNode* const prev, const std::uint32_t address
    )
    {
      auto node = std::make_unique<SymbolAddressNode>();
      node->next = next;
      node->prev = prev;
      node->address = address;
      SymbolAddressNode* const rawNode = node.get();
      nodes_.push_back(std::move(node));
      return rawNode;
    }

    [[nodiscard]]
    static std::uint32_t ComputeAddressHash(const std::uint32_t address)
    {
      const long mixed = static_cast<long>(address ^ kHashXorMask);
      const ldiv_t hashedParts = std::ldiv(mixed, kHashDivisor);
      long hashedValue = kHashMul * hashedParts.rem - kHashSub * hashedParts.quot;
      if (hashedValue < 0) {
        hashedValue += kHashModulus;
      }
      return static_cast<std::uint32_t>(hashedValue);
    }

    [[nodiscard]]
    std::uint32_t ResolveBucketIndex(const std::uint32_t address) const
    {
      return ComputeAddressHash(address) & symbolAddrMask_;
    }

    void EnsureInitialized()
    {
      if (!bucketHeads_.empty()) {
        return;
      }
      symbolAddrMask_ = kInitialSymbolAddressMask;
      NormalizeBucketVectorSize(bucketHeads_, static_cast<std::size_t>(symbolAddrMask_) + 1U, nullptr);
    }

    void Rehash(const std::uint32_t nextMask)
    {
      std::vector<SymbolAddressNode*> nextBucketHeads;
      NormalizeBucketVectorSize(nextBucketHeads, static_cast<std::size_t>(nextMask) + 1U, nullptr);

      for (const std::unique_ptr<SymbolAddressNode>& ownedNode : nodes_) {
        SymbolAddressNode* const node = ownedNode.get();
        node->next = nullptr;
        node->prev = nullptr;

        SymbolAddressNode*& bucketHead = nextBucketHeads[ComputeAddressHash(node->address) & nextMask];
        SymbolAddressNode* previous = nullptr;
        SymbolAddressNode* cursor = bucketHead;
        while (cursor != nullptr && cursor->address < node->address) {
          previous = cursor;
          cursor = cursor->next;
        }

        node->next = cursor;
        node->prev = previous;
        if (previous != nullptr) {
          previous->next = node;
        } else {
          bucketHead = node;
        }
        if (cursor != nullptr) {
          cursor->prev = node;
        }
      }

      bucketHeads_.swap(nextBucketHeads);
      symbolAddrMask_ = nextMask;
    }

    void EnsureCapacityForInsert()
    {
      const std::uint32_t bucketCount = static_cast<std::uint32_t>(bucketHeads_.size());
      if (bucketCount == 0) {
        return;
      }

      // Keep the same high-level growth policy as the recovered helper path:
      // grow when the cache exceeds 4 addresses per bucket on average.
      if (symbolAddrNodeCount_ > (bucketCount * 4U)) {
        const std::uint32_t nextMask = (symbolAddrMask_ * 2U) + 1U;
        Rehash(nextMask);
      }
    }

  public:
    void Clear()
    {
      bucketHeads_.clear();
      nodes_.clear();
      symbolAddrMask_ = 0;
      symbolAddrNodeCount_ = 0;
    }

    /**
     * Address: 0x008D4C10 (FUN_008D4C10, sub_8D4C10)
     *
     * What it does:
     * Looks up one frame address in the symbol cache and inserts it when absent.
     */
    [[nodiscard]]
    bool InsertIfMissing(const std::uint32_t address)
    {
      EnsureInitialized();
      EnsureCapacityForInsert();

      SymbolAddressNode*& bucketHead = bucketHeads_[ResolveBucketIndex(address)];
      SymbolAddressNode* previous = nullptr;
      SymbolAddressNode* cursor = bucketHead;
      while (cursor != nullptr && cursor->address < address) {
        previous = cursor;
        cursor = cursor->next;
      }

      if (cursor != nullptr && cursor->address == address) {
        return false;
      }

      SymbolAddressNode* const insertedNode = CreateSymbolAddressNode(cursor, previous, address);
      if (previous != nullptr) {
        previous->next = insertedNode;
      } else {
        bucketHead = insertedNode;
      }
      if (cursor != nullptr) {
        cursor->prev = insertedNode;
      }

      ++symbolAddrNodeCount_;
      return true;
    }

  private:
    std::uint32_t symbolAddrMask_ = 0;
    std::uint32_t symbolAddrNodeCount_ = 0;
    std::vector<SymbolAddressNode*> bucketHeads_{};
    std::vector<std::unique_ptr<SymbolAddressNode>> nodes_{};
  };

  class AllocationLogRuntime
  {
  public:
    [[nodiscard]]
    bool Open(const char* const path)
    {
      if (path == nullptr || path[0] == '\0' || file_ != nullptr) {
        return false;
      }

      std::FILE* file = nullptr;
      if (::fopen_s(&file, path, "wb") != 0 || file == nullptr) {
        return false;
      }

      LARGE_INTEGER frequency{};
      ::QueryPerformanceFrequency(&frequency);
      (void)::fwrite(&frequency, sizeof(frequency), 1, file);

      ::InitializeCriticalSection(&criticalSection_);
      criticalSectionInitialized_ = true;
      file_ = file;
      return true;
    }

    void Close()
    {
      if (file_ != nullptr) {
        (void)::fclose(file_);
        file_ = nullptr;
      }

      if (criticalSectionInitialized_) {
        ::DeleteCriticalSection(&criticalSection_);
        criticalSectionInitialized_ = false;
      }

      isFlushing_ = false;
      symbolAddressCache_.Clear();
    }

    void WriteEntry(const int isFreeing, const int size, const void* const pointerValue)
    {
      if (file_ == nullptr || !criticalSectionInitialized_) {
        return;
      }

      ::EnterCriticalSection(&criticalSection_);
      if (isFlushing_) {
        ::LeaveCriticalSection(&criticalSection_);
        return;
      }

      isFlushing_ = true;
      try {
        const std::uint32_t threadId = static_cast<std::uint32_t>(::GetCurrentThreadId());
        (void)::fwrite(&threadId, sizeof(threadId), 1, file_);

        LARGE_INTEGER performanceCounter{};
        ::QueryPerformanceCounter(&performanceCounter);
        (void)::fwrite(&performanceCounter, sizeof(performanceCounter), 1, file_);

        (void)::fwrite(&isFreeing, sizeof(isFreeing), 1, file_);
        (void)::fwrite(&size, sizeof(size), 1, file_);

        const std::uint32_t pointerWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pointerValue));
        (void)::fwrite(&pointerWord, sizeof(pointerWord), 1, file_);

        std::uint32_t frames[64]{};
        const std::uint32_t frameCount = moho::PLAT_GetCallStack(nullptr, 64, frames);
        for (std::uint32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
          const std::uint32_t frameAddress = frames[frameIndex];
          (void)::fwrite(&frameAddress, sizeof(frameAddress), 1, file_);
          WriteSymbolLineIfFirstSeen(frameAddress);
        }

        constexpr std::uint32_t kTerminator = 0;
        (void)::fwrite(&kTerminator, sizeof(kTerminator), 1, file_);
      } catch (...) {
        // Preserve binary intent: swallow logging-side failures.
      }

      isFlushing_ = false;
      ::LeaveCriticalSection(&criticalSection_);
    }

  private:
    void WriteSymbolLineIfFirstSeen(const std::uint32_t frameAddress)
    {
      if (!symbolAddressCache_.InsertIfMissing(frameAddress)) {
        return;
      }

      moho::SPlatSymbolInfo symbolInfo{};
      if (!moho::PLAT_GetSymbolInfo(frameAddress, &symbolInfo)) {
        return;
      }

      const msvc8::string symbolLine = symbolInfo.FormatResolvedLine();
      (void)::fwrite(symbolLine.c_str(), 1, symbolLine.size() + 1U, file_);
    }

    std::FILE* file_ = nullptr;
    CRITICAL_SECTION criticalSection_{};
    bool criticalSectionInitialized_ = false;
    bool isFlushing_ = false;
    AllocationLogSymbolAddressCache symbolAddressCache_{};
  };

  AllocationLogRuntime sAllocationLogRuntime{};
  STICKYKEYS sSavedStickyKeys{};
  TOGGLEKEYS sSavedToggleKeys{};
  FILTERKEYS sSavedFilterKeys{};

  /**
   * Address: 0x008D2140 (FUN_008D2140, func_CleanupAllocLoc)
   *
   * What it does:
   * Removes the allocation hook callback and closes alloc-log runtime state.
   */
  void func_CleanupAllocLoc()
  {
    gpg::SetMemHook(nullptr);
    sAllocationLogRuntime.Close();
  }

  /**
   * Address: 0x008D1E50 (FUN_008D1E50, func_MemHook)
   *
   * int isFreeing, int size, ...
   *
   * What it does:
   * Alloc-log sink callback: records thread/time/op/size/pointer, writes callstack
   * frame addresses, and appends symbol text once per unique frame address.
   */
  void func_MemHook(const int isFreeing, const int size, ...)
  {
    va_list ptrs;
    va_start(ptrs, size);
    const void* const pointerValue = va_arg(ptrs, const void*);
    va_end(ptrs);

    sAllocationLogRuntime.WriteEntry(isFreeing, size, pointerValue);
  }

  /**
   * Address: 0x008D2170 (FUN_008D2170)
   *
   * What it does:
   * Opens the `/alloclog` target file, writes the QPC frequency header,
   * sets the memory hook callback, and keeps the sink active for process life.
   */
  void InitializeAllocationLog(const char* const path)
  {
    if (!sAllocationLogRuntime.Open(path)) {
      return;
    }

    (void)::atexit(&func_CleanupAllocLoc);
    gpg::SetMemHook(&func_MemHook);
  }

  /**
   * Address: 0x004F1500 (FUN_004F1500)
   *
   * What it does:
   * Fatal die-handler callback registered by WinMain.
   */
  void FatalErrorDieHandler(const char* const message)
  {
    moho::WIN_ShowCrashDialog(2, nullptr, "Fatal Error", message != nullptr ? message : "");
  }

  /**
   * Address: 0x008D4320 (FUN_008D4320)
   *
   * What it does:
   * Applies startup accessibility tweaks or restores previously captured values.
   */
  void ConfigureAccessibilitySystemParameters(const bool restoreOriginalValues)
  {
    if (restoreOriginalValues) {
      (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &sSavedStickyKeys, 0);
      (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &sSavedToggleKeys, 0);
      (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &sSavedFilterKeys, 0);
      return;
    }

    STICKYKEYS nextStickyKeys = sSavedStickyKeys;
    if ((sSavedStickyKeys.dwFlags & SKF_STICKYKEYSON) == 0) {
      nextStickyKeys.dwFlags = sSavedStickyKeys.dwFlags & ~(SKF_HOTKEYACTIVE | SKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &nextStickyKeys, 0);
    }

    TOGGLEKEYS nextToggleKeys = sSavedToggleKeys;
    if ((sSavedToggleKeys.dwFlags & TKF_TOGGLEKEYSON) == 0) {
      nextToggleKeys.dwFlags = sSavedToggleKeys.dwFlags & ~(TKF_HOTKEYACTIVE | TKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &nextToggleKeys, 0);
    }

    FILTERKEYS nextFilterKeys = sSavedFilterKeys;
    if ((sSavedFilterKeys.dwFlags & FKF_FILTERKEYSON) == 0) {
      nextFilterKeys.dwFlags = sSavedFilterKeys.dwFlags & ~(FKF_HOTKEYACTIVE | FKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &nextFilterKeys, 0);
    }
  }

  /**
   * Address: 0x008D4410 (FUN_008D4410)
   *
   * What it does:
   * Launches Windows Media Center shell when `/mediacenter` is requested.
   */
  [[nodiscard]]
  bool TryLaunchMediaCenterIfRequested()
  {
    if (!moho::CFG_GetArgOption("/mediacenter", 0, nullptr)) {
      return false;
    }

    if (::GetSystemMetrics(SM_MEDIACENTER) == 0) {
      return false;
    }

    std::array<wchar_t, MAX_PATH> ehomePath{};
    const DWORD expandedLength = ::ExpandEnvironmentStringsW(
      L"%SystemRoot%\\ehome\\ehshell.exe", ehomePath.data(), static_cast<DWORD>(ehomePath.size())
    );
    if (expandedLength == 0 || expandedLength > ehomePath.size()) {
      return false;
    }

    if (::GetFileAttributesW(ehomePath.data()) == INVALID_FILE_ATTRIBUTES) {
      return false;
    }

    const HINSTANCE result = ::ShellExecuteW(nullptr, L"open", ehomePath.data(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<std::uintptr_t>(result) > 32U;
  }

} // namespace

/**
 * Address: 0x008D44A0 (FUN_008D44A0)
 * Mangled: _WinMain@16
 *
 * HINSTANCE,HINSTANCE,LPSTR,int
 *
 * What it does:
 * Applies startup command-line behavior, executes CScApp through WIN_AppExecute,
 * restores input system settings, and returns IWinApp::exitValue.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nShowCmd;

  gpg::time::Timer runTimer{};

  if (moho::CFG_GetArgOption("/waitfordebugger", 0, nullptr)) {
    ::MessageBoxW(nullptr, L"Attach the debugger and click OK.", L"Waiting", 0);
  }

  if (moho::CFG_GetArgOption("/aqtime", 0, nullptr)) {
    moho::APP_SetAqtimeInstrumentationMode(0);
  }

  msvc8::vector<msvc8::string> allocLogArgs;
  if (moho::CFG_GetArgOption("/alloclog", 1, &allocLogArgs) && !allocLogArgs.empty()) {
    InitializeAllocationLog(allocLogArgs[0].c_str());
  }

  gpg::SetDieHandler(&FatalErrorDieHandler);

  if (moho::CFG_GetArgOption("/singleproc", 0, nullptr)) {
    DWORD_PTR processAffinityMask = 0;
    DWORD_PTR systemAffinityMask = 0;
    (void)::GetProcessAffinityMask(::GetCurrentProcess(), &processAffinityMask, &systemAffinityMask);

    DWORD_PTR selectedMask = 1;
    if (processAffinityMask != 0) {
      unsigned long bitIndex = 0;
      const unsigned long maxBits = static_cast<unsigned long>(sizeof(DWORD_PTR) * 8U);
      while (bitIndex + 1 < maxBits && ((processAffinityMask >> bitIndex) & 1U) == 0U) {
        ++bitIndex;
      }
      selectedMask = static_cast<DWORD_PTR>(1ULL << bitIndex);
    }
    (void)::SetProcessAffinityMask(::GetCurrentProcess(), selectedMask);
  }

  if (moho::CFG_GetArgOption("/purgecache", 0, nullptr)) {
    moho::USER_PurgeAppCacheDir();
  }

  (void)::SystemParametersInfoW(SPI_GETSTICKYKEYS, sizeof(STICKYKEYS), &sSavedStickyKeys, 0);
  (void)::SystemParametersInfoW(SPI_GETTOGGLEKEYS, sizeof(TOGGLEKEYS), &sSavedToggleKeys, 0);
  (void)::SystemParametersInfoW(SPI_GETFILTERKEYS, sizeof(FILTERKEYS), &sSavedFilterKeys, 0);
  ConfigureAccessibilitySystemParameters(false);

  int exitCode = 0;
  try {
    {
      CScApp app;
      moho::WIN_AppExecute(&app);
      exitCode = app.exitValue;
      app.framerates.Reset();
    }

    const int totalSeconds = static_cast<int>(runTimer.ElapsedSeconds());
    gpg::Logf("Run time: %dh%02dm%02ds", totalSeconds / 3600, (totalSeconds % 3600) / 60, totalSeconds % 60);
  } catch (const gpg::gal::Error& galError) {
    std::ostringstream formatted;
    formatted << "file : " << galError.GetRuntimeMessage() << "(" << galError.GetRuntimeLine() << ")\n";
    formatted << "error: " << galError.what();
    gpg::Die("GAL Exception: %s", formatted.str().c_str());
  } catch (const std::exception& ex) {
    gpg::Die("Unhandled exception:\n\n%s", ex.what());
  }

  ConfigureAccessibilitySystemParameters(true);
  (void)TryLaunchMediaCenterIfRequested();
  return exitCode;
}
