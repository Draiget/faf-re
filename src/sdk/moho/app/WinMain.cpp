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

#include <crtdbg.h> // DIAGNOSTIC PROBE -- remove before committing
#include <csignal>  // DIAGNOSTIC PROBE -- remove before committing
#include <dbghelp.h> // DIAGNOSTIC PROBE -- remove before committing

#include "CScApp.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Error.hpp"
#include "WinApp.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
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
     * Address: 0x008D5D00 (FUN_008D5D00, sub_8D5D00)
     *
     * What it does:
     * Compacts one pointer-vector tail by shifting `[eraseEnd, finish)` onto
     * `eraseBegin` and updating vector logical end to the new tail.
     */
    [[nodiscard]] static SymbolAddressNode** CompactBucketVectorTail(
      std::vector<SymbolAddressNode*>& bucketHeads,
      SymbolAddressNode** const eraseBegin,
      SymbolAddressNode** const eraseEnd
    )
    {
      if (eraseBegin != eraseEnd) {
        SymbolAddressNode** writeCursor = eraseBegin;
        SymbolAddressNode** readCursor = eraseEnd;
        SymbolAddressNode** const finish =
          bucketHeads.data() + static_cast<std::ptrdiff_t>(bucketHeads.size());
        while (readCursor != finish) {
          *writeCursor = *readCursor;
          ++writeCursor;
          ++readCursor;
        }
        bucketHeads.resize(static_cast<std::size_t>(writeCursor - bucketHeads.data()));
      }
      return eraseBegin;
    }

    /**
     * Address: 0x008D5580 (FUN_008D5580, sub_8D5580)
     *
     * What it does:
     * Normalizes the bucket-head vector size used by the symbol-address cache.
     *
     * Address: 0x008D5D70 (FUN_008D5D70, sub_8D5D70) -- the compiler's
     * out-of-line `std::vector<SymbolAddressNode*>::_Insert_n` emission
     * triggered by this function's `bucketHeads.insert(bucketHeads.end(),
     * size - bucketHeads.size(), fillValue)` call below (grow branch):
     * `__thiscall(this, outIter, count, &value)`, handles the capacity-full
     * reallocate-and-copy path and the capacity-available shift-and-fill
     * path for a 4-byte pointer element. Genuine `std::` (not `msvc8::`)
     * STL internals for this file's own `std::vector` usage -- not
     * hand-modeled here since the recovered source already invokes the
     * real `std::vector::insert` API that the compiler lowers to this body.
     * Address: 0x008D72F0 (FUN_008D72F0, sub_8D72F0) -- this instantiation's
     * fill-n sub-step, called from `FUN_008D5D70`'s capacity-available
     * path: `for (; count; ++dst) { if (dst) *dst = value; --count; }
     * return count;`, a trivial per-element pointer broadcast matching
     * `_Uninit_fill_n`/`fill_n` for a 4-byte trivially-copyable element.
     */
    static void NormalizeBucketVectorSize(
      std::vector<SymbolAddressNode*>& bucketHeads, const std::size_t size, SymbolAddressNode* const fillValue
    )
    {
      if (bucketHeads.size() < size) {
        bucketHeads.insert(bucketHeads.end(), size - bucketHeads.size(), fillValue);
      } else if (bucketHeads.size() > size) {
        SymbolAddressNode** const eraseBegin =
          bucketHeads.data() + static_cast<std::ptrdiff_t>(size);
        SymbolAddressNode** const eraseEnd =
          bucketHeads.data() + static_cast<std::ptrdiff_t>(bucketHeads.size());
        (void)CompactBucketVectorTail(bucketHeads, eraseBegin, eraseEnd);
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
   * Address: 0x008D4260 (FUN_008D4260, sub_8D4260)
   *
   * void*
   *
   * What it does:
   * `SC_StartMemoryLog <filename>` console command. Forwards the filename
   * argument straight to `InitializeAllocationLog` above.
   *
   * Registrar: FUN_00BE9700 (`__xc_a` lane), data-xref
   * `dword_F5BEFC = offset sub_8D4260` is the callsite evidence.
   */
  void SC_StartMemoryLog(const msvc8::vector<msvc8::string>& args)
  {
    if (args.size() != 2u) {
      return;
    }

    const msvc8::string* const pathToken = moho::ConCommandArg(args, 1u);
    if (pathToken == nullptr) {
      return;
    }

    InitializeAllocationLog(pathToken->c_str());
  }

  /**
   * Address: 0x008D42B0 (FUN_008D42B0, sub_8D42B0)
   *
   * What it does:
   * `SC_StopMemoryLog` console command. `func_CleanupAllocLoc` above already
   * reproduces the binary's exact teardown sequence (clear the mem hook,
   * close the alloc-log runtime) - this command just runs it on demand
   * instead of only at process exit.
   *
   * Registrar: FUN_00BE9740 (`__xc_a` lane), data-xref
   * `dword_F5BF0C = offset sub_8D42B0` is the callsite evidence.
   */
  void SC_StopMemoryLog(const msvc8::vector<msvc8::string>& args)
  {
    (void)args;
    func_CleanupAllocLoc();
  }

  /// 0x00E4F23C, the `.data` initializer of `Moho::CConFunc_SC_StartMemoryLog`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCStartMemoryLogDescription = "Start up memory logging to filename";
  moho::CConFunc gCConFunc_SC_StartMemoryLog{};

  /// 0x00E4F274, the `.data` initializer of `Moho::CConFunc_SC_StopMemoryLog`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCStopMemoryLogDescription = "Stop memory logging";
  moho::CConFunc gCConFunc_SC_StopMemoryLog{};

  /**
   * Address: 0x00C08F10 (FUN_00C08F10, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_StartMemoryLog`.
   */
  void cleanup_CConFunc_SC_StartMemoryLog()
  {
    moho::CleanupStartupConCommand(gCConFunc_SC_StartMemoryLog);
  }

  void register_CConFunc_SC_StartMemoryLog()
  {
    gCConFunc_SC_StartMemoryLog.InitializeRecovered(
      kConsoleStartupSCStartMemoryLogDescription, "SC_StartMemoryLog", &SC_StartMemoryLog
    );
    (void)std::atexit(&cleanup_CConFunc_SC_StartMemoryLog);
  }

  /**
   * Address: 0x00C08F40 (FUN_00C08F40, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_StopMemoryLog`.
   */
  void cleanup_CConFunc_SC_StopMemoryLog()
  {
    moho::CleanupStartupConCommand(gCConFunc_SC_StopMemoryLog);
  }

  void register_CConFunc_SC_StopMemoryLog()
  {
    gCConFunc_SC_StopMemoryLog.InitializeRecovered(
      kConsoleStartupSCStopMemoryLogDescription, "SC_StopMemoryLog", &SC_StopMemoryLog
    );
    (void)std::atexit(&cleanup_CConFunc_SC_StopMemoryLog);
  }

  // The binary runs these registrars from the CRT static-initializer array;
  // this file-scope bootstrap object reproduces that, matching the
  // `ResolutionConsoleRegistrations`/`FrameDumpConsoleRegistrations` pattern
  // established in moho/app/ResolutionCommands.cpp / FrameDumpCommands.cpp.
  struct WinMainConsoleRegistrations
  {
    WinMainConsoleRegistrations()
    {
      register_CConFunc_SC_StartMemoryLog();
      register_CConFunc_SC_StopMemoryLog();
    }
  };

  [[maybe_unused]] WinMainConsoleRegistrations gWinMainConsoleRegistrations;

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

  // ---------------------------------------------------------------------
  // DIAGNOSTIC PROBE -- NOT PART OF THE RECOVERY. Remove before committing.
  //
  // The debug CRT aborts inside ucrtbased with a stack the debugger cannot
  // walk (every frame resolves to data or to a non-return address), so the
  // one thing that actually names the fault -- the CRT's own report text,
  // e.g. "HEAP CORRUPTION DETECTED: after Normal block (#NNNN)" or an
  // invalid-parameter expression -- is discarded. These two hooks copy it
  // into faf_diag.log beside the other probes.
  //
  // `/heapcheck` additionally turns on _CRTDBG_CHECK_ALWAYS_DF, which
  // validates the whole CRT heap on every allocation and free.
  //
  // Note this only covers the *CRT* heap. `gpg/core/utils/Global.cpp` replaces
  // `malloc`/`free` with the engine's own small-block allocator, so most engine
  // allocations never reach the CRT heap at all. The switch for that one is the
  // environment variable FAF_HEAPWATCH=1, which makes the allocator's existing
  // stamp/validate probe watch every size class instead of the single stale
  // class it was pinned to. For an engine-side corruption that is the switch
  // that matters; this one is the backstop for whatever does reach the CRT.
  // ---------------------------------------------------------------------
  // The log sits beside the executable, not in whatever the process happened to
  // make its working directory, so it can actually be found and handed over.
  const char* DiagLogPath()
  {
    static char sPath[MAX_PATH * 2] = {};
    static bool sResolved = false;
    if (!sResolved) {
      sResolved = true;
      char exePath[MAX_PATH] = {};
      const DWORD written = ::GetModuleFileNameA(nullptr, exePath, static_cast<DWORD>(sizeof(exePath)));
      if (written == 0u || written >= sizeof(exePath)) {
        (void)::strcpy_s(sPath, sizeof(sPath), "faf_diag.log");
      } else {
        char* const lastSlash = std::strrchr(exePath, '\\');
        if (lastSlash != nullptr) {
          *(lastSlash + 1) = '\0';
        } else {
          exePath[0] = '\0';
        }
        (void)::sprintf_s(sPath, sizeof(sPath), "%sfaf_diag.log", exePath);
      }
    }
    return sPath;
  }

  void DiagLine(const char* const format, ...)
  {
    std::FILE* sink = nullptr;
    if (::fopen_s(&sink, DiagLogPath(), "a") != 0 || sink == nullptr) {
      return;
    }

    std::va_list args;
    va_start(args, format);
    (void)std::vfprintf(sink, format, args);
    va_end(args);

    (void)std::fputc(0x0A, sink);
    (void)std::fclose(sink);
  }

  // ---------------------------------------------------------------------
  // DIAGNOSTIC PROBE -- self-symbolising backtrace.
  //
  // The reported fault is an abort raised on the sim thread from inside
  // ucrtbased, and the debugger cannot walk out of it: ucrtbased ships no
  // symbols here, so every frame above the break resolves to data or to a
  // non-return address and the one useful thing -- which engine call asked the
  // CRT to do something illegal -- is lost.
  //
  // The process does not need the debugger for that. main.exe is built with a
  // PDB and dbghelp.lib is already linked, so it can resolve its own return
  // addresses to function + file:line. Capturing the stack *inside* the handler
  // also beats reading it afterwards: the handler runs on the faulting thread
  // before any unwinding, so the frames above it are the real ones.
  // ---------------------------------------------------------------------
  bool DiagSymbolsReady()
  {
    static bool sReady = false;
    static bool sTried = false;
    if (!sTried) {
      sTried = true;
      (void)::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
      // WinApp.cpp already initialises dbghelp for the crash reporter. A second
      // call fails with ERROR_INVALID_PARAMETER and that is fine - the handle is
      // already usable, so treat "already initialised" as success.
      sReady = ::SymInitialize(::GetCurrentProcess(), nullptr, TRUE) != FALSE
        || ::GetLastError() == ERROR_INVALID_PARAMETER;
    }
    return sReady;
  }

  void DiagDescribeAddress(const void* const address, char* const out, const std::size_t outBytes)
  {
    const auto raw = reinterpret_cast<DWORD64>(address);

    // Module + RVA always works, even with no symbols, and is what makes an
    // unresolved frame decodable offline against the map file.
    char moduleName[MAX_PATH] = "?";
    DWORD64 moduleBase = 0;
    HMODULE module = nullptr;
    if (::GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          static_cast<LPCSTR>(address),
          &module
        ) != FALSE
        && module != nullptr) {
      moduleBase = reinterpret_cast<DWORD64>(module);
      char fullPath[MAX_PATH] = {};
      if (::GetModuleFileNameA(module, fullPath, static_cast<DWORD>(sizeof(fullPath))) != 0u) {
        const char* const slash = std::strrchr(fullPath, '\\');
        (void)::strcpy_s(moduleName, sizeof(moduleName), (slash != nullptr) ? (slash + 1) : fullPath);
      }
    }

    char symbolText[300] = {};
    if (DiagSymbolsReady()) {
      alignas(SYMBOL_INFO) unsigned char storage[sizeof(SYMBOL_INFO) + 256] = {};
      auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
      symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
      symbol->MaxNameLen = 255;

      DWORD64 symbolOffset = 0;
      if (::SymFromAddr(::GetCurrentProcess(), raw, &symbolOffset, symbol) != FALSE) {
        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineOffset = 0;
        // `_TRUNCATE`, never `sprintf_s`: a decorated template name runs to
        // `MaxNameLen` (255) and `line.FileName` is a full source path, so the
        // two of them overflow `symbolText` routinely. `sprintf_s` treats that
        // as an invalid parameter and aborts the process -- which is how a
        // perfectly loggable access violation turned into a CRT assertion box
        // with the real fault's stack already discarded.
        if (::SymGetLineFromAddr64(::GetCurrentProcess(), raw, &lineOffset, &line) != FALSE) {
          (void)::_snprintf_s(
            symbolText, sizeof(symbolText), _TRUNCATE, " %s+0x%llX (%s:%lu)",
            symbol->Name, symbolOffset, (line.FileName != nullptr) ? line.FileName : "?", line.LineNumber
          );
        } else {
          (void)::_snprintf_s(symbolText, sizeof(symbolText), _TRUNCATE, " %s+0x%llX", symbol->Name, symbolOffset);
        }
      }
    }

    (void)::_snprintf_s(
      out, outBytes, _TRUNCATE, "%08llX %s+0x%llX%s",
      raw, moduleName, (moduleBase != 0) ? (raw - moduleBase) : 0ull, symbolText
    );
  }

  void DiagLogStack(const char* const tag)
  {
    void* frames[40] = {};
    const USHORT captured = ::RtlCaptureStackBackTrace(1, 40, frames, nullptr);

    DiagLine("[STACK] %s tid=%lu frames=%u", tag, ::GetCurrentThreadId(), static_cast<unsigned>(captured));
    for (USHORT i = 0; i < captured; ++i) {
      char described[420] = {};
      DiagDescribeAddress(frames[i], described, sizeof(described));
      DiagLine("[STACK]   #%02u %s", static_cast<unsigned>(i), described);
    }
  }

  int CrtReportToDiagLog(const int reportType, char* const message, int* const returnValue)
  {
    static const char* const kKind[] = {"WARN", "ERROR", "ASSERT"};
    const char* const kind =
      (reportType >= 0 && reportType < 3) ? kKind[reportType] : "?";
    DiagLine("[CRTDIAG] %s: %s", kind, (message != nullptr) ? message : "(null)");
    DiagLogStack("crt-report");

    if (returnValue != nullptr) {
      *returnValue = 0; // do not force a breakpoint; let the CRT proceed
    }
    return 0; // fall through to the CRT's own reporting too
  }

  void DiagAbortSignalHandler(int)
  {
    DiagLine("[CRTDIAG] abort() raised");
    DiagLogStack("abort");
  }

  void DiagTerminateHandler()
  {
    DiagLine("[CRTDIAG] std::terminate (uncaught exception or noexcept violation)");
    DiagLogStack("terminate");
    // Let the CRT's own terminate run so behaviour is unchanged.
    (void)std::signal(SIGABRT, SIG_DFL);
    std::abort();
  }

  void DiagPureCallHandler()
  {
    DiagLine("[CRTDIAG] pure virtual call");
    DiagLogStack("purecall");
  }

  // First-chance, log-only. Always continues the search, so the debugger still
  // receives every exception exactly as before.
  LONG CALLBACK DiagVectoredHandler(EXCEPTION_POINTERS* const info)
  {
    if (info == nullptr || info->ExceptionRecord == nullptr) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    constexpr DWORD kCppException = 0xE06D7363u;

    // A C++ throw is an ordinary control-flow event in this engine, so it is
    // opt-in (FAF_LOGTHROW=1) - useful for pinning the bad_alloc, far too noisy
    // by default.
    static int sThrowBudget = 0;
    static const bool sLogThrows = ::GetEnvironmentVariableA("FAF_LOGTHROW", nullptr, 0) != 0u;

    static int sFaultBudget = 0;

    if (code == kCppException) {
      if (!sLogThrows || sThrowBudget >= 40) {
        return EXCEPTION_CONTINUE_SEARCH;
      }
      ++sThrowBudget;
      DiagLine("[FAULT] C++ throw");
      DiagLogStack("throw");
      return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_ACCESS_VIOLATION
        && code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_INT_DIVIDE_BY_ZERO
        && code != EXCEPTION_STACK_OVERFLOW) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    if (sFaultBudget >= 12) {
      return EXCEPTION_CONTINUE_SEARCH;
    }
    ++sFaultBudget;

    char detail[160] = {};
    if (code == EXCEPTION_ACCESS_VIOLATION && info->ExceptionRecord->NumberParameters >= 2) {
      const ULONG_PTR kind = info->ExceptionRecord->ExceptionInformation[0];
      const ULONG_PTR target = info->ExceptionRecord->ExceptionInformation[1];
      (void)::sprintf_s(
        detail, sizeof(detail), " %s address %08IX",
        (kind == 0) ? "reading" : ((kind == 1) ? "writing" : "executing"), target
      );
    }

    DiagLine(
      "[FAULT] code=0x%08lX at %08IX%s",
      code, reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress), detail
    );
    DiagLogStack("fault");
    return EXCEPTION_CONTINUE_SEARCH;
  }

  void CrtInvalidParameterToDiagLog(
    const wchar_t* const expression,
    const wchar_t* const function,
    const wchar_t* const file,
    const unsigned int line,
    const std::uintptr_t
  )
  {
    DiagLine(
      "[CRTDIAG] invalid parameter: expr=%ls function=%ls file=%ls line=%u",
      (expression != nullptr) ? expression : L"(none)",
      (function != nullptr) ? function : L"(none)",
      (file != nullptr) ? file : L"(none)",
      line
    );
  }

  void InstallCrtDiagnosticHooks()
  {
    (void)_CrtSetReportHook(&CrtReportToDiagLog);
    (void)_set_invalid_parameter_handler(&CrtInvalidParameterToDiagLog);

    // Every route the CRT can take to kill the process, each one logging the
    // stack of whoever asked for it. The vectored handler is first-chance and
    // always continues the search, so a debugger still sees everything.
    (void)::AddVectoredExceptionHandler(1UL, &DiagVectoredHandler);
    (void)std::signal(SIGABRT, &DiagAbortSignalHandler);
    (void)std::set_terminate(&DiagTerminateHandler);
    (void)_set_purecall_handler(&DiagPureCallHandler);
    (void)_set_abort_behavior(0U, _WRITE_ABORT_MSG); // no modal box on abort

    DiagLine("[CRTDIAG] ==== run start, pid=%lu ====", ::GetCurrentProcessId());

    if (moho::CFG_GetArgOption("/heapcheck", 0, nullptr)) {
      // _CRTDBG_CHECK_ALWAYS_DF walks every live block on every alloc and free.
      // On this engine that never gets past mounting the archives, so the
      // interval is selectable: FAF_HEAPCHECK_EVERY=1/16/128/1024 (default
      // 1024) still narrows an overrun to the allocations either side of it,
      // at a cost the run survives.
      char interval[16]{};
      const DWORD intervalLen = ::GetEnvironmentVariableA("FAF_HEAPCHECK_EVERY", interval, sizeof(interval));
      int checkFlag = _CRTDBG_CHECK_EVERY_1024_DF;
      const char* checkName = "every 1024 allocations";
      if (intervalLen != 0U && intervalLen < sizeof(interval)) {
        if (std::strcmp(interval, "1") == 0) {
          checkFlag = _CRTDBG_CHECK_ALWAYS_DF;
          checkName = "on every alloc/free";
        } else if (std::strcmp(interval, "16") == 0) {
          checkFlag = _CRTDBG_CHECK_EVERY_16_DF;
          checkName = "every 16 allocations";
        } else if (std::strcmp(interval, "128") == 0) {
          checkFlag = _CRTDBG_CHECK_EVERY_128_DF;
          checkName = "every 128 allocations";
        }
      }

      int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
      flags |= _CRTDBG_ALLOC_MEM_DF | checkFlag;
      (void)_CrtSetDbgFlag(flags);
      DiagLine("[CRTDIAG] /heapcheck on: validating the heap %s", checkName);
    }
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

  InstallCrtDiagnosticHooks(); // DIAGNOSTIC PROBE -- remove before committing

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
      exitCode = app.GetExitValue();
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
