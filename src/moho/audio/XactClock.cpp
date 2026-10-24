// FAF addition, not in the shipped binary: see XactClock.h.

#include "moho/audio/XactClock.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <span>
#include <windows.h>

#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  /// The process clock starts here, not at 0: XACT treats a zero timestamp as
  /// "never set" (its cue elapsed-time helper at x86 0x00413495).
  constexpr LONGLONG kClockBaseSeconds = 60;

  struct XactClockOrigin
  {
    LONGLONG mFrequency = 1;       // QueryPerformanceFrequency
    LONGLONG mCounterAtStart = 0;  // system counter when the first engine was created
    DWORD mTicksAtStart = 0;       // system GetTickCount at the same moment
    double mTestOffsetDays = 0.0;  // FAF_TEST_TICK_OFFSET_DAYS
    LONGLONG mTestCounterOffset = 0;
    DWORD mTestTickOffset = 0;
  };

  XactClockOrigin sOrigin{};
  std::once_flag sOriginOnce;

  /// The clock Windows reports, moved forward by the test offset.
  [[nodiscard]] LONGLONG ReadSystemCounter()
  {
    LARGE_INTEGER counter{};
    ::QueryPerformanceCounter(&counter);
    return counter.QuadPart + sOrigin.mTestCounterOffset;
  }

  [[nodiscard]] DWORD ReadSystemTicks()
  {
    return ::GetTickCount() + sOrigin.mTestTickOffset;
  }

  BOOL WINAPI QueryProcessCounter(LARGE_INTEGER* const counter)
  {
    counter->QuadPart = ReadSystemCounter() - sOrigin.mCounterAtStart + sOrigin.mFrequency * kClockBaseSeconds;
    return TRUE;
  }

  DWORD WINAPI GetProcessTickCount()
  {
    return ReadSystemTicks() - sOrigin.mTicksAtStart + static_cast<DWORD>(kClockBaseSeconds * 1000);
  }

  /// Test only (`/realtickcount` with FAF_TEST_TICK_OFFSET_DAYS): the system
  /// clock as a machine up that many days longer would report it.
  BOOL WINAPI QueryShiftedSystemCounter(LARGE_INTEGER* const counter)
  {
    counter->QuadPart = ReadSystemCounter();
    return TRUE;
  }

  DWORD WINAPI GetShiftedSystemTickCount()
  {
    return ReadSystemTicks();
  }

  void InitializeOrigin()
  {
    LARGE_INTEGER frequency{};
    if (::QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) {
      sOrigin.mFrequency = frequency.QuadPart;
    }

    if (const char* const days = std::getenv("FAF_TEST_TICK_OFFSET_DAYS"); days != nullptr && *days != '\0') {
      sOrigin.mTestOffsetDays = std::strtod(days, nullptr);
      const double seconds = sOrigin.mTestOffsetDays * 86400.0;
      sOrigin.mTestCounterOffset = static_cast<LONGLONG>(seconds * static_cast<double>(sOrigin.mFrequency));
      sOrigin.mTestTickOffset = static_cast<DWORD>(static_cast<LONGLONG>(seconds * 1000.0));
    }

    sOrigin.mCounterAtStart = ReadSystemCounter();
    sOrigin.mTicksAtStart = ReadSystemTicks();
  }

  struct ImportReplacement
  {
    const char* mName;
    const void* mFunction;
    bool mPatched;
  };

  template <class T>
  [[nodiscard]] T* ImageData(const HMODULE module, const DWORD rva)
  {
    return reinterpret_cast<T*>(reinterpret_cast<char*>(module) + rva);
  }

  /// Rewrites the module's KERNEL32 import slots named in `replacements`.
  int PatchKernel32Imports(const HMODULE module, const std::span<ImportReplacement> replacements)
  {
    const auto* const dosHeader = ImageData<const IMAGE_DOS_HEADER>(module, 0);
    const auto* const ntHeaders = ImageData<const IMAGE_NT_HEADERS>(module, static_cast<DWORD>(dosHeader->e_lfanew));
    const IMAGE_DATA_DIRECTORY& importDirectory =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0) {
      return 0;
    }

    int patched = 0;
    for (const auto* descriptor = ImageData<const IMAGE_IMPORT_DESCRIPTOR>(module, importDirectory.VirtualAddress);
         descriptor->Name != 0;
         ++descriptor) {
      if (::_stricmp(ImageData<const char>(module, descriptor->Name), "kernel32.dll") != 0 ||
          descriptor->OriginalFirstThunk == 0) {
        continue;
      }

      const auto* nameThunk = ImageData<const IMAGE_THUNK_DATA>(module, descriptor->OriginalFirstThunk);
      auto* addressThunk = ImageData<IMAGE_THUNK_DATA>(module, descriptor->FirstThunk);
      for (; nameThunk->u1.AddressOfData != 0; ++nameThunk, ++addressThunk) {
        if (IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal)) {
          continue;
        }

        const auto* const importName =
          ImageData<const IMAGE_IMPORT_BY_NAME>(module, static_cast<DWORD>(nameThunk->u1.AddressOfData));
        for (ImportReplacement& replacement : replacements) {
          if (std::strcmp(importName->Name, replacement.mName) != 0) {
            continue;
          }

          DWORD oldProtection = 0;
          if (::VirtualProtect(&addressThunk->u1.Function, sizeof(addressThunk->u1.Function), PAGE_EXECUTE_READWRITE, &oldProtection)) {
            ::InterlockedExchangePointer(
              reinterpret_cast<PVOID volatile*>(&addressThunk->u1.Function), const_cast<void*>(replacement.mFunction)
            );
            ::VirtualProtect(&addressThunk->u1.Function, sizeof(addressThunk->u1.Function), oldProtection, &oldProtection);
            replacement.mPatched = true;
            ++patched;
          }
        }
      }
    }
    return patched;
  }
} // namespace

namespace moho
{
  void SND_InstallXactClock(const IXACTEngine& engine)
  {
    // A COM object's first word is its interface table, which sits in the
    // image of the DLL that implements it.
    const void* const interfaceTable = *reinterpret_cast<const void* const*>(&engine);
    HMODULE module = nullptr;
    if (!::GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          static_cast<LPCWSTR>(interfaceTable),
          &module
        )) {
      gpg::Warnf("SND: could not find the XACT engine module; its clock stays on system uptime");
      return;
    }

    char modulePath[MAX_PATH]{};
    ::GetModuleFileNameA(module, modulePath, MAX_PATH);
    const char* moduleName = std::strrchr(modulePath, '\\');
    moduleName = moduleName != nullptr ? moduleName + 1 : modulePath;

    std::call_once(sOriginOnce, &InitializeOrigin);

    const bool systemClock = CFG_GetArgOption("/realtickcount", 0, nullptr);
    if (systemClock && sOrigin.mTestOffsetDays == 0.0) {
      gpg::Logf("SND: /realtickcount: %s times itself with the system uptime clock", moduleName);
      return;
    }

    std::array<ImportReplacement, 2> replacements{{
      {"QueryPerformanceCounter", systemClock ? reinterpret_cast<const void*>(&QueryShiftedSystemCounter)
                                              : reinterpret_cast<const void*>(&QueryProcessCounter), false},
      {"GetTickCount", systemClock ? reinterpret_cast<const void*>(&GetShiftedSystemTickCount)
                                   : reinterpret_cast<const void*>(&GetProcessTickCount), false},
    }};
    const int patched = PatchKernel32Imports(module, replacements);

    if (systemClock) {
      gpg::Logf(
        "SND: /realtickcount: %s times itself with the system uptime clock, shifted %.2f days by FAF_TEST_TICK_OFFSET_DAYS (%d imports)",
        moduleName,
        sOrigin.mTestOffsetDays,
        patched
      );
      return;
    }

    gpg::Logf(
      "SND: %s clock imports patched to count from process start (QueryPerformanceCounter %s, GetTickCount %s%s); /realtickcount disables",
      moduleName,
      replacements[0].mPatched ? "yes" : "no",
      replacements[1].mPatched ? "yes" : "no",
      sOrigin.mTestOffsetDays != 0.0 ? ", system clock shifted by FAF_TEST_TICK_OFFSET_DAYS" : ""
    );
  }
} // namespace moho
