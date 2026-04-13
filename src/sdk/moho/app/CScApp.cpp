#include "CScApp.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/gal/AppRuntimeView.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/audio/SofdecRuntime.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/TimeBar.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/Common.h"
#include "moho/app/WxAppRuntime.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/app/WinApp.h"
#include "moho/render/RCamManager.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/task/CTaskThread.h"
#include "moho/ui/IUIManager.h"

namespace gpg
{
  void Logf(const char* fmt, ...);
  void Warnf(const char* fmt, ...);
} // namespace gpg

namespace
{
  constexpr std::uintptr_t kAddressSpaceQueryLimit = 0x80000000u;
  constexpr double kAddressSpaceQueryIntervalSeconds = 3.0;

  moho::StatItem* sEngineStatHeapReserved = nullptr;
  moho::StatItem* sEngineStatHeapCommitted = nullptr;
  moho::StatItem* sEngineStatHeapTotal = nullptr;
  moho::StatItem* sEngineStatHeapInSmallBlocks = nullptr;
  moho::StatItem* sEngineStatHeapInUse = nullptr;
  moho::StatItem* sEngineStatHeapTotalCheck = nullptr;

  moho::StatItem* sEngineStatHeapAddressSpaceCommit = nullptr;
  moho::StatItem* sEngineStatHeapAddressSpaceReserve = nullptr;
  moho::StatItem* sEngineStatHeapAddressSpaceFree = nullptr;
  moho::StatItem* sEngineStatHeapAddressSpaceRegions = nullptr;
  moho::StatItem* sEngineStatHeapAddressSpaceAllocations = nullptr;

  bool sAddressSpaceMonitorInitialized = false;
  bool sAddressSpaceMonitorEnabled = false;
  gpg::time::Timer sAddressSpaceMonitorTimer{};

  void AccumulateClamped(std::uint32_t& counter, const SIZE_T increment)
  {
    const std::uint32_t maxValue = (std::numeric_limits<std::uint32_t>::max)();
    const std::uint32_t remaining = maxValue - counter;
    const std::uint32_t clamped = static_cast<std::uint32_t>((std::min<SIZE_T>)(increment, remaining));
    counter += clamped;
  }

  void EnsureEngineStringStatItem(moho::StatItem*& slot, const char* const statPath)
  {
    if (slot != nullptr) {
      return;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (engineStats == nullptr) {
      return;
    }

    slot = engineStats->GetItem_0(statPath);
    if (slot != nullptr) {
      (void)slot->Release(0);
    }
  }

  void EnsureEngineIntStatItem(moho::StatItem*& slot, const char* const statPath)
  {
    if (slot != nullptr) {
      return;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (engineStats == nullptr) {
      return;
    }

    slot = engineStats->GetItem2(statPath);
    if (slot != nullptr) {
      (void)slot->Release(0);
    }
  }

  /**
   * Address: 0x008D1040 (FUN_008D1040, func_FmtByteSize)
   *
   * What it does:
   * Formats byte counts as `B/K/M/G` with precision rules based on magnitude.
   */
  [[nodiscard]] msvc8::string FormatByteSize(const std::uint32_t valueBytes)
  {
    const int scaled = static_cast<int>(valueBytes);
    if (valueBytes + 0x400u <= 0x800u) {
      return gpg::STR_Printf("%dB", scaled);
    }

    const char* suffix = "KMG";
    int shifted = scaled;
    while (shifted >= 0x100000 || shifted <= -0x100000) {
      ++suffix;
      shifted >>= 10;
    }

    const double normalizedValue = static_cast<double>(shifted) * (1.0 / 1024.0);
    const double absValue = std::fabs(normalizedValue);
    if (absValue < 10.0) {
      return gpg::STR_Printf("%.3f%c", normalizedValue, *suffix);
    }
    if (absValue < 100.0) {
      return gpg::STR_Printf("%.2f%c", normalizedValue, *suffix);
    }
    return gpg::STR_Printf("%.1f%c", normalizedValue, *suffix);
  }

  void PublishEngineStringStat(
    moho::StatItem*& slot, const char* const statPath, const std::uint32_t valueBytes
  )
  {
    EnsureEngineStringStatItem(slot, statPath);
    if (slot == nullptr) {
      return;
    }

    slot->SetValue(FormatByteSize(valueBytes));
  }

  void PublishEngineIntStat(moho::StatItem*& slot, const char* const statPath, const std::int32_t value)
  {
    EnsureEngineIntStatItem(slot, statPath);
    if (slot == nullptr) {
      return;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&slot->mPrimaryValueBits);
    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, static_cast<long>(value), observed) != observed);
  }

  /**
   * Address: 0x008D1130 (FUN_008D1130, func_QueryHeap)
   *
   * What it does:
   * Scans user-space virtual-memory regions and publishes address-space stats.
   */
  void QueryHeapAddressSpace()
  {
    std::uintptr_t cursor = 0;
    std::uintptr_t previousAllocationBase = (std::numeric_limits<std::uintptr_t>::max)();
    std::uint32_t committedBytes = 0;
    std::uint32_t reservedBytes = 0;
    std::uint32_t freeBytes = 0;
    std::int32_t regionCount = 0;
    std::int32_t allocationCount = 0;

    while (cursor < kAddressSpaceQueryLimit) {
      MEMORY_BASIC_INFORMATION memoryInfo{};
      const SIZE_T queried = ::VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &memoryInfo, sizeof(memoryInfo));
      if (queried != sizeof(memoryInfo) || memoryInfo.RegionSize == 0) {
        break;
      }

      ++regionCount;

      const std::uintptr_t allocationBase = reinterpret_cast<std::uintptr_t>(memoryInfo.AllocationBase);
      if (allocationBase != 0 && allocationBase != previousAllocationBase) {
        ++allocationCount;
        previousAllocationBase = allocationBase;
      }

      switch (memoryInfo.State) {
        case MEM_COMMIT:
          AccumulateClamped(committedBytes, memoryInfo.RegionSize);
          break;
        case MEM_RESERVE:
          AccumulateClamped(reservedBytes, memoryInfo.RegionSize);
          break;
        case MEM_FREE:
          AccumulateClamped(freeBytes, memoryInfo.RegionSize);
          break;
        default:
          break;
      }

      cursor += static_cast<std::uintptr_t>(memoryInfo.RegionSize);
    }

    PublishEngineStringStat(
      sEngineStatHeapAddressSpaceCommit, "Heap_Address Space_Commit", committedBytes
    );
    PublishEngineStringStat(
      sEngineStatHeapAddressSpaceReserve, "Heap_Address Space_Reserve", reservedBytes
    );
    PublishEngineStringStat(sEngineStatHeapAddressSpaceFree, "Heap_Address Space_Free", freeBytes);
    PublishEngineIntStat(
      sEngineStatHeapAddressSpaceRegions, "Heap_Address Space_Regions", regionCount
    );
    PublishEngineIntStat(
      sEngineStatHeapAddressSpaceAllocations, "Heap_Address Space_Allocations", allocationCount
    );
  }

  /**
   * Address: 0x008D1470 (FUN_008D1470) - heap stat publish prelude.
   *
   * What it does:
   * Pulls allocator counters and publishes the six heap stat strings used by UI stats.
   */
  void PublishAllocatorHeapStats()
  {
    gpg::HeapStats heapStats{};
    gpg::GetHeapInfo(&heapStats);

    PublishEngineStringStat(sEngineStatHeapReserved, "Heap_Reserved", heapStats.reserved);
    PublishEngineStringStat(sEngineStatHeapCommitted, "Heap_Committed", heapStats.committed);
    PublishEngineStringStat(sEngineStatHeapTotal, "Heap_Total", heapStats.total);
    PublishEngineStringStat(
      sEngineStatHeapInSmallBlocks, "Heap_InSmallBlocks", heapStats.inSmallBlocks
    );
    PublishEngineStringStat(sEngineStatHeapInUse, "Heap_InUse", heapStats.inUse);
    PublishEngineStringStat(
      sEngineStatHeapTotalCheck, "Heap_TotalCheck", heapStats.inSmallBlocks + heapStats.inUse
    );
  }

  void UpdateAddressSpaceMonitor()
  {
    if (!sAddressSpaceMonitorInitialized) {
      sAddressSpaceMonitorInitialized = true;
      // Inference for source-only runtime: use command-line switch when dbg cvar lane is not yet recovered.
      sAddressSpaceMonitorEnabled = moho::CFG_GetArgOption("/monitoraddressspace", 0, nullptr);
      sAddressSpaceMonitorTimer.Reset();
    }

    if (!sAddressSpaceMonitorEnabled) {
      return;
    }

    if (sAddressSpaceMonitorTimer.ElapsedSeconds() > kAddressSpaceQueryIntervalSeconds) {
      sAddressSpaceMonitorTimer.Reset();
      QueryHeapAddressSpace();
    }
  }

  void PushFrameDelta(CScApp::RollingFrameRates& history, const float deltaSeconds)
  {
    const int next = (history.end + 1) % 10;
    if (next == history.start) {
      history.start = (history.start + 1) % 10;
    }

    history.vals[history.end] = deltaSeconds;
    history.end = next;
  }

  [[nodiscard]] float TryReadFixedFrameDeltaSeconds()
  {
    msvc8::vector<msvc8::string> framerateArgs;
    if (!moho::CFG_GetArgOption("/framerate", 1, &framerateArgs) || framerateArgs.empty()) {
      return -1.0f;
    }

    const char* const rateText = framerateArgs[0].c_str();
    if (rateText == nullptr || *rateText == '\0') {
      return -1.0f;
    }

    const float rate = std::strtof(rateText, nullptr);
    if (!(rate > 0.0f)) {
      return -1.0f;
    }

    return 1.0f / rate;
  }

  void SetFrontEndReplayFilename(const msvc8::string& replayPath)
  {
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject globals = state->GetGlobals();
    if (globals.IsNil()) {
      return;
    }

    LuaPlus::LuaObject frontEndData = globals.GetByName("FrontEndData");
    if (frontEndData.IsNil() || !frontEndData.IsTable()) {
      frontEndData.AssignNewTable(state, 0, 0);
      globals.SetObject("FrontEndData", frontEndData);
    }

    frontEndData.SetString("replay_filename", replayPath.c_str());
  }

  [[nodiscard]] msvc8::string ResolveLoadPath(gpg::StrArg requestedPath)
  {
    msvc8::string loadPath;
    loadPath.assign_owned(requestedPath != nullptr ? requestedPath : "");
    if (loadPath.empty()) {
      return loadPath;
    }

    if (moho::FILE_IsAbsolute(loadPath.c_str())) {
      return loadPath;
    }

    return moho::USER_GetSaveGameDir() + loadPath + "." + moho::USER_GetSaveGameExt();
  }

  /**
   * Address: 0x008CE3D0 (FUN_008CE3D0, func_InitializeSession)
   *
   * What it does:
   * Runs first-frame command-line session bootstrap and chooses one UI/session
   * startup path (`scenario/map`, lobby host/join, perf, gpgnet, or splash).
   */
  void InitializeSessionFromCommandLine()
  {
    msvc8::vector<msvc8::string> args;

    if (moho::CFG_GetArgOption("/scenario", 1, &args) || moho::CFG_GetArgOption("/map", 1, &args)) {
      if (!args.empty()) {
        const msvc8::string mapScenario = moho::FindMapScenario(args[0].c_str());
        if (moho::StartCommandLineSession(mapScenario.c_str(), false)) {
          return;
        }
      }

      (void)moho::UI_StartSplashScreens();
      return;
    }

    if (moho::CFG_GetArgOption("/replay", 1, &args)) {
      if (!args.empty()) {
        SetFrontEndReplayFilename(args[0]);
        msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = moho::VCR_SetupReplaySession(args[0].c_str());
        if (sessionInfo.get() != nullptr) {
          moho::WLD_BeginSession(sessionInfo);
          return;
        }

        const msvc8::string message = gpg::STR_Printf("Unable to load game replay from %s", args[0].c_str());
        moho::WIN_OkBox("Ack!", message.c_str());
      } else {
        gpg::Warnf("InitializeSession: /replay specified without a replay path.");
      }
      (void)moho::UI_StartSplashScreens();
      return;
    }

    if (moho::CFG_GetArgOption("/load", 1, &args)) {
      if (!args.empty()) {
        const msvc8::string loadPath = ResolveLoadPath(args[0].c_str());
        try {
          moho::CSavedGame savedGame(loadPath.c_str());
          msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = savedGame.CreateSinglePlayerSessionInfo();
          if (sessionInfo.get() != nullptr) {
            moho::WLD_BeginSession(sessionInfo);
            return;
          }

          const msvc8::string message = gpg::STR_Printf("Unable to load saved game from %s", loadPath.c_str());
          moho::WIN_OkBox("Ack!", message.c_str());
        } catch (const std::exception& exception) {
          const msvc8::string message =
            gpg::STR_Printf("Failed to load saved game from \"%s\":\n%s", loadPath.c_str(), exception.what());
          moho::WIN_OkBox("Ack!", message.c_str());
        } catch (...) {
          const msvc8::string message = gpg::STR_Printf("Failed to load saved game from \"%s\".", loadPath.c_str());
          moho::WIN_OkBox("Ack!", message.c_str());
        }
      } else {
        gpg::Warnf("InitializeSession: /load specified without a save path.");
      }
      (void)moho::UI_StartSplashScreens();
      return;
    }

    if (moho::CFG_GetArgOption("/hostgame", 5, &args) && args.size() == 5) {
      const msvc8::string mapScenario = moho::FindMapScenario(args[4].c_str());
      const int hostPort = std::atoi(args[1].c_str());
      (void)moho::UI_StartHostLobbyUI(
        args[0].c_str(), hostPort, args[2].c_str(), args[3].c_str(), mapScenario.c_str()
      );
      return;
    }

    if (moho::CFG_GetArgOption("/joingame", 3, &args) && args.size() == 3) {
      (void)moho::UI_StartJoinLobbyUI(args[0].c_str(), args[1].c_str(), args[2].c_str());
      return;
    }

    if (moho::CFG_GetArgOption("/perf", 0, nullptr)) {
      const msvc8::string mapScenario = moho::FindMapScenario("PerfTest");
      if (moho::StartCommandLineSession(mapScenario.c_str(), true)) {
        return;
      }

      (void)moho::UI_StartSplashScreens();
      return;
    }

    if (moho::CFG_GetArgOption("/gpgnet", 1, &args) && !args.empty()) {
      const msvc8::string endpoint = args[0];
      u_long address = 0;
      u_short port = 0;
      if (!moho::NET_GetAddrInfo(endpoint.c_str(), 0, true, address, port) || port == 0) {
        const msvc8::string message =
          gpg::STR_Printf("Invalid address:port for connecting to the gpg.net client: \"%s\".", endpoint.c_str());
        moho::WIN_OkBox("Ack!", message.c_str());
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
        return;
      }

      try {
        moho::GPGNET_Attach(address, port);
      } catch (const std::exception& exception) {
        const msvc8::string message =
          gpg::STR_Printf("Unable to connect to gpgnet endpoint \"%s\":\n%s", endpoint.c_str(), exception.what());
        moho::WIN_OkBox("Ack!", message.c_str());
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
        return;
      }

      LuaPlus::LuaState* const state = moho::USER_GetLuaState();
      moho::IUIManager* const uiManager = moho::UI_GetManager();
      if (state == nullptr || uiManager == nullptr || !uiManager->SetNewLuaState(state)) {
        moho::WIN_OkBox("Ack!", "UI_GetManager()->SetNewLuaState(state) failed!");
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
        return;
      }

      try {
        const LuaPlus::LuaObject gpgNetModule = moho::SCR_ImportLuaModule(state, "/lua/multiplayer/gpgnet.lua");
        const LuaPlus::LuaObject createUi = moho::SCR_GetLuaTableField(state, gpgNetModule, "CreateUI");
        if (createUi.IsNil()) {
          throw std::runtime_error("Missing CreateUI entrypoint in /lua/multiplayer/gpgnet.lua");
        }

        LuaPlus::LuaFunction<void> createUiFn(createUi);
        createUiFn();
      } catch (const std::exception& exception) {
        const msvc8::string message = gpg::STR_Printf("Unable to start gpgnet UI:\n%s", exception.what());
        moho::WIN_OkBox("Ack!", message.c_str());
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
      } catch (...) {
        moho::WIN_OkBox("Ack!", "Unable to start gpgnet UI.");
        if (wxTheApp != nullptr) {
          wxTheApp->ExitMainLoop();
        }
      }

      return;
    }

    (void)moho::UI_StartSplashScreens();
  }

  constexpr wxPoint kWxDefaultPosition{-1, -1};
  constexpr std::int32_t kFullscreenFrameStyle = 0x200800;
  constexpr std::int32_t kWindowedFrameStyle = 0x20400E40;

  [[nodiscard]] bool IsPositiveIntegerArg(const msvc8::string& text)
  {
    return std::atoi(text.c_str()) > 0;
  }

  [[nodiscard]] std::int32_t ParseIntegerArg(const msvc8::string& text)
  {
    return static_cast<std::int32_t>(std::atoi(text.c_str()));
  }

  [[nodiscard]] msvc8::string BuildSplashImagePath()
  {
    std::filesystem::path launchDirectory = moho::DISK_GetLaunchDirectory();
    if (launchDirectory.empty()) {
      std::error_code currentPathError;
      launchDirectory = std::filesystem::current_path(currentPathError);
      if (currentPathError) {
        launchDirectory.clear();
      }
    }

    std::filesystem::path splashPath = launchDirectory;
    splashPath /= "splash.png";

    std::error_code canonicalizeError;
    const std::filesystem::path canonicalSplashPath = std::filesystem::weakly_canonical(splashPath, canonicalizeError);
    if (!canonicalizeError) {
      splashPath = canonicalSplashPath;
    }

    msvc8::string splashPathUtf8;
    splashPathUtf8.assign_owned(splashPath.generic_string());
    return splashPathUtf8;
  }

  [[nodiscard]] std::uint32_t ClampAtLeast(const std::uint32_t floorValue, const std::int32_t parsed)
  {
    return static_cast<std::uint32_t>((std::max)(floorValue, static_cast<std::uint32_t>((std::max)(0, parsed))));
  }

  [[nodiscard]] bool TryGetWindowOptionArgs(msvc8::vector<msvc8::string>* const outArgs)
  {
    if (outArgs == nullptr) {
      return false;
    }

    if (moho::CFG_GetArgOptionComposedAliases(
          moho::CFG_GetDualOptionAliases(),
          moho::CFG_GetHeadOptionAliases(),
          2,
          outArgs
        )) {
      return outArgs->size() == 2 && IsPositiveIntegerArg((*outArgs)[0]) && IsPositiveIntegerArg((*outArgs)[1]);
    }

    if (moho::CFG_GetArgOptionComposedAliases(
          moho::CFG_GetDualOptionAliases(),
          moho::CFG_GetHeadOptionAliases(),
          4,
          outArgs
        )) {
      return outArgs->size() == 4 && IsPositiveIntegerArg((*outArgs)[0]) && IsPositiveIntegerArg((*outArgs)[1]) &&
             IsPositiveIntegerArg((*outArgs)[2]) && IsPositiveIntegerArg((*outArgs)[3]);
    }

    return false;
  }

  [[nodiscard]] bool TryGetFullscreenOptionArgs(msvc8::vector<msvc8::string>* const outArgs)
  {
    if (outArgs == nullptr ||
        !moho::CFG_GetArgOptionAliases(moho::CFG_GetFullscreenOptionAliases(), 2, outArgs)) {
      return false;
    }

    return outArgs->size() == 2 && IsPositiveIntegerArg((*outArgs)[0]) && IsPositiveIntegerArg((*outArgs)[1]);
  }

  [[nodiscard]] bool TryGetWindowedOptionArgs(msvc8::vector<msvc8::string>* const outArgs)
  {
    if (outArgs == nullptr ||
        !moho::CFG_GetArgOptionAliases(moho::CFG_GetWindowedOptionAliases(), 2, outArgs)) {
      return false;
    }

    return outArgs->size() == 2 && IsPositiveIntegerArg((*outArgs)[0]) && IsPositiveIntegerArg((*outArgs)[1]);
  }

  [[nodiscard]] bool IsDisabledAdapterToken(const msvc8::string& value)
  {
    return value.equals_no_case("disabled");
  }

  [[nodiscard]] bool IsWindowedAdapterToken(const msvc8::string& value)
  {
    return value.equals_no_case("windowed");
  }

  void ClampPositionToMonitor(wxPoint* const inOutPosition)
  {
    if (inOutPosition == nullptr) {
      return;
    }

    const POINT monitorPoint{inOutPosition->x, inOutPosition->y};
    const HMONITOR monitor = ::MonitorFromPoint(monitorPoint, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (monitor == nullptr || ::GetMonitorInfoW(monitor, &monitorInfo) == FALSE) {
      return;
    }

    const LONG clampedX =
      (std::max)(monitorInfo.rcMonitor.left, (std::min)(static_cast<LONG>(inOutPosition->x), monitorInfo.rcMonitor.right));
    const LONG clampedY =
      (std::max)(monitorInfo.rcMonitor.top, (std::min)(static_cast<LONG>(inOutPosition->y), monitorInfo.rcMonitor.bottom));

    inOutPosition->x = static_cast<std::int32_t>(clampedX);
    inOutPosition->y = static_cast<std::int32_t>(clampedY);
  }

  void ApplyPackedAntiAliasing(gpg::gal::Head& head, const std::int32_t packedAntiAliasing)
  {
    head.antialiasingHigh = static_cast<std::uint32_t>(packedAntiAliasing >> 5);
    head.antialiasingLow = static_cast<std::uint32_t>(packedAntiAliasing & 0x1F);
  }

  void DestroyFrameWindow(wxWindowBase*& frameWindow)
  {
    if (frameWindow == nullptr) {
      return;
    }

    (void)moho::WxAppRuntime::DestroyWindow(frameWindow);
    frameWindow = nullptr;
  }

  void DestroySupComFrameWindow(WSupComFrame*& frameWindow)
  {
    if (frameWindow == nullptr) {
      return;
    }

    (void)moho::WxAppRuntime::DestroyWindow(frameWindow);
    frameWindow = nullptr;
  }

  /**
   * Address: 0x008CED90 (FUN_008CED90, func_CreateFileMapping)
   *
   * What it does:
   * Publishes the current primary-window bounds into
   * `Local\\FullScreenPresentationModeInfo` shared memory for
   * fullscreen-presentation compatibility paths.
   */
  void PublishWindowedPresentationBounds(HWND const windowHandle)
  {
    HANDLE const mapping = ::CreateFileMappingW(
      INVALID_HANDLE_VALUE,
      nullptr,
      PAGE_READWRITE,
      0,
      sizeof(RECT),
      L"Local\\FullScreenPresentationModeInfo"
    );
    if (mapping == nullptr) {
      return;
    }

    auto* const windowRect = static_cast<RECT*>(::MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0));
    if (windowRect == nullptr) {
      return;
    }

    ::GetWindowRect(windowHandle, windowRect);
    (void)::UnmapViewOfFile(windowRect);
  }
} // namespace

/**
 * Address: 0x008D5280 (FUN_008D5280, sub_8D5280)
 *
 * What it does:
 * Flushes the ring and resets start/end indexes to zero.
 */
void CScApp::RollingFrameRates::Reset()
{
  if (start != end) {
    do {
      start = (start + 1) % 10;
    } while (start != end);
  }

  start = 0;
  end = 0;
}

/**
 * Address: 0x008D4B20 (FUN_008D4B20, struct_RollingFrameRates::median)
 *
 * What it does:
 * Copies the active ring window to a scratch buffer, sorts it,
 * and returns the middle sample.
 */
float CScApp::RollingFrameRates::Median() const
{
  std::array<float, 10> samples{};
  int cursor = start;
  int count = 0;

  while (cursor != end && count < 10) {
    samples[static_cast<std::size_t>(count)] = vals[cursor];
    cursor = (cursor + 1) % 10;
    ++count;
  }

  if (count == 0) {
    return 0.0f;
  }

  std::sort(samples.begin(), samples.begin() + count);
  return samples[static_cast<std::size_t>(count / 2)];
}

/**
 * Address: 0x008CE0A0 (FUN_008CE0A0)
 * Mangled context: constructor prologue used by app bootstrap.
 *
 * What it does:
 * Initializes core CScApp runtime fields after IWinApp base construction.
 */
CScApp::CScApp()
  : IWinApp("SupCom", "SupremeCommander")
  , usingScreensaver(0)
  , initialized(0)
  , isMinimized(0)
  , reserved4A{0, 0}
  , supcomFrame(nullptr)
  , frame(nullptr)
  , firstFramePending(1)
  , reserved55{0, 0, 0}
  , curTime()
  , framerates{}
{
  // FA ctor calls gpg::time::Timer::Timer/Reset at +0x58 and zeroes ring indexes.
  curTime.Reset();
  framerates.start = 0;
  framerates.end = 0;
  moho::APP_InitializeIdentity();
}

/**
 * Address: 0x008D1CB0 (FUN_008D1CB0, CScApp::Dtr scalar deleting dtor)
 *
 * What it does:
 * Clears rolling framerate state, then tears down IWinApp base state.
 */
CScApp::~CScApp()
{
  framerates.Reset();
}

/**
 * Address: 0x008CEDE0 (FUN_008CEDE0)
 * Mangled: ?Init@CScApp@@UAE_NXZ
 *
 * What it does:
 * Performs app startup bootstrap. This first-pass lift keeps the recovered
 * ordering around common-service init, timing/ring reset, and screensaver
 * suppression used by the render loop path.
 */
bool CScApp::Init()
{
  moho::APP_InitializeIdentity();
  framerates.Reset();
  curTime.Reset();
  firstFramePending = 1;
  initialized = 0;
  isMinimized = 0;

  if (moho::CFG_GetArgOption("/splash", 0, nullptr)) {
    const msvc8::string splashImagePath = BuildSplashImagePath();
    moho::WINX_InitSplash(splashImagePath.c_str());
  }

  if (!AppInitCommonServices()) {
    return false;
  }

  moho::USER_EnsureDocumentDirectories();
  moho::UI_Init();
  if (!CreateDevice()) {
    return false;
  }

  moho::WIN_SetMainWindow(supcomFrame);

  if (!::SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &usingScreensaver, 0)) {
    usingScreensaver = 0;
  }

  if (!::SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, 0, nullptr, 0)) {
    gpg::Warnf("unable to suppress screensaver");
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device->GetDeviceContext();
  if (context->GetHeadCount() > 0) {
    const gpg::gal::Head& primaryHead = context->GetHead(0);
    if (primaryHead.mWindowed && primaryHead.mHandle != nullptr) {
      PublishWindowedPresentationBounds(reinterpret_cast<HWND>(primaryHead.mHandle));
    }
  }

  return true;
}

/**
 * Address: 0x008D1470 (FUN_008D1470)
 * Mangled: ?Main@CScApp@@UAEXXZ
 *
 * What it does:
 * Drives per-frame app timing state, including heap stat publishing,
 * scoped timebar instrumentation, command-line fixed framerate override
 * handling, audio/task/sofdec frame dispatch, camera manager/render
 * frame updates, one-time session bootstrap, and minimized wait-handle/timer
 * routing.
 */
void CScApp::Main()
{
  moho::CTimeBarSection appFrameSection("AppFrame");
  PublishAllocatorHeapStats();
  UpdateAddressSpaceMonitor();
  moho::WIN_SetMainWindow(supcomFrame);

  moho::ISTIDriver* const simDriver = moho::SIM_GetActiveDriver();
  if (simDriver != nullptr) {
    if (moho::CWaitHandleSet* const waitHandleSet = moho::WIN_GetWaitHandleSet()) {
      waitHandleSet->RemoveHandle(simDriver->GetSyncDataAvailableEvent());
    }
  }

  float frameSeconds = 0.0f;
  float fixedFrameSeconds = -1.0f;
  if (firstFramePending != 0) {
    firstFramePending = 0;
    curTime.Reset();
  } else {
    fixedFrameSeconds = TryReadFixedFrameDeltaSeconds();
    if (fixedFrameSeconds > 0.0f) {
      frameSeconds = fixedFrameSeconds;
    } else {
      frameSeconds = static_cast<float>(curTime.ElapsedMilliseconds() * 0.001);
    }

    curTime.Reset();
  }

  PushFrameDelta(framerates, frameSeconds);
  moho::SND_Frame();
  moho::DISK_UpdateWatcher();

  const float smoothedFrameSeconds = fixedFrameSeconds > 0.0f ? fixedFrameSeconds : framerates.Median();
  if (!moho::WLD_Frame(smoothedFrameSeconds) && wxTheApp != nullptr) {
    wxTheApp->ExitMainLoop();
  }

  moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
  const std::int32_t gameTick = activeSession != nullptr ? activeSession->mGameTick : 0;
  const float simDeltaSeconds = activeSession != nullptr ? activeSession->mTimeSinceLastTick : 0.0f;
  moho::CAM_GetManager()->Frame(simDeltaSeconds, frameSeconds);
  if (moho::sUserStage != nullptr) {
    moho::sUserStage->UserFrame();
  }
  ::ADXM_ExecMain();
  moho::REN_Frame(gameTick, simDeltaSeconds, frameSeconds);
  if (moho::IUserSoundManager* const userSound = moho::USER_GetSound(); userSound != nullptr) {
    userSound->Frame(simDeltaSeconds, frameSeconds);
  }

  if (moho::IUIManager* const uiManager = moho::UI_GetManager()) {
    uiManager->UpdateFrameRate(frameSeconds);
  }

  bool minimizedNow = false;
  if (moho::sMainWindow != nullptr) {
    const HWND windowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
    minimizedNow = windowHandle != nullptr && ::IsIconic(windowHandle) != FALSE;
  }

  if (minimizedNow) {
    if (activeSession != nullptr) {
      const float delayToNextBeatSeconds = activeSession->GetDelayToNextBeat();
      if (delayToNextBeatSeconds > 0.0f) {
        moho::WIN_SetWakeupTimer(delayToNextBeatSeconds * 1000.0f);
      } else if (simDriver != nullptr) {
        if (moho::CWaitHandleSet* const waitHandleSet = moho::WIN_GetWaitHandleSet()) {
          waitHandleSet->AddHandle(simDriver->GetSyncDataAvailableEvent());
        }
      }
    }
  } else if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
    device->Refresh();
  }

  if (initialized == 0) {
    InitializeSessionFromCommandLine();
    initialized = 1;
  }

  if (minimizedNow != (isMinimized != 0)) {
    moho::SND_Mute(minimizedNow);
    if (moho::IUIManager* const uiManager = moho::UI_GetManager()) {
      uiManager->SetMinimized(minimizedNow);
    }
    gpg::Logf("Minimized %s", minimizedNow ? "true" : "false");
  }

  isMinimized = minimizedNow ? 1 : 0;
}

/**
 * Address: 0x008D0F20 (FUN_008D0F20)
 * Mangled: ?Destroy@CScApp@@UAEXXZ
 *
 * What it does:
 * App shutdown teardown. This pass preserves screensaver restore, world/gpgnet
 * teardown, frame-window destruction, cursor unclipping, and local runtime
 * cleanup.
 */
void CScApp::Destroy()
{
  moho::WIN_SetMainWindow(nullptr);

  if (!::SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, usingScreensaver, nullptr, 0)) {
    gpg::Warnf("unable to reset screensaver");
  }

  moho::WLD_Teardown();
  moho::GPGNET_Shutdown();
  moho::UI_Exit();

  if (supcomFrame != nullptr) {
    (void)moho::WxAppRuntime::DestroyWindow(supcomFrame);
    supcomFrame = nullptr;
  }

  if (frame != nullptr) {
    (void)moho::WxAppRuntime::DestroyWindow(frame);
    frame = nullptr;
  }

  ::ClipCursor(nullptr);
  framerates.Reset();
  firstFramePending = 1;
  initialized = 0;
  isMinimized = 0;
}

/**
 * Address: 0x008D0370 (FUN_008D0370)
 * Mangled: ?CreateDevice@CScApp@@AAE_NXZ
 *
 * What it does:
 * Builds gal::DeviceContext heads from command-line/preferences and
 * drives startup adapter/fidelity initialization.
 */
bool CScApp::CreateDevice()
{
  struct DeviceLockGuard
  {
    ~DeviceLockGuard()
    {
      moho::sDeviceLock = false;
    }
  };

  moho::sDeviceLock = true;
  DeviceLockGuard lockGuard{};

  msvc8::string title("Forged Alliance");
  msvc8::vector<msvc8::string> options;
  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();

  const bool useD3D10 = moho::CFG_GetArgOption("/D3D10", 0, nullptr);
  moho::d3d_WindowsCursor = useD3D10;

  gpg::gal::DeviceContext context(useD3D10 ? 2 : 1);
  context.mVSync = moho::OPTIONS_GetInt("vsync") == 1;
  context.AddHead(gpg::gal::Head{});

  gpg::gal::Head& primaryHead = context.GetHead(0);
  primaryHead.mWindowed = true;
  primaryHead.mWidth = static_cast<std::uint32_t>(moho::wnd_DefaultCreateWidth);
  primaryHead.mHeight = static_cast<std::uint32_t>(moho::wnd_DefaultCreateHeight);
  primaryHead.framesPerSecond = 60;

  wxPoint position = kWxDefaultPosition;
  bool windowedByCommandLine = false;
  bool secondarySetupMode = false;

  if (TryGetWindowOptionArgs(&options)) {
    context.AddHead(gpg::gal::Head{});
    gpg::gal::Head& secondaryHead = context.GetHead(1);

    primaryHead.mWindowed = true;
    secondaryHead.mWindowed = true;
    primaryHead.mWidth = ClampAtLeast(moho::wnd_DefaultCreateWidth, ParseIntegerArg(options[0]));
    primaryHead.mHeight = ClampAtLeast(moho::wnd_DefaultCreateHeight, ParseIntegerArg(options[1]));

    if (options.size() == 4) {
      secondaryHead.mWidth = ClampAtLeast(moho::wnd_DefaultCreateWidth, ParseIntegerArg(options[2]));
      secondaryHead.mHeight = ClampAtLeast(moho::wnd_DefaultCreateHeight, ParseIntegerArg(options[3]));
    } else {
      secondaryHead.mWidth = primaryHead.mWidth;
      secondaryHead.mHeight = primaryHead.mHeight;
    }

    moho::sAdapterNotCLOverridden = 0;
  } else if (TryGetFullscreenOptionArgs(&options)) {
    primaryHead.mWindowed = true;
    primaryHead.mWidth = ClampAtLeast(moho::wnd_DefaultCreateWidth, ParseIntegerArg(options[0]));
    primaryHead.mHeight = ClampAtLeast(moho::wnd_DefaultCreateHeight, ParseIntegerArg(options[1]));
    moho::sAdapterNotCLOverridden = 0;
  } else if (TryGetWindowedOptionArgs(&options)) {
    primaryHead.mWindowed = false;
    primaryHead.mWidth = ClampAtLeast(moho::wnd_MinCmdLineWidth, ParseIntegerArg(options[0]));
    primaryHead.mHeight = ClampAtLeast(moho::wnd_MinCmdLineHeight, ParseIntegerArg(options[1]));
    moho::sAdapterNotCLOverridden = 0;
    windowedByCommandLine = true;
    secondarySetupMode = true;
  } else {
    secondarySetupMode = true;

    const msvc8::string secondaryAdapter = moho::OPTIONS_GetString("secondary_adapter");
    const msvc8::string primaryAdapter = moho::OPTIONS_GetString("primary_adapter");

    if (!IsDisabledAdapterToken(secondaryAdapter) && !IsWindowedAdapterToken(primaryAdapter)) {
      context.AddHead(gpg::gal::Head{});
      gpg::gal::Head& secondaryHead = context.GetHead(1);
      primaryHead.mWindowed = true;
      secondaryHead.mWindowed = true;

      moho::ResolutionTriple primaryResolution{};
      if (moho::CFG_ParseResolutionTriple(primaryAdapter.c_str(), &primaryResolution)) {
        primaryHead.mWidth = static_cast<std::uint32_t>(primaryResolution.width);
        primaryHead.mHeight = static_cast<std::uint32_t>(primaryResolution.height);
        primaryHead.framesPerSecond = static_cast<std::uint32_t>(primaryResolution.framesPerSecond);
      }

      moho::ResolutionTriple secondaryResolution{};
      if (moho::CFG_ParseResolutionTriple(secondaryAdapter.c_str(), &secondaryResolution)) {
        secondaryHead.mWidth = static_cast<std::uint32_t>(secondaryResolution.width);
        secondaryHead.mHeight = static_cast<std::uint32_t>(secondaryResolution.height);
        secondaryHead.framesPerSecond = static_cast<std::uint32_t>(secondaryResolution.framesPerSecond);
      }
    } else if (!IsWindowedAdapterToken(primaryAdapter)) {
      moho::ResolutionTriple primaryResolution{};
      if (moho::CFG_ParseResolutionTriple(primaryAdapter.c_str(), &primaryResolution)) {
        primaryHead.mWindowed = true;
        primaryHead.mWidth = static_cast<std::uint32_t>(primaryResolution.width);
        primaryHead.mHeight = static_cast<std::uint32_t>(primaryResolution.height);
        primaryHead.framesPerSecond = static_cast<std::uint32_t>(primaryResolution.framesPerSecond);
      }
    } else {
      primaryHead.mWindowed = false;
      const msvc8::string widthKey("Windows.Main.width");
      const msvc8::string heightKey("Windows.Main.height");
      primaryHead.mWidth = static_cast<std::uint32_t>(
        preferences != nullptr
          ? preferences->GetInteger(widthKey, moho::wnd_DefaultCreateWidth)
          : moho::wnd_DefaultCreateWidth
      );
      primaryHead.mHeight = static_cast<std::uint32_t>(
        preferences != nullptr
          ? preferences->GetInteger(heightKey, moho::wnd_DefaultCreateHeight)
          : moho::wnd_DefaultCreateHeight
      );
    }
  }

  if (context.GetHeadCount() == 1 &&
      moho::CFG_GetArgOptionAliases(moho::CFG_GetAdapterOptionAliases(), 1, &options) &&
      !options.empty()) {
    context.mAdapter = ParseIntegerArg(options[0]);
  }

  const bool hasMaximizeOption = moho::CFG_HasMaximizeOption();
  if (hasMaximizeOption) {
    moho::sAdapterNotCLOverridden = 0;
  }

  const bool maximizeFromPrefs = preferences != nullptr
                                 && preferences->GetBoolean(msvc8::string("Windows.Main.maximized"), false);
  const bool maximized = !windowedByCommandLine && !primaryHead.mWindowed && (hasMaximizeOption || maximizeFromPrefs);

  if (!primaryHead.mWindowed) {
    if (moho::CFG_GetArgOption("/position", 2, &options) && options.size() >= 2) {
      position.x = ParseIntegerArg(options[0]);
      position.y = ParseIntegerArg(options[1]);
    } else if (preferences != nullptr) {
      position.x = preferences->GetInteger(msvc8::string("Windows.Main.x"), position.x);
      position.y = preferences->GetInteger(msvc8::string("Windows.Main.y"), position.y);
    }

    ClampPositionToMonitor(&position);
  }

  const std::int32_t packedAntiAliasing = moho::OPTIONS_GetInt("antialiasing");
  ApplyPackedAntiAliasing(primaryHead, packedAntiAliasing);
  if (context.GetHeadCount() > 1) {
    ApplyPackedAntiAliasing(context.GetHead(1), packedAntiAliasing);
  }

  if (!CreateAppFrame(title, maximized, position, context)) {
    gpg::gal::DeviceContext fallbackContext(useD3D10 ? 2 : 1);
    context = fallbackContext;

    gpg::gal::Head fallbackHead{};
    fallbackHead.mWindowed = true;
    fallbackHead.mWidth = static_cast<std::uint32_t>(moho::wnd_DefaultCreateWidth);
    fallbackHead.mHeight = static_cast<std::uint32_t>(moho::wnd_DefaultCreateHeight);
    context.AddHead(fallbackHead);

    if (!CreateAppFrame(title, false, position, context)) {
      return false;
    }
  }

  (void)gpg::gal::Device::GetInstance();
  moho::SetupPrimaryAdapterSettings();
  moho::SetupSecondaryAdapterSettings(secondarySetupMode);
  moho::CreateFidelityPresets();
  moho::SetupFidelitySettings();
  moho::SetupShadowQualitySettings();
  moho::SetupAntiAliasingSettings();
  moho::SetupBasicMovieManager();
  moho::OPTIONS_Apply();

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  (void)device->GetDeviceContext();
  return true;
}

/**
 * Address: 0x008CF8C0 (FUN_008CF8C0)
 * Mangled:
 * ?CreateAppFrame@CScApp@@AAE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_NABVwxPoint@@AAVDeviceContext@gal@gpg@@@Z
 *
 * What it does:
 * Creates primary/secondary frame windows, viewport bindings, and D3D
 * bootstrap handoff for the startup render path.
 */
bool CScApp::CreateAppFrame(
  const msvc8::string& title,
  const bool maximized,
  const wxPoint& position,
  gpg::gal::DeviceContext& context
)
{
  auto handleFailure = [this](const char* const reason) -> bool {
    moho::WINX_ExitSplash();
    DestroyFrameWindow(frame);
    DestroySupComFrameWindow(supcomFrame);
    moho::WIN_SetMainWindow(nullptr);

    if (wxTheApp != nullptr) {
      while (wxTheApp->Pending()) {
        wxTheApp->Dispatch();
      }
    }

    if (reason != nullptr && reason[0] != '\0') {
      gpg::Warnf("GAL Exception: %s", reason);
    }
    return false;
  };

  try {
    gpg::gal::Head& primaryHead = context.GetHead(0);
    const std::int32_t frameStyle = primaryHead.mWindowed ? kFullscreenFrameStyle : kWindowedFrameStyle;

    const wxSize primarySize{
      static_cast<std::int32_t>(primaryHead.mWidth),
      static_cast<std::int32_t>(primaryHead.mHeight),
    };

    frame = nullptr;
    supcomFrame = WX_CreateSupComFrame(title.c_str(), position, primarySize, frameStyle);

    if (primaryHead.mWindowed) {
      supcomFrame->Show(false);
    } else {
      if (maximized) {
        supcomFrame->Maximize(true);
      } else {
        supcomFrame->DoSetClientSize(primarySize.x, primarySize.y);

        std::int32_t appliedWidth = 0;
        std::int32_t appliedHeight = 0;
        supcomFrame->DoGetClientSize(&appliedWidth, &appliedHeight);
        if (appliedWidth != primarySize.x || appliedHeight != primarySize.y) {
          gpg::Warnf(
            "Unable to set requested size %i,%i. Results are undefined.", primarySize.x, primarySize.y
          );
        }
      }

      if (!moho::CFG_GetArgOption("/splash", 0, nullptr)) {
        moho::WINX_ExitSplash();
      }
      supcomFrame->Show(true);
    }

    if (!primaryHead.mWindowed && maximized) {
      std::int32_t maximizedWidth = 0;
      std::int32_t maximizedHeight = 0;
      supcomFrame->DoGetClientSize(&maximizedWidth, &maximizedHeight);
      primaryHead.mWidth = static_cast<std::uint32_t>(maximizedWidth);
      primaryHead.mHeight = static_cast<std::uint32_t>(maximizedHeight);
    }

    moho::WIN_SetMainWindow(supcomFrame);

    std::int32_t clientWidth = 0;
    std::int32_t clientHeight = 0;
    moho::sMainWindow->DoGetClientSize(&clientWidth, &clientHeight);

    const wxSize viewportSize{clientWidth, clientHeight};
    const bool hasSecondHead = context.GetHeadCount() > 1;
    moho::WD3DViewport* const viewport = moho::REN_CreateGameViewport(
      moho::sMainWindow, title.c_str(), viewportSize, hasSecondHead
    );

    primaryHead.mHandle = reinterpret_cast<void*>(static_cast<std::uintptr_t>(viewport->m_parent->GetHandle()));
    primaryHead.mWindow = reinterpret_cast<void*>(static_cast<std::uintptr_t>(viewport->GetHandle()));

    if (hasSecondHead) {
      gpg::gal::Head& secondaryHead = context.GetHead(1);
      const wxSize secondarySize{
        static_cast<std::int32_t>(secondaryHead.mWidth),
        static_cast<std::int32_t>(secondaryHead.mHeight),
      };

      frame = WX_CreateSupComFrame(title.c_str(), position, secondarySize, frameStyle);
      frame->Show(!secondaryHead.mWindowed);
      secondaryHead.mHandle = primaryHead.mHandle;
      secondaryHead.mWindow = reinterpret_cast<void*>(static_cast<std::uintptr_t>(frame->GetHandle()));
    }

    moho::wxPaintEventRuntime paintEvent{};
    viewport->OnPaint(paintEvent);

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    device->Clear2(true);

    context.mValidate = !moho::CFG_GetArgOption("/novalidate", 0, nullptr);
    moho::CreateDeviceD3D(&context);

    device->SetRenViewport(viewport);
    device->Clear2(false);

    moho::WINX_ExitSplash();
    supcomFrame->Show(true);
    if (frame != nullptr) {
      frame->Show(true);
    }

    moho::ren_Viewport = viewport;
    viewport->SetFocus();
    moho::WINX_PrecreateLogWindow();

    if (moho::IUIManager* const uiManager = moho::UI_GetManager()) {
      uiManager->AddFrame(viewport, supcomFrame);
      if (frame != nullptr) {
        uiManager->AddFrame(frame, frame);
      }
    }

    return true;
  } catch (const gpg::gal::Error& error) {
    std::ostringstream formatted;
    formatted << "file : " << error.GetRuntimeMessage() << "(" << error.GetRuntimeLine() << ")\n";
    formatted << "error: " << error.what();
    const std::string text = formatted.str();
    return handleFailure(text.c_str());
  } catch (const std::exception& exception) {
    return handleFailure(exception.what());
  } catch (...) {
    return handleFailure("unknown exception");
  }
}

/**
 * Address: 0x008CE1D0 (FUN_008CE1D0, CScApp::HasFrame)
 * Mangled: ?AppDoSuppressWindowsKeys@CScApp@@UBE_NXZ
 *
 * What it does:
 * Returns whether low-level keyboard suppression should be active.
 */
bool CScApp::AppDoSuppressWindowsKeys() const
{
  if (!gpg::gal::DeviceAppView::IsReady()) {
    return false;
  }

  auto* const device = gpg::gal::DeviceAppView::GetInstance();
  if (device == nullptr) {
    return false;
  }

  auto* const context = device->GetDeviceContext();
  if (context == nullptr) {
    return false;
  }

  if (!context->GetHead(0).windowed) {
    return false;
  }

  if (supcomFrame == nullptr) {
    return false;
  }

  return moho::WxAppRuntime::IsSupComFrameWindowActive(supcomFrame);
}
