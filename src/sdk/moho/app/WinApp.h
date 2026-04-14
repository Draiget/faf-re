#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "moho/task/CTaskThread.h"

struct _EXCEPTION_POINTERS;
class wxWindowBase;
class wxString;

namespace moho
{
  class CWaitHandleSet;
  class IWinApp;

  struct SPlatSymbolInfo
  {
    // +0x00
    std::uint32_t addr;
    // +0x04
    msvc8::string symbol;
    // +0x20
    std::uint32_t symDis;
    // +0x24
    msvc8::string filename;
    // +0x40
    std::uint32_t lineNum;
    // +0x44
    std::uint32_t lineDis;

    /**
     * What it does:
     * Formats one resolved symbol line as:
     * `symbol + symDis bytes (file(lineNum) + lineDis bytes)`.
     */
    [[nodiscard]] msvc8::string FormatResolvedLine() const;
  };

  static_assert(offsetof(SPlatSymbolInfo, addr) == 0x00, "SPlatSymbolInfo::addr offset must be 0x00");
  static_assert(offsetof(SPlatSymbolInfo, symbol) == 0x04, "SPlatSymbolInfo::symbol offset must be 0x04");
  static_assert(offsetof(SPlatSymbolInfo, symDis) == 0x20, "SPlatSymbolInfo::symDis offset must be 0x20");
  static_assert(offsetof(SPlatSymbolInfo, filename) == 0x24, "SPlatSymbolInfo::filename offset must be 0x24");
  static_assert(offsetof(SPlatSymbolInfo, lineNum) == 0x40, "SPlatSymbolInfo::lineNum offset must be 0x40");
  static_assert(offsetof(SPlatSymbolInfo, lineDis) == 0x44, "SPlatSymbolInfo::lineDis offset must be 0x44");
  static_assert(sizeof(SPlatSymbolInfo) == 0x48, "SPlatSymbolInfo size must be 0x48");

  /**
   * Address: 0x004F2480
   */
  CTaskStage* WIN_GetBeforeEventsStage();

  /**
   * Address: 0x004F24F0
   */
  CTaskStage* WIN_GetBeforeWaitStage();

  /**
   * Address: 0x004F2420 (FUN_004F2420, Moho::WIN_GetWaitHandleSet)
   *
   * What it does:
   * Returns one process-lifetime wait-handle set singleton used by the main
   * message/event wait lanes.
   *
   */
  CWaitHandleSet* WIN_GetWaitHandleSet();

  /**
   * Address: 0x004F20B0 (FUN_004F20B0)
   *
   * IWinApp *
   *
   * What it does:
   * Drives app bootstrap, frame pumping, and shutdown around the IWinApp interface.
   */
  void WIN_AppExecute(IWinApp* app);

  /**
   * Address: 0x004F1FC0 (called via Main-frame timing paths)
   *
   * What it does:
   * Requests that the main wait loop wake no later than `milliseconds` from now.
   */
  void WIN_SetWakeupTimer(float milliseconds);

  /**
   * Address: 0x004A2150 (FUN_004A2150)
   *
   * What it does:
   * Initializes symbol-handler state and process-wide platform mutex.
   * Uses DbgHelp options:
   * `SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_LOAD_LINES |
   *  SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME` (`0x216`).
   */
  void PLAT_Init();

  /**
   * Address: 0x004A2D30 (FUN_004A2D30)
   *
   * What it does:
   * Installs the engine top-level SEH filter.
   */
  void PLAT_CatchStructuredExceptions();

  /**
   * Address: 0x004A2210 (FUN_004A2210)
   *
   * What it does:
   * Tears down symbol-handler state initialized by `PLAT_Init`.
   */
  void PLAT_Exit();

  /**
   * Address: 0x004A0FC0 (FUN_004A0FC0)
   * Mangled: ?PLAT_InitErrorReportOutputDir@Moho@@YAXPB_W@Z
   *
   * What it does:
   * Sets the directory root used for crash-report attachments and normalizes
   * a trailing path separator.
   */
  void PLAT_InitErrorReportOutputDir(const wchar_t* outputDir);

  /**
   * Address: 0x004A0ED0 (FUN_004A0ED0)
   * Mangled: ?PLAT_RegisterFileForErrorReport@Moho@@YAXPB_W@Z
   *
   * What it does:
   * Adds one wide-path attachment to the crash-report file list when it is
   * non-empty and not already present.
   */
  void PLAT_RegisterFileForErrorReport(const wchar_t* file);

  /**
   * Address: 0x004A1230 (FUN_004A1230)
   * Mangled: ?PLAT_CreateGameLogForReport@Moho@@YAXXZ
   *
   * What it does:
   * Persists recent in-memory log lines into a `.sclog` file under the current
   * report directory and registers that file for crash attachments.
   */
  void PLAT_CreateGameLogForReport();

  /**
   * Address: 0x0047A4F0 (FUN_0047A4F0)
   * Mangled:
   * ?LOG_GetRecentLines@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
   *
   * What it does:
   * Returns UTF-8 text containing recent log-history lines for crash/report
   * output flows.
   */
  msvc8::string LOG_GetRecentLines(std::uint32_t maxLines);

  /**
   * Address: 0x004A22B0 (FUN_004A22B0)
   * Mangled: ?PLAT_GetCallStack@Moho@@YAIPAXIPAI@Z
   *
   * What it does:
   * Captures up to `maxFrames` return addresses from the supplied CPU context
   * (or current thread context when null).
   */
  std::uint32_t PLAT_GetCallStack(void* contextRecord, std::uint32_t maxFrames, std::uint32_t* outFrames);

  /**
   * Address: 0x004A2440 (FUN_004A2440)
   * Mangled: ?PLAT_GetSymbolInfo@Moho@@YA_NIAAUSPlatSymbolInfo@1@@Z
   *
   * What it does:
   * Resolves one callstack address into symbol/file/line metadata when available.
   */
  bool PLAT_GetSymbolInfo(std::uint32_t address, SPlatSymbolInfo* outInfo);

  /**
   * Address: 0x004A26E0 (FUN_004A26E0)
   * Mangled:
   * ?PLAT_FormatCallstack@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@HHPBI@Z
   *
   * What it does:
   * Formats callstack entries from `[firstFrame, endFrame)` into text lines.
   */
  msvc8::string PLAT_FormatCallstack(std::int32_t firstFrame, std::int32_t endFrame, const std::uint32_t* frames);

  /**
   * Address: 0x004A25D0 (FUN_004A25D0)
   * Mangled:
   * ?PLAT_UnDecorateSymbolName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBD_N@Z
   *
   * What it does:
   * Converts one decorated symbol into undecorated text under the shared
   * symbol-handler mutex, with optional underscore-stripping mode.
   */
  msvc8::string PLAT_UnDecorateSymbolName(const char* name, bool stripLeadingUnderscore);

  /**
   * Address: 0x004A1F10 (FUN_004A1F10)
   *
   * What it does:
   * Writes one registry value at `keyPath` using raw byte payload and explicit
   * registry value type.
   */
  bool PLAT_SetRegistryValue(
    const char* keyPath, const std::uint8_t* data, std::uint32_t dataSize, std::uint32_t valueType
  );

  /**
   * Address: 0x004A2F60 (FUN_004A2F60)
   *
   * What it does:
   * Writes one 32-bit DWORD registry value.
   */
  bool PLAT_SetRegistryValueDword(const char* keyPath, std::uint32_t value);

  /**
   * Address: 0x004A2F80 (FUN_004A2F80)
   *
   * What it does:
   * Writes one zero-terminated string registry value; null input writes an
   * empty string payload.
   */
  bool PLAT_SetRegistryValueString(const char* value, const char* keyPath);

  /**
   * Address: 0x004A2D40 (FUN_004A2D40)
   *
   * What it does:
   * Reads one registry value payload into `outData` and returns byte count read.
   * Binary behavior clamps read size to 0x100 bytes.
   */
  std::uint32_t PLAT_GetRegistryValue(const char* keyPath, void* outData, std::uint32_t maxDataBytes);

  /**
   * Address: 0x004F25D0 (FUN_004F25D0)
   * Mangled:
   * ?WIN_GetClipboardText@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
   *
   * What it does:
   * Reads UTF-16 clipboard text from `CF_UNICODETEXT`, converts it to UTF-8,
   * and returns empty text when clipboard ownership/data is unavailable.
   */
  msvc8::string WIN_GetClipboardText();

  /**
   * Address: 0x004F2800 (FUN_004F2800, ?WIN_OkBox@Moho@@YAXVStrArg@gpg@@0@Z)
   *
   * What it does:
   * Displays a UTF-8 message box using the active engine main window as owner
   * when available.
   */
  void WIN_OkBox(gpg::StrArg caption, gpg::StrArg text);

  /**
   * Address: 0x004F2900 (FUN_004F2900, ?WIN_YesNoBox@Moho@@YA_NVStrArg@gpg@@0@Z)
   *
   * What it does:
   * Displays a UTF-8 yes/no message box and returns true only when the user
   * picks `IDYES`.
   */
  bool WIN_YesNoBox(gpg::StrArg caption, gpg::StrArg text);

  /**
   * Address: 0x004F2A00 (FUN_004F2A00)
   * Mangled:
   * ?WIN_GetLastError@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
   *
   * What it does:
   * Converts current `GetLastError()` value into readable UTF-8 text.
   */
  msvc8::string WIN_GetLastError();

  /**
   * Address: 0x004F1190 (FUN_004F1190)
   * Mangled: ?WIN_ShowCrashDialog@Moho@@YAXPBD0PAU_EXCEPTION_POINTERS@@H@Z
   *
   * What it does:
   * Builds crash-details text (program, args, callstack, recent log lines) and
   * displays the crash dialog UI/fallback prompt.
   */
  void WIN_ShowCrashDialog(
    std::int32_t skipCallstackFrames,
    _EXCEPTION_POINTERS* exceptionInfo,
    gpg::StrArg caption,
    gpg::StrArg summaryText
  );

  /**
   * Address: 0x004F3A60 (FUN_004F3A60, ?WINX_Exit@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys all managed dialog/frame windows and unlinks their registry slots.
   */
  void WINX_Exit();

  /**
   * Address: 0x004F3B60 (FUN_004F3B60, ?WINX_Printf@Moho@@YA?AVwxString@@PBDZZ)
   *
   * What it does:
   * Formats one UTF-8 vararg string, converts it to UTF-16, and writes the
   * result into caller-provided `wxString` storage.
   */
  wxString* WINX_Printf(wxString* out, const char* format, ...);

  /**
   * Address: 0x004F3CE0 (FUN_004F3CE0)
   * Mangled: ?WINX_InitSplash@Moho@@YAXVStrArg@gpg@@@Z
   *
   * What it does:
   * Loads splash image content and replaces the active splash-screen runtime.
   */
  void WINX_InitSplash(gpg::StrArg filename);

  /**
   * Address: 0x004F67E0 (FUN_004F67E0)
   * Mangled: ?WINX_PrecreateLogWindow@Moho@@YAXXZ
   *
   * What it does:
   * Ensures the log dialog window object exists before first use.
   */
  void WINX_PrecreateLogWindow();

  /**
   * Address: 0x004F3F30 (FUN_004F3F30)
   * Mangled: ?WINX_ExitSplash@Moho@@YAXXZ
   *
   * What it does:
   * Destroys and clears active splash-screen state.
   */
  void WINX_ExitSplash();

  /**
   * Address: 0x00BC7260 (FUN_00BC7260, register_wxAppFactory)
   *
   * What it does:
   * Replays the bootstrap app-factory registration lane used by the process
   * startup initializer.
   */
  void register_wxAppFactory();

  /**
   * Address: 0x00BC7240 (FUN_00BC7240, register_wakeupTimer)
   *
   * What it does:
   * Restores the wakeup timer duration lane to the process-default infinity
   * value used at startup.
   */
  void register_wakeupTimer();

  /**
   * Address: 0x00BC7230 (FUN_00BC7230, register_startTime)
   *
   * What it does:
   * Re-initializes the shared wakeup timer baseline used by the main loop.
   */
  void register_startTime();

  /**
   * Address: 0x00BC7310 (FUN_00BC7310, wxNewEventType init)
   *
   * What it does:
   * Allocates and stores the process-wide custom wx event type token used by
   * this bootstrap lane.
   */
  int register_WinAppEventType();

  /**
   * Address: 0x00BC7320 (FUN_00BC7320, register_managedWindowsCleanup)
   *
   * What it does:
   * Installs process-exit cleanup for the managed-dialog slot vector storage.
   */
  int register_managedWindowsCleanup();

  /**
   * Address: 0x00BC7330 (FUN_00BC7330, register_managedFramesCleanup)
   *
   * What it does:
   * Installs process-exit cleanup for the managed-frame slot vector storage.
   */
  int register_managedFramesCleanup();

  /**
   * Address: 0x00BC7340 (FUN_00BC7340, register_winLogTarget)
   *
   * What it does:
   * Touches the global log-target owner during startup so the source-side
   * lifetime model stays aligned with the recovered binary lane.
   */
  void register_winLogTarget();

  /**
   * Address: 0x00BC73E0 (FUN_00BC73E0, register_splashScreen)
   *
   * What it does:
   * Installs splash-screen process-exit cleanup for the startup lane.
   */
  void register_splashScreen();

  /**
   * Recovered helper used by startup/shutdown ownership handoff.
   */
  void WIN_SetMainWindow(wxWindowBase* mainWindow);
} // namespace moho
