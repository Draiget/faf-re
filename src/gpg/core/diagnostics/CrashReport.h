#ifndef GPG_CORE_DIAGNOSTICS_CRASHREPORT_H
#define GPG_CORE_DIAGNOSTICS_CRASHREPORT_H

#include <cstdio>

struct _EXCEPTION_POINTERS;

namespace gpg::diag
{

  /** Fault context handed to crash-section writers. */
  struct CrashSectionInfo
  {
    /** SEH exception address, null on non-SEH fatal paths. */
    const void* faultAddress = nullptr;
    /** Access-violation target address (read/write), null otherwise. */
    const void* accessTarget = nullptr;
  };

  /**
   * Callback that appends one named section to the crash report (sim state,
   * Lua stacks, ...). Registered by engine layers at startup; invoked only on
   * the crash path, with a `std::FILE*` sink already positioned inside the
   * section header.
   */
  using CrashSectionWriter = void (*)(std::FILE* sink, const CrashSectionInfo& info);

  /**
   * Section placement: sections with priority below kAfterModulesPriority run
   * between Registers and Threads (game context reads better there than
   * buried under hundreds of stack lines); the rest run after Modules.
   * Lower priority runs earlier within each group.
   */
  constexpr int kAfterModulesPriority = 500;

  /** Registers one extra report section (max 8, priority order). */
  void AddCrashSection(const char* name, CrashSectionWriter writer, int priority = kAfterModulesPriority);

  struct CrashReportContext
  {
    /** SEH exception being handled, or null for non-SEH fatal paths. */
    _EXCEPTION_POINTERS* exceptionInfo = nullptr;
    /** Non-SEH cause: engine Die() message, "std::terminate", "pure virtual call"... */
    const char* reason = nullptr;
  };

  /** Report file path: `<exe dir>\faf_crash_YYYYMMDD_HHMMSS.txt` (per crash). */
  const char* CrashReportPath();

  /** Stable copy of the newest report: `<exe dir>\faf_crash_latest.txt`. */
  const char* CrashLatestReportPath();

  /** Minidump path: this run's report stem with `.dmp` (mirrored to latest). */
  const char* CrashDumpPath();

  /**
   * Writes the full crash report: build/process/system header, exception,
   * registers, all-thread symbolised stacks, module list, registered
   * sections, recent log lines. Crash-safe: one file handle, flushed per
   * line; re-entering while a report is being written is a no-op.
   */
  bool WriteCrashReport(const CrashReportContext& context);

  /**
   * One fatal path end-to-end: write the report, write the minidump, show
   * the crash-report dialog. The dialog appears only on the call that
   * actually wrote the report - nested fatals (abort after terminate) stay
   * silent so the user never sees two dialogs. Use for every non-SEH fatal
   * path (engine Die, std::terminate, purecall, abort) so all of them leave
   * the same visible, copyable record.
   */
  void HandleFatalPath(const CrashReportContext& context);

  /**
   * Writes `<exe dir>\faf_crash.dmp` via MiniDumpWriteDump. On by default;
   * set FAF_MINIDUMP=0 to disable. (Operator decision 2026-10-13: the dump
   * is what answers the questions the text report cannot.)
   */
  bool WriteCrashMinidump(_EXCEPTION_POINTERS* exceptionInfo);

  /**
   * Engine addition, debugging aid (default off): a sim Lua script error was just logged.
   *
   * With `FAF_DUMP_ON_SIM_LUA_ERROR=<n>` (n >= 1) the first n errors whose text contains none
   * of the `;`-separated substrings in `FAF_DUMP_ON_SIM_LUA_ERROR_IGNORE` each write a
   * full-memory minidump `<exe dir>\faf_luaerr_<time>_<k>.dmp` and the error text (with its
   * traceback) beside it as `.txt`; the run then continues. The heap at the moment a corrupted
   * object first surfaces in Lua is usually the best evidence of what corrupted it. Without the
   * variable this is one cached test.
   */
  void NoteSimLuaError(const char* message);

  /**
   * Copies the report text to the clipboard (CF_UNICODETEXT, no CRT heap).
   * Client only (CrashReportDialog.cpp).
   */
  void CopyCrashReportToClipboard();

  /**
   * Modal crash dialog built from an in-memory template (no resource
   * dependency): read-only report text + Copy / Open folder / Close.
   * Falls back to a message box when even that fails. Client only
   * (CrashReportDialog.cpp).
   */
  void ShowCrashReportDialog(const char* reportPath);

  /**
   * Engine addition (dedicated-server plan WPR.12): the dialog the fatal path
   * shows after writing the report and the minidump. CrashReportDialog.cpp sets
   * it to ShowCrashReportDialog during static initialisation; a program without
   * the client (headless, the game server) leaves it null and ends without a
   * dialog.
   */
  using CrashReportDialogHook = void (*)(const char* reportPath);
  extern CrashReportDialogHook sCrashReportDialog;

} // namespace gpg::diag

#endif // GPG_CORE_DIAGNOSTICS_CRASHREPORT_H
