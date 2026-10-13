#ifndef GPG_CORE_DIAGNOSTICS_CRASHREPORT_H
#define GPG_CORE_DIAGNOSTICS_CRASHREPORT_H

#include <cstdio>

struct _EXCEPTION_POINTERS;

namespace gpg::diag
{

  /**
   * Callback that appends one named section to the crash report (sim state,
   * Lua stacks, ...). Registered by engine layers at startup; invoked only on
   * the crash path, with a `std::FILE*` sink already positioned inside the
   * section header.
   */
  using CrashSectionWriter = void (*)(std::FILE* sink);

  /** Registers one extra report section (max 8, first-registered order). */
  void AddCrashSection(const char* name, CrashSectionWriter writer);

  struct CrashReportContext
  {
    /** SEH exception being handled, or null for non-SEH fatal paths. */
    _EXCEPTION_POINTERS* exceptionInfo = nullptr;
    /** Non-SEH cause: engine Die() message, "std::terminate", "pure virtual call"... */
    const char* reason = nullptr;
  };

  /** Report file path: `<exe dir>\faf_crash.txt`. */
  const char* CrashReportPath();

  /** Minidump path: `<exe dir>\faf_crash.dmp` (written only when FAF_MINIDUMP is set). */
  const char* CrashDumpPath();

  /**
   * Writes the full crash report: build/process/system header, exception,
   * registers, all-thread symbolised stacks, module list, registered
   * sections, recent log lines. Crash-safe: one file handle, flushed per
   * line; re-entering while a report is being written is a no-op.
   */
  bool WriteCrashReport(const CrashReportContext& context);

  /**
   * Writes `<exe dir>\faf_crash.dmp` via MiniDumpWriteDump. Only called when
   * the FAF_MINIDUMP environment variable is set; returns false (and writes
   * nothing) otherwise.
   */
  bool WriteCrashMinidump(_EXCEPTION_POINTERS* exceptionInfo);

  /** Copies the report text to the clipboard (CF_UNICODETEXT, no CRT heap). */
  void CopyCrashReportToClipboard();

  /**
   * Modal crash dialog built from an in-memory template (no resource
   * dependency): read-only report text + Copy / Open folder / Close.
   * Falls back to a message box when even that fails.
   */
  void ShowCrashReportDialog(const char* reportPath);

} // namespace gpg::diag

#endif // GPG_CORE_DIAGNOSTICS_CRASHREPORT_H
