#ifndef GPG_CORE_DIAGNOSTICS_CRASHHOOKS_H
#define GPG_CORE_DIAGNOSTICS_CRASHHOOKS_H

#include <cstddef>

namespace gpg::diag
{

  /**
   * Options for the CRT/SEH diagnostic hooks, resolved by the caller
   * (`moho::WinMain`) so the gpg core layer stays free of engine
   * command-line dependencies.
   */
  struct CrtDiagOptions
  {
    /**
     * `/heapcheck`: turn on periodic CRT heap validation. The validation
     * interval is still selected through FAF_HEAPCHECK_EVERY (1/16/128/1024,
     * default 1024).
     */
    bool enableHeapCheck = false;
  };

  /**
   * Installs the diagnostic hooks that keep a faulting process observable:
   * CRT report/invalid-parameter capture, SIGABRT/std::terminate/purecall
   * handlers, and a first-chance vectored exception handler that logs fault
   * records with symbolised stacks into faf_diag.log beside the executable.
   *
   * Every hook is log-only: the vectored handler always continues the
   * exception search and the CRT handlers fall through to the CRT's own
   * reporting, so behaviour is unchanged apart from the log records.
   */
  void InstallCrtDiagnosticHooks(const CrtDiagOptions& options = {});

  /** Log file path beside the executable (faf_diag.log). */
  const char* DiagLogPath();

  /** Appends one line to faf_diag.log; open/write/close, crash-safe. */
  void DiagLine(const char* format, ...);

  /** Captures and symbolises the current thread's stack into faf_diag.log. */
  void DiagLogStack(const char* tag);

  /**
   * Formats one address as `module+RVA [symbol+offset (file:line)]`.
   * Always produces module+RVA even without symbols; truncates instead of
   * aborting when a name would overflow (see the sprintf_s note in the .cpp).
   */
  void DiagDescribeAddress(const void* address, char* out, std::size_t outBytes);

  /** True when dbghelp is initialized for this process (lazy, once). */
  bool DiagSymbolsReady();

} // namespace gpg::diag

#endif // GPG_CORE_DIAGNOSTICS_CRASHHOOKS_H
