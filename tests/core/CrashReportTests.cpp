// The crash report writer without a crash: Windows (src/gpg/core/diagnostics/CrashReport.cpp) writes a report from
// a made-up access violation beside this test program (<exe dir>\faf_crash_<time>.txt, mirrored to
// faf_crash_latest.txt), with one registered section before the thread stacks and one after, then the minidump;
// POSIX (gpg/core/diagnostics/posix/DiagnosticsPosix.cpp) writes its text report. On both, that fatal report comes
// from another thread while a failed assertion's report is being written: it waits for it, and the assertion's
// report keeps a name of its own (faf_crash_<time>_assert.txt), as the game goes on after one. Once a fatal report
// is written the writer refuses every later one for the rest of the process, so everything is one test.

#include "platform/PlatformDefines.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <print>
#include <sstream>
#include <string>
#include <thread>
#include <gtest/gtest.h>

#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Global.h"

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>
#endif

namespace
{
  /// What the die handler saw, from both threads: a report is written for every assertion that fails while none is
  /// being written.
  struct DieHandlerLog
  {
    std::atomic<int> calls = 0;
    std::atomic<int> written = 0;
    std::atomic<int> nestedWritten = 0; // assertions inside a report being written whose report was written

    void Reset()
    {
      calls = 0;
      written = 0;
      nestedWritten = 0;
    }
  };
  DieHandlerLog gDieLog{};
  thread_local bool tInSection = false;

  /// The fatal report the asserting section starts on another thread, and its result (read after the join).
  const gpg::diag::CrashReportContext* gFatalCrash = nullptr;
  std::thread gFatalThread;
  bool gFatalWritten = false;
  std::string gFatalReportPath;
  std::string gAssertReportPath; // seen inside the assertion's report, while it holds the writer

  /// The game's die handler, minus the dialog: the report for the message.
  void WriteReportForDie(
    const char* const message
  )
  {
    ++gDieLog.calls;
    gpg::diag::CrashReportContext context{};
    context.reason = message;
    if (gpg::diag::WriteCrashReport(context)) {
      ++gDieLog.written;
      if (tInSection) {
        ++gDieLog.nestedWritten;
      }
    }
  }

  /// A section whose writer fails an assertion, as engine code reached from a section can: that report is refused.
  /// In the first report (the assertion's) it also starts the fatal report on another thread, which must wait.
  void AssertingSection(
    std::FILE* sink,
    const gpg::diag::CrashSectionInfo&
  )
  {
    std::println(sink, "asserting section");
    tInSection = true;
    gpg::HandleAssertFailure("inside a report", 1, "CrashReportTests.cpp");
    tInSection = false;

    if (gFatalCrash != nullptr && !gFatalThread.joinable()) {
      gAssertReportPath = gpg::diag::CrashReportPath();
      gFatalThread = std::thread([] {
        gFatalWritten = gpg::diag::WriteCrashReport(*gFatalCrash);
        gFatalReportPath = gpg::diag::CrashReportPath();
      });
      std::this_thread::sleep_for(std::chrono::milliseconds(200)); // the fatal report waits meanwhile
    }
  }

  std::string ReadAll(
    const char* path
  )
  {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
  }

  /// A failed assertion, a fatal report from another thread while the assertion's is written, then the paths:
  /// returns the assertion's report path.
  std::string ReportAnAssertionAndACrash(
    const gpg::diag::CrashReportContext& crash
  )
  {
    gFatalCrash = &crash;
    const gpg::die_handler_t previous = gpg::SetDieHandler(&WriteReportForDie);
    gpg::HandleAssertFailure("x == y", 42, "CrashReportTests.cpp");
    if (gFatalThread.joinable()) {
      gFatalThread.join();
    }
    (void)gpg::SetDieHandler(previous);
    gFatalCrash = nullptr;
    const std::string assertPath = gAssertReportPath;

    // The assertion, the one inside its report, and the one inside the fatal report: only the first one's written.
    EXPECT_EQ(gDieLog.calls, 3);
    EXPECT_EQ(gDieLog.written, 1);
    EXPECT_EQ(gDieLog.nestedWritten, 0);
    EXPECT_FALSE(gpg::TakeAssertFailureReport());
    gDieLog.Reset();

    EXPECT_TRUE(gFatalWritten) << "the fatal report after a failed assertion's report was refused";
    EXPECT_NE(assertPath.find("_assert.txt"), std::string::npos) << assertPath;
    EXPECT_EQ(gFatalReportPath.find("_assert"), std::string::npos) << gFatalReportPath;
    EXPECT_NE(gFatalReportPath, assertPath);
    return assertPath;
  }

  /// After the fatal report, nothing writes another: a second fatal one, or an assertion.
  void ExpectWriterClosed(
    const gpg::diag::CrashReportContext& crash
  )
  {
    EXPECT_FALSE(gpg::diag::WriteCrashReport(crash));
    const gpg::die_handler_t previous = gpg::SetDieHandler(&WriteReportForDie);
    gpg::HandleAssertFailure("after the crash", 7, "CrashReportTests.cpp");
    (void)gpg::SetDieHandler(previous);
    EXPECT_EQ(gDieLog.calls, 1);
    EXPECT_EQ(gDieLog.written, 0);
  }

#if FAFRE_PLATFORM_WINDOWS
  void EarlySection(
    std::FILE* sink,
    const gpg::diag::CrashSectionInfo& info
  )
  {
    std::println(sink, "early section, access target {}", info.accessTarget);
  }

  void LateSection(
    std::FILE* sink,
    const gpg::diag::CrashSectionInfo&
  )
  {
    std::println(sink, "late section text");
  }
#endif
} // namespace

#if FAFRE_PLATFORM_WINDOWS
TEST(
  CrashReport,
  WritesEverySectionForAnAccessViolation
)
{
  gpg::diag::AddCrashSection("Test early", &EarlySection, 10);
  gpg::diag::AddCrashSection("Test asserting", &AssertingSection, 20);
  gpg::diag::AddCrashSection("Test late", &LateSection, gpg::diag::kAfterModulesPriority + 10);

  CONTEXT context{};
  ::RtlCaptureContext(&context);
  EXCEPTION_RECORD record{};
  record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
  record.ExceptionAddress = reinterpret_cast<void*>(&ReadAll);
  record.NumberParameters = 2;
  record.ExceptionInformation[0] = 0; // a read
  record.ExceptionInformation[1] = 0x10;
  EXCEPTION_POINTERS pointers{&record, &context};
  gpg::diag::CrashReportContext crash{};
  crash.exceptionInfo = &pointers;

  const std::string assertPath = ReportAnAssertionAndACrash(crash);
  ASSERT_TRUE(gFatalWritten);
  const std::string assertReport = ReadAll(assertPath.c_str());
  EXPECT_NE(assertReport.find("Failed assertion: x == y"), std::string::npos);
  EXPECT_NE(assertReport.find("--- Test asserting ---"), std::string::npos);

  const std::string report = ReadAll(gpg::diag::CrashReportPath());
  ASSERT_FALSE(report.empty()) << gpg::diag::CrashReportPath();
  for (const char* part :
       {"=== FAF crash report ===",
        "--- Exception ---",
        "EXCEPTION_ACCESS_VIOLATION",
        "--- Test early ---",
        "early section, access target",
        "--- Test late ---",
        "late section text",
        "--- Log (recent) ---"}) {
    EXPECT_NE(report.find(part), std::string::npos) << "no \"" << part << "\" in the report";
  }
  // Game sections come before the thread stacks, later ones after the module list.
  EXPECT_LT(report.find("--- Test early ---"), report.find("--- Test late ---"));
  EXPECT_EQ(ReadAll(gpg::diag::CrashLatestReportPath()), report);

  ExpectWriterClosed(crash);

  ASSERT_TRUE(gpg::diag::WriteCrashMinidump(&pointers));
  std::error_code ignored;
  EXPECT_GT(std::filesystem::file_size(gpg::diag::CrashDumpPath(), ignored), 0u);

  for (const char* path :
       {assertPath.c_str(),
        gpg::diag::CrashReportPath(),
        gpg::diag::CrashLatestReportPath(),
        gpg::diag::CrashDumpPath()}) {
    std::filesystem::remove(path, ignored);
  }
  std::filesystem::path latestDump = gpg::diag::CrashLatestReportPath();
  latestDump.replace_extension(".dmp");
  std::filesystem::remove(latestDump, ignored);
}
#else
TEST(
  CrashReport,
  WritesTheFatalReportAfterAFailedAssertion
)
{
  gpg::diag::AddCrashSection("Test asserting", &AssertingSection, 20);

  gpg::diag::CrashReportContext crash{};
  crash.reason = "SIGSEGV (segmentation fault) at address 0x10";
  const std::string assertPath = ReportAnAssertionAndACrash(crash);
  ASSERT_TRUE(gFatalWritten);
  const std::string assertReport = ReadAll(assertPath.c_str());
  EXPECT_NE(assertReport.find("reason: Failed assertion: x == y"), std::string::npos) << assertReport;

  const std::string report = ReadAll(gpg::diag::CrashReportPath());
  EXPECT_NE(report.find("reason: SIGSEGV"), std::string::npos) << report;
  EXPECT_NE(report.find("== Test asserting =="), std::string::npos) << report;
  EXPECT_EQ(ReadAll(gpg::diag::CrashLatestReportPath()), report);

  ExpectWriterClosed(crash);

  std::error_code ignored;
  for (const char* path : {assertPath.c_str(), gpg::diag::CrashReportPath(), gpg::diag::CrashLatestReportPath()}) {
    std::filesystem::remove(path, ignored);
  }
}
#endif
