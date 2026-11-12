// The crash report writer (src/gpg/core/diagnostics/CrashReport.cpp) without a crash: one report from a made-up access
// violation, written beside this test program (<exe dir>\faf_crash_<time>.txt, mirrored to faf_crash_latest.txt),
// with one registered section before the thread stacks and one after, then the minidump. Windows only: the Linux
// build leaves CrashReport.cpp out (cmake/FafLinux.cmake). The writer runs once per process (a second report while
// one is written is refused, and the flag stays set), so everything is one test.

#include "platform/PlatformDefines.h"

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <gtest/gtest.h>

#include "gpg/core/diagnostics/CrashReport.h"

namespace
{
  void EarlySection(
    std::FILE* sink,
    const gpg::diag::CrashSectionInfo& info
  )
  {
    std::fprintf(sink, "early section, access target %p\n", info.accessTarget);
  }

  void LateSection(
    std::FILE* sink,
    const gpg::diag::CrashSectionInfo&
  )
  {
    std::fprintf(sink, "late section text\n");
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
} // namespace

TEST(
  CrashReport,
  WritesEverySectionForAnAccessViolation
)
{
  gpg::diag::AddCrashSection("Test early", &EarlySection, 10);
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
  ASSERT_TRUE(gpg::diag::WriteCrashReport(crash));

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

  // A second report in the same process is refused (the nested-fault guard stays set).
  EXPECT_FALSE(gpg::diag::WriteCrashReport(crash));

  ASSERT_TRUE(gpg::diag::WriteCrashMinidump(&pointers));
  std::error_code ignored;
  EXPECT_GT(std::filesystem::file_size(gpg::diag::CrashDumpPath(), ignored), 0u);

  for (const char* path :
       {gpg::diag::CrashReportPath(), gpg::diag::CrashLatestReportPath(), gpg::diag::CrashDumpPath()}) {
    std::filesystem::remove(path, ignored);
  }
  std::filesystem::path latestDump = gpg::diag::CrashLatestReportPath();
  latestDump.replace_extension(".dmp");
  std::filesystem::remove(latestDump, ignored);
}
#endif
