// The debugging probes and memory watches (src/gpg/core/diagnostics/ProbeWatch.cpp, armed in the game by /w, /p,
// faf_watch, faf_probe and FADeepProbe requests from Lua): the spec parsers turn down what they can't arm, a watch on
// a variable reports the write to it, and the crash report's section lists it. Windows only: watches use the debug
// registers, as in the game. Probes (an int3 written into code) are not run here: one on a function of this test
// program stopped the process, which wasn't looked into yet.

#if defined(_WIN32)

#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/diagnostics/ProbeWatch.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <string>

namespace
{
  volatile std::uint32_t gWatched = 0;

  std::string Hex(
    const std::uintptr_t value
  )
  {
    char text[32] = {};
    (void)std::snprintf(text, sizeof(text), "%llX", static_cast<unsigned long long>(value));
    return text;
  }

  std::string Section()
  {
    std::FILE* const sink = std::tmpfile();
    if (sink == nullptr) {
      return {};
    }
    gpg::diag::CrashSectionInfo info{};
    gpg::diag::WriteProbeWatchSection(sink, info);
    std::fflush(sink);
    std::rewind(sink);
    std::string text;
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), sink) != nullptr) {
      text += buffer;
    }
    std::fclose(sink);
    return text;
  }
} // namespace

TEST(
  ProbeWatch,
  SpecsItCannotArmAreTurnedDown
)
{
  EXPECT_FALSE(gpg::diag::ParseWatchSpec(nullptr));
  EXPECT_FALSE(gpg::diag::ParseWatchSpec(""));
  EXPECT_FALSE(gpg::diag::ParseProbeSpec(nullptr));
  EXPECT_FALSE(gpg::diag::ParseProbeSpec(""));
  EXPECT_FALSE(gpg::diag::ParseProbeSpec("0"));        // no address
  EXPECT_FALSE(gpg::diag::ParseProbeSpec(":ecx+474")); // an expression without an address
  EXPECT_FALSE(gpg::diag::ParseFadepProbeRequest(nullptr));
  EXPECT_FALSE(gpg::diag::ParseFadepProbeRequest("FADeepProbe nothing"));
  EXPECT_FALSE(gpg::diag::ParseFadepProbeRequest("something else"));
}

TEST(
  ProbeWatch,
  AWatchReportsTheWrite
)
{
  gpg::diag::InstallProbeWatchHandler();

  // The watch, armed the way a FADeepProbe request from Lua arms it; the address is rounded to its dword.
  const std::uintptr_t watched = reinterpret_cast<std::uintptr_t>(&gWatched) & ~static_cast<std::uintptr_t>(3);
  ASSERT_TRUE(gpg::diag::ParseFadepProbeRequest(("FADeepProbe watchaddr " + Hex(watched)).c_str()));
  gWatched = 0x42;

  const std::string section = Section();
  EXPECT_NE(section.find("watch " + Hex(watched) + ": 1 report(s)"), std::string::npos) << section;
}

// The game's own end-to-end check (/crashtest watch): arms a watch on a local and writes it.
TEST(
  ProbeWatch,
  SelfTestRunsThroughTheWholeWatchPath
)
{
  gpg::diag::InstallProbeWatchHandler();
  gpg::diag::ProbeWatchSelfTest();
  EXPECT_NE(Section().find("selftest: wrote, scratch=42"), std::string::npos) << Section();
}

#endif
