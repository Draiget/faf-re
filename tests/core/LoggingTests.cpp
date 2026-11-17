// gpg/core/utils/Logging: log targets and their dispatch, scoped thread contexts, the stream target's text layout,
// the in-memory history, the log-scope depth padding and the microsecond time stamp text. Every message a test
// sends carries a marker, and the capturing target keeps only those, so engine logging in the same process can't
// change a result.

#include "gpg/core/utils/Logging.h"

#include <gtest/gtest.h>

#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace
{
  constexpr const char* kMarker = "[logtest]";

  struct Seen
  {
    gpg::LogSeverity level;
    std::string message;
    std::vector<std::string> context;
    int previousDepth;
  };

  /** Registered on construction (LogTarget(true)); keeps the messages that carry the marker. */
  class CapturingTarget final : public gpg::LogTarget
  {
  public:
    CapturingTarget()
      : gpg::LogTarget(true)
    {}

    void OnMessage(
      const gpg::LogSeverity level,
      const fa::string& message,
      const fa::vector<fa::string>& context,
      const int previousDepth
    ) override
    {
      const std::string text = message.c_str();
      if (!text.contains(kMarker)) {
        return;
      }
      Seen seen{level, text, {}, previousDepth};
      for (const fa::string& entry : context) {
        seen.context.emplace_back(entry.c_str());
      }
      mSeen.push_back(std::move(seen));
    }

    std::vector<Seen> mSeen;
  };

  std::string Marked(
    const char* text
  )
  {
    return std::string(kMarker) + " " + text;
  }

  std::string Format(
    const gpg::LogSeverity level,
    const char* message,
    const std::vector<std::string>& context,
    const int previousDepth
  )
  {
    std::ostringstream out;
    gpg::StreamLogTarget target(out, 0u); // not registered
    fa::vector<fa::string> ctx;
    for (const std::string& entry : context) {
      ctx.push_back(fa::string(entry.c_str()));
    }
    target.OnMessage(level, fa::string(message), ctx, previousDepth);
    return out.str();
  }
} // namespace

TEST(
  Logging,
  TargetsGetEachSeverityAndStopAfterDestruction
)
{
  std::vector<Seen> seen;
  {
    CapturingTarget target;
    gpg::Debugf("%s debug %d", kMarker, 1);
    gpg::Logf("%s info %s", kMarker, "two");
    gpg::Warnf("%s warn", kMarker);
    gpg::LogMessage(gpg::LogSeverity::Info, fa::string(Marked("direct").c_str()));
    seen = target.mSeen;
  }
  ASSERT_EQ(seen.size(), 4u);
  EXPECT_EQ(seen[0].level, gpg::LogSeverity::Debug);
  EXPECT_EQ(seen[0].message, Marked("debug 1"));
  EXPECT_EQ(seen[1].level, gpg::LogSeverity::Info);
  EXPECT_EQ(seen[1].message, Marked("info two"));
  EXPECT_EQ(seen[2].level, gpg::LogSeverity::Warn);
  EXPECT_EQ(seen[3].message, Marked("direct"));
  EXPECT_EQ(seen[0].previousDepth, 0) << "a new target's first message starts at depth 0";

  // The target is gone: logging again must not reach it (it would crash if it did).
  gpg::Logf("%s after", kMarker);
}

TEST(
  Logging,
  ScopedContextsTravelWithTheMessage
)
{
  CapturingTarget target;
  {
    gpg::ScopedLogContext outer("loading map");
    {
      gpg::ScopedLogContext inner(fa::string("units"));
      gpg::Logf("%s inside both", kMarker);
    }
    gpg::Logf("%s inside outer", kMarker);
  }
  gpg::Logf("%s outside", kMarker);

  ASSERT_EQ(target.mSeen.size(), 3u);
  EXPECT_EQ(target.mSeen[0].context, (std::vector<std::string>{"loading map", "units"}));
  EXPECT_EQ(target.mSeen[1].context, (std::vector<std::string>{"loading map"}));
  EXPECT_TRUE(target.mSeen[2].context.empty());

  const gpg::ScopedLogContext nullText(static_cast<const char*>(nullptr));
  gpg::Logf("%s null label", kMarker);
  ASSERT_EQ(target.mSeen.size(), 4u);
  EXPECT_EQ(target.mSeen[3].context, (std::vector<std::string>{""}));
}

// The stream target writes each context label not yet shown on its own line, four spaces deeper per level, then
// "<severity>: " and the message; later lines of the message line up under its first character.
TEST(
  Logging,
  StreamTargetIndentsContextsAndContinuationLines
)
{
  EXPECT_EQ(Format(gpg::LogSeverity::Info, "plain", {}, 0), "info: plain\n");
  EXPECT_EQ(Format(gpg::LogSeverity::Debug, "d", {}, 0), "debug: d\n");
  EXPECT_EQ(Format(gpg::LogSeverity::Warn, "w", {}, 0), "warning: w\n");
  EXPECT_EQ(Format(static_cast<gpg::LogSeverity>(7), "x", {}, 0), "info: x\n") << "unknown levels print as info";

  EXPECT_EQ(
    Format(gpg::LogSeverity::Info, "line1\nline2", {"a", "b"}, 0),
    "a:\n"
    "    b:\n"
    "        info: line1\n"
    "              line2\n"
  );
  // Labels already shown (previous depth 1) are not written again; the depth is clamped to the context's size.
  EXPECT_EQ(Format(gpg::LogSeverity::Warn, "m", {"a", "b"}, 1), "    b:\n        warning: m\n");
  EXPECT_EQ(Format(gpg::LogSeverity::Info, "m", {"a"}, 5), "    info: m\n");
  EXPECT_EQ(Format(gpg::LogSeverity::Info, "m", {"a"}, -3), "a:\n    info: m\n");
  // A message ending in a newline gets no extra line.
  EXPECT_EQ(Format(gpg::LogSeverity::Info, "end\n", {}, 0), "info: end\n");
  EXPECT_EQ(Format(gpg::LogSeverity::Info, "a\nb\nc", {}, 0), "info: a\n      b\n      c\n");
}

TEST(
  Logging,
  StreamTargetRegistersWithFlagOneAndOwnsWithFlagTwo
)
{
  std::ostringstream out;
  {
    gpg::StreamLogTarget target(out, 1u);
    gpg::Logf("%s to the stream", kMarker);
  }
  gpg::Logf("%s not any more", kMarker);
  const std::string text = out.str();
  EXPECT_NE(text.find(Marked("to the stream")), std::string::npos);
  EXPECT_EQ(text.find("not any more"), std::string::npos);

  // Flag 2: the target deletes the stream it was given (a leak checker would see it otherwise).
  auto* owned = new std::ostringstream;
  {
    gpg::StreamLogTarget target(*owned, 2u);
  }
}

TEST(
  Logging,
  HistoryKeepsTheNewestMessagesWithTheirContexts
)
{
  EXPECT_FALSE(gpg::ReplayLogHistory(nullptr));

  gpg::EnableLogHistory(2);
  {
    gpg::ScopedLogContext scope("history scope");
    gpg::Logf("%s h1", kMarker);
    gpg::Logf("%s h2", kMarker);
  }
  gpg::Warnf("%s h3", kMarker);

  const std::string lines = gpg::GetRecentLogLines().c_str();
  EXPECT_EQ(lines.find("h1"), std::string::npos) << lines;
  EXPECT_NE(lines.find("history scope:\n    info: " + Marked("h2")), std::string::npos) << lines;
  EXPECT_NE(lines.find("warning: " + Marked("h3")), std::string::npos) << lines;

  std::ostringstream sink;
  gpg::StreamLogTarget streamSink(sink, 0u);
  EXPECT_TRUE(gpg::ReplayLogHistory(&streamSink));
  EXPECT_EQ(sink.str(), lines);

  gpg::EnableLogHistory(0); // keep nothing for the tests after this one
  EXPECT_EQ(std::string(gpg::GetRecentLogLines().c_str()), "");
}

TEST(
  Logging,
  ScopeDepthPaddingFollowsDepthTimesScale
)
{
  const int savedDepth = gpg::g_LogScopeDepth;
  const int savedScale = gpg::g_LogScopeDepthScale;
  gpg::g_LogScopeDepth = 0;
  gpg::g_LogScopeDepthScale = 3;

  EXPECT_EQ(std::string(gpg::IncreaseLogScopeDepth()->c_str()), "   ");
  EXPECT_EQ(std::string(gpg::IncreaseLogScopeDepth()->c_str()), "      ");
  EXPECT_EQ(gpg::g_LogScopeDepth, 2);
  EXPECT_EQ(std::string(gpg::DecreaseLogScopeDepth()->c_str()), "   ");
  EXPECT_EQ(std::string(gpg::DecreaseLogScopeDepth()->c_str()), "");

  gpg::g_LogScopeDepth = savedDepth;
  gpg::g_LogScopeDepthScale = savedScale;
}

// Microseconds since 1601 to local "HH:MM:SS.mmm". Time zones move whole minutes, so seconds and milliseconds are
// fixed: 1970-01-01 00:00:45.678900 UTC prints ":45.678" wherever the test runs.
TEST(
  Logging,
  FileTimeToStringPrintsLocalClockWithMilliseconds
)
{
  constexpr long long kUnixEpochUs = 11644473600LL * 1000000LL;
  const std::string text = gpg::FileTimeToString(kUnixEpochUs + 45678900LL).c_str();
  EXPECT_TRUE(std::regex_match(text, std::regex(R"(\d\d:\d\d:45\.678)"))) << text;
}
