// Plan WP13.1, WP15.3: the replay log (server/ReplayLog.h): only bytes old enough are read, in order, and the tee
// writes the same bytes to the replay file and the log.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gpg/core/streams/MemBufferStream.h"
#include "server/ReplayLog.h"

namespace
{
  std::string Text(const std::vector<std::uint8_t>& bytes)
  {
    return std::string(bytes.begin(), bytes.end());
  }
} // namespace

TEST(ReplayLog, ReadsOnlyWhatIsOldEnough)
{
  faf::server::CReplayLog log;
  log.Append("abc", 3u, 100u);
  log.Append("de", 2u, 200u);
  std::vector<std::uint8_t> out;
  EXPECT_EQ(log.Read(0u, 99u, 100u, out), 0u); // nothing written that early
  EXPECT_EQ(log.Read(0u, 150u, 100u, out), 3u);
  EXPECT_EQ(Text(out), "abc");
  EXPECT_EQ(log.Read(3u, 150u, 100u, out), 0u); // "de" is too new yet
  EXPECT_EQ(log.Read(3u, 200u, 100u, out), 2u);
  EXPECT_EQ(Text(out), "abcde");
  out.clear();
  EXPECT_EQ(log.Read(1u, 500u, 2u, out), 2u); // at most maxBytes
  EXPECT_EQ(Text(out), "bc");
  EXPECT_EQ(log.Read(9u, 500u, 100u, out), 0u); // past the end
  EXPECT_EQ(log.Size(), 5u);
  EXPECT_FALSE(log.Finished());
  log.Finish();
  EXPECT_TRUE(log.Finished());
}

TEST(ReplayLog, AClockThatStepsBackKeepsTheOrder)
{
  faf::server::CReplayLog log;
  log.Append("x", 1u, 300u);
  log.Append("y", 1u, 100u); // taken as 300: a later byte is never older than an earlier one
  std::vector<std::uint8_t> out;
  EXPECT_EQ(log.Read(0u, 200u, 10u, out), 0u);
  EXPECT_EQ(log.Read(0u, 300u, 10u, out), 2u);
  EXPECT_EQ(Text(out), "xy");
}

TEST(ReplayLog, TheTeeWritesTheFileAndTheLog)
{
  auto file = std::make_unique<gpg::MemBufferStream>(64u);
  gpg::MemBufferStream* const fileView = file.get();
  auto log = std::make_shared<faf::server::CReplayLog>();
  std::uint64_t now = 1000u;
  {
    faf::server::CReplayTee tee(std::move(file), log, [&now] { return now; });
    tee.Write("header", 6u);
    now = 2000u;
    tee.Write("beat1", 5u);
    tee.VirtFlush();
    const std::string written(fileView->mWriteStart, fileView->BytesWritten());
    EXPECT_EQ(written, "headerbeat1");
    std::vector<std::uint8_t> early;
    EXPECT_EQ(log->Read(0u, 1500u, 100u, early), 6u);
    EXPECT_EQ(Text(early), "header");
    EXPECT_FALSE(log->Finished());
  }
  EXPECT_TRUE(log->Finished()); // the tee went with the replay file
  std::vector<std::uint8_t> all;
  EXPECT_EQ(log->Read(0u, 5000u, 100u, all), 11u);
  EXPECT_EQ(Text(all), "headerbeat1");
}
