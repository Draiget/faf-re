// The SFD header parser (src/moho/movie/sfd/SfdHeaderParser.cpp, docs/FAF_SFD_COMPATIBILITY.md) on
// synthetic headers: relocation, truncation, malformed metadata and random input.

#include "moho/movie/sfd/SfdHeaderParser.h"

#include <gtest/gtest.h>

#include <cstring>
#include <random>
#include <vector>

using namespace moho::sfd;

namespace
{
  // A 192x192, 150-frame, 29.97 fps stream header starting at `base`.
  std::vector<std::byte> Fixture(const std::size_t base)
  {
    std::vector<std::byte> bytes(base + 2048);
    auto put = [&](const std::size_t offset, const unsigned value) {
      bytes[base + offset] = static_cast<std::byte>(value);
    };
    std::memcpy(bytes.data() + base + 32, "SofdecStream            ", 24);
    put(0x81, 8);
    put(0x88, 2);
    put(0x8d, 8);
    put(0xb0, 2);
    put(0xb2, 1);
    put(0xb3, 1);
    put(0xc0, 150);
    put(0x180 + 24, 0xbf);
    put(0x1c0 + 24, 0xe0);
    put(0x1c0 + 28, 12);
    put(0x1c0 + 29, 0);
    put(0x1c0 + 30, 192);
    put(0x1c0 + 31, 4);
    return bytes;
  }
} // namespace

TEST(SfdHeaderParser, RelocatedHeaderParses)
{
  for (const std::size_t base : {0U, 37U, 2048U, 4096U, 8192U}) {
    SCOPED_TRACE(testing::Message() << "base " << base);
    const auto bytes = Fixture(base);
    HeaderInfo h;
    ASSERT_TRUE(ParseSfdHeader(bytes, h));
    EXPECT_EQ(h.width, 192);
    EXPECT_EQ(h.height, 192);
    EXPECT_EQ(h.frameCount, 150u);
    EXPECT_EQ(h.fpsMilli, 29970);
  }
}

TEST(SfdHeaderParser, TruncatedHeaderIsRefused)
{
  for (const std::size_t base : {0U, 37U, 2048U, 4096U, 8192U}) {
    const auto bytes = Fixture(base);
    HeaderInfo h;
    for (std::size_t n = 0; n < base + 0x200; ++n) {
      ASSERT_FALSE(ParseSfdHeader(std::span(bytes).first(n), h)) << "base " << base << ", first " << n << " bytes";
    }
  }
}

TEST(SfdHeaderParser, CompositionModeFollowsTheEffect)
{
  for (const std::size_t base : {0U, 37U, 2048U, 4096U, 8192U}) {
    auto bytes = Fixture(base);
    HeaderInfo h;
    for (const unsigned effect : {1U, 3U, 6U}) {
      SCOPED_TRACE(testing::Message() << "base " << base << " effect " << effect);
      bytes[base + 0x1c0 + 39] = static_cast<std::byte>(effect);
      ASSERT_TRUE(ParseSfdHeader(bytes, h));
      EXPECT_EQ(h.compositionMode, effect == 1 ? 33 : effect == 3 ? 81 : 97);
    }
    bytes[base + 55] = std::byte{'!'};
    EXPECT_FALSE(ParseSfdHeader(bytes, h)) << "a damaged stream name, base " << base;
  }
}

TEST(SfdHeaderParser, MalformedMetadataIsRefused)
{
  const auto bytes = Fixture(0);
  HeaderInfo h;
  for (const auto offset : {0xb0, 0xb1, 0xb2, 0xb3, 0x84, 0x88, 0x1df}) {
    SCOPED_TRACE(testing::Message() << "offset 0x" << std::hex << offset);
    auto bad = bytes;
    bad[offset] = std::byte{255};
    EXPECT_FALSE(ParseSfdHeader(bad, h));
    EXPECT_EQ(h.width, 0);
  }
}

// Random bytes, half of them over a valid header: refused or parsed, never a crash.
TEST(SfdHeaderParser, RandomInputDoesNotCrash)
{
  const auto bytes = Fixture(0);
  HeaderInfo h;
  std::mt19937 random(873);
  for (int i = 0; i < 20000; ++i) {
    std::vector<std::byte> input(random() % 8192);
    for (auto& b : input) {
      b = static_cast<std::byte>(random());
    }
    if (i % 2 == 0 && input.size() >= bytes.size()) {
      std::copy(bytes.begin(), bytes.end(), input.begin());
    }
    for (int j = 0; j < 10 && !input.empty(); ++j) {
      input[random() % input.size()] = static_cast<std::byte>(random());
    }
    (void)ParseSfdHeader(input, h);
  }
}
