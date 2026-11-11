// Engine addition, dedicated server (plan WPR.45): the nftables ruleset the server writes for its port.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_server_tests
// Run:   build/linux-clang-x64-release-plain/faf_server_tests   (exit code = failures)

#include <string>

#include <gtest/gtest.h>

#include "server/Nftables.h"

namespace
{
  using faf::server::MakeNftablesRuleset;
  using faf::server::SNftablesConfig;

  [[nodiscard]] bool Has(
    const std::string& text,
    const std::string& part
  )
  {
    return text.find(part) != std::string::npos;
  }

  TEST(
    Nftables,
    AddressText
  )
  {
    EXPECT_EQ(faf::server::NftablesAddressText(0xC0A82A4Du), "192.168.42.77");
    EXPECT_EQ(faf::server::NftablesAddressText(0x0A000001u), "10.0.0.1");
  }

  TEST(
    Nftables,
    StrictListDropsEveryOtherAddress
  )
  {
    SNftablesConfig config;
    config.port = 27050;
    config.listed = {0xC0A82A4Du, 0x0A000001u};
    const std::string rules = MakeNftablesRuleset(config);
    EXPECT_TRUE(Has(rules, "table inet faf_server_27050 {"));
    EXPECT_TRUE(Has(rules, "delete table inet faf_server_27050\n")) << "loading it twice must replace, not add";
    EXPECT_TRUE(Has(rules, "elements = { 192.168.42.77, 10.0.0.1 }"));
    EXPECT_TRUE(Has(rules, "udp dport 27050 ip saddr @listed4 counter accept"));
    EXPECT_FALSE(Has(rules, "meter")) << "no admission path";
    EXPECT_TRUE(Has(rules, "udp dport 27050 counter drop comment \"unlisted\""));
    // The listed rule comes before the drop.
    EXPECT_LT(rules.find("@listed4 counter accept"), rules.find("counter drop comment \"unlisted\""));
  }

  TEST(
    Nftables,
    AdmissionPathIsRateLimited
  )
  {
    SNftablesConfig config;
    config.port = 27016;
    config.unlistedPerSourcePps = 100;
    config.unlistedTotalPps = 2000;
    const std::string rules = MakeNftablesRuleset(config);
    EXPECT_FALSE(Has(rules, "elements")) << "an empty set has no elements line";
    const std::size_t total = rules.find("limit rate over 2000/second counter drop");
    const std::size_t perSource = rules.find(
      "meter faf_server_27016_unlisted4 { ip saddr limit rate 100/second burst 100 packets } counter accept"
    );
    const std::size_t drop = rules.find("udp dport 27016 counter drop comment \"unlisted\"");
    ASSERT_NE(total, std::string::npos);
    ASSERT_NE(perSource, std::string::npos);
    ASSERT_NE(drop, std::string::npos);
    EXPECT_LT(total, perSource) << "the total cap first, then each source's";
    EXPECT_LT(perSource, drop);
  }

  TEST(
    Nftables,
    NoTotalCapWhenZero
  )
  {
    SNftablesConfig config;
    config.port = 1;
    config.unlistedPerSourcePps = 10;
    const std::string rules = MakeNftablesRuleset(config);
    EXPECT_FALSE(Has(rules, "limit rate over"));
    EXPECT_TRUE(Has(rules, "limit rate 10/second burst 10 packets"));
  }
} // namespace
