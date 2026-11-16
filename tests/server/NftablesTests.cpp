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
    return text.contains(part);
  }

  using faf::remote::net::IpAddress;
  using faf::remote::net::MapIpv4;

  [[nodiscard]] IpAddress Ip(
    const char* const text
  )
  {
    IpAddress address{};
    EXPECT_TRUE(faf::remote::net::ParseAddress(text, address)) << text;
    return address;
  }

  TEST(
    Nftables,
    ElementText
  )
  {
    EXPECT_EQ(faf::server::NftablesElementText(MapIpv4(0xC000024Du)), "192.0.2.77");
    EXPECT_EQ(faf::server::NftablesElementText(MapIpv4(0xC6336401u)), "198.51.100.1");
    EXPECT_EQ(faf::server::NftablesElementText(Ip("2001:db8:aa:bb:1:2:3:4")), "2001:db8:aa:bb::/64");
  }

  // Issue #160: IPv6 addresses go into their own set by /64; one /64 is one element.
  TEST(
    Nftables,
    Ipv6ListedByPrefix
  )
  {
    SNftablesConfig config;
    config.port = 27050;
    config.listed = {Ip("2001:db8:aa:bb::10"), MapIpv4(0xC000024Du), Ip("2001:db8:aa:bb::20"), Ip("2001:db8:cc::1")};
    config.unlistedPerSourcePps = 100;
    const std::string rules = MakeNftablesRuleset(config);
    EXPECT_TRUE(Has(rules, "set listed6 {\n    type ipv6_addr\n    flags interval\n"));
    EXPECT_TRUE(Has(rules, "elements = { 2001:db8:aa:bb::/64, 2001:db8:cc::/64 }"));
    EXPECT_TRUE(Has(rules, "elements = { 192.0.2.77 }"));
    EXPECT_TRUE(Has(rules, "udp dport 27050 ip6 saddr @listed6 counter accept"));
    EXPECT_TRUE(
      Has(rules, "meter faf_server_27050_unlisted6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate 100/second")
    );
    EXPECT_LT(rules.find("@listed6 counter accept"), rules.find("counter drop comment \"unlisted\""));
  }

  TEST(
    Nftables,
    StrictListDropsEveryOtherAddress
  )
  {
    SNftablesConfig config;
    config.port = 27050;
    config.listed = {MapIpv4(0xC000024Du), MapIpv4(0xC6336401u)};
    const std::string rules = MakeNftablesRuleset(config);
    EXPECT_TRUE(Has(rules, "table inet faf_server_27050 {"));
    EXPECT_TRUE(Has(rules, "delete table inet faf_server_27050\n")) << "loading it twice must replace, not add";
    EXPECT_TRUE(Has(rules, "elements = { 192.0.2.77, 198.51.100.1 }"));
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
