// Plan WP12.2 (the FAF client's launch path): a game a launcher started with /gpgnet joins a game server from one
// connection string, given as GPGNet's `JoinServer address token uid` or as /connectserver /servertoken /serveruid.
// Both are checked by MakeServerConnectRequest; a game on a game server ignores the launcher's peer lobby and link
// commands (IsPeerLinkCommand); a server-mode build says so in its peer announcement (EPeerFeature::ServerSession).

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include "moho/net/PeerFeatures.h"
#include "remote/client/ServerConnect.h"

namespace
{
  using faf::remote::IsPeerLinkCommand;
  using faf::remote::MakeServerConnectRequest;
  using faf::remote::SServerConnectRequest;

  TEST(
    LaunchPath,
    ConnectionStringIsTaken
  )
  {
    SServerConnectRequest request;
    const auto made = MakeServerConnectRequest("203.0.113.7:27050", "token-of-seat-one", 1001, request);
    ASSERT_TRUE(made) << made.error();
    EXPECT_EQ(request.endpoint, "203.0.113.7:27050");
    EXPECT_EQ(request.address, faf::remote::net::MapIpv4((203u << 24) | (0u << 16) | (113u << 8) | 7u));
    EXPECT_EQ(request.port, 27050);
    EXPECT_EQ(request.token, "token-of-seat-one");
    EXPECT_EQ(request.uid, 1001);
  }

  // Issue #160: a game server on IPv6.
  TEST(
    LaunchPath,
    Ipv6ConnectionStringIsTaken
  )
  {
    SServerConnectRequest request;
    const auto made = MakeServerConnectRequest("[2001:db8::7]:27050", "token-of-seat-one", 1001, request);
    ASSERT_TRUE(made) << made.error();
    EXPECT_EQ(request.endpoint, "[2001:db8::7]:27050");
    EXPECT_EQ(faf::remote::net::AddressText(request.address), "2001:db8::7");
    EXPECT_EQ(request.port, 27050);
    SServerConnectRequest refused;
    EXPECT_FALSE(MakeServerConnectRequest("2001:db8::7:27050", "token", 1001, refused))
      << "an IPv6 address without brackets leaves the port unclear";
  }

  TEST(
    LaunchPath,
    BadAddressIsRefused
  )
  {
    for (const char* const endpoint : {
           "", "203.0.113.7", "203.0.113.7:0", "203.0.113.7:70000", "server:27050", "1.2.3:27050", " 203.0.113.4:27050"
         }) {
      SServerConnectRequest request;
      const auto made = MakeServerConnectRequest(endpoint, "token", 1001, request);
      ASSERT_FALSE(made) << endpoint;
      EXPECT_NE(made.error().find("IPv4 address and port"), std::string::npos) << made.error();
      EXPECT_NE(made.error().find("[address]:port"), std::string::npos) << made.error();
      EXPECT_TRUE(request.token.empty()) << "a refused request keeps nothing";
    }
  }

  TEST(
    LaunchPath,
    BadTokenIsRefusedWithoutShowingIt
  )
  {
    const std::string tooLong(1025, 'a');
    for (const std::string& token :
         {std::string(), std::string("two words"), std::string("tab\there"), tooLong, std::string("caf\xC3\xA9")}) {
      SServerConnectRequest request;
      const auto made = MakeServerConnectRequest("192.0.2.1:27050", token, 1001, request);
      ASSERT_FALSE(made) << token;
      EXPECT_FALSE(made.error().empty());
      if (!token.empty()) {
        EXPECT_EQ(made.error().find(token), std::string::npos) << "the error must not repeat the token";
      }
    }
    SServerConnectRequest longest;
    const auto made = MakeServerConnectRequest("192.0.2.1:27050", std::string(1024, 'a'), 1001, longest);
    EXPECT_TRUE(made) << made.error();
  }

  TEST(
    LaunchPath,
    UidMustBePositive
  )
  {
    for (const std::int32_t uid : {0, -1, -1001}) {
      SServerConnectRequest request;
      const auto made = MakeServerConnectRequest("192.0.2.1:27050", "token", uid, request);
      ASSERT_FALSE(made) << uid;
      EXPECT_NE(made.error().find("above 0"), std::string::npos) << made.error();
    }
  }

  TEST(
    LaunchPath,
    PeerLobbyAndLinkCommandsAreIgnoredOnAServer
  )
  {
    for (const char* const command :
         {"CreateLobby",
          "HostGame",
          "JoinGame",
          "ConnectToPeer",
          "DisconnectFromPeer",
          "SendNatPacket",
          "EjectPlayer",
          "IceServers",
          "IceMsg",
          "NetlinkConfig",
          "NetlinkPeer"}) {
      EXPECT_TRUE(IsPeerLinkCommand(command)) << command;
    }
    for (const char* const command :
         {"JoinServer",
          "GameState",
          "Test",
          "Connected",
          "ConnectionShutdown",
          "Stats",
          "GameResult",
          "Chat",
          "createlobby",
          ""}) {
      EXPECT_FALSE(IsPeerLinkCommand(command)) << command;
    }
  }

  TEST(
    LaunchPath,
    ServerModeBuildAnnouncesServerSessions
  )
  {
    // Bits travel as positions and never change (docs/PEER_FEATURES.md).
    EXPECT_EQ(moho::PeerFeatureBit(moho::EPeerFeature::ServerSession), std::uint64_t{1} << 5);
#if FAF_SERVER_MODE
    EXPECT_NE(moho::PeerBuildMask() & moho::PeerFeatureBit(moho::EPeerFeature::ServerSession), 0u);
#else
    EXPECT_EQ(moho::PeerBuildMask() & moho::PeerFeatureBit(moho::EPeerFeature::ServerSession), 0u);
#endif
  }
} // namespace
