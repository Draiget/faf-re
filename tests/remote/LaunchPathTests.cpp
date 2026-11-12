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
    std::string error;
    ASSERT_TRUE(MakeServerConnectRequest("203.0.113.7:27050", "token-of-seat-one", 1001, request, error)) << error;
    EXPECT_EQ(request.endpoint, "203.0.113.7:27050");
    EXPECT_EQ(request.address, (203u << 24) | (0u << 16) | (113u << 8) | 7u);
    EXPECT_EQ(request.port, 27050);
    EXPECT_EQ(request.token, "token-of-seat-one");
    EXPECT_EQ(request.uid, 1001);
  }

  TEST(
    LaunchPath,
    BadAddressIsRefused
  )
  {
    for (const char* const endpoint :
         {"", "203.0.113.7", "203.0.113.7:0", "203.0.113.7:70000", "server:27050", "1.2.3:27050", " 1.2.3.4:27050"}) {
      SServerConnectRequest request;
      std::string error;
      EXPECT_FALSE(MakeServerConnectRequest(endpoint, "token", 1001, request, error)) << endpoint;
      EXPECT_NE(error.find("IPv4 address and port"), std::string::npos) << error;
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
      std::string error;
      EXPECT_FALSE(MakeServerConnectRequest("10.0.0.1:27050", token, 1001, request, error)) << token;
      EXPECT_FALSE(error.empty());
      if (!token.empty()) {
        EXPECT_EQ(error.find(token), std::string::npos) << "the error must not repeat the token";
      }
    }
    SServerConnectRequest longest;
    std::string error;
    EXPECT_TRUE(MakeServerConnectRequest("10.0.0.1:27050", std::string(1024, 'a'), 1001, longest, error)) << error;
  }

  TEST(
    LaunchPath,
    UidMustBePositive
  )
  {
    for (const std::int32_t uid : {0, -1, -1001}) {
      SServerConnectRequest request;
      std::string error;
      EXPECT_FALSE(MakeServerConnectRequest("10.0.0.1:27050", "token", uid, request, error)) << uid;
      EXPECT_NE(error.find("above 0"), std::string::npos) << error;
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
